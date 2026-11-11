//go:build windows

package platform

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows Firewall is configured through its own COM policy object rather than
// through PowerShell. This is the same object model the NetSecurity cmdlets
// wrap, so the rule keeps a real per-interface binding: netsh advfirewall has
// no interface parameter at all and would silently widen the exception to every
// adapter.
var (
	ole32                   = windows.NewLazySystemDLL("ole32.dll")
	oleaut32                = windows.NewLazySystemDLL("oleaut32.dll")
	procCoInitializeEx      = ole32.NewProc("CoInitializeEx")
	procCoUninitialize      = ole32.NewProc("CoUninitialize")
	procCoCreateInstance    = ole32.NewProc("CoCreateInstance")
	procCLSIDFromProgID     = ole32.NewProc("CLSIDFromProgID")
	procSysAllocString      = oleaut32.NewProc("SysAllocString")
	procSysFreeString       = oleaut32.NewProc("SysFreeString")
	procSafeArrayCreate     = oleaut32.NewProc("SafeArrayCreate")
	procSafeArrayPutElement = oleaut32.NewProc("SafeArrayPutElement")
	procSafeArrayDestroy    = oleaut32.NewProc("SafeArrayDestroy")
)

var (
	iidNetFwPolicy2 = windows.GUID{Data1: 0x98325047, Data2: 0xC671, Data3: 0x4174, Data4: [8]byte{0x8D, 0x81, 0xDE, 0xFC, 0xD3, 0xF0, 0x31, 0x86}}
	iidNetFwRules   = windows.GUID{Data1: 0x9C4C6277, Data2: 0x5027, Data3: 0x441E, Data4: [8]byte{0xAF, 0xAE, 0xCA, 0x1F, 0x54, 0x2D, 0xA0, 0x09}}
	iidNetFwRule    = windows.GUID{Data1: 0xAF230D27, Data2: 0xBABA, Data3: 0x4E42, Data4: [8]byte{0xAC, 0xED, 0xF5, 0x24, 0xF2, 0x2C, 0xFC, 0xE2}}
)

const (
	coinitMultithreaded = 0
	clsctxServer        = 0x1 | 0x4 // in-process or local server
	rpcEChangedMode     = 0x80010106
	ePointer            = 0x80004003
	errorFileNotFound   = 0x80070002 // INetFwRules::Item reports a missing rule this way

	variantTrue       = 0xFFFF     // VARIANT_BOOL true
	netFwProfileAll   = 0x7FFFFFFF // NET_FW_PROFILE2_ALL
	fwRuleDirectionIn = 1          // NET_FW_RULE_DIR_IN
	fwActionAllow     = 1          // NET_FW_ACTION_ALLOW

	vtBstr    = 8
	vtVariant = 12
	vtArray   = 0x2000

	// COM vtable slots, counting the three IUnknown and four IDispatch entries
	// that precede every dual interface.
	slotRelease = 2

	policySlotGetRules = 7 + 11

	rulesSlotAdd    = 7 + 1
	rulesSlotRemove = 7 + 2
	rulesSlotItem   = 7 + 3

	ruleSlotPutName            = 7 + 1
	ruleSlotPutDescription     = 7 + 3
	ruleSlotGetRemoteAddresses = 7 + 16
	ruleSlotPutRemoteAddresses = 7 + 17
	ruleSlotPutDirection       = 7 + 21
	ruleSlotPutInterfaces      = 7 + 23
	ruleSlotPutEnabled         = 7 + 27
	ruleSlotPutProfiles        = 7 + 31
	ruleSlotPutAction          = 7 + 35
)

// variant mirrors the 24-byte OLE VARIANT. Only the first union word is used:
// a SAFEARRAY pointer for arrays and a BSTR pointer for property values. They
// are only ever handed back to COM, never dereferenced here.
type variant struct {
	Type      uint16
	Reserved1 uint16
	Reserved2 uint16
	Reserved3 uint16
	Value     uintptr
	Value2    uintptr
}

type safeArrayBound struct {
	Elements uint32
	Lower    int32
}

func oleResult(hr uintptr, context string) error {
	if hr == 0 {
		return nil
	}
	return fmt.Errorf("%s: %w", context, syscall.Errno(hr&0xFFFF))
}

// vtCall invokes a COM method. object is an unsafe.Pointer so the vtable can be
// dereferenced without converting a uintptr back into a pointer.
func vtCall(object unsafe.Pointer, slot int, args ...uintptr) uintptr {
	if object == nil {
		return ePointer
	}
	vtable := *(*unsafe.Pointer)(object)
	if vtable == nil {
		return ePointer
	}
	procedure := *(*uintptr)(unsafe.Add(vtable, uintptr(slot)*unsafe.Sizeof(uintptr(0))))
	for len(args) < 8 {
		args = append(args, 0)
	}
	result, _, _ := syscall.SyscallN(procedure, args...)
	return result
}

func releaseObject(object unsafe.Pointer) {
	if object != nil {
		vtCall(object, slotRelease, uintptr(object))
	}
}

func bstrOf(value string) (uintptr, error) {
	pointer, err := windows.UTF16PtrFromString(value)
	if err != nil {
		return 0, err
	}
	allocated, _, _ := procSysAllocString.Call(uintptr(unsafe.Pointer(pointer)))
	if allocated == 0 {
		return 0, errors.New("SysAllocString failed")
	}
	return allocated, nil
}

func comClassID(progID string) (windows.GUID, error) {
	pointer, err := windows.UTF16PtrFromString(progID)
	if err != nil {
		return windows.GUID{}, err
	}
	var clsid windows.GUID
	hr, _, _ := procCLSIDFromProgID.Call(uintptr(unsafe.Pointer(pointer)), uintptr(unsafe.Pointer(&clsid)))
	if hr != 0 {
		return windows.GUID{}, oleResult(hr, "CLSIDFromProgID("+progID+")")
	}
	return clsid, nil
}

func comCreate(progID string, iid windows.GUID) (unsafe.Pointer, error) {
	clsid, err := comClassID(progID)
	if err != nil {
		return nil, err
	}
	var object unsafe.Pointer
	hr, _, _ := procCoCreateInstance.Call(
		uintptr(unsafe.Pointer(&clsid)), 0, uintptr(clsctxServer),
		uintptr(unsafe.Pointer(&iid)), uintptr(unsafe.Pointer(&object)))
	if hr != 0 {
		return nil, oleResult(hr, "CoCreateInstance("+progID+")")
	}
	return object, nil
}

// safeArrayOfStrings builds the VT_ARRAY|VT_VARIANT form Windows Firewall
// requires: the array element type is VARIANT, each holding a BSTR. A plain
// VT_ARRAY|VT_BSTR array is rejected with E_INVALIDARG.
func safeArrayOfStrings(values []string) (uintptr, error) {
	bound := safeArrayBound{Elements: uint32(len(values)), Lower: 0}
	array, _, _ := procSafeArrayCreate.Call(uintptr(vtVariant), 1, uintptr(unsafe.Pointer(&bound)))
	if array == 0 {
		return 0, errors.New("SafeArrayCreate failed")
	}
	for index, value := range values {
		element := variant{Type: vtBstr}
		var err error
		element.Value, err = bstrOf(value)
		if err != nil {
			procSafeArrayDestroy.Call(array)
			return 0, err
		}
		position := int32(index)
		if hr, _, _ := procSafeArrayPutElement.Call(array, uintptr(unsafe.Pointer(&position)), uintptr(unsafe.Pointer(&element))); hr != 0 {
			procSysFreeString.Call(element.Value)
			procSafeArrayDestroy.Call(array)
			return 0, oleResult(hr, "SafeArrayPutElement")
		}
	}
	return array, nil
}

// normalizePrefixText accepts the address/mask spelling Windows Firewall
// reports ("10.242.0.0/255.255.255.0") as well as CIDR ("10.242.0.0/24").
func normalizePrefixText(value string) (netip.Prefix, error) {
	value = strings.TrimSpace(value)
	address, mask, found := strings.Cut(value, "/")
	addr, err := netip.ParseAddr(address)
	if err != nil {
		return netip.Prefix{}, err
	}
	if !found {
		return netip.PrefixFrom(addr, addr.BitLen()), nil
	}
	if strings.Contains(mask, ".") {
		parsed := net.ParseIP(mask)
		if parsed == nil || parsed.To4() == nil {
			return netip.Prefix{}, fmt.Errorf("invalid IPv4 mask %q", mask)
		}
		ones, bits := net.IPMask(parsed.To4()).Size()
		if bits != 32 {
			return netip.Prefix{}, fmt.Errorf("invalid IPv4 mask %q", mask)
		}
		return netip.PrefixFrom(addr, ones).Masked(), nil
	}
	bits, err := strconv.Atoi(mask)
	if err != nil {
		return netip.Prefix{}, err
	}
	if bits < 0 || bits > addr.BitLen() {
		return netip.Prefix{}, fmt.Errorf("invalid prefix length %q", mask)
	}
	return netip.PrefixFrom(addr, bits).Masked(), nil
}

// firewallSpec is the inbound exception the mesh needs on its virtual adapter.
type firewallSpec struct {
	Name        string
	Description string
	Interfaces  []string
	Remote      string
}

// firewallState is what cleanup verifies before deleting a rule.
type firewallState struct {
	Found  bool
	Remote string
}

// firewallControl isolates the COM policy object so tests can substitute it.
type firewallControl interface {
	Add(spec firewallSpec) error
	Lookup(name string) (firewallState, error)
	Remove(name string) error
}

var firewall firewallControl = netFirewallControl{}

type netFirewallControl struct{}

// withFirewallRules runs fn against the live policy object and releases every
// COM object it handed out. COM apartments are per-thread, so the call is
// pinned to one OS thread for its duration.
func withFirewallRules(fn func(rules unsafe.Pointer) error) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	hr, _, _ := procCoInitializeEx.Call(0, coinitMultithreaded)
	if hr != 0 && hr != rpcEChangedMode {
		return oleResult(hr, "CoInitializeEx")
	}
	if hr == 0 {
		defer procCoUninitialize.Call()
	}
	policy, err := comCreate("HNetCfg.FwPolicy2", iidNetFwPolicy2)
	if err != nil {
		return err
	}
	defer releaseObject(policy)
	var rules unsafe.Pointer
	if hr := vtCall(policy, policySlotGetRules, uintptr(policy), uintptr(unsafe.Pointer(&rules))); hr != 0 {
		return oleResult(hr, "INetFwPolicy2::Rules")
	}
	defer releaseObject(rules)
	return fn(rules)
}

func newFirewallRule(spec firewallSpec) (unsafe.Pointer, error) {
	rule, err := comCreate("HNetCfg.FWRule", iidNetFwRule)
	if err != nil {
		return nil, err
	}
	fail := func(cause error) (unsafe.Pointer, error) {
		releaseObject(rule)
		return nil, cause
	}
	put := func(slot int, context, value string) error {
		allocated, err := bstrOf(value)
		if err != nil {
			return err
		}
		defer procSysFreeString.Call(allocated)
		return oleResult(vtCall(rule, slot, uintptr(rule), allocated), context)
	}
	if err := put(ruleSlotPutName, "INetFwRule::put_Name", spec.Name); err != nil {
		return fail(err)
	}
	if err := put(ruleSlotPutDescription, "INetFwRule::put_Description", spec.Description); err != nil {
		return fail(err)
	}
	if err := put(ruleSlotPutRemoteAddresses, "INetFwRule::put_RemoteAddresses", spec.Remote); err != nil {
		return fail(err)
	}
	if hr := vtCall(rule, ruleSlotPutDirection, uintptr(rule), uintptr(fwRuleDirectionIn)); hr != 0 {
		return fail(oleResult(hr, "INetFwRule::put_Direction"))
	}
	if hr := vtCall(rule, ruleSlotPutAction, uintptr(rule), uintptr(fwActionAllow)); hr != 0 {
		return fail(oleResult(hr, "INetFwRule::put_Action"))
	}
	if hr := vtCall(rule, ruleSlotPutEnabled, uintptr(rule), uintptr(variantTrue)); hr != 0 {
		return fail(oleResult(hr, "INetFwRule::put_Enabled"))
	}
	if hr := vtCall(rule, ruleSlotPutProfiles, uintptr(rule), uintptr(netFwProfileAll)); hr != 0 {
		return fail(oleResult(hr, "INetFwRule::put_Profiles"))
	}
	array, err := safeArrayOfStrings(spec.Interfaces)
	if err != nil {
		return fail(err)
	}
	defer procSafeArrayDestroy.Call(array)
	interfaces := variant{Type: vtArray | vtVariant, Value: array}
	if hr := vtCall(rule, ruleSlotPutInterfaces, uintptr(rule), uintptr(unsafe.Pointer(&interfaces))); hr != 0 {
		return fail(oleResult(hr, "INetFwRule::put_Interfaces"))
	}
	return rule, nil
}

func (netFirewallControl) Add(spec firewallSpec) error {
	return withFirewallRules(func(rules unsafe.Pointer) error {
		rule, err := newFirewallRule(spec)
		if err != nil {
			return err
		}
		defer releaseObject(rule)
		if hr := vtCall(rules, rulesSlotAdd, uintptr(rules), uintptr(rule)); hr != 0 {
			return oleResult(hr, "INetFwRules::Add")
		}
		return nil
	})
}

func (netFirewallControl) Lookup(name string) (firewallState, error) {
	var state firewallState
	err := withFirewallRules(func(rules unsafe.Pointer) error {
		allocated, err := bstrOf(name)
		if err != nil {
			return err
		}
		defer procSysFreeString.Call(allocated)
		var rule unsafe.Pointer
		hr := vtCall(rules, rulesSlotItem, uintptr(rules), allocated, uintptr(unsafe.Pointer(&rule)))
		if hr == errorFileNotFound {
			return nil
		}
		if hr != 0 {
			return oleResult(hr, "INetFwRules::Item")
		}
		defer releaseObject(rule)
		state.Found = true
		// The property returns a BSTR the caller owns. Taking it as a typed
		// out-parameter avoids turning a uintptr back into a pointer.
		var remote *uint16
		if hr := vtCall(rule, ruleSlotGetRemoteAddresses, uintptr(rule), uintptr(unsafe.Pointer(&remote))); hr == 0 && remote != nil {
			text := windows.UTF16PtrToString(remote)
			procSysFreeString.Call(uintptr(unsafe.Pointer(remote)))
			if prefix, err := normalizePrefixText(text); err == nil {
				state.Remote = prefix.String()
			} else {
				state.Remote = strings.TrimSpace(text)
			}
		}
		return nil
	})
	return state, err
}

func (netFirewallControl) Remove(name string) error {
	return withFirewallRules(func(rules unsafe.Pointer) error {
		allocated, err := bstrOf(name)
		if err != nil {
			return err
		}
		defer procSysFreeString.Call(allocated)
		if hr := vtCall(rules, rulesSlotRemove, uintptr(rules), allocated); hr != 0 && hr != errorFileNotFound {
			return oleResult(hr, "INetFwRules::Remove")
		}
		return nil
	})
}
