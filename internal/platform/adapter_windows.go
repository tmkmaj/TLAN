//go:build windows

package platform

import (
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// adapterInfo is the subset of a Windows network adapter the mesh resource
// ledger tracks. It is read in-process through the IP helper API so the
// connect path never has to start PowerShell.
type adapterInfo struct {
	Name       string // interface alias, e.g. "LANMesh"
	GUID       string // device interface GUID, e.g. {7CA4C178-...}
	IfIndex    uint32
	IfType     uint32
	OperStatus uint32
	MTU        uint32
	LUID       uint64
}

// listAdapters is a seam for tests; production reads the Win32 adapter table.
var listAdapters = windowsAdapters

func windowsAdapters() ([]adapterInfo, error) {
	// GetAdaptersAddresses reports the required size through ERROR_BUFFER_OVERFLOW.
	size := uint32(15 * 1024)
	for attempt := 0; ; attempt++ {
		buffer := make([]byte, size)
		first := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buffer[0]))
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC,
			windows.GAA_FLAG_SKIP_ANYCAST|windows.GAA_FLAG_SKIP_MULTICAST|windows.GAA_FLAG_SKIP_DNS_SERVER,
			0, first, &size)
		if err == nil {
			return collectAdapters(first), nil
		}
		if err != windows.ERROR_BUFFER_OVERFLOW || attempt >= 4 {
			return nil, fmt.Errorf("enumerate network adapters: %w", err)
		}
	}
}

func collectAdapters(first *windows.IpAdapterAddresses) []adapterInfo {
	var adapters []adapterInfo
	for node := first; node != nil; node = node.Next {
		adapters = append(adapters, adapterInfo{
			Name:       windows.UTF16PtrToString(node.FriendlyName),
			GUID:       windows.BytePtrToString(node.AdapterName),
			IfIndex:    node.IfIndex,
			IfType:     node.IfType,
			OperStatus: node.OperStatus,
			MTU:        node.Mtu,
			LUID:       node.Luid,
		})
	}
	return adapters
}

// lookupAdapter resolves an interface alias to its adapter table entry. A
// missing adapter is reported as present=false rather than an error so callers
// can distinguish "already gone" from "could not be queried".
func lookupAdapter(name string) (adapterInfo, bool, error) {
	adapters, err := listAdapters()
	if err != nil {
		return adapterInfo{}, false, fmt.Errorf("query adapter %q: %w", name, err)
	}
	var found []adapterInfo
	for _, adapter := range adapters {
		if strings.EqualFold(adapter.Name, name) {
			found = append(found, adapter)
		}
	}
	switch len(found) {
	case 0:
		return adapterInfo{}, false, nil
	case 1:
		return found[0], true, nil
	default:
		return adapterInfo{}, true, fmt.Errorf("%w: adapter %q is ambiguous", ErrResourceNotOwned, name)
	}
}

func queryAdapterGUID(name string) (string, bool, error) {
	adapter, present, err := lookupAdapter(name)
	if err != nil || !present {
		return "", present, err
	}
	guid, err := normalizeGUID(adapter.GUID)
	if err != nil {
		return "", true, fmt.Errorf("%w: adapter %q GUID: %v", ErrResourceNotOwned, name, err)
	}
	return guid, true, nil
}
