//go:build windows

package platform

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/tun"
)

func commandWindows(program string, args ...string) error {
	return commandWindowsWithRunner(SystemRunner{}, program, args...)
}

func commandWindowsWithRunner(runner Runner, program string, args ...string) error {
	_, err := commandOutputWithRunner(runner, program, args...)
	return err
}

// commandOutputWithRunner runs a native System32 utility and returns its stdout
// for inspection. It never invokes a shell or a scripting engine.
func commandOutputWithRunner(runner Runner, program string, args ...string) ([]byte, error) {
	if runner == nil {
		runner = SystemRunner{}
	}
	path := filepath.Join(os.Getenv("SystemRoot"), "System32", program)
	return runner.Run(path, args...)
}

func openTunnel(name string, address netip.Prefix, mtu int, options TunnelOptions) (*IPTunnel, error) {
	if name == "" {
		name = "LANMesh"
	}
	// Do not reconfigure a pre-existing interface that another application owns.
	if _, err := net.InterfaceByName(name); err == nil {
		return nil, fmt.Errorf("interface %q already exists; close the other TmkNetworkLAN instance first", name)
	}
	requestedGUID, err := windows.GenerateGUID()
	if err != nil {
		return nil, fmt.Errorf("generate Wintun adapter GUID: %w", err)
	}
	device, err := tun.CreateTUNWithRequestedGUID(name, &requestedGUID, mtu)
	if err != nil {
		return nil, fmt.Errorf("create Wintun: %w (administrator permission and wintun.dll beside EXE are required)", err)
	}
	if options.Runner == nil {
		options.Runner = SystemRunner{}
	}
	if options.Cleaner == nil {
		options.Cleaner = func(record ResourceRecord) error {
			return CleanupResourceWithRunner(record, options.Runner)
		}
	}
	interfaceGUID, err := waitForAdapterGUID(name)
	if err != nil {
		_ = device.Close()
		return nil, err
	}

	var records []ResourceRecord
	tracked := make(map[ResourceKey]bool)
	addRecord := func(record ResourceRecord) error {
		// Append before persisting so a ledger write failure can still trigger
		// an exact in-process rollback. Untracked records use a direct cleaner
		// and are never added to a ledger we could not write.
		records = append(records, record)
		if options.Ledger == nil {
			tracked[record.Key()] = true
			return nil
		}
		if err := options.Ledger.Add(record); err != nil {
			return err
		}
		tracked[record.Key()] = true
		return nil
	}
	cleanupRecord := func(record ResourceRecord) error {
		if options.Ledger != nil && tracked[record.Key()] {
			return trackedCleanup(options.Ledger, record, options.Cleaner)
		}
		return options.Cleaner(record)
	}
	rollback := func(cause error) error {
		var cleanupErrs []error
		for i := len(records) - 1; i >= 0; i-- {
			if records[i].Type == ResourceWintunInterface {
				continue
			}
			if err := cleanupRecord(records[i]); err != nil {
				cleanupErrs = append(cleanupErrs, err)
			}
		}
		if err := device.Close(); err != nil {
			cleanupErrs = append(cleanupErrs, err)
		}
		for i := len(records) - 1; i >= 0; i-- {
			if records[i].Type != ResourceWintunInterface {
				continue
			}
			if err := cleanupRecord(records[i]); err != nil {
				cleanupErrs = append(cleanupErrs, err)
			}
		}
		return errors.Join(append([]error{cause}, cleanupErrs...)...)
	}

	interfaceRecord, err := NewResourceRecord(options.InstanceID, ResourceWintunInterface, name, address.String(), interfaceGUID)
	if err != nil {
		return nil, rollback(err)
	}
	interfaceRecord.ParentID = interfaceGUID
	if err := addRecord(interfaceRecord); err != nil {
		return nil, rollback(err)
	}

	mask := net.IP(net.CIDRMask(address.Bits(), 32)).String()
	firewallName := "LANMesh-" + name
	// Create the limited-broadcast and multicast routes before assigning the
	// address. This preserves the original Windows setup order and avoids
	// colliding with routes Windows may add for a newly assigned address.
	for _, prefix := range []string{"255.255.255.255/32", "224.0.0.0/4"} {
		if err := ensureIPv4Route(options.Runner, name, prefix, 5); err != nil {
			return nil, rollback(err)
		}
		routeType := ResourceBroadcastRoute
		if strings.HasPrefix(prefix, "224.") {
			routeType = ResourceMulticastRoute
		}
		routeRecord, err := NewResourceRecord(options.InstanceID, routeType, name, prefix, "")
		if err != nil {
			return nil, rollback(err)
		}
		routeRecord.ParentID = interfaceGUID
		if err := addRecord(routeRecord); err != nil {
			return nil, rollback(err)
		}
	}
	steps := [][]string{
		{"interface", "ipv4", "set", "address", "name=" + name, "source=static", "address=" + address.Addr().String(), "mask=" + mask, "gateway=none", "store=active"},
		{"interface", "ipv4", "set", "subinterface", name, "mtu=" + strconv.Itoa(mtu), "store=active"},
		{"interface", "ipv4", "set", "interface", name, "metric=5", "forwarding=disabled"},
	}
	for _, args := range steps {
		if err := commandWindowsWithRunner(options.Runner, "netsh.exe", args...); err != nil {
			return nil, rollback(err)
		}
	}
	addressRecord, err := NewResourceRecord(options.InstanceID, ResourceIPv4Address, name, address.String(), "")
	if err != nil {
		return nil, rollback(err)
	}
	addressRecord.ParentID = interfaceGUID
	if err := addRecord(addressRecord); err != nil {
		return nil, rollback(err)
	}
	mtuRecord, err := NewResourceRecord(options.InstanceID, ResourceMTU, name, strconv.Itoa(mtu), "")
	if err != nil {
		return nil, rollback(err)
	}
	mtuRecord.ParentID = interfaceGUID
	if err := addRecord(mtuRecord); err != nil {
		return nil, rollback(err)
	}
	metricRecord, err := NewResourceRecord(options.InstanceID, ResourceMetric, name, "5", "")
	if err != nil {
		return nil, rollback(err)
	}
	metricRecord.ParentID = interfaceGUID
	if err := addRecord(metricRecord); err != nil {
		return nil, rollback(err)
	}

	// Scope the inbound exception to this virtual interface, including broadcast
	// destinations; never disable the firewall or open the physical interface.
	firewallScript := "New-NetFirewallRule -Name " + psQuote(firewallName) + " -DisplayName " + psQuote(firewallName) + " -Direction Inbound -Action Allow -Profile Any -InterfaceAlias " + psQuote(name) + " -RemoteAddress " + psQuote(address.Masked().String()) + " -ErrorAction Stop | Out-Null"
	if err := firewallScriptWithRunner(options.Runner, firewallScript); err != nil {
		return nil, rollback(err)
	}
	ruleID, err := firewallRuleID(options.Runner, firewallName)
	if err != nil {
		_ = firewallScriptWithRunner(options.Runner, "Remove-NetFirewallRule -Name "+psQuote(firewallName)+" -Confirm:$false -ErrorAction Stop | Out-Null")
		return nil, rollback(err)
	}
	firewallRecord, err := NewResourceRecord(options.InstanceID, ResourceFirewallRule, firewallName, address.Masked().String(), ruleID)
	if err != nil {
		return nil, rollback(err)
	}
	firewallRecord.ParentID = interfaceGUID
	if err := addRecord(firewallRecord); err != nil {
		return nil, rollback(err)
	}

	cleanupBefore := func() error {
		var errs []error
		for i := len(records) - 1; i >= 0; i-- {
			if records[i].Type == ResourceWintunInterface {
				continue
			}
			if err := cleanupRecord(records[i]); err != nil {
				errs = append(errs, err)
			}
		}
		return errors.Join(errs...)
	}
	cleanupAfter := func() error {
		var errs []error
		for i := len(records) - 1; i >= 0; i-- {
			if records[i].Type != ResourceWintunInterface {
				continue
			}
			if err := cleanupRecord(records[i]); err != nil {
				errs = append(errs, err)
			}
		}
		return errors.Join(errs...)
	}
	repair := func() error {
		iface, err := net.InterfaceByName(name)
		if err != nil {
			return fmt.Errorf("mesh adapter %q is missing: %w", name, err)
		}
		// Fast path: while the adapter still owns its assigned address there is
		// nothing to heal, so the periodic check stays one cheap lookup.
		if addrs, err := iface.Addrs(); err == nil && addressPresent(addrs, address.Addr()) {
			return nil
		}
		// Windows re-created the adapter (driver update, PnP restart, reinstall)
		// and every piece of configuration below was lost along with it.
		for _, prefix := range []string{"255.255.255.255/32", "224.0.0.0/4"} {
			script := "$route=Get-NetRoute -InterfaceAlias " + psQuote(name) + " -DestinationPrefix " + psQuote(prefix) + " -PolicyStore ActiveStore -ErrorAction SilentlyContinue; if ($null -eq $route) { New-NetRoute -InterfaceAlias " + psQuote(name) + " -DestinationPrefix " + psQuote(prefix) + " -RouteMetric 5 -PolicyStore ActiveStore -ErrorAction Stop | Out-Null } else { $route | Set-NetRoute -RouteMetric 5 -ErrorAction Stop | Out-Null }"
			if err := firewallScriptWithRunner(options.Runner, script); err != nil {
				return fmt.Errorf("repair route %s: %w", prefix, err)
			}
		}
		steps := [][]string{
			{"interface", "ipv4", "set", "address", "name=" + name, "source=static", "address=" + address.Addr().String(), "mask=" + mask, "gateway=none", "store=active"},
			{"interface", "ipv4", "set", "subinterface", name, "mtu=" + strconv.Itoa(mtu), "store=active"},
			{"interface", "ipv4", "set", "interface", name, "metric=5", "forwarding=disabled"},
		}
		for _, args := range steps {
			if err := commandWindowsWithRunner(options.Runner, "netsh.exe", args...); err != nil {
				return fmt.Errorf("repair adapter %q: %w", name, err)
			}
		}
		script := "$rule=Get-NetFirewallRule -Name " + psQuote(firewallName) + " -ErrorAction SilentlyContinue; if ($null -eq $rule) { New-NetFirewallRule -Name " + psQuote(firewallName) + " -DisplayName " + psQuote(firewallName) + " -Direction Inbound -Action Allow -Profile Any -InterfaceAlias " + psQuote(name) + " -RemoteAddress " + psQuote(address.Masked().String()) + " -ErrorAction Stop | Out-Null } else { Set-NetFirewallRule -Name " + psQuote(firewallName) + " -Enabled True -Action Allow -Profile Any -ErrorAction Stop | Out-Null }"
		if err := firewallScriptWithRunner(options.Runner, script); err != nil {
			return fmt.Errorf("repair firewall rule %q: %w", firewallName, err)
		}
		return nil
	}

	return &IPTunnel{
		repair:        repair,
		Device:        device,
		cleanupBefore: cleanupBefore,
		cleanupAfter:  cleanupAfter,
		ledger:        options.Ledger,
		resources:     append([]ResourceRecord(nil), records...),
	}, nil
}

// addressPresent reports whether want is assigned to an interface, ignoring
// IPv4-mapped IPv6 forms that Go can report for a v4 address.
func addressPresent(addrs []net.Addr, want netip.Addr) bool {
	for _, addr := range addrs {
		var ip net.IP
		switch value := addr.(type) {
		case *net.IPNet:
			ip = value.IP
		case *net.IPAddr:
			ip = value.IP
		default:
			continue
		}
		if parsed, ok := netip.AddrFromSlice(ip); ok && parsed.Unmap() == want {
			return true
		}
	}
	return false
}

func psQuote(value string) string { return "'" + strings.ReplaceAll(value, "'", "''") + "'" }

func waitForAdapterGUID(name string) (string, error) {
	var lastErr error
	for attempt := 0; attempt < 10; attempt++ {
		guid, present, err := queryAdapterGUID(name)
		if err != nil {
			lastErr = err
		} else if present {
			return guid, nil
		}
		if attempt < 9 {
			time.Sleep(100 * time.Millisecond)
		}
	}
	if lastErr != nil {
		return "", lastErr
	}
	return "", fmt.Errorf("Wintun adapter %q was not visible after creation", name)
}
func firewallScript(script string) error {
	return firewallScriptWithRunner(SystemRunner{}, script)
}

func firewallScriptWithRunner(runner Runner, script string) error {
	_, err := runPowerShell(runner, script)
	return err
}

func firewallRuleID(runner Runner, name string) (string, error) {
	output, err := runPowerShell(runner, "Get-NetFirewallRule -Name "+psQuote(name)+" -ErrorAction Stop | Select-Object -ExpandProperty InstanceID")
	if err != nil {
		return "", fmt.Errorf("read firewall rule identity: %w", err)
	}
	values := nonEmptyLines(output)
	if len(values) != 1 {
		return "", fmt.Errorf("firewall rule %q did not return exactly one identity", name)
	}
	return normalizeFirewallRuleID(values[0])
}
