//go:build windows

package platform

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"unicode/utf16"

	"golang.org/x/sys/windows"
)

func runPowerShell(runner Runner, script string) ([]byte, error) {
	if runner == nil {
		runner = SystemRunner{}
	}
	units := utf16.Encode([]rune("$ErrorActionPreference='Stop'; " + script))
	data := make([]byte, len(units)*2)
	for i, value := range units {
		binary.LittleEndian.PutUint16(data[i*2:], value)
	}
	return runner.Run(systemPowerShell(), "-NoProfile", "-NonInteractive", "-EncodedCommand", base64.StdEncoding.EncodeToString(data))
}

func cleanupResource(record ResourceRecord, runner Runner) error {
	switch record.Type {
	case ResourceWireGuardTransport, ResourcePlainTransport:
		return nil
	case ResourceWintunInterface:
		return cleanupWintunInterface(record, runner)
	case ResourceIPv4Address:
		return cleanupIPv4Address(record, runner)
	case ResourceMTU, ResourceMetric:
		return cleanupInterfaceAttribute(record, runner)
	case ResourceBroadcastRoute, ResourceMulticastRoute:
		return cleanupRoute(record, runner)
	case ResourceFirewallRule:
		return cleanupFirewallRule(record, runner)
	default:
		return fmt.Errorf("%w: %s", ErrResourceUnsupported, record.Type)
	}
}

func cleanupWintunInterface(record ResourceRecord, runner Runner) error {
	guid, present, err := queryAdapterGUID(record.Name)
	if err != nil {
		return err
	}
	if !present {
		return nil
	}
	if !sameGUID(guid, record.ResourceID) {
		return fmt.Errorf("%w: adapter %q GUID %q does not match %q", ErrResourceNotOwned, record.Name, guid, record.ResourceID)
	}
	if _, err := runPowerShell(runner, "Remove-NetAdapter -Name "+psQuote(record.Name)+" -Confirm:$false -ErrorAction Stop | Out-Null"); err != nil {
		return fmt.Errorf("remove Wintun adapter %q: %w", record.Name, err)
	}
	return nil
}

func cleanupIPv4Address(record ResourceRecord, runner Runner) error {
	prefix, err := netip.ParsePrefix(record.Prefix)
	if err != nil || !prefix.Addr().Is4() {
		return fmt.Errorf("%w: invalid IPv4 address prefix %q", ErrResourceNotOwned, record.Prefix)
	}
	present, err := verifyAdapterParent(record)
	if err != nil || !present {
		return err
	}
	query := "$addresses=@(Get-NetIPAddress -InterfaceAlias " + psQuote(record.Name) +
		" -AddressFamily IPv4 -IPAddress " + psQuote(prefix.Addr().String()) +
		" -PrefixLength " + strconv.Itoa(prefix.Bits()) +
		" -ErrorAction SilentlyContinue); if ($addresses.Count -eq 0) { exit 0 }; $addresses | Select-Object -ExpandProperty IPAddress"
	output, err := runPowerShell(runner, query)
	if err != nil {
		return fmt.Errorf("query IPv4 address %q: %w", record.Prefix, err)
	}
	values := nonEmptyLines(output)
	if len(values) == 0 {
		return nil
	}
	if len(values) != 1 || !strings.EqualFold(strings.TrimSpace(values[0]), prefix.Addr().String()) {
		return fmt.Errorf("%w: IPv4 address %q is ambiguous", ErrResourceNotOwned, record.Prefix)
	}
	command := "Remove-NetIPAddress -InterfaceAlias " + psQuote(record.Name) +
		" -IPAddress " + psQuote(prefix.Addr().String()) +
		" -PrefixLength " + strconv.Itoa(prefix.Bits()) +
		" -Confirm:$false -ErrorAction Stop | Out-Null"
	if _, err := runPowerShell(runner, command); err != nil {
		return fmt.Errorf("remove IPv4 address %q: %w", record.Prefix, err)
	}
	return nil
}

func cleanupInterfaceAttribute(record ResourceRecord, runner Runner) error {
	present, err := verifyAdapterParent(record)
	if err != nil || !present {
		return err
	}
	// MTU and metric are attributes of the exact adapter. Removing the adapter
	// is the only deletion action; verify its identity and leave the value alone.
	return nil
}

func cleanupRoute(record ResourceRecord, runner Runner) error {
	prefix, err := netip.ParsePrefix(record.Prefix)
	if err != nil || !prefix.Addr().Is4() {
		return fmt.Errorf("%w: invalid route prefix %q", ErrResourceNotOwned, record.Prefix)
	}
	present, err := verifyAdapterParent(record)
	if err != nil || !present {
		return err
	}
	present, err = routePresent(runner, record.Name, prefix.String())
	if err != nil {
		return err
	}
	if !present {
		return nil
	}
	return deleteIPv4Route(runner, record.Name, prefix.String())
}

func cleanupFirewallRule(record ResourceRecord, runner Runner) error {
	query := "$rules=@(Get-NetFirewallRule -Name " + psQuote(record.Name) +
		" -ErrorAction SilentlyContinue); if ($rules.Count -eq 0) { exit 0 }; $rules | Select-Object -ExpandProperty InstanceID"
	output, err := runPowerShell(runner, query)
	if err != nil {
		return fmt.Errorf("query firewall rule %q: %w", record.Name, err)
	}
	values := nonEmptyLines(output)
	if len(values) == 0 {
		return nil
	}
	if len(values) != 1 {
		return fmt.Errorf("%w: firewall rule %q is ambiguous", ErrResourceNotOwned, record.Name)
	}
	ruleID, err := normalizeFirewallRuleID(values[0])
	if err != nil || !sameFirewallRuleID(ruleID, record.ResourceID) {
		return fmt.Errorf("%w: firewall rule %q identity does not match", ErrResourceNotOwned, record.Name)
	}
	if _, err := runPowerShell(runner, "Remove-NetFirewallRule -Name "+psQuote(record.Name)+" -Confirm:$false -ErrorAction Stop | Out-Null"); err != nil {
		return fmt.Errorf("remove firewall rule %q: %w", record.Name, err)
	}
	return nil
}

func verifyAdapterParent(record ResourceRecord) (bool, error) {
	guid, present, err := queryAdapterGUID(record.Name)
	if err != nil {
		return false, err
	}
	if !present {
		return false, nil
	}
	if !sameGUID(guid, record.ParentID) {
		return false, fmt.Errorf("%w: adapter %q GUID %q does not match parent %q", ErrResourceNotOwned, record.Name, guid, record.ParentID)
	}
	return true, nil
}

func normalizeFirewallRuleID(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", errors.New("empty firewall rule identity")
	}
	if guid, err := normalizeGUID(value); err == nil {
		return guid, nil
	}
	if !validExactName(value) || len(value) > 256 {
		return "", errors.New("invalid firewall rule identity")
	}
	return value, nil
}

func sameFirewallRuleID(a, b string) bool {
	first, err := normalizeFirewallRuleID(a)
	if err != nil {
		return false
	}
	second, err := normalizeFirewallRuleID(b)
	if err != nil {
		return false
	}
	return strings.EqualFold(first, second)
}
func normalizeGUID(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", errors.New("empty GUID")
	}
	guid, err := windows.GUIDFromString(value)
	if err != nil {
		return "", err
	}
	return guid.String(), nil
}

func sameGUID(a, b string) bool {
	first, err := normalizeGUID(a)
	if err != nil {
		return false
	}
	second, err := normalizeGUID(b)
	if err != nil {
		return false
	}
	return strings.EqualFold(first, second)
}

func nonEmptyLines(output []byte) []string {
	var values []string
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line != "" {
			values = append(values, line)
		}
	}
	return values
}
