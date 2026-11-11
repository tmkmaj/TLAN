//go:build windows

package platform

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"
)

type fakeCommand struct {
	Name string
	Args []string
}

func (c fakeCommand) line() string { return c.Name + " " + strings.Join(c.Args, " ") }

type fakeWindowsRunner struct {
	scripts  []string
	commands []fakeCommand
	handle   func(string) ([]byte, error)
	native   func(fakeCommand) ([]byte, error)
}

func (r *fakeWindowsRunner) Run(name string, args ...string) ([]byte, error) {
	script := decodePowerShellCommand(args)
	if script != "" {
		r.scripts = append(r.scripts, script)
		if r.handle == nil {
			return nil, nil
		}
		return r.handle(script)
	}
	command := fakeCommand{Name: filepath.Base(name), Args: append([]string(nil), args...)}
	r.commands = append(r.commands, command)
	if r.native == nil {
		return nil, nil
	}
	return r.native(command)
}

func decodePowerShellCommand(args []string) string {
	for i := 0; i+1 < len(args); i++ {
		if args[i] != "-EncodedCommand" {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(args[i+1])
		if err != nil || len(raw)%2 != 0 {
			return ""
		}
		units := make([]uint16, len(raw)/2)
		for j := range units {
			units[j] = binary.LittleEndian.Uint16(raw[j*2:])
		}
		return string(utf16.Decode(units))
	}
	return ""
}

type fakeFirewall struct {
	rules   map[string]firewallState
	added   []firewallSpec
	removed []string
}

func (f *fakeFirewall) Add(spec firewallSpec) error {
	f.added = append(f.added, spec)
	return nil
}

func (f *fakeFirewall) Lookup(name string) (firewallState, error) {
	return f.rules[name], nil
}

func (f *fakeFirewall) Remove(name string) error {
	f.removed = append(f.removed, name)
	return nil
}

func stubFirewall(t *testing.T, replacement firewallControl) {
	t.Helper()
	previous := firewall
	firewall = replacement
	t.Cleanup(func() { firewall = previous })
}

func TestWindowsCleanupFirewallRemovesOwnedRule(t *testing.T) {
	record := makeOwnedRecord(t, "instance", ResourceFirewallRule, "LANMesh-LANMesh", "10.44.0.0/24", "LANMesh-LANMesh", "{22222222-2222-2222-2222-222222222222}")
	fake := &fakeFirewall{rules: map[string]firewallState{"LANMesh-LANMesh": {Found: true, Remote: "10.44.0.0/24"}}}
	stubFirewall(t, fake)
	if err := CleanupResourceWithRunner(record, &fakeWindowsRunner{}); err != nil {
		t.Fatal(err)
	}
	if len(fake.removed) != 1 || fake.removed[0] != "LANMesh-LANMesh" {
		t.Fatalf("removed = %#v", fake.removed)
	}
}

func TestWindowsCleanupFirewallRejectsRemoteMismatch(t *testing.T) {
	record := makeOwnedRecord(t, "instance", ResourceFirewallRule, "LANMesh-LANMesh", "10.44.0.0/24", "LANMesh-LANMesh", "{22222222-2222-2222-2222-222222222222}")
	fake := &fakeFirewall{rules: map[string]firewallState{"LANMesh-LANMesh": {Found: true, Remote: "10.99.0.0/24"}}}
	stubFirewall(t, fake)
	if err := CleanupResourceWithRunner(record, &fakeWindowsRunner{}); !errors.Is(err, ErrResourceNotOwned) {
		t.Fatalf("cleanup error = %v, want ErrResourceNotOwned", err)
	}
	if len(fake.removed) != 0 {
		t.Fatalf("mismatched rule was removed: %#v", fake.removed)
	}
}

func TestWindowsCleanupFirewallIgnoresMissingRule(t *testing.T) {
	record := makeOwnedRecord(t, "instance", ResourceFirewallRule, "LANMesh-LANMesh", "10.44.0.0/24", "LANMesh-LANMesh", "{22222222-2222-2222-2222-222222222222}")
	fake := &fakeFirewall{rules: map[string]firewallState{}}
	stubFirewall(t, fake)
	if err := CleanupResourceWithRunner(record, &fakeWindowsRunner{}); err != nil {
		t.Fatal(err)
	}
	if len(fake.removed) != 0 {
		t.Fatalf("missing rule was removed: %#v", fake.removed)
	}
}

// Windows Firewall reports remote addresses as address/mask, while the ledger
// stores CIDR. Both spellings must compare equal.
func TestNormalizePrefixText(t *testing.T) {
	tests := map[string]string{
		"10.242.0.0/24":            "10.242.0.0/24",
		"10.242.0.0/255.255.255.0": "10.242.0.0/24",
		"10.242.0.7/255.255.255.0": "10.242.0.0/24",
		" 10.44.0.0/16 ":           "10.44.0.0/16",
	}
	for input, want := range tests {
		got, err := normalizePrefixText(input)
		if err != nil {
			t.Fatalf("normalizePrefixText(%q): %v", input, err)
		}
		if got.String() != want {
			t.Fatalf("normalizePrefixText(%q) = %s, want %s", input, got, want)
		}
	}
	if _, err := normalizePrefixText("not-an-address"); err == nil {
		t.Fatal("normalizePrefixText accepted garbage")
	}
}

func TestWindowsCleanupAdapterRequiresExactGUID(t *testing.T) {
	record := makeOwnedRecord(t, "instance", ResourceWintunInterface, "LANMesh", "10.44.0.1/24", "{11111111-1111-1111-1111-111111111111}", "{11111111-1111-1111-1111-111111111111}")
	restore := stubAdapters(t, []adapterInfo{{Name: "LANMesh", GUID: "{11111111-1111-1111-1111-111111111111}"}})
	defer restore()
	runner := &fakeWindowsRunner{handle: func(script string) ([]byte, error) {
		if !strings.Contains(script, "Remove-NetAdapter") {
			t.Fatalf("unexpected script: %s", script)
		}
		return nil, nil
	}}
	if err := CleanupResourceWithRunner(record, runner); err != nil {
		t.Fatal(err)
	}
	if len(runner.scripts) != 1 {
		t.Fatalf("cleanup scripts = %#v", runner.scripts)
	}
}

func TestWindowsCleanupAdapterMismatchDoesNotRemove(t *testing.T) {
	record := makeOwnedRecord(t, "instance", ResourceWintunInterface, "LANMesh", "10.44.0.1/24", "{11111111-1111-1111-1111-111111111111}", "{11111111-1111-1111-1111-111111111111}")
	restore := stubAdapters(t, []adapterInfo{{Name: "LANMesh", GUID: "{99999999-9999-9999-9999-999999999999}"}})
	defer restore()
	runner := &fakeWindowsRunner{handle: func(script string) ([]byte, error) {
		t.Fatalf("mismatched adapter must not be removed: %s", script)
		return nil, nil
	}}
	if err := CleanupResourceWithRunner(record, runner); !errors.Is(err, ErrResourceNotOwned) {
		t.Fatalf("cleanup error = %v, want ErrResourceNotOwned", err)
	}
}

func TestWindowsCleanupRouteUsesExactPrefix(t *testing.T) {
	record := makeOwnedRecord(t, "instance", ResourceBroadcastRoute, "LANMesh", "255.255.255.255/32", "", "{11111111-1111-1111-1111-111111111111}")
	restore := stubAdapters(t, []adapterInfo{{Name: "LANMesh", GUID: "{11111111-1111-1111-1111-111111111111}"}})
	defer restore()
	runner := &fakeWindowsRunner{native: func(command fakeCommand) ([]byte, error) {
		switch strings.Join(command.Args, " ") {
		case "interface ipv4 show route store=active":
			return []byte(routeTableSample), nil
		case "interface ipv4 delete route prefix=255.255.255.255/32 interface=LANMesh store=active":
			return []byte("Ok.\r\n"), nil
		default:
			t.Fatalf("unexpected command: %s", command.line())
			return nil, nil
		}
	}}
	if err := CleanupResourceWithRunner(record, runner); err != nil {
		t.Fatal(err)
	}
	if len(runner.commands) != 2 {
		t.Fatalf("commands = %#v", runner.commands)
	}
	if joined := strings.Join(runner.commands[1].Args, " "); !strings.Contains(joined, "delete route prefix=255.255.255.255/32 interface=LANMesh") {
		t.Fatalf("delete command = %q", joined)
	}
	if strings.Contains(strings.Join(runner.commands[0].Args, " "), "*") {
		t.Fatal("route query used a wildcard")
	}
}

// routeTableSample is verbatim "netsh interface ipv4 show route" output.
const routeTableSample = "\r\n" +
	"Publish  Type      Met  Prefix                    Idx  Gateway/Interface Name\r\n" +
	"-------  --------  ---  ------------------------  ---  ------------------------\r\n" +
	"No       Manual    9256  0.0.0.0/0                   9  26.0.0.1\r\n" +
	"No       Manual    0    0.0.0.0/0                  10  172.16.85.254\r\n" +
	"No       System    256  127.0.0.0/8                 1  Loopback Pseudo-Interface 1\r\n" +
	"No       Manual    5    255.255.255.255/32         12  LANMesh\r\n" +
	"No       Manual    5    255.255.255.255/32          9  Radmin VPN\r\n"

func TestRoutePresentMatchesPrefixAndInterface(t *testing.T) {
	runner := &fakeWindowsRunner{native: func(command fakeCommand) ([]byte, error) {
		return []byte(routeTableSample), nil
	}}
	present, err := routePresent(runner, "LANMesh", "255.255.255.255/32")
	if err != nil || !present {
		t.Fatalf("routePresent(LANMesh) = %v, %v", present, err)
	}
	present, err = routePresent(runner, "Radmin VPN", "255.255.255.255/32")
	if err != nil || !present {
		t.Fatalf("routePresent(Radmin VPN) = %v, %v", present, err)
	}
	present, err = routePresent(runner, "LANMesh", "224.0.0.0/4")
	if err != nil || present {
		t.Fatalf("routePresent(missing) = %v, %v", present, err)
	}
	present, err = routePresent(runner, "以太网", "255.255.255.255/32")
	if err != nil || present {
		t.Fatalf("routePresent(other interface) = %v, %v", present, err)
	}
}

func TestEnsureIPv4RouteFallsBackToSetWhenRouteExists(t *testing.T) {
	runner := &fakeWindowsRunner{native: func(command fakeCommand) ([]byte, error) {
		joined := strings.Join(command.Args, " ")
		if strings.Contains(joined, " add route ") {
			return []byte("The object already exists.\r\n"), errors.New("exit status 1")
		}
		if strings.Contains(joined, " set route ") {
			return []byte("Ok.\r\n"), nil
		}
		return nil, errors.New("unexpected command " + joined)
	}}
	if err := ensureIPv4Route(runner, "LANMesh", "255.255.255.255/32", 5); err != nil {
		t.Fatal(err)
	}
	if len(runner.commands) != 2 || !strings.Contains(strings.Join(runner.commands[1].Args, " "), "set route") {
		t.Fatalf("commands = %#v", runner.commands)
	}
}

func TestEnsureIPv4RouteAddsWhenMissing(t *testing.T) {
	runner := &fakeWindowsRunner{native: func(command fakeCommand) ([]byte, error) {
		return []byte("Ok.\r\n"), nil
	}}
	if err := ensureIPv4Route(runner, "LANMesh", "224.0.0.0/4", 5); err != nil {
		t.Fatal(err)
	}
	if len(runner.commands) != 1 {
		t.Fatalf("commands = %#v", runner.commands)
	}
	joined := strings.Join(runner.commands[0].Args, " ")
	if !strings.Contains(joined, "add route prefix=224.0.0.0/4 interface=LANMesh metric=5 store=active") {
		t.Fatalf("add command = %q", joined)
	}
}

func TestWindowsAdapterQueryTreatsMissingAdapterAsAbsent(t *testing.T) {
	restore := stubAdapters(t, []adapterInfo{{Name: "Other", GUID: "{11111111-1111-1111-1111-111111111111}"}})
	defer restore()
	if guid, present, err := queryAdapterGUID("LANMesh-Test"); err != nil || present || guid != "" {
		t.Fatalf("missing adapter result = guid=%q present=%v err=%v", guid, present, err)
	}
	if guid, present, err := queryAdapterGUID("Other"); err != nil || !present || guid != "{11111111-1111-1111-1111-111111111111}" {
		t.Fatalf("present adapter result = guid=%q present=%v err=%v", guid, present, err)
	}
}

func stubAdapters(t *testing.T, adapters []adapterInfo) func() {
	t.Helper()
	previous := listAdapters
	listAdapters = func() ([]adapterInfo, error) { return adapters, nil }
	return func() { listAdapters = previous }
}
