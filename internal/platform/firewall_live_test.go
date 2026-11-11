//go:build windows

package platform

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestLiveFirewallRuleRoundTrip exercises the real Windows Firewall policy
// object. It needs administrator rights and mutates the machine, so it only
// runs when explicitly requested.
func TestLiveFirewallRuleRoundTrip(t *testing.T) {
	if os.Getenv("TMK_FIREWALL_LIVE") == "" {
		t.Skip("set TMK_FIREWALL_LIVE=1 to exercise the live Windows Firewall policy")
	}
	adapters, err := windowsAdapters()
	if err != nil {
		t.Fatal(err)
	}
	var alias string
	for _, adapter := range adapters {
		if adapter.Name != "" && adapter.GUID != "" && !strings.Contains(adapter.Name, "Loopback") && !strings.Contains(adapter.Name, "Teredo") {
			alias = adapter.Name
			break
		}
	}
	if alias == "" {
		t.Skip("no physical adapter available")
	}
	const name = "TmkNetworkLAN-LiveTest"
	_ = firewall.Remove(name)
	spec := firewallSpec{Name: name, Description: "TmkNetworkLAN live test", Interfaces: []string{alias}, Remote: "10.242.0.0/24"}
	if err := firewall.Add(spec); err != nil {
		t.Fatalf("Add: %v", err)
	}
	defer firewall.Remove(name)

	shown := netshFirewallShow(t, name)
	if !strings.Contains(shown, "10.242.0.0/24") {
		t.Fatalf("rule not visible to the firewall service:\n%s", shown)
	}
	if !strings.Contains(shown, "Allow") || !strings.Contains(shown, "In") {
		t.Fatalf("rule has unexpected action/direction:\n%s", shown)
	}

	state, err := firewall.Lookup(name)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if !state.Found || strings.TrimSpace(state.Remote) != "10.242.0.0/24" {
		t.Fatalf("Lookup = %+v", state)
	}
	if err := firewall.Remove(name); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	state, err = firewall.Lookup(name)
	if err != nil {
		t.Fatalf("Lookup after remove: %v", err)
	}
	if state.Found {
		t.Fatal("rule survived removal")
	}
}

func netshFirewallShow(t *testing.T, name string) string {
	t.Helper()
	netsh := filepath.Join(os.Getenv("SystemRoot"), "System32", "netsh.exe")
	output, err := exec.Command(netsh, "advfirewall", "firewall", "show", "rule", "name="+name, "verbose").CombinedOutput()
	if err != nil {
		t.Fatalf("netsh show rule %s: %v: %s", name, err, output)
	}
	return string(output)
}
