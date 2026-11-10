package mesh

import (
	"net/netip"

	"github.com/private-radminlan/lanmesh/core"
	"testing"
	"time"
)

func TestCandidateFingerprintTracksEnvironment(t *testing.T) {
	base := []candidateInterfaceSnapshot{
		{Name: "Wi-Fi", Up: true, IPv4: []string{"192.168.1.10", "10.20.0.10"}},
	}
	reordered := []candidateInterfaceSnapshot{
		{Name: "Wi-Fi", Up: true, IPv4: []string{"10.20.0.10", "192.168.1.10"}},
	}
	if got, want := candidateFingerprint(reordered, true), candidateFingerprint(base, true); got != want {
		t.Fatalf("order changed fingerprint: %q != %q", got, want)
	}

	tests := []struct {
		name          string
		interfaces    []candidateInterfaceSnapshot
		stunAvailable bool
	}{
		{
			name:          "address",
			interfaces:    []candidateInterfaceSnapshot{{Name: "Wi-Fi", Up: true, IPv4: []string{"192.168.1.11", "10.20.0.10"}}},
			stunAvailable: true,
		},
		{
			name:          "interface",
			interfaces:    []candidateInterfaceSnapshot{{Name: "Ethernet", Up: true, IPv4: []string{"192.168.1.10", "10.20.0.10"}}},
			stunAvailable: true,
		},
		{
			name:          "up_state",
			interfaces:    []candidateInterfaceSnapshot{{Name: "Wi-Fi", Up: false, IPv4: []string{"192.168.1.10", "10.20.0.10"}}},
			stunAvailable: true,
		},
		{
			name:          "stun",
			interfaces:    base,
			stunAvailable: false,
		},
	}
	baseline := candidateFingerprint(base, true)
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := candidateFingerprint(test.interfaces, test.stunAvailable); got == baseline {
				t.Fatal("fingerprint did not change")
			}
		})
	}
}

func TestCandidateFingerprintChangeTriggersImmediateRefresh(t *testing.T) {
	snapshots := []candidateInterfaceSnapshot{
		{Name: "Wi-Fi", Up: true, IPv4: []string{"192.168.1.10"}},
	}
	engine := &Engine{
		options: Options{
			candidateSnapshot: func() []candidateInterfaceSnapshot { return []candidateInterfaceSnapshot{snapshots[0]} },
		},
		plain: newTunnel(netip.MustParseAddr("10.242.0.2"), netip.MustParsePrefix("10.242.0.0/24")),
		bind:  &meshBind{port: 51820},
	}
	engine.gatherCandidates()
	lastGather := time.Now()
	if engine.refreshCandidatesIfNeeded(lastGather.Add(time.Second), lastGather) {
		t.Fatal("stable fingerprint triggered refresh")
	}

	snapshots[0] = candidateInterfaceSnapshot{Name: "Wi-Fi", Up: true, IPv4: []string{"192.168.1.11"}}
	if !engine.refreshCandidatesIfNeeded(lastGather.Add(2*time.Second), lastGather) {
		t.Fatal("changed fingerprint did not trigger refresh")
	}
	want := netip.MustParseAddrPort("192.168.1.11:51820").String()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		engine.candidateMu.Lock()
		candidates := append([]core.Candidate(nil), engine.candidates...)
		engine.candidateMu.Unlock()
		if len(candidates) == 1 && candidates[0].Address == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	engine.candidateMu.Lock()
	defer engine.candidateMu.Unlock()
	t.Fatalf("candidates = %+v, want address %s", engine.candidates, want)
}
