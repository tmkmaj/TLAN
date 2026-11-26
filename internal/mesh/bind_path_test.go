package mesh

import (
	"net/netip"
	"testing"
	"time"
)

func TestDirectPreferredUsesRelayOnlyForColdOrSlowDirectPath(t *testing.T) {
	now := time.Unix(100, 0)
	address := netip.MustParseAddrPort("198.51.100.10:40000")
	tests := []struct {
		name           string
		route          *peerRoute
		relayAvailable bool
		want           bool
	}{
		{name: "fresh low rtt", route: &peerRoute{direct: address, lastDirect: now, rtt: 20 * time.Millisecond}, relayAvailable: true, want: true},
		{name: "fresh high rtt", route: &peerRoute{direct: address, lastDirect: now, rtt: 500 * time.Millisecond, slow: true}, relayAvailable: true, want: false},
		{name: "fresh without relay", route: &peerRoute{direct: address, lastDirect: now, rtt: 500 * time.Millisecond, slow: true}, relayAvailable: false, want: true},
		{name: "warming up", route: &peerRoute{direct: address, lastDirect: now}, relayAvailable: true, want: true},
		{name: "stale", route: &peerRoute{direct: address, lastDirect: now.Add(-13 * time.Second), rtt: 20 * time.Millisecond}, relayAvailable: true, want: false},
		{name: "missing direct", route: &peerRoute{lastDirect: now}, relayAvailable: true, want: false},
		{name: "too many failures", route: &peerRoute{direct: address, lastDirect: now, rtt: 10 * time.Millisecond, failures: directFailureThreshold}, relayAvailable: true, want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := test.route.directPreferred(now, test.relayAvailable); got != test.want {
				t.Fatalf("directPreferred() = %t, want %t", got, test.want)
			}
		})
	}
}

// The latency decision must have a deadband: a sample just above the "use
// direct" threshold but below the "drop direct" threshold keeps the existing
// choice, and only a sustained change flips it.
func TestDirectPreferredHysteresis(t *testing.T) {
	address := netip.MustParseAddrPort("198.51.100.10:40000")
	now := time.Unix(100, 0)
	route := peerRoute{direct: address, lastDirect: now, rtt: 200 * time.Millisecond}
	if !route.directPreferred(now, true) {
		t.Fatal("a latency between the two thresholds must not drop the direct path")
	}
	for i := 0; i < directRTTSamples-1; i++ {
		route.noteRTT(300 * time.Millisecond)
	}
	if route.slow {
		t.Fatal("entered slow mode before the debounce completed")
	}
	route.noteRTT(300 * time.Millisecond)
	if !route.slow {
		t.Fatal("did not enter slow mode after sustained high latency")
	}
	for i := 0; i < directRTTSamples-1; i++ {
		route.noteRTT(20 * time.Millisecond)
	}
	if !route.slow {
		t.Fatal("left slow mode before the debounce completed")
	}
	route.noteRTT(20 * time.Millisecond)
	if route.slow {
		t.Fatal("did not leave slow mode after sustained low latency")
	}
}

// A single lost probe must not move the flow, and a healthy socket must not
// steal the pinned mapping from the socket that owns it.
func TestPinnedSocketSurvivesHealthyPath(t *testing.T) {
	address := netip.MustParseAddrPort("198.51.100.10:40000")
	other := netip.MustParseAddrPort("198.51.100.10:40001")
	now := time.Unix(100, 0)
	route := peerRoute{}
	route.observeSuccess(now, address, 1, 20*time.Millisecond)
	for i := 0; i < directFailureThreshold-1; i++ {
		route.observeFailure(now)
	}
	if !route.directUsable(now) {
		t.Fatal("path was dropped before the failure threshold")
	}
	route.observeSuccess(now, other, 2, 20*time.Millisecond)
	if route.direct != address || route.directSocket != 1 {
		t.Fatalf("healthy pinned path migrated to %v socket %d", route.direct, route.directSocket)
	}
	route.observeFailure(now)
	route.observeSuccess(now, other, 2, 20*time.Millisecond)
	if route.direct != other || route.directSocket != 2 {
		t.Fatalf("path did not migrate after the failure threshold: %v socket %d", route.direct, route.directSocket)
	}
}
