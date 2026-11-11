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
		route          peerRoute
		relayAvailable bool
		want           bool
	}{
		{name: "fresh low rtt", route: peerRoute{direct: address, lastDirect: now, rtt: 20 * time.Millisecond}, relayAvailable: true, want: true},
		{name: "fresh high rtt", route: peerRoute{direct: address, lastDirect: now, rtt: 500 * time.Millisecond}, relayAvailable: true, want: false},
		{name: "fresh without relay", route: peerRoute{direct: address, lastDirect: now, rtt: 500 * time.Millisecond}, relayAvailable: false, want: true},
		{name: "warming up", route: peerRoute{direct: address, lastDirect: now}, relayAvailable: true, want: true},
		{name: "stale", route: peerRoute{direct: address, lastDirect: now.Add(-11 * time.Second), rtt: 20 * time.Millisecond}, relayAvailable: true, want: false},
		{name: "missing direct", route: peerRoute{lastDirect: now}, relayAvailable: true, want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := test.route.directPreferred(now, test.relayAvailable); got != test.want {
				t.Fatalf("directPreferred() = %t, want %t", got, test.want)
			}
		})
	}
}
