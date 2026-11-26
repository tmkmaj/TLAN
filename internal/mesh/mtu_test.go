package mesh

import (
	"net/netip"
	"testing"
)

func TestTunnelHonorsConfiguredMTU(t *testing.T) {
	local := netip.MustParseAddr("10.240.0.2")
	prefix := netip.MustParsePrefix("10.240.0.0/24")
	tunnel := newTunnel(local, prefix, 1200)
	mtu, err := tunnel.MTU()
	if err != nil {
		t.Fatal(err)
	}
	if mtu != 1200+envelopeSize {
		t.Fatalf("MTU=%d want %d", mtu, 1200+envelopeSize)
	}
}

func TestNormalizeMeshMTU(t *testing.T) {
	for _, test := range []struct {
		input int
		want  int
	}{{0, MTU}, {-1, MTU}, {575, MTU}, {576, 576}, {1400, 1400}, {1501, MTU}} {
		if got := normalizeMeshMTU(test.input); got != test.want {
			t.Fatalf("normalizeMeshMTU(%d)=%d want %d", test.input, got, test.want)
		}
	}
}
