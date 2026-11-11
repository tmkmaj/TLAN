//go:build windows

package platform

import (
	"net"
	"net/netip"
	"testing"
)

func v4net(t *testing.T, ip string, bits int) *net.IPNet {
	t.Helper()
	parsed := net.ParseIP(ip)
	if parsed == nil {
		t.Fatalf("parse %s", ip)
	}
	return &net.IPNet{IP: parsed.To4(), Mask: net.CIDRMask(bits, 32)}
}

func TestAddressPresentDetectsAdapterAddress(t *testing.T) {
	want := netip.MustParseAddr("10.242.0.7")
	other := netip.MustParseAddr("10.242.0.9")
	tests := []struct {
		name  string
		addrs []net.Addr
		want  bool
	}{
		{name: "assigned", addrs: []net.Addr{v4net(t, "10.242.0.7", 24)}, want: true},
		{name: "not assigned", addrs: []net.Addr{v4net(t, "10.242.0.9", 24)}, want: false},
		{name: "empty", addrs: nil, want: false},
		{name: "ip addr form", addrs: []net.Addr{&net.IPAddr{IP: want.AsSlice()}}, want: true},
		{name: "v4 mapped v6", addrs: []net.Addr{ipnetOf(netip.MustParseAddr("::ffff:10.242.0.7"))}, want: true},
		{name: "mixed", addrs: []net.Addr{v4net(t, "10.242.0.9", 24), v4net(t, "10.242.0.7", 24)}, want: true},
		{name: "ignores other kinds", addrs: []net.Addr{fakeAddr("pseudo")}, want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := addressPresent(test.addrs, want); got != test.want {
				t.Fatalf("addressPresent(%v, %v) = %t, want %t", test.addrs, want, got, test.want)
			}
		})
	}
	if !addressPresent([]net.Addr{v4net(t, "10.242.0.9", 24)}, other) {
		t.Fatal("addressPresent failed to match a different expected address")
	}
}

func ipnetOf(addr netip.Addr) *net.IPNet {
	bits := 128
	if addr.Is4() {
		bits = 32
	}
	return &net.IPNet{IP: net.IP(addr.AsSlice()), Mask: net.CIDRMask(bits, bits)}
}

type fakeAddr string

func (a fakeAddr) Network() string { return "fake" }
func (a fakeAddr) String() string  { return string(a) }
