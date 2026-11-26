package mesh

import (
	"net/netip"
	"testing"
)

func TestRoutableCandidateAddr(t *testing.T) {
	cases := []struct {
		address string
		want    bool
	}{
		{"10.0.0.1", true},
		{"192.168.1.4", true},
		{"100.64.0.1", true},
		{"8.8.8.8", true},
		{"127.0.0.1", false},
		{"127.1.2.3", false},
		{"169.254.10.1", false},
		{"224.0.0.1", false},
		{"0.0.0.0", false},
		{"::1", false},
		{"fe80::1", false},
	}
	for _, tc := range cases {
		if got := routableCandidateAddr(netip.MustParseAddr(tc.address)); got != tc.want {
			t.Errorf("routableCandidateAddr(%s) = %v, want %v", tc.address, got, tc.want)
		}
	}
}
