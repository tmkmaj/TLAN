//go:build windows

package winproc

import "testing"

func TestTargetIntegrityPolicy(t *testing.T) {
	cases := []struct {
		parent uint32
		want   uint32
	}{
		{integrityUntrustedRID, integrityUntrustedRID},
		{integrityLowRID, integrityLowRID},
		{integrityMediumRID, integrityMediumRID},
		{integrityHighRID, integrityMediumRID},
		{integritySystemRID, integrityMediumRID},
	}
	for _, tc := range cases {
		got, err := targetIntegrityRID(tc.parent)
		if err != nil {
			t.Fatalf("targetIntegrityRID(%#x): %v", tc.parent, err)
		}
		if got != tc.want {
			t.Fatalf("targetIntegrityRID(%#x) = %#x, want %#x", tc.parent, got, tc.want)
		}
	}
}
