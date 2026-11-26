//go:build windows

package platform

import "testing"

func TestNormalizeAdapterGUID(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{in: "{abcdef01-2345-6789-abcd-ef0123456789}", want: "{ABCDEF01-2345-6789-ABCD-EF0123456789}"},
		{in: " abcdef01-2345-6789-abcd-ef0123456789 ", want: "{ABCDEF01-2345-6789-ABCD-EF0123456789}"},
		{in: "", want: ""},
		{in: "{}", want: ""},
	}
	for _, tc := range cases {
		if got := normalizeAdapterGUID(tc.in); got != tc.want {
			t.Fatalf("normalizeAdapterGUID(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
