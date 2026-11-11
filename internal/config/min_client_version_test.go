package config

import "testing"

func TestValidateMinClientVersion(t *testing.T) {
	for _, ok := range []string{"", "   ", "v0.7.0", "0.7.0"} {
		if err := validateMinClientVersion(ok); err != nil {
			t.Fatalf("validateMinClientVersion(%q) = %v, want nil", ok, err)
		}
	}
	// Beta and malformed values are rejected so the release gate can never be
	// configured to half-apply to the beta channel.
	for _, bad := range []string{"0.7", "latest", "v0.7.0-beta.1", "v0.7.0-rc.1", "v0.7.0+build.5", "1.2.3.4"} {
		if err := validateMinClientVersion(bad); err == nil {
			t.Fatalf("validateMinClientVersion(%q) accepted", bad)
		}
	}
}
