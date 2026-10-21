//go:build windows

package clientidentity

import "testing"

func TestStrictSecretRejectsPlaintext(t *testing.T) {
	if _, err := UnprotectSecretStrict("plaintext-token"); err == nil {
		t.Fatal("plaintext secret was accepted by strict DPAPI reader")
	}
}

func TestStrictSecretRoundTrip(t *testing.T) {
	protected, err := ProtectSecret("secret-value")
	if err != nil {
		t.Fatal(err)
	}
	plain, err := UnprotectSecretStrict(protected)
	if err != nil {
		t.Fatal(err)
	}
	if plain != "secret-value" {
		t.Fatalf("round trip = %q", plain)
	}
}
