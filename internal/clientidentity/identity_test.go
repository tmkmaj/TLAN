package clientidentity

import (
	"path/filepath"
	"testing"
)

func TestLoadOrCreateIsStableAndValid(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.json")
	first, err := LoadOrCreate(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Validate(); err != nil {
		t.Fatal(err)
	}
	second, err := LoadOrCreate(path)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("identity changed after reload")
	}
	if request := first.RegisterRequest(); request.WireGuardPublicKey != first.PublicKey || request.DeviceID != first.DeviceID {
		t.Fatalf("registration request did not use public identity: %+v", request)
	}
}
