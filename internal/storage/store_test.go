package storage

import (
	"encoding/base64"
	"path/filepath"
	"testing"

	"github.com/private-radminlan/lanmesh/core"
)

func TestFailedPersistRollsBackMemory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	first, err := store.CreateNetwork("first", "a valid password", "10.240.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	store.path = filepath.Join(path, "cannot-exist.json")
	if _, err = store.CreateNetwork("must not commit", "a valid password", "10.241.0.0/24"); err == nil {
		t.Fatal("expected persistence failure")
	}
	if len(store.ListNetworks()) != 1 {
		t.Fatal("failed disk write was committed in memory")
	}
	store.path = path
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	_, _, err = store.RegisterDevice(core.RegisterDeviceRequest{DeviceID: "test-device", WireGuardPublicKey: key})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.JoinRegisteredNetwork(core.NetworkID(first.ID), "member", "a valid password", "test-device"); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reopened.NetworkMembershipExists(core.NetworkID(first.ID), "test-device") {
		t.Fatal("state was not persisted after rollback")
	}
}

func TestFRPPortRangeDefaultsAndPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if store.HasFRPPortRange() {
		t.Fatal("expected unset custom FRP port range by default")
	}
	got := store.FRPPortRange()
	if got != (PortRange{Start: 60000, End: 61000}) {
		t.Fatalf("default FRPPortRange = %+v, want 60000-61000", got)
	}
	if _, err := store.SetFRPPortRange(70000, 70001); err == nil {
		t.Fatal("expected invalid port range rejection")
	}
	if _, err := store.SetFRPPortRange(50010, 50000); err == nil {
		t.Fatal("expected reversed port range rejection")
	}
	saved, err := store.SetFRPPortRange(60100, 60200)
	if err != nil || saved != (PortRange{Start: 60100, End: 60200}) {
		t.Fatalf("SetFRPPortRange = %+v, err=%v", saved, err)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reopened.HasFRPPortRange() || reopened.FRPPortRange() != saved {
		t.Fatalf("reopened FRPPortRange = %+v (has=%v), want %+v", reopened.FRPPortRange(), reopened.HasFRPPortRange(), saved)
	}
}
