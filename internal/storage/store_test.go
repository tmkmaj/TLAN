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
