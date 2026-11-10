package storage

import (
	"encoding/base64"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/private-radminlan/lanmesh/core"
)

func adminStorageFixture(t *testing.T) (*Store, NetworkSummary, Device) {
	t.Helper()
	store, err := Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	network, err := store.EnsurePrivateNetwork("Admin", "TmkNetwork", "10.250.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	_, member, _, err := store.EnrollPrivate(core.RegisterDeviceRequest{
		DeviceID:           "device-admin-test",
		WireGuardPublicKey: base64.StdEncoding.EncodeToString(make([]byte, 32)),
	}, "TmkNetwork")
	if err != nil {
		t.Fatal(err)
	}
	return store, network, member
}

func TestPrivateNetworkLookup(t *testing.T) {
	store, want, _ := adminStorageFixture(t)
	got, err := store.PrivateNetwork()
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != want.ID || got.Name != want.Name {
		t.Fatalf("private network = %+v, want %+v", got, want)
	}
}

func TestRenameDevicePreservesIdentity(t *testing.T) {
	store, network, member := adminStorageFixture(t)
	got, err := store.RenameDevice(network.ID, member.ID, "  Living room  ")
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "Living room" || got.ID != member.ID || got.VirtualIP != member.VirtualIP || got.PublicKey != member.PublicKey {
		t.Fatalf("renamed device = %+v", got)
	}
	devices, err := store.ListDevices(network.ID)
	if err != nil || len(devices) != 1 || devices[0].Name != "Living room" {
		t.Fatalf("listed devices = %+v, err=%v", devices, err)
	}
	if _, err := store.RenameDevice(network.ID, member.ID, "bad\x00name"); err == nil {
		t.Fatal("control character in name was accepted")
	}
}

func TestBlockedDeviceIsFilteredAndCannotReenroll(t *testing.T) {
	store, network, member := adminStorageFixture(t)
	if _, err := store.SetDeviceBlocked(network.ID, member.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Heartbeat(core.DeviceID(member.ID)); !errors.Is(err, ErrBlocked) {
		t.Fatalf("heartbeat error = %v, want ErrBlocked", err)
	}
	request := core.RegisterDeviceRequest{DeviceID: core.DeviceID(member.ID), WireGuardPublicKey: member.PublicKey}
	if _, _, _, err := store.EnrollPrivate(request, "TmkNetwork"); !errors.Is(err, ErrBlocked) {
		t.Fatalf("reenroll error = %v, want ErrBlocked", err)
	}
	visible, err := store.ListDevices(network.ID)
	if err != nil || len(visible) != 0 {
		t.Fatalf("blocked device remained visible: %+v, err=%v", visible, err)
	}
	all, err := store.ListDevicesWithBlocked(network.ID, true)
	if err != nil || len(all) != 1 || !all[0].Blocked {
		t.Fatalf("admin device list = %+v, err=%v", all, err)
	}
	if _, err := store.SetDeviceBlocked(network.ID, member.ID, false); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := store.EnrollPrivate(request, "TmkNetwork"); err != nil {
		t.Fatalf("unblocked reenroll failed: %v", err)
	}
}

func TestRevokeMemberCredentials(t *testing.T) {
	store, network, member := adminStorageFixture(t)
	_, _, token, err := store.EnrollPrivate(core.RegisterDeviceRequest{DeviceID: core.DeviceID(member.ID), WireGuardPublicKey: member.PublicKey}, "TmkNetwork")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.RevokeMemberCredentials(network.ID, member.ID); err != nil {
		t.Fatal(err)
	}
	if _, ok := store.AuthenticateMember(token); ok {
		t.Fatal("revoked credential still authenticated")
	}
}

func TestRenameDeviceRejectsInvalidName(t *testing.T) {
	store, network, member := adminStorageFixture(t)
	for _, name := range []string{"", strings.Repeat("x", 129), "bad\nname"} {
		if _, err := store.RenameDevice(network.ID, member.ID, name); err == nil {
			t.Fatalf("name %q was accepted", name)
		}
	}
}
func adminTestKey(seed byte) string {
	key := make([]byte, 32)
	key[0] = seed
	return base64.StdEncoding.EncodeToString(key)
}

func TestEnrollPrivateAsAdminIssuesMemberCredential(t *testing.T) {
	store, network, _ := adminStorageFixture(t)
	request := core.RegisterDeviceRequest{DeviceID: "device-admin-enroll", DisplayName: "Admin Node", WireGuardPublicKey: adminTestKey(7)}
	summary, member, token, err := store.EnrollPrivateAsAdmin(request)
	if err != nil {
		t.Fatal(err)
	}
	if summary.ID != network.ID || member.ID != request.DeviceID.String() || !strings.HasPrefix(token, "member_") {
		t.Fatalf("admin enrollment = %+v/%+v/%q", summary, member, token)
	}
	credential, ok := store.AuthenticateMember(token)
	if !ok || credential.DeviceID != request.DeviceID.String() || credential.NetworkID != network.ID {
		t.Fatalf("admin member credential = %+v/%v", credential, ok)
	}
}

func TestEnrollPrivateAsAdminPreservesIdentity(t *testing.T) {
	store, network, member := adminStorageFixture(t)
	request := core.RegisterDeviceRequest{DeviceID: core.DeviceID(member.ID), DisplayName: member.Name, WireGuardPublicKey: member.PublicKey}
	_, again, _, err := store.EnrollPrivateAsAdmin(request)
	if err != nil {
		t.Fatal(err)
	}
	if again.ID != member.ID || again.VirtualIP != member.VirtualIP || !again.JoinedAt.Equal(member.JoinedAt) {
		t.Fatalf("admin reenrollment changed identity: %+v -> %+v", member, again)
	}
	if _, err := store.PrivateNetwork(); err != nil {
		t.Fatal(err)
	}
	_ = network
}

func TestEnrollPrivateAsAdminRejectsBlockedDevice(t *testing.T) {
	store, network, member := adminStorageFixture(t)
	if _, err := store.SetDeviceBlocked(network.ID, member.ID, true); err != nil {
		t.Fatal(err)
	}
	_, _, _, err := store.EnrollPrivateAsAdmin(core.RegisterDeviceRequest{DeviceID: core.DeviceID(member.ID), WireGuardPublicKey: member.PublicKey})
	if !errors.Is(err, ErrBlocked) {
		t.Fatalf("blocked admin enrollment error = %v, want ErrBlocked", err)
	}
}
