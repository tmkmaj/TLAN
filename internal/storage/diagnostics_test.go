package storage

import (
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/private-radminlan/lanmesh/core"
)

func diagnosticsFixture(t *testing.T) (*Store, core.NetworkID, core.DeviceID) {
	t.Helper()
	store, err := Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	network, err := store.EnsurePrivateNetwork("diagnostics", "diagnostics-code", "10.249.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	_, member, _, err := store.EnrollPrivate(core.RegisterDeviceRequest{
		DeviceID: "device-diagnostics", WireGuardPublicKey: base64.StdEncoding.EncodeToString(make([]byte, 32)),
	}, "diagnostics-code")
	if err != nil {
		t.Fatal(err)
	}
	return store, core.NetworkID(network.ID), core.DeviceID(member.ID)
}

func TestSaveDiagnosticsSupportsLegacyChecksAndCompleteFRPReport(t *testing.T) {
	store, networkID, deviceID := diagnosticsFixture(t)
	checksOnly, err := store.SaveDiagnostics(DiagnosticReport{
		NetworkID: networkID, DeviceID: deviceID,
		Checks: []DiagnosticCheck{{Name: "legacy", Status: "pass"}},
	})
	if err != nil || len(checksOnly.Checks) != 1 || len(checksOnly.FRPReport) != 0 {
		t.Fatalf("legacy checks report = %+v, err=%v", checksOnly, err)
	}
	raw := json.RawMessage(`{"schema_version":1,"generated_at":"2026-10-22T10:00:00Z","profiles":[{"profile_id":"profile-a","snapshot":{"Running":true,"LastError":"token=token-secret"},"logs":["capability=capability-secret"],"managed_leases":[]}]}`)
	saved, err := store.SaveDiagnostics(DiagnosticReport{NetworkID: networkID, DeviceID: deviceID, FRPReport: raw})
	if err != nil {
		t.Fatal(err)
	}
	if len(saved.Checks) != 0 || len(saved.FRPReport) == 0 {
		t.Fatalf("FRP-only report was not saved: %+v", saved)
	}
	for _, secret := range []string{"token-secret", "capability-secret"} {
		if strings.Contains(string(saved.FRPReport), secret) {
			t.Fatalf("saved report contains %s", secret)
		}
	}
	raw[0] = '['
	reports, err := store.ListDiagnostics(networkID, deviceID)
	if err != nil {
		t.Fatal(err)
	}
	if len(reports) != 2 || !json.Valid(reports[1].FRPReport) {
		t.Fatalf("listed reports = %+v", reports)
	}
	reports[1].FRPReport[0] = '['
	again, err := store.ListDiagnostics(networkID, deviceID)
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(again[1].FRPReport) {
		t.Fatal("diagnostic listing aliases stored FRP report")
	}
	reopened, err := Open(store.path)
	if err != nil {
		t.Fatal(err)
	}
	persisted, err := reopened.ListDiagnostics(networkID, deviceID)
	if err != nil || len(persisted) != 2 || !json.Valid(persisted[1].FRPReport) {
		t.Fatalf("persisted FRP diagnostics = %+v, err=%v", persisted, err)
	}
}

func TestSaveDiagnosticsRejectsInvalidFRPReport(t *testing.T) {
	store, networkID, deviceID := diagnosticsFixture(t)
	for name, raw := range map[string]string{
		"unknown field": `{"schema_version":1,"generated_at":"2026-10-22T10:00:00Z","profiles":[],"token":"secret"}`,
		"wrong schema":  `{"schema_version":2,"generated_at":"2026-10-22T10:00:00Z","profiles":[]}`,
		"not object":    `[]`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := store.SaveDiagnostics(DiagnosticReport{NetworkID: networkID, DeviceID: deviceID, FRPReport: json.RawMessage(raw)})
			if err == nil {
				t.Fatal("invalid FRP report was accepted")
			}
		})
	}
}
