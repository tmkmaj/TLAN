package control

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/private-radminlan/lanmesh/core"
	"github.com/private-radminlan/lanmesh/internal/clientapi"
	"github.com/private-radminlan/lanmesh/internal/diagreport"
	"github.com/private-radminlan/lanmesh/internal/storage"
)

func diagnosticsControlFixture(t *testing.T) (*storage.Store, core.NetworkID, core.DeviceID, string, *httptest.Server) {
	t.Helper()
	store, err := storage.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	network, err := store.EnsurePrivateNetwork("diagnostics API", "diagnostics-api-code", "10.248.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	_, member, token, err := store.EnrollPrivate(core.RegisterDeviceRequest{
		DeviceID: "device-diagnostics-api", WireGuardPublicKey: base64.StdEncoding.EncodeToString(make([]byte, 32)),
	}, "diagnostics-api-code")
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer((&Server{Store: store}).Handler())
	t.Cleanup(server.Close)
	return store, core.NetworkID(network.ID), core.DeviceID(member.ID), token, server
}

func TestDiagnosticsAPIStoresAndReadsCompleteFRPReport(t *testing.T) {
	store, networkID, deviceID, token, server := diagnosticsControlFixture(t)
	api := clientapi.New(server.URL, token)
	report := json.RawMessage(`{"schema_version":1,"generated_at":"2026-10-22T10:00:00Z","profiles":[{"profile_id":"profile-a","snapshot":{"Running":true,"LastError":"token=token-secret"},"logs":["capability=capability-secret"],"managed_leases":[]}]}`)
	if _, err := api.SubmitDiagnosticsWithFRP(networkID, deviceID, []clientapi.DiagnosticCheck{{Name: "legacy", Status: "pass"}}, report); err != nil {
		t.Fatal(err)
	}
	reports, err := api.ListDiagnostics(networkID, deviceID)
	if err != nil {
		t.Fatal(err)
	}
	if len(reports) != 1 || len(reports[0].FRPReport) == 0 || len(reports[0].Checks) != 1 {
		t.Fatalf("diagnostics response = %+v", reports)
	}
	for _, secret := range []string{"token-secret", "capability-secret"} {
		if bytes.Contains(reports[0].FRPReport, []byte(secret)) {
			t.Fatalf("FRP report leaked %q", secret)
		}
	}
	stored, err := store.ListDiagnostics(networkID, deviceID)
	if err != nil || len(stored) != 1 || !json.Valid(stored[0].FRPReport) {
		t.Fatalf("stored diagnostics = %+v, err=%v", stored, err)
	}
}

func TestDiagnosticsAPIRejectsUnknownFieldsAndOversizedBody(t *testing.T) {
	_, networkID, deviceID, token, server := diagnosticsControlFixture(t)
	endpoint := server.URL + "/api/v1/networks/" + networkID.String() + "/devices/" + deviceID.String() + "/diagnostics"
	post := func(body string) *http.Response {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	resp := post(`{"checks":[],"unexpected":true}`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown field status = %d", resp.StatusCode)
	}
	resp.Body.Close()
	resp = post(`{"frp_report":{"schema_version":1,"generated_at":"2026-10-22T10:00:00Z","profiles":[],"token":"secret"}}`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown report field status = %d", resp.StatusCode)
	}
	resp.Body.Close()
	oversized := `{"checks":[],"frp_report":"` + strings.Repeat("x", diagreport.MaxRequestBytes+1024) + `"}`
	resp = post(oversized)
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized status = %d", resp.StatusCode)
	}
	resp.Body.Close()
}
