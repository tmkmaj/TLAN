package clientapi_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/private-radminlan/lanmesh/core"
	"github.com/private-radminlan/lanmesh/internal/clientapi"
	"github.com/private-radminlan/lanmesh/internal/control"
	"github.com/private-radminlan/lanmesh/internal/storage"
)

func TestUploadDiagnosticsWithFRPKeepsLegacyBatchesAndUploadsReportOnce(t *testing.T) {
	store, err := storage.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.EnsurePrivateNetwork("friends", "friends-code", "10.243.0.0/24"); err != nil {
		t.Fatal(err)
	}
	network, member, token, err := store.EnrollPrivate(core.RegisterDeviceRequest{DeviceID: "device-a", WireGuardPublicKey: base64.StdEncoding.EncodeToString(make([]byte, 32))}, "friends-code")
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer((&control.Server{Store: store}).Handler())
	defer server.Close()
	api := clientapi.New(server.URL, token)
	checks := make([]clientapi.DiagnosticCheck, 129)
	for i := range checks {
		checks[i] = clientapi.DiagnosticCheck{Name: fmt.Sprintf("peer %d", i), Status: "pass"}
	}
	report := json.RawMessage(`{"schema_version":1,"generated_at":"2026-10-22T10:00:00Z","profiles":[{"profile_id":"profile-a","snapshot":{"Running":true},"logs":[],"managed_leases":[]}]}`)
	if err := api.UploadDiagnosticsWithFRP(core.NetworkID(network.ID), core.DeviceID(member.ID), checks, report); err != nil {
		t.Fatal(err)
	}
	reports, err := api.ListDiagnostics(core.NetworkID(network.ID), core.DeviceID(member.ID))
	if err != nil {
		t.Fatal(err)
	}
	if len(reports) != 3 {
		t.Fatalf("reports = %d, want 3", len(reports))
	}
	reportsWithFRP := 0
	count := 0
	for _, report := range reports {
		if len(report.FRPReport) > 0 {
			reportsWithFRP++
		}
		for _, check := range report.Checks {
			if check.Name != checks[count].Name {
				t.Fatalf("check %d was lost or reordered", count)
			}
			count++
		}
	}
	if reportsWithFRP != 1 {
		t.Fatalf("reports with FRP = %d, want 1", reportsWithFRP)
	}
	if count != len(checks) {
		t.Fatalf("uploaded %d of %d checks", count, len(checks))
	}
}

func TestUploadDiagnosticsWithFRPRejectsInvalidReportBeforeUpload(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()
	err := clientapi.New(server.URL, "test").UploadDiagnosticsWithFRP("net-a", "device-a", []clientapi.DiagnosticCheck{{Name: "probe", Status: "pass"}}, json.RawMessage(`{"schema_version":1,"generated_at":"2026-10-22T10:00:00Z","profiles":[],"token":"secret"}`))
	if err == nil || !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("invalid report error = %v", err)
	}
	if requests != 0 {
		t.Fatalf("requests = %d, want 0", requests)
	}
}
