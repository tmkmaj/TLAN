package clientapi_test

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/private-radminlan/lanmesh/core"
	"github.com/private-radminlan/lanmesh/internal/clientapi"
	"github.com/private-radminlan/lanmesh/internal/control"
	"github.com/private-radminlan/lanmesh/internal/storage"
)

func TestUploadDiagnosticsForFullNetwork(t *testing.T) {
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
	// Adapter + 127 peers + last error on a full 128-device network.
	checks := make([]clientapi.DiagnosticCheck, 129)
	for i := range checks {
		checks[i] = clientapi.DiagnosticCheck{Name: fmt.Sprintf("peer %d", i), Status: "pass"}
	}
	if err := api.UploadDiagnostics(core.NetworkID(network.ID), core.DeviceID(member.ID), checks); err != nil {
		t.Fatal(err)
	}
	reports, err := api.ListDiagnostics(core.NetworkID(network.ID), core.DeviceID(member.ID))
	if err != nil {
		t.Fatal(err)
	}
	if len(reports) != 3 {
		t.Fatalf("reports = %d, want 3", len(reports))
	}
	count := 0
	for _, report := range reports {
		if len(report.Checks) > 64 {
			t.Fatal("report exceeds server limit")
		}
		for _, check := range report.Checks {
			if check.Name != checks[count].Name {
				t.Fatalf("check %d was lost or reordered", count)
			}
			count++
		}
	}
	if count != len(checks) {
		t.Fatalf("uploaded %d of %d checks", count, len(checks))
	}
}

func TestUploadDiagnosticsStopsOnFailedBatch(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if requests == 2 {
			http.Error(w, "unavailable", 503)
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()
	if err := clientapi.New(server.URL, "test").UploadDiagnostics("net-a", "device-a", make([]clientapi.DiagnosticCheck, 129)); err == nil {
		t.Fatal("failed batch was ignored")
	}
	if requests != 2 {
		t.Fatalf("requests = %d, want 2", requests)
	}
}
