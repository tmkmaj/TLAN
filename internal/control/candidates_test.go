package control

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/private-radminlan/lanmesh/core"
	"github.com/private-radminlan/lanmesh/internal/storage"
)

// A client behind a loopback STUN server publishes a loopback reflexive
// candidate. The whole set used to be rejected with 400, which made "connect"
// fail for every peer; invalid entries must be dropped instead.
func TestCandidatePostDropsNonRoutableCandidates(t *testing.T) {
	store, err := storage.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	service := &Server{Store: store, AdminToken: "token"}
	h := httptest.NewServer(service.Handler())
	defer h.Close()

	register := core.RegisterDeviceRequest{DeviceID: core.DeviceID("dev-test"), WireGuardPublicKey: "CQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", DisplayName: "Desktop"}
	body, _ := json.Marshal(register)
	req, _ := http.NewRequest(http.MethodPost, h.URL+"/api/v1/devices/register", bytes.NewReader(body))
	req.Header.Set("X-Admin-Token", "token")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register status = %d", resp.StatusCode)
	}

	network, err := store.CreateNetwork("Private", "network-password", "10.240.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.JoinRegisteredNetwork(core.NetworkID(network.ID), "Desktop", "network-password", core.DeviceID("dev-test")); err != nil {
		t.Fatal(err)
	}

	candidateBody := `{"candidates":[{"kind":"host","transport":"udp","address":"127.0.0.1:4000","priority":10},{"kind":"host","transport":"udp","address":"10.0.0.2:4000","priority":20}]}`
	req, _ = http.NewRequest(http.MethodPost, h.URL+"/api/v1/networks/"+network.ID+"/devices/dev-test/candidates", bytes.NewReader([]byte(candidateBody)))
	req.Header.Set("X-Admin-Token", "token")
	req.Header.Set("Content-Type", "application/json")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("candidate status = %d, want 200", resp.StatusCode)
	}

	record, err := store.GetCandidates(core.NetworkID(network.ID), core.DeviceID("dev-test"))
	if err != nil {
		t.Fatal(err)
	}
	if len(record.Candidates) != 1 || record.Candidates[0].Address != "10.0.0.2:4000" {
		t.Fatalf("stored candidates = %+v, want only 10.0.0.2:4000", record.Candidates)
	}
}
