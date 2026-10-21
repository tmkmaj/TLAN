package control

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/private-radminlan/lanmesh/core"
	"github.com/private-radminlan/lanmesh/internal/network"
	"github.com/private-radminlan/lanmesh/internal/storage"
)

func TestDeviceControlPlaneLifecycle(t *testing.T) {
	store, err := storage.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	service := &Server{Store: store, AdminToken: "token"}
	h := httptest.NewServer(service.Handler())
	defer h.Close()
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	register := core.RegisterDeviceRequest{DeviceID: core.DeviceID("dev-test"), WireGuardPublicKey: key, DisplayName: "Desktop"}
	body, _ := json.Marshal(register)
	req, _ := http.NewRequest(http.MethodPost, h.URL+"/api/v1/devices/register", bytes.NewReader(body))
	req.Header.Set("X-Admin-Token", "token")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register status = %d", resp.StatusCode)
	}
	resp.Body.Close()

	network, err := store.CreateNetwork("Private", "network-password", "10.240.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.JoinRegisteredNetwork(core.NetworkID(network.ID), "Desktop", "network-password", core.DeviceID("dev-test")); err != nil {
		t.Fatal(err)
	}
	candidateBody := `{"candidates":[{"kind":"host","transport":"udp","address":"10.0.0.2:4000","priority":10}]}`
	req, _ = http.NewRequest(http.MethodPost, h.URL+"/api/v1/networks/"+network.ID+"/devices/dev-test/candidates", bytes.NewReader([]byte(candidateBody)))
	req.Header.Set("X-Admin-Token", "token")
	req.Header.Set("Content-Type", "application/json")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("candidate status = %d", resp.StatusCode)
	}
	resp.Body.Close()

	badReq, _ := http.NewRequest(http.MethodPost, h.URL+"/api/v1/devices/register", bytes.NewReader([]byte(`{"device_id":"bad id"}`)))
	badReq.Header.Set("X-Admin-Token", "token")
	badReq.Header.Set("Content-Type", "application/json")
	resp, err = http.DefaultClient.Do(badReq)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid register status = %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestRelayTicketRequiresRegisteredDevices(t *testing.T) {
	store, err := storage.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	broker := network.NewRelayBroker(1024)
	service := &Server{Store: store, AdminToken: "token", Relay: broker}
	h := httptest.NewServer(service.Handler())
	defer h.Close()
	request := func(body string) *http.Response {
		req, _ := http.NewRequest(http.MethodPost, h.URL+"/api/v1/relay/sessions", bytes.NewBufferString(body))
		req.Header.Set("X-Admin-Token", "token")
		req.Header.Set("Content-Type", "application/json")
		resp, requestErr := http.DefaultClient.Do(req)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		return resp
	}
	netSummary, err := store.CreateNetwork("Relay", "network-password", "10.241.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	resp := request(`{"network_id":"` + netSummary.ID + `","source_device_id":"dev-a","target_device_id":"dev-b"}`)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unregistered relay status = %d", resp.StatusCode)
	}
	resp.Body.Close()
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	for index, id := range []string{"dev-a", "dev-b"} {
		keyBytes := make([]byte, 32)
		copy(keyBytes, []byte(key))
		keyBytes[0] = byte(index)
		deviceKey := base64.StdEncoding.EncodeToString(keyBytes)
		_, _, err := store.RegisterDevice(core.RegisterDeviceRequest{DeviceID: core.DeviceID(id), WireGuardPublicKey: deviceKey})
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range []string{"dev-a", "dev-b"} {
		if _, err := store.JoinRegisteredNetwork(core.NetworkID(netSummary.ID), id, "network-password", core.DeviceID(id)); err != nil {
			t.Fatal(err)
		}
	}
	resp = request(`{"network_id":"` + netSummary.ID + `","source_device_id":"dev-a","target_device_id":"dev-b","ttl_seconds":30}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("registered relay status = %d", resp.StatusCode)
	}
	var ticket network.RelayTicket
	if err := json.NewDecoder(resp.Body).Decode(&ticket); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if !ticket.Valid(time.Now()) {
		t.Fatal("relay ticket is not valid")
	}
}
