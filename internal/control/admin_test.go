package control

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/private-radminlan/lanmesh/core"
	"github.com/private-radminlan/lanmesh/internal/network"
	"github.com/private-radminlan/lanmesh/internal/storage"
)

func adminAPIFixture(t *testing.T) (*httptest.Server, *storage.Store, storage.NetworkSummary, storage.Device, string, network.RelayTicket) {
	t.Helper()
	store, err := storage.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	summary, err := store.EnsurePrivateNetwork("Admin API", "TmkNetwork", "10.251.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	_, member, token, err := store.EnrollPrivate(core.RegisterDeviceRequest{DeviceID: "device-a", WireGuardPublicKey: key}, "TmkNetwork")
	if err != nil {
		t.Fatal(err)
	}
	relay := network.NewRelayBroker(1024)
	ticket, err := relay.CreateSession(core.DeviceID("device-a"), core.DeviceID("device-b"), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	service := &Server{Store: store, Relay: relay, StartedAt: time.Now().UTC()}
	return httptest.NewServer(service.AdminHandler("Tmkmaj233", false)), store, summary, member, token, ticket
}

func adminLoginClient(t *testing.T, base string) (*http.Client, string) {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Jar: jar}
	body := bytes.NewBufferString(`{"token":"Tmkmaj233"}`)
	resp, err := client.Post(base+"/admin/login", "application/json", body)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login status = %d", resp.StatusCode)
	}
	var payload struct {
		CSRF string `json:"csrf_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil || payload.CSRF == "" {
		t.Fatalf("login payload: %+v err=%v", payload, err)
	}
	return client, payload.CSRF
}

func adminAction(t *testing.T, client *http.Client, method, url, csrf, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, url, bytes.NewBufferString(body))
	if err != nil {
		t.Fatal(err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if csrf != "" {
		req.Header.Set(adminCSRFHeader, csrf)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestAdminAPIMemberLifecycle(t *testing.T) {
	server, store, summary, member, token, _ := adminAPIFixture(t)
	defer server.Close()
	client, csrf := adminLoginClient(t, server.URL)

	resp := adminAction(t, client, http.MethodGet, server.URL+"/admin/api/overview", "", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("overview status = %d", resp.StatusCode)
	}
	resp.Body.Close()

	resp = adminAction(t, client, http.MethodGet, server.URL+"/admin/api/members", "", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("members status = %d", resp.StatusCode)
	}
	var membersPayload struct {
		Members []adminMember `json:"members"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&membersPayload); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if len(membersPayload.Members) != 1 || membersPayload.Members[0].ID != member.ID {
		t.Fatalf("members = %+v", membersPayload.Members)
	}

	resp = adminAction(t, client, http.MethodPost, server.URL+"/admin/api/members/"+member.ID+"/rename", csrf, `{"name":"Renamed"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("rename status = %d", resp.StatusCode)
	}
	resp.Body.Close()
	devices, _ := store.ListDevices(summary.ID)
	if len(devices) != 1 || devices[0].Name != "Renamed" {
		t.Fatalf("renamed devices = %+v", devices)
	}

	resp = adminAction(t, client, http.MethodPost, server.URL+"/admin/api/members/"+member.ID+"/disconnect", csrf, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("disconnect status = %d", resp.StatusCode)
	}
	resp.Body.Close()

	resp = adminAction(t, client, http.MethodPost, server.URL+"/admin/api/members/"+member.ID+"/kick", csrf, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("kick status = %d", resp.StatusCode)
	}
	resp.Body.Close()
	if _, ok := store.AuthenticateMember(token); ok {
		t.Fatal("kick left old credentials valid")
	}

	resp = adminAction(t, client, http.MethodPost, server.URL+"/admin/api/members/"+member.ID+"/ban", csrf, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("ban status = %d", resp.StatusCode)
	}
	resp.Body.Close()
	if _, _, _, err := store.EnrollPrivate(core.RegisterDeviceRequest{DeviceID: core.DeviceID(member.ID), WireGuardPublicKey: member.PublicKey}, "TmkNetwork"); !errors.Is(err, storage.ErrBlocked) {
		t.Fatalf("banned enroll error = %v", err)
	}
	visible, _ := store.ListDevices(summary.ID)
	if len(visible) != 0 {
		t.Fatalf("blocked member remained visible: %+v", visible)
	}

	resp = adminAction(t, client, http.MethodPost, server.URL+"/admin/api/members/"+member.ID+"/unban", csrf, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unban status = %d", resp.StatusCode)
	}
	resp.Body.Close()
	if _, err := store.SetForwarding(summary.ID, member.ID, true); err != nil {
		t.Fatalf("unbanned member unavailable: %v", err)
	}
}

func TestAdminAPIRequiresCSRF(t *testing.T) {
	server, _, _, member, _, _ := adminAPIFixture(t)
	defer server.Close()
	client, _ := adminLoginClient(t, server.URL)
	resp := adminAction(t, client, http.MethodPost, server.URL+"/admin/api/members/"+member.ID+"/rename", "", `{"name":"Nope"}`)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("missing CSRF status = %d", resp.StatusCode)
	}
	resp.Body.Close()
}
