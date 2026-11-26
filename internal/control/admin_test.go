package control

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/private-radminlan/lanmesh/core"
	"github.com/private-radminlan/lanmesh/internal/network"
	"github.com/private-radminlan/lanmesh/internal/storage"
)

type adminTestEnvelope struct {
	OK        bool            `json:"ok"`
	Data      json.RawMessage `json:"data"`
	Error     *adminAPIError  `json:"error"`
	RequestID string          `json:"request_id"`
}

func decodeAdminTestEnvelope(t *testing.T, resp *http.Response) adminTestEnvelope {
	t.Helper()
	defer resp.Body.Close()
	var envelope adminTestEnvelope
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.RequestID == "" {
		t.Fatal("admin response missing request_id")
	}
	return envelope
}

func adminAPIFixture(t *testing.T) (*httptest.Server, *storage.Store, storage.NetworkSummary, storage.Device, string, network.RelayTicket) {
	t.Helper()
	store, err := storage.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	summary, err := store.EnsurePrivateNetwork("Admin API", "test-join-code", "10.251.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	_, member, token, err := store.EnrollPrivate(core.RegisterDeviceRequest{DeviceID: "device-a", WireGuardPublicKey: key}, "test-join-code")
	if err != nil {
		t.Fatal(err)
	}
	relay := network.NewRelayBroker(1024)
	ticket, err := relay.CreateSession(core.DeviceID("device-a"), core.DeviceID("device-b"), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	service := &Server{Store: store, Relay: relay, StartedAt: time.Now().UTC()}
	return httptest.NewServer(service.AdminHandler("test-admin-token", false)), store, summary, member, token, ticket
}

func adminLoginClient(t *testing.T, base string) (*http.Client, string) {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Jar: jar}
	body := bytes.NewBufferString(`{"token":"test-admin-token"}`)
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

	envelope := decodeAdminTestEnvelope(t, adminAction(t, client, http.MethodGet, server.URL+"/admin/api/overview", "", ""))
	if !envelope.OK {
		t.Fatalf("overview envelope = %+v", envelope)
	}

	envelope = decodeAdminTestEnvelope(t, adminAction(t, client, http.MethodGet, server.URL+"/admin/api/members", "", ""))
	if !envelope.OK {
		t.Fatalf("members envelope = %+v", envelope)
	}
	var membersPayload struct {
		Members []adminMember `json:"members"`
	}
	if err := json.Unmarshal(envelope.Data, &membersPayload); err != nil {
		t.Fatal(err)
	}
	if len(membersPayload.Members) != 1 || membersPayload.Members[0].ID != member.ID {
		t.Fatalf("members = %+v", membersPayload.Members)
	}

	envelope = decodeAdminTestEnvelope(t, adminAction(t, client, http.MethodPost, server.URL+"/admin/api/members/"+member.ID+"/rename", csrf, `{"name":"Renamed"}`))
	if !envelope.OK {
		t.Fatalf("rename envelope = %+v", envelope)
	}
	devices, _ := store.ListDevices(summary.ID)
	if len(devices) != 1 || devices[0].Name != "Renamed" {
		t.Fatalf("renamed devices = %+v", devices)
	}

	envelope = decodeAdminTestEnvelope(t, adminAction(t, client, http.MethodPost, server.URL+"/admin/api/members/"+member.ID+"/disconnect", csrf, ""))
	if !envelope.OK {
		t.Fatalf("disconnect envelope = %+v", envelope)
	}

	envelope = decodeAdminTestEnvelope(t, adminAction(t, client, http.MethodPost, server.URL+"/admin/api/members/"+member.ID+"/kick", csrf, ""))
	if !envelope.OK {
		t.Fatalf("kick envelope = %+v", envelope)
	}
	if _, ok := store.AuthenticateMember(token); ok {
		t.Fatal("kick left old credentials valid")
	}

	envelope = decodeAdminTestEnvelope(t, adminAction(t, client, http.MethodPost, server.URL+"/admin/api/members/"+member.ID+"/ban", csrf, ""))
	if !envelope.OK {
		t.Fatalf("ban envelope = %+v", envelope)
	}
	if _, _, _, err := store.EnrollPrivate(core.RegisterDeviceRequest{DeviceID: core.DeviceID(member.ID), WireGuardPublicKey: member.PublicKey}, "test-join-code"); !errors.Is(err, storage.ErrBlocked) {
		t.Fatalf("banned enroll error = %v", err)
	}
	visible, _ := store.ListDevices(summary.ID)
	if len(visible) != 0 {
		t.Fatalf("blocked member remained visible: %+v", visible)
	}

	envelope = decodeAdminTestEnvelope(t, adminAction(t, client, http.MethodPost, server.URL+"/admin/api/members/"+member.ID+"/unban", csrf, ""))
	if !envelope.OK {
		t.Fatalf("unban envelope = %+v", envelope)
	}
	if _, err := store.SetForwarding(summary.ID, member.ID, true); err != nil {
		t.Fatalf("unbanned member unavailable: %v", err)
	}
}

func TestAdminAPISessionEndpoint(t *testing.T) {
	server, _, _, _, _, _ := adminAPIFixture(t)
	defer server.Close()
	client, csrf := adminLoginClient(t, server.URL)
	envelope := decodeAdminTestEnvelope(t, adminAction(t, client, http.MethodGet, server.URL+"/admin/api/session", "", ""))
	if !envelope.OK {
		t.Fatalf("session envelope = %+v", envelope)
	}
	var payload struct {
		CSRF      string    `json:"csrf_token"`
		ExpiresAt time.Time `json:"expires_at"`
		StartedAt time.Time `json:"started_at"`
	}
	if err := json.Unmarshal(envelope.Data, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.CSRF != csrf || payload.ExpiresAt.IsZero() || payload.StartedAt.IsZero() {
		t.Fatalf("session payload = %+v", payload)
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
	envelope := decodeAdminTestEnvelope(t, resp)
	if envelope.Error == nil || envelope.Error.Code != "UNAUTHORIZED" {
		t.Fatalf("missing CSRF envelope = %+v", envelope)
	}
}

func TestAdminAPIInvalidDeviceID(t *testing.T) {
	server, _, _, _, _, _ := adminAPIFixture(t)
	defer server.Close()
	client, csrf := adminLoginClient(t, server.URL)
	resp := adminAction(t, client, http.MethodPost, server.URL+"/admin/api/members/bad%20id/rename", csrf, `{"name":"Nope"}`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid ID status = %d", resp.StatusCode)
	}
	envelope := decodeAdminTestEnvelope(t, resp)
	if envelope.Error == nil || envelope.Error.Code != "INVALID_DEVICE_ID" {
		t.Fatalf("invalid ID envelope = %+v", envelope)
	}
}

func TestAdminAllowedHostAndOrigin(t *testing.T) {
	console := &adminConsole{listenAddress: "10.10.0.20:8081"}
	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.Host = "10.10.0.20:8081"
	if !console.allowedHost(req) {
		t.Fatal("configured host rejected")
	}
	req.Host = "evil.example:8081"
	req.Header.Set("X-Forwarded-Host", "10.10.0.20:8081")
	if console.allowedHost(req) {
		t.Fatal("forwarded host bypassed host validation")
	}
	req.Host = "10.10.0.20:9999"
	if console.allowedHost(req) {
		t.Fatal("wrong port accepted")
	}

	console.listenAddress = "127.0.0.1:8081"
	req = httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.Host = "localhost:8081"
	if !console.allowedHost(req) {
		t.Fatal("loopback alias rejected")
	}

	req = httptest.NewRequest(http.MethodPost, "/admin/api/members/device-a/ban", nil)
	req.Host = "127.0.0.1:8081"
	req.Header.Set("Origin", "http://127.0.0.1:8081")
	if !console.allowedOrigin(req) {
		t.Fatal("same-origin request rejected")
	}
	req.Header.Set("Origin", "http://evil.example")
	if console.allowedOrigin(req) {
		t.Fatal("cross-origin request accepted")
	}
	req.Header.Set("Origin", "https://127.0.0.1:8081")
	if console.allowedOrigin(req) {
		t.Fatal("scheme-mismatched origin accepted")
	}
}

func TestAdminPageDoesNotLeakToken(t *testing.T) {
	server, _, _, _, _, _ := adminAPIFixture(t)
	defer server.Close()
	resp, err := http.Get(server.URL + "/admin")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var body bytes.Buffer
	if _, err := body.ReadFrom(resp.Body); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(body.String(), "test-admin-token") {
		t.Fatal("admin page leaked token")
	}
}
func TestAdminAPIMemberTokenRejected(t *testing.T) {
	server, _, _, _, memberToken, _ := adminAPIFixture(t)
	defer server.Close()
	req, err := http.NewRequest(http.MethodGet, server.URL+"/admin/api/overview", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+memberToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("member token status = %d", resp.StatusCode)
	}
	envelope := decodeAdminTestEnvelope(t, resp)
	if envelope.Error == nil || envelope.Error.Code != "UNAUTHORIZED" {
		t.Fatalf("member token envelope = %+v", envelope)
	}
}

func TestAdminAPIRouteIsolationAndUnknownPaths(t *testing.T) {
	server, _, _, _, _, _ := adminAPIFixture(t)
	defer server.Close()
	for _, path := range []string{"/api/v1/status", "/admin/..%2fadmin", "/admin/%2e%2e/", "/admin/nope", "/admin/favicon.ico"} {
		resp, err := http.Get(server.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("%s status = %d, want 404", path, resp.StatusCode)
		}
		envelope := decodeAdminTestEnvelope(t, resp)
		if envelope.Error == nil || envelope.Error.Code != "NOT_FOUND" {
			t.Fatalf("%s envelope = %+v", path, envelope)
		}
	}
}

func TestAdminLoginResponseDoesNotLeakToken(t *testing.T) {
	server, _, _, _, _, _ := adminAPIFixture(t)
	defer server.Close()
	resp, err := http.Post(server.URL+"/admin/login", "application/json", bytes.NewBufferString(`{"token":"test-admin-token"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var body bytes.Buffer
	if _, err := body.ReadFrom(resp.Body); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(body.String(), "test-admin-token") {
		t.Fatal("login response leaked admin token")
	}
	if len(resp.Cookies()) != 1 || resp.Cookies()[0].Value == "test-admin-token" {
		t.Fatal("login cookie leaked admin token")
	}
}
func TestAdminMetricsEndpointRequiresAuthentication(t *testing.T) {
	store, err := storage.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	service := &Server{Store: store, Relay: network.NewRelayBroker(1024), StartedAt: time.Now().UTC()}
	server := httptest.NewServer(service.AdminHandler("test-admin-token", false))
	defer server.Close()

	resp, err := http.Get(server.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous /metrics status = %d, want 401", resp.StatusCode)
	}

	client, _ := adminLoginClient(t, server.URL)
	resp, err = client.Get(server.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("authenticated /metrics status = %d", resp.StatusCode)
	}
	var body strings.Builder
	if _, err := io.Copy(&body, resp.Body); err != nil {
		t.Fatal(err)
	}
	payload := body.String()
	for _, want := range []string{
		"tlan_active_members",
		"tlan_relay_sessions",
		"tlan_relay_queue_dropped_total",
		"tlan_client_version",
	} {
		if !strings.Contains(payload, want) {
			t.Fatalf("/metrics missing %q: %s", want, payload)
		}
	}
}
func TestAdminMetricsScrapeAuthenticatesWithRawAdminToken(t *testing.T) {
	store, err := storage.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	service := &Server{Store: store, Relay: network.NewRelayBroker(1024), StartedAt: time.Now().UTC()}
	server := httptest.NewServer(service.AdminHandler("test-admin-token", false))
	defer server.Close()

	req, err := http.NewRequest(http.MethodGet, server.URL+"/metrics", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Admin-Token", "test-admin-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("token /metrics status = %d", resp.StatusCode)
	}
	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(payload), "tlan_active_members") {
		t.Fatalf("token /metrics body missing metrics: %s", payload)
	}
}
func TestAdminMetricsUsesCounterTypesForCumulativeRelayDrops(t *testing.T) {
	store, err := storage.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	service := &Server{Store: store, Relay: network.NewRelayBroker(1024), StartedAt: time.Now().UTC()}
	server := httptest.NewServer(service.AdminHandler("test-admin-token", false))
	defer server.Close()
	req, err := http.NewRequest(http.MethodGet, server.URL+"/metrics", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Admin-Token", "test-admin-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"# TYPE tlan_active_members gauge",
		"# TYPE tlan_relay_sessions gauge",
		"# TYPE tlan_relay_queue_dropped_total counter",
		"# TYPE tlan_relay_backpressure_total counter",
		"# TYPE tlan_relay_write_errors_total counter",
	} {
		if !strings.Contains(string(payload), want) {
			t.Fatalf("/metrics missing %q: %s", want, payload)
		}
	}
}
func TestAdminMetricsVersionDistributionIncludesBlockedMembers(t *testing.T) {
	store, err := storage.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	privateNetwork, err := store.EnsurePrivateNetwork("Metrics", "test-join-code", "10.252.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	keyA := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	keyB := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))
	_, first, _, err := store.EnrollPrivate(core.RegisterDeviceRequest{DeviceID: "metrics-a", WireGuardPublicKey: keyA}, "test-join-code")
	if err != nil {
		t.Fatal(err)
	}
	_, second, _, err := store.EnrollPrivate(core.RegisterDeviceRequest{DeviceID: "metrics-b", WireGuardPublicKey: keyB}, "test-join-code")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetClientVersion(core.DeviceID(first.ID), "v0.7.0"); err != nil {
		t.Fatal(err)
	}
	if err := store.SetClientVersion(core.DeviceID(second.ID), "v0.6.0"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SetDeviceBlocked(privateNetwork.ID, second.ID, true); err != nil {
		t.Fatal(err)
	}
	service := &Server{Store: store, Relay: network.NewRelayBroker(1024), StartedAt: time.Now().UTC()}
	server := httptest.NewServer(service.AdminHandler("test-admin-token", false))
	defer server.Close()
	req, err := http.NewRequest(http.MethodGet, server.URL+"/metrics", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Admin-Token", "test-admin-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`version="v0.7.0"} 1`, `version="v0.6.0"} 1`} {
		if !strings.Contains(string(payload), want) {
			t.Fatalf("version distribution missing %q: %s", want, payload)
		}
	}
}

func TestAdminWebAPISetFRPPortRange(t *testing.T) {
	server, store, _, _, _, _ := adminAPIFixture(t)
	defer server.Close()
	client, csrf := adminLoginClient(t, server.URL)

	envelope := decodeAdminTestEnvelope(t, adminAction(t, client, http.MethodPost, server.URL+"/admin/api/frp-port-range", csrf, `{"start":60100,"end":60200}`))
	if !envelope.OK {
		t.Fatalf("set port range envelope = %+v", envelope)
	}
	if got := store.FRPPortRange(); got.Start != 60100 || got.End != 60200 {
		t.Fatalf("store.FRPPortRange = %+v", got)
	}
	bad := decodeAdminTestEnvelope(t, adminAction(t, client, http.MethodPost, server.URL+"/admin/api/frp-port-range", csrf, `{"start":61000,"end":60000}`))
	if bad.OK {
		t.Fatalf("expected invalid reversed range failure, got %+v", bad)
	}
}

func TestAdminServerDisplayAndBootstrap(t *testing.T) {
	store, err := storage.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.EnsurePrivateNetwork("private-mesh", "join-secret-1234", "10.77.0.0/24"); err != nil {
		t.Fatal(err)
	}
	srv := &Server{
		Store:      store,
		AdminToken: "test-admin-token",
		FRPBootstrap: func() (FRPBootstrapConfig, error) {
			return FRPBootstrapConfig{Enabled: true, Mode: "external", Port: 7000, Transport: "tcp", Token: "boot-tok"}, nil
		},
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	adminTS := httptest.NewServer(srv.AdminHandler(srv.AdminToken, false))
	defer adminTS.Close()

	httpClient, csrf := adminLoginClient(t, adminTS.URL)

	// Configure custom alias via admin endpoint.
	okEnv := decodeAdminTestEnvelope(t, adminAction(t, httpClient, http.MethodPost, adminTS.URL+"/admin/api/server-display", csrf, `{"mode":"alias","alias":"深圳中继节点"}`))
	if !okEnv.OK {
		t.Fatalf("expected server-display update ok, got %+v", okEnv)
	}
	got := store.ServerDisplay()
	if got.Mode != "alias" || got.Alias != "深圳中继节点" {
		t.Fatalf("stored server display = %+v", got)
	}

	// Empty alias in alias mode must be rejected.
	badEnv := decodeAdminTestEnvelope(t, adminAction(t, httpClient, http.MethodPost, adminTS.URL+"/admin/api/server-display", csrf, `{"mode":"alias","alias":""}`))
	if badEnv.OK {
		t.Fatalf("expected error on blank alias in alias mode, got %+v", badEnv)
	}

	// Verify /api/v1/status reports 1.0.0 with admin token.
	statusReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/status", nil)
	statusReq.Header.Set("X-Admin-Token", srv.AdminToken)
	resp, err := http.DefaultClient.Do(statusReq)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status HTTP %d", resp.StatusCode)
	}
	var st map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		t.Fatal(err)
	}
	if st["version"] != "1.0.0" {
		t.Fatalf("status version = %v, want 1.0.0", st["version"])
	}

	// Verify /api/v1/frp/bootstrap works with member token.
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	_, _, memberToken, err := store.EnrollPrivate(core.RegisterDeviceRequest{
		DeviceID:           core.DeviceID("dev-bootstrap-1"),
		DisplayName:        "Node-1",
		WireGuardPublicKey: key,
	}, "join-secret-1234")
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/frp/bootstrap", nil)
	req.Header.Set("Authorization", "Bearer "+memberToken)
	bootResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer bootResp.Body.Close()
	if bootResp.StatusCode != http.StatusOK {
		t.Fatalf("bootstrap HTTP %d", bootResp.StatusCode)
	}
	var boot FRPBootstrapConfig
	if err := json.NewDecoder(bootResp.Body).Decode(&boot); err != nil {
		t.Fatal(err)
	}
	if !boot.Enabled || boot.Token != "boot-tok" || boot.Port != 7000 {
		t.Fatalf("unexpected bootstrap payload: %+v", boot)
	}

	// Rename network via admin API and check store updates.
	netEnv := decodeAdminTestEnvelope(t, adminAction(t, httpClient, http.MethodPost, adminTS.URL+"/admin/api/network-name", csrf, `{"name":"TLAN 工作室内网"}`))
	if !netEnv.OK {
		t.Fatalf("expected network-name update ok, got %+v", netEnv)
	}
	summary, err := store.PrivateNetwork()
	if err != nil || summary.Name != "TLAN 工作室内网" {
		t.Fatalf("renamed network = %+v, err=%v", summary, err)
	}
}
