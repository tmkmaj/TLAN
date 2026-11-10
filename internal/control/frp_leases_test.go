package control

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/private-radminlan/lanmesh/core"
	"github.com/private-radminlan/lanmesh/internal/frpauth"
	"github.com/private-radminlan/lanmesh/internal/storage"
)

type frpAPIFixture struct {
	store   *storage.Store
	frp     *frpauth.Store
	service *Server
	server  *httptest.Server
	network string
	device  string
	token   string
}

func newFRPAPIFixture(t *testing.T) *frpAPIFixture {
	t.Helper()
	store, err := storage.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	network, err := store.EnsurePrivateNetwork("FRP API", "frp-api-passcode", "10.245.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	_, device, token, err := store.EnrollPrivate(core.RegisterDeviceRequest{
		DeviceID:           core.DeviceID("dev-frp-a"),
		WireGuardPublicKey: key,
		DisplayName:        "FRP API device",
	}, "frp-api-passcode")
	if err != nil {
		t.Fatal(err)
	}
	frpStore, err := frpauth.NewStore(frpauth.Options{
		StatePath:      filepath.Join(t.TempDir(), "frp-leases.json"),
		ServerID:       "frps-managed-1",
		CoreVersion:    "0.71.1",
		LeaseTTL:       10 * time.Minute,
		AllowedPorts:   []frpauth.PortRange{{Start: 30000, End: 30099}},
		AllowedDomains: []string{"frp.example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	service := &Server{Store: store, AdminToken: "admin-token", FRP: frpStore}
	return &frpAPIFixture{
		store:   store,
		frp:     frpStore,
		service: service,
		server:  httptest.NewServer(service.Handler()),
		network: network.ID,
		device:  device.ID,
		token:   token,
	}
}

func (f *frpAPIFixture) close() { f.server.Close() }

func (f *frpAPIFixture) request(method, path, token, body string) *http.Response {
	request, _ := http.NewRequest(method, f.server.URL+path, strings.NewReader(body))
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		panic(err)
	}
	return response
}

func leaseRequest(networkID, deviceID string) string {
	return `{"network_id":"` + networkID + `","device_id":"` + deviceID + `","server_id":"frps-managed-1","rules":[` +
		`{"id":"rule-tcp","proxy_name":"tlan_tcp","type":"tcp","remote_port":30001,"bind_port":8080},` +
		`{"id":"rule-http","proxy_name":"tlan_http","type":"http","custom_domains":["app.frp.example.com"],"bind_port":8081}` +
		`]}`
}

func TestFRPLeaseRequiresMemberToken(t *testing.T) {
	fixture := newFRPAPIFixture(t)
	defer fixture.close()
	body := leaseRequest(fixture.network, fixture.device)

	response := fixture.request(http.MethodPost, "/api/v1/frp/leases", "", body)
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated FRP lease status = %d, body = %s", response.StatusCode, readResponse(response))
	}
	response.Body.Close()

	response = fixture.request(http.MethodPost, "/api/v1/frp/leases", fixture.service.AdminToken, body)
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("admin-token FRP lease status = %d, body = %s", response.StatusCode, readResponse(response))
	}
	response.Body.Close()

	response = fixture.request(http.MethodGet, "/api/v1/frp/capabilities", "", "")
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated FRP capabilities status = %d, body = %s", response.StatusCode, readResponse(response))
	}
	response.Body.Close()
}

func TestFRPLeaseMemberAPIAndRevocation(t *testing.T) {
	fixture := newFRPAPIFixture(t)
	defer fixture.close()
	response := fixture.request(http.MethodGet, "/api/v1/frp/capabilities", fixture.token, "")
	if response.StatusCode != http.StatusOK {
		t.Fatalf("capabilities status = %d, body = %s", response.StatusCode, readResponse(response))
	}
	var capabilities frpauth.Capabilities
	if err := json.NewDecoder(response.Body).Decode(&capabilities); err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if capabilities.Mode != frpauth.ModeManaged || capabilities.CoreVersion != "0.71.1" || len(capabilities.PluginOps) != 4 {
		t.Fatalf("capabilities = %+v", capabilities)
	}

	response = fixture.request(http.MethodPost, "/api/v1/frp/leases", fixture.token, leaseRequest(fixture.network, fixture.device))
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("create status = %d, body = %s", response.StatusCode, readResponse(response))
	}
	var lease frpauth.LeaseResponse
	if err := json.NewDecoder(response.Body).Decode(&lease); err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if lease.LeaseID == "" || lease.Credential == "" || len(lease.Rules) != 2 {
		t.Fatalf("lease response = %+v", lease)
	}

	response = fixture.request(http.MethodPost, "/api/v1/frp/leases/"+lease.LeaseID+"/renew", fixture.token, "")
	if response.StatusCode != http.StatusOK {
		t.Fatalf("renew status = %d, body = %s", response.StatusCode, readResponse(response))
	}
	var renewed frpauth.LeaseResponse
	if err := json.NewDecoder(response.Body).Decode(&renewed); err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if renewed.LeaseID != lease.LeaseID || renewed.Credential != "" || !renewed.ExpiresAt.After(lease.ExpiresAt) {
		t.Fatalf("renewed lease = %+v", renewed)
	}
	if err := fixture.frp.AuthorizeLogin(frpauth.LoginRequest{
		LeaseID: lease.LeaseID, Capability: lease.Credential, ServerID: "frps-managed-1", User: "device-user", RunID: "run-a",
	}); err != nil {
		t.Fatal(err)
	}
	if err := fixture.frp.AuthorizeNewProxy(frpauth.NewProxyRequest{
		LeaseID: lease.LeaseID, Capability: lease.Credential, ServerID: "frps-managed-1",
		User: "device-user", RunID: "run-a", ProxyName: "tlan_tcp", ProxyType: "tcp", RemotePort: 30001,
	}); err != nil {
		t.Fatal(err)
	}
	response = fixture.request(http.MethodGet, "/api/v1/frp/leases/"+lease.LeaseID+"/status", fixture.token, "")
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status code = %d, body = %s", response.StatusCode, readResponse(response))
	}
	var status frpauth.LeaseStatus
	if err := json.NewDecoder(response.Body).Decode(&status); err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if !status.LoginSeen || !status.ProxySeen || status.Revoked {
		t.Fatalf("lease status = %+v", status)
	}

	// The API response is the only source of the plaintext capability. A
	// second request must not be able to obtain or enumerate it.
	response = fixture.request(http.MethodDelete, "/api/v1/frp/leases/"+lease.LeaseID, fixture.token, "")
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("revoke status = %d, body = %s", response.StatusCode, readResponse(response))
	}
	response.Body.Close()

	response = fixture.request(http.MethodPost, "/api/v1/frp/leases/"+lease.LeaseID+"/renew", fixture.token, "")
	if response.StatusCode != http.StatusGone {
		t.Fatalf("revoked renew status = %d, body = %s", response.StatusCode, readResponse(response))
	}
	response.Body.Close()

	login := map[string]any{
		"version": "0.71.1", "user": "device-user", "run_id": "run-a",
		"metas": map[string]string{"tlan_lease": lease.LeaseID, "tlan_capability": lease.Credential, "tlan_server": "frps-managed-1"},
	}
	body, _ := json.Marshal(map[string]any{"version": frpauth.PluginAPIVersion, "op": "Login", "content": login})
	pluginRequest := httptest.NewRequest(http.MethodPost, frpauth.PluginPath+"?version="+frpauth.PluginAPIVersion+"&op=Login", bytes.NewReader(body))
	pluginRecorder := httptest.NewRecorder()
	frpauth.NewPluginHandler(fixture.frp).ServeHTTP(pluginRecorder, pluginRequest)
	if pluginRecorder.Code != http.StatusOK || !strings.Contains(pluginRecorder.Body.String(), "FRP_LEASE_REVOKED") {
		t.Fatalf("revoked plugin response = %d %s", pluginRecorder.Code, pluginRecorder.Body.String())
	}
}

func TestFRPLeaseBindsMeshTargetsToServerDirectory(t *testing.T) {
	fixture := newFRPAPIFixture(t)
	defer fixture.close()
	keyBytes := make([]byte, 32)
	keyBytes[0] = 2
	key := base64.StdEncoding.EncodeToString(keyBytes)
	_, peer, _, err := fixture.store.EnrollPrivate(core.RegisterDeviceRequest{
		DeviceID: core.DeviceID("dev-frp-b"), WireGuardPublicKey: key, DisplayName: "FRP peer",
	}, "frp-api-passcode")
	if err != nil {
		t.Fatal(err)
	}
	body := func(target frpauth.Rule) string {
		target.ID = "rule-mesh"
		target.ProxyName = "tlan_mesh"
		target.Type = "tcp"
		target.RemotePort = 30002
		target.BindPort = 8080
		data, err := json.Marshal(map[string]any{
			"network_id": fixture.network, "device_id": fixture.device, "server_id": "frps-managed-1",
			"rules": []frpauth.Rule{target},
		})
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}

	serviceBody, err := json.Marshal(map[string]any{
		"network_id": fixture.network, "device_id": peer.ID, "service_id": "svc-peer",
		"protocol": "tcp", "port": 8080, "description": "FRP test service", "ttl_seconds": 3600,
	})
	if err != nil {
		t.Fatal(err)
	}
	response := fixture.request(http.MethodPost, "/api/v1/frp/services", "admin-token", string(serviceBody))
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("service grant status = %d, body = %s", response.StatusCode, readResponse(response))
	}
	var service frpauth.ServiceResponse
	if err := json.NewDecoder(response.Body).Decode(&service); err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	peerRule := frpauth.Rule{
		TargetKind: "mesh_peer", TargetNetworkID: fixture.network, TargetDeviceID: peer.ID,
		TargetPublicKey: peer.PublicKey, TargetHost: peer.VirtualIP, TargetServiceID: service.ID,
	}
	response = fixture.request(http.MethodPost, "/api/v1/frp/leases", fixture.token, body(peerRule))
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("peer grant status = %d, body = %s", response.StatusCode, readResponse(response))
	}
	var peerLease frpauth.LeaseResponse
	if err := json.NewDecoder(response.Body).Decode(&peerLease); err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if len(peerLease.Rules) != 1 || peerLease.Rules[0].TargetDeviceID != peer.ID || peerLease.Rules[0].TargetHost != peer.VirtualIP {
		t.Fatalf("peer grant = %+v", peerLease.Rules)
	}
	response = fixture.request(http.MethodDelete, "/api/v1/frp/leases/"+peerLease.LeaseID, fixture.token, "")
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("revoke peer grant status = %d, body = %s", response.StatusCode, readResponse(response))
	}
	response.Body.Close()

	response = fixture.request(http.MethodPost, "/api/v1/frp/leases", fixture.token, body(frpauth.Rule{
		TargetKind: "mesh_peer", TargetNetworkID: fixture.network, TargetDeviceID: peer.ID,
		TargetPublicKey: peer.PublicKey, TargetHost: "10.245.0.99", TargetServiceID: service.ID,
	}))
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("forged peer target status = %d, body = %s", response.StatusCode, readResponse(response))
	}
	response.Body.Close()

	response = fixture.request(http.MethodPost, "/api/v1/frp/leases", fixture.token, body(frpauth.Rule{
		TargetKind: "mesh_peer", TargetNetworkID: fixture.network, TargetDeviceID: fixture.device,
		TargetPublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", TargetHost: "10.245.0.2", TargetServiceID: service.ID,
	}))
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("self-as-peer status = %d, body = %s", response.StatusCode, readResponse(response))
	}
	response.Body.Close()

	memberIP := ""
	for _, item := range mustDevices(t, fixture.store, fixture.network) {
		if item.ID == fixture.device {
			memberIP = item.VirtualIP
		}
	}
	response = fixture.request(http.MethodPost, "/api/v1/frp/leases", fixture.token, body(frpauth.Rule{
		TargetKind: "mesh_self", TargetNetworkID: fixture.network, TargetDeviceID: fixture.device,
		TargetHost: memberIP,
	}))
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("self grant status = %d, body = %s", response.StatusCode, readResponse(response))
	}
	var selfLease frpauth.LeaseResponse
	if err := json.NewDecoder(response.Body).Decode(&selfLease); err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if len(selfLease.Rules) != 1 || selfLease.Rules[0].TargetPublicKey == "" {
		t.Fatalf("self grant did not bind public key: %+v", selfLease.Rules)
	}
}

func mustDevices(t *testing.T, store *storage.Store, networkID string) []storage.Device {
	t.Helper()
	devices, err := store.ListDevices(networkID)
	if err != nil {
		t.Fatal(err)
	}
	return devices
}

func TestRemovingMemberRevokesManagedLeases(t *testing.T) {
	fixture := newFRPAPIFixture(t)
	defer fixture.close()
	response := fixture.request(http.MethodGet, "/api/v1/frp/capabilities", fixture.token, "")
	if response.StatusCode != http.StatusOK {
		t.Fatalf("capabilities status = %d, body = %s", response.StatusCode, readResponse(response))
	}
	var capabilities frpauth.Capabilities
	if err := json.NewDecoder(response.Body).Decode(&capabilities); err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if capabilities.Mode != frpauth.ModeManaged || capabilities.CoreVersion != "0.71.1" || len(capabilities.PluginOps) != 4 {
		t.Fatalf("capabilities = %+v", capabilities)
	}

	response = fixture.request(http.MethodPost, "/api/v1/frp/leases", fixture.token, leaseRequest(fixture.network, fixture.device))
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("create status = %d, body = %s", response.StatusCode, readResponse(response))
	}
	var lease frpauth.LeaseResponse
	if err := json.NewDecoder(response.Body).Decode(&lease); err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	response = fixture.request(http.MethodDelete, "/api/v1/networks/"+fixture.network+"/devices?id="+fixture.device, "admin-token", "")
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("remove member status = %d, body = %s", response.StatusCode, readResponse(response))
	}
	response.Body.Close()
	if err := fixture.frp.AuthorizeLogin(frpauth.LoginRequest{
		LeaseID: lease.LeaseID, Capability: lease.Credential, ServerID: "frps-managed-1", User: "device-user", RunID: "run-a",
	}); !errors.Is(err, frpauth.ErrRevoked) {
		t.Fatalf("removed member lease error = %v", err)
	}
}

func TestFRPLeaseRequiresMemberOwnership(t *testing.T) {
	fixture := newFRPAPIFixture(t)
	defer fixture.close()
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	// The key must differ from the first member's key.
	keyBytes := make([]byte, 32)
	keyBytes[0] = 1
	key = base64.StdEncoding.EncodeToString(keyBytes)
	_, _, otherToken, err := fixture.store.EnrollPrivate(core.RegisterDeviceRequest{
		DeviceID: core.DeviceID("dev-frp-b"), WireGuardPublicKey: key, DisplayName: "Other",
	}, "frp-api-passcode")
	if err != nil {
		t.Fatal(err)
	}
	response := fixture.request(http.MethodPost, "/api/v1/frp/leases", otherToken, leaseRequest(fixture.network, fixture.device))
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-member create status = %d, body = %s", response.StatusCode, readResponse(response))
	}
	response.Body.Close()

	response = fixture.request(http.MethodPost, "/api/v1/frp/leases", "admin-token", leaseRequest(fixture.network, fixture.device))
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("admin lease create status = %d, body = %s", response.StatusCode, readResponse(response))
	}
	response.Body.Close()

	response = fixture.request(http.MethodPost, "/api/v1/frp/leases", "", leaseRequest(fixture.network, fixture.device))
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d", response.StatusCode)
	}
	response.Body.Close()

	response = fixture.request(http.MethodPost, "/api/v1/frp/leases", fixture.token, leaseRequest(fixture.network, fixture.device))
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("owner create status = %d", response.StatusCode)
	}
	var lease frpauth.LeaseResponse
	if err := json.NewDecoder(response.Body).Decode(&lease); err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	response = fixture.request(http.MethodDelete, "/api/v1/frp/leases/"+lease.LeaseID, otherToken, "")
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("cross-member revoke status = %d", response.StatusCode)
	}
	response.Body.Close()
}

func TestFRPLeaseStrictJSONAndDisabledMode(t *testing.T) {
	fixture := newFRPAPIFixture(t)
	defer fixture.close()
	response := fixture.request(http.MethodPost, "/api/v1/frp/leases", fixture.token, `{"network_id":"`+fixture.network+`","device_id":"`+fixture.device+`","server_id":"frps-managed-1","rules":[],"unknown":true}`)
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown field status = %d", response.StatusCode)
	}
	response.Body.Close()

	fixture.service.FRP = nil
	response = fixture.request(http.MethodPost, "/api/v1/frp/leases", fixture.token, leaseRequest(fixture.network, fixture.device))
	if response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("disabled status = %d", response.StatusCode)
	}
	response.Body.Close()
}

func readResponse(response *http.Response) string {
	defer response.Body.Close()
	body := new(bytes.Buffer)
	_, _ = body.ReadFrom(response.Body)
	return body.String()
}

func TestFRPServiceTargetMemberApprovalAPI(t *testing.T) {
	fixture := newFRPAPIFixture(t)
	defer fixture.close()
	keyBytes := make([]byte, 32)
	keyBytes[0] = 2
	_, targetDevice, targetToken, err := fixture.store.EnrollPrivate(core.RegisterDeviceRequest{
		DeviceID: core.DeviceID("dev-frp-approval-target"), WireGuardPublicKey: base64.StdEncoding.EncodeToString(keyBytes), DisplayName: "Approval target",
	}, "frp-api-passcode")
	if err != nil {
		t.Fatal(err)
	}

	requestBody := `{"target_device_id":"` + targetDevice.ID + `","service_id":"svc_api_approval","protocol":"tcp","port":8080,"description":"approval API","ttl_seconds":3600}`
	response := fixture.request(http.MethodPost, "/api/v1/frp/services/requests", fixture.token, requestBody)
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("request status = %d, body = %s", response.StatusCode, readResponse(response))
	}
	var service frpauth.ServiceResponse
	if err := json.NewDecoder(response.Body).Decode(&service); err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if service.ApprovalStatus != frpauth.ServiceApprovalPending || service.RequesterDeviceID != fixture.device {
		t.Fatalf("pending service = %+v", service)
	}

	response = fixture.request(http.MethodGet, "/api/v1/frp/services/pending", targetToken, "")
	if response.StatusCode != http.StatusOK {
		t.Fatalf("pending status = %d, body = %s", response.StatusCode, readResponse(response))
	}
	var pending struct {
		Services []frpauth.ServiceResponse `json:"services"`
	}
	if err := json.NewDecoder(response.Body).Decode(&pending); err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if len(pending.Services) != 1 || pending.Services[0].ID != service.ID {
		t.Fatalf("pending services = %+v", pending.Services)
	}

	response = fixture.request(http.MethodPost, "/api/v1/frp/services/"+service.ID+"/approve", fixture.token, "")
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("requester approved its own request: status = %d", response.StatusCode)
	}
	response.Body.Close()
	response = fixture.request(http.MethodPost, "/api/v1/frp/services/"+service.ID+"/approve", targetToken, "")
	if response.StatusCode != http.StatusOK {
		t.Fatalf("approve status = %d, body = %s", response.StatusCode, readResponse(response))
	}
	var approved frpauth.ServiceResponse
	if err := json.NewDecoder(response.Body).Decode(&approved); err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if approved.ApprovalStatus != frpauth.ServiceApprovalApproved || approved.ApprovedBy != targetDevice.ID {
		t.Fatalf("approved service = %+v", approved)
	}

	response = fixture.request(http.MethodGet, "/api/v1/frp/services?network_id="+fixture.network+"&device_id="+targetDevice.ID, targetToken, "")
	if response.StatusCode != http.StatusOK {
		t.Fatalf("target list status = %d, body = %s", response.StatusCode, readResponse(response))
	}
	response.Body.Close()

	denyBody := `{"target_device_id":"` + targetDevice.ID + `","service_id":"svc_api_denied","protocol":"tcp","port":8081,"description":"deny API","ttl_seconds":3600}`
	response = fixture.request(http.MethodPost, "/api/v1/frp/services/requests", fixture.token, denyBody)
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("deny request status = %d, body = %s", response.StatusCode, readResponse(response))
	}
	var denyService frpauth.ServiceResponse
	if err := json.NewDecoder(response.Body).Decode(&denyService); err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	response = fixture.request(http.MethodPost, "/api/v1/frp/services/"+denyService.ID+"/deny", targetToken, "")
	if response.StatusCode != http.StatusOK {
		t.Fatalf("deny status = %d, body = %s", response.StatusCode, readResponse(response))
	}
	var denied frpauth.ServiceResponse
	if err := json.NewDecoder(response.Body).Decode(&denied); err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if denied.ApprovalStatus != frpauth.ServiceApprovalDenied {
		t.Fatalf("denied service = %+v", denied)
	}
}

func TestFRPLeaseAPIAdvancedFields(t *testing.T) {
	fixture := newFRPAPIFixture(t)
	defer fixture.close()
	rules := []frpauth.Rule{
		{
			ID: "rule-http-advanced", ProxyName: "tlan_http_advanced", Type: "http", BindPort: 8081,
			CustomDomains: []string{"app.frp.example.com"}, SubDomain: "app", Locations: []string{"/", "/api"},
			HTTPUser: "alice", HTTPPasswordHash: frpauth.HashSecret("api-password"),
			HostHeaderRewrite: "backend.frp.example.com", Headers: map[string]string{"X-From": "tlan"},
			ResponseHeaders: map[string]string{"X-Response": "tlan"}, RouteByHTTPUser: "alice",
		},
		{
			ID: "rule-tcpmux", ProxyName: "tlan_tcpmux", Type: "tcpmux", BindPort: 8082,
			CustomDomains: []string{"mux.frp.example.com"}, Multiplexer: "httpconnect",
			HTTPUser: "bob", HTTPPasswordHash: frpauth.HashSecret("mux-password"), RouteByHTTPUser: "bob",
		},
		{
			ID: "rule-xtcp", ProxyName: "tlan_xtcp", Type: "xtcp", BindPort: 8083,
			SecretHash: frpauth.HashSecret("xtcp-secret"), AllowUsers: []string{"peer-b", "peer-a"},
		},
	}
	body, err := json.Marshal(map[string]any{
		"network_id": fixture.network, "device_id": fixture.device, "server_id": "frps-managed-1", "rules": rules,
	})
	if err != nil {
		t.Fatal(err)
	}
	response := fixture.request(http.MethodPost, "/api/v1/frp/leases", fixture.token, string(body))
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("advanced lease status = %d, body = %s", response.StatusCode, readResponse(response))
	}
	var lease frpauth.LeaseResponse
	if err := json.NewDecoder(response.Body).Decode(&lease); err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if len(lease.Rules) != 3 || lease.Rules[0].HTTPPasswordHash == "" || lease.Rules[1].Multiplexer != "httpconnect" || lease.Rules[2].SecretHash == "" {
		t.Fatalf("advanced lease response = %+v", lease)
	}
}
