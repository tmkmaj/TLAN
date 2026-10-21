package frpauth

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type pluginFixture struct {
	store *Store
	lease LeaseResponse
	user  string
	runID string
	metas map[string]string
}

func newPluginFixture(t *testing.T) pluginFixture {
	t.Helper()
	store, _ := testStore(t)
	lease, err := store.Issue("net-test", "dev-test", "frps-managed-1", testRules())
	if err != nil {
		t.Fatal(err)
	}
	return pluginFixture{
		store: store,
		lease: lease,
		user:  "device-user",
		runID: "run-a",
		metas: map[string]string{
			metadataLease:      lease.LeaseID,
			metadataCapability: lease.Credential,
			metadataServer:     "frps-managed-1",
		},
	}
}

func (f pluginFixture) call(t *testing.T, op string, content any) pluginResponse {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"version": PluginAPIVersion,
		"op":      op,
		"content": content,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, PluginPath+"?version="+PluginAPIVersion+"&op="+op, bytes.NewReader(body))
	recorder := httptest.NewRecorder()
	NewPluginHandler(f.store).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("%s status = %d, body = %s", op, recorder.Code, recorder.Body.String())
	}
	var response pluginResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	return response
}

func (f pluginFixture) loginContent(metas map[string]string) map[string]any {
	return map[string]any{
		"version":        "0.71.1",
		"hostname":       "fixture",
		"os":             "windows",
		"arch":           "amd64",
		"user":           f.user,
		"run_id":         f.runID,
		"metas":          metas,
		"client_address": "127.0.0.1:12345",
	}
}

func (f pluginFixture) proxyContent(metas map[string]string, name, proxyType string, remotePort int, domains []string) map[string]any {
	content := map[string]any{
		"user": map[string]any{
			"user":   f.user,
			"metas":  metas,
			"run_id": f.runID,
		},
		"proxy_name": name,
		"proxy_type": proxyType,
	}
	if remotePort != 0 {
		content["remote_port"] = remotePort
	}
	if len(domains) != 0 {
		content["custom_domains"] = domains
	}
	return content
}

func (f pluginFixture) sessionContent(metas map[string]string) map[string]any {
	return map[string]any{
		"user": map[string]any{
			"user": f.user, "metas": metas, "run_id": f.runID,
		},
		"privilege_key": "fixture-key",
		"timestamp":     1,
	}
}

func (f pluginFixture) userConnContent(metas map[string]string, name, proxyType string) map[string]any {
	return map[string]any{
		"user": map[string]any{
			"user": f.user, "metas": metas, "run_id": f.runID,
		},
		"proxy_name":  name,
		"proxy_type":  proxyType,
		"remote_addr": "203.0.113.9:45678",
	}
}

func TestPluginLoginAndNewProxySuccess(t *testing.T) {
	fixture := newPluginFixture(t)
	if response := fixture.call(t, "Login", fixture.loginContent(fixture.metas)); response.Reject {
		t.Fatalf("login rejected: %s", response.RejectReason)
	}
	if response := fixture.call(t, "NewProxy", fixture.proxyContent(fixture.metas, "tlan_tcp", "tcp", 30001, nil)); response.Reject {
		t.Fatalf("proxy rejected: %s", response.RejectReason)
	}
	if response := fixture.call(t, "NewProxy", fixture.proxyContent(fixture.metas, "tlan_http", "http", 0, []string{"app.frp.example.com"})); response.Reject {
		t.Fatalf("HTTP proxy rejected: %s", response.RejectReason)
	}
	if response := fixture.call(t, "Ping", fixture.sessionContent(fixture.metas)); response.Reject {
		t.Fatalf("heartbeat rejected: %s", response.RejectReason)
	}
	if response := fixture.call(t, "NewUserConn", fixture.userConnContent(fixture.metas, "tlan_tcp", "tcp")); response.Reject {
		t.Fatalf("user connection rejected: %s", response.RejectReason)
	}
	if response := fixture.call(t, "NewUserConn", fixture.userConnContent(fixture.metas, "tlan_tcp", "udp")); !response.Reject {
		t.Fatal("user connection with mismatched proxy type was accepted")
	}
}

func TestPluginRevocationStopsHeartbeatAndNewConnections(t *testing.T) {
	fixture := newPluginFixture(t)
	if response := fixture.call(t, "Login", fixture.loginContent(fixture.metas)); response.Reject {
		t.Fatalf("login rejected: %s", response.RejectReason)
	}
	if response := fixture.call(t, "NewProxy", fixture.proxyContent(fixture.metas, "tlan_tcp", "tcp", 30001, nil)); response.Reject {
		t.Fatalf("proxy rejected: %s", response.RejectReason)
	}
	if err := fixture.store.Revoke(fixture.lease.LeaseID, "net-test", "dev-test"); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		op      string
		content any
	}{
		{op: "Ping", content: fixture.sessionContent(fixture.metas)},
		{op: "NewUserConn", content: fixture.userConnContent(fixture.metas, "tlan_tcp", "tcp")},
	} {
		response := fixture.call(t, tc.op, tc.content)
		if !response.Reject || !strings.Contains(response.RejectReason, "FRP_LEASE_REVOKED") {
			t.Fatalf("%s response = %+v", tc.op, response)
		}
	}
}

func TestPluginFailsClosedForMissingOrForgedMetadata(t *testing.T) {
	fixture := newPluginFixture(t)
	cases := []struct {
		name   string
		metas  map[string]string
		reason string
	}{
		{name: "missing", metas: nil, reason: "FRP_AUTH_REJECTED"},
		{name: "wrong capability", metas: map[string]string{metadataLease: fixture.lease.LeaseID, metadataCapability: "cap_wrong_wrong_wrong_wrong_wrong", metadataServer: "frps-managed-1"}, reason: "FRP_AUTH_REJECTED"},
		{name: "wrong server", metas: map[string]string{metadataLease: fixture.lease.LeaseID, metadataCapability: fixture.lease.Credential, metadataServer: "frps-other"}, reason: "FRP_AUTH_REJECTED"},
		{name: "extra tlan key", metas: map[string]string{metadataLease: fixture.lease.LeaseID, metadataCapability: fixture.lease.Credential, metadataServer: "frps-managed-1", "tlan_extra": "x"}, reason: "FRP_AUTH_REJECTED"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			response := fixture.call(t, "Login", fixture.loginContent(tc.metas))
			if !response.Reject || !strings.Contains(response.RejectReason, tc.reason) {
				t.Fatalf("response = %+v", response)
			}
		})
	}
}

func TestPluginRejectsMismatchedProxyResources(t *testing.T) {
	fixture := newPluginFixture(t)
	if response := fixture.call(t, "Login", fixture.loginContent(fixture.metas)); response.Reject {
		t.Fatalf("login rejected: %s", response.RejectReason)
	}
	cases := []struct {
		name    string
		content map[string]any
		reason  string
	}{
		{name: "wrong port", content: fixture.proxyContent(fixture.metas, "tlan_tcp", "tcp", 30002, nil), reason: "FRP_REMOTE_PORT_DENIED"},
		{name: "wrong type", content: fixture.proxyContent(fixture.metas, "tlan_tcp", "udp", 30001, nil), reason: "FRP_AUTH_REJECTED"},
		{name: "wrong domain", content: fixture.proxyContent(fixture.metas, "tlan_http", "http", 0, []string{"other.frp.example.com"}), reason: "FRP_DOMAIN_DENIED"},
		{name: "unknown proxy", content: fixture.proxyContent(fixture.metas, "tlan_unknown", "tcp", 30001, nil), reason: "FRP_AUTH_REJECTED"},
		{name: "subdomain bypass", content: func() map[string]any {
			content := fixture.proxyContent(fixture.metas, "tlan_tcp", "tcp", 30001, nil)
			content["subdomain"] = "evil"
			return content
		}(), reason: "FRP_AUTH_REJECTED"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			response := fixture.call(t, "NewProxy", tc.content)
			if !response.Reject || !strings.Contains(response.RejectReason, tc.reason) {
				t.Fatalf("response = %+v", response)
			}
		})
	}
}

func TestPluginRejectsProtocolMismatchAndUnsupportedOp(t *testing.T) {
	fixture := newPluginFixture(t)
	body, err := json.Marshal(map[string]any{"version": PluginAPIVersion, "op": "Login", "content": fixture.loginContent(fixture.metas)})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, PluginPath+"?version=9.9.9&op=Login", bytes.NewReader(body))
	recorder := httptest.NewRecorder()
	NewPluginHandler(fixture.store).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "FRP_AUTH_REJECTED") {
		t.Fatalf("version mismatch response = %d %s", recorder.Code, recorder.Body.String())
	}
	if response := fixture.call(t, "Unknown", map[string]any{}); !response.Reject {
		t.Fatal("unsupported op was accepted")
	}
}

func TestPluginRejectsWrongFRPVersion(t *testing.T) {
	fixture := newPluginFixture(t)
	content := fixture.loginContent(fixture.metas)
	content["version"] = "0.70.0"
	if response := fixture.call(t, "Login", content); !response.Reject || !strings.Contains(response.RejectReason, "unsupported FRP core version") {
		t.Fatalf("response = %+v", response)
	}
}
