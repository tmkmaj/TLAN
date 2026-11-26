package frpauth

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func testStore(t *testing.T) (*Store, *time.Time) {
	t.Helper()
	clock := time.Now().UTC().Truncate(time.Second)
	store, err := NewStore(Options{
		StatePath:      filepath.Join(t.TempDir(), "frp-leases.json"),
		ServerID:       "frps-managed-1",
		CoreVersion:    "0.71.1",
		LeaseTTL:       10 * time.Minute,
		AllowedPorts:   []PortRange{{Start: 30000, End: 30099}},
		AllowedDomains: []string{"frp.example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	store.now = func() time.Time { return clock }
	return store, &clock
}

func testRules() []Rule {
	return []Rule{
		{ID: "rule-tcp", ProxyName: "tlan_tcp", Type: "tcp", RemotePort: 30001, BindPort: 8080},
		{ID: "rule-udp", ProxyName: "tlan_udp", Type: "udp", RemotePort: 30001, BindPort: 8081},
		{ID: "rule-http", ProxyName: "tlan_http", Type: "http", CustomDomains: []string{"APP.FRP.EXAMPLE.COM"}, BindPort: 8082},
	}
}

func TestIssuePersistsOnlyCapabilityHashAndSurvivesRestart(t *testing.T) {
	store, clock := testStore(t)
	lease, err := store.Issue("net-test", "dev-test", "frps-managed-1", testRules())
	if err != nil {
		t.Fatal(err)
	}
	if lease.LeaseID == "" || lease.Credential == "" || len(lease.Rules) != 3 {
		t.Fatalf("unexpected lease response: %+v", lease)
	}
	if lease.Rules[2].CustomDomains[0] != "app.frp.example.com" {
		t.Fatalf("domain was not normalized: %+v", lease.Rules[2])
	}
	state, err := os.ReadFile(store.path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(state), lease.Credential) {
		t.Fatal("state file contains the plaintext capability")
	}
	if !strings.Contains(string(state), capabilityHash(lease.Credential)) {
		t.Fatal("state file does not contain the capability hash")
	}
	if runtime.GOOS != "windows" {
		info, statErr := os.Stat(store.path)
		if statErr != nil {
			t.Fatal(statErr)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("state file mode = %o, want 600", info.Mode().Perm())
		}
	}

	reopened, err := NewStore(Options{
		StatePath:      store.path,
		ServerID:       "frps-managed-1",
		CoreVersion:    "0.71.1",
		LeaseTTL:       10 * time.Minute,
		AllowedPorts:   []PortRange{{Start: 30000, End: 30099}},
		AllowedDomains: []string{"frp.example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	reopened.now = func() time.Time { return clock.Add(time.Minute) }
	if err := reopened.AuthorizeLogin(LoginRequest{
		LeaseID: lease.LeaseID, Capability: lease.Credential, ServerID: "frps-managed-1", User: "device-user", RunID: "",
	}); err != nil {
		t.Fatalf("login after restart: %v", err)
	}
	if err := reopened.AuthorizeNewProxy(NewProxyRequest{
		LeaseID: lease.LeaseID, Capability: lease.Credential, ServerID: "frps-managed-1", User: "device-user", RunID: "run-1",
		ProxyName: "tlan_tcp", ProxyType: "tcp", RemotePort: 30001,
	}); err != nil {
		t.Fatalf("new proxy after restart: %v", err)
	}
}

func TestIssueAllowsTCPAndUDPToShareNumberButRejectsConflicts(t *testing.T) {
	store, _ := testStore(t)
	if _, err := store.Issue("net-a", "dev-a", "frps-managed-1", testRules()); err != nil {
		t.Fatal(err)
	}
	_, err := store.Issue("net-a", "dev-b", "frps-managed-1", []Rule{
		{ID: "rule-tcp-2", ProxyName: "tlan_tcp_2", Type: "tcp", RemotePort: 30001, BindPort: 9000},
	})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("same TCP port error = %v", err)
	}
	_, err = store.Issue("net-a", "dev-b", "frps-managed-1", []Rule{
		{ID: "rule-domain-2", ProxyName: "tlan_domain_2", Type: "http", CustomDomains: []string{"app.frp.example.com"}, BindPort: 9001},
	})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("same domain error = %v", err)
	}
	if _, err := store.Issue("net-a", "dev-b", "frps-managed-1", []Rule{
		{ID: "rule-tcp-3", ProxyName: "tlan_tcp_3", Type: "tcp", RemotePort: 30002, BindPort: 9002},
	}); err != nil {
		t.Fatalf("unrelated TCP port should be available: %v", err)
	}
}

func TestIssueQuotasAndValidation(t *testing.T) {
	store, _ := testStore(t)
	store.limits = Limits{MaxRulesPerLease: 2, MaxLeasesPerDevice: 1, MaxPortsPerDevice: 2, MaxDomainsPerDevice: 2, MaxDomainsPerRule: 2}
	if _, err := store.Issue("net-a", "dev-a", "frps-managed-1", []Rule{
		{ID: "rule-a", ProxyName: "tlan_a", Type: "tcp", RemotePort: 30001, BindPort: 1},
		{ID: "rule-b", ProxyName: "tlan_b", Type: "udp", RemotePort: 30001, BindPort: 2},
	}); err != nil {
		t.Fatal(err)
	}
	_, err := store.Issue("net-a", "dev-a", "frps-managed-1", []Rule{
		{ID: "rule-c", ProxyName: "tlan_c", Type: "tcp", RemotePort: 30002, BindPort: 3},
	})
	if !errors.Is(err, ErrQuota) {
		t.Fatalf("lease quota error = %v", err)
	}
	_, err = store.Issue("net-a", "dev-b", "frps-managed-1", []Rule{
		{ID: "rule-d", ProxyName: "tlan_d", Type: "http", CustomDomains: []string{"outside.example.com"}, BindPort: 4},
	})
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("domain policy error = %v", err)
	}
	_, err = store.Issue("net-a", "dev-b", "frps-managed-1", []Rule{
		{ID: "rule-e", ProxyName: "tlan_e", Type: "tcp", RemotePort: 40000, BindPort: 5},
	})
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("port policy error = %v", err)
	}
}

func TestExpiryAndRevocationFailClosed(t *testing.T) {
	store, clock := testStore(t)
	lease, err := store.Issue("net-a", "dev-a", "frps-managed-1", testRules())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.AuthorizeLogin(LoginRequest{LeaseID: lease.LeaseID, Capability: lease.Credential, ServerID: "frps-managed-1", User: "user-a", RunID: "run-a"}); err != nil {
		t.Fatal(err)
	}
	if err := store.AuthorizeNewProxy(NewProxyRequest{LeaseID: lease.LeaseID, Capability: lease.Credential, ServerID: "frps-managed-1", User: "user-a", RunID: "run-a", ProxyName: "tlan_tcp", ProxyType: "tcp", RemotePort: 30001}); err != nil {
		t.Fatal(err)
	}
	*clock = clock.Add(11 * time.Minute)
	if err := store.AuthorizeLogin(LoginRequest{LeaseID: lease.LeaseID, Capability: lease.Credential, ServerID: "frps-managed-1", User: "user-a", RunID: "run-a"}); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired login error = %v", err)
	}
	if err := store.AuthorizeNewProxy(NewProxyRequest{LeaseID: lease.LeaseID, Capability: lease.Credential, ServerID: "frps-managed-1", User: "user-a", RunID: "run-a", ProxyName: "tlan_tcp", ProxyType: "tcp", RemotePort: 30001}); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired proxy error = %v", err)
	}
	if err := store.Revoke(lease.LeaseID, "net-a", "dev-a"); err != nil {
		t.Fatal(err)
	}
	if err := store.AuthorizeLogin(LoginRequest{LeaseID: lease.LeaseID, Capability: lease.Credential, ServerID: "frps-managed-1", User: "user-a", RunID: "run-a"}); !errors.Is(err, ErrRevoked) {
		t.Fatalf("revoked login error = %v", err)
	}
	if err := store.AuthorizeNewProxy(NewProxyRequest{LeaseID: lease.LeaseID, Capability: lease.Credential, ServerID: "frps-managed-1", User: "user-a", RunID: "run-a", ProxyName: "tlan_tcp", ProxyType: "tcp", RemotePort: 30001}); !errors.Is(err, ErrRevoked) {
		t.Fatalf("revoked proxy error = %v", err)
	}
	if _, err := store.Issue("net-a", "dev-a", "frps-managed-1", []Rule{
		{ID: "rule-replacement", ProxyName: "tlan_tcp", Type: "tcp", RemotePort: 30001, BindPort: 8080},
	}); err != nil {
		t.Fatalf("revoked lease resources were not released: %v", err)
	}
}

func TestRenewExtendsLeaseAndPingRequiresBoundSession(t *testing.T) {
	store, clock := testStore(t)
	lease, err := store.Issue("net-a", "dev-a", "frps-managed-1", testRules())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.AuthorizeLogin(LoginRequest{LeaseID: lease.LeaseID, Capability: lease.Credential, ServerID: "frps-managed-1", User: "user-a", RunID: ""}); err != nil {
		t.Fatal(err)
	}
	if err := store.AuthorizeNewProxy(NewProxyRequest{LeaseID: lease.LeaseID, Capability: lease.Credential, ServerID: "frps-managed-1", User: "user-a", RunID: "run-a", ProxyName: "tlan_tcp", ProxyType: "tcp", RemotePort: 30001}); err != nil {
		t.Fatal(err)
	}
	if err := store.AuthorizePing(SessionRequest{LeaseID: lease.LeaseID, Capability: lease.Credential, ServerID: "frps-managed-1", User: "user-a", RunID: "run-a"}); err != nil {
		t.Fatal(err)
	}
	if err := store.AuthorizePing(SessionRequest{LeaseID: lease.LeaseID, Capability: lease.Credential, ServerID: "frps-managed-1", User: "user-a", RunID: "run-b"}); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("wrong heartbeat run id error = %v", err)
	}
	*clock = clock.Add(9 * time.Minute)
	renewed, err := store.Renew(lease.LeaseID, "net-a", "dev-a")
	if err != nil {
		t.Fatal(err)
	}
	if !renewed.ExpiresAt.Equal(clock.Add(10 * time.Minute)) {
		t.Fatalf("renewed expiry = %s", renewed.ExpiresAt)
	}
	*clock = clock.Add(2 * time.Minute)
	if err := store.AuthorizePing(SessionRequest{LeaseID: lease.LeaseID, Capability: lease.Credential, ServerID: "frps-managed-1", User: "user-a", RunID: "run-a"}); err != nil {
		t.Fatalf("ping after renewal: %v", err)
	}
	if err := store.Revoke(lease.LeaseID, "net-a", "dev-a"); err != nil {
		t.Fatal(err)
	}
	if err := store.AuthorizePing(SessionRequest{LeaseID: lease.LeaseID, Capability: lease.Credential, ServerID: "frps-managed-1", User: "user-a", RunID: "run-a"}); !errors.Is(err, ErrRevoked) {
		t.Fatalf("revoked heartbeat error = %v", err)
	}
}

func TestRenewNeverMovesExpiryBackward(t *testing.T) {
	store, _ := testStore(t)
	lease, err := store.Issue("net-a", "dev-a", "frps-managed-1", testRules())
	if err != nil {
		t.Fatal(err)
	}
	renewed, err := store.Renew(lease.LeaseID, "net-a", "dev-a")
	if err != nil {
		t.Fatal(err)
	}
	if !renewed.ExpiresAt.After(lease.ExpiresAt) {
		t.Fatalf("renewed expiry %s did not advance past %s", renewed.ExpiresAt, lease.ExpiresAt)
	}
}
func TestRevokeDeviceInvalidatesEveryOwnedLease(t *testing.T) {
	store, _ := testStore(t)
	first, err := store.Issue("net-a", "dev-a", "frps-managed-1", []Rule{
		{ID: "rule-a", ProxyName: "tlan_a", Type: "tcp", RemotePort: 30001, BindPort: 8080},
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.Issue("net-a", "dev-a", "frps-managed-1", []Rule{
		{ID: "rule-b", ProxyName: "tlan_b", Type: "tcp", RemotePort: 30002, BindPort: 8081},
	})
	if err != nil {
		t.Fatal(err)
	}
	other, err := store.Issue("net-a", "dev-b", "frps-managed-1", []Rule{
		{ID: "rule-c", ProxyName: "tlan_c", Type: "tcp", RemotePort: 30003, BindPort: 8082},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.RevokeDevice("net-a", "dev-a"); err != nil {
		t.Fatal(err)
	}
	for _, lease := range []LeaseResponse{first, second} {
		if err := store.AuthorizeLogin(LoginRequest{LeaseID: lease.LeaseID, Capability: lease.Credential, ServerID: "frps-managed-1", User: "user-a", RunID: "run-a"}); !errors.Is(err, ErrRevoked) {
			t.Fatalf("device lease %s error = %v", lease.LeaseID, err)
		}
	}
	if err := store.AuthorizeLogin(LoginRequest{LeaseID: other.LeaseID, Capability: other.Credential, ServerID: "frps-managed-1", User: "user-b", RunID: "run-b"}); err != nil {
		t.Fatalf("other device lease was revoked: %v", err)
	}
}

func TestServiceAuthorizationGatesMeshPeerLease(t *testing.T) {
	store, clock := testStore(t)
	publicKey := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	baseRule := Rule{
		ID: "rule-peer", ProxyName: "tlan_peer", Type: "tcp", RemotePort: 30001, BindPort: 8080,
		TargetKind: "mesh_peer", TargetNetworkID: "net-a", TargetDeviceID: "dev-b",
		TargetPublicKey: publicKey, TargetHost: "10.240.0.5",
	}
	if _, err := store.Issue("net-a", "dev-a", "frps-managed-1", []Rule{baseRule}); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("unregistered service error = %v", err)
	}
	service, err := store.IssueService("net-a", "dev-b", "svc-peer", "tcp", 8080, "peer service", 2*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	baseRule.TargetServiceID = service.ID
	lease, err := store.Issue("net-a", "dev-a", "frps-managed-1", []Rule{baseRule})
	if err != nil {
		t.Fatal(err)
	}
	if len(lease.Rules) != 1 || lease.Rules[0].GrantID == "" || lease.Rules[0].TargetServiceID != service.ID {
		t.Fatalf("service grant = %+v", lease.Rules)
	}
	*clock = clock.Add(3 * time.Minute)
	if _, err := store.Renew(lease.LeaseID, "net-a", "dev-a"); !errors.Is(err, ErrExpired) {
		t.Fatalf("renew after service expiry error = %v", err)
	}
	if err := store.RevokeService(service.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.AuthorizeLogin(LoginRequest{LeaseID: lease.LeaseID, Capability: lease.Credential, ServerID: "frps-managed-1", User: "user-a", RunID: "run-a"}); !errors.Is(err, ErrRevoked) {
		t.Fatalf("service revocation did not revoke lease: %v", err)
	}
}

func TestSTCPMeshServiceGrantUsesTCPBackend(t *testing.T) {
	store, _ := testStore(t)
	service, err := store.IssueService("net-a", "dev-b", "svc-stcp", "tcp", 22, "SSH", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := store.Issue("net-a", "dev-a", "frps-managed-1", []Rule{{
		ID: "rule-stcp", ProxyName: "tlan_stcp", Type: "stcp", BindPort: 22,
		TargetKind: "mesh_peer", TargetNetworkID: "net-a", TargetDeviceID: "dev-b",
		TargetPublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", TargetHost: "10.240.0.5", TargetServiceID: service.ID,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(lease.Rules) != 1 || lease.Rules[0].GrantID == "" {
		t.Fatalf("stcp grant = %+v", lease.Rules)
	}
}
func TestServiceGrantAndMeshLeasePersistAcrossRestart(t *testing.T) {
	store, _ := testStore(t)
	service, err := store.IssueService("net-a", "dev-b", "svc-persist", "tcp", 8080, "persist", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := store.Issue("net-a", "dev-a", "frps-managed-1", []Rule{{
		ID: "rule-peer", ProxyName: "tlan_peer", Type: "tcp", RemotePort: 30001, BindPort: 8080,
		TargetKind: "mesh_peer", TargetNetworkID: "net-a", TargetDeviceID: "dev-b",
		TargetPublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", TargetHost: "10.240.0.5", TargetServiceID: service.ID,
	}})
	if err != nil {
		t.Fatal(err)
	}
	reopened, err := NewStore(Options{
		StatePath: store.path, ServerID: "frps-managed-1", CoreVersion: "0.71.1", LeaseTTL: 10 * time.Minute,
		AllowedPorts: []PortRange{{Start: 30000, End: 30099}}, AllowedDomains: []string{"frp.example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if services, err := reopened.ListServices("net-a", "dev-b"); err != nil || len(services) != 1 || services[0].ID != service.ID {
		t.Fatalf("persisted services = %+v, err = %v", services, err)
	}
	status, err := reopened.Status(lease.LeaseID, "net-a", "dev-a")
	if err != nil || status.Revoked {
		t.Fatalf("persisted lease status = %+v, err = %v", status, err)
	}
}
func TestProxyIdentityAndDomainChecks(t *testing.T) {
	store, _ := testStore(t)
	lease, err := store.Issue("net-a", "dev-a", "frps-managed-1", testRules())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.AuthorizeLogin(LoginRequest{LeaseID: lease.LeaseID, Capability: lease.Credential, ServerID: "frps-managed-1", User: "user-a", RunID: "run-a"}); err != nil {
		t.Fatal(err)
	}
	if err := store.AuthorizeNewProxy(NewProxyRequest{LeaseID: lease.LeaseID, Capability: lease.Credential, ServerID: "frps-managed-1", User: "user-a", RunID: "run-a", ProxyName: "tlan_tcp", ProxyType: "tcp", RemotePort: 30002}); !errors.Is(err, ErrPortDenied) {
		t.Fatalf("wrong port error = %v", err)
	}
	if err := store.AuthorizeNewProxy(NewProxyRequest{LeaseID: lease.LeaseID, Capability: lease.Credential, ServerID: "frps-managed-1", User: "user-a", RunID: "run-a", ProxyName: "tlan_http", ProxyType: "http", CustomDomains: []string{"other.frp.example.com"}}); !errors.Is(err, ErrDomainDenied) {
		t.Fatalf("wrong domain error = %v", err)
	}
	if err := store.AuthorizeNewProxy(NewProxyRequest{LeaseID: lease.LeaseID, Capability: lease.Credential, ServerID: "frps-managed-1", User: "other", RunID: "run-a", ProxyName: "tlan_tcp", ProxyType: "tcp", RemotePort: 30001}); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("wrong user error = %v", err)
	}
	if err := store.AuthorizeNewProxy(NewProxyRequest{LeaseID: lease.LeaseID, Capability: lease.Credential, ServerID: "frps-managed-1", User: "user-a", RunID: "run-b", ProxyName: "tlan_tcp", ProxyType: "tcp", RemotePort: 30001}); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("wrong run id error = %v", err)
	}
}

func TestExternalSharedTokenModeDoesNotCreateManagedStore(t *testing.T) {
	// This test records the separation contract at the package boundary: the
	// managed store always requires a server id and state path.
	if _, err := NewStore(Options{ServerID: "", StatePath: filepath.Join(t.TempDir(), "state.json")}); err == nil {
		t.Fatal("managed store accepted an empty server id")
	}
}

func TestNewStoreRejectsMalformedOrUnknownState(t *testing.T) {
	for _, contents := range []string{`{"schema_version":1,"leases":[],"unknown":true}`, `{"schema_version":99,"leases":[]}`, `{}`} {
		path := filepath.Join(t.TempDir(), "state.json")
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := NewStore(Options{
			StatePath: path, ServerID: "frps-managed-1", CoreVersion: "0.71.1",
			AllowedPorts: []PortRange{{Start: 30000, End: 30099}},
		}); err == nil {
			t.Fatalf("malformed state was accepted: %s", contents)
		}
	}
}

func TestRevokeDeviceRevokesOnlyThatMembersLeases(t *testing.T) {
	store, _ := testStore(t)
	first, err := store.Issue("net-a", "dev-a", "frps-managed-1", []Rule{
		{ID: "rule-a", ProxyName: "tlan_a", Type: "tcp", RemotePort: 30001, BindPort: 8080},
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.Issue("net-b", "dev-b", "frps-managed-1", []Rule{
		{ID: "rule-b", ProxyName: "tlan_b", Type: "tcp", RemotePort: 30002, BindPort: 8081},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = store.RevokeDevice("net-a", "dev-a"); err != nil {
		t.Fatal(err)
	}
	if _, err = store.Renew(first.LeaseID, "net-a", "dev-a"); !errors.Is(err, ErrRevoked) {
		t.Fatalf("revoked device renewal error = %v", err)
	}
	if _, err = store.Renew(second.LeaseID, "net-b", "dev-b"); err != nil {
		t.Fatalf("unrelated device renewal failed: %v", err)
	}
}

func TestTargetMemberApprovalLifecycle(t *testing.T) {
	store, _ := testStore(t)
	service, err := store.RequestService("net-a", "dev-b", "dev-a", "svc-approval", "tcp", 8080, "approval flow", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if service.ApprovalStatus != ServiceApprovalPending || service.RequesterDeviceID != "dev-a" {
		t.Fatalf("pending service = %+v", service)
	}
	pending, err := store.ListPendingServices("net-a", "dev-b")
	if err != nil || len(pending) != 1 || pending[0].ID != service.ID {
		t.Fatalf("pending services = %+v, err = %v", pending, err)
	}
	rule := Rule{
		ID: "rule-approval", ProxyName: "tlan_approval", Type: "tcp", RemotePort: 30001, BindPort: 8080,
		TargetKind: "mesh_peer", TargetNetworkID: "net-a", TargetDeviceID: "dev-b",
		TargetPublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", TargetHost: "10.240.0.5", TargetServiceID: service.ID,
	}
	if _, err = store.Issue("net-a", "dev-a", "frps-managed-1", []Rule{rule}); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("pending service issued a lease: %v", err)
	}
	if _, err = store.ApproveService(service.ID, "net-a", "dev-c"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("wrong target approved service: %v", err)
	}
	approved, err := store.ApproveService(service.ID, "net-a", "dev-b")
	if err != nil {
		t.Fatal(err)
	}
	if approved.ApprovalStatus != ServiceApprovalApproved || approved.ApprovedAt == nil || approved.ApprovedBy != "dev-b" {
		t.Fatalf("approved service = %+v", approved)
	}
	if _, err = store.Issue("net-a", "dev-a", "frps-managed-1", []Rule{rule}); err != nil {
		t.Fatalf("approved service lease: %v", err)
	}
	otherRule := rule
	otherRule.ID = "rule-other"
	otherRule.ProxyName = "tlan_other"
	otherRule.RemotePort = 30002
	if _, err = store.Issue("net-a", "dev-c", "frps-managed-1", []Rule{otherRule}); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("unrequested publisher used approved service: %v", err)
	}
	if err = store.RevokeServiceByTarget(service.ID, "net-a", "dev-c"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("wrong target revoked service: %v", err)
	}
	if err = store.RevokeServiceByTarget(service.ID, "net-a", "dev-b"); err != nil {
		t.Fatalf("target revoke: %v", err)
	}
	if _, err = store.Issue("net-a", "dev-a", "frps-managed-1", []Rule{rule}); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("revoked service issued a lease: %v", err)
	}

	deniedService, err := store.RequestService("net-a", "dev-b", "dev-a", "svc-denied", "tcp", 8081, "deny flow", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	denied, err := store.DenyService(deniedService.ID, "net-a", "dev-b")
	if err != nil {
		t.Fatal(err)
	}
	if denied.ApprovalStatus != ServiceApprovalDenied || denied.DeniedAt == nil || denied.RevokedAt == nil {
		t.Fatalf("denied service = %+v", denied)
	}
	if pending, err = store.ListPendingServices("net-a", "dev-b"); err != nil || len(pending) != 0 {
		t.Fatalf("pending after deny = %+v, err = %v", pending, err)
	}
}

func TestAdvancedManagedLeaseAuthorizationAndSecretHashing(t *testing.T) {
	store, _ := testStore(t)
	httpPassword := "http-password-advanced"
	xtcpSecret := "xtcp-secret-advanced"
	rules := []Rule{
		{
			ID: "rule-http-advanced", ProxyName: "tlan_http_advanced", Type: "http", BindPort: 8081,
			CustomDomains: []string{"app.frp.example.com"}, SubDomain: "app",
			Locations: []string{"/", "/api"}, HTTPUser: "alice", HTTPPasswordHash: HashSecret(httpPassword),
			HostHeaderRewrite: "backend.example.com", Headers: map[string]string{"X-From": "tlan"},
			ResponseHeaders: map[string]string{"X-Response": "tlan"}, RouteByHTTPUser: "alice",
			UseEncryption: true, UseCompression: true,
		},
		{
			ID: "rule-tcpmux", ProxyName: "tlan_tcpmux", Type: "tcpmux", BindPort: 8082,
			CustomDomains: []string{"mux.frp.example.com"}, Multiplexer: "httpconnect",
			HTTPUser: "bob", HTTPPasswordHash: HashSecret("mux-password"), RouteByHTTPUser: "bob",
		},
		{
			ID: "rule-xtcp", ProxyName: "tlan_xtcp", Type: "xtcp", BindPort: 8083,
			SecretHash: HashSecret(xtcpSecret), AllowUsers: []string{"peer-a", "peer-b"},
		},
	}
	lease, err := store.Issue("net-a", "dev-a", "frps-managed-1", rules)
	if err != nil {
		t.Fatal(err)
	}
	state, err := os.ReadFile(store.path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(state), httpPassword) || strings.Contains(string(state), xtcpSecret) {
		t.Fatal("plaintext advanced secret was persisted in lease state")
	}
	if !strings.Contains(string(state), HashSecret(httpPassword)) || !strings.Contains(string(state), HashSecret(xtcpSecret)) {
		t.Fatal("advanced secret hashes were not persisted")
	}
	if err := store.AuthorizeLogin(LoginRequest{LeaseID: lease.LeaseID, Capability: lease.Credential, ServerID: "frps-managed-1", User: "user-a", RunID: "run-a"}); err != nil {
		t.Fatal(err)
	}
	httpRequest := NewProxyRequest{
		LeaseID: lease.LeaseID, Capability: lease.Credential, ServerID: "frps-managed-1",
		User: "user-a", RunID: "run-a", ProxyName: "tlan_http_advanced", ProxyType: "http",
		CustomDomains: []string{"app.frp.example.com"}, SubDomain: "app", Locations: []string{"/api", "/"},
		HTTPUser: "alice", HTTPPwd: httpPassword, HostHeaderRewrite: "backend.example.com",
		Headers: map[string]string{"X-From": "tlan"}, ResponseHeaders: map[string]string{"X-Response": "tlan"},
		RouteByHTTPUser: "alice", UseEncryption: true, UseCompression: true,
	}
	if err := store.AuthorizeNewProxy(httpRequest); err != nil {
		t.Fatalf("advanced HTTP authorization: %v", err)
	}
	if err := store.AuthorizeNewProxy(NewProxyRequest{
		LeaseID: lease.LeaseID, Capability: lease.Credential, ServerID: "frps-managed-1",
		User: "user-a", RunID: "run-a", ProxyName: "tlan_tcpmux", ProxyType: "tcpmux",
		CustomDomains: []string{"mux.frp.example.com"}, Multiplexer: "httpconnect",
		HTTPUser: "bob", HTTPPwd: "mux-password", RouteByHTTPUser: "bob",
	}); err != nil {
		t.Fatalf("TCPMUX authorization: %v", err)
	}
	if err := store.AuthorizeNewProxy(NewProxyRequest{
		LeaseID: lease.LeaseID, Capability: lease.Credential, ServerID: "frps-managed-1",
		User: "user-a", RunID: "run-a", ProxyName: "tlan_xtcp", ProxyType: "xtcp",
		Sk: xtcpSecret, AllowUsers: []string{"peer-b", "peer-a"},
	}); err != nil {
		t.Fatalf("XTCP authorization: %v", err)
	}
	if err := store.AuthorizeNewProxy(NewProxyRequest{
		LeaseID: lease.LeaseID, Capability: lease.Credential, ServerID: "frps-managed-1",
		User: "user-a", RunID: "run-a", ProxyName: "tlan_http_advanced", ProxyType: "http",
		CustomDomains: []string{"app.frp.example.com"}, SubDomain: "app", Locations: []string{"/", "/api"},
		HTTPUser: "alice", HTTPPwd: "wrong-password", HostHeaderRewrite: "backend.example.com",
		Headers: map[string]string{"X-From": "tlan"}, ResponseHeaders: map[string]string{"X-Response": "tlan"},
		RouteByHTTPUser: "alice", UseEncryption: true, UseCompression: true,
	}); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("wrong HTTP password error = %v", err)
	}
	if err := store.AuthorizeNewProxy(NewProxyRequest{
		LeaseID: lease.LeaseID, Capability: lease.Credential, ServerID: "frps-managed-1",
		User: "user-a", RunID: "run-a", ProxyName: "tlan_xtcp", ProxyType: "xtcp",
		Sk: "wrong-xtcp-secret",
	}); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("wrong XTCP secret error = %v", err)
	}
}

func TestAdvancedServiceProtocolsAndTCPBackendMapping(t *testing.T) {
	for _, proxyType := range []string{"tcpmux", "xtcp"} {
		if !serviceProtocolMatches("tcp", proxyType) {
			t.Fatalf("%s did not map to a TCP target backend", proxyType)
		}
		if !serviceProtocolMatches(proxyType, proxyType) {
			t.Fatalf("%s service protocol did not match its proxy type", proxyType)
		}
	}
	if serviceProtocolMatches("udp", "tcpmux") || serviceProtocolMatches("udp", "xtcp") {
		t.Fatal("TCP-only advanced proxy type accepted a UDP target service")
	}
	store, _ := testStore(t)
	service, err := store.IssueService("net-a", "dev-b", "svc-tcpmux", "tcpmux", 8080, "TCPMUX target", time.Hour)
	if err != nil {
		t.Fatalf("issue tcpmux service: %v", err)
	}
	if service.Protocol != "tcpmux" {
		t.Fatalf("tcpmux service protocol = %q", service.Protocol)
	}
	service, err = store.IssueService("net-a", "dev-b", "svc-xtcp", "xtcp", 22, "XTCP target", time.Hour)
	if err != nil {
		t.Fatalf("issue xtcp service: %v", err)
	}
	if service.Protocol != "xtcp" {
		t.Fatalf("xtcp service protocol = %q", service.Protocol)
	}
}

func TestReopenAllowsRevokedLeaseOutsideCurrentPolicy(t *testing.T) {
	store, clock := testStore(t)
	*clock = time.Now().UTC()
	lease, err := store.Issue("net-a", "dev-a", "frps-managed-1", testRules())
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Revoke(lease.LeaseID, "net-a", "dev-a"); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewStore(Options{
		StatePath:    store.path,
		ServerID:     "frps-managed-1",
		CoreVersion:  "0.71.1",
		AllowedPorts: []PortRange{{Start: 30000, End: 30099}},
	})
	if err != nil {
		t.Fatalf("reopen after domain allowlist shrink: %v", err)
	}
	status, err := reopened.Status(lease.LeaseID, "net-a", "dev-a")
	if err != nil {
		t.Fatal(err)
	}
	if !status.Revoked {
		t.Fatalf("revoked lease status = %+v", status)
	}
}

func TestReopenRevokesActiveLeaseOutsideCurrentPolicy(t *testing.T) {
	store, clock := testStore(t)
	*clock = time.Now().UTC()
	lease, err := store.Issue("net-a", "dev-a", "frps-managed-1", testRules())
	if err != nil {
		t.Fatal(err)
	}
	reopened, err := NewStore(Options{
		StatePath:    store.path,
		ServerID:     "frps-managed-1",
		CoreVersion:  "0.71.1",
		AllowedPorts: []PortRange{{Start: 30000, End: 30099}},
	})
	if err != nil {
		t.Fatalf("reopen active lease after domain allowlist shrink: %v", err)
	}
	status, err := reopened.Status(lease.LeaseID, "net-a", "dev-a")
	if err != nil {
		t.Fatal(err)
	}
	if !status.Revoked {
		t.Fatalf("out-of-policy lease was not revoked: %+v", status)
	}
	if err = reopened.AuthorizeLogin(LoginRequest{
		LeaseID: lease.LeaseID, Capability: lease.Credential, ServerID: "frps-managed-1", User: "user-a",
	}); !errors.Is(err, ErrRevoked) {
		t.Fatalf("out-of-policy login error = %v", err)
	}
	state, err := os.ReadFile(store.path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(state), lease.Credential) {
		t.Fatal("reconciled state contains a plaintext capability")
	}
	reopenedAgain, err := NewStore(Options{
		StatePath:    store.path,
		ServerID:     "frps-managed-1",
		CoreVersion:  "0.71.1",
		AllowedPorts: []PortRange{{Start: 30000, End: 30099}},
	})
	if err != nil {
		t.Fatalf("second reopen after policy reconciliation: %v", err)
	}
	status, err = reopenedAgain.Status(lease.LeaseID, "net-a", "dev-a")
	if err != nil || !status.Revoked {
		t.Fatalf("persisted reconciliation status = %+v, %v", status, err)
	}
}

func TestPolicyReconciliationPreservesServiceAuthorizations(t *testing.T) {
	store, clock := testStore(t)
	*clock = time.Now().UTC()
	if _, err := store.Issue("net-a", "dev-a", "frps-managed-1", testRules()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.IssueService("net-a", "dev-b", "svc-persist", "tcp", 8080, "persist across reconciliation", time.Hour); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewStore(Options{
		StatePath:    store.path,
		ServerID:     "frps-managed-1",
		CoreVersion:  "0.71.1",
		AllowedPorts: []PortRange{{Start: 30000, End: 30099}},
	})
	if err != nil {
		t.Fatalf("reopen with out-of-policy lease: %v", err)
	}
	services, err := reopened.ListServices("net-a", "dev-b")
	if err != nil {
		t.Fatal(err)
	}
	if len(services) != 1 || services[0].ID != "svc-persist" {
		t.Fatalf("service authorizations after reconciliation = %+v", services)
	}
}
func TestActiveLeaseCountFiltersNetworkAndDevice(t *testing.T) {
	store, _ := testStore(t)
	lease, err := store.Issue("net-a", "dev-a", "frps-managed-1", testRules())
	if err != nil {
		t.Fatal(err)
	}
	if got := store.ActiveLeaseCount("net-a", "dev-a"); got != 1 {
		t.Fatalf("device lease count = %d, want 1", got)
	}
	if got := store.ActiveLeaseCount("net-a", ""); got != 1 {
		t.Fatalf("network lease count = %d, want 1", got)
	}
	if got := store.ActiveLeaseCount("net-b", ""); got != 0 {
		t.Fatalf("other network lease count = %d, want 0", got)
	}
	if err := store.Revoke(lease.LeaseID, "net-a", "dev-a"); err != nil {
		t.Fatal(err)
	}
	if got := store.ActiveLeaseCount("net-a", "dev-a"); got != 0 {
		t.Fatalf("revoked lease count = %d, want 0", got)
	}
}

func TestSetAllowedPortsUpdatesAndRevokesOutOfPolicyLeases(t *testing.T) {
	store, _ := testStore(t)
	lease, err := store.Issue("net-a", "dev-a", "frps-managed-1", []Rule{
		{ID: "rule-a", ProxyName: "tlan_a", Type: "tcp", RemotePort: 30001, BindPort: 8080},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetAllowedPorts([]PortRange{{Start: 60000, End: 61000}}); err != nil {
		t.Fatal(err)
	}
	if err := store.AuthorizeLogin(LoginRequest{LeaseID: lease.LeaseID, Capability: lease.Credential, ServerID: "frps-managed-1", User: "user-a", RunID: "run-a"}); !errors.Is(err, ErrRevoked) {
		t.Fatalf("out-of-policy lease after SetAllowedPorts = %v, want ErrRevoked", err)
	}
	if _, err := store.Issue("net-a", "dev-a", "frps-managed-1", []Rule{
		{ID: "rule-b", ProxyName: "tlan_b", Type: "tcp", RemotePort: 60005, BindPort: 8080},
	}); err != nil {
		t.Fatalf("new range lease error = %v", err)
	}
	caps := store.Capabilities()
	if len(caps.AllowedPorts) != 1 || caps.AllowedPorts[0] != (PortRange{Start: 60000, End: 61000}) {
		t.Fatalf("Capabilities().AllowedPorts = %+v", caps.AllowedPorts)
	}
}
