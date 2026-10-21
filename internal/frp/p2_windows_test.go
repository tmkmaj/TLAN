//go:build windows

package frp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/private-radminlan/lanmesh/internal/frpauth"
)

func TestManagerRejectsLANTargetInsideMeshCIDR(t *testing.T) {
	cfg := testConfig(t)
	cfg.Profile.Rules[0].Target = Target{Kind: "lan", Host: "10.77.0.5", Port: 8080}
	prefix, err := netip.ParsePrefix("10.77.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	manager := &Manager{meshCIDRs: []netip.Prefix{prefix.Masked()}}
	if err = manager.validatePolicy(cfg); ErrorCode(err) != CodeRouteConflict {
		t.Fatalf("policy error = %v, code = %s", err, ErrorCode(err))
	}
}

type fakeLeaseProvider struct {
	request LeaseRequest
	lease   Lease
}

func (f *fakeLeaseProvider) Acquire(_ context.Context, request LeaseRequest) (Lease, error) {
	f.request = request
	return f.lease, nil
}
func (f *fakeLeaseProvider) Renew(_ context.Context, _ string) (Lease, error) { return f.lease, nil }
func (f *fakeLeaseProvider) Release(_ context.Context, _ string) error        { return nil }

func TestProxyRemoteAddressNormalization(t *testing.T) {
	server := Server{Host: "frp.example.test", PublicHTTPPort: 18080, PublicHTTPSPort: 18443}
	tcp := Rule{Type: "tcp", Exposure: Exposure{RemotePort: 30001}}
	if got := proxyRemoteAddress(tcp, ":30001", server); got != "frp.example.test:30001" {
		t.Fatalf("TCP address = %q", got)
	}
	httpRule := Rule{Type: "http", Exposure: Exposure{CustomDomains: []string{"app.example.test"}}}
	if got := proxyRemoteAddress(httpRule, "app.example.test:18080", server); got != "http://app.example.test:18080" {
		t.Fatalf("HTTP address = %q", got)
	}
	if got := proxyRemoteAddress(httpRule, "", server); got != "http://app.example.test:18080" {
		t.Fatalf("HTTP fallback address = %q", got)
	}
}
func TestProxyRemoteAddressUsesSubdomainHostAndTCPMuxPort(t *testing.T) {
	server := Server{
		Host: "frp.example.test", PublicHTTPPort: 18080, PublicHTTPSPort: 18443,
		PublicTCPMuxPort: 18081, SubdomainHost: "frp.example.test",
	}
	httpRule := Rule{Type: "http", Exposure: Exposure{Subdomain: "app"}}
	if got := ruleAccessAddress(httpRule, server); got != "http://app.frp.example.test:18080" {
		t.Fatalf("subdomain HTTP address = %q", got)
	}
	muxRule := Rule{Type: "tcpmux", Exposure: Exposure{Subdomain: "mux", Multiplexer: "httpconnect"}}
	if got := ruleAccessAddress(muxRule, server); got != "http://mux.frp.example.test:18081" {
		t.Fatalf("subdomain TCPMUX address = %q", got)
	}
}
func TestManagedVerifierIsRequired(t *testing.T) {
	cfg := testConfig(t)
	cfg.Profile.Server.Kind = "managed"
	cfg.Profile.Server.ServerID = "frps-managed-1"
	lease := &Lease{ID: "lease-verifier", Credential: "capability", ExpiresAt: time.Now().Add(time.Hour)}
	manager := &Manager{leaseProvider: &fakeLeaseProvider{}}
	if err := manager.verifyManagedLease(context.Background(), cfg, lease); ErrorCode(err) != CodeAuthRejected {
		t.Fatalf("missing verifier error = %v", err)
	}
}

func TestManagerManagedLeaseRequest(t *testing.T) {
	cfg := testConfig(t)
	cfg.Profile.Server.Kind = "managed"
	cfg.Profile.Server.ServerID = "frps-managed-1"
	cfg.Profile.ID = "profile-office"
	cfg.Profile.Rules[0].Type = "tcp"
	lease := Lease{ID: "lease-1", Credential: "capability-1", ExpiresAt: time.Now().Add(time.Hour)}
	if got := managedLeaseEnvironment(&lease)[managedCapabilityEnv]; got != lease.Credential {
		t.Fatalf("managed environment capability = %q", got)
	}
	provider := &fakeLeaseProvider{lease: lease}
	manager := &Manager{deviceID: "device-1", networkID: "network-1", leaseProvider: provider}
	got, err := manager.acquireLease(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.ID != lease.ID || provider.request.ServerID != cfg.Profile.Server.ServerID || provider.request.DeviceID != "device-1" || provider.request.NetworkID != "network-1" {
		t.Fatalf("lease request = %+v, lease = %+v", provider.request, got)
	}
	if len(provider.request.Rules) != 1 || provider.request.Rules[0].ProxyName != ProxyName("device-1", cfg.Profile.ID, cfg.Profile.Rules[0].ID) {
		t.Fatalf("lease rules = %+v", provider.request.Rules)
	}
}

type renewalLeaseProvider struct {
	mu    sync.Mutex
	calls int
}

func (p *renewalLeaseProvider) Acquire(context.Context, LeaseRequest) (Lease, error) {
	return Lease{}, nil
}

func (p *renewalLeaseProvider) Renew(_ context.Context, leaseID string) (Lease, error) {
	p.mu.Lock()
	p.calls++
	p.mu.Unlock()
	return Lease{ID: leaseID, ExpiresAt: time.Now().Add(3 * time.Second)}, nil
}

func (p *renewalLeaseProvider) Release(context.Context, string) error { return nil }

func (p *renewalLeaseProvider) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls
}

func TestManagedLeaseWatchdogRenewsSameLease(t *testing.T) {
	provider := &renewalLeaseProvider{}
	manager := &Manager{leaseProvider: provider}
	inst := &managedInstance{
		done:   make(chan struct{}),
		config: Config{Profile: Profile{Server: Server{Kind: "managed"}}},
		lease:  &Lease{ID: "lease-renew", Credential: "capability", ExpiresAt: time.Now().Add(3 * time.Second)},
	}
	manager.startLeaseWatch(inst)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && provider.count() == 0 {
		time.Sleep(25 * time.Millisecond)
	}
	if provider.count() == 0 {
		t.Fatal("lease watchdog did not renew")
	}
	inst.leaseMu.Lock()
	expiresAt := inst.lease.ExpiresAt
	inst.leaseMu.Unlock()
	if !expiresAt.After(time.Now().Add(2 * time.Second)) {
		t.Fatalf("renewed expiry was not applied: %s", expiresAt)
	}
	if lease := manager.takeInstanceLease(inst); lease == nil || lease.ID != "lease-renew" || lease.Credential != "capability" {
		t.Fatalf("lease was not preserved across renewal: %+v", lease)
	}
}

func TestUpdateMembershipStillBlocksManagedOrMeshDependentRuntime(t *testing.T) {
	managed := testConfig(t)
	managed.Profile.Server.Kind = "managed"
	for name, cfg := range map[string]Config{
		"managed": managed,
		"mesh": func() Config {
			mesh := testConfig(t)
			mesh.Profile.Server.Kind = "private_token"
			mesh.Profile.Rules[0].Target = Target{Kind: "mesh_peer", Host: "10.240.0.9", Port: 8080, NetworkID: "net", DeviceID: "dev"}
			return mesh
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			inst := &managedInstance{config: cfg}
			manager := &Manager{state: "running", config: cfg, hasConfig: true, instance: inst, instanceGeneration: inst.generation}
			manager.desiredRun.Store(true)
			if err := manager.UpdateMembership("net-new", "dev-new", "10.50.0.0/16"); ErrorCode(err) != CodeConfigurationInvalid {
				t.Fatalf("identity-dependent runtime was not blocked: %v", err)
			}
		})
	}
}

func TestRequiresIdentityStopTracksManagedRuntime(t *testing.T) {
	cfg := testConfig(t)
	cfg.Profile.Server.Kind = "managed"
	manager := &Manager{state: "stopped", config: cfg, hasConfig: true}
	if manager.RequiresIdentityStop() {
		t.Fatal("stopped manager requires identity stop")
	}
	manager.desiredRun.Store(true)
	if !manager.RequiresIdentityStop() {
		t.Fatal("desired managed runtime does not block identity change")
	}
	manager.desiredRun.Store(false)
	manager.state = "waiting_dependency"
	if !manager.RequiresIdentityStop() {
		t.Fatal("waiting managed dependency does not block identity change")
	}
}

func TestRequiresIdentityStopIgnoresIndependentPrivateTokenRuntime(t *testing.T) {
	for _, target := range []Target{
		{Kind: "loopback", Host: "127.0.0.1", Port: 8080},
		{Kind: "lan", Host: "192.168.1.20", Port: 8080},
	} {
		t.Run(target.Kind, func(t *testing.T) {
			cfg := testConfig(t)
			cfg.Profile.Server.Kind = "private_token"
			cfg.Profile.Rules[0].Target = target
			inst := &managedInstance{config: cfg}
			manager := &Manager{
				state: "running", config: cfg, hasConfig: true, instance: inst,
				instanceGeneration: inst.generation,
			}
			manager.desiredRun.Store(true)
			if manager.RequiresIdentityStop() {
				t.Fatal("independent private-token runtime must not block TLAN identity changes")
			}
			if err := manager.UpdateMembership("net-new", "dev-new", "10.50.0.0/16"); err != nil {
				t.Fatalf("independent runtime blocked membership update: %v", err)
			}
		})
	}
}
func TestLeaseRenewDelayBounds(t *testing.T) {
	now := time.Now()
	// Renewal is the revocation heartbeat, so every active lease must be
	// checked within the 10-second managed revocation SLA.
	if got := leaseRenewDelay(now, now.Add(90*time.Second)); got != 5*time.Second {
		t.Fatalf("short delay = %s", got)
	}
	if got := leaseRenewDelay(now, now.Add(24*time.Hour)); got != 5*time.Second {
		t.Fatalf("long delay = %s", got)
	}
	if got := leaseRenewDelay(now, now.Add(-time.Minute)); got != 250*time.Millisecond {
		t.Fatalf("expired delay = %s", got)
	}
}
func TestDependencyRetryHonorsStopRequest(t *testing.T) {
	manager := &Manager{}
	manager.desiredRun.Store(false)
	if err := manager.startForRetry(context.Background()); !errors.Is(err, errRunCancelled) {
		t.Fatalf("retry after Stop error = %v", err)
	}
}

func TestMeshTargetRequiresMatchingLeaseGrant(t *testing.T) {
	cfg := testConfig(t)
	cfg.Profile.Server.Kind = "managed"
	cfg.Profile.Server.ServerID = "frps-a"
	publicKey := base64.StdEncoding.EncodeToString(make([]byte, 32))
	cfg.Profile.Rules[0].Target = Target{
		Kind: "mesh_peer", Host: "10.240.0.5", Port: 22,
		NetworkID: "net-a", DeviceID: "dev-b", PublicKey: publicKey, ServiceID: "svc-mesh",
	}
	if err := ValidateConfig(cfg); err != nil {
		t.Fatalf("valid managed Mesh rule rejected: %v", err)
	}
	manager := &Manager{networkID: "net-a", deviceID: "dev-a"}
	lease := &Lease{Rules: []LeaseRule{{
		ID: "rule-game", TargetKind: "mesh_peer", TargetNetworkID: "net-a",
		TargetDeviceID: "dev-b", TargetPublicKey: publicKey, TargetHost: "10.240.0.5", TargetServiceID: "svc-mesh", GrantID: "grant-mesh", BindPort: 22,
	}}}
	if err := manager.validateLeaseGrant(cfg, lease); err != nil {
		t.Fatalf("matching grant rejected: %v", err)
	}
	lease.Rules[0].TargetDeviceID = "dev-forged"
	if err := manager.validateLeaseGrant(cfg, lease); ErrorCode(err) != CodeAuthRejected {
		t.Fatalf("forged target grant error = %v", err)
	}
	lease.Rules[0].TargetDeviceID = "dev-b"
	lease.Rules[0].TargetServiceID = "svc-forged"
	if err := manager.validateLeaseGrant(cfg, lease); ErrorCode(err) != CodeAuthRejected {
		t.Fatalf("forged service ID grant error = %v", err)
	}
	lease.Rules[0].TargetServiceID = ""
	if err := manager.validateLeaseGrant(cfg, lease); ErrorCode(err) != CodeAuthRejected {
		t.Fatalf("missing service ID grant error = %v", err)
	}
}

func TestMeshSelfValidationAndGrant(t *testing.T) {
	cfg := testConfig(t)
	cfg.Profile.Server.Kind = "managed"
	cfg.Profile.Server.ServerID = "frps-a"
	cfg.Profile.Rules[0].Target = Target{Kind: "mesh_self", Host: "10.240.0.2", Port: 8080, NetworkID: "net-a", DeviceID: "dev-a"}
	if err := ValidateConfig(cfg); err != nil {
		t.Fatalf("valid mesh_self rule rejected: %v", err)
	}
	manager := &Manager{networkID: "net-a", deviceID: "dev-a"}
	publicKey := base64.StdEncoding.EncodeToString(make([]byte, 32))
	lease := &Lease{Rules: []LeaseRule{{
		ID: "rule-game", TargetKind: "mesh_self", TargetNetworkID: "net-a",
		TargetDeviceID: "dev-a", TargetPublicKey: publicKey, TargetHost: "10.240.0.2", GrantID: "grant-self", BindPort: 8080,
	}}}
	if err := manager.validateLeaseGrant(cfg, lease); err != nil {
		t.Fatalf("matching mesh_self grant rejected: %v", err)
	}
}

func TestManagedLeaseRequestCarriesAdvancedFieldsAsHashes(t *testing.T) {
	cfg := testConfig(t)
	cfg = NormalizeConfig(cfg)
	cfg.Profile.Server.Kind = "managed"
	cfg.Profile.Server.ServerID = "frps-managed-1"
	cfg.Profile.Rules = []Rule{
		{
			ID: "rule-http", Name: "Advanced HTTP", Type: "http", Enabled: true,
			Target: Target{Kind: "loopback", Host: "127.0.0.1", Port: 8080},
			Exposure: Exposure{
				CustomDomains: []string{"app.example.com"}, Subdomain: "app", Locations: []string{"/", "/api"},
				HTTPUser: "alice", HTTPPasswordRef: "http-password", HostHeaderRewrite: "backend.example.com",
				RouteByHTTPUser: "alice", RequestHeaders: map[string]string{"X-From": "tlan"},
				ResponseHeaders: map[string]string{"X-Response": "tlan"},
			},
			Transport: RuleTransport{UseEncryption: true, UseCompression: true},
		},
		{
			ID: "rule-mux", Name: "Advanced TCPMUX", Type: "tcpmux", Enabled: true,
			Target: Target{Kind: "loopback", Host: "127.0.0.1", Port: 8081},
			Exposure: Exposure{CustomDomains: []string{"mux.example.com"}, Multiplexer: "httpconnect",
				HTTPUser: "bob", HTTPPasswordRef: "mux-password", RouteByHTTPUser: "bob"},
		},
		{
			ID: "rule-xtcp", Name: "Advanced XTCP", Type: "xtcp", Enabled: true, SecretRef: "xtcp-secret",
			Target: Target{Kind: "loopback", Host: "127.0.0.1", Port: 8082},
		},
	}
	secrets := map[string]string{"http-password": "http-plain", "mux-password": "mux-plain", "xtcp-secret": "xtcp-plain"}
	provider := &fakeLeaseProvider{lease: Lease{ID: "lease-advanced", Credential: "capability-advanced", ExpiresAt: time.Now().Add(time.Hour)}}
	manager := &Manager{deviceID: "device-1", networkID: "network-1", leaseProvider: provider}
	lease, err := manager.acquireLeaseWithSecrets(context.Background(), cfg, secrets)
	if err != nil {
		t.Fatal(err)
	}
	if lease == nil || len(provider.request.Rules) != 3 {
		t.Fatalf("advanced lease request = %+v, lease = %+v", provider.request, lease)
	}
	requestJSON, err := json.Marshal(provider.request)
	if err != nil {
		t.Fatal(err)
	}
	for _, plaintext := range []string{"http-plain", "mux-plain", "xtcp-plain"} {
		if strings.Contains(string(requestJSON), plaintext) {
			t.Fatalf("lease request leaked plaintext secret %q: %s", plaintext, requestJSON)
		}
	}
	if provider.request.Rules[0].HTTPPasswordHash != frpauth.HashSecret("http-plain") ||
		provider.request.Rules[1].HTTPPasswordHash != frpauth.HashSecret("mux-plain") ||
		provider.request.Rules[2].SecretHash != frpauth.HashSecret("xtcp-plain") {
		t.Fatalf("advanced secret hashes = %+v", provider.request.Rules)
	}
}

func TestManagedLeaseRequestUsesApprovedTargetServiceID(t *testing.T) {
	cfg := managedMeshTargetConfig(t, "10.240.0.5")
	cfg.Profile.Rules[0].Target.ServiceID = "svc-approved"
	manager := &Manager{networkID: "net-a", deviceID: "dev-a"}
	rules, err := manager.buildLeaseRules(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 {
		t.Fatalf("lease rules = %+v", rules)
	}
	if rules[0].ID != cfg.Profile.Rules[0].ID {
		t.Fatalf("lease rule ID = %q, want %q", rules[0].ID, cfg.Profile.Rules[0].ID)
	}
	if rules[0].TargetServiceID != "svc-approved" || rules[0].TargetServiceID == rules[0].ID {
		t.Fatalf("target service ID = %q, rule ID = %q", rules[0].TargetServiceID, rules[0].ID)
	}
}
