//go:build windows

package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/private-radminlan/lanmesh/internal/clientapi"
	frpctl "github.com/private-radminlan/lanmesh/internal/frp"
	"github.com/private-radminlan/lanmesh/internal/frpauth"
)

func TestFRPLeaseProviderCanBeCreatedBeforeEnrollment(t *testing.T) {
	provider := newFRPLeaseProvider(clientapi.New("https://example.invalid", ""), "", "")
	if provider == nil {
		t.Fatal("provider was not created before enrollment")
	}
	provider.UpdateIdentity("net-after-enrollment", "dev-after-enrollment")
	provider.mu.Lock()
	networkID, deviceID := provider.networkID, provider.deviceID
	provider.mu.Unlock()
	if networkID != "net-after-enrollment" || deviceID != "dev-after-enrollment" {
		t.Fatalf("identity after enrollment = %q/%q", networkID, deviceID)
	}
}
func TestFRPLeaseProviderRenewsInPlace(t *testing.T) {
	creates, renews := 0, 0
	expiresAt := time.Now().Add(10 * time.Minute).UTC().Truncate(time.Second)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/frp/leases":
			creates++
			_ = json.NewEncoder(w).Encode(frpauth.LeaseResponse{
				LeaseID: "lease-1", Credential: "capability-1", ExpiresAt: expiresAt,
				Rules: []frpauth.Rule{{ID: "rule-1", ProxyName: "tlan_rule", Type: "tcp", RemotePort: 30001, BindPort: 8080}},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/frp/leases/lease-1/renew":
			renews++
			_ = json.NewEncoder(w).Encode(frpauth.LeaseResponse{
				LeaseID: "lease-1", ExpiresAt: expiresAt.Add(10 * time.Minute),
				Rules: []frpauth.Rule{{ID: "rule-1", ProxyName: "tlan_rule", Type: "tcp", RemotePort: 30001, BindPort: 8080}},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	provider := newFRPLeaseProvider(clientapi.New(server.URL, "member_test"), "net-1", "dev-1")
	lease, err := provider.Acquire(context.Background(), frpctl.LeaseRequest{
		ServerID: "frps-managed-1",
		Rules:    []frpctl.LeaseRule{{ID: "rule-1", ProxyName: "tlan_rule", Type: "tcp", RemotePort: 30001, BindPort: 8080}},
	})
	if err != nil {
		t.Fatal(err)
	}
	renewed, err := provider.Renew(context.Background(), lease.ID)
	if err != nil {
		t.Fatal(err)
	}
	if creates != 1 || renews != 1 {
		t.Fatalf("create calls = %d, renew calls = %d", creates, renews)
	}
	if renewed.ID != lease.ID || renewed.Credential != lease.Credential {
		t.Fatalf("renewed lease = %+v", renewed)
	}
	if !renewed.ExpiresAt.Equal(expiresAt.Add(10 * time.Minute)) {
		t.Fatalf("renewed expiry = %s", renewed.ExpiresAt)
	}
}

func TestFRPLeaseProviderMarksGoneAsTerminal(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/frp/leases":
			_ = json.NewEncoder(w).Encode(frpauth.LeaseResponse{
				LeaseID: "lease-gone", Credential: "capability-gone", ExpiresAt: time.Now().Add(time.Minute),
			})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/frp/leases/lease-gone/renew":
			w.WriteHeader(http.StatusGone)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "lease revoked"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	provider := newFRPLeaseProvider(clientapi.New(server.URL, "member_test"), "net-1", "dev-1")
	lease, err := provider.Acquire(context.Background(), frpctl.LeaseRequest{ServerID: "frps-managed-1"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = provider.Renew(context.Background(), lease.ID)
	if !errors.Is(err, frpctl.ErrLeaseTerminal) {
		t.Fatalf("renew error = %v", err)
	}
}
func TestFRPLeaseProviderVerifiesManagedPluginObservation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/frp/leases":
			_ = json.NewEncoder(w).Encode(frpauth.LeaseResponse{
				LeaseID: "lease-observed", Credential: "capability", ExpiresAt: time.Now().Add(time.Minute),
				Rules: []frpauth.Rule{{ID: "rule-1", ProxyName: "tlan_rule", Type: "tcp", RemotePort: 30001, BindPort: 8080}},
			})
		case "/api/v1/frp/leases/lease-observed/status":
			_ = json.NewEncoder(w).Encode(frpauth.LeaseStatus{
				LeaseID: "lease-observed", ExpiresAt: time.Now().Add(time.Minute), LoginSeen: true, ProxySeen: true,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	provider := newFRPLeaseProvider(clientapi.New(server.URL, "member_test"), "net-1", "dev-1")
	lease, err := provider.Acquire(context.Background(), frpctl.LeaseRequest{
		ServerID: "frps-managed-1",
		Rules:    []frpctl.LeaseRule{{ID: "rule-1", ProxyName: "tlan_rule", Type: "tcp", RemotePort: 30001, BindPort: 8080}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := provider.VerifyActive(context.Background(), lease.ID, true); err != nil {
		t.Fatal(err)
	}
}

func TestFRPLeaseProviderPreservesAdvancedGrantFields(t *testing.T) {
	httpHash := frpauth.HashSecret("http-password")
	xtcpHash := frpauth.HashSecret("xtcp-secret")
	var received frpauth.Rule
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/frp/leases" {
			http.NotFound(w, r)
			return
		}
		var request struct {
			Rules []frpauth.Rule `json:"rules"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode lease request: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if len(request.Rules) != 1 {
			t.Errorf("lease rules = %+v", request.Rules)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		received = request.Rules[0]
		_ = json.NewEncoder(w).Encode(frpauth.LeaseResponse{
			LeaseID: "lease-advanced", Credential: "capability-advanced", ExpiresAt: time.Now().Add(time.Minute),
			Rules: request.Rules,
		})
	}))
	defer server.Close()
	provider := newFRPLeaseProvider(clientapi.New(server.URL, "member_test"), "net-1", "dev-1")
	lease, err := provider.Acquire(context.Background(), frpctl.LeaseRequest{
		ServerID: "frps-managed-1",
		Rules: []frpctl.LeaseRule{{
			ID: "rule-http", ProxyName: "tlan_http", Type: "http", BindPort: 8080,
			SubDomain: "app", Locations: []string{"/api"}, HTTPUser: "alice",
			HTTPPasswordHash: httpHash, HostHeaderRewrite: "backend.example.com",
			Headers: map[string]string{"X-From": "tlan"}, ResponseHeaders: map[string]string{"X-Response": "tlan"},
			RouteByHTTPUser: "alice", Multiplexer: "httpconnect", SecretHash: xtcpHash,
			AllowUsers: []string{"peer"}, UseEncryption: true, UseCompression: true,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if received.HTTPPasswordHash != httpHash || received.SecretHash != xtcpHash || received.SubDomain != "app" ||
		received.Multiplexer != "httpconnect" || len(received.Locations) != 1 || received.Headers["X-From"] != "tlan" {
		t.Fatalf("received advanced rule = %+v", received)
	}
	if len(lease.Rules) != 1 || lease.Rules[0].HTTPPasswordHash != httpHash || lease.Rules[0].SecretHash != xtcpHash {
		t.Fatalf("returned advanced lease = %+v", lease)
	}
}

func TestFRPLeaseRuleRoundTripPreservesApprovedServiceID(t *testing.T) {
	input := frpctl.LeaseRule{
		ID: "rule-local", TargetServiceID: "svc-approved",
		AllowUsers: []string{"peer-a", "peer-b"},
	}
	authRule := authRuleFromLeaseRule(input)
	if authRule.TargetServiceID != "svc-approved" || len(authRule.AllowUsers) != 2 {
		t.Fatalf("auth rule = %+v", authRule)
	}
	back := leaseRuleFromAuthRule(authRule)
	if back.TargetServiceID != "svc-approved" || len(back.AllowUsers) != 2 {
		t.Fatalf("round-tripped lease rule = %+v", back)
	}
}
