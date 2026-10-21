//go:build windows

package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	frpctl "github.com/private-radminlan/lanmesh/internal/frp"
	"github.com/private-radminlan/lanmesh/internal/netpolicy"
)

func TestBuildFRPDiagnosticExportIncludesRequiredSectionsAndRedactsSecrets(t *testing.T) {
	now := time.Now().UTC()
	caPath := writeFRPDiagnosticTestCA(t, now.Add(-time.Hour), now.Add(365*24*time.Hour))
	cfg := frpctl.NewDefaultConfig()
	cfg.Profile.ID = "profile-diag"
	cfg.Profile.Name = "诊断测试穿透"
	cfg.Profile.Server = frpctl.Server{
		Kind: "managed", Host: "127.0.0.1", Port: 7000, Transport: "kcp",
		TLSServerName: "localhost", TrustedCAPath: caPath, CredentialRef: "default",
		ServerID: "frps-managed-1", PublicHTTPPort: 18080, PublicHTTPSPort: 18443,
	}
	cfg.Profile.Rules = []frpctl.Rule{{
		ID: "rule-diag", Name: "Mesh 回显", Type: "tcp", Enabled: true,
		Target: frpctl.Target{Kind: "mesh_peer", Host: "10.240.0.8", Port: 8080, NetworkID: "net-diag", DeviceID: "device-target", ServiceID: "service-target"},
	}}
	snapshot := frpctl.Snapshot{
		Configured: true, Running: true, DesiredRunning: true, Authenticated: true,
		State: "running", ProfileName: cfg.Profile.Name, ServerHost: cfg.Profile.Server.Host, ServerPort: cfg.Profile.Server.Port,
		Rules: []frpctl.RuleRuntimeStatus{{
			RuleID: "rule-diag", Name: "Mesh 回显", Type: "TCP", Enabled: true,
			State: "已注册", RemoteAddr: "frp.example.test:30001", Backend: "运行中",
			GatewayStats: "gen 7 · TCP 1/2 拒绝 0", ErrorDetail: "token=token-super-secret",
		}},
		Endpoints:   []frpctl.EndpointRecord{{Host: "127.0.0.1", Port: 49152, Protocol: frpctl.EndpointProtocolTCP, Kind: frpctl.EndpointKindTargetGateway, State: frpctl.EndpointStateRunning, Owner: frpctl.EndpointOwner{ProfileID: cfg.Profile.ID, InstanceScope: "scope-diag", InstanceGeneration: 7, RuleID: "rule-diag", Purpose: "TargetGateway listener"}}},
		Observation: netpolicy.ObservationStatus{Generation: 3, StableState: netpolicy.ObservationHealthy, CandidateState: netpolicy.ObservationHealthy, CandidateCount: 2, StaleDropped: 1},
		Gateways: []frpctl.GatewayRuntimeStatus{{
			RuleID: "rule-diag", Protocol: "tcp", Address: "127.0.0.1:49152", Path: "direct UDP", State: "运行中",
		}},
		Logs: []string{
			"login token=token-super-secret",
			"capability=capability-super-secret",
			"Authorization: Bearer bearer-super-secret",
			"member=member-token-super-secret",
			"private key=private-key-space-secret",
			"-----BEGIN PRIVATE KEY-----\nprivate-key-super-secret\n-----END PRIVATE KEY-----",
		},
	}
	provider := &frpLeaseProvider{
		leases: map[string]frpctl.Lease{
			"lease-1234567890": {
				ID: "lease-1234567890", Credential: "capability-super-secret", ExpiresAt: now.Add(time.Hour),
				Rules: []frpctl.LeaseRule{{ID: "rule-diag", ProxyName: "diag", Type: "tcp"}},
			},
		},
		requests: map[string]frpctl.LeaseRequest{
			"lease-1234567890": {NetworkID: "net-diag", DeviceID: "device-local", ServerID: "frps-managed-1", Rules: []frpctl.LeaseRule{{ID: "rule-diag"}}},
		},
	}
	report, checks := buildFRPDiagnosticExport(context.Background(), []frpDiagnosticSource{{
		ProfileID: cfg.Profile.ID, Config: cfg, Configured: true, Provider: provider, Snapshot: &snapshot,
	}}, []string{"member-token-super-secret"}, now)
	if len(report.Profiles) != 1 {
		t.Fatalf("profiles = %d, want 1", len(report.Profiles))
	}
	profile := report.Profiles[0]
	if len(profile.ManagedLeases) != 1 || len(profile.Routes) != 1 || len(profile.TargetGateways) != 1 {
		t.Fatalf("missing diagnostic sections: leases=%d routes=%d gateways=%d", len(profile.ManagedLeases), len(profile.Routes), len(profile.TargetGateways))
	}
	if len(profile.Egress) == 0 || len(profile.Logs) == 0 || !profile.TLS.CAValid || profile.TLS.Status != "pass" {
		t.Fatalf("missing egress/log/TLS diagnostics: %+v", profile)
	}
	if profile.TLS.SkippedReason == "" {
		t.Fatal("KCP TLS check should report skipped handshake reason")
	}
	if len(checks) < 5 {
		t.Fatalf("checks = %d, want profile/lease/route/gateway/tls", len(checks))
	}
	if got := profile.ManagedLeases[0].LeaseID; got == "lease-1234567890" || !strings.Contains(got, "…") {
		t.Fatalf("lease ID was not masked: %q", got)
	}
	export := diagnosticExport{
		SchemaVersion: diagnosticSchemaVersion, AppVersion: appVersion, GeneratedAt: now,
		Checks: checks, FRP: report,
	}
	dir := t.TempDir()
	jsonPath, textPath, err := writeDiagnosticExport(dir, export, []string{"member-token-super-secret"})
	if err != nil {
		t.Fatal(err)
	}
	if jsonPath != filepath.Join(dir, "diagnostics.json") || textPath != filepath.Join(dir, "diagnostics.txt") {
		t.Fatalf("unexpected paths: %s %s", jsonPath, textPath)
	}
	jsonData, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatal(err)
	}
	textData, err := os.ReadFile(textPath)
	if err != nil {
		t.Fatal(err)
	}
	var decoded diagnosticExport
	if err := json.Unmarshal(jsonData, &decoded); err != nil {
		t.Fatalf("diagnostics.json is invalid: %v", err)
	}
	for _, secret := range []string{"token-super-secret", "capability-super-secret", "bearer-super-secret", "member-token-super-secret", "private-key-super-secret", "private-key-space-secret", "lease-1234567890"} {
		if strings.Contains(string(jsonData), secret) || strings.Contains(string(textData), secret) {
			t.Fatalf("diagnostic export leaked %q", secret)
		}
	}
	for _, section := range []string{`"snapshot"`, `"managed_leases"`, `"egress"`, `"routes"`, `"target_gateways"`, `"logs"`, `"tls"`} {
		if !strings.Contains(string(jsonData), section) {
			t.Fatalf("diagnostics.json missing %s", section)
		}
	}
	if !strings.Contains(string(textData), "FRP 日志") || !strings.Contains(string(textData), "TargetGateway") || !strings.Contains(string(textData), "EndpointRegistry") || !strings.Contains(string(textData), "RouteObservation") {
		t.Fatal("text diagnostic is missing FRP sections")
	}
}

func TestBuildFRPEgressReportsLocalGuardAndControlRoute(t *testing.T) {
	cfg := frpctl.NewDefaultConfig()
	cfg.Profile.Server.Host = "frps.example.test"
	cfg.Profile.Server.Port = 7000
	cfg.Profile.Server.Transport = "tcp"
	egress := buildFRPEgress(cfg, []frpctl.TargetReservation{{
		Host: "127.0.0.1", Port: 41000, Purpose: "FRPC egress guard proxy listener",
	}})
	if len(egress) < 2 {
		t.Fatalf("egress entries = %d, want control and guard", len(egress))
	}
	foundGuard := false
	for _, item := range egress {
		if item.Kind == "control" && item.Mode != "local-policy-proxy" {
			t.Fatalf("control mode = %q, want local-policy-proxy", item.Mode)
		}
		if item.Kind == "local_egress_guard" {
			foundGuard = true
		}
	}
	if !foundGuard {
		t.Fatal("local egress guard was not reported")
	}
}

func TestInspectFRPTLSRejectsExpiredCA(t *testing.T) {
	now := time.Now().UTC()
	caPath := writeFRPDiagnosticTestCA(t, now.Add(-48*time.Hour), now.Add(-24*time.Hour))
	cfg := frpctl.NewDefaultConfig()
	cfg.Profile.Server.TrustedCAPath = caPath
	cfg.Profile.Server.TLSServerName = "localhost"
	cfg.Profile.Server.Transport = "kcp"
	check := inspectFRPTLS(context.Background(), cfg, now)
	if check.Status != "fail" || check.CAValid {
		t.Fatalf("expired CA check = %+v", check)
	}
	if !strings.Contains(check.Error, "过期") {
		t.Fatalf("expired CA error = %q", check.Error)
	}
}

func writeFRPDiagnosticTestCA(t *testing.T, notBefore, notAfter time.Time) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "TLAN Diagnostic Test CA"},
		NotBefore:    notBefore, NotAfter: notAfter,
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestInspectFRPTLSCompletesVerifiedLocalHandshake(t *testing.T) {
	now := time.Now().UTC()
	caPath, serverCert := writeFRPDiagnosticTLSServerFixture(t, now)
	listener, err := tls.Listen("tcp4", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{serverCert}, MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		if tlsConn, ok := conn.(*tls.Conn); ok {
			_ = tlsConn.Handshake()
		}
		_ = conn.Close()
	}()
	addr := listener.Addr().(*net.TCPAddr)
	cfg := frpctl.NewDefaultConfig()
	cfg.Profile.Server.Host = "127.0.0.1"
	cfg.Profile.Server.Port = addr.Port
	cfg.Profile.Server.Transport = "tcp"
	cfg.Profile.Server.TLSServerName = "localhost"
	cfg.Profile.Server.TrustedCAPath = caPath
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	check := inspectFRPTLS(ctx, cfg, now)
	<-serverDone
	if check.Status != "pass" || !check.CAValid || !check.HandshakeAttempted || !check.HandshakeOK || !check.Verified {
		t.Fatalf("TLS handshake diagnostic = %+v", check)
	}
	if check.TLSVersion == "" || len(check.ServerCertificates) == 0 {
		t.Fatalf("TLS handshake details missing: %+v", check)
	}
}

func writeFRPDiagnosticTLSServerFixture(t *testing.T, now time.Time) (string, tls.Certificate) {
	t.Helper()
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(10), Subject: pkix.Name{CommonName: "TLAN Diagnostic Test CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(11), Subject: pkix.Name{CommonName: "localhost"},
		DNSNames: []string{"localhost"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caTemplate, &serverKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return caPath, tls.Certificate{Certificate: [][]byte{serverDER}, PrivateKey: serverKey}
}
