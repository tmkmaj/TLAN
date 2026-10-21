//go:build frp_audit_regression

package frp

import (
	"encoding/base64"
	"testing"
)

// These probes reproduce F-04/F-05/F-06 from
// docs/CURRENT-CODE-VERIFICATION-2026-10-21.md. They remain behind an
// explicit build tag until the corresponding R1 fixes are merged so the
// default baseline stays green. The same file is portable and is expected to
// become part of the normal validation suite after those fixes.

func TestAuditRegressionMetadataTargetMustBeRejected(t *testing.T) {
	cfg := testConfig(t)
	cfg.Profile.Rules[0].Target = Target{Kind: "lan", Host: "169.254.169.254", Port: 80}
	if err := ValidateConfig(cfg); err == nil {
		t.Fatal("F-04: cloud metadata address passed backend validation")
	}
}

func TestAuditRegressionCGNATMeshTargetMustBeSupported(t *testing.T) {
	cfg := testConfig(t)
	cfg.Profile.Server.Kind = "managed"
	cfg.Profile.Server.ServerID = "frps-test"
	cfg.Profile.Rules[0].Target = Target{
		Kind: "mesh_peer", Host: "100.64.0.2", Port: 7777,
		NetworkID: "net-test", DeviceID: "dev-test",
		PublicKey: base64.StdEncoding.EncodeToString(make([]byte, 32)),
		ServiceID: "svc-test",
	}
	if err := ValidateConfig(cfg); err != nil {
		t.Fatalf("F-05: TLAN-supported 100.64.0.0/10 Mesh target was rejected: %v", err)
	}
}

func TestKnownLocalFRPSPublishLoopMustBeRejected(t *testing.T) {
	cfg := testConfig(t)
	cfg.Profile.Server.Host = "127.0.0.1"
	cfg.Profile.Rules[0].Type = "tcp"
	cfg.Profile.Rules[0].Target = Target{Kind: "loopback", Host: "127.0.0.1", Port: 18080}
	cfg.Profile.Rules[0].Exposure = Exposure{RemotePort: 18080}
	if err := ValidateConfig(cfg); !IsReservedTargetError(err) {
		t.Fatalf("self-referential FRPS entry error = %v", err)
	}
}

func TestAuditRegressionMeshProfileWithIndependentVisitorMustBeRejected(t *testing.T) {
	cfg := testConfig(t)
	cfg.Profile.Server.Kind = "managed"
	cfg.Profile.Server.ServerID = "frps-test"
	cfg.Profile.Rules[0].Target = Target{
		Kind: "mesh_peer", Host: "10.240.0.2", Port: 7777,
		NetworkID: "net-test", DeviceID: "dev-test",
		PublicKey: base64.StdEncoding.EncodeToString(make([]byte, 32)),
		ServiceID: "svc-test",
	}
	cfg.Profile.Visitors = []Visitor{{
		ID: "visitor-test", Name: "Independent visitor", Type: "stcp", Enabled: true,
		ServerName: "remote-independent", SecretRef: "test-secret",
		BindAddr: "127.0.0.1", BindPort: 19000,
	}}
	if err := ValidateConfig(cfg); err == nil {
		t.Fatal("F-06: independent visitor accepted in a Mesh-dependent process group")
	}
}
