//go:build windows && frp_audit_regression

package frp

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// These probes reproduce F-01/F-02/F-03 from
// docs/CURRENT-CODE-VERIFICATION-2026-10-21.md. They are opt-in regression
// gates for R1 and must not be included in the default green baseline.

func TestAuditRegressionFRPSInsideMeshMustBeRejected(t *testing.T) {
	cfg := testConfig(t)
	cfg.Profile.Server.Host = "10.240.0.20"
	m := &Manager{meshCIDRs: []netip.Prefix{netip.MustParsePrefix("10.240.0.0/24")}}
	if err := m.validatePolicy(cfg); err == nil {
		t.Fatal("F-03: FRPS endpoint inside active Mesh CIDR passed the conflict policy")
	}
}

func TestAuditRegressionFailedStartMustNotLockIdentity(t *testing.T) {
	cfg := testConfig(t)
	cfg.Profile.Rules[0].Target = Target{Kind: "lan", Host: "10.240.0.20", Port: 7777}
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	saved, err := store.Save(cfg, "audit-token")
	if err != nil {
		t.Fatal(err)
	}
	m := &Manager{
		store: store, config: saved, hasConfig: true,
		meshCIDRs: []netip.Prefix{netip.MustParsePrefix("10.240.0.0/24")},
	}
	if err := m.Start(context.Background()); ErrorCode(err) != CodeRouteConflict {
		t.Fatalf("expected route rejection, got %v", err)
	}
	snapshot := m.Snapshot(context.Background())
	if !snapshot.Running && m.RequiresIdentityStop() {
		t.Fatalf("F-02: state=%s running=%v but identity changes remain blocked; GUI only offers Start when Running=false", snapshot.State, snapshot.Running)
	}
}

func TestAuditRegressionRollbackMustNotRepublishRemovedRule(t *testing.T) {
	frpsPath := filepath.Join("..", "..", ".tmp-runtime", "frps-v0.71.1.exe")
	frpcPath := filepath.Join("..", "..", "assets", "frp", "windows-amd64", "frpc.exe")
	if _, err := os.Stat(frpsPath); err != nil {
		t.Skipf("fixed FRPS binary unavailable: %v", err)
	}
	if _, err := os.Stat(frpcPath); err != nil {
		t.Skipf("bundled FRPC binary unavailable: %v", err)
	}

	work := t.TempDir()
	ca, cert, key := makeServerTLS(t, work)
	controlPort, remotePort := freePort(t), freePort(t)
	deniedPort := freePort(t)
	for deniedPort == remotePort {
		deniedPort = freePort(t)
	}
	configPath := filepath.Join(work, "frps.toml")
	config := fmt.Sprintf("bindAddr = \"127.0.0.1\"\nbindPort = %d\nproxyBindAddr = \"127.0.0.1\"\nauth.token = \"audit-token\"\ntransport.tls.force = true\ntransport.tls.certFile = %s\ntransport.tls.keyFile = %s\nallowPorts = [{ single = %d }]\n", controlPort, tomlQuote(cert), tomlQuote(key), remotePort)
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	process := exec.Command(frpsPath, "-c", configPath)
	process.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = process.Process.Kill()
		_ = process.Wait()
	}()
	waitPort(t, controlPort)

	store, err := NewStore(filepath.Join(work, "store"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := NewDefaultConfig()
	cfg.Profile.Server.Host = "127.0.0.1"
	cfg.Profile.Server.Port = controlPort
	cfg.Profile.Server.TLSServerName = "localhost"
	cfg.Profile.Server.TrustedCAPath = ca
	backend := startTCPEcho(t)
	cfg.Profile.Rules = []Rule{{
		ID: "withdraw-me", Name: "Old public service", Type: "tcp", Enabled: true,
		Target:   Target{Kind: "loopback", Host: "127.0.0.1", Port: backend},
		Exposure: Exposure{RemotePort: remotePort},
	}}
	cfg, err = store.Save(cfg, "audit-token")
	if err != nil {
		t.Fatal(err)
	}
	manager, err := NewManager(Options{Store: store, CorePath: frpcPath, DeviceID: "dev-audit"})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close(context.Background())
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	if err := manager.Start(ctx); err != nil {
		t.Fatal(err)
	}

	replacement := CloneConfig(cfg)
	replacement.Profile.Rules = []Rule{{
		ID: "new-service", Name: "Replacement service", Type: "tcp", Enabled: true,
		Target:   Target{Kind: "loopback", Host: "127.0.0.1", Port: backend},
		Exposure: Exposure{RemotePort: deniedPort},
	}}
	if _, err := manager.Apply(ctx, replacement, ""); err == nil {
		t.Fatal("expected new port registration failure")
	}
	connection, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", remotePort), time.Second)
	if err != nil {
		return
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(time.Second))
	if _, err = connection.Write([]byte("audit")); err != nil {
		return
	}
	response := make([]byte, 5)
	if _, err = io.ReadFull(connection, response); err == nil && string(response) == "audit" {
		t.Fatal("F-01: removed public service was reopened and still forwards after failed replacement")
	}
}
