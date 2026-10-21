//go:build windows

package frp

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/private-radminlan/lanmesh/internal/targetgateway"
)

func r1FRPBinaries(t *testing.T) (string, string) {
	t.Helper()
	frpcPath := filepath.Join("..", "..", "assets", "frp", "windows-amd64", "frpc.exe")
	frpsPath := os.Getenv("TLAN_FRPS_BINARY")
	if frpsPath == "" {
		frpsPath = filepath.Join("..", "..", ".tmp-runtime", "frps-v0.71.1.exe")
	}
	if _, err := os.Stat(frpcPath); err != nil {
		t.Skipf("frpc not available: %v", err)
	}
	if _, err := os.Stat(frpsPath); err != nil {
		t.Skipf("frps not available: %v", err)
	}
	return frpcPath, frpsPath
}

func startR1FRPS(t *testing.T, work, token, certPath, keyPath string, ports ...int) int {
	t.Helper()
	frpsPath := os.Getenv("TLAN_FRPS_BINARY")
	if frpsPath == "" {
		frpsPath = filepath.Join("..", "..", ".tmp-runtime", "frps-v0.71.1.exe")
	}
	controlPort := freePort(t)
	tokenPath := filepath.Join(work, "r1-token")
	if err := os.WriteFile(tokenPath, []byte(token), 0o600); err != nil {
		t.Fatal(err)
	}
	allowed := make([]string, 0, len(ports))
	for _, port := range ports {
		allowed = append(allowed, fmt.Sprintf("{ single = %d }", port))
	}
	toml := fmt.Sprintf(`bindAddr = "127.0.0.1"
bindPort = %d
proxyBindAddr = "127.0.0.1"
auth.method = "token"
auth.tokenSource.type = "file"
auth.tokenSource.file.path = %s
transport.tls.force = true
transport.tls.certFile = %s
transport.tls.keyFile = %s
allowPorts = [%s]
log.to = "console"
log.level = "info"
`, controlPort, tomlQuote(tokenPath), tomlQuote(certPath), tomlQuote(keyPath), strings.Join(allowed, ", "))
	configPath := filepath.Join(work, "r1-frps.toml")
	if err := os.WriteFile(configPath, []byte(toml), 0o600); err != nil {
		t.Fatal(err)
	}
	process := exec.Command(frpsPath, "-c", configPath)
	process.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := os.OpenFile(filepath.Join(work, "r1-frps.out"), os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	errOut, err := os.OpenFile(filepath.Join(work, "r1-frps.err"), os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		_ = out.Close()
		t.Fatal(err)
	}
	process.Stdout, process.Stderr = out, errOut
	if err = process.Start(); err != nil {
		_ = out.Close()
		_ = errOut.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if process.Process != nil {
			_ = process.Process.Kill()
			_ = process.Wait()
		}
		_ = out.Close()
		_ = errOut.Close()
	})
	waitPort(t, controlPort)
	return controlPort
}

func waitR1TCP(t *testing.T, port int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 150*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("TCP port %d did not open", port)
}

func waitR1TCPClosed(t *testing.T, port int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 150*time.Millisecond)
		if err != nil {
			return
		}
		_ = conn.Close()
		time.Sleep(75 * time.Millisecond)
	}
	t.Fatalf("TCP port %d remained reachable", port)
}

func r1Echo(t *testing.T, port int, payload string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 3*time.Second)
	if err != nil {
		t.Fatalf("dial %d: %v", port, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err = conn.Write([]byte(payload)); err != nil {
		t.Fatalf("write %d: %v", port, err)
	}
	got := make([]byte, len(payload))
	if _, err = io.ReadFull(conn, got); err != nil {
		t.Fatalf("read %d: %v", port, err)
	}
	if string(got) != payload {
		t.Fatalf("echo %d = %q, want %q", port, got, payload)
	}
}

func TestLiveApplyRestrictionRestoresOnlyAllowedRules(t *testing.T) {
	if os.Getenv("TLAN_FRP_INTEGRATION") != "1" {
		t.Skip("set TLAN_FRP_INTEGRATION=1 to run real FRP integration")
	}
	frpcPath, _ := r1FRPBinaries(t)
	work := t.TempDir()
	caPath, certPath, keyPath := makeServerTLS(t, work)
	keptPort := freePort(t)
	removedPort := freePort(t)
	deniedPort := freePort(t)
	for removedPort == keptPort {
		removedPort = freePort(t)
	}
	for deniedPort == keptPort || deniedPort == removedPort {
		deniedPort = freePort(t)
	}
	controlPort := startR1FRPS(t, work, "r1-token", certPath, keyPath, keptPort, removedPort)
	backendPort := startTCPEcho(t)
	cfg := NewDefaultConfig()
	cfg.Profile.Server.Host = "127.0.0.1"
	cfg.Profile.Server.Port = controlPort
	cfg.Profile.Server.TLSServerName = "localhost"
	cfg.Profile.Server.TrustedCAPath = caPath
	cfg.Profile.Rules = []Rule{
		{ID: "rule-kept", Name: "Kept service", Type: "tcp", Enabled: true, Target: Target{Kind: "loopback", Host: "127.0.0.1", Port: backendPort}, Exposure: Exposure{RemotePort: keptPort}},
		{ID: "rule-removed", Name: "Removed service", Type: "tcp", Enabled: true, Target: Target{Kind: "loopback", Host: "127.0.0.1", Port: backendPort}, Exposure: Exposure{RemotePort: removedPort}},
	}
	store, err := NewStore(filepath.Join(work, "store"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg, err = store.Save(cfg, "r1-token"); err != nil {
		t.Fatal(err)
	}
	manager, err := NewManager(Options{Store: store, CorePath: frpcPath, DeviceID: "r1-device"})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close(context.Background())
	startCtx, startCancel := context.WithTimeout(context.Background(), 45*time.Second)
	if err = manager.Start(startCtx); err != nil {
		startCancel()
		t.Fatalf("start: %v\nlogs:\n%s", err, manager.logs.text())
	}
	startCancel()
	r1Echo(t, keptPort, "kept-before")
	r1Echo(t, removedPort, "removed-before")

	replacement := CloneConfig(cfg)
	replacement.Profile.Rules = []Rule{
		cfg.Profile.Rules[0],
		{ID: "rule-denied", Name: "Denied service", Type: "tcp", Enabled: true, Target: Target{Kind: "loopback", Host: "127.0.0.1", Port: backendPort}, Exposure: Exposure{RemotePort: deniedPort}},
	}
	applyCtx, applyCancel := context.WithTimeout(context.Background(), 45*time.Second)
	_, err = manager.Apply(applyCtx, replacement, "")
	applyCancel()
	if err == nil {
		t.Fatal("expected denied replacement to fail")
	}
	if !strings.Contains(err.Error(), "撤销") && !strings.Contains(err.Error(), "remain closed") {
		t.Logf("apply failure: %v", err)
	}
	snapshot := manager.Snapshot(context.Background())
	if !snapshot.Running || !snapshot.DesiredRunning || !snapshot.CanStop {
		t.Fatalf("partial rollback snapshot = %+v", snapshot)
	}
	waitR1TCP(t, keptPort)
	r1Echo(t, keptPort, "kept-after")
	waitR1TCPClosed(t, removedPort)
}

func TestLiveDisableRuleSaveFailureKeepsOldRuleClosed(t *testing.T) {
	if os.Getenv("TLAN_FRP_INTEGRATION") != "1" {
		t.Skip("set TLAN_FRP_INTEGRATION=1 to run real FRP integration")
	}
	frpcPath, _ := r1FRPBinaries(t)
	work := t.TempDir()
	caPath, certPath, keyPath := makeServerTLS(t, work)
	remotePort := freePort(t)
	controlPort := startR1FRPS(t, work, "r1-token", certPath, keyPath, remotePort)
	backendPort := startTCPEcho(t)
	cfg := NewDefaultConfig()
	cfg.Profile.Server.Host = "127.0.0.1"
	cfg.Profile.Server.Port = controlPort
	cfg.Profile.Server.TLSServerName = "localhost"
	cfg.Profile.Server.TrustedCAPath = caPath
	cfg.Profile.Rules = []Rule{{ID: "rule-disabled", Name: "Disabled service", Type: "tcp", Enabled: true, Target: Target{Kind: "loopback", Host: "127.0.0.1", Port: backendPort}, Exposure: Exposure{RemotePort: remotePort}}}
	store, err := NewStore(filepath.Join(work, "store"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg, err = store.Save(cfg, "r1-token"); err != nil {
		t.Fatal(err)
	}
	manager, err := NewManager(Options{Store: store, CorePath: frpcPath, DeviceID: "r1-device"})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close(context.Background())
	startCtx, startCancel := context.WithTimeout(context.Background(), 45*time.Second)
	if err = manager.Start(startCtx); err != nil {
		startCancel()
		t.Fatalf("start: %v\nlogs:\n%s", err, manager.logs.text())
	}
	startCancel()
	r1Echo(t, remotePort, "before-disable")

	profilePath := filepath.Join(store.Root(), profileFileName)
	if err = os.Chmod(profilePath, 0o444); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(profilePath, 0o600)
	replacement := CloneConfig(cfg)
	replacement.Profile.Rules[0].Enabled = false
	applyCtx, applyCancel := context.WithTimeout(context.Background(), 45*time.Second)
	_, err = manager.Apply(applyCtx, replacement, "")
	applyCancel()
	if err == nil {
		t.Fatal("expected profile save failure")
	}
	waitR1TCPClosed(t, remotePort)
	snapshot := manager.Snapshot(context.Background())
	if snapshot.Running || snapshot.DesiredRunning || snapshot.CanStop || manager.RequiresIdentityStop() {
		t.Fatalf("failed restricted apply did not release runtime intent: %+v", snapshot)
	}
	restartCtx, restartCancel := context.WithTimeout(context.Background(), 5*time.Second)
	err = manager.Start(restartCtx)
	restartCancel()
	if err == nil {
		t.Fatal("Start reopened the old profile after a restrictive apply failed")
	}
	waitR1TCPClosed(t, remotePort)

	restarted, err := NewManager(Options{Store: store, CorePath: frpcPath, DeviceID: "r1-device"})
	if err != nil {
		t.Fatalf("load persisted permission ceiling: %v", err)
	}
	defer restarted.Close(context.Background())
	restartCtx, restartCancel = context.WithTimeout(context.Background(), 5*time.Second)
	err = restarted.Start(restartCtx)
	restartCancel()
	if err == nil {
		t.Fatal("a new Manager reopened the old profile despite the persisted permission ceiling")
	}
	waitR1TCPClosed(t, remotePort)
}

type recoverableGatewayProvider struct {
	backendPort int
	mu          sync.Mutex
	down        bool
	done        chan struct{}
}

func (p *recoverableGatewayProvider) currentDone() <-chan struct{} {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.done == nil {
		p.done = make(chan struct{})
	}
	return p.done
}

func (p *recoverableGatewayProvider) setDown(down bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if down {
		if !p.down && p.done != nil {
			close(p.done)
		}
		p.down = true
		return
	}
	if p.down || p.done == nil {
		p.done = make(chan struct{})
	}
	p.down = false
}

type recoverableGatewayLease struct{ done <-chan struct{} }

func (l recoverableGatewayLease) Validate(context.Context, targetgateway.Target) (targetgateway.Lease, error) {
	return targetgateway.Lease{Generation: 1, Done: l.done}, nil
}

func (p *recoverableGatewayProvider) PrepareTarget(context.Context, Rule) (targetgateway.Target, targetgateway.LeaseValidator, targetgateway.Dialer, error) {
	return targetgateway.Target{NetworkID: "net-r1", IPv4: netip.MustParseAddr("10.240.0.9"), Port: uint16(p.backendPort), DeviceID: "dev-r1"}, recoverableGatewayLease{done: p.currentDone()}, gatewayTestDialer{backendPort: p.backendPort}, nil
}

func TestLiveDependencyWaitStopDoesNotRestartAfterRecovery(t *testing.T) {
	if os.Getenv("TLAN_FRP_INTEGRATION") != "1" {
		t.Skip("set TLAN_FRP_INTEGRATION=1 to run real FRP integration")
	}
	frpcPath, _ := r1FRPBinaries(t)
	work := t.TempDir()
	caPath, certPath, keyPath := makeServerTLS(t, work)
	remotePort := freePort(t)
	controlPort := startR1FRPS(t, work, "r1-token", certPath, keyPath, remotePort)
	backendPort := startTCPEcho(t)
	cfg := NewDefaultConfig()
	cfg.Profile.Server.Kind = "managed"
	cfg.Profile.Server.ServerID = "frps-r1"
	cfg.Profile.Server.Host = "127.0.0.1"
	cfg.Profile.Server.Port = controlPort
	cfg.Profile.Server.TLSServerName = "localhost"
	cfg.Profile.Server.TrustedCAPath = caPath
	cfg.Profile.Rules = []Rule{{ID: "rule-wait", Name: "Waiting service", Type: "tcp", Enabled: true, Target: Target{Kind: "mesh_peer", Host: "10.240.0.9", Port: backendPort, NetworkID: "net-r1", DeviceID: "dev-r1", PublicKey: base64.StdEncoding.EncodeToString(make([]byte, 32)), ServiceID: "svc-r1"}, Exposure: Exposure{RemotePort: remotePort}}}
	store, err := NewStore(filepath.Join(work, "store"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg, err = store.Save(cfg, "r1-token"); err != nil {
		t.Fatal(err)
	}
	provider := &recoverableGatewayProvider{backendPort: backendPort}
	manager, err := NewManager(Options{Store: store, CorePath: frpcPath, DeviceID: "dev-local", NetworkID: "net-r1", MeshCIDR: "10.240.0.0/24", LeaseProvider: gatewayLeaseProvider{}, MeshTargetProvider: provider})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close(context.Background())
	startCtx, startCancel := context.WithTimeout(context.Background(), 45*time.Second)
	if err = manager.Start(startCtx); err != nil {
		startCancel()
		t.Fatalf("start: %v\nlogs:\n%s", err, manager.logs.text())
	}
	startCancel()
	r1Echo(t, remotePort, "waiting-before")
	provider.setDown(true)
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		snapshot := manager.Snapshot(context.Background())
		if !snapshot.Running && (snapshot.State == "waiting_dependency" || snapshot.State == "retry_backoff") {
			if !snapshot.DesiredRunning || !snapshot.CanStop {
				t.Fatalf("waiting snapshot lacks stop contract: %+v", snapshot)
			}
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if snapshot := manager.Snapshot(context.Background()); snapshot.Running || (snapshot.State != "waiting_dependency" && snapshot.State != "retry_backoff") {
		t.Fatalf("manager did not enter waiting state: %+v\nlogs:\n%s", snapshot, manager.logs.text())
	}
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 15*time.Second)
	if err = manager.Stop(stopCtx); err != nil {
		stopCancel()
		t.Fatal(err)
	}
	stopCancel()
	provider.setDown(false)
	time.Sleep(3 * time.Second)
	snapshot := manager.Snapshot(context.Background())
	if snapshot.Running || snapshot.DesiredRunning || snapshot.CanStop || manager.RequiresIdentityStop() {
		t.Fatalf("stopped dependency retry reopened after recovery: %+v\nlogs:\n%s", snapshot, manager.logs.text())
	}
	waitR1TCPClosed(t, remotePort)
}

func TestFailedStartClearsIntentAndStopContract(t *testing.T) {
	cfg := testConfig(t)
	cfg.Profile.Rules[0].Target = Target{Kind: "lan", Host: "10.240.0.20", Port: 7777}
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	saved, err := store.Save(cfg, "r1-token")
	if err != nil {
		t.Fatal(err)
	}
	manager := &Manager{store: store, config: saved, hasConfig: true, meshCIDRs: []netip.Prefix{netip.MustParsePrefix("10.240.0.0/24")}, state: "stopped"}
	if err = manager.Start(context.Background()); ErrorCode(err) != CodeRouteConflict {
		t.Fatalf("start error = %v", err)
	}
	snapshot := manager.Snapshot(context.Background())
	if snapshot.Running || snapshot.DesiredRunning || snapshot.CanStop || manager.RequiresIdentityStop() {
		t.Fatalf("failed start retained an unstoppable intent: %+v", snapshot)
	}
}
func TestPreviousAllowedByNextUsesPermissionIntersection(t *testing.T) {
	previous := testConfig(t)
	previous.Profile.Rules = []Rule{
		{ID: "rule-port", Name: "Port", Type: "tcp", Enabled: true, Target: Target{Kind: "loopback", Host: "127.0.0.1", Port: 7001}, Exposure: Exposure{RemotePort: 30001}},
		{ID: "rule-domain", Name: "Domain", Type: "http", Enabled: true, Target: Target{Kind: "loopback", Host: "127.0.0.1", Port: 7002}, Exposure: Exposure{CustomDomains: []string{"keep.example", "remove.example"}}},
		{ID: "rule-kept", Name: "Kept", Type: "tcp", Enabled: true, Target: Target{Kind: "loopback", Host: "127.0.0.1", Port: 7003}, Exposure: Exposure{RemotePort: 30003}},
	}
	previous.Profile.Visitors = []Visitor{{ID: "visitor-remove", Name: "Visitor", Type: "stcp", Enabled: true, ServerName: "remote", SecretRef: "visitor-secret", BindAddr: "127.0.0.1", BindPort: 9000}}
	next := CloneConfig(previous)
	next.Profile.Rules[0].Exposure.RemotePort = 30011
	next.Profile.Rules[1].Exposure.CustomDomains = []string{"keep.example"}
	next.Profile.Visitors = nil

	rollback, fullyAllowed := previousAllowedByNext(previous, next, "token", "token", map[string]string{"visitor-secret": "secret"}, map[string]string{"visitor-secret": "secret"})
	if fullyAllowed {
		t.Fatal("tightened port/domain and removed visitor were treated as fully reversible")
	}
	if len(rollback.Profile.Rules) != 1 || rollback.Profile.Rules[0].ID != "rule-kept" {
		t.Fatalf("rollback intersection = %+v", rollback.Profile.Rules)
	}
	if len(rollback.Profile.Visitors) != 0 {
		t.Fatalf("removed visitor was retained: %+v", rollback.Profile.Visitors)
	}

	broadened := CloneConfig(previous)
	broadened.Profile.Rules[1].Exposure.CustomDomains = []string{"keep.example", "remove.example", "new.example"}
	rollback, fullyAllowed = previousAllowedByNext(previous, broadened, "token", "token", map[string]string{"visitor-secret": "secret"}, map[string]string{"visitor-secret": "secret"})
	if !fullyAllowed || len(rollback.Profile.Rules) != 3 || len(rollback.Profile.Visitors) != 1 {
		t.Fatalf("domain broadening should preserve old permissions: fully=%v rules=%+v visitors=%+v", fullyAllowed, rollback.Profile.Rules, rollback.Profile.Visitors)
	}
}
