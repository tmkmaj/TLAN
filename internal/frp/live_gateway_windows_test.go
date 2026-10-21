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
	"testing"
	"time"

	"github.com/private-radminlan/lanmesh/internal/targetgateway"
)

type gatewayLeaseProvider struct{}

func (gatewayLeaseProvider) Acquire(_ context.Context, request LeaseRequest) (Lease, error) {
	lease := Lease{ID: "lease-gateway", Credential: "capability-gateway", ExpiresAt: time.Now().Add(10 * time.Minute)}
	lease.Rules = append([]LeaseRule(nil), request.Rules...)
	for i := range lease.Rules {
		if lease.Rules[i].TargetKind == "mesh_peer" || lease.Rules[i].TargetKind == "mesh_self" {
			lease.Rules[i].GrantID = "grant-gateway"
		}
	}
	return lease, nil
}

func (p gatewayLeaseProvider) Renew(_ context.Context, leaseID string) (Lease, error) {
	return Lease{ID: leaseID, Credential: "capability-gateway", ExpiresAt: time.Now().Add(10 * time.Minute)}, nil
}

func (gatewayLeaseProvider) Release(context.Context, string) error { return nil }

func (gatewayLeaseProvider) VerifyActive(context.Context, string, bool) error { return nil }

type gatewayTestProvider struct {
	backendPort int
	done        chan struct{}
}

type gatewayTestLease struct{ done <-chan struct{} }

func (l gatewayTestLease) Validate(_ context.Context, _ targetgateway.Target) (targetgateway.Lease, error) {
	return targetgateway.Lease{Generation: 1, Done: l.done}, nil
}

type gatewayTestDialer struct{ backendPort int }

func (d gatewayTestDialer) DialTCP(ctx context.Context, _ targetgateway.Target, _ uint64) (net.Conn, error) {
	return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(d.backendPort)))
}
func (d gatewayTestDialer) DialUDP(ctx context.Context, _ targetgateway.Target, _ uint64) (net.Conn, error) {
	return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "udp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(d.backendPort)))
}

func (p gatewayTestProvider) PrepareTarget(_ context.Context, _ Rule) (targetgateway.Target, targetgateway.LeaseValidator, targetgateway.Dialer, error) {
	return targetgateway.Target{NetworkID: "net-gateway", IPv4: mustAddr("10.240.0.9"), Port: uint16(p.backendPort), DeviceID: "dev-gateway"}, gatewayTestLease{done: p.done}, gatewayTestDialer{backendPort: p.backendPort}, nil
}

func mustAddr(value string) (addr netip.Addr) {
	addr, _ = netip.ParseAddr(value)
	return addr
}

func TestLiveTargetGatewayPublishAndDependencyStop(t *testing.T) {
	if os.Getenv("TLAN_FRP_INTEGRATION") != "1" {
		t.Skip("set TLAN_FRP_INTEGRATION=1 to run real FRP integration")
	}
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
	work := t.TempDir()
	caPath, certPath, keyPath := makeServerTLS(t, work)
	controlPort := freePort(t)
	remotePort := freePort(t)
	backendPort := startTCPEcho(t)
	tokenPath := filepath.Join(work, "token")
	if err := os.WriteFile(tokenPath, []byte("gateway-live-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	frpsConfig := filepath.Join(work, "frps.toml")
	toml := fmt.Sprintf(`bindAddr = "127.0.0.1"
bindPort = %d
proxyBindAddr = "127.0.0.1"
auth.method = "token"
auth.tokenSource.type = "file"
auth.tokenSource.file.path = %s
transport.tls.force = true
transport.tls.certFile = %s
transport.tls.keyFile = %s
allowPorts = [{ start = %d, end = %d }]
log.to = "console"
log.level = "info"
`, controlPort, tomlQuote(tokenPath), tomlQuote(certPath), tomlQuote(keyPath), remotePort, remotePort)
	if err := os.WriteFile(frpsConfig, []byte(toml), 0o600); err != nil {
		t.Fatal(err)
	}
	frps := exec.Command(frpsPath, "-c", frpsConfig)
	out, _ := os.OpenFile(filepath.Join(work, "frps.out"), os.O_CREATE|os.O_WRONLY, 0o600)
	errOut, _ := os.OpenFile(filepath.Join(work, "frps.err"), os.O_CREATE|os.O_WRONLY, 0o600)
	frps.Stdout, frps.Stderr = out, errOut
	if err := frps.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if frps.Process != nil {
			_ = frps.Process.Kill()
			_, _ = frps.Process.Wait()
		}
		_ = out.Close()
		_ = errOut.Close()
	}()
	waitPort(t, controlPort)

	cfg := NewDefaultConfig()
	cfg.Profile.Server.Kind = "managed"
	cfg.Profile.Server.ServerID = "frps-gateway"
	cfg.Profile.Server.Host = "127.0.0.1"
	cfg.Profile.Server.Port = controlPort
	cfg.Profile.Server.TLSServerName = "localhost"
	cfg.Profile.Server.TrustedCAPath = caPath
	cfg.Profile.Rules = []Rule{{ID: "rule-gateway", Name: "Mesh gateway", Type: "tcp", Enabled: true, Target: Target{Kind: "mesh_peer", Host: "10.240.0.9", Port: backendPort, NetworkID: "net-gateway", DeviceID: "dev-gateway", PublicKey: base64.StdEncoding.EncodeToString(make([]byte, 32)), ServiceID: "svc-gateway"}, Exposure: Exposure{RemotePort: remotePort}}}
	store, err := NewStore(filepath.Join(work, "store"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.Save(cfg, "gateway-live-token"); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	provider := gatewayTestProvider{backendPort: backendPort, done: done}
	manager, err := NewManager(Options{Store: store, CorePath: frpcPath, DeviceID: "dev-local", NetworkID: "net-gateway", MeshCIDR: "10.240.0.0/24", LeaseProvider: gatewayLeaseProvider{}, MeshTargetProvider: provider})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err = manager.Start(ctx); err != nil {
		t.Fatalf("gateway start: %v\nlogs:\n%s", err, manager.logs.text())
	}
	defer manager.Close(context.Background())
	// The GUI/start request context is intentionally short-lived. TargetGateway
	// must remain owned by the manager runtime after Start returns.
	cancel()
	conn, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(remotePort)), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = conn.Write([]byte("gateway-live"))
	buf := make([]byte, 32)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := io.ReadAtLeast(conn, buf, len("gateway-live"))
	_ = conn.Close()
	if err != nil || string(buf[:n]) != "gateway-live" {
		stats := targetgateway.Stats{}
		if manager.instance != nil && len(manager.instance.gateways) > 0 {
			stats = manager.instance.gateways[0].Stats()
		}
		t.Fatalf("gateway echo = %q, %v; stats=%+v; logs=%s", buf[:n], err, stats, manager.logs.text())
	}
	close(done)
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		if !manager.Snapshot(context.Background()).Running {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if manager.Snapshot(context.Background()).Running {
		t.Fatal("FRP runtime did not stop after Mesh dependency invalidation")
	}
}
