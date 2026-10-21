//go:build windows

package frp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"github.com/private-radminlan/lanmesh/internal/frpauth"
)

type managedTestProvider struct {
	store     *frpauth.Store
	networkID string
	deviceID  string
	mu        sync.Mutex
	leaseID   string
}

func (p *managedTestProvider) Acquire(_ context.Context, request LeaseRequest) (Lease, error) {
	rules := make([]frpauth.Rule, 0, len(request.Rules))
	for _, rule := range request.Rules {
		rules = append(rules, frpauth.Rule{
			ID: rule.ID, ProxyName: rule.ProxyName, Type: rule.Type, RemotePort: rule.RemotePort,
			CustomDomains: append([]string(nil), rule.CustomDomains...), BindPort: rule.BindPort,
			SubDomain: rule.SubDomain, Locations: append([]string(nil), rule.Locations...),
			HTTPUser: rule.HTTPUser, HTTPPasswordHash: rule.HTTPPasswordHash,
			HostHeaderRewrite: rule.HostHeaderRewrite, Headers: cloneStringMap(rule.Headers),
			ResponseHeaders: cloneStringMap(rule.ResponseHeaders), RouteByHTTPUser: rule.RouteByHTTPUser,
			Multiplexer: rule.Multiplexer, SecretHash: rule.SecretHash,
			AllowUsers: append([]string(nil), rule.AllowUsers...), UseEncryption: rule.UseEncryption,
			UseCompression: rule.UseCompression, TargetKind: rule.TargetKind,
			TargetNetworkID: rule.TargetNetworkID, TargetDeviceID: rule.TargetDeviceID,
			TargetPublicKey: rule.TargetPublicKey, TargetHost: rule.TargetHost,
			TargetServiceID: rule.TargetServiceID,
		})
	}
	response, err := p.store.Issue(p.networkID, p.deviceID, request.ServerID, rules)
	if err != nil {
		return Lease{}, err
	}
	p.mu.Lock()
	p.leaseID = response.LeaseID
	p.mu.Unlock()
	return Lease{ID: response.LeaseID, Credential: response.Credential, ExpiresAt: response.ExpiresAt}, nil
}

func (p *managedTestProvider) VerifyActive(_ context.Context, leaseID string, requireProxy bool) error {
	status, err := p.store.Status(leaseID, p.networkID, p.deviceID)
	if err != nil {
		return err
	}
	if status.Revoked || !status.LoginSeen || requireProxy && !status.ProxySeen {
		return errors.New("managed authorization was not observed")
	}
	return nil
}

func (p *managedTestProvider) currentLeaseID() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.leaseID
}
func (p *managedTestProvider) Renew(_ context.Context, leaseID string) (Lease, error) {
	response, err := p.store.Renew(leaseID, p.networkID, p.deviceID)
	if err != nil {
		return Lease{}, err
	}
	lease := Lease{ID: response.LeaseID, ExpiresAt: response.ExpiresAt}
	for _, rule := range response.Rules {
		lease.Rules = append(lease.Rules, LeaseRule{
			ID: rule.ID, ProxyName: rule.ProxyName, Type: rule.Type, RemotePort: rule.RemotePort,
			CustomDomains: append([]string(nil), rule.CustomDomains...), BindPort: rule.BindPort,
			SubDomain: rule.SubDomain, Locations: append([]string(nil), rule.Locations...),
			HTTPUser: rule.HTTPUser, HTTPPasswordHash: rule.HTTPPasswordHash,
			HostHeaderRewrite: rule.HostHeaderRewrite, Headers: cloneStringMap(rule.Headers),
			ResponseHeaders: cloneStringMap(rule.ResponseHeaders), RouteByHTTPUser: rule.RouteByHTTPUser,
			Multiplexer: rule.Multiplexer, SecretHash: rule.SecretHash,
			AllowUsers: append([]string(nil), rule.AllowUsers...), UseEncryption: rule.UseEncryption,
			UseCompression: rule.UseCompression, TargetKind: rule.TargetKind,
			TargetNetworkID: rule.TargetNetworkID, TargetDeviceID: rule.TargetDeviceID,
			TargetPublicKey: rule.TargetPublicKey, TargetHost: rule.TargetHost,
			TargetServiceID: rule.TargetServiceID, GrantID: rule.GrantID,
		})
	}
	return lease, nil
}
func (p *managedTestProvider) Release(_ context.Context, leaseID string) error {
	return p.store.Revoke(leaseID, p.networkID, p.deviceID)
}

func TestLiveManagedFRPLease(t *testing.T) {
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
	tcpPort := startTCPEcho(t)
	authStore, err := frpauth.NewStore(frpauth.Options{
		StatePath: filepath.Join(work, "leases.json"), ServerID: "frps-managed-1",
		AllowedPorts: []frpauth.PortRange{{Start: remotePort, End: remotePort}},
	})
	if err != nil {
		t.Fatal(err)
	}
	plugin := httptest.NewServer(frpauth.NewPluginHandler(authStore))
	defer plugin.Close()
	pluginURL, _ := url.Parse(plugin.URL)
	_, pluginPort, _ := net.SplitHostPort(pluginURL.Host)
	outerToken := filepath.Join(work, "outer-token")
	if err = os.WriteFile(outerToken, []byte("managed-outer-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	frpsConfig := filepath.Join(work, "frps.toml")
	frpsTOML := fmt.Sprintf(`bindAddr = "127.0.0.1"
bindPort = %d
proxyBindAddr = "127.0.0.1"
auth.method = "token"
auth.tokenSource.type = "file"
auth.tokenSource.file.path = %s
transport.tls.force = true
transport.heartbeatTimeout = 8
transport.tls.certFile = %s
transport.tls.keyFile = %s
allowPorts = [{ start = %d, end = %d }]
log.to = "console"
log.level = "info"
[[httpPlugins]]
name = "tlan-managed-auth"
addr = "127.0.0.1:%s"
path = "/api/v1/frp/plugin"
ops = ["Login", "NewProxy", "Ping", "NewUserConn"]
`, controlPort, tomlQuote(outerToken), tomlQuote(certPath), tomlQuote(keyPath), remotePort, remotePort, pluginPort)
	if err = os.WriteFile(frpsConfig, []byte(frpsTOML), 0o600); err != nil {
		t.Fatal(err)
	}
	frps := exec.Command(frpsPath, "-c", frpsConfig)
	out, _ := os.OpenFile(filepath.Join(work, "frps.out"), os.O_CREATE|os.O_WRONLY, 0o600)
	errOut, _ := os.OpenFile(filepath.Join(work, "frps.err"), os.O_CREATE|os.O_WRONLY, 0o600)
	frps.Stdout, frps.Stderr = out, errOut
	if err = frps.Start(); err != nil {
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
	cfg.Profile.Server.ServerID = "frps-managed-1"
	cfg.Profile.Server.Host = "127.0.0.1"
	cfg.Profile.Server.Port = controlPort
	cfg.Profile.Server.TLSServerName = "localhost"
	cfg.Profile.Server.TrustedCAPath = caPath
	cfg.Profile.Rules = []Rule{{ID: "rule-managed", Name: "Managed TCP", Type: "tcp", Enabled: true, Target: Target{Kind: "loopback", Host: "127.0.0.1", Port: tcpPort}, Exposure: Exposure{RemotePort: remotePort}}}
	store, err := NewStore(filepath.Join(work, "store"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.Save(cfg, "managed-outer-token"); err != nil {
		t.Fatal(err)
	}
	provider := &managedTestProvider{store: authStore, networkID: "net-managed", deviceID: "dev-managed"}
	manager, err := NewManager(Options{Store: store, CorePath: frpcPath, DeviceID: "dev-managed", NetworkID: "net-managed", LeaseProvider: provider})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err = manager.Start(ctx); err != nil {
		t.Fatalf("managed start: %v\nlogs:\n%s", err, manager.logs.text())
	}
	conn, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(remotePort)), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = conn.Write([]byte("managed-live"))
	buf := make([]byte, 32)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := conn.Read(buf)
	_ = conn.Close()
	if err != nil || string(buf[:n]) != "managed-live" {
		t.Fatalf("managed echo = %q, %v", buf[:n], err)
	}
	// Runtime Apply must revoke the old exclusive lease before requesting the
	// replacement. This is the regression path that previously failed with a
	// proxy-name/port conflict.
	updated, ok := manager.Config()
	if !ok {
		t.Fatal("managed manager has no current config")
	}
	updated.Profile.Rules[0].Name = "Managed TCP Updated"
	if _, err = manager.Apply(ctx, updated, "managed-outer-token"); err != nil {
		t.Fatalf("managed runtime apply: %v\nlogs:\n%s", err, manager.logs.text())
	}
	conn, err = net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(remotePort)), 5*time.Second)
	if err != nil {
		t.Fatalf("dial after managed apply: %v", err)
	}
	_, _ = conn.Write([]byte("managed-apply"))
	buf = make([]byte, 32)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err = conn.Read(buf)
	_ = conn.Close()
	if err != nil || string(buf[:n]) != "managed-apply" {
		t.Fatalf("managed echo after apply = %q, %v", buf[:n], err)
	}
	manager.mu.Lock()
	oldInstance := manager.instance
	manager.mu.Unlock()
	if oldInstance == nil {
		t.Fatal("managed manager has no runtime instance before crash test")
	}
	if err = windows.TerminateProcess(oldInstance.process.Process, 1); err != nil {
		t.Fatalf("terminate managed frpc: %v", err)
	}
	restartDeadline := time.Now().Add(20 * time.Second)
	restarted := false
	for time.Now().Before(restartDeadline) {
		manager.mu.Lock()
		currentInstance := manager.instance
		manager.mu.Unlock()
		if currentInstance != nil && currentInstance != oldInstance {
			restarted = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !restarted {
		t.Fatalf("managed runtime did not restart after frpc crash\nlogs:\n%s", manager.logs.text())
	}
	conn, err = net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(remotePort)), 5*time.Second)
	if err != nil {
		t.Fatalf("dial after managed restart: %v", err)
	}
	_, _ = conn.Write([]byte("managed-restart"))
	buf = make([]byte, 32)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err = conn.Read(buf)
	_ = conn.Close()
	if err != nil || string(buf[:n]) != "managed-restart" {
		t.Fatalf("managed echo after restart = %q, %v", buf[:n], err)
	}
	if err = manager.Stop(context.Background()); err != nil {
		t.Fatalf("stop after restart: %v", err)
	}
	if err = manager.Start(context.Background()); err != nil {
		t.Fatalf("start for revocation test: %v\nlogs:\n%s", err, manager.logs.text())
	}
	leaseID := provider.currentLeaseID()
	if leaseID == "" {
		t.Fatal("managed provider did not record the issued lease")
	}
	revokedAt := time.Now()
	if err = authStore.Revoke(leaseID, "net-managed", "dev-managed"); err != nil {
		t.Fatal(err)
	}
	deadline := revokedAt.Add(10 * time.Second)
	for time.Now().Before(deadline) && manager.Snapshot(context.Background()).Running {
		time.Sleep(100 * time.Millisecond)
	}
	if manager.Snapshot(context.Background()).Running {
		t.Fatalf("managed manager remained running after revocation\nlogs:\n%s", manager.logs.text())
	}
	if elapsed := time.Since(revokedAt); elapsed > 10*time.Second {
		t.Fatalf("managed manager stopped after %s, want <=10s", elapsed)
	}
	if err = manager.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if snapshot := manager.Snapshot(context.Background()); snapshot.Running {
		t.Fatal("managed manager still running")
	}
}
