//go:build windows

package frp

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

type unobservedLeaseProvider struct {
	lease Lease
}

func (p *unobservedLeaseProvider) Acquire(context.Context, LeaseRequest) (Lease, error) {
	return p.lease, nil
}

func (p *unobservedLeaseProvider) Renew(context.Context, string) (Lease, error) {
	return p.lease, nil
}

func (p *unobservedLeaseProvider) Release(context.Context, string) error { return nil }

func (p *unobservedLeaseProvider) VerifyActive(context.Context, string, bool) error {
	return errors.New("plugin observation missing")
}

func TestLiveManagedRejectsUnobservedPlugin(t *testing.T) {
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
	tokenPath := filepath.Join(work, "outer-token")
	if err := os.WriteFile(tokenPath, []byte("unobserved-outer-token"), 0o600); err != nil {
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
	cfg.Profile.Server.ServerID = "frps-managed-1"
	cfg.Profile.Server.Host = "127.0.0.1"
	cfg.Profile.Server.Port = controlPort
	cfg.Profile.Server.TLSServerName = "localhost"
	cfg.Profile.Server.TrustedCAPath = caPath
	cfg.Profile.Rules = []Rule{{
		ID: "rule-unobserved", Name: "Unobserved managed rule", Type: "tcp", Enabled: true,
		Target:   Target{Kind: "loopback", Host: "127.0.0.1", Port: backendPort},
		Exposure: Exposure{RemotePort: remotePort},
	}}
	store, err := NewStore(filepath.Join(work, "store"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.Save(cfg, "unobserved-outer-token"); err != nil {
		t.Fatal(err)
	}
	provider := &unobservedLeaseProvider{lease: Lease{
		ID: "lease-unobserved", Credential: "capability-unobserved", ExpiresAt: time.Now().Add(time.Minute),
	}}
	manager, err := NewManager(Options{Store: store, CorePath: frpcPath, DeviceID: "dev-unobserved", NetworkID: "net-unobserved", LeaseProvider: provider})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = manager.Close(context.Background()) }()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err = manager.Start(ctx)
	if ErrorCode(err) != CodeAuthRejected {
		t.Fatalf("unobserved plugin start error = %v", err)
	}
	if manager.Snapshot(context.Background()).Running {
		t.Fatal("manager reported running without plugin observation")
	}
}
