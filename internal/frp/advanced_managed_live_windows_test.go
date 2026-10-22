//go:build windows

package frp

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	neturl "net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/private-radminlan/lanmesh/internal/frpauth"
)

func TestLiveManagedAdvancedHTTPTCPMUXAndXTCPAuthorization(t *testing.T) {
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
	vhostPort := freePort(t)
	tcpmuxPort := freePort(t)
	echoPort := startTCPEcho(t)
	httpBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Response", "tlan")
		_, _ = io.WriteString(w, "managed-advanced-http")
	}))
	defer httpBackend.Close()
	httpURL, err := neturl.Parse(httpBackend.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, httpPortText, err := net.SplitHostPort(httpURL.Host)
	if err != nil {
		t.Fatal(err)
	}
	httpPort, err := strconv.Atoi(httpPortText)
	if err != nil {
		t.Fatal(err)
	}

	authStore, err := frpauth.NewStore(frpauth.Options{
		StatePath: filepath.Join(work, "advanced-leases.json"), ServerID: "frps-managed-advanced",
		CoreVersion: "0.71.1", LeaseTTL: 10 * time.Minute,
		AllowedDomains: []string{"frp.example.com", "mux.example.net"},
	})
	if err != nil {
		t.Fatal(err)
	}
	pluginServer := httptest.NewServer(frpauth.NewPluginHandler(authStore))
	defer pluginServer.Close()
	pluginURL, err := neturl.Parse(pluginServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, pluginPort, err := net.SplitHostPort(pluginURL.Host)
	if err != nil {
		t.Fatal(err)
	}
	outerToken := filepath.Join(work, "outer-token")
	if err = os.WriteFile(outerToken, []byte("managed-advanced-outer-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	frpsConfig := filepath.Join(work, "frps.toml")
	frpsTOML := fmt.Sprintf(`bindAddr = "127.0.0.1"
bindPort = %d
proxyBindAddr = "127.0.0.1"
vhostHTTPPort = %d
subdomainHost = "frp.example.com"
tcpmuxHTTPConnectPort = %d
auth.method = "token"
auth.tokenSource.type = "file"
auth.tokenSource.file.path = %s
transport.tls.force = true
transport.tls.certFile = %s
transport.tls.keyFile = %s
transport.heartbeatTimeout = 8
log.to = "console"
log.level = "info"
[[httpPlugins]]
name = "tlan-managed-advanced"
addr = "127.0.0.1:%s"
path = "/api/v1/frp/plugin"
ops = ["Login", "NewProxy", "Ping", "NewUserConn"]
`, controlPort, vhostPort, tcpmuxPort, tomlQuote(outerToken), tomlQuote(certPath), tomlQuote(keyPath), pluginPort)
	if err = os.WriteFile(frpsConfig, []byte(frpsTOML), 0o600); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command(frpsPath, "verify", "-c", frpsConfig, "--strict_config=true").CombinedOutput(); err != nil {
		t.Fatalf("frps verify: %v\n%s", err, output)
	}
	frps := exec.Command(frpsPath, "-c", frpsConfig)
	frpsOut, _ := os.OpenFile(filepath.Join(work, "frps.out"), os.O_CREATE|os.O_WRONLY, 0o600)
	frpsErr, _ := os.OpenFile(filepath.Join(work, "frps.err"), os.O_CREATE|os.O_WRONLY, 0o600)
	frps.Stdout, frps.Stderr = frpsOut, frpsErr
	if err = frps.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if frps.Process != nil {
			_ = frps.Process.Kill()
			_, _ = frps.Process.Wait()
		}
		_ = frpsOut.Close()
		_ = frpsErr.Close()
		if t.Failed() {
			if data, readErr := os.ReadFile(filepath.Join(work, "frps.err")); readErr == nil {
				t.Logf("frps stderr:\n%s", data)
			}
			if data, readErr := os.ReadFile(filepath.Join(work, "frps.out")); readErr == nil {
				t.Logf("frps stdout:\n%s", data)
			}
		}
	}()
	waitPort(t, controlPort)

	cfg := NewDefaultConfig()
	cfg.Profile.Server.Kind = "managed"
	cfg.Profile.Server.ServerID = "frps-managed-advanced"
	cfg.Profile.Server.Host = "localhost"
	cfg.Profile.Server.Port = controlPort
	cfg.Profile.Server.TLSServerName = "localhost"
	cfg.Profile.Server.TrustedCAPath = caPath
	cfg.Profile.Server.PublicHTTPPort = vhostPort
	cfg.Profile.Rules = []Rule{
		{
			ID: "rule-http-advanced", Name: "Managed advanced HTTP", Type: "http", Enabled: true,
			Target: Target{Kind: "loopback", Host: "127.0.0.1", Port: httpPort},
			Exposure: Exposure{
				Subdomain: "app",
				Locations: []string{"/api"}, HTTPUser: "alice", HTTPPasswordRef: "http-password",
				HostHeaderRewrite: "backend.example.com", RouteByHTTPUser: "alice",
				RequestHeaders: map[string]string{"X-From": "tlan"}, ResponseHeaders: map[string]string{"X-Response": "tlan"},
			},
		},
		{
			ID: "rule-tcpmux", Name: "Managed TCPMUX", Type: "tcpmux", Enabled: true,
			Target: Target{Kind: "loopback", Host: "127.0.0.1", Port: echoPort},
			Exposure: Exposure{CustomDomains: []string{"mux.example.net"}, Multiplexer: "httpconnect",
				HTTPUser: "bob", HTTPPasswordRef: "mux-password", RouteByHTTPUser: "bob"},
		},
		{
			ID: "rule-xtcp", Name: "Managed XTCP", Type: "xtcp", Enabled: true, SecretRef: "xtcp-secret",
			Target: Target{Kind: "loopback", Host: "127.0.0.1", Port: echoPort},
		},
	}
	localStore, err := NewStore(filepath.Join(work, "local-store"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = localStore.SaveWithSecrets(cfg, "managed-advanced-outer-token", map[string]string{
		"http-password": "managed-http-password", "mux-password": "managed-mux-password", "xtcp-secret": "managed-xtcp-secret",
	}); err != nil {
		t.Fatal(err)
	}
	provider := &managedTestProvider{store: authStore, networkID: "net-managed-advanced", deviceID: "dev-managed-advanced"}
	manager, err := NewManager(Options{Store: localStore, CorePath: frpcPath, DeviceID: "dev-managed-advanced", NetworkID: "net-managed-advanced", LeaseProvider: provider})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err = manager.Start(ctx); err != nil {
		t.Fatalf("managed advanced start: %v\nlogs:\n%s", err, manager.logs.text())
	}
	defer func() { _ = manager.Close(context.Background()) }()

	httpReq, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/api", vhostPort), nil)
	if err != nil {
		t.Fatal(err)
	}
	httpReq.Host = "app.frp.example.com"
	httpReq.SetBasicAuth("alice", "managed-http-password")
	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "managed-advanced-http" || resp.Header.Get("X-Response") != "tlan" {
		t.Fatalf("managed advanced HTTP = %d %q headers=%v", resp.StatusCode, body, resp.Header)
	}

	conn, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(tcpmuxPort)), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	auth := base64.StdEncoding.EncodeToString([]byte("bob:managed-mux-password"))
	if _, err = fmt.Fprintf(conn, "CONNECT mux.example.net:80 HTTP/1.1\r\nHost: mux.example.net:80\r\nProxy-Authorization: Basic %s\r\nAuthorization: Basic %s\r\n\r\n", auth, auth); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(statusLine, " 200 ") {
		t.Fatalf("managed TCPMUX CONNECT status = %q", statusLine)
	}
	for {
		line, readErr := reader.ReadString('\n')
		if readErr != nil {
			t.Fatal(readErr)
		}
		if line == "\r\n" {
			break
		}
	}
	if _, err = conn.Write([]byte("managed-tcpmux")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len("managed-tcpmux"))
	if _, err = io.ReadFull(reader, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "managed-tcpmux" {
		t.Fatalf("managed TCPMUX echo = %q", got)
	}
	leaseID := provider.currentLeaseID()
	status, err := authStore.Status(leaseID, "net-managed-advanced", "dev-managed-advanced")
	if err != nil {
		t.Fatal(err)
	}
	if !status.LoginSeen || !status.ProxySeen || status.Revoked {
		t.Fatalf("managed XTCP/plugin authorization status = %+v", status)
	}
}
