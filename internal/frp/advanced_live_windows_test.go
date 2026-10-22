//go:build windows

package frp

import (
	"bufio"
	"context"
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
)

func TestLiveAdvancedFRPTransports(t *testing.T) {
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
	tokenPath := filepath.Join(work, "token")
	if err := os.WriteFile(tokenPath, []byte("advanced-live-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	tcpBind := freePort(t)
	kcpBind := freePort(t)
	quicBind := freePort(t)
	vhostHTTP := freePort(t)
	vhostHTTPS := freePort(t)
	remotePorts := []int{freePort(t), freePort(t), freePort(t), freePort(t), freePort(t)}
	allowPorts := make([]string, 0, len(remotePorts))
	for _, port := range remotePorts {
		allowPorts = append(allowPorts, fmt.Sprintf(`{ start = %d, end = %d }`, port, port))
	}
	frpsConfig := filepath.Join(work, "frps.toml")
	frpsTOML := fmt.Sprintf(`bindAddr = "127.0.0.1"
bindPort = %d
kcpBindPort = %d
quicBindPort = %d
proxyBindAddr = "127.0.0.1"
vhostHTTPPort = %d
vhostHTTPSPort = %d
auth.method = "token"
auth.tokenSource.type = "file"
auth.tokenSource.file.path = %s
transport.tls.force = true
transport.tls.certFile = %s
transport.tls.keyFile = %s
allowPorts = [%s]
maxPortsPerClient = 16
log.to = "console"
log.level = "info"
`, tcpBind, kcpBind, quicBind, vhostHTTP, vhostHTTPS, tomlQuote(tokenPath), tomlQuote(certPath), tomlQuote(keyPath), strings.Join(allowPorts, ", "))
	if err := os.WriteFile(frpsConfig, []byte(frpsTOML), 0o600); err != nil {
		t.Fatal(err)
	}
	verify := exec.Command(frpsPath, "verify", "-c", frpsConfig, "--strict_config=true")
	if output, err := verify.CombinedOutput(); err != nil {
		t.Fatalf("frps verify: %v\n%s", err, output)
	}
	frps := exec.Command(frpsPath, "-c", frpsConfig)
	frpsOut, _ := os.OpenFile(filepath.Join(work, "frps.out"), os.O_CREATE|os.O_WRONLY, 0o600)
	frpsErr, _ := os.OpenFile(filepath.Join(work, "frps.err"), os.O_CREATE|os.O_WRONLY, 0o600)
	frps.Stdout, frps.Stderr = frpsOut, frpsErr
	if err := frps.Start(); err != nil {
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
	waitPort(t, tcpBind)
	time.Sleep(300 * time.Millisecond)
	backendPort := startTCPEcho(t)
	transports := []struct {
		name       string
		serverPort int
		remotePort int
	}{
		{"tcp", tcpBind, remotePorts[0]},
		{"websocket", tcpBind, remotePorts[1]},
		{"wss", tcpBind, remotePorts[2]},
		{"kcp", kcpBind, remotePorts[3]},
		{"quic", quicBind, remotePorts[4]},
	}
	for _, transport := range transports {
		t.Run(transport.name, func(t *testing.T) {
			if transport.name == "wss" {
				t.Skip("fixed FRP v0.71.1 frps does not expose a TLS-then-WebSocket listener on bindPort; schema/render is verified, but this runtime path requires an external WSS reverse proxy")
			}
			store, err := NewStore(filepath.Join(work, "store-"+transport.name))
			if err != nil {
				t.Fatal(err)
			}
			cfg := NewDefaultConfig()
			cfg.Profile.Server.Host = "localhost"
			cfg.Profile.Server.Port = transport.serverPort
			cfg.Profile.Server.Transport = transport.name
			cfg.Profile.Server.TLSServerName = "localhost"
			cfg.Profile.Server.TrustedCAPath = caPath
			cfg.Profile.Server.PublicHTTPPort = vhostHTTP
			cfg.Profile.Server.PublicHTTPSPort = vhostHTTPS
			cfg.Profile.Rules = []Rule{{
				ID: "rule-" + transport.name, Name: "Advanced " + transport.name, Type: "tcp", Enabled: true,
				Target:   Target{Kind: "loopback", Host: "127.0.0.1", Port: backendPort},
				Exposure: Exposure{RemotePort: transport.remotePort},
			}}
			if _, err = store.SaveWithSecrets(cfg, "advanced-live-token", nil); err != nil {
				t.Fatal(err)
			}
			manager, err := NewManager(Options{Store: store, CorePath: frpcPath, DeviceID: "advanced-live-device"})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err = manager.Start(ctx); err != nil {
				t.Fatalf("manager start: %v\nlogs:\n%s", err, manager.logs.text())
			}
			defer manager.Close(context.Background())
			if transport.name == "kcp" || transport.name == "quic" {
				if manager.instance == nil || manager.instance.udpEgressProxy == nil {
					t.Fatal("UDP transport did not start the UDP egress guard")
				}
			} else if manager.instance == nil || manager.instance.egressProxy == nil {
				t.Fatal("TCP transport did not start the TCP egress guard")
			}
			conn, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(transport.remotePort)), 5*time.Second)
			if err != nil {
				t.Fatalf("public connect: %v", err)
			}
			defer conn.Close()
			if _, err = conn.Write([]byte("advanced-live")); err != nil {
				t.Fatal(err)
			}
			got := make([]byte, len("advanced-live"))
			if _, err = io.ReadFull(conn, got); err != nil {
				t.Fatal(err)
			}
			if string(got) != "advanced-live" {
				t.Fatalf("echo = %q", got)
			}
		})
	}
}

func TestLiveAdvancedHTTPFields(t *testing.T) {
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
	tokenPath := filepath.Join(work, "token")
	if err := os.WriteFile(tokenPath, []byte("advanced-http-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	controlPort := freePort(t)
	vhostHTTPPort := freePort(t)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("X-From") != "tlan" {
			t.Errorf("request header rewrite missing: %q", r.Header.Get("X-From"))
		}
		if r.Host != "backend.example.com" {
			t.Errorf("host header rewrite = %q", r.Host)
		}
		w.Header().Set("X-Response", "tlan")
		_, _ = io.WriteString(w, "advanced-http")
	}))
	defer backend.Close()
	backendURL, err := neturl.Parse(backend.URL)
	if err != nil {
		t.Fatal(err)
	}
	backendPort, err := strconv.Atoi(backendURL.Port())
	if err != nil {
		t.Fatal(err)
	}
	frpsConfig := filepath.Join(work, "frps.toml")
	frpsTOML := fmt.Sprintf(`bindAddr = "127.0.0.1"
bindPort = %d
proxyBindAddr = "127.0.0.1"
vhostHTTPPort = %d
auth.method = "token"
auth.tokenSource.type = "file"
auth.tokenSource.file.path = %s
transport.tls.force = true
transport.tls.certFile = %s
transport.tls.keyFile = %s
log.to = "console"
log.level = "info"
`, controlPort, vhostHTTPPort, tomlQuote(tokenPath), tomlQuote(certPath), tomlQuote(keyPath))
	if err := os.WriteFile(frpsConfig, []byte(frpsTOML), 0o600); err != nil {
		t.Fatal(err)
	}
	verify := exec.Command(frpsPath, "verify", "-c", frpsConfig, "--strict_config=true")
	if output, err := verify.CombinedOutput(); err != nil {
		t.Fatalf("frps verify: %v\n%s", err, output)
	}
	frps := exec.Command(frpsPath, "-c", frpsConfig)
	frpsOut, _ := os.OpenFile(filepath.Join(work, "frps.out"), os.O_CREATE|os.O_WRONLY, 0o600)
	frpsErr, _ := os.OpenFile(filepath.Join(work, "frps.err"), os.O_CREATE|os.O_WRONLY, 0o600)
	frps.Stdout, frps.Stderr = frpsOut, frpsErr
	if err := frps.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if frps.Process != nil {
			_ = frps.Process.Kill()
			_, _ = frps.Process.Wait()
		}
		_ = frpsOut.Close()
		_ = frpsErr.Close()
	}()
	waitPort(t, controlPort)
	store, err := NewStore(filepath.Join(work, "store"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := NewDefaultConfig()
	cfg.Profile.Server.Host = "localhost"
	cfg.Profile.Server.Port = controlPort
	cfg.Profile.Server.TLSServerName = "localhost"
	cfg.Profile.Server.TrustedCAPath = caPath
	cfg.Profile.Server.PublicHTTPPort = vhostHTTPPort
	cfg.Profile.Rules = []Rule{{
		ID: "rule-http-advanced", Name: "Advanced HTTP", Type: "http", Enabled: true,
		Target: Target{Kind: "loopback", Host: "127.0.0.1", Port: backendPort},
		Exposure: Exposure{
			CustomDomains: []string{"app.test"}, Locations: []string{"/api"},
			HTTPUser: "alice", HTTPPasswordRef: "http-secret", HostHeaderRewrite: "backend.example.com",
			RequestHeaders: map[string]string{"X-From": "tlan"}, ResponseHeaders: map[string]string{"X-Response": "tlan"},
		},
		Transport: RuleTransport{UseEncryption: true, UseCompression: true},
	}}
	if _, err = store.SaveWithSecrets(cfg, "advanced-http-token", map[string]string{"http-secret": "http-password"}); err != nil {
		t.Fatal(err)
	}
	manager, err := NewManager(Options{Store: store, CorePath: frpcPath, DeviceID: "advanced-http-device"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err = manager.Start(ctx); err != nil {
		t.Fatalf("manager start: %v\nlogs:\n%s", err, manager.logs.text())
	}
	defer manager.Close(context.Background())
	request := func(path string, auth bool) (*http.Response, []byte) {
		req, reqErr := http.NewRequest(http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d%s", vhostHTTPPort, path), nil)
		if reqErr != nil {
			t.Fatal(reqErr)
		}
		req.Host = "app.test"
		if auth {
			req.SetBasicAuth("alice", "http-password")
		}
		resp, reqErr := (&http.Client{Timeout: 5 * time.Second}).Do(req)
		if reqErr != nil {
			t.Fatal(reqErr)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return resp, body
	}
	resp, body := request("/api", false)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("HTTP without basic auth = %d %q", resp.StatusCode, body)
	}
	resp, body = request("/api", true)
	if resp.StatusCode != http.StatusOK || string(body) != "advanced-http" || resp.Header.Get("X-Response") != "tlan" {
		t.Fatalf("advanced HTTP response = %d %q headers=%v", resp.StatusCode, body, resp.Header)
	}
	resp, body = request("/other", true)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("HTTP location bypass = %d %q", resp.StatusCode, body)
	}
}

func TestLiveTCPMuxHTTPConnect(t *testing.T) {
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
	tokenPath := filepath.Join(work, "token")
	if err := os.WriteFile(tokenPath, []byte("tcpmux-live-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	controlPort := freePort(t)
	tcpmuxPort := freePort(t)
	frpsConfig := filepath.Join(work, "frps.toml")
	frpsTOML := fmt.Sprintf(`bindAddr = "127.0.0.1"
bindPort = %d
proxyBindAddr = "127.0.0.1"
tcpmuxHTTPConnectPort = %d
auth.method = "token"
auth.tokenSource.type = "file"
auth.tokenSource.file.path = %s
transport.tls.force = true
transport.tls.certFile = %s
transport.tls.keyFile = %s
log.to = "console"
log.level = "info"
`, controlPort, tcpmuxPort, tomlQuote(tokenPath), tomlQuote(certPath), tomlQuote(keyPath))
	if err := os.WriteFile(frpsConfig, []byte(frpsTOML), 0o600); err != nil {
		t.Fatal(err)
	}
	verify := exec.Command(frpsPath, "verify", "-c", frpsConfig, "--strict_config=true")
	if output, err := verify.CombinedOutput(); err != nil {
		t.Fatalf("frps verify: %v\n%s", err, output)
	}
	frps := exec.Command(frpsPath, "-c", frpsConfig)
	frpsOut, _ := os.OpenFile(filepath.Join(work, "frps.out"), os.O_CREATE|os.O_WRONLY, 0o600)
	frpsErr, _ := os.OpenFile(filepath.Join(work, "frps.err"), os.O_CREATE|os.O_WRONLY, 0o600)
	frps.Stdout, frps.Stderr = frpsOut, frpsErr
	if err := frps.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if frps.Process != nil {
			_ = frps.Process.Kill()
			_, _ = frps.Process.Wait()
		}
		_ = frpsOut.Close()
		_ = frpsErr.Close()
	}()
	waitPort(t, controlPort)
	backendPort := startTCPEcho(t)
	store, err := NewStore(filepath.Join(work, "store"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := NewDefaultConfig()
	cfg.Profile.Server.Host = "localhost"
	cfg.Profile.Server.Port = controlPort
	cfg.Profile.Server.TLSServerName = "localhost"
	cfg.Profile.Server.TrustedCAPath = caPath
	cfg.Profile.Rules = []Rule{{
		ID: "rule-tcpmux", Name: "TCPMUX live", Type: "tcpmux", Enabled: true,
		Target:   Target{Kind: "loopback", Host: "127.0.0.1", Port: backendPort},
		Exposure: Exposure{CustomDomains: []string{"tunnel.test"}, Multiplexer: "httpconnect"},
	}}
	if _, err = store.SaveWithSecrets(cfg, "tcpmux-live-token", nil); err != nil {
		t.Fatal(err)
	}
	manager, err := NewManager(Options{Store: store, CorePath: frpcPath, DeviceID: "tcpmux-live-device"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err = manager.Start(ctx); err != nil {
		t.Fatalf("manager start: %v\nlogs:\n%s", err, manager.logs.text())
	}
	defer manager.Close(context.Background())
	conn, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(tcpmuxPort)), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err = fmt.Fprintf(conn, "CONNECT tunnel.test:80 HTTP/1.1\r\nHost: tunnel.test:80\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(statusLine, " 200 ") {
		t.Fatalf("TCPMUX CONNECT status = %q", statusLine)
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
	if _, err = conn.Write([]byte("tcpmux-live")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len("tcpmux-live"))
	if _, err = io.ReadFull(reader, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "tcpmux-live" {
		t.Fatalf("TCPMUX echo = %q", got)
	}
}
