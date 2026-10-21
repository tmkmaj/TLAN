//go:build windows

package frpauth

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// This test is intentionally opt-in because it requires the pinned local FRP
// binaries. It exercises the actual v0.71.1 HTTP-plugin JSON shape rather than
// only synthetic handler fixtures.
func TestLiveFRPSPluginTCPAndHTTPProxy(t *testing.T) {
	if os.Getenv("TLAN_FRP_LIVE") != "1" {
		t.Skip("set TLAN_FRP_LIVE=1 to run the pinned FRP integration test")
	}
	if runtime.GOOS != "windows" {
		t.Skip("pinned live test is Windows-only")
	}
	frpsPath := filepath.Clean(filepath.Join("..", "..", ".tmp-runtime", "frps-v0.71.1.exe"))
	frpcPath := filepath.Clean(filepath.Join("..", "..", ".tmp-runtime", "frpc-v0.71.1.exe"))
	if _, err := os.Stat(frpsPath); err != nil {
		t.Skipf("frps binary unavailable: %v", err)
	}
	if _, err := os.Stat(frpcPath); err != nil {
		t.Skipf("frpc binary unavailable: %v", err)
	}

	remotePort := findFreeTCPPort(t, 30001, 30099)
	frpsPort := freeTCPPort(t)
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	go echoBackend(backend)
	httpBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "frp-http-live")
	}))
	defer httpBackend.Close()
	udpBackend, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer udpBackend.Close()
	go echoUDPBackend(udpBackend)

	store, err := NewStore(Options{
		StatePath:      filepath.Join(t.TempDir(), "frp-leases.json"),
		ServerID:       "frps-managed-1",
		CoreVersion:    "0.71.1",
		LeaseTTL:       time.Minute,
		AllowedPorts:   []PortRange{{Start: remotePort, End: remotePort}},
		AllowedDomains: []string{"frp.example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	lease, err := store.Issue("net-live", "dev-live", "frps-managed-1", []Rule{
		{ID: "rule-live", ProxyName: "tlan_live", Type: "tcp", RemotePort: remotePort, BindPort: backend.Addr().(*net.TCPAddr).Port},
		{ID: "rule-http-live", ProxyName: "tlan_live_http", Type: "http", CustomDomains: []string{"app.frp.example.com"}, BindPort: httpBackend.Listener.Addr().(*net.TCPAddr).Port},
		{ID: "rule-udp-live", ProxyName: "tlan_live_udp", Type: "udp", RemotePort: remotePort, BindPort: udpBackend.LocalAddr().(*net.UDPAddr).Port},
	})
	if err != nil {
		t.Fatal(err)
	}
	pluginServer := httptest.NewServer(NewPluginHandler(store))
	defer pluginServer.Close()
	pluginAddr := strings.TrimPrefix(pluginServer.URL, "http://")
	vhostPort := freeTCPPort(t)
	dir := t.TempDir()
	frpsConfig := filepath.Join(dir, "frps.toml")
	frpcConfig := filepath.Join(dir, "frpc.toml")
	if err := os.WriteFile(frpsConfig, []byte(fmt.Sprintf(`
bindAddr = "127.0.0.1"
bindPort = %d
proxyBindAddr = "127.0.0.1"
transport.tls.force = false
transport.heartbeatTimeout = 8
auth.method = "token"
auth.token = "outer-token"
allowPorts = [{ start = %d, end = %d }]
vhostHTTPPort = %d
log.to = "console"
log.level = "info"
log.disablePrintColor = true

[[httpPlugins]]
name = "tlan-auth"
addr = "%s"
path = "/api/v1/frp/plugin"
ops = ["Login", "NewProxy", "Ping", "NewUserConn"]
`, frpsPort, remotePort, remotePort, vhostPort, pluginAddr)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(frpcConfig, []byte(fmt.Sprintf(`
serverAddr = "127.0.0.1"
serverPort = %d
user = "device-user"
loginFailExit = true
auth.method = "token"
auth.token = "outer-token"
metadatas.tlan_lease = "%s"
metadatas.tlan_capability = "%s"
metadatas.tlan_server = "frps-managed-1"
transport.heartbeatInterval = 2
transport.heartbeatTimeout = 6
log.to = "console"
log.level = "info"
log.disablePrintColor = true

[[proxies]]
name = "tlan_live"
type = "tcp"
localIP = "127.0.0.1"
localPort = %d
remotePort = %d

[[proxies]]
name = "tlan_live_http"
type = "http"
localIP = "127.0.0.1"
localPort = %d
customDomains = ["app.frp.example.com"]

[[proxies]]
name = "tlan_live_udp"
type = "udp"
localIP = "127.0.0.1"
localPort = %d
remotePort = %d
`, frpsPort, lease.LeaseID, lease.Credential, backend.Addr().(*net.TCPAddr).Port, remotePort, httpBackend.Listener.Addr().(*net.TCPAddr).Port, udpBackend.LocalAddr().(*net.UDPAddr).Port, remotePort)), 0o600); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command(frpsPath, "verify", "-c", frpsConfig).CombinedOutput(); err != nil {
		t.Fatalf("frps verify: %v\n%s", err, output)
	}
	frpsOutput := &lockedBuffer{}
	frps := startOwnedProcess(t, frpsPath, frpsConfig, frpsOutput)
	defer stopOwnedProcess(frps)
	waitTCP(t, fmt.Sprintf("127.0.0.1:%d", frpsPort), 10*time.Second, frpsOutput)

	frpcOutput := &lockedBuffer{}
	frpc := startOwnedProcess(t, frpcPath, frpcConfig, frpcOutput)
	defer stopOwnedProcess(frpc)
	connection := waitProxy(t, fmt.Sprintf("127.0.0.1:%d", remotePort), 15*time.Second, frpsOutput, frpcOutput)
	if connection == nil {
		t.Fatal("proxy did not become reachable")
	}
	defer connection.Close()
	if _, err := connection.Write([]byte("frp-live")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len("frp-live"))
	if _, err := io.ReadFull(connection, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "frp-live" {
		t.Fatalf("echo = %q", got)
	}
	waitHTTPProxy(t, vhostPort, "app.frp.example.com", 10*time.Second, frpsOutput, frpcOutput)
	waitUDPProxy(t, remotePort, 10*time.Second, frpsOutput, frpcOutput)

	// Revocation must terminate the existing control session and its TCP/UDP
	// data paths, not merely reject a future login. Official frpc v0.71.1
	// closes the control connection when the Ping hook rejects; FRPS closes it
	// after heartbeatTimeout if a non-compliant client keeps sending invalid
	// heartbeats.
	revokedAt := time.Now()
	if err := store.Revoke(lease.LeaseID, "net-live", "dev-live"); err != nil {
		t.Fatal(err)
	}
	_ = connection.SetReadDeadline(revokedAt.Add(10 * time.Second))
	_, readErr := connection.Read(make([]byte, 1))
	if readErr == nil {
		t.Fatal("existing TCP connection remained open after revocation")
	}
	if netErr, ok := readErr.(net.Error); ok && netErr.Timeout() {
		t.Fatalf("existing TCP connection was not closed within 10s: %v", readErr)
	}
	if elapsed := time.Since(revokedAt); elapsed > 10*time.Second {
		t.Fatalf("existing TCP connection closed after %s, want <=10s", elapsed)
	}

	waitProxyRejected(t, fmt.Sprintf("127.0.0.1:%d", remotePort), 10*time.Second)
	waitUDPRejected(t, remotePort, 10*time.Second)

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && !strings.Contains(frpcOutput.String(), "FRP_LEASE_REVOKED") {
		time.Sleep(100 * time.Millisecond)
	}
	if !strings.Contains(frpcOutput.String(), "FRP_LEASE_REVOKED") {
		t.Fatalf("revoked FRPC output did not contain revocation code:\n%s", frpcOutput.String())
	}
	stopOwnedProcess(frpc)
}

func waitProxyRejected(t *testing.T, address string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", address, 300*time.Millisecond)
		if err != nil {
			return
		}
		_ = conn.SetDeadline(time.Now().Add(500 * time.Millisecond))
		_, writeErr := conn.Write([]byte("revoked-live"))
		buffer := make([]byte, len("revoked-live"))
		_, readErr := conn.Read(buffer)
		_ = conn.Close()
		if writeErr != nil || readErr != nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("TCP proxy %s still forwarded after revocation", address)
}

func waitUDPRejected(t *testing.T, port int, timeout time.Duration) {
	t.Helper()
	address := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		connection, err := net.DialUDP("udp4", nil, address)
		if err != nil {
			return
		}
		_ = connection.SetDeadline(time.Now().Add(300 * time.Millisecond))
		_, writeErr := connection.Write([]byte("revoked-udp-live"))
		response := make([]byte, len("revoked-udp-live"))
		_, readErr := connection.Read(response)
		_ = connection.Close()
		if writeErr != nil || readErr != nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("UDP proxy %d still forwarded after revocation", port)
}

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}

func startOwnedProcess(t *testing.T, path, config string, output *lockedBuffer) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(path, "-c", config)
	cmd.Stdout = output
	cmd.Stderr = output
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	return cmd
}

func stopOwnedProcess(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Kill()
	_, _ = cmd.Process.Wait()
}

func waitTCP(t *testing.T, address string, timeout time.Duration, output *lockedBuffer) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", address, 250*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s\n%s", address, output.String())
}

func waitProxy(t *testing.T, address string, timeout time.Duration, frps, frpc *lockedBuffer) net.Conn {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", address, 500*time.Millisecond)
		if err == nil {
			return conn
		}
		time.Sleep(150 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for proxy %s\nfrps:\n%s\nfrpc:\n%s", address, frps.String(), frpc.String())
	return nil
}

func waitHTTPProxy(t *testing.T, port int, host string, timeout time.Duration, frps, frpc *lockedBuffer) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	client := &http.Client{Timeout: time.Second}
	for time.Now().Before(deadline) {
		request, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/", port), nil)
		request.Host = host
		response, err := client.Do(request)
		if err == nil {
			body, readErr := io.ReadAll(response.Body)
			response.Body.Close()
			if readErr == nil && response.StatusCode == http.StatusOK && string(body) == "frp-http-live" {
				return
			}
		}
		time.Sleep(150 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for HTTP proxy %s\nfrps:\n%s\nfrpc:\n%s", host, frps.String(), frpc.String())
}

func waitUDPProxy(t *testing.T, port int, timeout time.Duration, frps, frpc *lockedBuffer) {
	t.Helper()
	address := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		connection, err := net.DialUDP("udp4", nil, address)
		if err == nil {
			_ = connection.SetDeadline(time.Now().Add(300 * time.Millisecond))
			_, writeErr := connection.Write([]byte("frp-udp-live"))
			response := make([]byte, len("frp-udp-live"))
			_, readErr := connection.Read(response)
			connection.Close()
			if writeErr == nil && readErr == nil && string(response) == "frp-udp-live" {
				return
			}
		}
		time.Sleep(150 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for UDP proxy\nfrps:\n%s\nfrpc:\n%s", frps.String(), frpc.String())
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	return port
}

func findFreeTCPPort(t *testing.T, start, end int) int {
	t.Helper()
	for port := start; port <= end; port++ {
		listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err == nil {
			listener.Close()
			return port
		}
	}
	t.Fatalf("no free TCP port in %d-%d", start, end)
	return 0
}

func echoBackend(listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		go func(conn net.Conn) {
			defer conn.Close()
			_, _ = io.Copy(conn, conn)
		}(conn)
	}
}

func echoUDPBackend(connection *net.UDPConn) {
	buffer := make([]byte, 64*1024)
	for {
		n, address, err := connection.ReadFromUDP(buffer)
		if err != nil {
			return
		}
		_, _ = connection.WriteToUDP(buffer[:n], address)
	}
}
