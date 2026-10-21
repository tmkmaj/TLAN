//go:build windows

package frp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestLiveFRPTCPUDP(t *testing.T) {
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
	vhostHTTPPort := freePort(t)
	vhostHTTPSPort := freePort(t)
	tokenPath := filepath.Join(work, "token")
	if err := os.WriteFile(tokenPath, []byte("live-frp-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	frpsConfig := filepath.Join(work, "frps.toml")
	frpsTOML := fmt.Sprintf(`bindAddr = "127.0.0.1"
bindPort = %d
proxyBindAddr = "127.0.0.1"
vhostHTTPPort = %d
vhostHTTPSPort = %d
auth.method = "token"
auth.tokenSource.type = "file"
auth.tokenSource.file.path = %s
transport.tls.force = true
transport.tls.certFile = %s
transport.tls.keyFile = %s
allowPorts = [{ start = %d, end = %d }]
maxPortsPerClient = 16
log.to = "console"
log.level = "info"
`, controlPort, vhostHTTPPort, vhostHTTPSPort, tomlQuote(tokenPath), tomlQuote(certPath), tomlQuote(keyPath), remotePort, remotePort)
	if err := os.WriteFile(frpsConfig, []byte(frpsTOML), 0o600); err != nil {
		t.Fatal(err)
	}
	frps := exec.Command(frpsPath, "verify", "-c", frpsConfig, "--strict_config=true")
	if out, err := frps.CombinedOutput(); err != nil {
		t.Fatalf("frps verify: %v\\n%s", err, out)
	}
	frps = exec.Command(frpsPath, "-c", frpsConfig)
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

	tcpPort := startTCPEcho(t)
	udpPort := startUDPEcho(t)
	httpPort := startHTTPEcho(t)
	httpsPort := startHTTPSEcho(t, certPath, keyPath)
	visitorTCPPort := freePort(t)
	visitorUDPPort := freeUDPPort(t)
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
	cfg.Profile.Server.PublicHTTPSPort = vhostHTTPSPort
	profileID := DefaultProfileID
	deviceID := "live-test-device"
	cfg.Profile.ID = profileID
	cfg.Profile.Rules = []Rule{
		{ID: "rule-tcp", Name: "TCP echo", Type: "tcp", Enabled: true, Target: Target{Kind: "loopback", Host: "127.0.0.1", Port: tcpPort}, Exposure: Exposure{RemotePort: remotePort}},
		{ID: "rule-udp", Name: "UDP echo", Type: "udp", Enabled: true, Target: Target{Kind: "loopback", Host: "127.0.0.1", Port: udpPort}, Exposure: Exposure{RemotePort: remotePort}},
		{ID: "rule-http", Name: "HTTP echo", Type: "http", Enabled: true, Target: Target{Kind: "loopback", Host: "127.0.0.1", Port: httpPort}, Exposure: Exposure{CustomDomains: []string{"app.test"}}},
		{ID: "rule-https", Name: "HTTPS echo", Type: "https", Enabled: true, Target: Target{Kind: "loopback", Host: "127.0.0.1", Port: httpsPort}, Exposure: Exposure{CustomDomains: []string{"secure.test"}}},
		{ID: "rule-stcp", Name: "STCP echo", Type: "stcp", Enabled: true, SecretRef: "private-secret", Target: Target{Kind: "loopback", Host: "127.0.0.1", Port: tcpPort}},
		{ID: "rule-sudp", Name: "SUDP echo", Type: "sudp", Enabled: true, SecretRef: "private-secret", Target: Target{Kind: "loopback", Host: "127.0.0.1", Port: udpPort}},
	}
	cfg.Profile.Visitors = []Visitor{
		{ID: "visitor-stcp", Name: "STCP access", Type: "stcp", Enabled: true, ServerName: ProxyName(deviceID, profileID, "rule-stcp"), SecretRef: "private-secret", BindAddr: "127.0.0.1", BindPort: visitorTCPPort},
		{ID: "visitor-sudp", Name: "SUDP access", Type: "sudp", Enabled: true, ServerName: ProxyName(deviceID, profileID, "rule-sudp"), SecretRef: "private-secret", BindAddr: "127.0.0.1", BindPort: visitorUDPPort},
	}
	saved, err := store.SaveWithSecrets(cfg, "live-frp-token", map[string]string{"private-secret": "private-key"})
	if err != nil {
		t.Fatal(err)
	}
	cfg = saved
	manager, err := NewManager(Options{Store: store, CorePath: frpcPath, DeviceID: deviceID})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err = manager.Start(ctx); err != nil {
		t.Fatalf("manager start: %v\nlogs:\n%s", err, manager.logs.text())
	}
	defer manager.Close(context.Background())
	if manager.instance == nil || manager.instance.egressProxy == nil {
		t.Fatal("live FRPC runtime did not start the egress guard proxy")
	}
	connects, dials := manager.instance.egressProxy.Stats()
	if connects == 0 || dials == 0 {
		t.Fatalf("FRPC bypassed the egress guard proxy: connects=%d dials=%d", connects, dials)
	}

	conn, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(remotePort)), 4*time.Second)
	if err != nil {
		t.Fatalf("TCP public connect: %v", err)
	}
	defer conn.Close()
	if _, err = conn.Write([]byte("tcp-live")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len("tcp-live"))
	if _, err = io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "tcp-live" {
		t.Fatalf("TCP echo = %q", got)
	}

	udpConn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: remotePort})
	if err != nil {
		t.Fatal(err)
	}
	defer udpConn.Close()
	_ = udpConn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err = udpConn.Write([]byte("udp-live")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 32)
	n, err := udpConn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "udp-live" {
		t.Fatalf("UDP echo = %q", buf[:n])
	}

	waitPort(t, visitorTCPPort)
	privateConn, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(visitorTCPPort)), 5*time.Second)
	if err != nil {
		t.Fatalf("STCP visitor connect: %v", err)
	}
	defer privateConn.Close()
	if _, err = privateConn.Write([]byte("stcp-live")); err != nil {
		t.Fatal(err)
	}
	privateGot := make([]byte, len("stcp-live"))
	if _, err = io.ReadFull(privateConn, privateGot); err != nil {
		t.Fatal(err)
	}
	if string(privateGot) != "stcp-live" {
		t.Fatalf("STCP echo = %q", privateGot)
	}

	privateUDP, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: visitorUDPPort})
	if err != nil {
		t.Fatal(err)
	}
	defer privateUDP.Close()
	_ = privateUDP.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err = privateUDP.Write([]byte("sudp-live")); err != nil {
		t.Fatal(err)
	}
	privateBuf := make([]byte, 32)
	n, err = privateUDP.Read(privateBuf)
	if err != nil {
		t.Fatal(err)
	}
	if string(privateBuf[:n]) != "sudp-live" {
		t.Fatalf("SUDP echo = %q", privateBuf[:n])
	}
	httpsCA, err := os.ReadFile(caPath)
	if err != nil {
		t.Fatal(err)
	}
	httpsPool := x509.NewCertPool()
	if !httpsPool.AppendCertsFromPEM(httpsCA) {
		t.Fatal("append HTTPS CA")
	}
	httpsReq, err := http.NewRequest(http.MethodGet, fmt.Sprintf("https://127.0.0.1:%d/", vhostHTTPSPort), nil)
	if err != nil {
		t.Fatal(err)
	}
	httpsReq.Host = "secure.test"
	httpsClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: httpsPool, ServerName: "secure.test"}}, Timeout: 5 * time.Second}
	httpsResp, err := httpsClient.Do(httpsReq)
	if err != nil {
		t.Fatalf("HTTPS vhost request: %v", err)
	}
	httpsBody, _ := io.ReadAll(httpsResp.Body)
	_ = httpsResp.Body.Close()
	if httpsResp.StatusCode != http.StatusOK || string(httpsBody) != "https-live" {
		t.Fatalf("HTTPS vhost response = %d %q", httpsResp.StatusCode, httpsBody)
	}

	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/", vhostHTTPPort), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "app.test"
	httpClient := &http.Client{Timeout: 5 * time.Second}
	resp, err := httpClient.Do(req)
	if err != nil {
		t.Fatalf("HTTP vhost request: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "http-live" {
		t.Fatalf("HTTP vhost response = %d %q", resp.StatusCode, body)
	}

	snapshot := manager.Snapshot(context.Background())
	if !snapshot.Running || !snapshot.Authenticated {
		t.Fatalf("snapshot not running/authenticated: %+v", snapshot)
	}
	if len(snapshot.Rules) != 6 || snapshot.Rules[0].State != "已注册" || snapshot.Rules[1].State != "已注册" || snapshot.Rules[2].State != "已注册" || snapshot.Rules[2].RemoteAddr != fmt.Sprintf("http://app.test:%d", vhostHTTPPort) || snapshot.Rules[3].State != "已注册" || snapshot.Rules[3].RemoteAddr != fmt.Sprintf("https://secure.test:%d", vhostHTTPSPort) || snapshot.Rules[4].State != "已注册" || snapshot.Rules[5].State != "已注册" || len(snapshot.Visitors) != 2 || snapshot.Visitors[0].State != "监听中" || snapshot.Visitors[1].State != "监听中" {
		t.Fatalf("unexpected rule statuses: %+v; visitors: %+v", snapshot.Rules, snapshot.Visitors)
	}
	childPID := manager.instance.process.PID
	if err = manager.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if handle, openErr := windows.OpenProcess(windows.SYNCHRONIZE, false, childPID); openErr == nil {
		event, waitErr := windows.WaitForSingleObject(handle, 1000)
		_ = windows.CloseHandle(handle)
		if waitErr == nil && event == uint32(windows.WAIT_TIMEOUT) {
			t.Fatalf("managed frpc process %d survived stop", childPID)
		}
	}
	snapshot = manager.Snapshot(context.Background())
	if snapshot.Running {
		t.Fatal("manager still running after stop")
	}
	assertRuntimeClean(t, store)

	applied, err := manager.Apply(context.Background(), cfg, "live-frp-token")
	if err != nil {
		t.Fatalf("verify-only apply: %v", err)
	}
	cfg = applied
	assertRuntimeClean(t, store)

	badCA := CloneConfig(cfg)
	badCA.Profile.Server.TrustedCAPath = testCA(t)
	badCA, err = store.Save(badCA, "live-frp-token")
	if err != nil {
		t.Fatal(err)
	}
	badCAManager, err := NewManager(Options{Store: store, CorePath: frpcPath, DeviceID: "live-test-device"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel = context.WithTimeout(context.Background(), 20*time.Second)
	err = badCAManager.Start(ctx)
	cancel()
	if ErrorCode(err) != CodeTLSUntrusted {
		t.Fatalf("wrong CA error = %v, code = %s\\nlogs:\\n%s", err, ErrorCode(err), badCAManager.logs.text())
	}
	_ = badCAManager.Close(context.Background())
	assertRuntimeClean(t, store)

	wrongToken := CloneConfig(badCA)
	wrongToken.Profile.Server.TrustedCAPath = caPath
	wrongToken, err = store.Save(wrongToken, "wrong-token")
	if err != nil {
		t.Fatal(err)
	}
	badTokenManager, err := NewManager(Options{Store: store, CorePath: frpcPath, DeviceID: "live-test-device"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel = context.WithTimeout(context.Background(), 20*time.Second)
	err = badTokenManager.Start(ctx)
	cancel()
	if ErrorCode(err) != CodeAuthRejected {
		t.Fatalf("wrong token error = %v, code = %s", err, ErrorCode(err))
	}
	_ = badTokenManager.Close(context.Background())
	assertRuntimeClean(t, store)
}

func assertRuntimeClean(t *testing.T, store *Store) {
	t.Helper()
	entries, err := os.ReadDir(store.RuntimeRoot())
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("FRP runtime directory not clean: %v", entries)
	}
}

func makeServerTLS(t *testing.T, dir string) (string, string, string) {
	t.Helper()
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(100), Subject: pkix.Name{CommonName: "TLAN live test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
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
		SerialNumber: big.NewInt(101), Subject: pkix.Name{CommonName: "localhost"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		DNSNames: []string{"localhost", "secure.test"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caTemplate, &serverKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caPath := filepath.Join(dir, "ca.pem")
	certPath := filepath.Join(dir, "server.crt")
	keyPath := filepath.Join(dir, "server.key")
	if err = os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(serverKey)}), 0o600); err != nil {
		t.Fatal(err)
	}
	return caPath, certPath, keyPath
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func waitPort(t *testing.T, port int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("port %d did not open", port)
}

func startTCPEcho(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	return l.Addr().(*net.TCPAddr).Port
}

func startUDPEcho(t *testing.T) int {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = conn.WriteToUDP(buf[:n], addr)
		}
	}()
	return conn.LocalAddr().(*net.UDPAddr).Port
}
func startHTTPSEcho(t *testing.T, certPath, keyPath string) int {
	t.Helper()
	certificate, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("https-live"))
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}}
	server.StartTLS()
	t.Cleanup(server.Close)
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, portText, err := net.SplitHostPort(parsed.Host)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	return port
}

func startHTTPEcho(t *testing.T) int {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("http-live"))
	}))
	t.Cleanup(server.Close)
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, portText, err := net.SplitHostPort(parsed.Host)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	return port
}

func freeUDPPort(t *testing.T) int {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).Port
}
