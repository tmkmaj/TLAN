package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/private-radminlan/lanmesh/internal/egress"
)

type fakeTunnelStream struct {
	mu         sync.Mutex
	writes     bytes.Buffer
	readDone   bool
	closeWrite bool
	closed     bool
}

func (s *fakeTunnelStream) Read(p []byte) (int, error) {
	if s.readDone {
		return 0, io.EOF
	}
	s.mu.Lock()
	s.readDone = true
	s.mu.Unlock()
	return 0, io.EOF
}

func (s *fakeTunnelStream) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.writes.Write(p)
}

func (s *fakeTunnelStream) CloseWrite() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closeWrite = true
	return nil
}

func (s *fakeTunnelStream) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return nil
}

func (s *fakeTunnelStream) bytes() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.writes.Bytes()...)
}

type fakeTunnel struct {
	mu          sync.Mutex
	stream      *fakeTunnelStream
	openErr     error
	opened      []uint32
	datagrams   [][]byte
	receiveData []byte
	receiveErr  error
}

func (t *fakeTunnel) OpenStream(id uint32) (tunnelStream, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.opened = append(t.opened, id)
	if t.openErr != nil {
		return nil, t.openErr
	}
	if t.stream == nil {
		t.stream = &fakeTunnelStream{}
	}
	return t.stream, nil
}

func (t *fakeTunnel) SendDatagram(data []byte) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.datagrams = append(t.datagrams, append([]byte(nil), data...))
	return nil
}

func (t *fakeTunnel) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	if t.receiveErr != nil {
		return nil, t.receiveErr
	}
	return append([]byte(nil), t.receiveData...), nil
}

func (t *fakeTunnel) Snapshot() egress.EgressSnapshot {
	return egress.EgressSnapshot{State: egress.StateRunning}
}

type loopbackConn struct {
	net.Conn
	remote net.Addr
	local  net.Addr
}

func (c *loopbackConn) RemoteAddr() net.Addr { return c.remote }
func (c *loopbackConn) LocalAddr() net.Addr  { return c.local }

func testProxyConfig() proxyConfig {
	return proxyConfig{
		ListenAddr:     "127.0.0.1:1080",
		ServerAddr:     "gateway.example.com:443",
		ServerName:     "gateway.example.com",
		CAPath:         "ca.pem",
		ProfileID:      "profile-test",
		RuleID:         "rule-test",
		DeviceID:       "device-test",
		LeaseID:        "lease-test",
		PolicyVersion:  1,
		CapabilityFile: "capability.txt",
		Capability:     "capability-test",
		MaxConnections: 8,
	}
}

func newPipeProxy(t *testing.T, p *proxy) (net.Conn, <-chan error) {
	t.Helper()
	client, server := net.Pipe()
	wrapped := &loopbackConn{
		Conn:   server,
		remote: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 31000},
		local:  &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1080},
	}
	done := make(chan error, 1)
	go func() {
		err := p.handleConn(context.Background(), wrapped)
		_ = server.Close()
		done <- err
	}()
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	return client, done
}

func readN(t *testing.T, conn net.Conn, n int) []byte {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	data := make([]byte, n)
	if _, err := io.ReadFull(conn, data); err != nil {
		t.Fatalf("read %d bytes: %v", n, err)
	}
	return data
}

func writeAll(t *testing.T, conn net.Conn, data []byte) {
	t.Helper()
	_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write(data); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func TestSOCKS5UsernamePasswordAuthentication(t *testing.T) {
	fake := &fakeTunnel{}
	cfg := testProxyConfig()
	cfg.Username = "alice"
	cfg.Password = "correct horse battery staple"
	p, err := newProxy(cfg, fake)
	if err != nil {
		t.Fatal(err)
	}
	p.markReady()
	client, done := newPipeProxy(t, p)

	writeAll(t, client, []byte{5, 2, 0, 2})
	if got := readN(t, client, 2); !bytes.Equal(got, []byte{5, 2}) {
		t.Fatalf("method selection = %x, want 0502", got)
	}
	auth := append([]byte{1, byte(len("alice"))}, []byte("alice")...)
	auth = append(auth, byte(len(cfg.Password)))
	auth = append(auth, []byte(cfg.Password)...)
	writeAll(t, client, auth)
	if got := readN(t, client, 2); !bytes.Equal(got, []byte{1, 0}) {
		t.Fatalf("auth reply = %x, want 0100", got)
	}
	writeAll(t, client, []byte{5, 2, 0, 1, 127, 0, 0, 1, 0, 80})
	if got := readN(t, client, 10); got[1] != 7 {
		t.Fatalf("BIND reply code = %d, want 7 (reply %x)", got[1], got)
	}
	if err := <-done; err == nil {
		t.Fatal("expected command-not-supported error")
	}
}

func TestSOCKS5RejectsBadPassword(t *testing.T) {
	fake := &fakeTunnel{}
	cfg := testProxyConfig()
	cfg.Username = "alice"
	cfg.Password = "secret"
	p, err := newProxy(cfg, fake)
	if err != nil {
		t.Fatal(err)
	}
	p.markReady()
	client, done := newPipeProxy(t, p)

	writeAll(t, client, []byte{5, 1, 2})
	if got := readN(t, client, 2); !bytes.Equal(got, []byte{5, 2}) {
		t.Fatalf("method selection = %x, want 0502", got)
	}
	writeAll(t, client, []byte{1, 5, 'a', 'l', 'i', 'c', 'e', 5, 'w', 'r', 'o', 'n', 'g'})
	if got := readN(t, client, 2); !bytes.Equal(got, []byte{1, 1}) {
		t.Fatalf("auth reply = %x, want 0101", got)
	}
	if err := <-done; !errors.Is(err, errSocksAuthFailed) {
		t.Fatalf("handle error = %v, want errSocksAuthFailed", err)
	}
}

func TestConnectWritesTargetPreamble(t *testing.T) {
	fake := &fakeTunnel{}
	cfg := testProxyConfig()
	p, err := newProxy(cfg, fake)
	if err != nil {
		t.Fatal(err)
	}
	p.markReady()
	client, done := newPipeProxy(t, p)

	writeAll(t, client, []byte{5, 1, 0})
	if got := readN(t, client, 2); !bytes.Equal(got, []byte{5, 0}) {
		t.Fatalf("method selection = %x, want 0500", got)
	}
	host := []byte("example.com")
	req := append([]byte{5, 1, 0, 3, byte(len(host))}, host...)
	req = append(req, 0x01, 0xbb)
	writeAll(t, client, req)
	reply := readN(t, client, 10)
	if reply[1] != 0 {
		t.Fatalf("CONNECT reply = %x, want success", reply)
	}
	_ = client.Close()
	if err := <-done; err != nil {
		t.Fatalf("handle CONNECT: %v", err)
	}

	fake.mu.Lock()
	stream := fake.stream
	opened := append([]uint32(nil), fake.opened...)
	fake.mu.Unlock()
	if len(opened) != 1 || opened[0] == 0 {
		t.Fatalf("opened stream IDs = %v, want one nonzero ID", opened)
	}
	data := stream.bytes()
	target, err := egress.DecodeTargetHeader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("decode target preamble: %v (bytes %x)", err, data)
	}
	if target.Host != "example.com" || target.Port != 443 || target.Protocol != egress.ProtocolTCP {
		t.Fatalf("target = %+v, want tcp example.com:443", target)
	}
}

func TestBindIsRejectedWithoutOpeningStream(t *testing.T) {
	fake := &fakeTunnel{}
	cfg := testProxyConfig()
	p, err := newProxy(cfg, fake)
	if err != nil {
		t.Fatal(err)
	}
	p.markReady()
	client, done := newPipeProxy(t, p)

	writeAll(t, client, []byte{5, 1, 0})
	_ = readN(t, client, 2)
	writeAll(t, client, []byte{5, 2, 0, 1, 127, 0, 0, 1, 0, 80})
	reply := readN(t, client, 10)
	if reply[1] != 7 {
		t.Fatalf("BIND reply code = %d, want 7", reply[1])
	}
	if err := <-done; err == nil {
		t.Fatal("expected BIND rejection error")
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.opened) != 0 {
		t.Fatalf("BIND opened streams: %v", fake.opened)
	}
}

func TestNotReadyFailsClosed(t *testing.T) {
	fake := &fakeTunnel{}
	cfg := testProxyConfig()
	p, err := newProxy(cfg, fake)
	if err != nil {
		t.Fatal(err)
	}
	client, done := newPipeProxy(t, p)
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	if n, readErr := client.Read(buf); n != 0 || readErr == nil {
		t.Fatalf("not-ready connection read = (%d, %v), want closed connection", n, readErr)
	}
	if err := <-done; !errors.Is(err, errProxyNotReady) {
		t.Fatalf("handle error = %v, want errProxyNotReady", err)
	}
}

func TestNonLoopbackListenerRejected(t *testing.T) {
	for _, address := range []string{"0.0.0.0:1080", ":1080", "192.0.2.1:1080", "[::]:1080"} {
		if err := validateLoopbackListen(address); err == nil {
			t.Errorf("validateLoopbackListen(%q) accepted non-loopback address", address)
		}
	}
	for _, address := range []string{"127.0.0.1:1080", "[::1]:1080"} {
		if err := validateLoopbackListen(address); err != nil {
			t.Errorf("validateLoopbackListen(%q): %v", address, err)
		}
	}
}

func TestSOCKS5UDPAddressTypesAndTunnelEnvelope(t *testing.T) {
	tests := []struct {
		name   string
		packet []byte
		host   string
	}{
		{name: "ipv4", packet: []byte{0, 0, 0, 1, 203, 0, 113, 9, 0x01, 0xbb, 'a'}, host: "203.0.113.9"},
		{name: "domain", packet: append([]byte{0, 0, 0, 3, 11}, append([]byte("example.com"), 0x00, 0x35, 'a')...), host: "example.com"},
		{name: "ipv6", packet: append([]byte{0, 0, 0, 4}, append(net.ParseIP("2001:db8::1").To16(), 0x00, 0x35, 'a')...), host: "2001:db8::1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target, payload, err := parseSOCKS5UDPPacket(tt.packet)
			if err != nil {
				t.Fatal(err)
			}
			if target.Host != tt.host || target.Port == 0 || target.Protocol != egress.ProtocolUDP {
				t.Fatalf("target = %+v, want UDP host %s", target, tt.host)
			}
			if !bytes.Equal(payload, []byte{'a'}) {
				t.Fatalf("payload = %q, want a", payload)
			}
			envelope, err := egress.EncodeDatagram(target, payload)
			if err != nil {
				t.Fatal(err)
			}
			decodedTarget, decodedPayload, err := egress.DecodeDatagram(envelope)
			if err != nil {
				t.Fatal(err)
			}
			if decodedTarget.Address() != target.Address() || !bytes.Equal(decodedPayload, payload) {
				t.Fatalf("decoded envelope = (%+v, %q), want (%+v, %q)", decodedTarget, decodedPayload, target, payload)
			}
		})
	}
}

func TestSOCKS5UDPRejectsFragmentsAndTruncation(t *testing.T) {
	for _, packet := range [][]byte{
		{0, 0, 1, 1, 127, 0, 0, 1, 0, 53, 'x'},
		{0, 0, 0},
		{0, 0, 0, 3, 0},
		{0, 0, 0, 1, 127, 0, 0, 1, 0, 53},
	} {
		if _, _, err := parseSOCKS5UDPPacket(packet); err == nil {
			t.Errorf("parseSOCKS5UDPPacket(%x) succeeded, want error", packet)
		}
	}
}

func TestNonLoopbackPeerIsRejected(t *testing.T) {
	fake := &fakeTunnel{}
	p, err := newProxy(testProxyConfig(), fake)
	if err != nil {
		t.Fatal(err)
	}
	p.markReady()
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	conn := &loopbackConn{
		Conn:   server,
		remote: &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 31000},
		local:  &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1080},
	}
	if err := p.handleConn(context.Background(), conn); !errors.Is(err, errNonLoopbackPeer) {
		t.Fatalf("handleConn error = %v, want errNonLoopbackPeer", err)
	}
}
