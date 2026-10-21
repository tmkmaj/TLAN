package targetgateway

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const testTargetIP = "10.240.0.2"

func testTarget(port uint16) Target {
	return Target{
		NetworkID: "test-network",
		IPv4:      netip.MustParseAddr(testTargetIP),
		Port:      port,
		DeviceID:  "device-b",
	}
}

type leaseFixture struct {
	mu             sync.Mutex
	generation     uint64
	done           chan struct{}
	closed         bool
	err            error
	calls          int
	lastTarget     Target
	lastGeneration uint64
}

func newLeaseFixture() *leaseFixture {
	return &leaseFixture{generation: 1, done: make(chan struct{})}
}

func (f *leaseFixture) Validate(ctx context.Context, target Target) (Lease, error) {
	if err := ctx.Err(); err != nil {
		return Lease{}, err
	}
	f.mu.Lock()
	f.calls++
	f.lastTarget = target
	f.lastGeneration = f.generation
	generation := f.generation
	done := f.done
	closed := f.closed
	err := f.err
	f.mu.Unlock()
	if err != nil {
		return Lease{}, err
	}
	if closed {
		return Lease{}, ErrLeaseRevoked
	}
	select {
	case <-done:
		return Lease{}, ErrLeaseRevoked
	default:
	}
	return Lease{Generation: generation, Done: done}, nil
}

func (f *leaseFixture) rotate() uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.closed {
		close(f.done)
	}
	f.generation++
	f.done = make(chan struct{})
	f.closed = false
	f.err = nil
	return f.generation
}

func (f *leaseFixture) bumpGeneration() uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.generation++
	return f.generation
}

func (f *leaseFixture) revoke() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.closed {
		close(f.done)
		f.closed = true
	}
}

func (f *leaseFixture) setError(err error) {
	f.mu.Lock()
	f.err = err
	f.mu.Unlock()
}

func (f *leaseFixture) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func (f *leaseFixture) target() Target {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastTarget
}

type testDialer struct {
	tcpAddr string
	udpAddr string

	tcpCalls atomic.Int32
	udpCalls atomic.Int32

	mu             sync.Mutex
	lastTarget     Target
	lastGeneration uint64
	tcpErr         error
	udpErr         error
}

func (d *testDialer) DialTCP(ctx context.Context, target Target, generation uint64) (net.Conn, error) {
	d.tcpCalls.Add(1)
	d.record(target, generation)
	d.mu.Lock()
	err := d.tcpErr
	d.mu.Unlock()
	if err != nil {
		return nil, err
	}
	var dialer net.Dialer
	return dialer.DialContext(ctx, "tcp4", d.tcpAddr)
}

func (d *testDialer) DialUDP(ctx context.Context, target Target, generation uint64) (net.Conn, error) {
	d.udpCalls.Add(1)
	d.record(target, generation)
	d.mu.Lock()
	err := d.udpErr
	d.mu.Unlock()
	if err != nil {
		return nil, err
	}
	var dialer net.Dialer
	return dialer.DialContext(ctx, "udp4", d.udpAddr)
}

func (d *testDialer) record(target Target, generation uint64) {
	d.mu.Lock()
	d.lastTarget = target
	d.lastGeneration = generation
	d.mu.Unlock()
}

func (d *testDialer) last() (Target, uint64) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.lastTarget, d.lastGeneration
}

func (d *testDialer) setTCPError(err error) {
	d.mu.Lock()
	d.tcpErr = err
	d.mu.Unlock()
}

func startTCPEcho(t *testing.T) string {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	conns := make(map[*net.TCPConn]struct{})
	t.Cleanup(func() {
		_ = listener.Close()
		mu.Lock()
		for conn := range conns {
			_ = conn.Close()
		}
		mu.Unlock()
	})
	go func() {
		for {
			conn, err := listener.AcceptTCP()
			if err != nil {
				return
			}
			mu.Lock()
			conns[conn] = struct{}{}
			mu.Unlock()
			go func() {
				_, _ = io.Copy(conn, conn)
				_ = conn.CloseWrite()
				_ = conn.Close()
				mu.Lock()
				delete(conns, conn)
				mu.Unlock()
			}()
		}
	}()
	return listener.Addr().String()
}

func startUDPEcho(t *testing.T) string {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	go func() {
		buffer := make([]byte, 65535)
		for {
			n, addr, err := conn.ReadFromUDPAddrPort(buffer)
			if err != nil {
				return
			}
			_, _ = conn.WriteToUDPAddrPort(buffer[:n], addr)
		}
	}()
	return conn.LocalAddr().String()
}

func mustTCPClient(t *testing.T, address string) *net.TCPConn {
	t.Helper()
	addr, err := net.ResolveTCPAddr("tcp4", address)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.DialTCP("tcp4", nil, addr)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func mustUDPClient(t *testing.T, address string) *net.UDPConn {
	t.Helper()
	addr, err := net.ResolveUDPAddr("udp4", address)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.DialUDP("udp4", nil, addr)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func waitFor(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition was not met before timeout")
}

func expectReadFailure(t *testing.T, conn net.Conn) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buffer := make([]byte, 1)
	_, err := conn.Read(buffer)
	if err == nil {
		t.Fatal("expected read to fail after lease/session close")
	}
}

func expectUDPTimeout(t *testing.T, conn *net.UDPConn) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	buffer := make([]byte, 32)
	_, err := conn.Read(buffer)
	if err == nil {
		t.Fatal("expected UDP read timeout")
	}
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("expected timeout, got %v", err)
	}
}
