package targetgateway

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func startTCPGateway(t *testing.T, dialer Dialer, lease LeaseValidator, backendPort uint16) *Gateway {
	t.Helper()
	gateway, err := Start(context.Background(), Config{
		Protocol:          ProtocolTCP,
		ListenPort:        0,
		Target:            testTarget(backendPort),
		Lease:             lease,
		Dialer:            dialer,
		LeasePollInterval: 20 * time.Millisecond,
		DialTimeout:       time.Second,
		IdleTimeout:       2 * time.Second,
		WriteTimeout:      time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = gateway.Close() })
	if gateway.Addr().Addr() != netip.MustParseAddr(LoopbackAddress) {
		t.Fatalf("gateway listened on %s", gateway.Addr())
	}
	return gateway
}

func TestTCPHalfCloseAndLeaseChecks(t *testing.T) {
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	serverDone := make(chan string, 1)
	go func() {
		conn, err := listener.AcceptTCP()
		if err != nil {
			serverDone <- ""
			return
		}
		defer conn.Close()
		data, _ := io.ReadAll(conn)
		_, _ = conn.Write([]byte("reply:" + string(data)))
		_ = conn.CloseWrite()
		serverDone <- string(data)
	}()

	lease := newLeaseFixture()
	dialer := &testDialer{tcpAddr: listener.Addr().String()}
	gateway := startTCPGateway(t, dialer, lease, 9000)
	client := mustTCPClient(t, gateway.Addr().String())

	if _, err := client.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	if err := client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	response, err := io.ReadAll(client)
	if err != nil {
		t.Fatal(err)
	}
	if string(response) != "reply:request" {
		t.Fatalf("response = %q", response)
	}
	select {
	case got := <-serverDone:
		if got != "request" {
			t.Fatalf("backend received %q", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("backend did not observe half-close")
	}
	if lease.callCount() < 2 {
		t.Fatalf("lease was checked only %d times", lease.callCount())
	}
	stats := gateway.Stats()
	if stats.BytesToTarget < uint64(len("request")) || stats.BytesFromTarget < uint64(len("reply:request")) {
		t.Fatalf("unexpected byte stats: %+v", stats)
	}
}

func TestTCPConcurrentClients(t *testing.T) {
	backend := startTCPEcho(t)
	lease := newLeaseFixture()
	dialer := &testDialer{tcpAddr: backend}
	gateway := startTCPGateway(t, dialer, lease, 9000)

	const clients = 16
	var wait sync.WaitGroup
	errors := make(chan error, clients)
	for i := 0; i < clients; i++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			conn, err := net.DialTimeout("tcp4", gateway.Addr().String(), 3*time.Second)
			if err != nil {
				errors <- err
				return
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			payload := []byte(fmt.Sprintf("client-%02d", index))
			if _, err := conn.Write(payload); err != nil {
				errors <- err
				return
			}
			response := make([]byte, len(payload))
			if _, err := io.ReadFull(conn, response); err != nil {
				errors <- err
				return
			}
			if string(response) != string(payload) {
				errors <- fmt.Errorf("client %d received %q", index, response)
			}
		}(i)
	}
	wait.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Error(err)
		}
	}
	if stats := gateway.Stats(); stats.TCPAccepted < clients {
		t.Fatalf("accepted %d clients, want at least %d", stats.TCPAccepted, clients)
	}
}

func TestTCPLeaseRevocationClosesExistingAndRejectsNew(t *testing.T) {
	backend := startTCPEcho(t)
	lease := newLeaseFixture()
	dialer := &testDialer{tcpAddr: backend}
	gateway := startTCPGateway(t, dialer, lease, 9000)
	client := mustTCPClient(t, gateway.Addr().String())

	if _, err := client.Write([]byte("before")); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, len("before"))
	if _, err := io.ReadFull(client, response); err != nil {
		t.Fatal(err)
	}
	callsBefore := dialer.tcpCalls.Load()
	lease.revoke()
	waitFor(t, 2*time.Second, func() bool { return gateway.Stats().TCPActive == 0 })
	expectReadFailure(t, client)

	rejected := mustTCPClient(t, gateway.Addr().String())
	_ = rejected.SetReadDeadline(time.Now().Add(2 * time.Second))
	buffer := make([]byte, 1)
	if _, err := rejected.Read(buffer); err == nil {
		t.Fatal("new connection was not rejected after revocation")
	}
	waitFor(t, time.Second, func() bool { return gateway.Stats().TCPRejected >= 1 })
	if got := dialer.tcpCalls.Load(); got != callsBefore {
		t.Fatalf("dialer called after revocation: before=%d after=%d", callsBefore, got)
	}
	if gateway.Stats().LeaseRejections == 0 {
		t.Fatal("lease rejection was not counted")
	}
}

func TestTCPGenerationChangeClosesOldAndAllowsNewLease(t *testing.T) {
	backend := startTCPEcho(t)
	lease := newLeaseFixture()
	dialer := &testDialer{tcpAddr: backend}
	gateway := startTCPGateway(t, dialer, lease, 9000)
	oldClient := mustTCPClient(t, gateway.Addr().String())

	if _, err := oldClient.Write([]byte("old")); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 3)
	if _, err := io.ReadFull(oldClient, response); err != nil {
		t.Fatal(err)
	}
	generation := lease.rotate()
	waitFor(t, 2*time.Second, func() bool { return gateway.Stats().TCPActive == 0 })
	expectReadFailure(t, oldClient)

	newClient := mustTCPClient(t, gateway.Addr().String())
	if _, err := newClient.Write([]byte("new")); err != nil {
		t.Fatal(err)
	}
	newResponse := make([]byte, 3)
	if _, err := io.ReadFull(newClient, newResponse); err != nil {
		t.Fatal(err)
	}
	if string(newResponse) != "new" {
		t.Fatalf("new connection response = %q", newResponse)
	}
	_, gotGeneration := dialer.last()
	if gotGeneration != generation {
		t.Fatalf("dialer generation = %d, want %d", gotGeneration, generation)
	}
}

func TestTCPUnidirectionalTrafficDoesNotTriggerIdleTimeout(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		for i := 0; i < 10; i++ {
			_, _ = conn.Write([]byte("x"))
			time.Sleep(60 * time.Millisecond)
		}
	}()
	lease := newLeaseFixture()
	gateway, err := Start(context.Background(), Config{
		Protocol: ProtocolTCP, Target: testTarget(9000), Lease: lease,
		Dialer: &testDialer{tcpAddr: listener.Addr().String()}, IdleTimeout: 250 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer gateway.Close()
	client := mustTCPClient(t, gateway.Addr().String())
	defer client.Close()
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	buffer := make([]byte, 8)
	if _, err := io.ReadFull(client, buffer); err != nil {
		t.Fatalf("unidirectional stream was cut by idle timeout: %v", err)
	}
}

func TestTCPGenerationChangeSignalsDependencyInvalidation(t *testing.T) {
	backend := startTCPEcho(t)
	lease := newLeaseFixture()
	gateway := startTCPGateway(t, &testDialer{tcpAddr: backend}, lease, 9000)
	lease.bumpGeneration()
	waitFor(t, 2*time.Second, func() bool {
		select {
		case <-gateway.LeaseInvalid():
			return true
		default:
			return false
		}
	})
	if err := gateway.LeaseErr(); !errors.Is(err, ErrLeaseChanged) {
		t.Fatalf("lease invalidation error = %v", err)
	}
}

func TestTCPDialFailureDoesNotPublishConnection(t *testing.T) {
	lease := newLeaseFixture()
	dialer := &testDialer{tcpAddr: "127.0.0.1:1", tcpErr: fmt.Errorf("mesh route unavailable")}
	gateway := startTCPGateway(t, dialer, lease, 9000)
	client := mustTCPClient(t, gateway.Addr().String())
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	buffer := make([]byte, 1)
	if _, err := client.Read(buffer); err == nil {
		t.Fatal("connection survived backend dial failure")
	}
	waitFor(t, time.Second, func() bool { return gateway.Stats().DialFailures == 1 })
}

func TestTCPContextCancellationClosesListenerAndConnections(t *testing.T) {
	backend := startTCPEcho(t)
	lease := newLeaseFixture()
	dialer := &testDialer{tcpAddr: backend}
	ctx, cancel := context.WithCancel(context.Background())
	gateway, err := Start(ctx, Config{
		Protocol:          ProtocolTCP,
		Target:            testTarget(9000),
		Lease:             lease,
		Dialer:            dialer,
		LeasePollInterval: 20 * time.Millisecond,
		IdleTimeout:       2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = gateway.Close() })
	client := mustTCPClient(t, gateway.Addr().String())
	if _, err := client.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 1)
	if _, err := io.ReadFull(client, response); err != nil {
		t.Fatal(err)
	}

	cancel()
	select {
	case <-gateway.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("gateway did not finish cancellation")
	}
	expectReadFailure(t, client)
	if conn, err := net.DialTimeout("tcp4", gateway.Addr().String(), 200*time.Millisecond); err == nil {
		_ = conn.Close()
		t.Fatal("listener remained open after cancellation")
	}
	if active := gateway.Stats().TCPActive; active != 0 {
		t.Fatalf("active connections after cancellation: %d", active)
	}
}

func TestTCPGatewayUsesRequestedLoopbackPort(t *testing.T) {
	lease := newLeaseFixture()
	dialer := &testDialer{tcpAddr: "127.0.0.1:1"}
	first, err := Start(context.Background(), Config{
		Protocol: ProtocolTCP,
		Target:   testTarget(9000),
		Lease:    lease,
		Dialer:   dialer,
	})
	if err != nil {
		t.Fatal(err)
	}
	port := first.Addr().Port()
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}

	second, err := Start(context.Background(), Config{
		Protocol:   ProtocolTCP,
		ListenPort: port,
		Target:     testTarget(9000),
		Lease:      lease,
		Dialer:     dialer,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = second.Close() })
	want := netip.AddrPortFrom(netip.MustParseAddr(LoopbackAddress), port)
	if second.Addr() != want {
		t.Fatalf("listener = %s, want %s", second.Addr(), want)
	}
}

func TestTCPGenerationChangeWithoutDoneSignalClosesOldStream(t *testing.T) {
	backend := startTCPEcho(t)
	lease := newLeaseFixture()
	dialer := &testDialer{tcpAddr: backend}
	gateway := startTCPGateway(t, dialer, lease, 9000)
	oldClient := mustTCPClient(t, gateway.Addr().String())
	if _, err := oldClient.Write([]byte("old")); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 3)
	if _, err := io.ReadFull(oldClient, response); err != nil {
		t.Fatal(err)
	}

	generation := lease.bumpGeneration()
	waitFor(t, time.Second, func() bool { return gateway.Stats().TCPActive == 0 })
	expectReadFailure(t, oldClient)

	newClient := mustTCPClient(t, gateway.Addr().String())
	if _, err := newClient.Write([]byte("new")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(newClient, response); err != nil {
		t.Fatal(err)
	}
	_, gotGeneration := dialer.last()
	if gotGeneration != generation {
		t.Fatalf("dialer generation = %d, want %d", gotGeneration, generation)
	}
}
