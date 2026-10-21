package targetgateway

import (
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

func startUDPGateway(t *testing.T, dialer Dialer, lease LeaseValidator, maxDatagram int, maxSessions int, idle time.Duration) *Gateway {
	t.Helper()
	gateway, err := Start(context.Background(), Config{
		Protocol:          ProtocolUDP,
		ListenPort:        0,
		Target:            testTarget(9000),
		Lease:             lease,
		Dialer:            dialer,
		LeasePollInterval: 20 * time.Millisecond,
		DialTimeout:       time.Second,
		IdleTimeout:       idle,
		WriteTimeout:      time.Second,
		MaxDatagramSize:   maxDatagram,
		MaxUDPSessions:    maxSessions,
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

func TestUDPIsolationBetweenClients(t *testing.T) {
	backend := startUDPEcho(t)
	lease := newLeaseFixture()
	dialer := &testDialer{udpAddr: backend}
	gateway := startUDPGateway(t, dialer, lease, 0, 0, time.Second)
	clientA := mustUDPClient(t, gateway.Addr().String())
	clientB := mustUDPClient(t, gateway.Addr().String())

	if _, err := clientA.Write([]byte("client-A")); err != nil {
		t.Fatal(err)
	}
	if _, err := clientB.Write([]byte("client-B")); err != nil {
		t.Fatal(err)
	}
	replyA := make([]byte, len("client-A"))
	replyB := make([]byte, len("client-B"))
	if _, err := io.ReadFull(clientA, replyA); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(clientB, replyB); err != nil {
		t.Fatal(err)
	}
	if string(replyA) != "client-A" || string(replyB) != "client-B" {
		t.Fatalf("cross-session reply: A=%q B=%q", replyA, replyB)
	}
	if calls := dialer.udpCalls.Load(); calls < 2 {
		t.Fatalf("expected independent backend sockets, got %d", calls)
	}
	waitFor(t, time.Second, func() bool {
		stats := gateway.Stats()
		return stats.UDPAccepted >= 2 && stats.DatagramsToTarget >= 2 && stats.DatagramsFromTarget >= 2
	})
	stats := gateway.Stats()
	if stats.UDPAccepted < 2 || stats.DatagramsToTarget < 2 || stats.DatagramsFromTarget < 2 {
		t.Fatalf("unexpected UDP stats: %+v", stats)
	}
}

func TestUDPGenerationChangeRecreatesSessionAndRevocationBlocks(t *testing.T) {
	backend := startUDPEcho(t)
	lease := newLeaseFixture()
	dialer := &testDialer{udpAddr: backend}
	gateway := startUDPGateway(t, dialer, lease, 0, 0, time.Second)
	client := mustUDPClient(t, gateway.Addr().String())

	if _, err := client.Write([]byte("before")); err != nil {
		t.Fatal(err)
	}
	beforeReply := make([]byte, len("before"))
	if _, err := io.ReadFull(client, beforeReply); err != nil {
		t.Fatal(err)
	}
	lease.rotate()
	if _, err := client.Write([]byte("after")); err != nil {
		t.Fatal(err)
	}
	afterReply := make([]byte, len("after"))
	if _, err := io.ReadFull(client, afterReply); err != nil {
		t.Fatal(err)
	}
	if string(afterReply) != "after" {
		t.Fatalf("after-rotation reply = %q", afterReply)
	}
	if calls := dialer.udpCalls.Load(); calls < 2 {
		t.Fatalf("generation change reused stale backend socket: calls=%d", calls)
	}

	lease.revoke()
	waitFor(t, 2*time.Second, func() bool { return gateway.Stats().UDPActive == 0 })
	if _, err := client.Write([]byte("blocked")); err != nil {
		t.Fatal(err)
	}
	expectUDPTimeout(t, client)
	if calls := dialer.udpCalls.Load(); calls != 2 {
		t.Fatalf("dialer called after revocation: %d", calls)
	}
	if gateway.Stats().LeaseRejections == 0 {
		t.Fatal("UDP lease rejection was not counted")
	}
}

func TestUDPDatagramAndSessionLimits(t *testing.T) {
	backend := startUDPEcho(t)
	lease := newLeaseFixture()
	dialer := &testDialer{udpAddr: backend}
	gateway := startUDPGateway(t, dialer, lease, 8, 1, time.Second)
	clientA := mustUDPClient(t, gateway.Addr().String())
	clientB := mustUDPClient(t, gateway.Addr().String())

	if _, err := clientA.Write([]byte("first")); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, len("first"))
	if _, err := io.ReadFull(clientA, reply); err != nil {
		t.Fatal(err)
	}
	if _, err := clientB.Write([]byte("second")); err != nil {
		t.Fatal(err)
	}
	expectUDPTimeout(t, clientB)
	if _, err := clientA.Write([]byte("oversized-datagram")); err != nil {
		t.Fatal(err)
	}
	waitFor(t, time.Second, func() bool { return gateway.Stats().UDPDropped >= 2 })
	if calls := dialer.udpCalls.Load(); calls != 1 {
		t.Fatalf("session limit/oversize created extra backend socket: %d", calls)
	}
}

func TestUDPIdleSessionExpires(t *testing.T) {
	backend := startUDPEcho(t)
	lease := newLeaseFixture()
	dialer := &testDialer{udpAddr: backend}
	gateway := startUDPGateway(t, dialer, lease, 0, 0, 100*time.Millisecond)
	client := mustUDPClient(t, gateway.Addr().String())

	if _, err := client.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 1)
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 2*time.Second, func() bool { return gateway.Stats().UDPActive == 0 })
	if _, err := client.Write([]byte("y")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatal(err)
	}
	if calls := dialer.udpCalls.Load(); calls < 2 {
		t.Fatalf("idle session was not recreated: calls=%d", calls)
	}
}

func TestUDPFirstDispatchCloseRace(t *testing.T) {
	for i := 0; i < 50; i++ {
		lease := newLeaseFixture()
		gateway := startUDPGateway(t, &testDialer{udpAddr: "127.0.0.1:1"}, lease, 0, 4, time.Second)
		client, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(gateway.Addr()))
		if err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		writeDone := make(chan struct{})
		go func() {
			<-start
			_, _ = client.Write([]byte("race"))
			close(writeDone)
		}()
		go func() {
			<-start
			_ = gateway.Close()
		}()
		close(start)
		<-writeDone
		select {
		case <-gateway.Done():
		case <-time.After(time.Second):
			t.Fatal("gateway Close did not complete after dispatch race")
		}
		_ = client.Close()
	}
}
func TestUDPContextCancellationClosesSessions(t *testing.T) {
	backend := startUDPEcho(t)
	lease := newLeaseFixture()
	dialer := &testDialer{udpAddr: backend}
	ctx, cancel := context.WithCancel(context.Background())
	gateway, err := Start(ctx, Config{
		Protocol:          ProtocolUDP,
		Target:            testTarget(9000),
		Lease:             lease,
		Dialer:            dialer,
		LeasePollInterval: 20 * time.Millisecond,
		IdleTimeout:       time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = gateway.Close() })
	client := mustUDPClient(t, gateway.Addr().String())
	if _, err := client.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 1)
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case <-gateway.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("gateway did not finish cancellation")
	}
	if active := gateway.Stats().UDPActive; active != 0 {
		t.Fatalf("active UDP sessions after cancellation: %d", active)
	}
}
