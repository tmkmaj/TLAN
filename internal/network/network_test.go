package network

import (
	"bufio"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/private-radminlan/lanmesh/core"
)

func TestVirtualIPAllocatorStableAndReusable(t *testing.T) {
	prefix := netip.MustParsePrefix("10.240.1.0/29")
	allocator, err := NewVirtualIPAllocator(prefix, nil)
	if err != nil {
		t.Fatal(err)
	}
	first, err := allocator.Allocate(core.DeviceID("device-a"))
	if err != nil {
		t.Fatal(err)
	}
	if first != netip.MustParseAddr("10.240.1.1") {
		t.Fatalf("first address = %s", first)
	}
	again, err := allocator.Allocate(core.DeviceID("device-a"))
	if err != nil || again != first {
		t.Fatalf("allocation was not stable: %s, %v", again, err)
	}
	if err := allocator.Reserve(core.DeviceID("device-b"), netip.MustParseAddr("10.240.1.6")); err != nil {
		t.Fatal(err)
	}
	if !allocator.Release(core.DeviceID("device-a")) {
		t.Fatal("expected release")
	}
	if _, err := allocator.Allocate(core.DeviceID("device-c")); err != nil {
		t.Fatal(err)
	}
}

func TestACLFirstMatch(t *testing.T) {
	acl, err := NewACL([]core.ACLRule{
		{ID: "deny-ssh", Priority: 10, Action: "deny", Protocol: "tcp", FromPort: 22, ToPort: 22},
		{ID: "allow-all", Priority: 20, Action: "allow"},
	}, ACLDefaultDeny)
	if err != nil {
		t.Fatal(err)
	}
	if acl.Evaluate(PacketInfo{Source: netip.MustParseAddr("10.240.1.2"), Dest: netip.MustParseAddr("10.240.1.3"), Protocol: "tcp", Port: 22}) {
		t.Fatal("SSH should be denied by first matching rule")
	}
	if !acl.Evaluate(PacketInfo{Source: netip.MustParseAddr("10.240.1.2"), Dest: netip.MustParseAddr("10.240.1.3"), Protocol: "tcp", Port: 80}) {
		t.Fatal("HTTP should be allowed by second matching rule")
	}
}

func TestRelayRequiresBothAuthorizedEndpoints(t *testing.T) {
	broker := NewRelayBroker(1024)
	ticket, err := broker.CreateSession(core.DeviceID("device-a"), core.DeviceID("device-b"), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	wrong := ticket
	wrong.Secret = base64.RawURLEncoding.EncodeToString([]byte("wrong"))
	if _, err := broker.Attach(wrong, core.DeviceID("device-a")); !errors.Is(err, ErrRelayUnauthorized) {
		t.Fatalf("wrong ticket error = %v", err)
	}
	a, err := broker.Attach(ticket, core.DeviceID("device-a"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := broker.Attach(ticket, core.DeviceID("device-b"))
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("encrypted wireguard datagram")
	if err := a.Send(payload); err != nil {
		t.Fatal(err)
	}
	message, err := b.Receive()
	if err != nil {
		t.Fatal(err)
	}
	if string(message.Data) != string(payload) || message.From != core.DeviceID("device-a") || message.To != core.DeviceID("device-b") {
		t.Fatalf("unexpected relay message: %+v", message)
	}
	_ = a.Close()
	_ = b.Close()
}

func TestRelayLimitsAndIdleCleanup(t *testing.T) {
	b := NewRelayBrokerWithLimits(RelayLimits{MaxSessions: 1, IdleTimeout: time.Second})
	ticket, err := b.CreateSession(core.DeviceID("device-a"), core.DeviceID("device-b"), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.CreateSession(core.DeviceID("device-c"), core.DeviceID("device-d"), time.Minute); !errors.Is(err, ErrRelayCapacity) {
		t.Fatalf("second session error = %v", err)
	}
	b.mu.Lock()
	b.sessions[ticket.SessionID].lastActivity = time.Now().Add(-2 * time.Second)
	b.mu.Unlock()
	b.CleanupExpired()
	if _, err := b.Attach(ticket, core.DeviceID("device-a")); !errors.Is(err, ErrRelayUnauthorized) {
		t.Fatalf("expired idle session attach error = %v", err)
	}
}

func TestRelayServerForwardsLengthPrefixedPackets(t *testing.T) {
	b := NewRelayBroker(1024)
	ticket, err := b.CreateSession(core.DeviceID("device-a"), core.DeviceID("device-b"), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	leftClient, leftServer := net.Pipe()
	rightClient, rightServer := net.Pipe()
	server := &RelayServer{Broker: b}
	go func() { _ = server.ServeConn(leftServer) }()
	go func() { _ = server.ServeConn(rightServer) }()
	writeHandshake := func(conn net.Conn, device core.DeviceID) {
		request, _ := json.Marshal(RelayHandshake{Ticket: ticket, Device: device})
		_, _ = conn.Write(append(request, '\n'))
		var response relayHandshakeResponse
		if err := json.NewDecoder(bufio.NewReader(conn)).Decode(&response); err != nil || !response.OK {
			t.Errorf("handshake failed: %v %+v", err, response)
		}
	}
	writeHandshake(leftClient, core.DeviceID("device-a"))
	writeHandshake(rightClient, core.DeviceID("device-b"))
	payload := []byte("relay datagram")
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(payload)))
	if _, err := leftClient.Write(append(header[:], payload...)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(rightClient, header[:]); err != nil {
		t.Fatal(err)
	}
	data := make([]byte, binary.BigEndian.Uint32(header[:]))
	if _, err := io.ReadFull(rightClient, data); err != nil {
		t.Fatal(err)
	}
	if string(data) != string(payload) {
		t.Fatalf("forwarded payload = %q", data)
	}
	_ = leftClient.Close()
	_ = rightClient.Close()
}
