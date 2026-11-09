package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/private-radminlan/lanmesh/internal/egress"
)

type closeTrackingConn struct {
	net.Conn
	closeWrite atomic.Bool
}

func (c *closeTrackingConn) CloseWrite() error {
	c.closeWrite.Store(true)
	return nil
}

type memoryUDPPacket struct {
	data []byte
	addr net.Addr
}

type memoryPacketConn struct {
	incoming chan memoryUDPPacket
	outgoing chan memoryUDPPacket
	closed   chan struct{}
	closeOne sync.Once
}

func newMemoryPacketConn() *memoryPacketConn {
	return &memoryPacketConn{
		incoming: make(chan memoryUDPPacket, 8),
		outgoing: make(chan memoryUDPPacket, 8),
		closed:   make(chan struct{}),
	}
}

func (c *memoryPacketConn) ReadFrom(buffer []byte) (int, net.Addr, error) {
	select {
	case packet := <-c.incoming:
		count := copy(buffer, packet.data)
		return count, packet.addr, nil
	case <-c.closed:
		return 0, nil, net.ErrClosed
	}
}

func (c *memoryPacketConn) WriteTo(buffer []byte, address net.Addr) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	case c.outgoing <- memoryUDPPacket{data: append([]byte(nil), buffer...), addr: address}:
		return len(buffer), nil
	}
}

func (c *memoryPacketConn) Close() error {
	c.closeOne.Do(func() { close(c.closed) })
	return nil
}

func (c *memoryPacketConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9999}
}

func (c *memoryPacketConn) SetDeadline(time.Time) error      { return nil }
func (c *memoryPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *memoryPacketConn) SetWriteDeadline(time.Time) error { return nil }

type channelTunnel struct {
	*fakeTunnel
	receiveCh chan []byte
}

func (t *channelTunnel) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	select {
	case data, ok := <-t.receiveCh:
		if !ok {
			return nil, errors.New("receive channel closed")
		}
		return append([]byte(nil), data...), nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func waitForDatagram(t *testing.T, fake *fakeTunnel) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		fake.mu.Lock()
		count := len(fake.datagrams)
		fake.mu.Unlock()
		if count > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("timed out waiting for egress datagram")
}

func TestCopyBidirectionalPropagatesHalfClose(t *testing.T) {
	client, peer := net.Pipe()
	defer client.Close()
	defer peer.Close()
	tracked := &closeTrackingConn{Conn: client}
	stream := &fakeTunnelStream{}
	done := make(chan error, 1)
	go func() { done <- copyBidirectional(tracked, stream) }()
	_ = peer.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("copyBidirectional did not finish")
	}
	if !tracked.closeWrite.Load() {
		t.Fatal("TCP half-close was not propagated to the client connection")
	}
	stream.mu.Lock()
	defer stream.mu.Unlock()
	if !stream.closeWrite {
		t.Fatal("client EOF was not propagated with stream CloseWrite")
	}
}

func TestUnsupportedCommandAndAddressTypeReplies(t *testing.T) {
	tests := []struct {
		name      string
		request   []byte
		wantReply byte
	}{
		{name: "unknown command", request: []byte{5, 9, 0, 1, 127, 0, 0, 1, 0, 80}, wantReply: socksReplyCommandRejected},
		{name: "unknown command with unknown address type", request: []byte{5, 9, 0, 9}, wantReply: socksReplyCommandRejected},
		{name: "unknown address type", request: []byte{5, 1, 0, 9}, wantReply: socksReplyAddressType},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := newProxy(testProxyConfig(), &fakeTunnel{})
			if err != nil {
				t.Fatal(err)
			}
			p.markReady()
			client, done := newPipeProxy(t, p)
			writeAll(t, client, []byte{5, 1, 0})
			_ = readN(t, client, 2)
			writeAll(t, client, tt.request)
			reply := readN(t, client, 10)
			if reply[1] != tt.wantReply {
				t.Fatalf("reply code = %d, want %d (reply %x)", reply[1], tt.wantReply, reply)
			}
			if err := <-done; err == nil {
				t.Fatal("expected request rejection error")
			}
		})
	}
}

func TestUDPAssociateRelaysInMemoryEnvelope(t *testing.T) {
	base := &fakeTunnel{}
	fake := &channelTunnel{fakeTunnel: base, receiveCh: make(chan []byte, 1)}
	p, err := newProxy(testProxyConfig(), fake)
	if err != nil {
		t.Fatal(err)
	}
	packetConn := newMemoryPacketConn()
	p.udpListen = func(string, *net.UDPAddr) (net.PacketConn, error) {
		return packetConn, nil
	}
	p.markReady()
	client, done := newPipeProxy(t, p)

	writeAll(t, client, []byte{5, 1, 0})
	_ = readN(t, client, 2)
	writeAll(t, client, []byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0})
	reply := readN(t, client, 10)
	if reply[1] != socksReplySucceeded {
		t.Fatalf("UDP ASSOCIATE reply = %x, want success", reply)
	}
	if reply[3] != socksATYPIPv4 || binary.BigEndian.Uint16(reply[8:10]) != 9999 {
		t.Fatalf("UDP bind reply = %x, want 127.0.0.1:9999", reply)
	}

	clientUDP := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}
	requestPacket, err := encodeSOCKS5UDPPacket("dns.example", 53, []byte("query"))
	if err != nil {
		t.Fatal(err)
	}
	packetConn.incoming <- memoryUDPPacket{data: requestPacket, addr: clientUDP}
	waitForDatagram(t, base)

	base.mu.Lock()
	envelope := append([]byte(nil), base.datagrams[0]...)
	base.mu.Unlock()
	target, payload, err := egress.DecodeDatagram(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if target.Host != "dns.example" || target.Port != 53 || !bytes.Equal(payload, []byte("query")) {
		t.Fatalf("egress UDP envelope = (%+v, %q)", target, payload)
	}

	responseEnvelope, err := egress.EncodeDatagram(egress.OpenTarget{Host: "198.51.100.8", Port: 53, Protocol: egress.ProtocolUDP}, []byte("answer"))
	if err != nil {
		t.Fatal(err)
	}
	fake.receiveCh <- responseEnvelope
	select {
	case relayed := <-packetConn.outgoing:
		responseTarget, responsePayload, parseErr := parseSOCKS5UDPPacket(relayed.data)
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		if responseTarget.Host != "198.51.100.8" || responseTarget.Port != 53 || !bytes.Equal(responsePayload, []byte("answer")) {
			t.Fatalf("SOCKS5 UDP response = (%+v, %q)", responseTarget, responsePayload)
		}
		if !sameUDPAddr(relayed.addr, clientUDP) {
			t.Fatalf("UDP response destination = %s, want %s", relayed.addr, clientUDP)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for SOCKS5 UDP response")
	}

	_ = client.Close()
	if err := <-done; err != nil {
		t.Fatalf("handle UDP association: %v", err)
	}
}

func TestCheckModeValidatesWithoutConnecting(t *testing.T) {
	options := validCLIOptions(t)
	args := []string{
		"-check",
		"-listen", options.ListenAddr,
		"-server", options.ServerAddr,
		"-servername", options.ServerName,
		"-ca", options.CAPath,
		"-profile", options.ProfileID,
		"-rule", options.RuleID,
		"-device", options.DeviceID,
		"-lease", options.LeaseID,
		"-policy-version", "1",
		"-capability-file", options.CapabilityFile,
	}
	var stdout, stderr bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if code := runMain(ctx, args, &stdout, &stderr); code != 0 {
		t.Fatalf("runMain exit = %d; stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "EXPLICIT PROXY MODE") || !strings.Contains(stderr.String(), "not transparent forwarding") {
		t.Fatalf("banner = %q", stderr.String())
	}
	if !strings.Contains(stdout.String(), "no network connection made") {
		t.Fatalf("check output = %q", stdout.String())
	}
}
