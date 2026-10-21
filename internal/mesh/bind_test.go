package mesh

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/private-radminlan/lanmesh/internal/clientidentity"
	"github.com/private-radminlan/lanmesh/internal/network"
)

func TestSTUNUsesActiveWireGuardPort(t *testing.T) {
	identity, err := clientidentity.LoadOrCreate(filepath.Join(t.TempDir(), "identity.json"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := newBind(netip.MustParseAddr("10.242.0.1"), "test-net", identity.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	_, port, err := b.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serverDone := make(chan error, 1)
	go func() { serverDone <- network.ServeSTUN(ctx, socket) }()
	probeCtx, stop := context.WithTimeout(ctx, time.Second)
	defer stop()
	mapped, err := b.probeSTUN(probeCtx, socket.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	if mapped.Port() != port {
		t.Fatalf("STUN advertised %d, WireGuard is bound to %d", mapped.Port(), port)
	}
	cancel()
	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("STUN server did not stop")
	}
}

func TestProbeIgnoresForgedMAC(t *testing.T) {
	identity, err := clientidentity.LoadOrCreate(filepath.Join(t.TempDir(), "identity.json"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := newBind(netip.MustParseAddr("10.242.0.1"), "test-net", identity.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	peer := netip.MustParseAddr("10.242.0.2")
	b.routes[peer] = &peerRoute{key: []byte("unknown shared key")}
	_, _, err = b.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	packet := make([]byte, 41)
	copy(packet, "LMP1")
	packet[4] = 2
	copy(packet[5:9], peer.AsSlice())
	binary.BigEndian.PutUint64(packet[9:], uint64(time.Now().Unix()))
	b.handleProbe(b.udp, packet, netip.MustParseAddrPort("127.0.0.1:55000"))
	b.mu.RLock()
	direct := b.routes[peer].direct
	b.mu.RUnlock()
	if direct.IsValid() {
		t.Fatal("forged path was accepted")
	}
}
