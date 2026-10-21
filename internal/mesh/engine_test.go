package mesh

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/private-radminlan/lanmesh/core"
	"github.com/private-radminlan/lanmesh/internal/clientapi"
	"github.com/private-radminlan/lanmesh/internal/clientidentity"
	"github.com/private-radminlan/lanmesh/internal/control"
	"github.com/private-radminlan/lanmesh/internal/network"
	"github.com/private-radminlan/lanmesh/internal/storage"
	"golang.zx2c4.com/wireguard/tun"
)

type testNIC struct {
	out, in chan []byte
	done    chan struct{}
	events  chan tun.Event
	once    sync.Once
}

func newNIC() *testNIC {
	return &testNIC{out: make(chan []byte, 10), in: make(chan []byte, 10), done: make(chan struct{}), events: make(chan tun.Event)}
}
func (n *testNIC) File() *os.File           { return nil }
func (n *testNIC) Name() (string, error)    { return "test", nil }
func (n *testNIC) MTU() (int, error)        { return MTU, nil }
func (n *testNIC) BatchSize() int           { return 1 }
func (n *testNIC) Events() <-chan tun.Event { return n.events }
func (n *testNIC) Close() error             { n.once.Do(func() { close(n.done); close(n.events) }); return nil }
func (n *testNIC) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case <-n.done:
		return 0, os.ErrClosed
	case p := <-n.out:
		sizes[0] = copy(bufs[0][offset:], p)
		return 1, nil
	}
}
func (n *testNIC) Write(bufs [][]byte, offset int) (int, error) {
	for _, p := range bufs {
		select {
		case n.in <- append([]byte(nil), p[offset:]...):
		case <-n.done:
			return 0, os.ErrClosed
		}
	}
	return len(bufs), nil
}

func testPacket(source, target string) []byte {
	p := make([]byte, 40)
	p[0] = 0x45
	p[8] = 64
	p[9] = 17
	binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
	copy(p[12:], netip.MustParseAddr(source).AsSlice())
	copy(p[16:], netip.MustParseAddr(target).AsSlice())
	binary.BigEndian.PutUint16(p[24:], 20)
	copy(p[28:], "game payload")
	return p
}

func TestWireGuardEndToEnd(t *testing.T) {
	for _, mode := range []string{"HTTPS_upgrade_relay", "direct_UDP", "mixed_forced_relay", "member_HTTPS_relay"} {
		relayOnly := mode != "direct_UDP"
		t.Run(mode, func(t *testing.T) {
			store, err := storage.Open(filepath.Join(t.TempDir(), "state.json"))
			if err != nil {
				t.Fatal(err)
			}
			var networkSummary storage.NetworkSummary
			if mode == "member_HTTPS_relay" {
				networkSummary, err = store.EnsurePrivateNetwork("test", "test-password", "10.242.0.0/24")
			} else {
				networkSummary, err = store.CreateNetwork("test", "test-password", "10.242.0.0/24")
			}
			if err != nil {
				t.Fatal(err)
			}
			handler := (&control.Server{Store: store, AdminToken: "test", Relay: network.NewRelayBrokerWithLimits(network.RelayLimits{MaxSessions: 32})}).Handler()
			var server *httptest.Server
			var roots *x509.CertPool
			if relayOnly {
				server = httptest.NewUnstartedServer(handler)
				server.TLS = &tls.Config{GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
					if hello.ServerName != "" {
						t.Errorf("IP control/relay connection sent domain SNI %q", hello.ServerName)
					}
					return nil, nil
				}}
				server.StartTLS()
				roots = x509.NewCertPool()
				roots.AddCert(server.Certificate())
			} else {
				server = httptest.NewServer(handler)
			}
			defer server.Close()
			api := clientapi.New(server.URL, "test")
			if relayOnly {
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				_, untrustedErr := network.DialHTTPRelay(ctx, server.URL, "test", network.RelayTicket{}, "test")
				cancel()
				if untrustedErr == nil {
					t.Fatal("untrusted HTTPS relay certificate was accepted")
				}
			}
			api.HTTP = server.Client()
			api.HTTP.Timeout = 10 * time.Second
			identities := make([]clientidentity.Identity, 2)
			members := make([]clientapi.Device, 2)
			memberAPIs := make([]*clientapi.Client, 2)
			for i := range identities {
				identities[i], err = clientidentity.LoadOrCreate(filepath.Join(t.TempDir(), "identity.json"))
				if err != nil {
					t.Fatal(err)
				}
				memberAPIs[i] = api
				if mode == "member_HTTPS_relay" {
					membership, enrollErr := api.Enroll("test-password", identities[i].RegisterRequest(), identities[i].PrivateKey)
					if enrollErr != nil {
						t.Fatal(enrollErr)
					}
					members[i] = membership.Member
					memberAPIs[i] = clientapi.New(server.URL, membership.Token)
					memberAPIs[i].HTTP = server.Client()
					continue
				}
				if _, err = api.RegisterDevice(identities[i].RegisterRequest()); err != nil {
					t.Fatal(err)
				}
				members[i], err = api.JoinNetworkAs(core.NetworkID(networkSummary.ID), identities[i].DeviceID, "test", "test-password")
				if err != nil {
					t.Fatal(err)
				}
			}
			nics := []*testNIC{newNIC(), newNIC()}
			engines := make([]*Engine, 2)
			for i := range engines {
				engines[i], err = Start(context.Background(), Options{API: memberAPIs[i], Identity: identities[i], Network: clientapi.Network{ID: networkSummary.ID, CIDR: networkSummary.CIDR}, Member: members[i], Native: nics[i], RelayOnly: relayOnly && (mode != "mixed_forced_relay" || i == 0), TrustedRoots: roots})
				if err != nil {
					t.Fatal(err)
				}
				defer engines[i].Close()
			}
			deadline := time.Now().Add(12 * time.Second)
			for {
				ready := true
				for _, e := range engines {
					e.bind.mu.RLock()
					for _, r := range e.bind.routes {
						if relayOnly {
							ready = ready && r.relay != nil
						} else {
							ready = ready && time.Since(r.lastDirect) < 10*time.Second
						}
					}
					e.bind.mu.RUnlock()
				}
				if ready {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("transport did not become ready: %+v %+v", engines[0].Status(), engines[1].Status())
				}
				time.Sleep(50 * time.Millisecond)
			}
			for _, dest := range []string{members[1].VirtualIP, "255.255.255.255", "10.242.0.255", "239.1.2.3"} {
				packet := testPacket(members[0].VirtualIP, dest)
				nics[0].out <- packet
				select {
				case actual := <-nics[1].in:
					if string(actual) != string(packet) {
						t.Fatal("inner packet changed")
					}
				case <-time.After(8 * time.Second):
					t.Fatalf("no encrypted delivery to %s: %v / %v", dest, engines[0].Status(), engines[1].Status())
				}
			}
			latencyDeadline := time.Now().Add(8 * time.Second)
			for {
				state := engines[0].Status()
				if len(state.Peers) > 0 && state.Peers[0].Reachable && state.Peers[0].RTT > 0 {
					break
				}
				if time.Now().After(latencyDeadline) {
					t.Fatal("encrypted end-to-end latency probe did not complete")
				}
				time.Sleep(50 * time.Millisecond)
			}
			if !relayOnly {
				engines[0].bind.mu.Lock()
				for _, r := range engines[0].bind.routes {
					r.lastDirect = time.Time{}
				}
				engines[0].bind.mu.Unlock()
				nics[0].out <- testPacket(members[0].VirtualIP, members[1].VirtualIP)
				select {
				case <-nics[1].in:
				case <-time.After(8 * time.Second):
					t.Fatal("direct-to-relay failover lost packet")
				}
			}
			// OS packet spoofing must never be accepted into the WireGuard queue.
			before := engines[0].plain.Dropped.Load()
			nics[0].out <- testPacket("10.242.0.99", members[1].VirtualIP)
			time.Sleep(30 * time.Millisecond)
			if engines[0].plain.Dropped.Load() <= before {
				t.Fatal("spoofed source was accepted")
			}
			if err := api.RemoveDevice(core.NetworkID(networkSummary.ID), identities[1].DeviceID); err != nil {
				t.Fatal(err)
			}
			if err := engines[0].syncPeers(); err != nil {
				t.Fatal(err)
			}
			if len(engines[0].Status().Peers) != 0 {
				t.Fatal("removed peer remained in the tunnel")
			}
			if _, err := api.CreateRelaySession(core.NetworkID(networkSummary.ID), identities[0].DeviceID, identities[1].DeviceID, time.Minute); err == nil {
				t.Fatal("removed member received a relay ticket")
			}
		})
	}
}

func TestCancelledStartDoesNotOpenAdapter(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Start(ctx, Options{}); err != context.Canceled {
		t.Fatalf("cancelled start returned %v", err)
	}
}

func TestEnvelopeRejectsForeignAndMalformedPackets(t *testing.T) {
	local := netip.MustParseAddr("10.242.0.2")
	peer := netip.MustParseAddr("10.242.0.1")
	prefix := netip.MustParsePrefix("10.242.0.0/24")
	known := map[netip.Addr]bool{peer: true}
	valid := encapsulate(testPacket(peer.String(), local.String()), peer, local)
	if _, err := decapsulate(valid, local, prefix, known); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{valid[:10], encapsulate(testPacket("10.242.0.99", local.String()), peer, local), encapsulate(testPacket(peer.String(), "1.1.1.1"), peer, local)} {
		if _, err := decapsulate(bad, local, prefix, known); err == nil {
			t.Fatal("invalid envelope accepted")
		}
	}
}
