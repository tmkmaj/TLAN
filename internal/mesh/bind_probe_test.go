package mesh

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/private-radminlan/lanmesh/internal/clientidentity"
)

// These tests drive the real meshBind probe path. They are the regression
// guard for the three defects that caused "direct/relay flip-flop" plus
// periodic packet loss in the field.

func newProbePair(t *testing.T) (a, b *meshBind, peerA, peerB netip.Addr) {
	t.Helper()
	idA, err := clientidentity.LoadOrCreate(t.TempDir() + "/a.json")
	if err != nil {
		t.Fatal(err)
	}
	idB, err := clientidentity.LoadOrCreate(t.TempDir() + "/b.json")
	if err != nil {
		t.Fatal(err)
	}
	peerA = netip.MustParseAddr("10.244.0.1")
	peerB = netip.MustParseAddr("10.244.0.2")
	a, err = newBind(peerA, "probe-net", idA.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = a.Open(0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.Close() })
	b, err = newBind(peerB, "probe-net", idB.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = b.Open(0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { b.Close() })

	if err := a.updatePeer(peerB, idB.PublicKey, bindPorts(b)); err != nil {
		t.Fatal(err)
	}
	if err := b.updatePeer(peerA, idA.PublicKey, bindPorts(a)); err != nil {
		t.Fatal(err)
	}
	return a, b, peerA, peerB
}

// bindPorts returns the loopback form of every socket the bind listens on.
func bindPorts(b *meshBind) []netip.AddrPort {
	ports := []netip.AddrPort{}
	for _, u := range append([]*net.UDPConn{b.udp}, b.extra...) {
		if u == nil {
			continue
		}
		addr := u.LocalAddr().(*net.UDPAddr)
		ports = append(ports, netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(addr.Port)))
	}
	return ports
}

// Regression A: every probe carries a unique nonce, so a valid reply is never
// discarded just because another socket's check loop overwrote the pending one.
func TestProbeRepliesAreNeverDiscardedAsUnmatched(t *testing.T) {
	a, _, _, peerB := newProbePair(t)

	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		a.mu.RLock()
		r := a.routes[peerB]
		usable := r != nil && r.directUsable(time.Now())
		a.mu.RUnlock()
		if usable {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	a.mu.RLock()
	r := a.routes[peerB]
	direct, socket, failures := r.direct, r.directSocket, r.failures
	a.mu.RUnlock()
	if !direct.IsValid() {
		t.Fatal("a reachable peer was never learned: replies are being discarded")
	}
	if failures != 0 {
		t.Fatalf("healthy path recorded %d failures", failures)
	}
	if socket < 0 || socket >= meshBindPortCount {
		t.Fatalf("learned socket %d out of range", socket)
	}
}

// Regression C: the pinned socket must not change while it keeps answering,
// because changing it means sending on a NAT mapping the peer never learned.
func TestPinnedSocketDoesNotOscillate(t *testing.T) {
	a, _, _, peerB := newProbePair(t)

	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		a.mu.RLock()
		r := a.routes[peerB]
		ready := r != nil && r.direct.IsValid()
		a.mu.RUnlock()
		if ready {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	a.mu.RLock()
	pinned := a.routes[peerB].directSocket
	a.mu.RUnlock()
	switches := 0
	last := pinned
	end := time.Now().Add(7 * time.Second)
	for time.Now().Before(end) {
		a.mu.RLock()
		cur := a.routes[peerB].directSocket
		a.mu.RUnlock()
		if cur != last {
			switches++
			last = cur
		}
		time.Sleep(25 * time.Millisecond)
	}
	if switches != 0 {
		t.Fatalf("pinned direct socket moved %d times while the path was healthy", switches)
	}
}

// Regression B: with a healthy peer the direct path stays preferred with no
// periodic stale windows, which is what the UI shows as direct/relay flipping.
func TestDirectPathStaysPreferredWithoutFlapping(t *testing.T) {
	a, _, _, peerB := newProbePair(t)

	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		a.mu.RLock()
		r := a.routes[peerB]
		ready := r != nil && r.directUsable(time.Now())
		a.mu.RUnlock()
		if ready {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	flips := 0
	first := true
	last := false
	stale := 0
	end := time.Now().Add(7 * time.Second)
	for time.Now().Before(end) {
		a.mu.RLock()
		r := a.routes[peerB]
		now := time.Now()
		preferred := r != nil && r.directPreferred(now, true)
		a.mu.RUnlock()
		if first {
			// Seed from the first observation: the initial state is not a flip.
			last, first = preferred, false
		} else if preferred != last {
			flips++
			last = preferred
		}
		if !preferred {
			stale++
		}
		time.Sleep(25 * time.Millisecond)
	}
	if stale > 0 {
		t.Fatalf("direct path was de-preferred for %d samples despite a healthy peer", stale)
	}
	if flips > 0 {
		t.Fatalf("direct preference flipped %d times", flips)
	}
}
