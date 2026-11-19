package mesh

import (
	"net/netip"
	"testing"
	"time"

	"github.com/private-radminlan/lanmesh/internal/clientidentity"
)

func testKeys(t *testing.T) (string, string) {
	t.Helper()
	local, err := clientidentity.LoadOrCreate(t.TempDir() + "/local.json")
	if err != nil {
		t.Fatal(err)
	}
	peer, err := clientidentity.LoadOrCreate(t.TempDir() + "/peer.json")
	if err != nil {
		t.Fatal(err)
	}
	return local.PrivateKey, peer.PublicKey
}

// A datagram that no path could carry must be counted as a drop instead of
// being reported as a successful send.
func TestSendCountsDropWhenNoPathWorks(t *testing.T) {
	privateKey, publicKey := testKeys(t)
	b, err := newBind(netip.MustParseAddr("10.244.0.1"), "relay-fail", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.Open(0); err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	peer := netip.MustParseAddr("10.244.0.2")
	if err := b.updatePeer(peer, publicKey, nil); err != nil {
		t.Fatal(err)
	}
	drops := 0
	b.onDrop = func() { drops++ }

	// No relay, no direct path, no candidates: nowhere to send.
	if err := b.Send([][]byte{make([]byte, 32)}, &endpoint{netip.AddrPortFrom(peer, 1)}); err != nil {
		t.Fatal(err)
	}
	if drops != 1 {
		t.Fatalf("drops = %d, want 1: a packet that reached no path was not counted", drops)
	}
}

// A relay write failure must fall through to the pinned direct path instead of
// discarding the packet. The relay is forced to "unavailable" by detaching it,
// and the path is made non-preferred so the fallback branch is the one used.
func TestRelayFailureFallsBackToDirect(t *testing.T) {
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
	r := a.routes[peerB]
	if !r.direct.IsValid() || r.directSocket < 0 {
		a.mu.RUnlock()
		t.Fatal("no pinned direct path to fall back to")
	}
	a.mu.RUnlock()

	drops := 0
	a.onDrop = func() { drops++ }
	if err := a.Send([][]byte{make([]byte, 32)}, &endpoint{netip.AddrPortFrom(peerB, 1)}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if drops != 0 {
		t.Fatalf("drops = %d, want 0: the direct fallback should have carried the packet", drops)
	}
}
