package mesh

import (
	"errors"
	"net/netip"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/tun"
)

// tunnel is the private TUN used by wireguard-go, not the OS-facing interface.
// Its receive side accepts only encapsulated packets belonging to a member.
type tunnel struct {
	probeMu                 sync.Mutex
	probes                  map[netip.Addr]peerProbe
	local                   netip.Addr
	prefix                  netip.Prefix
	mu                      sync.RWMutex
	peers                   map[netip.Addr]bool
	out                     chan []byte
	in                      chan []byte
	done                    chan struct{}
	events                  chan tun.Event
	once                    sync.Once
	lastBroadcast           time.Time
	broadcastCount          int
	Sent, Received, Dropped atomic.Uint64
}

func newTunnel(local netip.Addr, prefix netip.Prefix) *tunnel {
	t := &tunnel{local: local, prefix: prefix, peers: make(map[netip.Addr]bool), out: make(chan []byte, 512), in: make(chan []byte, 512), done: make(chan struct{}), events: make(chan tun.Event, 2)}
	t.events <- tun.EventUp
	return t
}
func (t *tunnel) File() *os.File                     { return nil }
func (t *tunnel) Name() (string, error)              { return "TmkNetworkLAN-encrypted", nil }
func (t *tunnel) MTU() (int, error)                  { return MTU + envelopeSize, nil }
func (t *tunnel) BatchSize() int                     { return 1 }
func (t *tunnel) Events() <-chan tun.Event           { return t.events }
func (t *tunnel) Close() error                       { t.once.Do(func() { close(t.done); close(t.events) }); return nil }
func (t *tunnel) setPeers(peers map[netip.Addr]bool) { t.mu.Lock(); t.peers = peers; t.mu.Unlock() }
func (t *tunnel) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case <-t.done:
		return 0, os.ErrClosed
	case packet := <-t.out:
		if len(bufs[0])-offset < len(packet) {
			return 0, errors.New("WireGuard buffer too small")
		}
		sizes[0] = copy(bufs[0][offset:], packet)
		return 1, nil
	}
}
func (t *tunnel) Write(bufs [][]byte, offset int) (int, error) {
	for _, buf := range bufs {
		t.mu.RLock()
		packet, err := decapsulate(buf[offset:], t.local, t.prefix, t.peers)
		t.mu.RUnlock()
		if err != nil {
			t.Dropped.Add(1)
			continue
		}
		if t.handleProbe(packet) {
			continue
		}
		select {
		case t.in <- append([]byte(nil), packet...):
			t.Received.Add(uint64(len(packet)))
		case <-t.done:
			return 0, os.ErrClosed
		default:
			t.Dropped.Add(1)
		}
	}
	return len(bufs), nil
}
func (t *tunnel) submit(packet []byte) {
	source, dest, err := ipv4(packet)
	if err != nil || len(packet) > MTU || source != t.local {
		t.Dropped.Add(1)
		return
	}
	t.mu.Lock()
	targets := make([]netip.Addr, 0)
	if broadcast(dest, t.prefix) {
		if time.Since(t.lastBroadcast) >= time.Second {
			t.lastBroadcast = time.Now()
			t.broadcastCount = 0
		}
		t.broadcastCount++
		if t.broadcastCount <= 100 {
			for peer := range t.peers {
				targets = append(targets, peer)
			}
		}
		sort.Slice(targets, func(i, j int) bool { return targets[i].Less(targets[j]) })
		if len(targets) > 64 {
			targets = targets[:64]
		}
	} else if t.peers[dest] {
		targets = append(targets, dest)
	}
	t.mu.Unlock()
	for _, target := range targets {
		select {
		case t.out <- encapsulate(packet, t.local, target):
			t.Sent.Add(uint64(len(packet)))
		default:
			t.Dropped.Add(1)
		}
	}
}
