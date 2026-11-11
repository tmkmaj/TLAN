package mesh

import (
	"crypto/rand"
	"encoding/binary"
	"net/netip"
	"time"
)

type peerProbe struct {
	Nonce          [8]byte
	Sent, Received time.Time
	RTT            time.Duration
}

// measuredRTT records a successful round-trip sample. Some platforms (notably
// Windows) expose a monotonic clock whose resolution is coarser than a fast
// loopback round trip, so time.Since can return exactly zero. Zero is reserved
// to mean "no measurement yet", so successful samples are clamped positive.
func measuredRTT(d time.Duration) time.Duration {
	if d <= 0 {
		return time.Microsecond
	}
	return d
}

// Probes travel inside WireGuard over whichever authenticated path is selected,
// so relay latency is measured to the other device rather than to the server.
func probePacket(source, target netip.Addr, reply bool, nonce [8]byte) []byte {
	p := make([]byte, 33)
	p[0] = 0x45
	p[8] = 64
	p[9] = 253
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	copy(p[12:16], source.AsSlice())
	copy(p[16:20], target.AsSlice())
	copy(p[20:24], "LMP1")
	if reply {
		p[24] = 1
	}
	copy(p[25:], nonce[:])
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(p[i : i+2]))
	}
	for sum > 65535 {
		sum = sum&65535 + sum>>16
	}
	binary.BigEndian.PutUint16(p[10:12], ^uint16(sum))
	return p
}
func (t *tunnel) probePeers() {
	t.mu.RLock()
	peers := make([]netip.Addr, 0, len(t.peers))
	for ip := range t.peers {
		peers = append(peers, ip)
	}
	t.mu.RUnlock()
	t.probeMu.Lock()
	if t.probes == nil {
		t.probes = make(map[netip.Addr]peerProbe)
	}
	for ip := range t.probes {
		t.mu.RLock()
		active := t.peers[ip]
		t.mu.RUnlock()
		if !active {
			delete(t.probes, ip)
		}
	}
	t.probeMu.Unlock()
	for _, ip := range peers {
		var nonce [8]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			continue
		}
		t.probeMu.Lock()
		state := t.probes[ip]
		state.Nonce = nonce
		state.Sent = time.Now()
		t.probes[ip] = state
		t.probeMu.Unlock()
		t.submit(probePacket(t.local, ip, false, nonce))
	}
}
func (t *tunnel) handleProbe(p []byte) bool {
	if len(p) != 33 || p[0] != 0x45 || p[9] != 253 || string(p[20:24]) != "LMP1" || p[24] > 1 {
		return false
	}
	source, target, err := ipv4(p)
	if err != nil || target != t.local {
		return false
	}
	var nonce [8]byte
	copy(nonce[:], p[25:])
	if p[24] == 0 {
		t.submit(probePacket(t.local, source, true, nonce))
		return true
	}
	t.probeMu.Lock()
	defer t.probeMu.Unlock()
	state, ok := t.probes[source]
	if ok && state.Nonce == nonce && !state.Sent.IsZero() && time.Since(state.Sent) < 5*time.Second {
		state.RTT = measuredRTT(time.Since(state.Sent))
		state.Received = time.Now()
		state.Sent = time.Time{}
		t.probes[source] = state
	}
	return true
}
func (t *tunnel) peerLatency(ip netip.Addr) (time.Duration, bool) {
	t.probeMu.Lock()
	defer t.probeMu.Unlock()
	p := t.probes[ip]
	return p.RTT, !p.Received.IsZero() && time.Since(p.Received) < 10*time.Second
}
