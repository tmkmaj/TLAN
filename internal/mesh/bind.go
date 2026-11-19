package mesh

import (
	"context"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/private-radminlan/lanmesh/internal/network"
	"golang.zx2c4.com/wireguard/conn"
)

type endpoint struct{ address netip.AddrPort }

func (e *endpoint) ClearSrc()           {}
func (e *endpoint) SrcToString() string { return "" }
func (e *endpoint) DstToString() string { return e.address.String() }
func (e *endpoint) DstToBytes() []byte  { return []byte(e.address.String()) }
func (e *endpoint) DstIP() netip.Addr   { return e.address.Addr() }
func (e *endpoint) SrcIP() netip.Addr   { return netip.Addr{} }

// pendingProbe records one outstanding authenticated connectivity check.
// Probes are keyed by nonce so the three per-socket check loops never overwrite
// each other's outstanding check; a reply therefore matches the probe that
// actually produced it.
type pendingProbe struct {
	socket int
	sent   time.Time
}

type peerRoute struct {
	key        []byte
	candidates []netip.AddrPort

	// direct is the pinned direct path. Both halves identify it: the remote
	// address AND the local socket that owns the NAT mapping for it. Sending a
	// packet on a different socket would use a mapping the peer's NAT has never
	// seen, and the kernel would silently drop it.
	direct       netip.AddrPort
	directSocket int
	lastDirect   time.Time

	// pending holds the outstanding probes for this route, keyed by nonce.
	pending map[[8]byte]pendingProbe

	// failures counts consecutive unanswered probes on the pinned path. It is
	// the evidence required before the path may migrate to another socket.
	failures int

	// rtt plus a Schmitt-trigger state avoid flapping when the measured latency
	// sits near the preference boundary.
	rtt     time.Duration
	slow    bool
	slowRun int
	fastRun int

	relay       *network.StreamRelay
	relayExpiry time.Time
}
type datagram struct {
	data []byte
	peer netip.Addr
}
type stunReply struct {
	packet []byte
	source netip.AddrPort
	socket int
}

// meshBind multiplexes STUN, authenticated connectivity checks and encrypted
// WireGuard packets on the SAME UDP socket. Relay is a TCP/TLS fallback for the
// WireGuard datagram, never a replacement for WireGuard authentication.
type meshBind struct {
	mu        sync.RWMutex
	local     netip.Addr
	networkID string
	private   []byte
	relayOnly bool
	udp       *net.UDPConn
	extra     []*net.UDPConn
	port      uint16
	done      chan struct{}
	in        chan datagram
	routes    map[netip.Addr]*peerRoute
	stun      map[[12]byte]chan stunReply
	// onDrop is set by the engine so bind-level drops are counted with the
	// tunnel's own counters.
	onDrop func()
}

func newBind(local netip.Addr, networkID, privateKey string) (*meshBind, error) {
	key, err := base64.StdEncoding.DecodeString(privateKey)
	if err != nil || len(key) != 32 {
		return nil, errors.New("invalid private key")
	}
	return &meshBind{local: local, networkID: networkID, private: key, routes: make(map[netip.Addr]*peerRoute), stun: make(map[[12]byte]chan stunReply)}, nil
}
func (b *meshBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.udp != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	sockets := make([]*net.UDPConn, 0, meshBindPortCount)
	for index := 0; index < meshBindPortCount; index++ {
		listenPort := 0
		if index == 0 {
			listenPort = int(port)
		}
		u, err := net.ListenUDP("udp4", &net.UDPAddr{Port: listenPort})
		if err != nil {
			for _, opened := range sockets {
				_ = opened.Close()
			}
			return nil, 0, err
		}
		sockets = append(sockets, u)
	}
	b.udp = sockets[0]
	b.extra = append([]*net.UDPConn(nil), sockets[1:]...)
	b.port = uint16(b.udp.LocalAddr().(*net.UDPAddr).Port)
	b.done = make(chan struct{})
	b.in = make(chan datagram, 1024)
	done, in := b.done, b.in
	receivers := make([]conn.ReceiveFunc, 0, len(sockets))
	for index, u := range sockets {
		index, u := index, u
		go b.readUDP(u, done, in, index)
		receivers = append(receivers, func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
			select {
			case <-done:
				return 0, net.ErrClosed
			case packet := <-in:
				sizes[0] = copy(packets[0], packet.data)
				eps[0] = &endpoint{netip.AddrPortFrom(packet.peer, 1)}
				return 1, nil
			}
		})
	}
	go b.checkLoop(done)
	return receivers, b.port, nil
}
func (b *meshBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.udp == nil {
		return nil
	}
	close(b.done)
	var errs []error
	if err := b.udp.Close(); err != nil {
		errs = append(errs, err)
	}
	for _, u := range b.extra {
		if err := u.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	b.udp = nil
	b.extra = nil
	for _, r := range b.routes {
		if r.relay != nil {
			r.relay.Close()
			r.relay = nil
		}
	}
	return errors.Join(errs...)
}
func (b *meshBind) SetMark(uint32) error { return nil }
func (b *meshBind) BatchSize() int       { return 1 }
func (b *meshBind) ParseEndpoint(value string) (conn.Endpoint, error) {
	p, err := netip.ParseAddrPort(value)
	if err != nil {
		return nil, err
	}
	return &endpoint{p}, nil
}

const (
	// A direct path must beat these thresholds to be used, and the gap between
	// them is the deadband that keeps a path from flapping when its latency
	// hovers at the boundary.
	directRTTPreference = 180 * time.Millisecond
	directRTTDrop       = 220 * time.Millisecond
	directRTTSamples    = 3

	// The pinned path is abandoned only after this many consecutive probes go
	// unanswered, so a single lost packet never moves the flow.
	directFailureThreshold = 3
	directProbeTimeout     = 5 * time.Second
	directStaleAfter       = 12 * time.Second

	meshBindPortCount  = 3
	meshPredictedPorts = 3
)

// directUsable reports whether the pinned direct path is recent enough to
// trust. It deliberately reads the pinned pair (address + local socket) rather
// than "the last address any socket answered from".
func (r *peerRoute) directUsable(now time.Time) bool {
	if r == nil || !r.direct.IsValid() || r.lastDirect.IsZero() {
		return false
	}
	return now.Sub(r.lastDirect) < directStaleAfter
}

// directPreferred keeps both paths alive and prefers the pinned direct path.
// A relay is used immediately while the direct probe is still warming up, when
// the pinned path has failed directFailureThreshold probes in a row, or when
// the measured latency has crossed the slow threshold. Two separate thresholds
// (directRTTPreference and directRTTDrop) give the latency decision a deadband
// so it cannot oscillate sample by sample.
func (r *peerRoute) directPreferred(now time.Time, relayAvailable bool) bool {
	if !r.directUsable(now) {
		return false
	}
	if r.failures >= directFailureThreshold {
		return false
	}
	if !relayAvailable {
		return true
	}
	return r.rtt <= 0 || !r.slow
}

// observeSuccess promotes a socket to the pinned path and refreshes the RTT
// with hysteresis. Path migration is only allowed once the previously pinned
// path has gone unanswered directFailureThreshold times, so a socket that merely
// answers a probe does not steal the flow away from the mapping in use.
func (r *peerRoute) observeSuccess(now time.Time, address netip.AddrPort, socket int, rtt time.Duration) {
	if r.direct.IsValid() && r.directSocket != socket && r.failures < directFailureThreshold {
		// The pinned mapping is still healthy: record the sample as evidence but
		// keep sending on the socket the peer's NAT already learned.
		r.noteRTT(rtt)
		return
	}
	r.direct = address
	r.directSocket = socket
	r.lastDirect = now
	r.failures = 0
	r.noteRTT(rtt)
}

func (r *peerRoute) noteRTT(rtt time.Duration) {
	if rtt <= 0 {
		return
	}
	r.rtt = rtt
	if r.slow {
		if rtt < directRTTPreference {
			r.fastRun++
			if r.fastRun >= directRTTSamples {
				r.slow = false
				r.fastRun = 0
				r.slowRun = 0
			}
			return
		}
		r.fastRun = 0
		return
	}
	if rtt > directRTTDrop {
		r.slowRun++
		if r.slowRun >= directRTTSamples {
			r.slow = true
			r.slowRun = 0
			r.fastRun = 0
		}
		return
	}
	r.slowRun = 0
}

// observeFailure records one unanswered probe on the pinned path. The path is
// only abandoned after consecutive failures, which is the debounce that stops a
// single dropped packet from moving the flow to the relay.
func (r *peerRoute) observeFailure(now time.Time) {
	if r == nil || !r.direct.IsValid() {
		return
	}
	r.failures++
	if r.failures < directFailureThreshold {
		return
	}
	// Keep the learned address as a hint for the next round of punching, but
	// stop claiming it is usable.
	r.lastDirect = time.Time{}
	r.slow = false
	r.slowRun = 0
	r.fastRun = 0
}

func (b *meshBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	b.mu.RLock()
	r := b.routes[ep.DstIP()]
	primary := b.udp
	extra := append([]*net.UDPConn(nil), b.extra...)
	if r == nil || primary == nil {
		b.mu.RUnlock()
		return nil
	}
	sockets := append([]*net.UDPConn{primary}, extra...)
	direct, directSocket, relay := r.direct, r.directSocket, r.relay
	now := time.Now()
	useDirect := !b.relayOnly && r.directPreferred(now, relay != nil)
	candidates := append([]netip.AddrPort(nil), r.candidates...)
	b.mu.RUnlock()

	for _, packet := range bufs {
		// A genuine relay write failure must not silently drop the packet: fall
		// through to the direct path (or to punching) instead of returning a
		// success the caller never earned.
		if useDirect && directSocket >= 0 && directSocket < len(sockets) {
			if _, err := sockets[directSocket].WriteToUDPAddrPort(packet, direct); err == nil {
				continue
			}
		}
		if relay != nil {
			if err := relay.Send(packet); err == nil {
				continue
			} else if b.relayOnly {
				// Relay-only mode has no alternative path; make the drop visible
				// instead of reporting a success that never happened.
				b.recordDrop()
				continue
			}
		}
		if b.relayOnly {
			continue
		}
		if directSocket >= 0 && directSocket < len(sockets) && direct.IsValid() {
			if _, err := sockets[directSocket].WriteToUDPAddrPort(packet, direct); err == nil {
				continue
			}
		}
		wrote := false
		for _, u := range sockets {
			for _, address := range candidates {
				if _, err := u.WriteToUDPAddrPort(packet, address); err == nil {
					wrote = true
				}
			}
		}
		if !wrote {
			b.recordDrop()
		}
	}
	return nil
}

// recordDrop counts a datagram that the bind could not hand to any path. The
// tunnel already tracks drops it makes itself; this covers sends that fail
// below it so a broken path is visible instead of silently "succeeding".
func (b *meshBind) recordDrop() {
	if b.onDrop != nil {
		b.onDrop()
	}
}

func (b *meshBind) updatePeer(ip netip.Addr, publicKey string, candidates []netip.AddrPort) error {
	priv, err := ecdh.X25519().NewPrivateKey(b.private)
	if err != nil {
		return err
	}
	pubBytes, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		return err
	}
	pub, err := ecdh.X25519().NewPublicKey(pubBytes)
	if err != nil {
		return err
	}
	shared, err := priv.ECDH(pub)
	if err != nil {
		return err
	}
	hash := hmac.New(sha256.New, shared)
	hash.Write([]byte("LANMesh path probe v1/" + b.networkID))
	key := hash.Sum(nil)
	b.mu.Lock()
	defer b.mu.Unlock()
	r := b.routes[ip]
	if r == nil || !hmac.Equal(r.key, key) {
		if r != nil && r.relay != nil {
			r.relay.Close()
		}
		r = &peerRoute{key: key}
		b.routes[ip] = r
	}
	r.candidates = append([]netip.AddrPort(nil), candidates...)
	return nil
}
func (b *meshBind) removePeer(ip netip.Addr) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if r := b.routes[ip]; r != nil && r.relay != nil {
		r.relay.Close()
	}
	delete(b.routes, ip)
}
func (b *meshBind) hasRelay(ip netip.Addr, minRemaining time.Duration) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	r := b.routes[ip]
	return r != nil && r.relay != nil && r.relayExpiry.After(time.Now().Add(minRemaining))
}
func (b *meshBind) attachRelay(ip netip.Addr, relay *network.StreamRelay, expiry time.Time) bool {
	b.mu.Lock()
	r := b.routes[ip]
	if r == nil || b.udp == nil {
		b.mu.Unlock()
		relay.Close()
		return false
	}
	if r.relay != nil {
		r.relay.Close()
	}
	r.relay = relay
	r.relayExpiry = expiry
	done, in := b.done, b.in
	b.mu.Unlock()
	go func() {
		defer relay.Close()
		defer func() {
			b.mu.Lock()
			if r.relay == relay {
				r.relay = nil
			}
			b.mu.Unlock()
		}()
		for {
			packet, err := relay.ReceivePacket()
			if err != nil {
				return
			}
			select {
			case in <- datagram{packet, ip}:
			case <-done:
				return
			default:
			}
		}
	}()
	return true
}
func (b *meshBind) readUDP(u *net.UDPConn, done <-chan struct{}, in chan<- datagram, socketIndex int) {
	buffer := make([]byte, 65536)
	for {
		n, addr, err := u.ReadFromUDPAddrPort(buffer)
		if err != nil {
			return
		}
		addr = netip.AddrPortFrom(addr.Addr().Unmap(), addr.Port())
		packet := buffer[:n]
		if n >= 20 && binary.BigEndian.Uint32(packet[4:8]) == 0x2112a442 {
			var transaction [12]byte
			copy(transaction[:], packet[8:20])
			b.mu.RLock()
			pending := b.stun[transaction]
			b.mu.RUnlock()
			if pending != nil {
				select {
				case pending <- stunReply{packet: append([]byte(nil), packet...), source: addr, socket: socketIndex}:
				default:
				}
			}
			continue
		}
		if n == 41 && string(packet[:4]) == "LMP1" {
			if b.relayOnly {
				continue
			}
			b.handleProbeOn(u, packet, addr, socketIndex)
			continue
		}
		var peer netip.Addr
		b.mu.RLock()
		for ip, r := range b.routes {
			if r.direct == addr || containsAddrPort(r.candidates, addr) {
				peer = ip
				break
			}
		}
		b.mu.RUnlock()
		if !peer.IsValid() {
			continue
		}
		select {
		case in <- datagram{append([]byte(nil), packet...), peer}:
		case <-done:
			return
		default:
		}
	}
}

// checkLoop runs one authenticated connectivity check per tick. It is a single
// prober for ALL sockets rather than one goroutine per socket: a per-socket
// prober would repeatedly overwrite the route's outstanding probe and every
// reply but the last would be discarded as unmatched.
//
// Probing order follows the health of the pinned path: while it is answering,
// only that socket is probed (a probe on another socket would learn a mapping
// the peer's NAT has not seen and would move the flow). Only after the pinned
// path has failed directFailureThreshold times does probing fan out across the
// remaining sockets to find a better mapping.
func (b *meshBind) checkLoop(done <-chan struct{}) {
	if b.relayOnly {
		return
	}
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case now := <-ticker.C:
			b.probeOnce(now)
		}
	}
}

type probeSend struct {
	socket int
	addr   netip.AddrPort
	data   []byte
}

func (b *meshBind) probeOnce(now time.Time) {
	b.mu.RLock()
	sockets := append([]*net.UDPConn{b.udp}, b.extra...)
	b.mu.RUnlock()
	if len(sockets) == 0 || sockets[0] == nil {
		return
	}

	var sends []probeSend
	var routes []netip.Addr

	b.mu.Lock()
	for ip, r := range b.routes {
		if r.pending == nil {
			r.pending = make(map[[8]byte]pendingProbe)
		}
		// Retire probes that can no longer be answered. A timed-out probe on the
		// pinned socket is evidence of path trouble, not evidence about any
		// other socket.
		for nonce, probe := range r.pending {
			if now.Sub(probe.sent) < directProbeTimeout {
				continue
			}
			delete(r.pending, nonce)
			if r.directSocket == probe.socket {
				r.observeFailure(now)
			}
		}
		targets := b.socketsToProbe(r)
		for _, socket := range targets {
			var nonce [8]byte
			if _, err := rand.Read(nonce[:]); err != nil {
				continue
			}
			r.pending[nonce] = pendingProbe{socket: socket, sent: now}
			packet := make([]byte, 41)
			copy(packet, "LMP1")
			packet[4] = 1
			copy(packet[5:9], b.local.AsSlice())
			binary.BigEndian.PutUint64(packet[9:17], uint64(now.Unix()))
			copy(packet[17:25], nonce[:])
			signProbe(packet, r.key)
			for _, address := range r.candidates {
				sends = append(sends, probeSend{socket: socket, addr: address, data: packet})
			}
			if r.direct.IsValid() {
				sends = append(sends, probeSend{socket: socket, addr: r.direct, data: packet})
			}
		}
		routes = append(routes, ip)
	}
	// Bound the outstanding set: an unreachable peer must not grow it forever.
	for _, ip := range routes {
		if r := b.routes[ip]; r != nil && len(r.pending) > 512 {
			r.pending = make(map[[8]byte]pendingProbe)
		}
	}
	b.mu.Unlock()

	for _, send := range sends {
		if send.socket < 0 || send.socket >= len(sockets) || sockets[send.socket] == nil {
			continue
		}
		_, _ = sockets[send.socket].WriteToUDPAddrPort(send.data, send.addr)
	}
}

// socketsToProbe returns the sockets worth probing for this route. While the
// pinned mapping is healthy only it is probed; otherwise every socket is, so a
// closed port can be replaced.
func (b *meshBind) socketsToProbe(r *peerRoute) []int {
	total := 1 + len(b.extra)
	if r.direct.IsValid() && r.directSocket >= 0 && r.directSocket < total && r.failures < directFailureThreshold {
		return []int{r.directSocket}
	}
	all := make([]int, 0, total)
	for index := 0; index < total; index++ {
		all = append(all, index)
	}
	return all
}

func containsAddrPort(values []netip.AddrPort, target netip.AddrPort) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func signProbe(packet, key []byte) {
	hash := hmac.New(sha256.New, key)
	hash.Write(packet[:25])
	copy(packet[25:], hash.Sum(nil)[:16])
}
func (b *meshBind) handleProbe(u *net.UDPConn, packet []byte, addr netip.AddrPort) {
	b.handleProbeOn(u, packet, addr, 0)
}

func (b *meshBind) handleProbeOn(u *net.UDPConn, packet []byte, addr netip.AddrPort, socketIndex int) {
	peer := netip.AddrFrom4([4]byte(packet[5:9]))
	stamp := int64(binary.BigEndian.Uint64(packet[9:17]))
	if delta := time.Now().Unix() - stamp; delta > 10 || delta < -10 {
		return
	}
	b.mu.Lock()
	r := b.routes[peer]
	if r == nil {
		b.mu.Unlock()
		return
	}
	expected := append([]byte(nil), packet...)
	signProbe(expected, r.key)
	if !hmac.Equal(expected[25:], packet[25:]) {
		b.mu.Unlock()
		return
	}
	if packet[4] == 2 {
		var nonce [8]byte
		copy(nonce[:], packet[17:25])
		if probe, ok := r.pending[nonce]; ok {
			delete(r.pending, nonce)
			// Only a reply received on the socket that carried the probe proves
			// that socket's NAT mapping works; ignore cross-socket echoes.
			if probe.socket == socketIndex {
				r.observeSuccess(time.Now(), addr, socketIndex, measuredRTT(time.Since(probe.sent)))
			}
			b.mu.Unlock()
			return
		}
	}
	if packet[4] != 1 {
		b.mu.Unlock()
		return
	}
	reply := append([]byte(nil), packet...)
	reply[4] = 2
	copy(reply[5:9], b.local.AsSlice())
	signProbe(reply, r.key)
	b.mu.Unlock()
	_, _ = u.WriteToUDPAddrPort(reply, addr)
}

// probeSTUN uses the active primary WireGuard UDP port; probing a temporary
// socket would advertise a different NAT mapping and silently break punching.
func (b *meshBind) probeSTUN(ctx context.Context, server string) (netip.AddrPort, error) {
	b.mu.RLock()
	u := b.udp
	b.mu.RUnlock()
	return b.probeSTUNOn(ctx, server, u, 0)
}

func (b *meshBind) probeSTUNOn(ctx context.Context, server string, u *net.UDPConn, socketIndex int) (netip.AddrPort, error) {
	if u == nil {
		return netip.AddrPort{}, net.ErrClosed
	}
	host, portValue, err := net.SplitHostPort(server)
	if err != nil {
		return netip.AddrPort{}, err
	}
	port, err := strconv.ParseUint(portValue, 10, 16)
	if err != nil || port == 0 {
		return netip.AddrPort{}, errors.New("invalid STUN port")
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		resolved, lookupErr := net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
		if lookupErr != nil {
			return netip.AddrPort{}, lookupErr
		}
		if len(resolved) == 0 {
			return netip.AddrPort{}, errors.New("STUN has no IPv4 address")
		}
		ip = resolved[0]
	}
	if !ip.Is4() {
		return netip.AddrPort{}, errors.New("STUN socket uses IPv4")
	}
	address := net.UDPAddrFromAddrPort(netip.AddrPortFrom(ip, uint16(port)))
	var id [12]byte
	if _, err = rand.Read(id[:]); err != nil {
		return netip.AddrPort{}, err
	}
	response := make(chan stunReply, 1)
	b.mu.Lock()
	b.stun[id] = response
	b.mu.Unlock()
	defer func() { b.mu.Lock(); delete(b.stun, id); b.mu.Unlock() }()
	packet := make([]byte, 20)
	binary.BigEndian.PutUint16(packet, 1)
	binary.BigEndian.PutUint32(packet[4:], 0x2112a442)
	copy(packet[8:], id[:])
	if _, err = u.WriteToUDP(packet, address); err != nil {
		return netip.AddrPort{}, err
	}
	select {
	case <-ctx.Done():
		return netip.AddrPort{}, ctx.Err()
	case reply := <-response:
		if reply.socket != socketIndex || reply.source != address.AddrPort() {
			return netip.AddrPort{}, fmt.Errorf("unexpected STUN source")
		}
		return network.DecodeSTUNMappedAddress(reply.packet, id)
	}
}

func (b *meshBind) ports() []uint16 {
	b.mu.RLock()
	defer b.mu.RUnlock()
	ports := make([]uint16, 0, 1+len(b.extra))
	if b.udp != nil {
		ports = append(ports, b.port)
	}
	for _, u := range b.extra {
		if u == nil {
			continue
		}
		if addr, ok := u.LocalAddr().(*net.UDPAddr); ok && addr.Port > 0 {
			ports = append(ports, uint16(addr.Port))
		}
	}
	return ports
}

func (b *meshBind) probeSTUNPorts(ctx context.Context, server string) ([]netip.AddrPort, error) {
	b.mu.RLock()
	sockets := append([]*net.UDPConn{b.udp}, b.extra...)
	b.mu.RUnlock()
	type result struct {
		address netip.AddrPort
		err     error
	}
	results := make(chan result, len(sockets))
	for index, u := range sockets {
		if u == nil {
			results <- result{err: net.ErrClosed}
			continue
		}
		index, u := index, u
		go func() {
			address, err := b.probeSTUNOn(ctx, server, u, index)
			results <- result{address: address, err: err}
		}()
	}
	var mapped []netip.AddrPort
	var firstErr error
	for range sockets {
		result := <-results
		if result.err != nil {
			if firstErr == nil {
				firstErr = result.err
			}
			continue
		}
		mapped = append(mapped, result.address)
	}
	if len(mapped) == 0 && firstErr != nil {
		return nil, firstErr
	}
	return mapped, nil
}
