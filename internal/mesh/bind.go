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

type peerRoute struct {
	key         []byte
	candidates  []netip.AddrPort
	direct      netip.AddrPort
	lastDirect  time.Time
	nonce       [8]byte
	pingStarted time.Time
	rtt         time.Duration
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
	port      uint16
	done      chan struct{}
	in        chan datagram
	routes    map[netip.Addr]*peerRoute
	stun      map[[12]byte]chan stunReply
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
	u, err := net.ListenUDP("udp4", &net.UDPAddr{Port: int(port)})
	if err != nil {
		return nil, 0, err
	}
	b.udp = u
	b.port = uint16(u.LocalAddr().(*net.UDPAddr).Port)
	b.done = make(chan struct{})
	b.in = make(chan datagram, 1024)
	done, in := b.done, b.in
	go b.readUDP(u, done, in)
	go b.checkLoop(u, done)
	receive := func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		select {
		case <-done:
			return 0, net.ErrClosed
		case packet := <-in:
			sizes[0] = copy(packets[0], packet.data)
			eps[0] = &endpoint{netip.AddrPortFrom(packet.peer, 1)}
			return 1, nil
		}
	}
	return []conn.ReceiveFunc{receive}, b.port, nil
}
func (b *meshBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.udp == nil {
		return nil
	}
	close(b.done)
	err := b.udp.Close()
	b.udp = nil
	for _, r := range b.routes {
		if r.relay != nil {
			r.relay.Close()
			r.relay = nil
		}
	}
	return err
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
func (b *meshBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	b.mu.RLock()
	r := b.routes[ep.DstIP()]
	u := b.udp
	if r == nil || u == nil {
		b.mu.RUnlock()
		return nil
	}
	direct, fresh, relay := r.direct, time.Since(r.lastDirect) < 10*time.Second, r.relay
	candidates := append([]netip.AddrPort(nil), r.candidates...)
	b.mu.RUnlock()
	for _, packet := range bufs {
		if fresh && direct.IsValid() && !b.relayOnly {
			_, _ = u.WriteToUDPAddrPort(packet, direct)
			continue
		}
		if relay != nil {
			if err := relay.Send(packet); err == nil {
				continue
			}
		}
		if b.relayOnly {
			continue
		}
		for _, address := range candidates {
			_, _ = u.WriteToUDPAddrPort(packet, address)
		}
	}
	return nil
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
func (b *meshBind) hasRelay(ip netip.Addr) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	r := b.routes[ip]
	return r != nil && r.relay != nil && time.Until(r.relayExpiry) > 0
}
func (b *meshBind) attachRelay(ip netip.Addr, relay *network.StreamRelay, expiry time.Time) {
	b.mu.Lock()
	r := b.routes[ip]
	if r == nil || b.udp == nil {
		b.mu.Unlock()
		relay.Close()
		return
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
}
func (b *meshBind) readUDP(u *net.UDPConn, done <-chan struct{}, in chan<- datagram) {
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
				case pending <- stunReply{append([]byte(nil), packet...), addr}:
				default:
				}
			}
			continue
		}
		if n == 41 && string(packet[:4]) == "LMP1" {
			if b.relayOnly {
				continue
			}
			b.handleProbe(u, packet, addr)
			continue
		}
		var peer netip.Addr
		b.mu.RLock()
		for ip, r := range b.routes {
			if r.direct == addr {
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
func (b *meshBind) checkLoop(u *net.UDPConn, done <-chan struct{}) {
	if b.relayOnly {
		return
	}
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			type send struct {
				addr netip.AddrPort
				data []byte
			}
			var sends []send
			b.mu.Lock()
			for _, r := range b.routes {
				_, _ = rand.Read(r.nonce[:])
				r.pingStarted = time.Now()
				packet := make([]byte, 41)
				copy(packet, "LMP1")
				packet[4] = 1
				copy(packet[5:9], b.local.AsSlice())
				binary.BigEndian.PutUint64(packet[9:17], uint64(time.Now().Unix()))
				copy(packet[17:25], r.nonce[:])
				signProbe(packet, r.key)
				for _, addr := range r.candidates {
					sends = append(sends, send{addr, packet})
				}
				if r.direct.IsValid() {
					sends = append(sends, send{r.direct, packet})
				}
			}
			b.mu.Unlock()
			for _, s := range sends {
				_, _ = u.WriteToUDPAddrPort(s.data, s.addr)
			}
		}
	}
}
func signProbe(packet, key []byte) {
	hash := hmac.New(sha256.New, key)
	hash.Write(packet[:25])
	copy(packet[25:], hash.Sum(nil)[:16])
}
func (b *meshBind) handleProbe(u *net.UDPConn, packet []byte, addr netip.AddrPort) {
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
	if packet[4] == 2 && hmac.Equal(packet[17:25], r.nonce[:]) {
		r.direct = addr
		r.lastDirect = time.Now()
		r.rtt = time.Since(r.pingStarted)
		b.mu.Unlock()
		return
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

// probeSTUN uses the active WireGuard UDP port; probing a temporary socket
// would advertise a different NAT mapping and silently break hole punching.
func (b *meshBind) probeSTUN(ctx context.Context, server string) (netip.AddrPort, error) {
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
	u := b.udp
	b.stun[id] = response
	b.mu.Unlock()
	defer func() { b.mu.Lock(); delete(b.stun, id); b.mu.Unlock() }()
	if u == nil {
		return netip.AddrPort{}, net.ErrClosed
	}
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
		if reply.source != address.AddrPort() {
			return netip.AddrPort{}, fmt.Errorf("unexpected STUN source")
		}
		return network.DecodeSTUNMappedAddress(reply.packet, id)
	}
}
