//go:build windows

package frp

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/private-radminlan/lanmesh/internal/netpolicy"
	"golang.org/x/sys/windows"
)

const udpSessionIdleTimeout = 2 * time.Minute

// udpEgressProxy is a loopback-only UDP relay for FRP transports that cannot
// use FRP's TCP proxyURL option (KCP and QUIC). It resolves and pins every
// upstream socket to a non-TLAN route, while presenting a stable loopback
// endpoint to the fixed frpc process.
type udpEgressProxy struct {
	listener      *net.UDPConn
	observer      netpolicy.Observer
	endpoint      netpolicy.Endpoint
	protected     []netip.Prefix
	meshInterface string

	ctx    context.Context
	cancel context.CancelFunc

	mu        sync.Mutex
	sessions  map[string]*udpRelaySession
	closing   bool
	wg        sync.WaitGroup
	closeOnce sync.Once
}

type udpRelaySession struct {
	proxy    *udpEgressProxy
	client   *net.UDPAddr
	upstream *net.UDPConn
	lastSeen atomic.Int64
	closed   atomic.Bool
}

func startUDPEgressProxy(parent context.Context, observer netpolicy.Observer, cfg Config, protected []netip.Prefix, meshInterface string) (*udpEgressProxy, error) {
	if parent == nil {
		parent = context.Background()
	}
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		return nil, codedError(CodeLocalListenBusy, "启动 FRPS UDP 出口代理失败: %v", err)
	}
	ctx, cancel := context.WithCancel(parent)
	proxy := &udpEgressProxy{
		listener: listener, observer: observer,
		endpoint:  netpolicy.Endpoint{Host: cfg.Profile.Server.Host, Port: cfg.Profile.Server.Port, Label: "FRPS UDP control endpoint"},
		protected: append([]netip.Prefix(nil), protected...), meshInterface: meshInterface,
		ctx: ctx, cancel: cancel, sessions: make(map[string]*udpRelaySession),
	}
	proxy.wg.Add(2)
	go proxy.serve()
	go proxy.reapIdle()
	return proxy, nil
}

func (p *udpEgressProxy) Address() netip.AddrPort {
	if p == nil || p.listener == nil {
		return netip.AddrPort{}
	}
	addr, ok := p.listener.LocalAddr().(*net.UDPAddr)
	if !ok || addr == nil {
		return netip.AddrPort{}
	}
	return addr.AddrPort()
}

func (p *udpEgressProxy) Close() error {
	if p == nil {
		return nil
	}
	p.closeOnce.Do(func() {
		p.mu.Lock()
		p.closing = true
		p.mu.Unlock()
		p.cancel()
		_ = p.listener.Close()
		p.mu.Lock()
		sessions := make([]*udpRelaySession, 0, len(p.sessions))
		for _, session := range p.sessions {
			sessions = append(sessions, session)
		}
		p.mu.Unlock()
		for _, session := range sessions {
			session.close()
		}
		p.wg.Wait()
	})
	return nil
}

func (p *udpEgressProxy) serve() {
	defer p.wg.Done()
	buffer := make([]byte, 65535)
	for {
		n, clientAddr, err := p.listener.ReadFromUDP(buffer)
		if err != nil {
			if p.ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		if n == 0 {
			continue
		}
		session, err := p.sessionFor(clientAddr)
		if err != nil {
			continue
		}
		if _, err = session.upstream.Write(buffer[:n]); err != nil {
			p.removeSession(session)
		}
	}
}

func (p *udpEgressProxy) sessionFor(clientAddr *net.UDPAddr) (*udpRelaySession, error) {
	if clientAddr == nil {
		return nil, errors.New("UDP client address is nil")
	}
	client := *clientAddr
	key := client.String()
	p.mu.Lock()
	if p.closing {
		p.mu.Unlock()
		return nil, errors.New("UDP egress proxy is closing")
	}
	if session := p.sessions[key]; session != nil && !session.closed.Load() {
		session.lastSeen.Store(time.Now().UnixNano())
		p.mu.Unlock()
		return session, nil
	}
	p.mu.Unlock()

	upstream, err := p.dialUpstream(p.ctx)
	if err != nil {
		return nil, err
	}
	session := &udpRelaySession{proxy: p, client: &client, upstream: upstream}
	session.lastSeen.Store(time.Now().UnixNano())
	p.mu.Lock()
	if p.closing {
		p.mu.Unlock()
		session.close()
		return nil, errors.New("UDP egress proxy is closing")
	}
	if existing := p.sessions[key]; existing != nil && !existing.closed.Load() {
		p.mu.Unlock()
		session.close()
		return existing, nil
	}
	p.sessions[key] = session
	p.wg.Add(1)
	p.mu.Unlock()
	go session.readLoop()
	return session, nil
}

func (p *udpEgressProxy) dialUpstream(ctx context.Context) (*net.UDPConn, error) {
	planner := netpolicy.Planner{Observer: p.observer}
	routes, err := planner.ResolveControlRoutes(ctx, p.endpoint, p.protected, p.meshInterface)
	if err != nil {
		return nil, err
	}
	var lastErr error
	for _, route := range routes {
		conn, err := dialUDPRoute(ctx, p.endpoint, route)
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("no UDP route was available")
	}
	return nil, lastErr
}

func dialUDPRoute(ctx context.Context, endpoint netpolicy.Endpoint, route netpolicy.Route) (*net.UDPConn, error) {
	address := endpoint.Host
	if route.Destination.IsValid() {
		address = route.Destination.String()
	}
	dialer := net.Dialer{Timeout: 10 * time.Second}
	if route.InterfaceIndex != 0 && !route.Destination.IsLoopback() {
		index := route.InterfaceIndex
		dialer.Control = func(_, _ string, raw syscall.RawConn) error {
			var socketErr error
			if err := raw.Control(func(fd uintptr) {
				socketErr = bindUDPSocketToInterface(windows.Handle(fd), index)
			}); err != nil {
				return err
			}
			return socketErr
		}
	}
	conn, err := dialer.DialContext(ctx, "udp4", net.JoinHostPort(address, fmt.Sprint(endpoint.Port)))
	if err != nil {
		return nil, err
	}
	udp, ok := conn.(*net.UDPConn)
	if !ok {
		_ = conn.Close()
		return nil, errors.New("UDP route returned a non-UDP connection")
	}
	return udp, nil
}

func bindUDPSocketToInterface(handle windows.Handle, interfaceIndex uint32) error {
	const ipUnicastIf = 31
	var networkOrder [4]byte
	binary.BigEndian.PutUint32(networkOrder[:], interfaceIndex)
	value := *(*uint32)(unsafe.Pointer(&networkOrder[0]))
	return windows.SetsockoptInt(handle, windows.IPPROTO_IP, ipUnicastIf, int(value))
}

func (s *udpRelaySession) readLoop() {
	defer s.proxy.wg.Done()
	buffer := make([]byte, 65535)
	for {
		n, err := s.upstream.Read(buffer)
		if err != nil {
			s.proxy.removeSession(s)
			return
		}
		if n == 0 {
			continue
		}
		if _, err = s.proxy.listener.WriteToUDP(buffer[:n], s.client); err != nil {
			s.proxy.removeSession(s)
			return
		}
		s.lastSeen.Store(time.Now().UnixNano())
	}
}

func (s *udpRelaySession) close() {
	if s == nil {
		return
	}
	if s.closed.CompareAndSwap(false, true) {
		_ = s.upstream.Close()
	}
}

func (p *udpEgressProxy) removeSession(session *udpRelaySession) {
	if session == nil {
		return
	}
	key := session.client.String()
	p.mu.Lock()
	if p.sessions[key] == session {
		delete(p.sessions, key)
	}
	p.mu.Unlock()
	session.close()
}

func (p *udpEgressProxy) reapIdle() {
	defer p.wg.Done()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-p.ctx.Done():
			return
		case now := <-ticker.C:
			cutoff := now.Add(-udpSessionIdleTimeout).UnixNano()
			p.mu.Lock()
			stale := make([]*udpRelaySession, 0)
			for key, session := range p.sessions {
				if session.lastSeen.Load() < cutoff {
					delete(p.sessions, key)
					stale = append(stale, session)
				}
			}
			p.mu.Unlock()
			for _, session := range stale {
				session.close()
			}
		}
	}
}
