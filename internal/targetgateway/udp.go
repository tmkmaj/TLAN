package targetgateway

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

type udpSession struct {
	client     netip.AddrPort
	initial    Lease
	send       chan []byte
	done       chan struct{}
	once       sync.Once
	mu         sync.Mutex
	backend    net.Conn
	lastActive atomic.Int64
}

func newUDPSession(client netip.AddrPort, initial Lease, queueDepth int) *udpSession {
	session := &udpSession{
		client:  client,
		initial: initial,
		send:    make(chan []byte, queueDepth),
		done:    make(chan struct{}),
	}
	session.touch()
	return session
}

func (s *udpSession) Generation() uint64 { return s.initial.Generation }

func (s *udpSession) IsClosed() bool {
	select {
	case <-s.done:
		return true
	default:
		return false
	}
}

func (s *udpSession) enqueue(data []byte) bool {
	select {
	case <-s.done:
		return false
	default:
	}
	select {
	case s.send <- data:
		return true
	case <-s.done:
		return false
	default:
		return false
	}
}

func (s *udpSession) attach(conn net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	select {
	case <-s.done:
		return false
	default:
	}
	s.backend = conn
	return true
}

func (s *udpSession) close(g *Gateway, reason error) {
	if s == nil {
		return
	}
	s.once.Do(func() {
		close(s.done)
		s.mu.Lock()
		backend := s.backend
		s.backend = nil
		s.mu.Unlock()
		if backend != nil {
			_ = backend.Close()
		}
		if g != nil {
			g.removeSession(s)
			g.stats.udpActive.Add(-1)
		}
	})
}

func (s *udpSession) touch() {
	s.lastActive.Store(time.Now().UnixNano())
}

func (g *Gateway) dispatchUDP(client netip.AddrPort, data []byte, lease Lease) {
	var stale *udpSession
	start := false

	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		g.stats.udpDropped.Add(1)
		return
	}
	session := g.sessions[client]
	if session != nil && (session.Generation() != lease.Generation || session.IsClosed()) {
		delete(g.sessions, client)
		stale = session
		session = nil
	}
	if session == nil {
		if len(g.sessions) >= g.cfg.MaxUDPSessions {
			g.mu.Unlock()
			if stale != nil {
				stale.close(g, ErrLeaseChanged)
			}
			g.stats.udpDropped.Add(1)
			return
		}
		session = newUDPSession(client, lease, g.cfg.UDPQueueDepth)
		g.sessions[client] = session
		g.stats.udpAccepted.Add(1)
		g.stats.udpActive.Add(1)
		start = true
		g.wg.Add(1)
	}
	g.mu.Unlock()

	if stale != nil {
		stale.close(g, ErrLeaseChanged)
	}
	if start {
		go session.run(g)
	}
	if !session.enqueue(data) {
		g.stats.udpDropped.Add(1)
	}
}

func (s *udpSession) run(g *Gateway) {
	defer g.wg.Done()
	ctx, cancel := context.WithCancel(g.ctx)
	defer cancel()
	guard := newLeaseGuard(g.cfg.Lease, g.cfg.Target, s.initial, g.cfg.LeasePollInterval)
	go guard.watch(ctx)

	if s.IsClosed() {
		return
	}
	select {
	case <-ctx.Done():
		return
	default:
	}

	var backendWG sync.WaitGroup
	defer func() {
		cancel()
		guard.wait()
		s.close(g, ErrClosed)
		backendWG.Wait()
	}()

	dialCtx, dialCancel := context.WithTimeout(ctx, g.cfg.DialTimeout)
	backend, err := g.cfg.Dialer.DialUDP(dialCtx, g.cfg.Target, s.initial.Generation)
	dialCancel()
	if err != nil {
		if ctx.Err() == nil {
			g.stats.dialFailure.Add(1)
		}
		return
	}
	if backend == nil {
		g.stats.dialFailure.Add(1)
		return
	}
	if err := guard.check(ctx); err != nil {
		g.recordLeaseRejection(err)
		_ = backend.Close()
		return
	}
	if !s.attach(backend) {
		_ = backend.Close()
		return
	}
	s.touch()

	monitorDone := make(chan struct{})
	var monitorWG sync.WaitGroup
	monitorWG.Add(1)
	go func() {
		defer monitorWG.Done()
		select {
		case <-ctx.Done():
		case <-guard.Invalid():
		case <-s.done:
		case <-monitorDone:
		}
		s.close(g, ErrClosed)
	}()
	defer func() {
		close(monitorDone)
		monitorWG.Wait()
	}()

	backendWG.Add(1)
	go func() {
		defer backendWG.Done()
		s.readBackend(g, ctx, guard, backend)
	}()

	checkInterval := idleCheckInterval(g.cfg.IdleTimeout)
	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.done:
			return
		case <-guard.Invalid():
			return
		case data := <-s.send:
			if err := guard.check(ctx); err != nil {
				g.recordLeaseRejection(err)
				return
			}
			_ = backend.SetWriteDeadline(time.Now().Add(g.cfg.WriteTimeout))
			n, err := writeAll(backend, data)
			if n > 0 {
				g.stats.datagramsTo.Add(1)
			}
			if err != nil {
				g.stats.udpDropped.Add(1)
				return
			}
			if err := guard.check(ctx); err != nil {
				g.recordLeaseRejection(err)
				return
			}
			s.touch()
		case <-ticker.C:
			last := time.Unix(0, s.lastActive.Load())
			if time.Since(last) >= g.cfg.IdleTimeout {
				return
			}
		}
	}
}

func (s *udpSession) readBackend(g *Gateway, ctx context.Context, guard *leaseGuard, backend net.Conn) {
	defer s.close(g, ErrClosed)
	buffer := make([]byte, maxUDPReadBuffer)
	for {
		n, err := backend.Read(buffer)
		if err != nil {
			if ctx.Err() == nil && !errors.Is(err, net.ErrClosed) {
				g.stats.udpDropped.Add(1)
			}
			return
		}
		if n <= 0 {
			continue
		}
		if n > g.cfg.MaxDatagramSize {
			g.stats.udpDropped.Add(1)
			continue
		}
		if err := guard.check(ctx); err != nil {
			g.recordLeaseRejection(err)
			return
		}
		_, err = g.udp.WriteToUDPAddrPort(buffer[:n], s.client)
		if err != nil {
			if ctx.Err() == nil && !errors.Is(err, net.ErrClosed) {
				g.stats.udpDropped.Add(1)
			}
			return
		}
		g.stats.datagramsFrom.Add(1)
		s.touch()
	}
}

func idleCheckInterval(idle time.Duration) time.Duration {
	interval := idle / 2
	if interval < 10*time.Millisecond {
		interval = 10 * time.Millisecond
	}
	if interval > time.Second {
		interval = time.Second
	}
	return interval
}
