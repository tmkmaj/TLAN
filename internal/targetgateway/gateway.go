package targetgateway

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

type gatewayCounters struct {
	tcpAccepted   atomic.Uint64
	tcpRejected   atomic.Uint64
	tcpActive     atomic.Int64
	udpAccepted   atomic.Uint64
	udpDropped    atomic.Uint64
	udpActive     atomic.Int64
	leaseReject   atomic.Uint64
	dialFailure   atomic.Uint64
	bytesTo       atomic.Uint64
	bytesFrom     atomic.Uint64
	datagramsTo   atomic.Uint64
	datagramsFrom atomic.Uint64
}

// Gateway is one loopback listener for one protocol and one immutable Target.
type Gateway struct {
	cfg    Config
	ctx    context.Context
	cancel context.CancelFunc

	tcp *net.TCPListener
	udp *net.UDPConn

	addr       netip.AddrPort
	generation uint64
	wg         sync.WaitGroup
	leaseWG    sync.WaitGroup

	closeOnce    sync.Once
	done         chan struct{}
	leaseInvalid chan struct{}
	leaseErr     error
	leaseOnce    sync.Once

	mu       sync.Mutex
	closed   bool
	lastErr  error
	pairs    map[*tcpPair]struct{}
	sessions map[netip.AddrPort]*udpSession
	stats    gatewayCounters
}

// Start binds 127.0.0.1 and begins serving. The requested port may be zero.
// Start never contacts a target; the first accepted connection or datagram is
// validated against the injected lease before any backend dial is attempted.
func Start(parent context.Context, cfg Config) (*Gateway, error) {
	if parent == nil {
		return nil, errors.New("context is required")
	}
	if err := parent.Err(); err != nil {
		return nil, err
	}
	normalized, err := cfg.normalized()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(parent)
	initialLease, err := acquireLease(ctx, normalized.Lease, normalized.Target)
	if err != nil {
		cancel()
		return nil, err
	}
	g := &Gateway{
		cfg:          normalized,
		ctx:          ctx,
		cancel:       cancel,
		done:         make(chan struct{}),
		leaseInvalid: make(chan struct{}),
		generation:   initialLease.Generation,
		pairs:        make(map[*tcpPair]struct{}),
		sessions:     make(map[netip.AddrPort]*udpSession),
	}
	switch normalized.Protocol {
	case ProtocolTCP:
		listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(normalized.ListenPort)})
		if err != nil {
			cancel()
			return nil, fmt.Errorf("listen TCP target gateway: %w", err)
		}
		g.tcp = listener
		g.addr = listener.Addr().(*net.TCPAddr).AddrPort()
	case ProtocolUDP:
		conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(normalized.ListenPort)})
		if err != nil {
			cancel()
			return nil, fmt.Errorf("listen UDP target gateway: %w", err)
		}
		g.udp = conn
		g.addr = conn.LocalAddr().(*net.UDPAddr).AddrPort()
	default:
		cancel()
		return nil, fmt.Errorf("unsupported target gateway protocol %q", normalized.Protocol)
	}
	if err := ctx.Err(); err != nil {
		g.closeListeners()
		cancel()
		return nil, err
	}
	g.wg.Add(1)
	if g.cfg.Protocol == ProtocolTCP {
		go g.serveTCP()
	} else {
		go g.serveUDP()
	}
	go func() {
		<-ctx.Done()
		_ = g.Close()
	}()
	g.leaseWG.Add(1)
	go func() {
		defer g.leaseWG.Done()
		g.watchLease()
	}()
	return g, nil
}

// Close stops listeners, closes every tracked stream/session, and waits for
// all gateway goroutines before closing Done.
func (g *Gateway) Close() error {
	if g == nil {
		return nil
	}
	g.closeOnce.Do(func() {
		g.cancel()
		g.mu.Lock()
		g.closed = true
		g.mu.Unlock()
		g.closeListeners()

		g.mu.Lock()
		pairs := make([]*tcpPair, 0, len(g.pairs))
		for pair := range g.pairs {
			pairs = append(pairs, pair)
		}
		g.pairs = make(map[*tcpPair]struct{})
		sessions := make([]*udpSession, 0, len(g.sessions))
		for _, session := range g.sessions {
			sessions = append(sessions, session)
		}
		g.sessions = make(map[netip.AddrPort]*udpSession)
		g.mu.Unlock()

		for _, pair := range pairs {
			pair.close()
		}
		for _, session := range sessions {
			session.close(g, ErrClosed)
		}
		g.wg.Wait()
		g.leaseWG.Wait()
		close(g.done)
	})
	return nil
}

func (g *Gateway) closeListeners() {
	if g.tcp != nil {
		_ = g.tcp.Close()
	}
	if g.udp != nil {
		_ = g.udp.Close()
	}
}

// Addr is the actual loopback listener address. Its address component is
// always 127.0.0.1.
func (g *Gateway) Addr() netip.AddrPort { return g.addr }

// Protocol returns the transport served by this Gateway.
func (g *Gateway) Protocol() Protocol { return g.cfg.Protocol }

// Done is closed after Close has stopped all listeners and active traffic.
func (g *Gateway) Done() <-chan struct{} { return g.done }

// Err reports a fatal listener/serving error. Lease revocation is not fatal:
// the gateway keeps listening but rejects traffic until a valid lease returns.
func (g *Gateway) LeaseInvalid() <-chan struct{} { return g.leaseInvalid }

func (g *Gateway) LeaseErr() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.leaseErr
}

func (g *Gateway) watchLease() {
	ticker := time.NewTicker(g.cfg.LeasePollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-g.ctx.Done():
			return
		case <-ticker.C:
			lease, err := acquireLease(g.ctx, g.cfg.Lease, g.cfg.Target)
			if err == nil && lease.Generation != g.generation {
				err = fmt.Errorf("%w: expected %d, got %d", ErrLeaseChanged, g.generation, lease.Generation)
			}
			if err != nil {
				g.leaseOnce.Do(func() {
					g.mu.Lock()
					g.leaseErr = err
					g.mu.Unlock()
					close(g.leaseInvalid)
				})
				return
			}
		}
	}
}

func (g *Gateway) Err() error {
	if g == nil {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.lastErr
}

// Stats returns counters for this gateway instance.
func (g *Gateway) Stats() Stats {
	if g == nil {
		return Stats{}
	}
	activeTCP := g.stats.tcpActive.Load()
	if activeTCP < 0 {
		activeTCP = 0
	}
	activeUDP := g.stats.udpActive.Load()
	if activeUDP < 0 {
		activeUDP = 0
	}
	return Stats{
		LeaseGeneration:     g.generation,
		TCPAccepted:         g.stats.tcpAccepted.Load(),
		TCPActive:           uint64(activeTCP),
		TCPRejected:         g.stats.tcpRejected.Load(),
		UDPAccepted:         g.stats.udpAccepted.Load(),
		UDPActive:           uint64(activeUDP),
		UDPDropped:          g.stats.udpDropped.Load(),
		LeaseRejections:     g.stats.leaseReject.Load(),
		DialFailures:        g.stats.dialFailure.Load(),
		BytesToTarget:       g.stats.bytesTo.Load(),
		BytesFromTarget:     g.stats.bytesFrom.Load(),
		DatagramsToTarget:   g.stats.datagramsTo.Load(),
		DatagramsFromTarget: g.stats.datagramsFrom.Load(),
	}
}

func (g *Gateway) setFatal(err error) {
	if err == nil || g.ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
		return
	}
	g.mu.Lock()
	if g.lastErr == nil {
		g.lastErr = err
	}
	g.mu.Unlock()
	g.cancel()
}

func (g *Gateway) recordLeaseRejection(err error) {
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || g.ctx.Err() != nil {
		return
	}
	g.stats.leaseReject.Add(1)
}

func (g *Gateway) tryTCPActive() bool {
	for {
		current := g.stats.tcpActive.Load()
		if current >= int64(g.cfg.MaxConnections) {
			return false
		}
		if g.stats.tcpActive.CompareAndSwap(current, current+1) {
			return true
		}
	}
}

func (g *Gateway) registerPair(pair *tcpPair) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return false
	}
	g.pairs[pair] = struct{}{}
	return true
}

func (g *Gateway) removePair(pair *tcpPair) {
	g.mu.Lock()
	delete(g.pairs, pair)
	g.mu.Unlock()
}

func (g *Gateway) removeSession(session *udpSession) {
	g.mu.Lock()
	if current := g.sessions[session.client]; current == session {
		delete(g.sessions, session.client)
	}
	g.mu.Unlock()
}

func (g *Gateway) serveTCP() {
	defer g.wg.Done()
	var delay time.Duration
	for {
		conn, err := g.tcp.AcceptTCP()
		if err != nil {
			if g.ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			if temporary, ok := err.(net.Error); ok && temporary.Temporary() {
				if delay == 0 {
					delay = 5 * time.Millisecond
				} else {
					delay *= 2
					if delay > 250*time.Millisecond {
						delay = 250 * time.Millisecond
					}
				}
				select {
				case <-g.ctx.Done():
					return
				case <-time.After(delay):
					continue
				}
			}
			g.setFatal(fmt.Errorf("accept TCP target gateway: %w", err))
			return
		}
		delay = 0
		if g.ctx.Err() != nil {
			_ = conn.Close()
			return
		}
		_ = conn.SetKeepAlive(true)
		_ = conn.SetKeepAlivePeriod(30 * time.Second)
		if !g.tryTCPActive() {
			g.stats.tcpRejected.Add(1)
			_ = conn.Close()
			continue
		}
		g.stats.tcpAccepted.Add(1)
		g.wg.Add(1)
		go func() {
			defer g.wg.Done()
			defer g.stats.tcpActive.Add(-1)
			g.handleTCP(conn)
		}()
	}
}

func (g *Gateway) serveUDP() {
	defer g.wg.Done()
	buffer := make([]byte, maxUDPReadBuffer)
	for {
		n, client, err := g.udp.ReadFromUDPAddrPort(buffer)
		if err != nil {
			if g.ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			g.setFatal(fmt.Errorf("read UDP target gateway: %w", err))
			return
		}
		client = netip.AddrPortFrom(client.Addr().Unmap(), client.Port())
		if !client.Addr().IsLoopback() {
			g.stats.udpDropped.Add(1)
			continue
		}
		if n > g.cfg.MaxDatagramSize {
			g.stats.udpDropped.Add(1)
			continue
		}
		lease, err := acquireLease(g.ctx, g.cfg.Lease, g.cfg.Target)
		if err != nil {
			g.recordLeaseRejection(err)
			g.stats.udpDropped.Add(1)
			continue
		}
		data := append([]byte(nil), buffer[:n]...)
		g.dispatchUDP(client, data, lease)
	}
}
