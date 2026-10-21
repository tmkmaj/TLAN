//go:build windows

package frp

import (
	"bufio"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/private-radminlan/lanmesh/internal/netpolicy"
)

// egressProxy is a loopback-only, authenticated HTTP CONNECT proxy used by the
// fixed FRPC core for its TCP control connections. It only accepts the exact
// configured FRPS endpoint, re-resolves the route per connection, and pins the
// outbound socket to the selected non-TLAN interface.
type egressProxy struct {
	listener      net.Listener
	observer      netpolicy.Observer
	endpoint      netpolicy.Endpoint
	protected     []netip.Prefix
	meshInterface string

	username string
	password string

	ctx    context.Context
	cancel context.CancelFunc

	mu        sync.Mutex
	conns     map[net.Conn]struct{}
	wg        sync.WaitGroup
	closeOnce sync.Once
	connects  atomic.Uint64
	dials     atomic.Uint64
}

func startEgressProxy(parent context.Context, observer netpolicy.Observer, cfg Config, protected []netip.Prefix, meshInterface string) (*egressProxy, error) {
	if parent == nil {
		parent = context.Background()
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, codedError(CodeLocalListenBusy, "启动 FRPS 出口代理失败: %v", err)
	}
	username, err := NewSecret(18)
	if err != nil {
		_ = listener.Close()
		return nil, err
	}
	password, err := NewSecret(32)
	if err != nil {
		_ = listener.Close()
		return nil, err
	}
	ctx, cancel := context.WithCancel(parent)
	proxy := &egressProxy{
		listener: listener, observer: observer,
		endpoint: netpolicy.Endpoint{
			Host: cfg.Profile.Server.Host, Port: cfg.Profile.Server.Port, Label: "FRPS control endpoint",
		},
		protected: append([]netip.Prefix(nil), protected...), meshInterface: meshInterface,
		username: username, password: password, ctx: ctx, cancel: cancel,
		conns: make(map[net.Conn]struct{}),
	}
	proxy.wg.Add(1)
	go proxy.serve()
	go func() {
		<-ctx.Done()
		_ = proxy.Close()
	}()
	return proxy, nil
}

func (p *egressProxy) URL() string {
	if p == nil || p.listener == nil {
		return ""
	}
	return (&url.URL{
		Scheme: "http", Host: p.listener.Addr().String(),
		User: url.UserPassword(p.username, p.password),
	}).String()
}

func (p *egressProxy) Address() netip.AddrPort {
	if p == nil || p.listener == nil {
		return netip.AddrPort{}
	}
	if tcp, ok := p.listener.Addr().(*net.TCPAddr); ok {
		return tcp.AddrPort()
	}
	return netip.AddrPort{}
}

func (p *egressProxy) Stats() (connects, dials uint64) {
	if p == nil {
		return 0, 0
	}
	return p.connects.Load(), p.dials.Load()
}

func (p *egressProxy) Close() error {
	if p == nil {
		return nil
	}
	p.closeOnce.Do(func() {
		p.cancel()
		_ = p.listener.Close()
		p.mu.Lock()
		for conn := range p.conns {
			_ = conn.Close()
		}
		p.mu.Unlock()
		p.wg.Wait()
	})
	return nil
}

func (p *egressProxy) serve() {
	defer p.wg.Done()
	for {
		conn, err := p.listener.Accept()
		if err != nil {
			if p.ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		p.track(conn)
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			defer p.untrack(conn)
			defer conn.Close()
			p.handle(conn)
		}()
	}
}

func (p *egressProxy) track(conn net.Conn) {
	p.mu.Lock()
	p.conns[conn] = struct{}{}
	p.mu.Unlock()
}

func (p *egressProxy) untrack(conn net.Conn) {
	p.mu.Lock()
	delete(p.conns, conn)
	p.mu.Unlock()
}

func (p *egressProxy) handle(client net.Conn) {
	_ = client.SetDeadline(time.Now().Add(10 * time.Second))
	req, err := http.ReadRequest(bufio.NewReader(client))
	if err != nil {
		return
	}
	defer req.Body.Close()
	if req.Method != http.MethodConnect {
		writeProxyStatus(client, http.StatusMethodNotAllowed, "CONNECT required")
		return
	}
	if !p.authorized(req.Header.Get("Proxy-Authorization")) {
		writeProxyStatus(client, http.StatusProxyAuthRequired, "proxy authentication required")
		return
	}
	target := req.Host
	if target == "" && req.URL != nil {
		target = req.URL.Host
	}
	if !p.targetAllowed(target) {
		writeProxyStatus(client, http.StatusForbidden, "target is not the configured FRPS endpoint")
		return
	}
	p.connects.Add(1)
	dialCtx, cancel := context.WithTimeout(p.ctx, 12*time.Second)
	upstream, err := netpolicy.DialPinned(dialCtx, p.observer, p.endpoint, p.protected, p.meshInterface)
	cancel()
	if err != nil {
		writeProxyStatus(client, http.StatusBadGateway, "FRPS egress policy rejected the route")
		return
	}
	p.dials.Add(1)
	defer upstream.Close()
	if err = client.SetDeadline(time.Time{}); err != nil {
		return
	}
	if _, err = io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	copyDone := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(upstream, client)
		copyDone <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(client, upstream)
		copyDone <- struct{}{}
	}()
	<-copyDone
	_ = client.SetDeadline(time.Now())
	_ = upstream.SetDeadline(time.Now())
	<-copyDone
}

func (p *egressProxy) authorized(header string) bool {
	const prefix = "Basic "
	if len(header) < len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(header[len(prefix):]))
	if err != nil {
		return false
	}
	expected := p.username + ":" + p.password
	return subtle.ConstantTimeCompare(decoded, []byte(expected)) == 1
}

func (p *egressProxy) targetAllowed(target string) bool {
	host, portValue, err := net.SplitHostPort(target)
	if err != nil {
		return false
	}
	port, err := strconv.Atoi(portValue)
	if err != nil || port != p.endpoint.Port {
		return false
	}
	host = strings.Trim(host, "[]")
	return strings.EqualFold(host, p.endpoint.Host)
}

func writeProxyStatus(conn net.Conn, status int, message string) {
	text := http.StatusText(status)
	_, _ = fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\nConnection: close\r\nContent-Length: %d\r\nContent-Type: text/plain\r\n\r\n%s", status, text, len(message), message)
}
