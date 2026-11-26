package network

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/private-radminlan/lanmesh/core"
)

const (
	defaultStreamRelayQueueDepth = 64
	streamRelayWriteTimeout      = 5 * time.Second
)

// StreamRelay forwards length-prefixed relay frames over one connection. Send
// only performs a bounded, non-blocking enqueue; a dedicated writer goroutine
// owns all socket writes, so one slow peer cannot hold a lock across callers.
type StreamRelay struct {
	conn   net.Conn
	reader *bufio.Reader

	mu         sync.Mutex
	queue      chan []byte
	done       chan struct{}
	writerDone chan struct{}
	closed     bool

	closeOnce sync.Once
	closeErr  error

	errMu    sync.Mutex
	writeErr error
	stats    relayCounters
}

func newStreamRelay(conn net.Conn, reader *bufio.Reader) *StreamRelay {
	return newStreamRelayWithQueue(conn, reader, defaultStreamRelayQueueDepth)
}

func newStreamRelayWithQueue(conn net.Conn, reader *bufio.Reader, queueDepth int) *StreamRelay {
	if queueDepth <= 0 {
		queueDepth = defaultStreamRelayQueueDepth
	}
	if reader == nil && conn != nil {
		reader = bufio.NewReader(conn)
	}
	relay := &StreamRelay{
		conn:       conn,
		reader:     reader,
		queue:      make(chan []byte, queueDepth),
		done:       make(chan struct{}),
		writerDone: make(chan struct{}),
	}
	go relay.writeLoop()
	return relay
}

func DialHTTPRelay(ctx context.Context, baseURL, token string, ticket RelayTicket, device core.DeviceID) (*StreamRelay, error) {
	return DialHTTPRelayWithRoots(ctx, baseURL, token, ticket, device, nil)
}

// WithRoots supports a private CA without disabling certificate validation.
func DialHTTPRelayWithRoots(ctx context.Context, baseURL, token string, ticket RelayTicket, device core.DeviceID, roots *x509.CertPool) (*StreamRelay, error) {
	u, err := url.Parse(baseURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return nil, errors.New("invalid control URL")
	}
	address := u.Host
	if u.Port() == "" {
		port := "80"
		if u.Scheme == "https" {
			port = "443"
		}
		address = net.JoinHostPort(u.Hostname(), port)
	}
	dialer := &net.Dialer{Timeout: 8 * time.Second}
	var c net.Conn
	if u.Scheme == "https" {
		c, err = (&tls.Dialer{NetDialer: dialer, Config: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12, ServerName: u.Hostname(), NextProtos: []string{"http/1.1"}}}).DialContext(ctx, "tcp", address)
	} else {
		c, err = dialer.DialContext(ctx, "tcp", address)
	}
	if err != nil {
		return nil, err
	}
	success := false
	// DialContext only covers connection establishment. Keep cancellation active
	// through HTTP Upgrade and ticket authentication, then hand off ownership.
	stopCancel := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer func() {
		stopCancel()
		if !success {
			c.Close()
		}
	}()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	u.Path = "/api/v1/relay/stream"
	u.RawQuery = ""
	u.Fragment = ""
	req, _ := http.NewRequest(http.MethodGet, u.String(), nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "lanmesh-relay")
	if strings.HasPrefix(token, "member_") {
		req.Header.Set("Authorization", "Bearer "+token)
	} else {
		req.Header.Set("X-Admin-Token", token)
	}
	if err = req.Write(c); err != nil {
		return nil, err
	}
	r := bufio.NewReader(c)
	response, err := http.ReadResponse(r, req)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != 101 {
		return nil, fmt.Errorf("relay upgrade: %s", response.Status)
	}
	if err = json.NewEncoder(c).Encode(RelayHandshake{Ticket: ticket, Device: device}); err != nil {
		return nil, err
	}
	line, err := readHandshakeLine(r, 4096)
	if err != nil {
		return nil, err
	}
	var answer relayHandshakeResponse
	if err = json.Unmarshal(line, &answer); err != nil {
		return nil, err
	}
	if !answer.OK {
		return nil, fmt.Errorf("relay rejected: %s", answer.Error)
	}
	_ = c.SetDeadline(time.Time{})
	if !stopCancel() || ctx.Err() != nil {
		return nil, ctx.Err()
	}
	success = true
	return newStreamRelay(c, r), nil
}

// Send validates and copies the payload, then performs a non-blocking enqueue.
// A full write queue returns a RelayBackpressureError instead of blocking the
// caller on a slow connection.
func (c *StreamRelay) Send(payload []byte) error {
	if c == nil || c.conn == nil {
		return ErrRelayClosed
	}
	if len(payload) == 0 || len(payload) > defaultRelayPacketLimit {
		return ErrRelayPacketTooLarge
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return ErrRelayClosed
	}
	packet := append([]byte{}, payload...)
	select {
	case c.queue <- packet:
		c.stats.recordEnqueued()
		return nil
	default:
		c.stats.recordQueueFullAttempt()
		c.stats.recordDroppedFull()
		return &RelayBackpressureError{Priority: RelayPriorityNormal, Reason: RelayDropQueueFull}
	}
}

func (c *StreamRelay) writeLoop() {
	defer close(c.writerDone)
	for {
		select {
		case <-c.done:
			return
		default:
		}
		select {
		case <-c.done:
			return
		case payload := <-c.queue:
			select {
			case <-c.done:
				return
			default:
			}
			if err := c.write(payload); err != nil {
				if c.isClosed() {
					return
				}
				c.recordWriteFailure(err)
				c.shutdown()
				return
			}
		}
	}
}

func (c *StreamRelay) write(payload []byte) error {
	_ = c.conn.SetWriteDeadline(time.Now().Add(streamRelayWriteTimeout))
	return writeRelayPacket(c.conn, payload, defaultRelayPacketLimit)
}

func (c *StreamRelay) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

func (c *StreamRelay) recordWriteFailure(err error) {
	c.stats.recordWriteError()
	c.errMu.Lock()
	if c.writeErr == nil {
		c.writeErr = err
	}
	c.errMu.Unlock()
}

func (c *StreamRelay) shutdown() {
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.closed = true
		if c.done != nil {
			close(c.done)
		}
		c.mu.Unlock()
		if c.conn != nil {
			c.closeErr = c.conn.Close()
		}
	})
}

// Close is safe to call multiple times. It stops the writer goroutine and waits
// for it to exit, including when the writer is blocked in a slow socket write.
func (c *StreamRelay) Close() error {
	if c == nil {
		return nil
	}
	c.shutdown()
	if c.writerDone != nil {
		<-c.writerDone
	}
	return c.closeErr
}

// WriteError returns the first asynchronous write failure, if any. The
// connection is closed when such an error is recorded.
func (c *StreamRelay) WriteError() error {
	if c == nil {
		return ErrRelayClosed
	}
	c.errMu.Lock()
	defer c.errMu.Unlock()
	return c.writeErr
}

// Stats returns a concurrent-safe snapshot of this stream's write queue.
func (c *StreamRelay) Stats() RelayStats {
	if c == nil {
		return RelayStats{}
	}
	stats := c.stats.snapshot()
	if c.queue != nil {
		stats.QueueDepth = len(c.queue)
		stats.QueueCapacity = cap(c.queue)
	}
	return stats
}

// ReceivePacket keeps the existing blocking read API and 4-byte length frame.
func (c *StreamRelay) ReceivePacket() ([]byte, error) {
	if c == nil || c.reader == nil {
		return nil, ErrRelayClosed
	}
	return readRelayPacket(c.reader, defaultRelayPacketLimit)
}
