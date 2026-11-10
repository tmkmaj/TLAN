package network

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/private-radminlan/lanmesh/core"
)

const (
	defaultRelayPacketLimit = 64 * 1024
	defaultRelayTTL         = 2 * time.Minute
	defaultRelayQueueDepth  = 64
)

var (
	ErrRelayExpired         = errors.New("relay session expired")
	ErrRelayUnauthorized    = errors.New("relay authorization failed")
	ErrRelayClosed          = errors.New("relay connection is closed")
	ErrRelayPacketTooLarge  = errors.New("relay packet exceeds limit")
	ErrRelayCapacity        = errors.New("relay session capacity reached")
	ErrRelayPeerUnavailable = errors.New("relay peer is not attached")
)

// RelayLimits bounds resources consumed by the relay. A zero value uses the
// safe defaults; invalid negative values fall back to those safe defaults.
type RelayLimits struct {
	PacketLimit int
	QueueDepth  int
	MaxSessions int
	IdleTimeout time.Duration
}

// RelayTicket is a short-lived, endpoint-bound capability. The secret is
// generated with crypto/rand and compared in constant time. Tickets should be
// delivered over the authenticated Signal channel.
type RelayTicket struct {
	SessionID string        `json:"session_id"`
	Source    core.DeviceID `json:"source"`
	Target    core.DeviceID `json:"target"`
	Secret    string        `json:"secret"`
	ExpiresAt time.Time     `json:"expires_at"`
}

func (t RelayTicket) Valid(now time.Time) bool {
	return t.SessionID != "" && t.Source != "" && t.Target != "" && t.Secret != "" && now.Before(t.ExpiresAt)
}

type RelaySessionSummary struct {
	SessionID     string        `json:"session_id"`
	Source        core.DeviceID `json:"source"`
	Target        core.DeviceID `json:"target"`
	CreatedAt     time.Time     `json:"created_at"`
	LastActivity  time.Time     `json:"last_activity"`
	AttachedPeers int           `json:"attached_peers"`
}

type RelayMessage struct {
	From core.DeviceID
	To   core.DeviceID
	Data []byte
}

type relaySession struct {
	createdAt    time.Time
	ticket       RelayTicket
	mu           sync.Mutex
	closed       bool
	peers        map[core.DeviceID]*RelayConnection
	lastActivity time.Time
}

// RelayBroker is an in-memory, two-party relay. It is intended as a reference
// implementation and test double; a production server can replace the queue
// with a bounded network stream while retaining the authorization rules.
type RelayBroker struct {
	mu          sync.Mutex
	sessions    map[string]*relaySession
	packetLimit int
	queueDepth  int
	maxSessions int
	idleTimeout time.Duration
	now         func() time.Time
	closed      bool
}

func NewRelayBroker(packetLimit int) *RelayBroker {
	return NewRelayBrokerWithLimits(RelayLimits{PacketLimit: packetLimit})
}

func NewRelayBrokerWithLimits(limits RelayLimits) *RelayBroker {
	if limits.PacketLimit == 0 {
		limits.PacketLimit = defaultRelayPacketLimit
	}
	if limits.QueueDepth == 0 {
		limits.QueueDepth = defaultRelayQueueDepth
	}
	if limits.MaxSessions == 0 {
		limits.MaxSessions = 4096
	}
	if limits.IdleTimeout == 0 {
		limits.IdleTimeout = 2 * time.Minute
	}
	if limits.PacketLimit < 0 || limits.QueueDepth < 0 || limits.MaxSessions < 0 || limits.IdleTimeout < 0 {
		return &RelayBroker{sessions: make(map[string]*relaySession), packetLimit: defaultRelayPacketLimit, queueDepth: defaultRelayQueueDepth, maxSessions: 4096, idleTimeout: 2 * time.Minute, now: time.Now}
	}
	return &RelayBroker{sessions: make(map[string]*relaySession), packetLimit: limits.PacketLimit, queueDepth: limits.QueueDepth, maxSessions: limits.MaxSessions, idleTimeout: limits.IdleTimeout, now: time.Now}
}

func (b *RelayBroker) CreateSession(source, target core.DeviceID, ttl time.Duration) (RelayTicket, error) {
	b.CleanupExpired()
	if err := source.Validate(); err != nil {
		return RelayTicket{}, err
	}
	if err := target.Validate(); err != nil {
		return RelayTicket{}, err
	}
	if source == target {
		return RelayTicket{}, errors.New("relay endpoints must be different")
	}
	if ttl <= 0 || ttl > time.Hour {
		ttl = defaultRelayTTL
	}
	sessionID, err := randomToken(18)
	if err != nil {
		return RelayTicket{}, err
	}
	secret, err := randomToken(32)
	if err != nil {
		return RelayTicket{}, err
	}
	ticket := RelayTicket{SessionID: sessionID, Source: source, Target: target, Secret: secret, ExpiresAt: b.now().Add(ttl)}
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return RelayTicket{}, ErrRelayClosed
	}
	if b.maxSessions > 0 && len(b.sessions) >= b.maxSessions {
		b.mu.Unlock()
		return RelayTicket{}, ErrRelayCapacity
	}
	b.sessions[sessionID] = &relaySession{ticket: ticket, peers: make(map[core.DeviceID]*RelayConnection), createdAt: b.now(), lastActivity: b.now()}
	b.mu.Unlock()
	return ticket, nil
}

func (b *RelayBroker) Snapshot() []RelaySessionSummary {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	items := make([]RelaySessionSummary, 0, len(b.sessions))
	for _, session := range b.sessions {
		session.mu.Lock()
		if !session.closed && session.ticket.Valid(now) {
			items = append(items, RelaySessionSummary{
				SessionID: session.ticket.SessionID, Source: session.ticket.Source, Target: session.ticket.Target,
				CreatedAt: session.createdAt, LastActivity: session.lastActivity, AttachedPeers: len(session.peers),
			})
		}
		session.mu.Unlock()
	}
	sort.Slice(items, func(i, j int) bool { return items[i].CreatedAt.Before(items[j].CreatedAt) })
	return items
}

func (b *RelayBroker) DisconnectDevice(device core.DeviceID) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	count := 0
	for id, session := range b.sessions {
		session.mu.Lock()
		if session.closed || (session.ticket.Source != device && session.ticket.Target != device) {
			session.mu.Unlock()
			continue
		}
		session.closed = true
		for _, peer := range session.peers {
			peer.closeLocked()
		}
		session.mu.Unlock()
		delete(b.sessions, id)
		count++
	}
	return count
}

func (b *RelayBroker) SessionActive(ticket RelayTicket) bool {
	b.mu.Lock()
	session, ok := b.sessions[ticket.SessionID]
	b.mu.Unlock()
	if !ok {
		return false
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	return !session.closed && session.ticket.Valid(b.now()) && secureEqual(session.ticket.Secret, ticket.Secret)
}

func (b *RelayBroker) Attach(ticket RelayTicket, device core.DeviceID) (*RelayConnection, error) {
	b.mu.Lock()
	session, ok := b.sessions[ticket.SessionID]
	b.mu.Unlock()
	if !ok {
		return nil, ErrRelayUnauthorized
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.closed || !session.ticket.Valid(b.now()) || !ticket.Valid(b.now()) {
		return nil, ErrRelayExpired
	}
	if session.ticket.Source != ticket.Source || session.ticket.Target != ticket.Target ||
		!secureEqual(session.ticket.Secret, ticket.Secret) || (device != ticket.Source && device != ticket.Target) {
		return nil, ErrRelayUnauthorized
	}
	if _, exists := session.peers[device]; exists {
		return nil, errors.New("device is already attached to relay session")
	}
	session.lastActivity = b.now()
	conn := &RelayConnection{broker: b, session: session, device: device, inbox: make(chan RelayMessage, b.queueDepth), done: make(chan struct{})}
	session.peers[device] = conn
	return conn, nil
}

func (b *RelayBroker) cleanupExpired() {
	now := b.now()
	b.mu.Lock()
	defer b.mu.Unlock()
	for id, session := range b.sessions {
		session.mu.Lock()
		idle := b.idleTimeout > 0 && now.Sub(session.lastActivity) >= b.idleTimeout
		if !session.closed && now.Before(session.ticket.ExpiresAt) && !idle {
			session.mu.Unlock()
			continue
		}
		session.closed = true
		for _, conn := range session.peers {
			conn.closeLocked()
		}
		session.mu.Unlock()
		delete(b.sessions, id)
	}
}

// CleanupExpired releases sessions whose tickets have expired. A production
// relay should call this periodically (for example once per minute).
func (b *RelayBroker) CleanupExpired() {
	b.cleanupExpired()
}

func (b *RelayBroker) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed = true
	for id, session := range b.sessions {
		session.mu.Lock()
		session.closed = true
		for _, peer := range session.peers {
			peer.closeLocked()
		}
		session.mu.Unlock()
		delete(b.sessions, id)
	}
	return nil
}

// RelayConnection is one endpoint of a two-party relay session.
type RelayConnection struct {
	broker  *RelayBroker
	session *relaySession
	device  core.DeviceID
	inbox   chan RelayMessage
	done    chan struct{}
	once    sync.Once
}

func (c *RelayConnection) Send(data []byte) error {
	return c.SendContext(context.Background(), data)
}

func (c *RelayConnection) SendContext(ctx context.Context, data []byte) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if len(data) > c.broker.packetLimit {
		return ErrRelayPacketTooLarge
	}
	c.session.mu.Lock()
	defer c.session.mu.Unlock()
	if c.session.closed || !c.session.ticket.Valid(c.broker.now()) {
		c.closeLocked()
		return ErrRelayClosed
	}
	if _, ok := c.session.peers[c.device]; !ok {
		return ErrRelayClosed
	}
	var recipient *RelayConnection
	for id, peer := range c.session.peers {
		if id != c.device {
			recipient = peer
			break
		}
	}
	if recipient == nil {
		return ErrRelayPeerUnavailable
	}
	message := RelayMessage{From: c.device, To: recipient.device, Data: append([]byte(nil), data...)}
	select {
	case recipient.inbox <- message:
		c.session.lastActivity = c.broker.now()
		return nil
	case <-ctx.Done():
		return ctx.Err()
	default:
		return errors.New("relay peer queue is full")
	}
}

func (c *RelayConnection) Receive() (RelayMessage, error) {
	return c.ReceiveContext(context.Background())
}

func (c *RelayConnection) ReceiveContext(ctx context.Context) (RelayMessage, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case message := <-c.inbox:
		if message.Data == nil {
			return RelayMessage{}, ErrRelayClosed
		}
		c.session.mu.Lock()
		if c.session.closed || !c.session.ticket.Valid(c.broker.now()) {
			c.session.mu.Unlock()
			return RelayMessage{}, ErrRelayExpired
		}
		c.session.lastActivity = c.broker.now()
		c.session.mu.Unlock()
		return message, nil
	case <-c.done:
		return RelayMessage{}, ErrRelayClosed
	case <-ctx.Done():
		return RelayMessage{}, ctx.Err()
	}
}

func (c *RelayConnection) Close() error {
	c.session.mu.Lock()
	if !c.session.closed {
		c.session.closed = true
		for _, peer := range c.session.peers {
			peer.closeLocked()
		}
	}
	c.session.mu.Unlock()
	return nil
}

func (c *RelayConnection) closeLocked() {
	c.once.Do(func() {
		delete(c.session.peers, c.device)
		close(c.done)
	})
}

// RelayChannel adapts the concrete connection to the small transport-facing
// interface used by the connectivity manager.
func (c *RelayConnection) ReceivePacket() ([]byte, error) {
	message, err := c.Receive()
	return message.Data, err
}

func randomToken(size int) (string, error) {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate relay token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func secureEqual(left, right string) bool {
	if len(left) != len(right) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}

// RelayHandshake is the first line sent on a RelayServer connection. The
// ticket is a bearer capability, so this endpoint must be protected by TLS.
type RelayHandshake struct {
	Ticket RelayTicket   `json:"ticket"`
	Device core.DeviceID `json:"device"`
}

type relayHandshakeResponse struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// RelayServer exposes an authenticated RelayBroker over a net.Conn. After a
// JSON handshake line, each packet is a 4-byte big-endian length followed by
// its payload. The payload is forwarded unchanged to the other endpoint.
type RelayServer struct {
	AllowedDevice    core.DeviceID
	Broker           *RelayBroker
	HandshakeLimit   int
	HandshakeTimeout time.Duration
}

func (s *RelayServer) ServeConn(conn net.Conn) error {
	if conn == nil {
		return errors.New("relay connection is nil")
	}
	defer conn.Close()
	if s == nil || s.Broker == nil {
		return errors.New("relay broker is nil")
	}
	limit := s.HandshakeLimit
	if limit <= 0 {
		limit = 16 * 1024
	}
	handshakeTimeout := s.HandshakeTimeout
	if handshakeTimeout <= 0 {
		handshakeTimeout = 10 * time.Second
	}
	_ = conn.SetDeadline(time.Now().Add(handshakeTimeout))
	line, err := readHandshakeLine(conn, limit)
	if err != nil {
		return err
	}
	var handshake RelayHandshake
	if err := json.Unmarshal(line, &handshake); err != nil {
		return s.writeHandshakeError(conn, err)
	}
	if s.AllowedDevice != "" && handshake.Device != s.AllowedDevice {
		return s.writeHandshakeError(conn, errors.New("relay device does not match member credential"))
	}
	connection, err := s.Broker.Attach(handshake.Ticket, handshake.Device)
	if err != nil {
		return s.writeHandshakeError(conn, err)
	}
	if err := json.NewEncoder(conn).Encode(relayHandshakeResponse{OK: true}); err != nil {
		_ = connection.Close()
		return err
	}
	_ = conn.SetDeadline(time.Time{})
	return s.serveAttached(conn, connection)
}

func (s *RelayServer) writeHandshakeError(conn net.Conn, cause error) error {
	_ = json.NewEncoder(conn).Encode(relayHandshakeResponse{Error: cause.Error()})
	return cause
}

func readHandshakeLine(r io.Reader, max int) ([]byte, error) {
	line := make([]byte, 0, minInt(max, 1024))
	var one [1]byte
	for {
		if len(line) >= max {
			return nil, errors.New("relay handshake is too large")
		}
		n, err := r.Read(one[:])
		if n > 0 {
			if one[0] == '\n' {
				return line, nil
			}
			line = append(line, one[0])
		}
		if err != nil {
			return nil, err
		}
	}
}

func minInt(left, right int) int {
	if left < right {
		return left
	}
	return right
}

func (s *RelayServer) serveAttached(conn net.Conn, endpoint *RelayConnection) error {
	errCh := make(chan error, 2)
	go func() {
		for {
			payload, err := readRelayPacket(conn, endpoint.broker.packetLimit)
			if err != nil {
				errCh <- err
				return
			}
			if err := endpoint.Send(payload); err != nil {
				if errors.Is(err, ErrRelayPeerUnavailable) {
					continue
				}
				errCh <- err
				return
			}
		}
	}()
	go func() {
		for {
			message, err := endpoint.Receive()
			if err != nil {
				errCh <- err
				return
			}
			_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := writeRelayPacket(conn, message.Data, endpoint.broker.packetLimit); err != nil {
				errCh <- err
				return
			}
		}
	}()
	err := <-errCh
	_ = endpoint.Close()
	return err
}
