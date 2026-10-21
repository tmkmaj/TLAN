package targetgateway

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/private-radminlan/lanmesh/core"
)

const (
	// LoopbackAddress is the only address on which a Gateway listens.
	LoopbackAddress = "127.0.0.1"

	DefaultLeasePollInterval = 250 * time.Millisecond
	DefaultDialTimeout       = 5 * time.Second
	DefaultIdleTimeout       = 5 * time.Minute
	DefaultWriteTimeout      = 30 * time.Second
	DefaultMaxConnections    = 256
	DefaultMaxUDPSessions    = 256
	DefaultMaxDatagramSize   = 65507
	DefaultUDPQueueDepth     = 64
	maxUDPReadBuffer         = 65535
)

var (
	ErrClosed           = errors.New("target gateway is closed")
	ErrLeaseRequired    = errors.New("target lease validator is required")
	ErrLeaseUnavailable = errors.New("target lease is unavailable")
	ErrLeaseRevoked     = errors.New("target lease is revoked")
	ErrLeaseChanged     = errors.New("target lease generation changed")
	ErrConnectionLimit  = errors.New("target gateway connection limit reached")
	ErrSessionLimit     = errors.New("target gateway UDP session limit reached")
	ErrDatagramTooLarge = errors.New("target gateway datagram exceeds limit")
	ErrIdleTimeout      = errors.New("target gateway connection idle timeout")
)

// Protocol identifies the transport used by a Gateway. A Gateway serves one
// protocol instance; run separate instances for a TCP and a UDP rule.
type Protocol string

const (
	ProtocolTCP Protocol = "tcp"
	ProtocolUDP Protocol = "udp"
)

// Target is the complete, immutable data-plane target of one gateway. It
// intentionally contains no hostname: address changes must produce a new
// target and a new lease generation.
type Target struct {
	// NetworkID is optional, but when set it is passed to the validator and
	// must be checked against the current Mesh network by the adapter.
	NetworkID string
	IPv4      netip.Addr
	Port      uint16
	// DeviceID is the Mesh device identity, not a display name.
	DeviceID string
	// PublicKey is optional. When set, it must be the canonical base64
	// WireGuard public key of DeviceID and the adapter must reject changes.
	PublicKey string
	// ServiceID binds this gateway to one exact published service/rule.
	ServiceID string
}

func (t Target) Validate() error {
	if t.NetworkID != "" {
		if err := core.NetworkID(t.NetworkID).Validate(); err != nil {
			return fmt.Errorf("target network ID: %w", err)
		}
	}
	if err := core.DeviceID(t.DeviceID).Validate(); err != nil {
		return fmt.Errorf("target device ID: %w", err)
	}
	if t.Port == 0 {
		return errors.New("target port is required")
	}
	if !t.IPv4.IsValid() || !t.IPv4.Is4() {
		return errors.New("target must be a literal IPv4 address")
	}
	if t.IPv4.IsUnspecified() || t.IPv4.IsLoopback() || t.IPv4.IsMulticast() || t.IPv4.IsLinkLocalUnicast() || !t.IPv4.IsGlobalUnicast() {
		return errors.New("target is not a usable unicast Mesh address")
	}
	if !isMeshPrivate(t.IPv4) {
		return fmt.Errorf("target %s is outside the allowed Mesh ranges 10.0.0.0/8 and 100.64.0.0/10", t.IPv4)
	}
	if t.PublicKey != "" {
		if err := core.ValidateWireGuardPublicKey(t.PublicKey); err != nil {
			return fmt.Errorf("target public key: %w", err)
		}
	}
	if t.ServiceID != "" && (len(t.ServiceID) > 64 || strings.ContainsAny(t.ServiceID, "\x00\r\n")) {
		return errors.New("target service ID is invalid")
	}
	return nil
}

func (t Target) AddrPort() netip.AddrPort {
	return netip.AddrPortFrom(t.IPv4, t.Port)
}

func isMeshPrivate(addr netip.Addr) bool {
	return mesh10.Contains(addr) || mesh10064.Contains(addr)
}

var (
	mesh10    = netip.MustParsePrefix("10.0.0.0/8")
	mesh10064 = netip.MustParsePrefix("100.64.0.0/10")
)

// Lease is the minimal generation/revocation capability returned by a
// LeaseValidator. Done must be closed by the adapter on Mesh stop, membership
// removal, address change, public-key change, authorization revocation, or any
// generation change. Generation must be nonzero and monotonic for one Mesh
// session; existing streams are closed when it changes.
type Lease struct {
	Generation uint64
	Done       <-chan struct{}
}

// LeaseValidator re-reads the current Mesh authorization before it is used.
// Implementations must be safe for concurrent calls and must honor ctx.
//
// Validate must verify, at minimum, that target.DeviceID is still a member,
// its current virtual IPv4 equals target.IPv4, its optional public key still
// matches, and the lease is not revoked. Returning a stale generation is not
// enough.
type LeaseValidator interface {
	Validate(ctx context.Context, target Target) (Lease, error)
}

// Dialer performs the actual data-plane connection through the current Mesh
// lease. It must not resolve DNS, use a public/physical-interface fallback, or
// ignore generation. A successful return must mean the route is pinned to the
// Mesh interface for that generation.
// DialUDP must return a connected datagram net.Conn so replies stay bound to
// that session.
type Dialer interface {
	DialTCP(ctx context.Context, target Target, generation uint64) (net.Conn, error)
	DialUDP(ctx context.Context, target Target, generation uint64) (net.Conn, error)
}

// Config configures one TCP or UDP Gateway. ListenPort zero requests an
// ephemeral port. The listen address is always 127.0.0.1.
type Config struct {
	Protocol Protocol
	// ListenPort is the requested loopback port; zero selects a free port.
	ListenPort uint16
	Target     Target
	Lease      LeaseValidator
	Dialer     Dialer

	LeasePollInterval time.Duration
	DialTimeout       time.Duration
	IdleTimeout       time.Duration
	WriteTimeout      time.Duration
	MaxConnections    int
	MaxUDPSessions    int
	MaxDatagramSize   int
	UDPQueueDepth     int
}

func (c Config) normalized() (Config, error) {
	c.Protocol = Protocol(strings.ToLower(strings.TrimSpace(string(c.Protocol))))
	switch c.Protocol {
	case ProtocolTCP, ProtocolUDP:
	default:
		return Config{}, fmt.Errorf("unsupported target gateway protocol %q", c.Protocol)
	}
	if err := c.Target.Validate(); err != nil {
		return Config{}, err
	}
	if c.Lease == nil {
		return Config{}, ErrLeaseRequired
	}
	if c.Dialer == nil {
		return Config{}, errors.New("target gateway dialer is required")
	}
	if c.LeasePollInterval < 0 || c.DialTimeout < 0 || c.IdleTimeout < 0 || c.WriteTimeout < 0 {
		return Config{}, errors.New("target gateway durations must not be negative")
	}
	if c.MaxConnections < 0 || c.MaxUDPSessions < 0 || c.MaxDatagramSize < 0 || c.UDPQueueDepth < 0 {
		return Config{}, errors.New("target gateway limits must not be negative")
	}
	if c.LeasePollInterval == 0 {
		c.LeasePollInterval = DefaultLeasePollInterval
	}
	if c.DialTimeout == 0 {
		c.DialTimeout = DefaultDialTimeout
	}
	if c.IdleTimeout == 0 {
		c.IdleTimeout = DefaultIdleTimeout
	}
	if c.WriteTimeout == 0 {
		c.WriteTimeout = DefaultWriteTimeout
	}
	if c.MaxConnections == 0 {
		c.MaxConnections = DefaultMaxConnections
	}
	if c.MaxUDPSessions == 0 {
		c.MaxUDPSessions = DefaultMaxUDPSessions
	}
	if c.MaxDatagramSize == 0 {
		c.MaxDatagramSize = DefaultMaxDatagramSize
	}
	if c.MaxDatagramSize > 65507 {
		return Config{}, errors.New("maximum UDP datagram size exceeds IPv4 payload limit")
	}
	if c.UDPQueueDepth == 0 {
		c.UDPQueueDepth = DefaultUDPQueueDepth
	}
	return c, nil
}

// Stats is a point-in-time snapshot. Counters are intentionally separated so a
// caller cannot mistake an accepted loopback connection for a verified backend.
type Stats struct {
	LeaseGeneration     uint64
	TCPAccepted         uint64
	TCPActive           uint64
	TCPRejected         uint64
	UDPAccepted         uint64
	UDPActive           uint64
	UDPDropped          uint64
	LeaseRejections     uint64
	DialFailures        uint64
	BytesToTarget       uint64
	BytesFromTarget     uint64
	DatagramsToTarget   uint64
	DatagramsFromTarget uint64
}
