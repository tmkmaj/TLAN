package egressgateway

import (
	"fmt"
	"net/netip"
	"strings"
	"sync"
)

// QuotaSnapshot is a consistent observation of one session's resource use.
type QuotaSnapshot struct {
	MaxConnections int
	MaxBytes       int64
	MaxRateBPS     int64
	Total          uint64
	TCP            uint64
	UDP            uint64
	Bytes          uint64
}

// Quota tracks connection and byte budgets for one authenticated session.
type Quota struct {
	mu     sync.Mutex
	limits Limits
	total  uint64
	tcp    uint64
	udp    uint64
	bytes  uint64
}

// NewQuota creates a quota with explicit positive limits.
func NewQuota(limits Limits) (*Quota, error) {
	if err := limits.Validate(); err != nil {
		return nil, err
	}
	return &Quota{limits: limits}, nil
}

// AcquireConnection reserves one TCP or UDP connection slot. MaxConnections is
// a total budget while TCP and UDP counts are tracked separately.
func (q *Quota) AcquireConnection(protocol Protocol) error {
	if protocol != ProtocolTCP && protocol != ProtocolUDP {
		return ErrProtocolDenied
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.total >= uint64(q.limits.MaxConnections) {
		return ErrConnectionQuota
	}
	q.total++
	if protocol == ProtocolTCP {
		q.tcp++
	} else {
		q.udp++
	}
	return nil
}

// ReleaseConnection returns a previously acquired connection slot. Extra
// releases are ignored so a retrying close path cannot create underflow.
func (q *Quota) ReleaseConnection(protocol Protocol) {
	q.mu.Lock()
	defer q.mu.Unlock()
	switch protocol {
	case ProtocolTCP:
		if q.tcp > 0 {
			q.tcp--
			if q.total > 0 {
				q.total--
			}
		}
	case ProtocolUDP:
		if q.udp > 0 {
			q.udp--
			if q.total > 0 {
				q.total--
			}
		}
	}
}

// ConsumeBytes reserves byte budget. Bytes are not refunded; the quota is a
// cumulative lease budget rather than a windowed rate limiter.
func (q *Quota) ConsumeBytes(count uint64) error {
	if count == 0 {
		return nil
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	maxBytes := uint64(q.limits.MaxBytes)
	if q.bytes > maxBytes || count > maxBytes-q.bytes {
		return ErrByteQuota
	}
	q.bytes += count
	return nil
}

// Snapshot returns current counters without exposing mutable internals.
func (q *Quota) Snapshot() QuotaSnapshot {
	q.mu.Lock()
	defer q.mu.Unlock()
	return QuotaSnapshot{
		MaxConnections: q.limits.MaxConnections,
		MaxBytes:       q.limits.MaxBytes,
		MaxRateBPS:     q.limits.MaxRateBPS,
		Total:          q.total,
		TCP:            q.tcp,
		UDP:            q.udp,
		Bytes:          q.bytes,
	}
}

// SessionPolicy enforces one lease's target, protocol, DNS, and quota rules.
type SessionPolicy struct {
	policy    Policy
	limits    Limits
	prefixes  []netip.Prefix
	resolvers map[netip.Addr]struct{}
	protocols map[Protocol]struct{}
	blocked   map[TargetClass]struct{}
	quota     *Quota
}

// NewSessionPolicy compiles a policy for one session. An optional limits
// argument supplies the issued lease limits; otherwise policy.Limits is used.
func NewSessionPolicy(policy Policy, limits ...Limits) (*SessionPolicy, error) {
	policy = policy.Clone()
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	effectiveLimits := policy.Limits
	if len(limits) > 1 {
		return nil, fmt.Errorf("%w: at most one limits argument is allowed", ErrInvalidPolicy)
	}
	if len(limits) == 1 {
		effectiveLimits = limits[0]
	}
	quota, err := NewQuota(effectiveLimits)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidPolicy, err)
	}

	prefixes := make([]netip.Prefix, 0, len(policy.AllowedTargetCIDRs))
	for _, raw := range policy.AllowedTargetCIDRs {
		prefix, parseErr := netip.ParsePrefix(strings.TrimSpace(raw))
		if parseErr != nil {
			return nil, fmt.Errorf("%w: invalid target CIDR %q", ErrInvalidPolicy, raw)
		}
		prefixes = append(prefixes, prefix.Masked())
	}
	resolvers := make(map[netip.Addr]struct{}, len(policy.DNSResolvers))
	for _, raw := range policy.DNSResolvers {
		addr, parseErr := netip.ParseAddr(strings.TrimSpace(raw))
		if parseErr != nil {
			return nil, fmt.Errorf("%w: invalid DNS resolver %q", ErrInvalidPolicy, raw)
		}
		resolvers[addr.Unmap()] = struct{}{}
	}
	protocols := make(map[Protocol]struct{}, len(policy.AllowedProtocols))
	for _, protocol := range policy.AllowedProtocols {
		protocols[Protocol(strings.ToLower(strings.TrimSpace(string(protocol))))] = struct{}{}
	}
	blocked := make(map[TargetClass]struct{}, len(policy.BlockedCategories))
	for _, class := range policy.BlockedCategories {
		blocked[TargetClass(strings.ToLower(strings.TrimSpace(string(class))))] = struct{}{}
	}
	return &SessionPolicy{
		policy: policy, limits: effectiveLimits, prefixes: prefixes,
		resolvers: resolvers, protocols: protocols, blocked: blocked, quota: quota,
	}, nil
}

// ValidateTarget checks classification, hard-deny categories, DNS policy,
// management ports, IPv6 policy, and allowed target CIDRs. It reclassifies the
// address itself; the class argument is only an optional consistency check.
func (s *SessionPolicy) ValidateTarget(target netip.AddrPort, class TargetClass) error {
	if !target.IsValid() || !target.Addr().IsValid() || target.Port() == 0 {
		return fmt.Errorf("%w: target must be a valid address and non-zero port", ErrInvalidTarget)
	}
	addr := target.Addr().Unmap()
	target = netip.AddrPortFrom(addr, target.Port())
	actualClass := ClassifyTarget(target)
	if class != "" && class != actualClass {
		return fmt.Errorf("%w: supplied %q but target is %q", ErrTargetClassMismatch, class, actualClass)
	}

	switch actualClass {
	case TargetClassCloudMetadata:
		return fmt.Errorf("%w: cloud metadata addresses are forbidden", ErrTargetBlocked)
	case TargetClassLoopback:
		return fmt.Errorf("%w: loopback addresses are forbidden", ErrTargetBlocked)
	case TargetClassPrivate:
		return fmt.Errorf("%w: private addresses are forbidden", ErrTargetBlocked)
	case TargetClassLinkLocal:
		return fmt.Errorf("%w: link-local addresses are forbidden", ErrTargetBlocked)
	case TargetClassMulticast:
		return fmt.Errorf("%w: multicast addresses are forbidden", ErrTargetBlocked)
	case TargetClassUnspecified:
		return fmt.Errorf("%w: unspecified addresses are forbidden", ErrTargetBlocked)
	case TargetClassReserved:
		return fmt.Errorf("%w: non-global addresses are forbidden", ErrTargetBlocked)
	case TargetClassIPv6:
		if s.policy.IPv6Policy == IPv6PolicyBlock {
			return ErrIPv6Blocked
		}
		if s.policy.IPv6Policy != IPv6PolicyAllowPublic {
			return fmt.Errorf("%w: unsupported IPv6 policy", ErrInvalidPolicy)
		}
	case TargetClassPublic:
		// Public IPv4 remains subject to CIDR and blocked-category checks.
	default:
		return fmt.Errorf("%w: unsupported target class %q", ErrTargetBlocked, actualClass)
	}
	if _, blocked := s.blocked[actualClass]; blocked {
		return fmt.Errorf("%w: category %q is explicitly blocked", ErrTargetBlocked, actualClass)
	}
	if IsReservedManagementPort(target.Port()) {
		return fmt.Errorf("%w: port %d", ErrManagementPortBlocked, target.Port())
	}
	if target.Port() == 53 {
		switch s.policy.DNSPolicy {
		case DNSPolicyBlock:
			return ErrDNSBlocked
		case DNSPolicyRemote:
			if _, ok := s.resolvers[addr]; !ok {
				return ErrDNSResolverDenied
			}
		default:
			return fmt.Errorf("%w: unsupported DNS policy", ErrInvalidPolicy)
		}
	}
	for _, prefix := range s.prefixes {
		if prefix.Contains(addr) {
			return nil
		}
	}
	return ErrTargetNotAllowed
}

// ValidateEgressTarget is a convenience wrapper that rejects a stale or
// caller-forged classification before running the policy checks.
func (s *SessionPolicy) ValidateEgressTarget(target EgressTarget) error {
	return s.ValidateTarget(target.AddrPort, target.Class)
}

// AcquireConnection enforces allowed protocols and the connection budget.
func (s *SessionPolicy) AcquireConnection(protocol Protocol) error {
	protocol = Protocol(strings.ToLower(strings.TrimSpace(string(protocol))))
	if _, ok := s.protocols[protocol]; !ok {
		return ErrProtocolDenied
	}
	return s.quota.AcquireConnection(protocol)
}

// ReleaseConnection returns a connection slot when its stream or datagram flow
// closes.
func (s *SessionPolicy) ReleaseConnection(protocol Protocol) {
	s.quota.ReleaseConnection(protocol)
}

// ConsumeBytes reserves cumulative lease byte budget.
func (s *SessionPolicy) ConsumeBytes(count uint64) error {
	return s.quota.ConsumeBytes(count)
}

// QuotaSnapshot returns current connection and byte usage.
func (s *SessionPolicy) QuotaSnapshot() QuotaSnapshot {
	return s.quota.Snapshot()
}

// Policy returns a deep copy of the immutable compiled policy.
func (s *SessionPolicy) Policy() Policy {
	return s.policy.Clone()
}

// Limits returns the effective limits supplied to the quota.
func (s *SessionPolicy) Limits() Limits {
	return s.limits
}
