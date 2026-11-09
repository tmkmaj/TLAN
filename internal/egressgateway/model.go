// Package egressgateway implements the server-side lease, policy, and NAT
// boundary for application egress forwarding.
//
// The package is intentionally independent from the FRP authorization package.
// Egress leases have a separate lifecycle, capability, policy, and quota model.
package egressgateway

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"time"
)

const (
	// SchemaVersion is the on-the-wire model version for new leases.
	SchemaVersion = 1

	DefaultLeaseTTL = 15 * time.Minute
	MaxLeaseTTL     = 24 * time.Hour

	DefaultMaxConnections = 128
	DefaultMaxBytes       = int64(1 << 30)
	DefaultMaxRateBPS     = int64(20 << 20)
)

var (
	ErrInvalidLease          = errors.New("invalid egress lease")
	ErrLeaseNotFound         = errors.New("egress lease not found")
	ErrLeaseUnauthorized     = errors.New("egress lease authentication failed")
	ErrLeaseExpired          = errors.New("egress lease expired")
	ErrLeaseRevoked          = errors.New("egress lease revoked")
	ErrPolicyVersionMismatch = errors.New("egress policy version mismatch")
	ErrInvalidPolicy         = errors.New("invalid egress policy")
	ErrInvalidTarget         = errors.New("invalid egress target")
	ErrTargetClassMismatch   = errors.New("egress target classification mismatch")
	ErrTargetBlocked         = errors.New("egress target blocked")
	ErrTargetNotAllowed      = errors.New("egress target is outside the allowed CIDRs")
	ErrIPv6Blocked           = errors.New("IPv6 egress is blocked by policy")
	ErrDNSBlocked            = errors.New("DNS is blocked by policy")
	ErrDNSResolverDenied     = errors.New("DNS target is not a gateway-provided resolver")
	ErrManagementPortBlocked = errors.New("reserved management port is blocked")
	ErrProtocolDenied        = errors.New("protocol is denied by policy")
	ErrConnectionQuota       = errors.New("egress connection quota exceeded")
	ErrByteQuota             = errors.New("egress byte quota exceeded")
)

var leaseIdentifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

// Protocol identifies the transport protocol governed by a lease.
type Protocol string

const (
	ProtocolTCP Protocol = "tcp"
	ProtocolUDP Protocol = "udp"
)

// TargetClass is the security classification of a target address.
type TargetClass string

const (
	TargetClassPublic        TargetClass = "public"
	TargetClassPrivate       TargetClass = "private"
	TargetClassLoopback      TargetClass = "loopback"
	TargetClassLinkLocal     TargetClass = "link_local"
	TargetClassMulticast     TargetClass = "multicast"
	TargetClassUnspecified   TargetClass = "unspecified"
	TargetClassCloudMetadata TargetClass = "cloud_metadata"
	TargetClassIPv6          TargetClass = "ipv6"
	TargetClassReserved      TargetClass = "reserved"
)

// IPv6Policy controls whether publicly routable IPv6 targets are eligible.
type IPv6Policy string

const (
	IPv6PolicyBlock       IPv6Policy = "block"
	IPv6PolicyAllowPublic IPv6Policy = "allow_public"
)

// DNSPolicy controls DNS destinations for an egress session.
type DNSPolicy string

const (
	DNSPolicyBlock  DNSPolicy = "block"
	DNSPolicyRemote DNSPolicy = "remote"
)

// RevocationReason records why a lease was revoked.
type RevocationReason string

const (
	RevocationReasonClientRequested RevocationReason = "client_requested"
	RevocationReasonAdministrator   RevocationReason = "administrator"
	RevocationReasonPolicyChanged   RevocationReason = "policy_changed"
	RevocationReasonSecurity        RevocationReason = "security"
	RevocationReasonShutdown        RevocationReason = "gateway_shutdown"
)

// Limits bounds resources owned by one lease. A zero value is not a valid
// issued lease; the issuer substitutes configured defaults only when the whole
// Limits value is zero.
type Limits struct {
	MaxConnections int   `json:"max_connections"`
	MaxBytes       int64 `json:"max_bytes"`
	MaxRateBPS     int64 `json:"max_rate_bps"`
}

func (l Limits) isZero() bool {
	return l.MaxConnections == 0 && l.MaxBytes == 0 && l.MaxRateBPS == 0
}

// Validate rejects negative or incomplete limits.
func (l Limits) Validate() error {
	if l.MaxConnections <= 0 {
		return fmt.Errorf("%w: max_connections must be positive", ErrInvalidLease)
	}
	if l.MaxBytes <= 0 {
		return fmt.Errorf("%w: max_bytes must be positive", ErrInvalidLease)
	}
	if l.MaxRateBPS <= 0 {
		return fmt.Errorf("%w: max_rate_bps must be positive", ErrInvalidLease)
	}
	return nil
}

// Policy is the complete, explicit security policy attached to a lease.
// Validation is fail-closed: unsupported IPv6, DNS, protocol, or target class
// values are rejected rather than interpreted as a permissive default.
type Policy struct {
	Version            int           `json:"version"`
	AllowedProtocols   []Protocol    `json:"allowed_protocols"`
	AllowedTargetCIDRs []string      `json:"allowed_target_cidrs"`
	BlockedCategories  []TargetClass `json:"blocked_categories,omitempty"`
	IPv6Policy         IPv6Policy    `json:"ipv6_policy"`
	DNSPolicy          DNSPolicy     `json:"dns_policy"`
	DNSResolvers       []string      `json:"dns_resolvers,omitempty"`
	Limits             Limits        `json:"limits"`
}

// Clone returns a deep copy safe for concurrent updates by the caller.
func (p Policy) Clone() Policy {
	out := p
	out.AllowedProtocols = append([]Protocol(nil), p.AllowedProtocols...)
	out.AllowedTargetCIDRs = append([]string(nil), p.AllowedTargetCIDRs...)
	out.BlockedCategories = append([]TargetClass(nil), p.BlockedCategories...)
	out.DNSResolvers = append([]string(nil), p.DNSResolvers...)
	return out
}

// Validate checks that a policy is explicit and internally consistent.
func (p Policy) Validate() error {
	if p.Version <= 0 {
		return fmt.Errorf("%w: version must be positive", ErrInvalidPolicy)
	}
	if len(p.AllowedProtocols) == 0 {
		return fmt.Errorf("%w: allowed_protocols must not be empty", ErrInvalidPolicy)
	}
	seenProtocols := make(map[Protocol]struct{}, len(p.AllowedProtocols))
	for _, protocol := range p.AllowedProtocols {
		normalized := Protocol(strings.ToLower(strings.TrimSpace(string(protocol))))
		if normalized != ProtocolTCP && normalized != ProtocolUDP {
			return fmt.Errorf("%w: unsupported protocol %q", ErrInvalidPolicy, protocol)
		}
		if _, exists := seenProtocols[normalized]; exists {
			return fmt.Errorf("%w: duplicate protocol %q", ErrInvalidPolicy, normalized)
		}
		seenProtocols[normalized] = struct{}{}
	}
	if len(p.AllowedTargetCIDRs) == 0 {
		return fmt.Errorf("%w: allowed_target_cidrs must not be empty", ErrInvalidPolicy)
	}
	for _, raw := range p.AllowedTargetCIDRs {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err != nil {
			return fmt.Errorf("%w: invalid target CIDR %q", ErrInvalidPolicy, raw)
		}
		if prefix.Masked() != prefix {
			return fmt.Errorf("%w: target CIDR %q has host bits set", ErrInvalidPolicy, raw)
		}
	}
	seenCategories := make(map[TargetClass]struct{}, len(p.BlockedCategories))
	for _, class := range p.BlockedCategories {
		normalized := TargetClass(strings.ToLower(strings.TrimSpace(string(class))))
		if !isKnownTargetClass(normalized) {
			return fmt.Errorf("%w: unsupported blocked category %q", ErrInvalidPolicy, class)
		}
		if _, exists := seenCategories[normalized]; exists {
			return fmt.Errorf("%w: duplicate blocked category %q", ErrInvalidPolicy, normalized)
		}
		seenCategories[normalized] = struct{}{}
	}
	if p.IPv6Policy != IPv6PolicyBlock && p.IPv6Policy != IPv6PolicyAllowPublic {
		return fmt.Errorf("%w: ipv6_policy must be %q or %q", ErrInvalidPolicy, IPv6PolicyBlock, IPv6PolicyAllowPublic)
	}
	switch p.DNSPolicy {
	case DNSPolicyBlock:
		if len(p.DNSResolvers) != 0 {
			return fmt.Errorf("%w: dns_resolvers must be empty when DNS is blocked", ErrInvalidPolicy)
		}
	case DNSPolicyRemote:
		if len(p.DNSResolvers) == 0 {
			return fmt.Errorf("%w: dns_resolvers is required for remote DNS", ErrInvalidPolicy)
		}
		for _, raw := range p.DNSResolvers {
			addr, err := netip.ParseAddr(strings.TrimSpace(raw))
			if err != nil || !addr.IsValid() || addr.IsUnspecified() {
				return fmt.Errorf("%w: invalid DNS resolver %q", ErrInvalidPolicy, raw)
			}
		}
	default:
		return fmt.Errorf("%w: dns_policy must be %q or %q", ErrInvalidPolicy, DNSPolicyBlock, DNSPolicyRemote)
	}
	if !p.Limits.isZero() {
		if err := p.Limits.Validate(); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidPolicy, err)
		}
	}
	return nil
}

// LeaseStatus is the current state of a lease.
type LeaseStatus string

const (
	LeaseStatusActive  LeaseStatus = "active"
	LeaseStatusRevoked LeaseStatus = "revoked"
	LeaseStatusExpired LeaseStatus = "expired"
)

// Lease is a device-, profile-, and rule-scoped egress authorization.
// Capability is populated only in the immediate Issue response and is never
// stored or returned by Get.
type Lease struct {
	ID               string           `json:"id"`
	DeviceID         string           `json:"device_id"`
	ProfileID        string           `json:"profile_id"`
	RuleID           string           `json:"rule_id"`
	PolicyVersion    int              `json:"policy_version"`
	IssuedAt         time.Time        `json:"issued_at"`
	ExpiresAt        time.Time        `json:"expires_at"`
	Nonce            string           `json:"nonce"`
	GatewayEndpoint  string           `json:"gateway_endpoint"`
	Limits           Limits           `json:"limits"`
	Policy           Policy           `json:"policy"`
	Capability       string           `json:"capability,omitempty"`
	RevokedAt        *time.Time       `json:"revoked_at,omitempty"`
	RevocationReason RevocationReason `json:"revocation_reason,omitempty"`
}

// Clone returns a deep copy of a lease.
func (l Lease) Clone() Lease {
	out := l
	out.Policy = l.Policy.Clone()
	if l.RevokedAt != nil {
		revokedAt := *l.RevokedAt
		out.RevokedAt = &revokedAt
	}
	return out
}

// EgressTarget is a classified destination used by session admission.
type EgressTarget struct {
	AddrPort netip.AddrPort
	Class    TargetClass
	Protocol Protocol
}

// NewEgressTarget classifies a destination without trusting caller input.
func NewEgressTarget(target netip.AddrPort, protocol Protocol) EgressTarget {
	return EgressTarget{AddrPort: target, Class: ClassifyTarget(target), Protocol: protocol}
}

// ClassifyTarget returns the highest-precedence security classification.
func ClassifyTarget(target netip.AddrPort) TargetClass {
	if !target.IsValid() {
		return TargetClassUnspecified
	}
	addr := target.Addr().Unmap()
	if isCloudMetadata(addr) {
		return TargetClassCloudMetadata
	}
	switch {
	case !addr.IsValid() || addr.IsUnspecified():
		return TargetClassUnspecified
	case addr.IsLoopback():
		return TargetClassLoopback
	case addr.IsLinkLocalUnicast() || addr.Zone() != "":
		return TargetClassLinkLocal
	case addr.IsMulticast():
		return TargetClassMulticast
	case addr.IsPrivate():
		return TargetClassPrivate
	case addr.Is6():
		return TargetClassIPv6
	case !addr.IsGlobalUnicast():
		return TargetClassReserved
	default:
		return TargetClassPublic
	}
}

func isCloudMetadata(addr netip.Addr) bool {
	addr = addr.Unmap()
	return addr == netip.MustParseAddr("169.254.169.254") ||
		addr == netip.MustParseAddr("fd00:ec2::254")
}

func isKnownTargetClass(class TargetClass) bool {
	switch class {
	case TargetClassPublic, TargetClassPrivate, TargetClassLoopback, TargetClassLinkLocal,
		TargetClassMulticast, TargetClassUnspecified, TargetClassCloudMetadata,
		TargetClassIPv6, TargetClassReserved:
		return true
	default:
		return false
	}
}

// IsReservedManagementPort reports whether a destination port is reserved for
// remote administration and must not be reachable through a lease.
func IsReservedManagementPort(port uint16) bool {
	switch port {
	case 22, 23, 135, 139, 445, 2375, 2376, 3389, 5985, 5986, 6443, 10250, 10255:
		return true
	default:
		return false
	}
}

func validateLeaseIdentifier(value, label string) error {
	if !leaseIdentifierPattern.MatchString(strings.TrimSpace(value)) {
		return fmt.Errorf("%w: %s must contain only ASCII letters, digits, '.', '_', ':' or '-'", ErrInvalidLease, label)
	}
	return nil
}

func statusForLease(lease Lease, now time.Time) LeaseStatus {
	if lease.RevokedAt != nil {
		return LeaseStatusRevoked
	}
	if !now.Before(lease.ExpiresAt) {
		return LeaseStatusExpired
	}
	return LeaseStatusActive
}
