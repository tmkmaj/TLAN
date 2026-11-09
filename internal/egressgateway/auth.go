package egressgateway

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// LeaseIssuerConfig configures an in-memory lease issuer. Persistence is
// intentionally out of scope for this package; a control-plane adapter can own
// durable storage in a later integration task.
type LeaseIssuerConfig struct {
	Now             func() time.Time
	GatewayEndpoint string
	DefaultTTL      time.Duration
	MaxTTL          time.Duration
	DefaultLimits   Limits
}

type leaseRecord struct {
	lease          Lease
	capabilityHash [sha256.Size]byte
}

// LeaseIssuer owns thread-safe, in-memory leases. Raw capability values are
// returned only from Issue and are represented in the store by a SHA-256 hash.
type LeaseIssuer struct {
	mu              sync.RWMutex
	leases          map[string]leaseRecord
	now             func() time.Time
	gatewayEndpoint string
	defaultTTL      time.Duration
	maxTTL          time.Duration
	defaultLimits   Limits
}

// NewLeaseIssuer constructs an issuer. Missing TTL and limit values receive
// conservative defaults. GatewayEndpoint is still required by Issue.
func NewLeaseIssuer(config LeaseIssuerConfig) *LeaseIssuer {
	now := config.Now
	if now == nil {
		now = time.Now
	}
	defaultTTL := config.DefaultTTL
	if defaultTTL <= 0 {
		defaultTTL = DefaultLeaseTTL
	}
	maxTTL := config.MaxTTL
	if maxTTL <= 0 {
		maxTTL = MaxLeaseTTL
	}
	if defaultTTL > maxTTL {
		defaultTTL = maxTTL
	}
	defaultLimits := config.DefaultLimits
	if defaultLimits.isZero() {
		defaultLimits = Limits{
			MaxConnections: DefaultMaxConnections,
			MaxBytes:       DefaultMaxBytes,
			MaxRateBPS:     DefaultMaxRateBPS,
		}
	}
	return &LeaseIssuer{
		leases:          make(map[string]leaseRecord),
		now:             now,
		gatewayEndpoint: strings.TrimSpace(config.GatewayEndpoint),
		defaultTTL:      defaultTTL,
		maxTTL:          maxTTL,
		defaultLimits:   defaultLimits,
	}
}

// Issue creates a lease scoped to one device, profile, and rule. The returned
// Lease includes Capability exactly once; subsequent Get and Renew results do
// not include it.
func (i *LeaseIssuer) Issue(deviceID, profileID, ruleID string, policy Policy, ttl time.Duration) (Lease, error) {
	if err := validateLeaseIdentifier(deviceID, "device_id"); err != nil {
		return Lease{}, err
	}
	if err := validateLeaseIdentifier(profileID, "profile_id"); err != nil {
		return Lease{}, err
	}
	if err := validateLeaseIdentifier(ruleID, "rule_id"); err != nil {
		return Lease{}, err
	}
	if err := validateGatewayEndpoint(i.gatewayEndpoint); err != nil {
		return Lease{}, err
	}
	policy = policy.Clone()
	if err := policy.Validate(); err != nil {
		return Lease{}, err
	}
	limits := policy.Limits
	if limits.isZero() {
		limits = i.defaultLimits
	}
	if err := limits.Validate(); err != nil {
		return Lease{}, fmt.Errorf("%w: %v", ErrInvalidLease, err)
	}
	ttl, err := i.normalizeTTL(ttl)
	if err != nil {
		return Lease{}, err
	}

	leaseID, err := randomCapability("egl_", 18)
	if err != nil {
		return Lease{}, err
	}
	nonce, err := randomCapability("nonce_", 24)
	if err != nil {
		return Lease{}, err
	}
	capability, err := randomCapability("egc_", 32)
	if err != nil {
		return Lease{}, err
	}
	now := i.nowUTC()
	lease := Lease{
		ID:              leaseID,
		DeviceID:        deviceID,
		ProfileID:       profileID,
		RuleID:          ruleID,
		PolicyVersion:   policy.Version,
		IssuedAt:        now,
		ExpiresAt:       now.Add(ttl),
		Nonce:           nonce,
		GatewayEndpoint: i.gatewayEndpoint,
		Limits:          limits,
		Policy:          policy,
		Capability:      capability,
	}
	record := leaseRecord{lease: lease.Clone(), capabilityHash: sha256.Sum256([]byte(capability))}
	record.lease.Capability = ""

	i.mu.Lock()
	if _, exists := i.leases[leaseID]; exists {
		i.mu.Unlock()
		return Lease{}, fmt.Errorf("%w: generated lease identifier collision", ErrInvalidLease)
	}
	i.leases[leaseID] = record
	i.mu.Unlock()
	return lease.Clone(), nil
}

// Renew extends an active lease after checking its device binding.
func (i *LeaseIssuer) Renew(leaseID, deviceID string, ttl time.Duration) (Lease, error) {
	if err := validateLeaseIdentifier(leaseID, "lease_id"); err != nil {
		return Lease{}, err
	}
	if err := validateLeaseIdentifier(deviceID, "device_id"); err != nil {
		return Lease{}, err
	}
	ttl, err := i.normalizeTTL(ttl)
	if err != nil {
		return Lease{}, err
	}

	i.mu.Lock()
	defer i.mu.Unlock()
	record, ok := i.leases[leaseID]
	if !ok {
		return Lease{}, ErrLeaseNotFound
	}
	if record.lease.DeviceID != deviceID {
		return Lease{}, ErrLeaseUnauthorized
	}
	now := i.nowUTC()
	if record.lease.RevokedAt != nil {
		return Lease{}, ErrLeaseRevoked
	}
	if !now.Before(record.lease.ExpiresAt) {
		return Lease{}, ErrLeaseExpired
	}
	record.lease.ExpiresAt = now.Add(ttl)
	i.leases[leaseID] = record
	return record.lease.Clone(), nil
}

// Revoke marks an active lease revoked. It is safe for an administrative
// caller that has already established authorization.
func (i *LeaseIssuer) Revoke(leaseID string, reason RevocationReason) error {
	return i.revoke(leaseID, "", reason, false)
}

// RevokeForDevice revokes a lease only when it is bound to deviceID.
func (i *LeaseIssuer) RevokeForDevice(leaseID, deviceID string, reason RevocationReason) error {
	if err := validateLeaseIdentifier(deviceID, "device_id"); err != nil {
		return err
	}
	return i.revoke(leaseID, deviceID, reason, true)
}

func (i *LeaseIssuer) revoke(leaseID, deviceID string, reason RevocationReason, bindDevice bool) error {
	if err := validateLeaseIdentifier(leaseID, "lease_id"); err != nil {
		return err
	}
	if !isKnownRevocationReason(reason) {
		return fmt.Errorf("%w: unsupported revocation reason %q", ErrInvalidLease, reason)
	}

	i.mu.Lock()
	defer i.mu.Unlock()
	record, ok := i.leases[leaseID]
	if !ok {
		return ErrLeaseNotFound
	}
	if bindDevice && record.lease.DeviceID != deviceID {
		return ErrLeaseUnauthorized
	}
	if record.lease.RevokedAt != nil {
		return ErrLeaseRevoked
	}
	now := i.nowUTC()
	if !now.Before(record.lease.ExpiresAt) {
		return ErrLeaseExpired
	}
	revokedAt := now
	record.lease.RevokedAt = &revokedAt
	record.lease.RevocationReason = reason
	i.leases[leaseID] = record
	return nil
}

// Get returns a lease without its raw capability. Expired and revoked leases
// remain retrievable for status reporting; use Verify for admission.
func (i *LeaseIssuer) Get(leaseID string) (Lease, error) {
	if err := validateLeaseIdentifier(leaseID, "lease_id"); err != nil {
		return Lease{}, err
	}
	i.mu.RLock()
	record, ok := i.leases[leaseID]
	i.mu.RUnlock()
	if !ok {
		return Lease{}, ErrLeaseNotFound
	}
	lease := record.lease.Clone()
	lease.Capability = ""
	return lease, nil
}

// Status reports active, revoked, or expired without exposing credentials.
func (i *LeaseIssuer) Status(leaseID string) (LeaseStatus, error) {
	lease, err := i.Get(leaseID)
	if err != nil {
		return "", err
	}
	return statusForLease(lease, i.nowUTC()), nil
}

// Verify validates device binding, capability, expiry, revocation, and policy
// version before a data session is admitted.
func (i *LeaseIssuer) Verify(leaseID, deviceID, capability string, policyVersion int) (Lease, error) {
	if err := validateLeaseIdentifier(leaseID, "lease_id"); err != nil {
		return Lease{}, err
	}
	if err := validateLeaseIdentifier(deviceID, "device_id"); err != nil {
		return Lease{}, err
	}
	if capability == "" {
		return Lease{}, ErrLeaseUnauthorized
	}

	i.mu.RLock()
	record, ok := i.leases[leaseID]
	i.mu.RUnlock()
	if !ok {
		return Lease{}, ErrLeaseNotFound
	}
	if record.lease.DeviceID != deviceID {
		return Lease{}, ErrLeaseUnauthorized
	}
	actualHash := sha256.Sum256([]byte(capability))
	if subtle.ConstantTimeCompare(record.capabilityHash[:], actualHash[:]) != 1 {
		return Lease{}, ErrLeaseUnauthorized
	}
	now := i.nowUTC()
	if record.lease.RevokedAt != nil {
		return Lease{}, ErrLeaseRevoked
	}
	if !now.Before(record.lease.ExpiresAt) {
		return Lease{}, ErrLeaseExpired
	}
	if record.lease.PolicyVersion != policyVersion {
		return Lease{}, ErrPolicyVersionMismatch
	}
	lease := record.lease.Clone()
	lease.Capability = ""
	return lease, nil
}

func (i *LeaseIssuer) normalizeTTL(ttl time.Duration) (time.Duration, error) {
	if ttl <= 0 {
		ttl = i.defaultTTL
	}
	if ttl > i.maxTTL {
		return 0, fmt.Errorf("%w: ttl exceeds maximum %s", ErrInvalidLease, i.maxTTL)
	}
	return ttl, nil
}

func (i *LeaseIssuer) nowUTC() time.Time {
	return i.now().UTC()
}

func randomCapability(prefix string, byteCount int) (string, error) {
	data := make([]byte, byteCount)
	if _, err := rand.Read(data); err != nil {
		return "", fmt.Errorf("%w: generate capability: %v", ErrInvalidLease, err)
	}
	return prefix + base64.RawURLEncoding.EncodeToString(data), nil
}

func validateGatewayEndpoint(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > 512 || strings.ContainsAny(raw, "\x00\r\n\t ") {
		return fmt.Errorf("%w: gateway_endpoint is required", ErrInvalidLease)
	}
	if parsed, err := url.Parse(raw); err == nil && parsed.Scheme != "" && parsed.Host != "" {
		switch parsed.Scheme {
		case "https", "tls", "wss":
			return nil
		default:
			return fmt.Errorf("%w: gateway_endpoint scheme must be https, tls, or wss", ErrInvalidLease)
		}
	}
	host, portText, err := net.SplitHostPort(raw)
	if err != nil || strings.TrimSpace(host) == "" {
		return fmt.Errorf("%w: gateway_endpoint must be a URL or host:port", ErrInvalidLease)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("%w: gateway_endpoint port is invalid", ErrInvalidLease)
	}
	return nil
}

func isKnownRevocationReason(reason RevocationReason) bool {
	switch reason {
	case RevocationReasonClientRequested, RevocationReasonAdministrator,
		RevocationReasonPolicyChanged, RevocationReasonSecurity, RevocationReasonShutdown:
		return true
	default:
		return false
	}
}
