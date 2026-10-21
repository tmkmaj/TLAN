// Package frpauth implements the TLAN-managed FRP authorization boundary.
//
// The package deliberately has no dependency on the FRP Go packages. FRPS
// talks to it through the fixed v0.71.1 server HTTP-plugin protocol, while the
// TLAN control plane issues short-lived, device-scoped publish leases.
package frpauth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/private-radminlan/lanmesh/core"
)

const (
	SchemaVersion = 1

	ModeDisabled = "disabled"
	ModeExternal = "external"
	ModeManaged  = "managed"

	DefaultLeaseTTL = 15 * time.Minute
	MaxLeaseTTL     = 24 * time.Hour

	DefaultMaxRulesPerLease    = 16
	DefaultMaxLeasesPerDevice  = 4
	DefaultMaxPortsPerDevice   = 16
	DefaultMaxDomainsPerDevice = 16
	DefaultMaxDomainsPerRule   = 16
	DefaultRetention           = 24 * time.Hour

	ServiceApprovalPending     = "pending"
	ServiceApprovalApproved    = "approved"
	ServiceApprovalDenied      = "denied"
	MaxPersistedLeaseRecords   = 4096
	MaxPersistedServiceRecords = 4096
	MaxCapabilityBytes         = 128
	MaxProxyNameLength         = 128
	MaxRuleIDLength            = 64
	MaxCustomDomainsPerRequest = 64
	MaxHeaderFields            = 32
	MaxLocations               = 32
)

var (
	ErrDisabled     = errors.New("managed FRP is disabled")
	ErrInvalid      = errors.New("invalid FRP lease request")
	ErrNotFound     = errors.New("FRP lease not found")
	ErrConflict     = errors.New("FRP lease resource conflict")
	ErrQuota        = errors.New("FRP lease quota exceeded")
	ErrExpired      = errors.New("FRP lease expired")
	ErrRevoked      = errors.New("FRP lease revoked")
	ErrUnauthorized = errors.New("FRP lease authentication failed")
	ErrPortDenied   = errors.New("FRP remote port denied")
	ErrDomainDenied = errors.New("FRP custom domain denied")

	identifierPattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	proxyNamePattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	domainLabelPattern = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)
)

// Rule is one resource granted by a lease. It is also the public request and
// response shape for the control-plane lease API.
type Rule struct {
	ID            string   `json:"id"`
	ProxyName     string   `json:"proxy_name"`
	Type          string   `json:"type"`
	RemotePort    int      `json:"remote_port,omitempty"`
	CustomDomains []string `json:"custom_domains,omitempty"`
	BindPort      int      `json:"bind_port"`

	// Advanced FRP v0.71.1 proxy fields. Secret values are never stored in
	// this type: HTTPPasswordHash and SecretHash contain only SHA-256
	// digests of the values sent by frpc to the FRPS plugin.
	SubDomain         string            `json:"subdomain,omitempty"`
	Locations         []string          `json:"locations,omitempty"`
	HTTPUser          string            `json:"http_user,omitempty"`
	HTTPPasswordHash  string            `json:"http_password_hash,omitempty"`
	HostHeaderRewrite string            `json:"host_header_rewrite,omitempty"`
	Headers           map[string]string `json:"headers,omitempty"`
	ResponseHeaders   map[string]string `json:"response_headers,omitempty"`
	RouteByHTTPUser   string            `json:"route_by_http_user,omitempty"`
	Multiplexer       string            `json:"multiplexer,omitempty"`
	SecretHash        string            `json:"secret_hash,omitempty"`
	AllowUsers        []string          `json:"allow_users,omitempty"`
	UseEncryption     bool              `json:"use_encryption,omitempty"`
	UseCompression    bool              `json:"use_compression,omitempty"`

	// Target grant fields bind a mesh_peer/mesh_self rule to one exact
	// member identity and virtual address. They are empty for ordinary
	// loopback/LAN rules and are never inferred from a client-supplied name.
	TargetKind      string `json:"target_kind,omitempty"`
	TargetNetworkID string `json:"target_network_id,omitempty"`
	TargetDeviceID  string `json:"target_device_id,omitempty"`
	TargetPublicKey string `json:"target_public_key,omitempty"`
	TargetHost      string `json:"target_host,omitempty"`
	TargetServiceID string `json:"target_service_id,omitempty"`
	GrantID         string `json:"grant_id,omitempty"`
}

// ServiceResponse is an administrator-managed target-service authorization.
// A publisher must reference its ID before a mesh_peer lease can be issued.
type ServiceResponse struct {
	ID                string     `json:"id"`
	ServerID          string     `json:"server_id"`
	NetworkID         string     `json:"network_id"`
	DeviceID          string     `json:"device_id"`
	RequesterDeviceID string     `json:"requester_device_id,omitempty"`
	Protocol          string     `json:"protocol"`
	Port              int        `json:"port"`
	Description       string     `json:"description,omitempty"`
	ApprovalStatus    string     `json:"approval_status"`
	ApprovedAt        *time.Time `json:"approved_at,omitempty"`
	ApprovedBy        string     `json:"approved_by,omitempty"`
	DeniedAt          *time.Time `json:"denied_at,omitempty"`
	CreatedAt         time.Time  `json:"created_at"`
	ExpiresAt         time.Time  `json:"expires_at"`
	RevokedAt         *time.Time `json:"revoked_at,omitempty"`
	Version           uint64     `json:"version"`
}

// LeaseResponse is the only lease representation returned to a member. The
// capability is returned exactly once and is never persisted in plaintext.
type LeaseResponse struct {
	LeaseID    string    `json:"lease_id"`
	Credential string    `json:"credential"`
	ExpiresAt  time.Time `json:"expires_at"`
	Rules      []Rule    `json:"rules"`
}

// Capabilities describes the managed FRP control-plane contract. It is
// intentionally metadata-only and never includes a token or capability.
type Capabilities struct {
	Mode        string   `json:"mode"`
	CoreVersion string   `json:"core_version"`
	ServerID    string   `json:"server_id"`
	LeaseTTL    int64    `json:"lease_ttl_seconds"`
	PluginOps   []string `json:"plugin_ops"`
	Features    []string `json:"features"`
}

// LeaseStatus is the server-side observation of a managed lease. It lets a
// client prove that the configured FRPS actually reached the authorization
// plugin before the client reports a managed runtime as healthy.
type LeaseStatus struct {
	LeaseID   string    `json:"lease_id"`
	ExpiresAt time.Time `json:"expires_at"`
	Revoked   bool      `json:"revoked"`
	LoginSeen bool      `json:"login_seen"`
	ProxySeen bool      `json:"proxy_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// Limits bounds resources owned by a single device and by one lease.
type Limits struct {
	MaxRulesPerLease    int
	MaxLeasesPerDevice  int
	MaxPortsPerDevice   int
	MaxDomainsPerDevice int
	MaxDomainsPerRule   int
}

// PortRange is an inclusive server-side remote-port range.
type PortRange struct {
	Start int
	End   int
}

// Options configures a managed authorization store.
type Options struct {
	StatePath      string
	ServerID       string
	CoreVersion    string
	LeaseTTL       time.Duration
	Limits         Limits
	AllowedPorts   []PortRange
	AllowedDomains []string
}

// LoginRequest is the normalized identity information extracted from FRPS's
// Login plugin hook.
type LoginRequest struct {
	LeaseID    string
	Capability string
	ServerID   string
	User       string
	RunID      string
}

// NewProxyRequest is the normalized proxy information extracted from FRPS's
// NewProxy plugin hook. FRPS does not expose localIP/localPort here, so this
// check authorizes the public resource only; target enforcement remains a
// client-side TargetGateway responsibility.
type NewProxyRequest struct {
	LeaseID            string
	Capability         string
	ServerID           string
	User               string
	RunID              string
	ProxyName          string
	ProxyType          string
	RemotePort         int
	CustomDomains      []string
	SubDomain          string
	Locations          []string
	HTTPUser           string
	HTTPPwd            string
	HostHeaderRewrite  string
	Headers            map[string]string
	ResponseHeaders    map[string]string
	RouteByHTTPUser    string
	Group              string
	GroupKey           string
	Sk                 string
	AllowUsers         []string
	Multiplexer        string
	UseEncryption      bool
	UseCompression     bool
	BandwidthLimit     string
	BandwidthLimitMode string
	Metas              map[string]string
	Annotations        map[string]string
}

// SessionRequest is the identity carried by FRPS heartbeat hooks. It binds
// an existing lease to the FRPS-assigned run ID without extending the lease.
type SessionRequest struct {
	LeaseID    string
	Capability string
	ServerID   string
	User       string
	RunID      string
}

// UserConnRequest is emitted by FRPS before a new TCP user connection is
// admitted. It lets the authorization layer reject new connections as soon as
// a lease is revoked; existing streams are terminated by the heartbeat path.
type UserConnRequest struct {
	LeaseID    string
	Capability string
	ServerID   string
	User       string
	RunID      string
	ProxyName  string
	ProxyType  string
	RemoteAddr string
}

func validateID(value, label string) error {
	value = strings.TrimSpace(value)
	if !identifierPattern.MatchString(value) {
		return fmt.Errorf("%w: %s must be 1-%d ASCII letters, digits, '.', '_' or '-'", ErrInvalid, label, MaxRuleIDLength)
	}
	return nil
}

func validateProxyName(value string) error {
	if !proxyNamePattern.MatchString(strings.TrimSpace(value)) {
		return fmt.Errorf("%w: proxy_name must be 1-%d ASCII letters, digits, '.', '_' or '-'", ErrInvalid, MaxProxyNameLength)
	}
	return nil
}

func validateCapability(value string) error {
	if len(value) < 32 || len(value) > MaxCapabilityBytes || strings.ContainsAny(value, "\x00\r\n") {
		return fmt.Errorf("%w: invalid capability", ErrUnauthorized)
	}
	return nil
}

func normalizeDomain(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" || len(value) > 253 || strings.ContainsAny(value, "\x00\r\n/*") {
		return "", fmt.Errorf("%w: invalid custom domain", ErrInvalid)
	}
	if _, err := netip.ParseAddr(value); err == nil {
		return "", fmt.Errorf("%w: IP addresses are not custom domains", ErrInvalid)
	}
	labels := strings.Split(value, ".")
	if len(labels) < 2 {
		return "", fmt.Errorf("%w: custom domain must contain a dot", ErrInvalid)
	}
	for _, label := range labels {
		if !domainLabelPattern.MatchString(label) {
			return "", fmt.Errorf("%w: invalid custom domain label", ErrInvalid)
		}
	}
	return value, nil
}

func normalizeDomainSuffix(value string) (string, error) {
	value = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(value)), ".")
	if value == "" || strings.ContainsAny(value, "\x00\r\n/*") {
		return "", fmt.Errorf("%w: invalid allowed domain suffix", ErrInvalid)
	}
	if _, err := netip.ParseAddr(value); err == nil {
		return "", fmt.Errorf("%w: allowed domain suffix cannot be an IP address", ErrInvalid)
	}
	labels := strings.Split(value, ".")
	for _, label := range labels {
		if !domainLabelPattern.MatchString(label) {
			return "", fmt.Errorf("%w: invalid allowed domain suffix", ErrInvalid)
		}
	}
	return value, nil
}

func domainAllowed(domain string, suffixes []string) bool {
	for _, suffix := range suffixes {
		if domain == suffix || strings.HasSuffix(domain, "."+suffix) {
			return true
		}
	}
	return false
}

func normalizePortRanges(ranges []PortRange) ([]PortRange, error) {
	out := append([]PortRange(nil), ranges...)
	sort.Slice(out, func(i, j int) bool { return out[i].Start < out[j].Start })
	for i, r := range out {
		if r.Start < 1 || r.End > 65535 || r.Start > r.End {
			return nil, fmt.Errorf("%w: invalid allowed port range", ErrInvalid)
		}
		if i > 0 && r.Start <= out[i-1].End {
			return nil, fmt.Errorf("%w: allowed port ranges overlap", ErrInvalid)
		}
	}
	return out, nil
}

func portAllowed(port int, ranges []PortRange) bool {
	for _, r := range ranges {
		if port >= r.Start && port <= r.End {
			return true
		}
	}
	return false
}

func normalizeLimits(l Limits) (Limits, error) {
	if l.MaxRulesPerLease == 0 {
		l.MaxRulesPerLease = DefaultMaxRulesPerLease
	}
	if l.MaxLeasesPerDevice == 0 {
		l.MaxLeasesPerDevice = DefaultMaxLeasesPerDevice
	}
	if l.MaxPortsPerDevice == 0 {
		l.MaxPortsPerDevice = DefaultMaxPortsPerDevice
	}
	if l.MaxDomainsPerDevice == 0 {
		l.MaxDomainsPerDevice = DefaultMaxDomainsPerDevice
	}
	if l.MaxDomainsPerRule == 0 {
		l.MaxDomainsPerRule = DefaultMaxDomainsPerRule
	}
	if l.MaxRulesPerLease < 1 || l.MaxLeasesPerDevice < 1 || l.MaxPortsPerDevice < 1 ||
		l.MaxDomainsPerDevice < 1 || l.MaxDomainsPerRule < 1 {
		return Limits{}, fmt.Errorf("%w: invalid lease limits", ErrInvalid)
	}
	if l.MaxRulesPerLease > 64 || l.MaxDomainsPerRule > MaxCustomDomainsPerRequest {
		return Limits{}, fmt.Errorf("%w: lease limits exceed supported bounds", ErrInvalid)
	}
	return l, nil
}

func normalizeRule(rule Rule, allowedPorts []PortRange, allowedDomains []string, maxDomains int, enforcePolicy bool) (Rule, error) {
	rule.ID = strings.TrimSpace(rule.ID)
	rule.ProxyName = strings.TrimSpace(rule.ProxyName)
	rule.Type = strings.ToLower(strings.TrimSpace(rule.Type))
	rule.SubDomain = strings.ToLower(strings.TrimSpace(rule.SubDomain))
	rule.HTTPUser = strings.TrimSpace(rule.HTTPUser)
	rule.HTTPPasswordHash = strings.TrimSpace(rule.HTTPPasswordHash)
	rule.HostHeaderRewrite = strings.TrimSpace(rule.HostHeaderRewrite)
	rule.RouteByHTTPUser = strings.TrimSpace(rule.RouteByHTTPUser)
	rule.Multiplexer = strings.ToLower(strings.TrimSpace(rule.Multiplexer))
	rule.SecretHash = strings.TrimSpace(rule.SecretHash)
	rule.TargetKind = strings.ToLower(strings.TrimSpace(rule.TargetKind))
	rule.TargetNetworkID = strings.TrimSpace(rule.TargetNetworkID)
	rule.TargetDeviceID = strings.TrimSpace(rule.TargetDeviceID)
	rule.TargetPublicKey = strings.TrimSpace(rule.TargetPublicKey)
	rule.TargetHost = strings.TrimSpace(rule.TargetHost)
	rule.TargetServiceID = strings.TrimSpace(rule.TargetServiceID)
	rule.GrantID = strings.TrimSpace(rule.GrantID)
	if err := validateID(rule.ID, "rule id"); err != nil {
		return Rule{}, err
	}
	if err := validateProxyName(rule.ProxyName); err != nil {
		return Rule{}, err
	}
	if rule.BindPort < 1 || rule.BindPort > 65535 {
		return Rule{}, fmt.Errorf("%w: bind_port must be 1-65535", ErrInvalid)
	}
	var err error
	rule, err = normalizeTargetGrant(rule)
	if err != nil {
		return Rule{}, err
	}
	if rule.HTTPPasswordHash, err = normalizeSecretHash(rule.HTTPPasswordHash); err != nil {
		return Rule{}, err
	}
	if rule.SecretHash, err = normalizeSecretHash(rule.SecretHash); err != nil {
		return Rule{}, err
	}
	if rule.Headers, err = normalizeRuleHeaders("request headers", rule.Headers); err != nil {
		return Rule{}, err
	}
	if rule.ResponseHeaders, err = normalizeRuleHeaders("response headers", rule.ResponseHeaders); err != nil {
		return Rule{}, err
	}
	if rule.Locations, err = normalizeRuleLocations(rule.Locations); err != nil {
		return Rule{}, err
	}
	if rule.AllowUsers, err = normalizeAllowUsers(rule.AllowUsers); err != nil {
		return Rule{}, err
	}
	if rule.Type == "tcpmux" && rule.Multiplexer == "" {
		rule.Multiplexer = "httpconnect"
	}

	switch rule.Type {
	case "tcp", "udp":
		if err := rejectHTTPAdvancedFields(rule, false, false); err != nil {
			return Rule{}, err
		}
		if rule.RemotePort < 1 || rule.RemotePort > 65535 {
			return Rule{}, fmt.Errorf("%w: remote_port must be 1-65535", ErrInvalid)
		}
		if enforcePolicy && !portAllowed(rule.RemotePort, allowedPorts) {
			return Rule{}, fmt.Errorf("%w: remote_port is outside the managed port ranges", ErrInvalid)
		}
		if len(rule.CustomDomains) != 0 || rule.SubDomain != "" {
			return Rule{}, fmt.Errorf("%w: custom_domains/subdomain are only valid for http/https/tcpmux", ErrInvalid)
		}
		rule.CustomDomains = nil
	case "http", "https", "tcpmux":
		if rule.RemotePort != 0 {
			return Rule{}, fmt.Errorf("%w: remote_port is not valid for http/https/tcpmux", ErrInvalid)
		}
		if len(rule.CustomDomains) == 0 && rule.SubDomain == "" {
			return Rule{}, fmt.Errorf("%w: http/https/tcpmux requires custom_domains or subdomain", ErrInvalid)
		}
		if err := normalizeRuleDomains(&rule, allowedDomains, maxDomains, enforcePolicy); err != nil {
			return Rule{}, err
		}
		if rule.Type == "https" {
			if err := rejectHTTPAdvancedFields(rule, false, true); err != nil {
				return Rule{}, err
			}
			break
		}
		if err := validateHTTPAdvancedFields(rule); err != nil {
			return Rule{}, err
		}
	case "stcp", "sudp", "xtcp":
		if rule.RemotePort != 0 || len(rule.CustomDomains) != 0 || rule.SubDomain != "" {
			return Rule{}, fmt.Errorf("%w: private rules cannot request a public port or domain", ErrInvalid)
		}
		if err := rejectHTTPAdvancedFields(rule, true, false); err != nil {
			return Rule{}, err
		}
		if rule.Type == "xtcp" && rule.SecretHash == "" {
			return Rule{}, fmt.Errorf("%w: xtcp requires a SHA-256 secret_hash", ErrInvalid)
		}
	default:
		return Rule{}, fmt.Errorf("%w: unsupported proxy type", ErrInvalid)
	}
	return rule, nil
}

func ruleDomainKeys(rule Rule) []string {
	out := append([]string(nil), rule.CustomDomains...)
	if rule.SubDomain != "" {
		out = append(out, "@"+rule.SubDomain)
	}
	return out
}

func normalizeRuleDomains(rule *Rule, allowedDomains []string, maxDomains int, enforcePolicy bool) error {
	if len(rule.CustomDomains) > MaxCustomDomainsPerRequest || (enforcePolicy && len(rule.CustomDomains) > maxDomains) {
		return fmt.Errorf("%w: too many custom_domains", ErrQuota)
	}
	seen := make(map[string]struct{}, len(rule.CustomDomains))
	domains := make([]string, 0, len(rule.CustomDomains))
	for _, raw := range rule.CustomDomains {
		domain, err := normalizeDomain(raw)
		if err != nil {
			return err
		}
		if enforcePolicy && !domainAllowed(domain, allowedDomains) {
			return fmt.Errorf("%w: custom domain is not allowed", ErrInvalid)
		}
		if _, exists := seen[domain]; exists {
			continue
		}
		seen[domain] = struct{}{}
		domains = append(domains, domain)
	}
	sort.Strings(domains)
	rule.CustomDomains = domains
	if rule.SubDomain != "" {
		if err := validateSubdomainLabel(rule.SubDomain); err != nil {
			return err
		}
		if enforcePolicy && len(rule.CustomDomains)+1 > maxDomains {
			return fmt.Errorf("%w: too many custom_domains/subdomain", ErrQuota)
		}
	}
	if len(rule.CustomDomains) == 0 && rule.SubDomain == "" {
		return fmt.Errorf("%w: http/https/tcpmux requires custom_domains or subdomain", ErrInvalid)
	}
	return nil
}

func validateHTTPAdvancedFields(rule Rule) error {
	if rule.SecretHash != "" || len(rule.AllowUsers) != 0 {
		return fmt.Errorf("%w: private secret fields are not valid for %s", ErrInvalid, rule.Type)
	}
	if rule.HTTPUser != "" || rule.HTTPPasswordHash != "" {
		if rule.Type != "http" && rule.Type != "tcpmux" {
			return fmt.Errorf("%w: HTTP authentication is only valid for http/tcpmux", ErrInvalid)
		}
		if rule.HTTPUser == "" || rule.HTTPPasswordHash == "" {
			return fmt.Errorf("%w: HTTP user and password hash must be set together", ErrInvalid)
		}
		if !validFRPName(rule.HTTPUser) {
			return fmt.Errorf("%w: HTTP user is invalid", ErrInvalid)
		}
	}
	if rule.HostHeaderRewrite != "" {
		if rule.Type != "http" {
			return fmt.Errorf("%w: host_header_rewrite is only valid for http", ErrInvalid)
		}
		if err := validateRuleText("host_header_rewrite", rule.HostHeaderRewrite, 253); err != nil {
			return err
		}
	}
	if rule.RouteByHTTPUser != "" {
		if rule.Type != "http" && rule.Type != "tcpmux" {
			return fmt.Errorf("%w: route_by_http_user is only valid for http/tcpmux", ErrInvalid)
		}
		if !validFRPName(rule.RouteByHTTPUser) {
			return fmt.Errorf("%w: route_by_http_user is invalid", ErrInvalid)
		}
	}
	if rule.Multiplexer != "" && rule.Type != "tcpmux" {
		return fmt.Errorf("%w: multiplexer is only valid for tcpmux", ErrInvalid)
	}
	if rule.Type == "tcpmux" {
		if rule.Multiplexer == "" {
			rule.Multiplexer = "httpconnect"
		}
		if rule.Multiplexer != "httpconnect" {
			return fmt.Errorf("%w: tcpmux multiplexer must be httpconnect", ErrInvalid)
		}
		if len(rule.Locations) != 0 || len(rule.Headers) != 0 || len(rule.ResponseHeaders) != 0 || rule.HostHeaderRewrite != "" {
			return fmt.Errorf("%w: tcpmux does not support locations/header rewrites", ErrInvalid)
		}
	}
	if rule.Type == "http" {
		if err := validateRuleLocations(rule.Locations); err != nil {
			return err
		}
	} else if len(rule.Locations) != 0 {
		return fmt.Errorf("%w: locations are only valid for http", ErrInvalid)
	}
	return nil
}

func rejectHTTPAdvancedFields(rule Rule, allowSecret bool, allowDomainOnly bool) error {
	if len(rule.Locations) != 0 || rule.HTTPUser != "" || rule.HTTPPasswordHash != "" ||
		rule.HostHeaderRewrite != "" || len(rule.Headers) != 0 || len(rule.ResponseHeaders) != 0 ||
		rule.RouteByHTTPUser != "" || rule.Multiplexer != "" {
		return fmt.Errorf("%w: advanced HTTP fields are not valid for %s", ErrInvalid, rule.Type)
	}
	if !allowSecret && (rule.SecretHash != "" || len(rule.AllowUsers) != 0) {
		return fmt.Errorf("%w: private secret fields are not valid for %s", ErrInvalid, rule.Type)
	}
	if !allowDomainOnly && rule.SubDomain != "" {
		return fmt.Errorf("%w: subdomain is not valid for %s", ErrInvalid, rule.Type)
	}
	return nil
}

func normalizeSecretHash(value string) (string, error) {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" {
		return "", nil
	}
	value = strings.TrimPrefix(value, "sha256:")
	if len(value) != 64 {
		return "", fmt.Errorf("%w: secret hash must be a SHA-256 hex digest", ErrInvalid)
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size {
		return "", fmt.Errorf("%w: secret hash must be a SHA-256 hex digest", ErrInvalid)
	}
	return hex.EncodeToString(decoded), nil
}

func normalizeRuleHeaders(label string, values map[string]string) (map[string]string, error) {
	if len(values) == 0 {
		return nil, nil
	}
	if len(values) > MaxHeaderFields {
		return nil, fmt.Errorf("%w: %s supports at most %d fields", ErrInvalid, label, MaxHeaderFields)
	}
	out := make(map[string]string, len(values))
	for rawKey, rawValue := range values {
		key := strings.TrimSpace(rawKey)
		if !validHTTPHeaderName(key) {
			return nil, fmt.Errorf("%w: invalid %s name", ErrInvalid, label)
		}
		value := strings.TrimSpace(rawValue)
		if len(value) > 4096 || strings.ContainsAny(value, "\x00\r\n") {
			return nil, fmt.Errorf("%w: invalid %s value", ErrInvalid, label)
		}
		out[key] = value
	}
	return out, nil
}

func validHTTPHeaderName(value string) bool {
	if value == "" || len(value) > 256 {
		return false
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			continue
		}
		switch r {
		case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '|', '~':
		default:
			return false
		}
	}
	return true
}

func normalizeRuleLocations(values []string) ([]string, error) {
	if len(values) == 0 {
		return nil, nil
	}
	if len(values) > MaxLocations {
		return nil, fmt.Errorf("%w: at most %d locations are supported", ErrInvalid, MaxLocations)
	}
	out := make([]string, 0, len(values))
	for _, raw := range values {
		value := strings.TrimSpace(raw)
		if value == "" || len(value) > 256 || !strings.HasPrefix(value, "/") ||
			strings.ContainsAny(value, "\x00\r\n\t ") || strings.Contains(value, "..") {
			return nil, fmt.Errorf("%w: invalid HTTP location", ErrInvalid)
		}
		out = append(out, value)
	}
	sort.Strings(out)
	return out, nil
}

func validateRuleLocations(values []string) error {
	if _, err := normalizeRuleLocations(values); err != nil {
		return err
	}
	return nil
}

func normalizeAllowUsers(values []string) ([]string, error) {
	if len(values) == 0 {
		return nil, nil
	}
	if len(values) > 64 {
		return nil, fmt.Errorf("%w: too many allow_users", ErrInvalid)
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, raw := range values {
		value := strings.TrimSpace(raw)
		if value != "*" && !validFRPName(value) {
			return nil, fmt.Errorf("%w: invalid allow_users entry", ErrInvalid)
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out, nil
}

func validateSubdomainLabel(value string) error {
	if value == "" || len(value) > 63 || strings.ContainsAny(value, ".*/\x00\r\n\t ") {
		return fmt.Errorf("%w: subdomain must be a 1-63 character DNS label", ErrInvalid)
	}
	if value[0] == '-' || value[len(value)-1] == '-' {
		return fmt.Errorf("%w: subdomain must not start or end with '-'", ErrInvalid)
	}
	for _, r := range value {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
			return fmt.Errorf("%w: subdomain may contain only lowercase letters, digits and '-'", ErrInvalid)
		}
	}
	return nil
}

func validateRuleText(label, value string, max int) error {
	if value == "" || len(value) > max || strings.ContainsAny(value, "\x00\r\n") {
		return fmt.Errorf("%w: %s is invalid", ErrInvalid, label)
	}
	return nil
}

func validFRPName(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '_' && r != '-' && r != '.' {
			return false
		}
	}
	return true
}

func validateRules(rules []Rule, limits Limits, allowedPorts []PortRange, allowedDomains []string, enforcePolicy bool) ([]Rule, error) {
	if len(rules) == 0 {
		return nil, fmt.Errorf("%w: at least one rule is required", ErrInvalid)
	}
	if enforcePolicy && len(rules) > limits.MaxRulesPerLease {
		return nil, fmt.Errorf("%w: too many rules in one lease", ErrQuota)
	}
	out := make([]Rule, 0, len(rules))
	ids := make(map[string]struct{}, len(rules))
	names := make(map[string]struct{}, len(rules))
	ports := make(map[string]struct{}, len(rules))
	domains := make(map[string]struct{}, len(rules))
	for _, raw := range rules {
		rule, err := normalizeRule(raw, allowedPorts, allowedDomains, limits.MaxDomainsPerRule, enforcePolicy)
		if err != nil {
			return nil, err
		}
		if _, ok := ids[rule.ID]; ok {
			return nil, fmt.Errorf("%w: duplicate rule id", ErrInvalid)
		}
		if _, ok := names[rule.ProxyName]; ok {
			return nil, fmt.Errorf("%w: duplicate proxy_name", ErrInvalid)
		}
		ids[rule.ID] = struct{}{}
		names[rule.ProxyName] = struct{}{}
		if rule.RemotePort != 0 {
			key := rule.Type + ":" + fmt.Sprint(rule.RemotePort)
			if _, ok := ports[key]; ok {
				return nil, fmt.Errorf("%w: duplicate remote port for protocol", ErrInvalid)
			}
			ports[key] = struct{}{}
		}
		for _, domain := range ruleDomainKeys(rule) {
			if _, ok := domains[domain]; ok {
				return nil, fmt.Errorf("%w: duplicate custom domain/subdomain", ErrInvalid)
			}
			domains[domain] = struct{}{}
		}
		out = append(out, rule)
	}
	return out, nil
}

func newRandomSecret(prefix string, bytesCount int) (string, error) {
	data := make([]byte, bytesCount)
	if _, err := rand.Read(data); err != nil {
		return "", fmt.Errorf("generate %s: %w", prefix, err)
	}
	return prefix + base64.RawURLEncoding.EncodeToString(data), nil
}

func capabilityHash(capability string) string {
	sum := sha256.Sum256([]byte(capability))
	return hex.EncodeToString(sum[:])
}

// HashSecret returns the canonical SHA-256 digest used by managed leases for
// FRP private keys and HTTP basic-auth passwords. The plaintext value must
// never be persisted in a lease or lease request.
func HashSecret(secret string) string {
	return capabilityHash(secret)
}

func constantTimeHashMatch(expectedHash, capability string) bool {
	if expectedHash == "" || capability == "" {
		return false
	}
	actual := capabilityHash(capability)
	if len(expectedHash) != len(actual) {
		return false
	}
	var diff byte
	for i := range actual {
		diff |= expectedHash[i] ^ actual[i]
	}
	return diff == 0
}

func cloneRule(rule Rule) Rule {
	rule.CustomDomains = append([]string(nil), rule.CustomDomains...)
	rule.Locations = append([]string(nil), rule.Locations...)
	rule.AllowUsers = append([]string(nil), rule.AllowUsers...)
	rule.Headers = cloneRuleStringMap(rule.Headers)
	rule.ResponseHeaders = cloneRuleStringMap(rule.ResponseHeaders)
	return rule
}

func cloneRuleStringMap(source map[string]string) map[string]string {
	if source == nil {
		return nil
	}
	out := make(map[string]string, len(source))
	for key, value := range source {
		out[key] = value
	}
	return out
}

func cloneRules(rules []Rule) []Rule {
	out := make([]Rule, len(rules))
	for i, rule := range rules {
		out[i] = cloneRule(rule)
	}
	return out
}

func sameStringSet(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	seen := make(map[string]int, len(left))
	for _, value := range left {
		seen[value]++
	}
	for _, value := range right {
		seen[value]--
	}
	for _, count := range seen {
		if count != 0 {
			return false
		}
	}
	return true
}

func (r leaseRecord) clone() leaseRecord {
	out := r
	out.Rules = cloneRules(r.Rules)
	out.Proxies = make(map[string]string, len(r.Proxies))
	for key, value := range r.Proxies {
		out.Proxies[key] = value
	}
	return out
}

func (r leaseRecord) response(capability string) LeaseResponse {
	return LeaseResponse{
		LeaseID:    r.ID,
		Credential: capability,
		ExpiresAt:  r.ExpiresAt,
		Rules:      cloneRules(r.Rules),
	}
}

func normalizeTargetGrant(rule Rule) (Rule, error) {
	hasTarget := rule.TargetKind != "" || rule.TargetNetworkID != "" || rule.TargetDeviceID != "" || rule.TargetPublicKey != "" || rule.TargetHost != "" || rule.TargetServiceID != ""
	if !hasTarget {
		return rule, nil
	}
	if rule.TargetKind != "mesh_peer" && rule.TargetKind != "mesh_self" {
		return Rule{}, fmt.Errorf("%w: target_kind must be mesh_peer or mesh_self", ErrInvalid)
	}
	if _, err := core.NewNetworkID(rule.TargetNetworkID); err != nil {
		return Rule{}, fmt.Errorf("%w: invalid target_network_id", ErrInvalid)
	}
	if _, err := core.NewDeviceID(rule.TargetDeviceID); err != nil {
		return Rule{}, fmt.Errorf("%w: invalid target_device_id", ErrInvalid)
	}
	addr, err := netip.ParseAddr(rule.TargetHost)
	if err != nil || !addr.Is4() || addr.IsLoopback() || addr.IsUnspecified() || addr.IsMulticast() || addr.IsLinkLocalUnicast() {
		return Rule{}, fmt.Errorf("%w: target_host must be a unicast Mesh IPv4 address", ErrInvalid)
	}
	if rule.TargetPublicKey == "" {
		if rule.TargetKind == "mesh_peer" {
			return Rule{}, fmt.Errorf("%w: mesh_peer target_public_key is required", ErrInvalid)
		}
	} else if err := core.ValidateWireGuardPublicKey(rule.TargetPublicKey); err != nil {
		return Rule{}, fmt.Errorf("%w: invalid target_public_key", ErrInvalid)
	}
	if rule.TargetServiceID != "" {
		if err := validateID(rule.TargetServiceID, "target service id"); err != nil {
			return Rule{}, err
		}
	}
	return rule, nil
}

func validateServerID(serverID string) error {
	if !identifierPattern.MatchString(strings.TrimSpace(serverID)) {
		return fmt.Errorf("%w: invalid server_id", ErrInvalid)
	}
	return nil
}

func validateLeaseID(leaseID string) error {
	if !identifierPattern.MatchString(strings.TrimSpace(leaseID)) {
		return fmt.Errorf("%w: invalid lease_id", ErrInvalid)
	}
	return nil
}

func validateNetworkDevice(networkID, deviceID string) error {
	if _, err := core.NewNetworkID(networkID); err != nil {
		return fmt.Errorf("%w: invalid network_id", ErrInvalid)
	}
	if _, err := core.NewDeviceID(deviceID); err != nil {
		return fmt.Errorf("%w: invalid device_id", ErrInvalid)
	}
	return nil
}
