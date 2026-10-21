package frp

import (
	"context"
	"errors"
	"time"

	"github.com/private-radminlan/lanmesh/internal/targetgateway"
)

// LeaseRule is the server-issued capability for one FRP proxy. ProxyName is
// the stable internal name; user-facing names are never trusted by FRPS.
// HTTPPasswordHash and SecretHash are SHA-256 digests; plaintext values never
// cross the control-plane lease boundary.
type LeaseRule struct {
	ID            string   `json:"id"`
	ProxyName     string   `json:"proxy_name"`
	Type          string   `json:"type"`
	RemotePort    int      `json:"remote_port,omitempty"`
	CustomDomains []string `json:"custom_domains,omitempty"`
	BindPort      int      `json:"bind_port,omitempty"`

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

	TargetKind      string `json:"target_kind,omitempty"`
	TargetNetworkID string `json:"target_network_id,omitempty"`
	TargetDeviceID  string `json:"target_device_id,omitempty"`
	TargetPublicKey string `json:"target_public_key,omitempty"`
	TargetHost      string `json:"target_host,omitempty"`
	TargetServiceID string `json:"target_service_id,omitempty"`
	GrantID         string `json:"grant_id,omitempty"`
}

type LeaseRequest struct {
	NetworkID  string        `json:"network_id"`
	DeviceID   string        `json:"device_id"`
	ServerID   string        `json:"server_id"`
	Rules      []LeaseRule   `json:"rules"`
	TTL        time.Duration `json:"-"`
	TTLSeconds int           `json:"ttl_seconds,omitempty"`
}

type Lease struct {
	ID         string      `json:"lease_id"`
	Credential string      `json:"credential"`
	ExpiresAt  time.Time   `json:"expires_at"`
	Rules      []LeaseRule `json:"rules,omitempty"`
	Revision   uint64      `json:"revision,omitempty"`
}

// ErrLeaseTerminal means the control plane definitively rejected or revoked a
// managed lease. Retrying cannot recover the same lease.
var ErrLeaseTerminal = errors.New("managed FRP lease is no longer valid")

type LeaseProvider interface {
	Acquire(ctx context.Context, request LeaseRequest) (Lease, error)
	Renew(ctx context.Context, leaseID string) (Lease, error)
	Release(ctx context.Context, leaseID string) error
}

// LeaseVerifier is implemented by a managed provider when the control plane
// can prove that FRPS reached the authorization plugin for a live lease.
type LeaseVerifier interface {
	VerifyActive(ctx context.Context, leaseID string, requireProxy bool) error
}

// MeshTargetProvider resolves a mesh_peer rule into a TargetGateway lease.
// The provider is implemented by the client mesh adapter and must reject
// stale identity, address, public-key, and generation values.
type MeshTargetProvider interface {
	PrepareTarget(ctx context.Context, rule Rule) (targetgateway.Target, targetgateway.LeaseValidator, targetgateway.Dialer, error)
}
