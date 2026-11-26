// Package frp owns TLAN's restricted FRP configuration, process supervision,
// and management API adapter. It deliberately does not import FRP Go packages.
package frp

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
)

const (
	CoreVersion          = "0.71.1"
	SchemaVersion        = 2
	LegacySchema         = 1
	SecretSchema         = 1
	DefaultProfileID     = "default"
	DefaultCredential    = "default"
	DefaultAdminUser     = "tlan-manager"
	MaxRules             = 16
	MaxDomains           = 16
	MaxVisitors          = 16
	DefaultHTTPPort      = 18080
	DefaultHTTPSPort     = 18443
	DefaultTCPMuxPort    = 18081
	DefaultWSSHTTPPort   = 18082
	DefaultWSSTCPMuxPort = 18083
	DefaultWSSHTTPSPort  = 18444
	DefaultSubdomainHost = "frp.example.com"
	MaxConfigBytes       = 64 * 1024
	MaxTokenBytes        = 4096
	MaxCABytes           = 4 * 1024 * 1024
	MaxHeaderFields      = 32
	MaxAllowUsers        = 64
)

var (
	ErrNoConfig         = errors.New("FRP profile is not configured")
	ErrRevisionConflict = errors.New("FRP profile revision conflict")
	identifierPattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)
)

// Config is TLAN's own schema. It is never passed directly to frpc.
type Config struct {
	SchemaVersion int     `json:"schemaVersion"`
	Profile       Profile `json:"profile"`
}

type Profile struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	CoreVersion string    `json:"coreVersion"`
	Revision    uint64    `json:"revision"`
	Server      Server    `json:"server"`
	Rules       []Rule    `json:"rules"`
	Visitors    []Visitor `json:"visitors,omitempty"`
}

type Server struct {
	Kind                      string `json:"kind"`
	Host                      string `json:"host"`
	Port                      int    `json:"port"`
	Transport                 string `json:"transport"`
	TLSServerName             string `json:"tlsServerName"`
	TrustedCAPath             string `json:"trustedCAPath,omitempty"`
	UseSystemCA               bool   `json:"useSystemCA,omitempty"`
	CredentialRef             string `json:"credentialRef"`
	ServerID                  string `json:"serverId,omitempty"`
	PublicHTTPPort            int    `json:"publicHttpPort,omitempty"`
	PublicHTTPSPort           int    `json:"publicHttpsPort,omitempty"`
	PublicTCPMuxPort          int    `json:"publicTcpMuxPort,omitempty"`
	SubdomainHost             string `json:"subdomainHost,omitempty"`
	TCPMux                    *bool  `json:"tcpMux,omitempty"`
	DisableCustomTLSFirstByte *bool  `json:"disableCustomTLSFirstByte,omitempty"`
}

type Rule struct {
	ID        string        `json:"id"`
	Name      string        `json:"name"`
	Type      string        `json:"type"`
	Enabled   bool          `json:"enabled"`
	SecretRef string        `json:"secretRef,omitempty"`
	Target    Target        `json:"target"`
	Exposure  Exposure      `json:"exposure"`
	Transport RuleTransport `json:"transport,omitempty"`
}

// RuleTransport mirrors the v0.71.1 ProxyTransport fields exposed by TLAN.
// The fixed core supports these options for every proxy type; validation
// applies tighter policy for protocol-specific fields below.
type RuleTransport struct {
	UseEncryption        bool   `json:"useEncryption,omitempty"`
	UseCompression       bool   `json:"useCompression,omitempty"`
	ProxyProtocolVersion string `json:"proxyProtocolVersion,omitempty"`
}

type Visitor struct {
	ID                string `json:"id"`
	Name              string `json:"name"`
	Type              string `json:"type"`
	Enabled           bool   `json:"enabled"`
	ServerName        string `json:"serverName"`
	ServerUser        string `json:"serverUser,omitempty"`
	SecretRef         string `json:"secretRef"`
	BindAddr          string `json:"bindAddr"`
	BindPort          int    `json:"bindPort"`
	Protocol          string `json:"protocol,omitempty"`
	KeepTunnelOpen    bool   `json:"keepTunnelOpen,omitempty"`
	MaxRetriesAnHour  int    `json:"maxRetriesAnHour,omitempty"`
	MinRetryInterval  int    `json:"minRetryInterval,omitempty"`
	FallbackTo        string `json:"fallbackTo,omitempty"`
	FallbackTimeoutMs int    `json:"fallbackTimeoutMs,omitempty"`
}

type Target struct {
	Kind      string `json:"kind"`
	Host      string `json:"host"`
	Port      int    `json:"port"`
	NetworkID string `json:"networkId,omitempty"`
	DeviceID  string `json:"deviceId,omitempty"`
	PublicKey string `json:"publicKey,omitempty"`
	ServiceID string `json:"serviceId,omitempty"`
}

type Exposure struct {
	RemotePort        int               `json:"remotePort,omitempty"`
	CustomDomains     []string          `json:"customDomains,omitempty"`
	Subdomain         string            `json:"subdomain,omitempty"`
	Locations         []string          `json:"locations,omitempty"`
	AllowUsers        []string          `json:"allowUsers,omitempty"`
	HTTPUser          string            `json:"httpUser,omitempty"`
	HTTPPasswordRef   string            `json:"httpPasswordRef,omitempty"`
	HostHeaderRewrite string            `json:"hostHeaderRewrite,omitempty"`
	RouteByHTTPUser   string            `json:"routeByHTTPUser,omitempty"`
	RequestHeaders    map[string]string `json:"requestHeaders,omitempty"`
	ResponseHeaders   map[string]string `json:"responseHeaders,omitempty"`
	Multiplexer       string            `json:"multiplexer,omitempty"`
}

func NewDefaultConfig() Config {
	return Config{
		SchemaVersion: SchemaVersion,
		Profile: Profile{
			ID:          DefaultProfileID,
			Name:        "我的穿透服务",
			CoreVersion: CoreVersion,
			Server: Server{
				Kind:             "private_token",
				Port:             7000,
				Transport:        "tcp",
				CredentialRef:    DefaultCredential,
				PublicHTTPPort:   DefaultHTTPPort,
				PublicHTTPSPort:  DefaultHTTPSPort,
				PublicTCPMuxPort: DefaultTCPMuxPort,
				SubdomainHost:    DefaultSubdomainHost,
			},
			Rules: []Rule{},
		},
	}
}

// DecodeConfig rejects unknown fields and trailing JSON. This is the only JSON
// ingress for persisted profiles.
func DecodeConfig(r io.Reader) (Config, error) {
	limited := io.LimitReader(r, MaxConfigBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return Config{}, fmt.Errorf("read FRP profile: %w", err)
	}
	if len(data) > MaxConfigBytes {
		return Config{}, unsupported("FRP profile exceeds %d bytes", MaxConfigBytes)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var cfg Config
	if err = decoder.Decode(&cfg); err != nil {
		return Config{}, unsupported("invalid FRP profile JSON: %v", err)
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return Config{}, unsupported("FRP profile contains trailing JSON data")
	}
	cfg = NormalizeConfig(cfg)
	if cfg.SchemaVersion == LegacySchema {
		cfg.SchemaVersion = SchemaVersion
	}
	if err = ValidateConfig(cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func EncodeConfig(cfg Config) ([]byte, error) {
	cfg = NormalizeConfig(cfg)
	if err := ValidateConfig(cfg); err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode FRP profile: %w", err)
	}
	return append(data, '\n'), nil
}

func NormalizeConfig(cfg Config) Config {
	cfg.Profile.ID = strings.TrimSpace(cfg.Profile.ID)
	cfg.Profile.Name = strings.TrimSpace(cfg.Profile.Name)
	cfg.Profile.CoreVersion = strings.TrimSpace(cfg.Profile.CoreVersion)
	cfg.Profile.Server.Kind = strings.ToLower(strings.TrimSpace(cfg.Profile.Server.Kind))
	cfg.Profile.Server.Host = strings.TrimSpace(cfg.Profile.Server.Host)
	cfg.Profile.Server.Transport = strings.ToLower(strings.TrimSpace(cfg.Profile.Server.Transport))
	cfg.Profile.Server.TLSServerName = strings.TrimSpace(cfg.Profile.Server.TLSServerName)
	cfg.Profile.Server.TrustedCAPath = strings.TrimSpace(cfg.Profile.Server.TrustedCAPath)
	cfg.Profile.Server.CredentialRef = strings.TrimSpace(cfg.Profile.Server.CredentialRef)
	cfg.Profile.Server.ServerID = strings.TrimSpace(cfg.Profile.Server.ServerID)
	cfg.Profile.Server.SubdomainHost = strings.ToLower(strings.TrimSpace(cfg.Profile.Server.SubdomainHost))
	if cfg.Profile.Server.Transport == "" {
		cfg.Profile.Server.Transport = "tcp"
	}
	if cfg.SchemaVersion == LegacySchema {
		cfg.SchemaVersion = SchemaVersion
	}
	if cfg.Profile.Server.PublicHTTPPort == 0 {
		cfg.Profile.Server.PublicHTTPPort = DefaultHTTPPort
	}
	if cfg.Profile.Server.PublicHTTPSPort == 0 {
		cfg.Profile.Server.PublicHTTPSPort = DefaultHTTPSPort
	}
	if cfg.Profile.Server.PublicTCPMuxPort == 0 {
		cfg.Profile.Server.PublicTCPMuxPort = DefaultTCPMuxPort
	}
	if cfg.Profile.Server.TCPMux == nil {
		value := true
		cfg.Profile.Server.TCPMux = &value
	}
	if cfg.Profile.Server.DisableCustomTLSFirstByte == nil {
		value := true
		cfg.Profile.Server.DisableCustomTLSFirstByte = &value
	}
	for i := range cfg.Profile.Rules {
		rule := &cfg.Profile.Rules[i]
		rule.ID = strings.TrimSpace(rule.ID)
		rule.Name = strings.TrimSpace(rule.Name)
		rule.Type = strings.ToLower(strings.TrimSpace(rule.Type))
		rule.SecretRef = strings.TrimSpace(rule.SecretRef)
		rule.Target.Kind = strings.ToLower(strings.TrimSpace(rule.Target.Kind))
		rule.Target.Host = strings.TrimSpace(rule.Target.Host)
		rule.Target.NetworkID = strings.TrimSpace(rule.Target.NetworkID)
		rule.Target.DeviceID = strings.TrimSpace(rule.Target.DeviceID)
		rule.Target.PublicKey = strings.TrimSpace(rule.Target.PublicKey)
		rule.Target.ServiceID = strings.TrimSpace(rule.Target.ServiceID)
		rule.Transport.ProxyProtocolVersion = strings.ToLower(strings.TrimSpace(rule.Transport.ProxyProtocolVersion))
		for j := range rule.Exposure.CustomDomains {
			rule.Exposure.CustomDomains[j] = strings.ToLower(strings.TrimSpace(rule.Exposure.CustomDomains[j]))
		}
		rule.Exposure.Subdomain = strings.ToLower(strings.TrimSpace(rule.Exposure.Subdomain))
		rule.Exposure.AllowUsers = normalizeAllowUsers(rule.Exposure.AllowUsers)
		for j := range rule.Exposure.Locations {
			rule.Exposure.Locations[j] = strings.TrimSpace(rule.Exposure.Locations[j])
		}
		rule.Exposure.HTTPUser = strings.TrimSpace(rule.Exposure.HTTPUser)
		rule.Exposure.HTTPPasswordRef = strings.TrimSpace(rule.Exposure.HTTPPasswordRef)
		rule.Exposure.HostHeaderRewrite = strings.TrimSpace(rule.Exposure.HostHeaderRewrite)
		rule.Exposure.RouteByHTTPUser = strings.TrimSpace(rule.Exposure.RouteByHTTPUser)
		rule.Exposure.Multiplexer = strings.ToLower(strings.TrimSpace(rule.Exposure.Multiplexer))
		if rule.Type == "tcpmux" && rule.Exposure.Multiplexer == "" {
			rule.Exposure.Multiplexer = "httpconnect"
		}
		rule.Exposure.RequestHeaders = normalizeHeaderMap(rule.Exposure.RequestHeaders)
		rule.Exposure.ResponseHeaders = normalizeHeaderMap(rule.Exposure.ResponseHeaders)
	}
	for i := range cfg.Profile.Visitors {
		visitor := &cfg.Profile.Visitors[i]
		visitor.ID = strings.TrimSpace(visitor.ID)
		visitor.Name = strings.TrimSpace(visitor.Name)
		visitor.Type = strings.ToLower(strings.TrimSpace(visitor.Type))
		visitor.ServerName = strings.TrimSpace(visitor.ServerName)
		visitor.ServerUser = strings.TrimSpace(visitor.ServerUser)
		visitor.SecretRef = strings.TrimSpace(visitor.SecretRef)
		visitor.BindAddr = strings.TrimSpace(visitor.BindAddr)
		visitor.Protocol = strings.ToLower(strings.TrimSpace(visitor.Protocol))
		visitor.FallbackTo = strings.TrimSpace(visitor.FallbackTo)
		if visitor.Type == "xtcp" {
			if visitor.Protocol == "" {
				visitor.Protocol = "quic"
			}
			if visitor.MaxRetriesAnHour == 0 {
				visitor.MaxRetriesAnHour = 8
			}
			if visitor.MinRetryInterval == 0 {
				visitor.MinRetryInterval = 90
			}
			if visitor.FallbackTimeoutMs == 0 {
				visitor.FallbackTimeoutMs = 1000
			}
		}
	}
	return cfg
}

func CloneConfig(cfg Config) Config {
	copy := cfg
	copy.Profile.Server.TCPMux = cloneBoolPtr(cfg.Profile.Server.TCPMux)
	copy.Profile.Server.DisableCustomTLSFirstByte = cloneBoolPtr(cfg.Profile.Server.DisableCustomTLSFirstByte)
	copy.Profile.Rules = append([]Rule(nil), cfg.Profile.Rules...)
	copy.Profile.Visitors = append([]Visitor(nil), cfg.Profile.Visitors...)
	for i := range copy.Profile.Rules {
		source := cfg.Profile.Rules[i]
		copy.Profile.Rules[i].Exposure.CustomDomains = append([]string(nil), source.Exposure.CustomDomains...)
		copy.Profile.Rules[i].Exposure.Locations = append([]string(nil), source.Exposure.Locations...)
		copy.Profile.Rules[i].Exposure.AllowUsers = append([]string(nil), source.Exposure.AllowUsers...)
		copy.Profile.Rules[i].Exposure.RequestHeaders = cloneStringMap(source.Exposure.RequestHeaders)
		copy.Profile.Rules[i].Exposure.ResponseHeaders = cloneStringMap(source.Exposure.ResponseHeaders)
	}
	return copy
}

func cloneBoolPtr(value *bool) *bool {
	if value == nil {
		return nil
	}
	copied := *value
	return &copied
}

func cloneStringMap(source map[string]string) map[string]string {
	if source == nil {
		return nil
	}
	out := make(map[string]string, len(source))
	for key, value := range source {
		out[key] = value
	}
	return out
}

func normalizeHeaderMap(source map[string]string) map[string]string {
	if len(source) == 0 {
		return nil
	}
	out := make(map[string]string, len(source))
	for key, value := range source {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		out[key] = strings.TrimSpace(value)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func normalizeAllowUsers(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, raw := range values {
		value := strings.TrimSpace(raw)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	if len(out) == 0 {
		return nil
	}
	sort.Strings(out)
	return out
}

func NewRuleID() (string, error) {
	var data [8]byte
	if _, err := rand.Read(data[:]); err != nil {
		return "", fmt.Errorf("generate FRP rule id: %w", err)
	}
	return "rule-" + hex.EncodeToString(data[:]), nil
}

func NewSecret(bytesCount int) (string, error) {
	if bytesCount < 16 {
		bytesCount = 16
	}
	data := make([]byte, bytesCount)
	if _, err := rand.Read(data); err != nil {
		return "", fmt.Errorf("generate random secret: %w", err)
	}
	return hex.EncodeToString(data), nil
}

func stableToken(parts ...string) string {
	h := sha256.New()
	for _, part := range parts {
		_, _ = h.Write([]byte(part))
		_, _ = h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func ProxyName(deviceID, profileID, ruleID string) string {
	return "tlan_" + stableToken(deviceID, profileID, ruleID)[:20]
}

func ClientUser(deviceID, profileID string) string {
	return "tlan_" + stableToken(deviceID, profileID)[:16]
}

func identifierValid(value string) bool { return identifierPattern.MatchString(value) }

func VisitorName(deviceID, profileID, visitorID string) string {
	return "tlan_v_" + stableToken(deviceID, profileID, visitorID)[:18]
}
