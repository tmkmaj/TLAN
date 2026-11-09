package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/private-radminlan/lanmesh/internal/egressgateway"
	"gopkg.in/yaml.v3"
)

const defaultConfigPath = "/etc/tlan-egress/egress-gateway.toml"

type gatewayConfig struct {
	Listen   string        `yaml:"listen"`
	StateDir string        `yaml:"state_dir"`
	TLSCert  string        `yaml:"tls_cert"`
	TLSKey   string        `yaml:"tls_key"`
	Control  controlConfig `yaml:"control"`
	Egress   egressConfig  `yaml:"egress"`
	Limits   limitsConfig  `yaml:"limits"`
	Policy   policyConfig  `yaml:"policy"`
}

type controlConfig struct {
	LeaseURL        string `yaml:"lease_url"`
	LeaseSecretFile string `yaml:"lease_secret_file"`
}

type egressConfig struct {
	Interface       string   `yaml:"interface"`
	IPv4CIDR        string   `yaml:"ipv4_cidr"`
	DNSServers      []string `yaml:"dns_servers"`
	EnableIPForward bool     `yaml:"enable_ip_forward"`
}

type limitsConfig struct {
	MaxSessions            int   `yaml:"max_sessions"`
	MaxConnectionsPerLease int   `yaml:"max_connections_per_lease"`
	MaxBytesPerLease       int64 `yaml:"max_bytes_per_lease"`
	MaxRateBPS             int64 `yaml:"max_rate_bps"`
}

type policyConfig struct {
	AllowCIDRs   []string `yaml:"allow_cidrs"`
	DenyPrivate  bool     `yaml:"deny_private"`
	DenyMetadata bool     `yaml:"deny_metadata"`
	DenyPorts    []int    `yaml:"deny_ports"`
	IPv6Policy   string   `yaml:"ipv6_policy"`
	DNSPolicy    string   `yaml:"dns_policy"`
}

func loadConfig(path string) (gatewayConfig, error) {
	if strings.TrimSpace(path) == "" {
		return gatewayConfig{}, errors.New("configuration path is required")
	}
	file, err := os.Open(path)
	if err != nil {
		return gatewayConfig{}, fmt.Errorf("open configuration: %w", err)
	}
	defer file.Close()

	decoder := yaml.NewDecoder(file)
	decoder.KnownFields(true)
	var cfg gatewayConfig
	if err := decoder.Decode(&cfg); err != nil {
		return gatewayConfig{}, fmt.Errorf("decode configuration: %w", err)
	}
	var trailing yaml.Node
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return gatewayConfig{}, errors.New("configuration must contain exactly one YAML document")
		}
		return gatewayConfig{}, fmt.Errorf("decode trailing configuration: %w", err)
	}
	cfg.normalize()
	if err := cfg.validate(); err != nil {
		return gatewayConfig{}, err
	}
	return cfg, nil
}

func (c *gatewayConfig) normalize() {
	c.Listen = strings.TrimSpace(c.Listen)
	c.StateDir = strings.TrimSpace(c.StateDir)
	c.TLSCert = strings.TrimSpace(c.TLSCert)
	c.TLSKey = strings.TrimSpace(c.TLSKey)
	c.Control.LeaseURL = strings.TrimSpace(c.Control.LeaseURL)
	c.Control.LeaseSecretFile = strings.TrimSpace(c.Control.LeaseSecretFile)
	c.Egress.Interface = strings.TrimSpace(c.Egress.Interface)
	c.Egress.IPv4CIDR = strings.TrimSpace(c.Egress.IPv4CIDR)
	for index := range c.Egress.DNSServers {
		c.Egress.DNSServers[index] = strings.TrimSpace(c.Egress.DNSServers[index])
	}
	for index := range c.Policy.AllowCIDRs {
		c.Policy.AllowCIDRs[index] = strings.TrimSpace(c.Policy.AllowCIDRs[index])
	}
	c.Policy.IPv6Policy = strings.ToLower(strings.TrimSpace(c.Policy.IPv6Policy))
	c.Policy.DNSPolicy = strings.ToLower(strings.TrimSpace(c.Policy.DNSPolicy))
}

func (c gatewayConfig) validate() error {
	if err := validateListenAddress(c.Listen); err != nil {
		return err
	}
	if err := validateAbsolutePath("state_dir", c.StateDir); err != nil {
		return err
	}
	if err := validateAbsolutePath("tls_cert", c.TLSCert); err != nil {
		return err
	}
	if err := validateAbsolutePath("tls_key", c.TLSKey); err != nil {
		return err
	}
	if err := validateAbsolutePath("control.lease_secret_file", c.Control.LeaseSecretFile); err != nil {
		return err
	}
	if _, err := resolveLeaseEndpoint(c.Control.LeaseURL); err != nil {
		return fmt.Errorf("control.lease_url: %w", err)
	}
	if c.Egress.Interface == "" || len(c.Egress.Interface) > 15 || strings.ContainsAny(c.Egress.Interface, " \t\r\n/\\") {
		return errors.New("egress.interface must be a valid interface name")
	}
	ipv4Prefix, err := netip.ParsePrefix(c.Egress.IPv4CIDR)
	if err != nil || !ipv4Prefix.Addr().Is4() || ipv4Prefix.Bits() == 0 || ipv4Prefix.Masked() != ipv4Prefix {
		return errors.New("egress.ipv4_cidr must be a masked non-default IPv4 prefix")
	}
	if !c.Egress.EnableIPForward {
		return errors.New("egress.enable_ip_forward must be true: the current NAT manager always enables IPv4 forwarding")
	}
	if err := validateDNSServers(c.Egress.DNSServers); err != nil {
		return err
	}
	if err := c.Limits.validate(); err != nil {
		return err
	}
	if err := c.Policy.validate(c.Egress.DNSServers); err != nil {
		return err
	}
	return nil
}

func validateListenAddress(value string) error {
	host, portText, err := net.SplitHostPort(value)
	if err != nil {
		return fmt.Errorf("listen must be host:port: %w", err)
	}
	if strings.TrimSpace(host) == "" {
		return errors.New("listen host is required")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 0 || port > 65535 {
		return errors.New("listen port must be between 0 and 65535")
	}
	return nil
}

func validateAbsolutePath(label, value string) error {
	if value == "" || !filepath.IsAbs(value) {
		return fmt.Errorf("%s must be an absolute path", label)
	}
	return nil
}

func validateDNSServers(values []string) error {
	seen := make(map[netip.Addr]struct{}, len(values))
	for _, raw := range values {
		addr, err := netip.ParseAddr(raw)
		if err != nil || !addr.IsValid() || addr.IsUnspecified() {
			return fmt.Errorf("egress.dns_servers contains invalid address %q", raw)
		}
		addr = addr.Unmap()
		if _, exists := seen[addr]; exists {
			return fmt.Errorf("egress.dns_servers contains duplicate address %q", raw)
		}
		seen[addr] = struct{}{}
	}
	return nil
}

func (l limitsConfig) validate() error {
	if l.MaxSessions <= 0 {
		return errors.New("limits.max_sessions must be positive")
	}
	if l.MaxConnectionsPerLease <= 0 {
		return errors.New("limits.max_connections_per_lease must be positive")
	}
	if l.MaxBytesPerLease <= 0 {
		return errors.New("limits.max_bytes_per_lease must be positive")
	}
	if l.MaxRateBPS <= 0 {
		return errors.New("limits.max_rate_bps must be positive")
	}
	return nil
}

func (l limitsConfig) gatewayLimits() egressgateway.Limits {
	return egressgateway.Limits{
		MaxConnections: l.MaxConnectionsPerLease,
		MaxBytes:       l.MaxBytesPerLease,
		MaxRateBPS:     l.MaxRateBPS,
	}
}

func (p policyConfig) validate(dnsServers []string) error {
	if len(p.AllowCIDRs) == 0 {
		return errors.New("policy.allow_cidrs must not be empty")
	}
	for _, raw := range p.AllowCIDRs {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil || prefix.Masked() != prefix {
			return fmt.Errorf("policy.allow_cidrs contains invalid or unmasked prefix %q", raw)
		}
	}
	switch p.IPv6Policy {
	case string(egressgateway.IPv6PolicyBlock), string(egressgateway.IPv6PolicyAllowPublic):
	default:
		return fmt.Errorf("policy.ipv6_policy must be %q or %q", egressgateway.IPv6PolicyBlock, egressgateway.IPv6PolicyAllowPublic)
	}
	switch p.DNSPolicy {
	case string(egressgateway.DNSPolicyBlock):
		if len(dnsServers) != 0 {
			return errors.New("egress.dns_servers must be empty when policy.dns_policy is block")
		}
	case string(egressgateway.DNSPolicyRemote):
		if len(dnsServers) == 0 {
			return errors.New("egress.dns_servers is required when policy.dns_policy is remote")
		}
	default:
		return fmt.Errorf("policy.dns_policy must be %q or %q", egressgateway.DNSPolicyBlock, egressgateway.DNSPolicyRemote)
	}
	seenPorts := make(map[uint16]struct{}, len(p.DenyPorts))
	for _, port := range p.DenyPorts {
		if port < 1 || port > 65535 {
			return fmt.Errorf("policy.deny_ports contains invalid port %d", port)
		}
		normalized := uint16(port)
		if _, exists := seenPorts[normalized]; exists {
			return fmt.Errorf("policy.deny_ports contains duplicate port %d", port)
		}
		seenPorts[normalized] = struct{}{}
	}
	return nil
}

func (c gatewayConfig) gatewayPolicy() (egressgateway.Policy, error) {
	blocked := make([]egressgateway.TargetClass, 0, 2)
	if c.Policy.DenyPrivate {
		blocked = append(blocked, egressgateway.TargetClassPrivate)
	}
	if c.Policy.DenyMetadata {
		blocked = append(blocked, egressgateway.TargetClassCloudMetadata)
	}
	dnsResolvers := []string(nil)
	if c.Policy.DNSPolicy == string(egressgateway.DNSPolicyRemote) {
		dnsResolvers = append(dnsResolvers, c.Egress.DNSServers...)
	}
	policy := egressgateway.Policy{
		Version:            egressgateway.SchemaVersion,
		AllowedProtocols:   []egressgateway.Protocol{egressgateway.ProtocolTCP, egressgateway.ProtocolUDP},
		AllowedTargetCIDRs: append([]string(nil), c.Policy.AllowCIDRs...),
		BlockedCategories:  blocked,
		IPv6Policy:         egressgateway.IPv6Policy(c.Policy.IPv6Policy),
		DNSPolicy:          egressgateway.DNSPolicy(c.Policy.DNSPolicy),
		DNSResolvers:       dnsResolvers,
		Limits:             c.Limits.gatewayLimits(),
	}
	if err := policy.Validate(); err != nil {
		return egressgateway.Policy{}, fmt.Errorf("build gateway policy: %w", err)
	}
	return policy, nil
}

func (c gatewayConfig) denyPortSet() map[uint16]struct{} {
	ports := make(map[uint16]struct{}, len(c.Policy.DenyPorts))
	for _, port := range c.Policy.DenyPorts {
		ports[uint16(port)] = struct{}{}
	}
	return ports
}

func (c gatewayConfig) natConfig() egressgateway.NATConfig {
	return egressgateway.NATConfig{
		EgressInterface: c.Egress.Interface,
		SourceCIDR:      c.Egress.IPv4CIDR,
	}
}

func ensureStateDir(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return fmt.Errorf("create state_dir: %w", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("stat state_dir: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("state_dir must be a real directory, not a symlink")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("state_dir permissions must not grant group or world access (mode %04o)", info.Mode().Perm())
	}
	return nil
}
