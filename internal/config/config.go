package config

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

const FileName = "tnlan-config.yml"

// Config is the complete server configuration. The YAML file is deliberately
// strict: misspelled or obsolete fields fail startup rather than being ignored.
type Config struct {
	Network  NetworkConfig  `yaml:"network"`
	Server   ServerConfig   `yaml:"server"`
	Storage  StorageConfig  `yaml:"storage"`
	Security SecurityConfig `yaml:"security"`
	FRP      FRPConfig      `yaml:"frp,omitempty"`
}

type NetworkConfig struct {
	Name     string `yaml:"name"`
	CIDR     string `yaml:"cidr"`
	JoinCode string `yaml:"join_code"`
}

type ServerConfig struct {
	AdminListen            string `yaml:"admin_listen,omitempty"`
	AdminTLSCert           string `yaml:"admin_tls_cert,omitempty"`
	AdminTLSKey            string `yaml:"admin_tls_key,omitempty"`
	AdminAllowInsecureHTTP bool   `yaml:"admin_allow_insecure_http"`
	Listen                 string `yaml:"listen"`
	STUNListen             string `yaml:"stun_listen"`
	TLSCert                string `yaml:"tls_cert"`
	TLSKey                 string `yaml:"tls_key"`
	RelayListen            string `yaml:"relay_listen"`
	RelayCert              string `yaml:"relay_cert"`
	RelayKey               string `yaml:"relay_key"`
}

type StorageConfig struct {
	DataDir string `yaml:"data_dir"`
}

type SecurityConfig struct {
	AdminToken string `yaml:"admin_token"`
}

// FRPConfig separates the external shared-token deployment from the
// TLAN-managed FRPS authorization mode. The FRPS outer token remains in the
// independent frps.toml and is intentionally not stored here.
type FRPConfig struct {
	Mode                string        `yaml:"mode,omitempty"`
	CoreVersion         string        `yaml:"core_version,omitempty"`
	ServerID            string        `yaml:"server_id,omitempty"`
	PluginListen        string        `yaml:"plugin_listen,omitempty"`
	LeaseTTLSeconds     int           `yaml:"lease_ttl_seconds,omitempty"`
	LeaseStateFile      string        `yaml:"lease_state_file,omitempty"`
	MaxRulesPerLease    int           `yaml:"max_rules_per_lease,omitempty"`
	MaxLeasesPerDevice  int           `yaml:"max_leases_per_device,omitempty"`
	MaxPortsPerDevice   int           `yaml:"max_ports_per_device,omitempty"`
	MaxDomainsPerDevice int           `yaml:"max_domains_per_device,omitempty"`
	MaxDomainsPerRule   int           `yaml:"max_domains_per_rule,omitempty"`
	AllowedPorts        FRPPortList   `yaml:"allowed_ports,omitempty"`
	AllowedDomains      FRPDomainList `yaml:"allowed_domains,omitempty"`
}

type FRPPortRange struct {
	Start int `yaml:"start"`
	End   int `yaml:"end"`
}

// FRPPortList and FRPDomainList are comparable canonical string values. This
// keeps Config comparable for existing deployment/upgrade code while exposing
// normal YAML lists at the file boundary.
type FRPPortList string
type FRPDomainList string

// LoadOrCreate implements the first-run lifecycle. Missing configuration is
// generated once and reported to the caller so the server can exit before it
// opens listeners or creates data. Later starts load and validate the file.
func LoadOrCreate(path string) (Config, bool, error) {
	if strings.TrimSpace(path) == "" {
		return Config{}, false, errors.New("configuration path is empty")
	}
	cfg, err := LoadFile(path)
	if err == nil {
		return cfg, false, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return Config{}, false, err
	}
	cfg, err = newDefault()
	if err != nil {
		return Config{}, false, err
	}
	// Preserve state from deployments that ran the server directly in its data
	// directory. Without this, upgrading to a config file would create a new
	// empty network and reassign every member IP.
	if info, statErr := os.Stat(filepath.Join(filepath.Dir(path), "state.json")); statErr == nil && !info.IsDir() {
		cfg.Storage.DataDir = "."
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, false, fmt.Errorf("generated configuration is invalid: %w", err)
	}
	if err := writeNew(path, cfg); err != nil {
		if errors.Is(err, os.ErrExist) {
			// Another instance won the first-run race. Load its complete file
			// instead of replacing it or reporting a misleading startup error.
			cfg, loadErr := LoadFile(path)
			return cfg, false, loadErr
		}
		return Config{}, false, err
	}
	return cfg, true, nil
}

func LoadFile(path string) (Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("open configuration %q: %w", path, err)
	}
	defer file.Close()

	var cfg Config
	decoder := yaml.NewDecoder(file)
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("parse configuration %q: %w", path, err)
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return Config{}, fmt.Errorf("parse configuration %q: multiple YAML documents are not supported", path)
		}
		return Config{}, fmt.Errorf("parse configuration %q: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, fmt.Errorf("validate configuration %q: %w", path, err)
	}
	return cfg, nil
}

func newDefault() (Config, error) {
	return Config{
		Network: NetworkConfig{
			Name:     "我的私人网络",
			CIDR:     "10.240.0.0/24",
			JoinCode: "TmkNetwork",
		},
		Server: ServerConfig{
			Listen:      "127.0.0.1:8080",
			STUNListen:  ":3478",
			AdminListen: "127.0.0.1:8081",
		},
		Storage: StorageConfig{DataDir: "./data"},
		Security: SecurityConfig{
			AdminToken: "Tmkmaj233",
		},
		FRP: FRPConfig{
			Mode:        "disabled",
			CoreVersion: "0.71.1",
		},
	}, nil
}

func randomToken(size int) (string, error) {
	data := make([]byte, size)
	if _, err := rand.Read(data); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

func writeNew(path string, cfg Config) error {
	var output bytes.Buffer
	output.WriteString("# TmkNetworkLAN Linux 服务端配置\n")
	output.WriteString("# 此文件包含管理员令牌与入网令牌，请勿上传或公开。\n")
	output.WriteString("# 修改配置后再次运行程序。程序只从当前目录读取 tnlan-config.yml。\n")
	output.WriteString("# 将 network.join_code 设为空字符串可禁止新成员加入。\n\n")
	output.WriteString("# frp.mode 默认 disabled；external 使用独立 FRPS 的共享 token；\n")
	output.WriteString("# managed 还需配置 frp.server_id、frp.plugin_listen 和允许的端口/域名。\n")
	output.WriteString("# 托管模式的外层 FRPS token 仍放在独立 frps.toml，不写入本文件。\n\n")
	output.WriteString("# IP HTTPS 部署：Caddy 在 8.163.21.82:8443 提供 HTTPS，代理到下方 listen。\n")
	output.WriteString("# 默认使用 Caddy 时保持 tls_cert/tls_key 为空；TCP 80 用于 IP 证书自动验证。\n\n")
	encoder := yaml.NewEncoder(&output)
	encoder.SetIndent(2)
	if err := encoder.Encode(cfg); err != nil {
		return fmt.Errorf("encode configuration %q: %w", path, err)
	}
	if err := encoder.Close(); err != nil {
		return fmt.Errorf("finish configuration %q: %w", path, err)
	}

	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create configuration %q: %w", path, err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = file.Close()
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(output.Bytes()); err != nil {
		return fmt.Errorf("write configuration %q: %w", path, err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync configuration %q: %w", path, err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close configuration %q: %w", path, err)
	}
	committed = true
	return nil
}

func (c Config) Validate() error {
	if name := strings.TrimSpace(c.Network.Name); name == "" || len(name) > 128 {
		return errors.New("network.name must contain 1-128 characters")
	}
	if err := validatePrivateCIDR(c.Network.CIDR); err != nil {
		return fmt.Errorf("network.cidr: %w", err)
	}
	if c.Network.JoinCode != "" {
		length := len([]byte(c.Network.JoinCode))
		if length < 8 || length > 256 {
			return errors.New("network.join_code must be empty or contain 8-256 bytes")
		}
	}
	if err := validateHostPort("server.listen", c.Server.Listen); err != nil {
		return err
	}
	if c.Server.STUNListen != "" && !strings.EqualFold(strings.TrimSpace(c.Server.STUNListen), "off") {
		if err := validateHostPort("server.stun_listen", c.Server.STUNListen); err != nil {
			return err
		}
	}
	if c.Server.RelayListen != "" {
		if err := validateHostPort("server.relay_listen", c.Server.RelayListen); err != nil {
			return err
		}
	}
	if (c.Server.TLSCert == "") != (c.Server.TLSKey == "") {
		return errors.New("server.tls_cert and server.tls_key must be set together")
	}
	if c.Server.AdminListen != "" {
		if err := validateHostPort("server.admin_listen", c.Server.AdminListen); err != nil {
			return err
		}
	}
	if (c.Server.AdminTLSCert == "") != (c.Server.AdminTLSKey == "") {
		return errors.New("server.admin_tls_cert and server.admin_tls_key must be set together")
	}
	if c.Server.AdminTLSCert != "" && c.Server.AdminListen == "" {
		return errors.New("server.admin_tls_cert requires server.admin_listen")
	}
	if c.Server.AdminListen != "" && c.Server.AdminTLSCert == "" && !loopbackHostPort(c.Server.AdminListen) && !c.Server.AdminAllowInsecureHTTP {
		return errors.New("server.admin_allow_insecure_http must be true to bind a non-loopback admin listener without TLS")
	}
	if (c.Server.RelayCert == "") != (c.Server.RelayKey == "") {
		return errors.New("server.relay_cert and server.relay_key must be set together")
	}
	if strings.TrimSpace(c.Storage.DataDir) == "" {
		return errors.New("storage.data_dir must not be empty")
	}
	tokenLength := len([]byte(c.Security.AdminToken))
	if tokenLength < 8 || tokenLength > 256 || c.Security.AdminToken == "change-me" || strings.HasPrefix(c.Security.AdminToken, "REPLACE_") {
		return errors.New("security.admin_token must contain 8-256 bytes")
	}

	if err := c.FRP.Validate(); err != nil {
		return fmt.Errorf("frp: %w", err)
	}
	if c.FRP.EffectiveMode() == "managed" && filepath.Clean(c.FRPLeaseStateFile()) == filepath.Clean(c.StateFile()) {
		return errors.New("frp.lease_state_file must not overwrite storage.state_file")
	}
	return nil
}

func (f FRPConfig) EffectiveMode() string {
	mode := strings.ToLower(strings.TrimSpace(f.Mode))
	if mode == "" {
		return "disabled"
	}
	return mode
}

func (f FRPConfig) EffectiveCoreVersion() string {
	version := strings.TrimSpace(f.CoreVersion)
	if version == "" {
		return "0.71.1"
	}
	return version
}

func (f FRPConfig) EffectiveLeaseTTLSeconds() int {
	if f.LeaseTTLSeconds <= 0 {
		return 900
	}
	return f.LeaseTTLSeconds
}

func (l FRPPortList) Ranges() ([]FRPPortRange, error) {
	value := strings.TrimSpace(string(l))
	if value == "" {
		return nil, nil
	}
	parts := strings.Split(value, ",")
	out := make([]FRPPortRange, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		startText, endText, found := strings.Cut(part, "-")
		if !found {
			startText, endText = part, part
		}
		start, err := strconv.Atoi(strings.TrimSpace(startText))
		if err != nil {
			return nil, fmt.Errorf("invalid allowed port range %q", part)
		}
		end, err := strconv.Atoi(strings.TrimSpace(endText))
		if err != nil {
			return nil, fmt.Errorf("invalid allowed port range %q", part)
		}
		out = append(out, FRPPortRange{Start: start, End: end})
	}
	return out, nil
}

func (l *FRPPortList) UnmarshalYAML(node *yaml.Node) error {
	if node.Tag == "!!null" {
		*l = ""
		return nil
	}
	if node.Kind == yaml.ScalarNode {
		value := strings.TrimSpace(node.Value)
		if value == "" {
			*l = ""
			return nil
		}
		// Also accept a compact scalar form for hand-written deployments:
		// "30000-30099,30100-30109".
		*l = FRPPortList(value)
		_, err := l.Ranges()
		return err
	}
	if node.Kind != yaml.SequenceNode {
		return errors.New("frp.allowed_ports must be a list")
	}
	out := make([]FRPPortRange, 0, len(node.Content))
	for _, item := range node.Content {
		var itemRange FRPPortRange
		switch item.Kind {
		case yaml.ScalarNode:
			value := strings.TrimSpace(item.Value)
			startText, endText, found := strings.Cut(value, "-")
			if !found {
				startText, endText = value, value
			}
			start, err := strconv.Atoi(strings.TrimSpace(startText))
			if err != nil {
				return fmt.Errorf("invalid allowed port range %q", value)
			}
			end, err := strconv.Atoi(strings.TrimSpace(endText))
			if err != nil {
				return fmt.Errorf("invalid allowed port range %q", value)
			}
			itemRange = FRPPortRange{Start: start, End: end}
		case yaml.MappingNode:
			if len(item.Content) != 4 {
				return errors.New("frp.allowed_ports entries must contain start and end")
			}
			seenStart, seenEnd := false, false
			for i := 0; i < len(item.Content); i += 2 {
				key, valueNode := item.Content[i].Value, item.Content[i+1]
				if valueNode.Kind != yaml.ScalarNode {
					return errors.New("frp.allowed_ports values must be integers")
				}
				value, err := strconv.Atoi(valueNode.Value)
				if err != nil {
					return errors.New("frp.allowed_ports values must be integers")
				}
				switch key {
				case "start":
					if seenStart {
						return errors.New("duplicate frp.allowed_ports start")
					}
					itemRange.Start, seenStart = value, true
				case "end":
					if seenEnd {
						return errors.New("duplicate frp.allowed_ports end")
					}
					itemRange.End, seenEnd = value, true
				default:
					return fmt.Errorf("unknown frp.allowed_ports field %q", key)
				}
			}
			if !seenStart || !seenEnd {
				return errors.New("frp.allowed_ports entries must contain start and end")
			}
		default:
			return errors.New("frp.allowed_ports entries must be mappings or strings")
		}
		out = append(out, itemRange)
	}
	canonical, err := canonicalPortRanges(out)
	if err != nil {
		return err
	}
	*l = FRPPortList(canonical)
	return nil
}

func (l FRPPortList) MarshalYAML() (any, error) {
	ranges, err := l.Ranges()
	if err != nil {
		return nil, err
	}
	if len(ranges) == 0 {
		return []FRPPortRange{}, nil
	}
	return ranges, nil
}

func canonicalPortRanges(ranges []FRPPortRange) (string, error) {
	if err := validateFRPPortRanges(ranges); err != nil {
		return "", err
	}
	sort.Slice(ranges, func(i, j int) bool { return ranges[i].Start < ranges[j].Start })
	parts := make([]string, 0, len(ranges))
	for _, item := range ranges {
		parts = append(parts, fmt.Sprintf("%d-%d", item.Start, item.End))
	}
	return strings.Join(parts, ","), nil
}

func (l FRPDomainList) Domains() ([]string, error) {
	value := strings.TrimSpace(string(l))
	if value == "" {
		return nil, nil
	}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out, nil
}

func (l *FRPDomainList) UnmarshalYAML(node *yaml.Node) error {
	if node.Tag == "!!null" {
		*l = ""
		return nil
	}
	if node.Kind == yaml.ScalarNode {
		value := strings.TrimSpace(node.Value)
		if value == "" {
			*l = ""
			return nil
		}
		*l = FRPDomainList(value)
		return nil
	}
	if node.Kind != yaml.SequenceNode {
		return errors.New("frp.allowed_domains must be a list")
	}
	values := make([]string, 0, len(node.Content))
	for _, item := range node.Content {
		if item.Kind != yaml.ScalarNode {
			return errors.New("frp.allowed_domains entries must be strings")
		}
		value := strings.ToLower(strings.TrimSpace(item.Value))
		if value != "" {
			values = append(values, value)
		}
	}
	sort.Strings(values)
	values = dedupeStrings(values)
	*l = FRPDomainList(strings.Join(values, ","))
	return nil
}

func (l FRPDomainList) MarshalYAML() (any, error) {
	domains, err := l.Domains()
	if err != nil {
		return nil, err
	}
	if len(domains) == 0 {
		return []string{}, nil
	}
	return domains, nil
}

func dedupeStrings(values []string) []string {
	if len(values) < 2 {
		return values
	}
	out := values[:1]
	for _, value := range values[1:] {
		if value != out[len(out)-1] {
			out = append(out, value)
		}
	}
	return out
}

func (c Config) FRPLeaseStateFile() string {
	path := strings.TrimSpace(c.FRP.LeaseStateFile)
	if path != "" {
		return path
	}
	return filepath.Join(c.Storage.DataDir, "frp-leases.json")
}

func (f FRPConfig) Validate() error {
	mode := f.EffectiveMode()
	ports, err := f.AllowedPorts.Ranges()
	if err != nil {
		return fmt.Errorf("frp.allowed_ports: %w", err)
	}
	domains, err := f.AllowedDomains.Domains()
	if err != nil {
		return fmt.Errorf("frp.allowed_domains: %w", err)
	}
	switch mode {
	case "disabled", "external":
		if f.ServerID != "" || f.PluginListen != "" || f.LeaseStateFile != "" ||
			f.LeaseTTLSeconds != 0 || f.MaxRulesPerLease != 0 || f.MaxLeasesPerDevice != 0 ||
			f.MaxPortsPerDevice != 0 || f.MaxDomainsPerDevice != 0 || f.MaxDomainsPerRule != 0 ||
			len(ports) != 0 || len(domains) != 0 {
			return fmt.Errorf("mode %q must not contain managed authorization fields", mode)
		}
		if f.CoreVersion != "" && f.CoreVersion != "0.71.1" {
			return errors.New("frp.core_version must be 0.71.1")
		}
		return nil
	case "managed":
	default:
		return fmt.Errorf("frp.mode must be disabled, external, or managed")
	}
	if f.EffectiveCoreVersion() != "0.71.1" {
		return errors.New("frp.core_version must be 0.71.1")
	}
	if err := validateFRPIdentifier("server_id", f.ServerID); err != nil {
		return err
	}
	if err := validateLoopbackHostPort("plugin_listen", f.PluginListen); err != nil {
		return err
	}
	if f.LeaseTTLSeconds < 0 || f.LeaseTTLSeconds > 86400 {
		return errors.New("frp.lease_ttl_seconds must be 0-86400")
	}
	for name, value := range map[string]int{
		"max_rules_per_lease":    f.MaxRulesPerLease,
		"max_leases_per_device":  f.MaxLeasesPerDevice,
		"max_ports_per_device":   f.MaxPortsPerDevice,
		"max_domains_per_device": f.MaxDomainsPerDevice,
		"max_domains_per_rule":   f.MaxDomainsPerRule,
	} {
		if value < 0 {
			return fmt.Errorf("frp.%s must not be negative", name)
		}
	}
	if f.MaxRulesPerLease > 64 || f.MaxDomainsPerRule > 64 {
		return errors.New("frp per-lease limits are too large")
	}
	if err := validateFRPPortRanges(ports); err != nil {
		return err
	}
	for _, domain := range domains {
		if err := validateAllowedDomainSuffix(domain); err != nil {
			return fmt.Errorf("frp.allowed_domains: %w", err)
		}
	}
	return nil
}

func validateFRPIdentifier(field, value string) error {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 64 {
		return fmt.Errorf("frp.%s must contain 1-64 characters", field)
	}
	for i, r := range value {
		valid := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-'
		if !valid || i == 0 && !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
			return fmt.Errorf("frp.%s contains invalid characters", field)
		}
	}
	return nil
}

func validateLoopbackHostPort(field, value string) error {
	host, port, err := net.SplitHostPort(strings.TrimSpace(value))
	if err != nil {
		return fmt.Errorf("frp.%s must be a host:port address: %w", field, err)
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 {
		return fmt.Errorf("frp.%s has an invalid port", field)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("frp.%s must bind to a loopback IP", field)
	}
	return nil
}

func validateFRPPortRanges(ranges []FRPPortRange) error {
	for i, r := range ranges {
		if r.Start < 1 || r.End > 65535 || r.Start > r.End {
			return fmt.Errorf("frp.allowed_ports[%d] must be an inclusive port range", i)
		}
		for j := 0; j < i; j++ {
			other := ranges[j]
			if r.Start <= other.End && other.Start <= r.End {
				return fmt.Errorf("frp.allowed_ports[%d] overlaps another range", i)
			}
		}
	}
	return nil
}

func validateAllowedDomainSuffix(value string) error {
	value = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(value)), ".")
	if value == "" || len(value) > 253 || strings.ContainsAny(value, "\x00\r\n/*") {
		return errors.New("must be a DNS suffix")
	}
	if ip := net.ParseIP(value); ip != nil {
		return errors.New("must not be an IP address")
	}
	labels := strings.Split(value, ".")
	if len(labels) < 2 {
		return errors.New("must contain a dot")
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return errors.New("contains an invalid DNS label")
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return errors.New("contains an invalid DNS label")
			}
		}
	}
	return nil
}

func validatePrivateCIDR(value string) error {
	prefix, err := netip.ParsePrefix(strings.TrimSpace(value))
	if err != nil {
		return fmt.Errorf("invalid IPv4 prefix: %w", err)
	}
	prefix = prefix.Masked()
	allowed := prefix.Overlaps(netip.MustParsePrefix("10.0.0.0/8")) || prefix.Overlaps(netip.MustParsePrefix("100.64.0.0/10"))
	if !prefix.Addr().Is4() || prefix.Bits() > 30 || !allowed {
		return errors.New("must be an IPv4 /30 or larger prefix inside 10.0.0.0/8 or 100.64.0.0/10")
	}
	return nil
}

func validateHostPort(field, value string) error {
	value = strings.TrimSpace(value)
	_, port, err := net.SplitHostPort(value)
	if err != nil {
		return fmt.Errorf("%s must be a host:port address: %w", field, err)
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 {
		return fmt.Errorf("%s has an invalid port", field)
	}
	return nil
}

func (c Config) StateFile() string { return filepath.Join(c.Storage.DataDir, "state.json") }

func (c Config) EnsureDataDir() error {
	if err := os.MkdirAll(c.Storage.DataDir, 0o750); err != nil {
		return fmt.Errorf("create data directory: %w", err)
	}
	return nil
}

func loopbackHostPort(address string) bool {
	host, _, err := net.SplitHostPort(strings.TrimSpace(address))
	if err != nil {
		return false
	}
	host = strings.Trim(host, "[]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
