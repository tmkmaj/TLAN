package frp

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

const (
	// ManagedHeartbeatInterval keeps revocation latency bounded for official
	// frpc v0.71.1 clients. The matching FRPS heartbeatTimeout is documented
	// in deploy/frps/frps.toml.example and must be <= 10 seconds.
	ManagedHeartbeatInterval = 3
	ManagedHeartbeatTimeout  = 8
	managedCapabilityEnv     = "TLAN_FRP_CAPABILITY"
)

type RenderInput struct {
	Config         Config
	DeviceID       string
	TokenPath      string
	AdminPort      int
	AdminUser      string
	AdminPassword  string
	Secrets        map[string]string
	Lease          *Lease
	LocalTargets   map[string]Target
	ServerProxyURL string
	ServerDialHost string
	ServerDialPort int
}

type RenderedConfig struct {
	TOML         string
	ProxyNames   map[string]string
	VisitorNames map[string]string
}

func RenderConfig(input RenderInput) (RenderedConfig, error) {
	cfg := NormalizeConfig(input.Config)
	if err := ValidateConfig(cfg); err != nil {
		return RenderedConfig{}, err
	}
	if input.TokenPath == "" || !filepath.IsAbs(input.TokenPath) {
		return RenderedConfig{}, unsupported("runtime token path must be absolute")
	}
	if input.AdminPort < 1 || input.AdminPort > 65535 {
		return RenderedConfig{}, codedError(CodeLocalListenBusy, "invalid local management port")
	}
	if input.AdminUser == "" || len(input.AdminUser) > 128 || strings.ContainsAny(input.AdminUser, "\x00\r\n") {
		return RenderedConfig{}, codedError(CodeConfigurationInvalid, "management user is invalid")
	}
	if len(input.AdminPassword) < 32 || len(input.AdminPassword) > 256 || strings.ContainsAny(input.AdminPassword, "\x00\r\n") {
		return RenderedConfig{}, codedError(CodeConfigurationInvalid, "management password must be 32-256 bytes")
	}

	deviceID := input.DeviceID
	if deviceID == "" {
		deviceID = "local-device"
	}
	protocol := cfg.Profile.Server.Transport
	if protocol == "" {
		protocol = "tcp"
	}
	var b strings.Builder
	serverHost := cfg.Profile.Server.Host
	serverPort := cfg.Profile.Server.Port
	if input.ServerDialHost != "" {
		serverHost = input.ServerDialHost
	}
	if input.ServerDialPort != 0 {
		if input.ServerDialPort < 1 || input.ServerDialPort > 65535 {
			return RenderedConfig{}, codedError(CodeConfigurationInvalid, "server dial port override is invalid")
		}
		serverPort = input.ServerDialPort
	}
	if (input.ServerDialHost != "" || input.ServerDialPort != 0) && protocol != "kcp" && protocol != "quic" {
		return RenderedConfig{}, codedError(CodeConfigurationInvalid, "server dial overrides are only valid for KCP/QUIC UDP egress relays")
	}
	writeTOMLString(&b, "serverAddr", serverHost)
	fmt.Fprintf(&b, "serverPort = %d\n", serverPort)
	writeTOMLString(&b, "user", ClientUser(deviceID, cfg.Profile.ID))
	b.WriteString("loginFailExit = false\n\n")

	b.WriteString("auth.method = \"token\"\n")
	b.WriteString("auth.tokenSource.type = \"file\"\n")
	writeTOMLString(&b, "auth.tokenSource.file.path", filepath.ToSlash(input.TokenPath))
	if protocol == "kcp" || protocol == "quic" {
		if input.ServerProxyURL != "" {
			return RenderedConfig{}, codedError(CodeConfigurationInvalid, "KCP/QUIC must use the UDP egress relay, not transport.proxyURL")
		}
		if input.ServerDialHost == "" || input.ServerDialPort == 0 || !isLoopbackHost(input.ServerDialHost) {
			return RenderedConfig{}, codedError(CodeConfigurationInvalid, "KCP/QUIC require a loopback UDP egress relay dial address")
		}
	}
	writeTOMLString(&b, "transport.protocol", protocol)
	b.WriteString("transport.dialServerTimeout = 10\n")
	b.WriteString("transport.poolCount = 1\n")
	if input.ServerProxyURL != "" {
		writeTOMLString(&b, "transport.proxyURL", input.ServerProxyURL)
	}
	tcpMux := true
	if cfg.Profile.Server.TCPMux != nil {
		tcpMux = *cfg.Profile.Server.TCPMux
	}
	fmt.Fprintf(&b, "transport.tcpMux = %t\n", tcpMux)
	b.WriteString("transport.tls.enable = true\n")
	disableFirstByte := true
	if cfg.Profile.Server.DisableCustomTLSFirstByte != nil {
		disableFirstByte = *cfg.Profile.Server.DisableCustomTLSFirstByte
	}
	fmt.Fprintf(&b, "transport.tls.disableCustomTLSFirstByte = %t\n", disableFirstByte)
	writeTOMLString(&b, "transport.tls.serverName", cfg.Profile.Server.TLSServerName)
	writeTOMLString(&b, "transport.tls.trustedCaFile", filepath.ToSlash(cfg.Profile.Server.TrustedCAPath))
	b.WriteString("\nlog.to = \"console\"\n")
	b.WriteString("log.level = \"info\"\n")
	b.WriteString("log.disablePrintColor = true\n\n")
	b.WriteString("webServer.addr = \"127.0.0.1\"\n")
	fmt.Fprintf(&b, "webServer.port = %d\n", input.AdminPort)
	writeTOMLString(&b, "webServer.user", input.AdminUser)
	writeTOMLString(&b, "webServer.password", input.AdminPassword)
	b.WriteString("webServer.pprofEnable = false\n")
	if cfg.Profile.Server.Kind == "managed" {
		if input.Lease == nil || input.Lease.ID == "" || input.Lease.Credential == "" {
			return RenderedConfig{}, codedError(CodeAuthRejected, "managed FRP lease is required")
		}
		fmt.Fprintf(&b, "transport.heartbeatInterval = %d\n", ManagedHeartbeatInterval)
		fmt.Fprintf(&b, "transport.heartbeatTimeout = %d\n", ManagedHeartbeatTimeout)
		writeTOMLString(&b, "metadatas.tlan_lease", input.Lease.ID)
		writeTOMLString(&b, "metadatas.tlan_capability", "{{ .Envs."+managedCapabilityEnv+" }}")
		writeTOMLString(&b, "metadatas.tlan_server", cfg.Profile.Server.ServerID)
	}

	names := make(map[string]string, len(cfg.Profile.Rules))
	for _, rule := range cfg.Profile.Rules {
		name := ProxyName(deviceID, cfg.Profile.ID, rule.ID)
		names[rule.ID] = name
		if !rule.Enabled {
			continue
		}
		target := rule.Target
		if local, ok := input.LocalTargets[rule.ID]; ok {
			target = local
		}
		if target.Kind == "mesh_peer" || target.Kind == "mesh_self" {
			return RenderedConfig{}, codedError(CodeConfigurationInvalid, "Mesh target gateway is not prepared for rule %q", rule.Name)
		}
		b.WriteString("\n[[proxies]]\n")
		writeTOMLString(&b, "name", name)
		writeTOMLString(&b, "type", rule.Type)
		writeTOMLString(&b, "localIP", target.Host)
		fmt.Fprintf(&b, "localPort = %d\n", target.Port)
		if rule.Transport.UseEncryption {
			b.WriteString("transport.useEncryption = true\n")
		}
		if rule.Transport.UseCompression {
			b.WriteString("transport.useCompression = true\n")
		}
		if rule.Transport.ProxyProtocolVersion != "" {
			writeTOMLString(&b, "transport.proxyProtocolVersion", rule.Transport.ProxyProtocolVersion)
		}
		switch rule.Type {
		case "tcp", "udp":
			fmt.Fprintf(&b, "remotePort = %d\n", rule.Exposure.RemotePort)
		case "http", "https", "tcpmux":
			writeDomainFields(&b, rule.Exposure)
			if rule.Type == "http" {
				writeLocations(&b, rule.Exposure.Locations)
				if err := writeHTTPAuth(&b, input, rule.Exposure); err != nil {
					return RenderedConfig{}, err
				}
				if rule.Exposure.HostHeaderRewrite != "" {
					writeTOMLString(&b, "hostHeaderRewrite", rule.Exposure.HostHeaderRewrite)
				}
				if rule.Exposure.RouteByHTTPUser != "" {
					writeTOMLString(&b, "routeByHTTPUser", rule.Exposure.RouteByHTTPUser)
				}
				writeHeaderOperations(&b, "requestHeaders", rule.Exposure.RequestHeaders)
				writeHeaderOperations(&b, "responseHeaders", rule.Exposure.ResponseHeaders)
			} else if rule.Type == "tcpmux" {
				writeTOMLString(&b, "multiplexer", rule.Exposure.Multiplexer)
				if err := writeHTTPAuth(&b, input, rule.Exposure); err != nil {
					return RenderedConfig{}, err
				}
				if rule.Exposure.RouteByHTTPUser != "" {
					writeTOMLString(&b, "routeByHTTPUser", rule.Exposure.RouteByHTTPUser)
				}
			}
		case "stcp", "sudp", "xtcp":
			secret := input.Secrets[rule.SecretRef]
			if secret == "" {
				return RenderedConfig{}, codedError(CodeConfigurationInvalid, "secret %q is not available", rule.SecretRef)
			}
			writeTOMLString(&b, "secretKey", secret)
			writeStringArray(&b, "allowUsers", rule.Exposure.AllowUsers)
		}
	}
	visitorNames := make(map[string]string, len(cfg.Profile.Visitors))
	for _, visitor := range cfg.Profile.Visitors {
		name := VisitorName(deviceID, cfg.Profile.ID, visitor.ID)
		visitorNames[visitor.ID] = name
		if !visitor.Enabled {
			continue
		}
		secret := input.Secrets[visitor.SecretRef]
		if secret == "" {
			return RenderedConfig{}, codedError(CodeConfigurationInvalid, "visitor secret %q is not available", visitor.SecretRef)
		}
		b.WriteString("\n[[visitors]]\n")
		writeTOMLString(&b, "name", name)
		writeTOMLString(&b, "type", visitor.Type)
		writeTOMLString(&b, "serverName", visitor.ServerName)
		if visitor.ServerUser != "" {
			writeTOMLString(&b, "serverUser", visitor.ServerUser)
		}
		writeTOMLString(&b, "secretKey", secret)
		b.WriteString("bindAddr = \"127.0.0.1\"\n")
		fmt.Fprintf(&b, "bindPort = %d\n", visitor.BindPort)
		if visitor.Type == "xtcp" {
			writeTOMLString(&b, "protocol", visitor.Protocol)
			if visitor.KeepTunnelOpen {
				b.WriteString("keepTunnelOpen = true\n")
			}
			if visitor.MaxRetriesAnHour > 0 {
				fmt.Fprintf(&b, "maxRetriesAnHour = %d\n", visitor.MaxRetriesAnHour)
			}
			if visitor.MinRetryInterval > 0 {
				fmt.Fprintf(&b, "minRetryInterval = %d\n", visitor.MinRetryInterval)
			}
			if visitor.FallbackTo != "" {
				writeTOMLString(&b, "fallbackTo", visitor.FallbackTo)
			}
			if visitor.FallbackTimeoutMs > 0 {
				fmt.Fprintf(&b, "fallbackTimeoutMs = %d\n", visitor.FallbackTimeoutMs)
			}
		}
	}
	return RenderedConfig{TOML: b.String(), ProxyNames: names, VisitorNames: visitorNames}, nil
}

func writeDomainFields(b *strings.Builder, exposure Exposure) {
	if len(exposure.CustomDomains) > 0 {
		b.WriteString("customDomains = [")
		for i, domain := range exposure.CustomDomains {
			if i > 0 {
				b.WriteString(", ")
			}
			b.WriteString(tomlQuote(domain))
		}
		b.WriteString("]\n")
	}
	if exposure.Subdomain != "" {
		writeTOMLString(b, "subdomain", exposure.Subdomain)
	}
}

func writeStringArray(b *strings.Builder, key string, values []string) {
	if len(values) == 0 {
		return
	}
	b.WriteString(key)
	b.WriteString(" = [")
	for i, value := range values {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(tomlQuote(value))
	}
	b.WriteString("]\n")
}

func writeLocations(b *strings.Builder, locations []string) {
	if len(locations) == 0 {
		return
	}
	b.WriteString("locations = [")
	for i, location := range locations {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(tomlQuote(location))
	}
	b.WriteString("]\n")
}

func writeHTTPAuth(b *strings.Builder, input RenderInput, exposure Exposure) error {
	if exposure.HTTPUser == "" {
		return nil
	}
	writeTOMLString(b, "httpUser", exposure.HTTPUser)
	secret := input.Secrets[exposure.HTTPPasswordRef]
	if secret == "" {
		return codedError(CodeConfigurationInvalid, "HTTP password secret %q is not available", exposure.HTTPPasswordRef)
	}
	writeTOMLString(b, "httpPassword", secret)
	return nil
}

func writeHeaderOperations(b *strings.Builder, field string, values map[string]string) {
	if len(values) == 0 {
		return
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		b.WriteString(field)
		b.WriteString(".set.")
		b.WriteString(tomlQuote(key))
		b.WriteString(" = ")
		b.WriteString(tomlQuote(values[key]))
		b.WriteByte('\n')
	}
}

func writeTOMLString(b *strings.Builder, key, value string) {
	b.WriteString(key)
	b.WriteString(" = ")
	b.WriteString(tomlQuote(value))
	b.WriteByte('\n')
}

func tomlQuote(value string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range value {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\b':
			b.WriteString(`\b`)
		case '\t':
			b.WriteString(`\t`)
		case '\n':
			b.WriteString(`\n`)
		case '\f':
			b.WriteString(`\f`)
		case '\r':
			b.WriteString(`\r`)
		default:
			if r < 0x20 || r == 0x7f {
				fmt.Fprintf(&b, `\u%04X`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}
