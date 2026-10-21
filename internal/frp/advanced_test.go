package frp

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestAdvancedSchemaRoundTripAndClone(t *testing.T) {
	cfg := testConfig(t)
	cfg.Profile.Rules[0] = Rule{
		ID: "rule-http-advanced", Name: "高级 HTTP", Type: "http", Enabled: true,
		Target: Target{Kind: "loopback", Host: "127.0.0.1", Port: 8080},
		Exposure: Exposure{
			CustomDomains:     []string{"app.example.com"},
			Subdomain:         "app",
			Locations:         []string{"/", "/api"},
			HTTPUser:          "alice",
			HTTPPasswordRef:   "http-password",
			HostHeaderRewrite: "backend.example.com",
			RouteByHTTPUser:   "alice",
			RequestHeaders:    map[string]string{"X-From": "tlan"},
			ResponseHeaders:   map[string]string{"X-Response": "tlan"},
		},
		Transport: RuleTransport{UseEncryption: true, UseCompression: true, ProxyProtocolVersion: "v2"},
	}
	cfg.Profile.Visitors = []Visitor{{
		ID: "visitor-xtcp", Name: "XTCP visitor", Type: "xtcp", Enabled: true,
		ServerName: "remote-xtcp", SecretRef: "visitor-secret", BindAddr: "127.0.0.1", BindPort: 9001,
		Protocol: "kcp", KeepTunnelOpen: true, MaxRetriesAnHour: 12, MinRetryInterval: 45,
		FallbackTo: "fallback-visitor", FallbackTimeoutMs: 750,
	}}
	cfg = NormalizeConfig(cfg)
	data, err := EncodeConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "http-secret") || strings.Contains(string(data), "rule-secret-value") {
		t.Fatal("runtime secret leaked into persisted profile")
	}
	decoded, err := DecodeConfig(strings.NewReader(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Profile.Rules[0].Exposure.Subdomain != "app" || decoded.Profile.Rules[0].Transport.ProxyProtocolVersion != "v2" {
		t.Fatalf("advanced fields did not round trip: %+v", decoded.Profile.Rules[0])
	}
	if decoded.Profile.Visitors[0].Protocol != "kcp" || decoded.Profile.Visitors[0].MaxRetriesAnHour != 12 {
		t.Fatalf("XTCP visitor did not round trip: %+v", decoded.Profile.Visitors[0])
	}
	cloned := CloneConfig(decoded)
	if decoded.Profile.Server.TCPMux == nil || cloned.Profile.Server.TCPMux == decoded.Profile.Server.TCPMux {
		t.Fatal("CloneConfig did not deep-copy server boolean pointers")
	}
	cloned.Profile.Rules[0].Exposure.Locations[0] = "/changed"
	cloned.Profile.Rules[0].Exposure.RequestHeaders["X-From"] = "changed"
	if decoded.Profile.Rules[0].Exposure.Locations[0] != "/" || decoded.Profile.Rules[0].Exposure.RequestHeaders["X-From"] != "tlan" {
		t.Fatal("CloneConfig did not deep-copy advanced fields")
	}
}

func TestRenderAdvancedHTTPAndTransportOptions(t *testing.T) {
	cfg := testConfig(t)
	cfg.Profile.Rules[0] = Rule{
		ID: "rule-http-advanced", Name: "高级 HTTP", Type: "http", Enabled: true,
		Target: Target{Kind: "loopback", Host: "127.0.0.1", Port: 8080},
		Exposure: Exposure{
			CustomDomains:     []string{"app.example.com"},
			Subdomain:         "app",
			Locations:         []string{"/", "/api"},
			HTTPUser:          "alice",
			HTTPPasswordRef:   "http-password",
			HostHeaderRewrite: "backend.example.com",
			RouteByHTTPUser:   "alice",
			RequestHeaders:    map[string]string{"X-From": "tlan"},
			ResponseHeaders:   map[string]string{"X-Response": "tlan"},
		},
		Transport: RuleTransport{UseEncryption: true, UseCompression: true, ProxyProtocolVersion: "v2"},
	}
	rendered, err := RenderConfig(RenderInput{
		Config: cfg, DeviceID: "device-1", TokenPath: cfg.Profile.Server.TrustedCAPath,
		AdminPort: 17401, AdminUser: DefaultAdminUser, AdminPassword: strings.Repeat("a", 64),
		Secrets: map[string]string{"http-password": "http-secret"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`transport.protocol = "tcp"`,
		`type = "http"`,
		`customDomains = ["app.example.com"]`,
		`subdomain = "app"`,
		`locations = ["/", "/api"]`,
		`httpUser = "alice"`,
		`httpPassword = "http-secret"`,
		`hostHeaderRewrite = "backend.example.com"`,
		`routeByHTTPUser = "alice"`,
		`requestHeaders.set."X-From" = "tlan"`,
		`responseHeaders.set."X-Response" = "tlan"`,
		`transport.useEncryption = true`,
		`transport.useCompression = true`,
		`transport.proxyProtocolVersion = "v2"`,
	} {
		if !strings.Contains(rendered.TOML, want) {
			t.Fatalf("rendered advanced TOML missing %q:\n%s", want, rendered.TOML)
		}
	}
}

func TestRenderHTTPSubdomainOnly(t *testing.T) {
	cfg := testConfig(t)
	cfg.Profile.Rules[0] = Rule{
		ID: "rule-subdomain", Name: "Subdomain HTTP", Type: "http", Enabled: true,
		Target:   Target{Kind: "loopback", Host: "127.0.0.1", Port: 8080},
		Exposure: Exposure{Subdomain: "app"},
	}
	rendered, err := RenderConfig(RenderInput{
		Config: cfg, DeviceID: "device-1", TokenPath: cfg.Profile.Server.TrustedCAPath,
		AdminPort: 17401, AdminUser: DefaultAdminUser, AdminPassword: strings.Repeat("a", 64),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rendered.TOML, `subdomain = "app"`) || strings.Contains(rendered.TOML, "customDomains =") {
		t.Fatalf("subdomain-only HTTP rendering is incorrect:\n%s", rendered.TOML)
	}
}

func TestRenderTCPMuxAndXTCP(t *testing.T) {
	cfg := testConfig(t)
	cfg.Profile.Rules = []Rule{
		{
			ID: "rule-mux", Name: "TCPMux", Type: "tcpmux", Enabled: true,
			Target:   Target{Kind: "loopback", Host: "127.0.0.1", Port: 10701},
			Exposure: Exposure{CustomDomains: []string{"tunnel.example.com"}, Multiplexer: "httpconnect"},
		},
		{
			ID: "rule-xtcp", Name: "XTCP", Type: "xtcp", Enabled: true, SecretRef: "rule-secret",
			Target: Target{Kind: "loopback", Host: "127.0.0.1", Port: 22},
		},
	}
	cfg.Profile.Visitors = []Visitor{{
		ID: "visitor-xtcp", Name: "XTCP access", Type: "xtcp", Enabled: true,
		ServerName: "remote-xtcp", SecretRef: "visitor-secret", BindAddr: "127.0.0.1", BindPort: 9001,
		Protocol: "quic", KeepTunnelOpen: true, MaxRetriesAnHour: 8, MinRetryInterval: 90, FallbackTimeoutMs: 1000,
	}}
	rendered, err := RenderConfig(RenderInput{
		Config: cfg, DeviceID: "device-1", TokenPath: cfg.Profile.Server.TrustedCAPath,
		AdminPort: 17401, AdminUser: DefaultAdminUser, AdminPassword: strings.Repeat("a", 64),
		Secrets: map[string]string{"rule-secret": "rule-secret-value", "visitor-secret": "visitor-secret-value"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`type = "tcpmux"`,
		`multiplexer = "httpconnect"`,
		`type = "xtcp"`,
		`secretKey = "rule-secret-value"`,
		`[[visitors]]`,
		`protocol = "quic"`,
		`keepTunnelOpen = true`,
		`maxRetriesAnHour = 8`,
		`minRetryInterval = 90`,
		`fallbackTimeoutMs = 1000`,
	} {
		if !strings.Contains(rendered.TOML, want) {
			t.Fatalf("rendered private/advanced TOML missing %q:\n%s", want, rendered.TOML)
		}
	}
}

func TestAdvancedTransportSchema(t *testing.T) {
	for _, transport := range []string{"tcp", "websocket", "wss", "quic", "kcp"} {
		t.Run(transport, func(t *testing.T) {
			cfg := testConfig(t)
			cfg.Profile.Server.Transport = transport
			if err := ValidateConfig(cfg); err != nil {
				t.Fatalf("transport %s rejected: %v", transport, err)
			}
			input := RenderInput{
				Config: cfg, DeviceID: "device-1", TokenPath: cfg.Profile.Server.TrustedCAPath,
				AdminPort: 17401, AdminUser: DefaultAdminUser, AdminPassword: strings.Repeat("a", 64),
			}
			if transport == "kcp" || transport == "quic" {
				input.ServerDialHost = "127.0.0.1"
				input.ServerDialPort = 23456
			}
			rendered, err := RenderConfig(input)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(rendered.TOML, `transport.protocol = "`+transport+`"`) {
				t.Fatalf("transport %s was not rendered:\n%s", transport, rendered.TOML)
			}
		})
	}
}

func TestUDPTransportRenderUsesRelayAndRejectsTCPProxyURL(t *testing.T) {
	cfg := testConfig(t)
	cfg.Profile.Server.Transport = "quic"
	rendered, err := RenderConfig(RenderInput{
		Config: cfg, DeviceID: "device-1", TokenPath: cfg.Profile.Server.TrustedCAPath,
		AdminPort: 17401, AdminUser: DefaultAdminUser, AdminPassword: strings.Repeat("a", 64),
		ServerDialHost: "127.0.0.1", ServerDialPort: 23456,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rendered.TOML, `serverAddr = "127.0.0.1"`) || !strings.Contains(rendered.TOML, "serverPort = 23456") {
		t.Fatalf("UDP relay override was not rendered:\n%s", rendered.TOML)
	}
	if _, err = RenderConfig(RenderInput{
		Config: cfg, DeviceID: "device-1", TokenPath: cfg.Profile.Server.TrustedCAPath,
		AdminPort: 17401, AdminUser: DefaultAdminUser, AdminPassword: strings.Repeat("a", 64),
		ServerProxyURL: "http://127.0.0.1:1234",
	}); err == nil {
		t.Fatal("KCP/QUIC accepted a TCP proxyURL")
	}
}

func TestAdvancedRulesFailClosedWithMeshTarget(t *testing.T) {
	for _, ruleType := range []string{"tcpmux", "xtcp"} {
		t.Run(ruleType, func(t *testing.T) {
			cfg := managedMeshTargetConfig(t, "100.64.0.2")
			cfg.Profile.Rules[0].Type = ruleType
			cfg.Profile.Rules[0].Exposure = Exposure{CustomDomains: []string{"mesh.example.com"}, Multiplexer: "httpconnect"}
			if ruleType == "xtcp" {
				cfg.Profile.Rules[0].SecretRef = "rule-secret"
				cfg.Profile.Rules[0].Exposure = Exposure{}
			}
			err := ValidateConfig(cfg)
			if err == nil || !IsDependencyIsolationError(err) {
				t.Fatalf("Mesh target with %s error = %v", ruleType, err)
			}
			if !strings.Contains(strings.ToLower(err.Error()), "dedicated") {
				t.Fatalf("Mesh isolation error is not actionable: %v", err)
			}
		})
	}
}

func TestManagedAdvancedRulesUseAuthorizationSchema(t *testing.T) {
	for _, ruleType := range []string{"tcpmux", "xtcp"} {
		t.Run(ruleType, func(t *testing.T) {
			cfg := testConfig(t)
			cfg.Profile.Server.Kind = "managed"
			cfg.Profile.Server.ServerID = "frps-managed"
			cfg.Profile.Rules[0].Type = ruleType
			cfg.Profile.Rules[0].Target = Target{Kind: "loopback", Host: "127.0.0.1", Port: 22}
			if ruleType == "tcpmux" {
				cfg.Profile.Rules[0].Exposure = Exposure{CustomDomains: []string{"tunnel.example.com"}, Multiplexer: "httpconnect"}
			} else {
				cfg.Profile.Rules[0].Exposure = Exposure{}
				cfg.Profile.Rules[0].SecretRef = "rule-secret"
			}
			if err := ValidateConfig(cfg); err != nil {
				t.Fatalf("managed %s was rejected: %v", ruleType, err)
			}
		})
	}
}

func TestAdvancedProtocolSpecificValidation(t *testing.T) {
	cfg := testConfig(t)
	cfg.Profile.Rules[0].Type = "https"
	cfg.Profile.Rules[0].Exposure = Exposure{CustomDomains: []string{"app.example.com"}, Locations: []string{"/api"}}
	if err := ValidateConfig(cfg); err == nil {
		t.Fatal("HTTPS locations accepted")
	}

	cfg = testConfig(t)
	cfg.Profile.Rules[0].Type = "tcpmux"
	cfg.Profile.Rules[0].Exposure = Exposure{CustomDomains: []string{"tunnel.example.com"}, Multiplexer: "wrong"}
	if err := ValidateConfig(cfg); err == nil {
		t.Fatal("invalid tcpmux multiplexer accepted")
	}

	cfg = testConfig(t)
	cfg.Profile.Rules[0].Type = "http"
	cfg.Profile.Rules[0].Exposure = Exposure{
		CustomDomains:  []string{"app.example.com"},
		RequestHeaders: map[string]string{"Bad Header": "value"},
	}
	if err := ValidateConfig(cfg); err == nil {
		t.Fatal("invalid HTTP header name accepted")
	}

	cfg = testConfig(t)
	cfg.Profile.Rules[0].Type = "http"
	cfg.Profile.Rules[0].Exposure = Exposure{CustomDomains: []string{"app.example.com"}, HTTPUser: "alice"}
	if err := ValidateConfig(cfg); err == nil {
		t.Fatal("HTTP user without password reference accepted")
	}

	cfg = testConfig(t)
	cfg.Profile.Rules[0].Type = "xtcp"
	cfg.Profile.Rules[0].Exposure = Exposure{}
	cfg.Profile.Rules[0].SecretRef = "rule-secret"
	cfg.Profile.Visitors = []Visitor{{
		ID: "visitor-xtcp", Name: "XTCP access", Type: "xtcp", Enabled: true,
		ServerName: "remote-xtcp", SecretRef: "visitor-secret", BindAddr: "127.0.0.1", BindPort: 9001,
		Protocol: "tcp", MaxRetriesAnHour: 8, MinRetryInterval: 90, FallbackTimeoutMs: 1000,
	}}
	if err := ValidateConfig(NormalizeConfig(cfg)); err == nil {
		t.Fatal("invalid XTCP visitor protocol accepted")
	}
}

func TestAdvancedDefaultsAreAcceptedBeforeNormalize(t *testing.T) {
	cfg := testConfig(t)
	cfg.Profile.Rules[0] = Rule{
		ID: "rule-mux", Name: "TCPMux", Type: "tcpmux", Enabled: true,
		Target:   Target{Kind: "loopback", Host: "127.0.0.1", Port: 10701},
		Exposure: Exposure{CustomDomains: []string{"tunnel.example.com"}},
	}
	if err := ValidateConfig(cfg); err != nil {
		t.Fatalf("tcpmux default multiplexer rejected: %v", err)
	}
	cfg = testConfig(t)
	cfg.Profile.Rules[0] = Rule{
		ID: "rule-xtcp", Name: "XTCP", Type: "xtcp", Enabled: true, SecretRef: "rule-secret",
		Target: Target{Kind: "loopback", Host: "127.0.0.1", Port: 22},
	}
	cfg.Profile.Visitors = []Visitor{{
		ID: "visitor-xtcp", Name: "XTCP access", Type: "xtcp", Enabled: true,
		ServerName: "remote-xtcp", SecretRef: "visitor-secret", BindAddr: "127.0.0.1", BindPort: 9001,
	}}
	if err := ValidateConfig(cfg); err != nil {
		t.Fatalf("XTCP defaults rejected before normalize: %v", err)
	}
}

func TestAdvancedRenderPassesFRPCVerify(t *testing.T) {
	binary := strings.TrimSpace(os.Getenv("TLAN_FRPC_VERIFY_BINARY"))
	if binary == "" {
		t.Skip("TLAN_FRPC_VERIFY_BINARY is not set")
	}
	cfg := testConfig(t)
	cfg.Profile.Rules = []Rule{
		{
			ID: "rule-http", Name: "Advanced HTTP", Type: "http", Enabled: true,
			Target: Target{Kind: "loopback", Host: "127.0.0.1", Port: 8080},
			Exposure: Exposure{
				CustomDomains: []string{"app.example.com"}, Subdomain: "app",
				Locations: []string{"/", "/api"}, HTTPUser: "alice", HTTPPasswordRef: "http-password",
				HostHeaderRewrite: "backend.example.com", RouteByHTTPUser: "alice",
				RequestHeaders: map[string]string{"X-From": "tlan"}, ResponseHeaders: map[string]string{"X-Response": "tlan"},
			},
			Transport: RuleTransport{UseEncryption: true, UseCompression: true, ProxyProtocolVersion: "v2"},
		},
		{
			ID: "rule-mux", Name: "Advanced TCPMux", Type: "tcpmux", Enabled: true,
			Target:   Target{Kind: "loopback", Host: "127.0.0.1", Port: 10701},
			Exposure: Exposure{CustomDomains: []string{"tunnel.example.com"}, Multiplexer: "httpconnect"},
		},
		{
			ID: "rule-xtcp", Name: "Advanced XTCP", Type: "xtcp", Enabled: true, SecretRef: "rule-secret",
			Target: Target{Kind: "loopback", Host: "127.0.0.1", Port: 22},
		},
	}
	cfg.Profile.Visitors = []Visitor{{
		ID: "visitor-xtcp", Name: "Advanced XTCP visitor", Type: "xtcp", Enabled: true,
		ServerName: "remote-xtcp", SecretRef: "visitor-secret", BindAddr: "127.0.0.1", BindPort: 9001,
		Protocol: "quic", KeepTunnelOpen: true, MaxRetriesAnHour: 8, MinRetryInterval: 90, FallbackTimeoutMs: 1000,
	}}
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token.txt")
	if err := os.WriteFile(tokenPath, []byte("test-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, transport := range []string{"tcp", "websocket", "wss", "quic", "kcp"} {
		t.Run(transport, func(t *testing.T) {
			cfg.Profile.Server.Transport = transport
			input := RenderInput{
				Config: cfg, DeviceID: "device-1", TokenPath: tokenPath,
				AdminPort: 17401, AdminUser: DefaultAdminUser, AdminPassword: strings.Repeat("a", 64),
				Secrets: map[string]string{"http-password": "http-secret", "rule-secret": "rule-secret-value", "visitor-secret": "visitor-secret-value"},
			}
			if transport == "kcp" || transport == "quic" {
				input.ServerDialHost = "127.0.0.1"
				input.ServerDialPort = 23456
			}
			rendered, err := RenderConfig(input)
			if err != nil {
				t.Fatal(err)
			}
			configPath := filepath.Join(dir, "frpc-"+transport+".toml")
			if err = os.WriteFile(configPath, []byte(rendered.TOML), 0o600); err != nil {
				t.Fatal(err)
			}
			output, err := exec.Command(binary, "verify", "-c", configPath).CombinedOutput()
			if err != nil {
				t.Fatalf("frpc verify failed: %v\n%s\n%s", err, output, rendered.TOML)
			}
		})
	}
}
