package frp

import (
	"errors"
	"strings"
	"testing"
)

func TestDecodeConfigRejectsUnknownAndUnsupportedFeatures(t *testing.T) {
	cfg := testConfig(t)
	data, err := EncodeConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	unknown := strings.Replace(string(data), "\"rules\"", "\"includes\": [\"x\"],\n  \"rules\"", 1)
	if _, err = DecodeConfig(strings.NewReader(unknown)); ErrorCode(err) != CodeUnsupportedFeature {
		t.Fatalf("unknown field error = %v, code = %s", err, ErrorCode(err))
	}
	unknown = strings.Replace(string(data), "\"type\": \"udp\"", "\"type\": \"udp\",\n      \"plugin\": \"virtual_net\"", 1)
	if _, err = DecodeConfig(strings.NewReader(unknown)); ErrorCode(err) != CodeUnsupportedFeature {
		t.Fatalf("plugin error = %v, code = %s", err, ErrorCode(err))
	}
}

func TestValidateConfigPortAndIdentityRules(t *testing.T) {
	cfg := testConfig(t)
	cfg.Profile.Rules = append(cfg.Profile.Rules, Rule{
		ID: "rule-game-tcp", Name: "游戏 TCP", Type: "tcp", Enabled: true,
		Target:   Target{Kind: "loopback", Host: "127.0.0.1", Port: 7777},
		Exposure: Exposure{RemotePort: 30001},
	})
	if err := ValidateConfig(cfg); err != nil {
		t.Fatalf("TCP/UDP may share a numeric remote port: %v", err)
	}

	cfg.Profile.Rules[1].Type = "udp"
	if err := ValidateConfig(cfg); ErrorCode(err) != CodeUnsupportedFeature {
		t.Fatalf("same protocol/remote port should fail: %v", err)
	}
	cfg.Profile.Rules[1].ID = cfg.Profile.Rules[0].ID
	cfg.Profile.Rules[1].Type = "tcp"
	if err := ValidateConfig(cfg); ErrorCode(err) != CodeUnsupportedFeature {
		t.Fatalf("duplicate rule id should fail: %v", err)
	}
	cfg = testConfig(t)
	cfg.Profile.Rules[0].Name = strings.ToUpper(cfg.Profile.Rules[0].Name)
	cfg.Profile.Rules = append(cfg.Profile.Rules, Rule{
		ID: "rule-2", Name: cfg.Profile.Rules[0].Name, Type: "tcp", Enabled: true,
		Target:   Target{Kind: "loopback", Host: "127.0.0.1", Port: 7778},
		Exposure: Exposure{RemotePort: 30002},
	})
	if err := ValidateConfig(cfg); ErrorCode(err) != CodeUnsupportedFeature {
		t.Fatalf("duplicate name should fail: %v", err)
	}
}

func TestValidateConfigStrictLoopbackAndTLS(t *testing.T) {
	cases := []func(*Config){
		func(c *Config) { c.Profile.Rules[0].Target.Kind = "lan" },
		func(c *Config) { c.Profile.Rules[0].Target.Host = "::ffff:127.0.0.1" },
		func(c *Config) { c.Profile.Rules[0].Target.Host = "localhost" },
		func(c *Config) { c.Profile.Server.Transport = "ftp" },
		func(c *Config) { c.Profile.Server.Kind = "virtual_net" },
		func(c *Config) { c.Profile.Server.TrustedCAPath = "" },
		func(c *Config) { c.Profile.Server.TLSServerName = "" },
	}
	for i, mutate := range cases {
		cfg := testConfig(t)
		mutate(&cfg)
		if err := ValidateConfig(cfg); err == nil {
			t.Fatalf("case %d should fail validation", i)
		}
	}
}

func TestValidateCARejectsNonPEM(t *testing.T) {
	path := t.TempDir() + "/ca.pem"
	if err := writePrivateFile(path, []byte("not a certificate")); err != nil {
		t.Fatal(err)
	}
	if err := ValidateCAFile(path); err == nil {
		t.Fatal("non-PEM CA accepted")
	}
}

func TestRenderConfigDoesNotContainToken(t *testing.T) {
	cfg := testConfig(t)
	cfg.Profile.Rules = append(cfg.Profile.Rules, Rule{
		ID: "rule-disabled", Name: "禁用规则", Type: "tcp", Enabled: false,
		Target:   Target{Kind: "loopback", Host: "127.0.0.1", Port: 7778},
		Exposure: Exposure{RemotePort: 30002},
	})
	rendered, err := RenderConfig(RenderInput{
		Config: cfg, DeviceID: "device-1", TokenPath: cfg.Profile.Server.TrustedCAPath,
		AdminPort: 17401, AdminUser: "tlan-manager", AdminPassword: strings.Repeat("a", 64),
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(rendered.TOML, "secret-token") || strings.Contains(rendered.TOML, "auth.token =") {
		t.Fatal("rendered TOML contains a literal token")
	}
	for _, want := range []string{
		"transport.tls.enable = true",
		"transport.tls.serverName = \"localhost\"",
		"transport.tls.trustedCaFile =",
		"auth.tokenSource.type = \"file\"",
		"webServer.addr = \"127.0.0.1\"",
		"[[proxies]]",
	} {
		if !strings.Contains(rendered.TOML, want) {
			t.Fatalf("rendered TOML missing %q:\n%s", want, rendered.TOML)
		}
	}
	if strings.Count(rendered.TOML, "[[proxies]]") != 1 {
		t.Fatal("disabled rule was rendered")
	}
	if rendered.ProxyNames["rule-game"] == rendered.ProxyNames["rule-disabled"] {
		t.Fatal("proxy names are not stable and unique")
	}
}

func TestErrorCode(t *testing.T) {
	err := codedError(CodeTLSUntrusted, "bad")
	if !errors.Is(err, err) || ErrorCode(err) != CodeTLSUntrusted {
		t.Fatal("coded error lost its code")
	}
}
