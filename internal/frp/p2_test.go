package frp

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestValidateP2TargetsAndDomains(t *testing.T) {
	cfg := testConfig(t)
	cfg.Profile.Rules[0].Type = "http"
	cfg.Profile.Rules[0].Target = Target{Kind: "lan", Host: "192.168.1.20", Port: 8080}
	cfg.Profile.Rules[0].Exposure = Exposure{CustomDomains: []string{"app.example.com"}}
	if err := ValidateConfig(cfg); err != nil {
		t.Fatalf("valid LAN HTTP rule rejected: %v", err)
	}
	cfg.Profile.Rules[0].Target.Host = "8.8.8.8"
	if err := ValidateConfig(cfg); err == nil {
		t.Fatal("public LAN target accepted")
	}
	cfg = testConfig(t)
	cfg.Profile.Rules[0].Type = "https"
	cfg.Profile.Rules[0].Exposure = Exposure{CustomDomains: []string{"app.example.com"}}
	if err := ValidateConfig(cfg); err != nil {
		t.Fatalf("valid HTTPS rule rejected: %v", err)
	}
	cfg.Profile.Rules = append(cfg.Profile.Rules, Rule{
		ID: "rule-domain-duplicate", Name: "重复域名", Type: "http", Enabled: true,
		Target:   Target{Kind: "loopback", Host: "127.0.0.1", Port: 8081},
		Exposure: Exposure{CustomDomains: []string{"APP.EXAMPLE.COM"}},
	})
	if err := ValidateConfig(NormalizeConfig(cfg)); err == nil {
		t.Fatal("duplicate custom domain accepted")
	}
	cfg = testConfig(t)
	cfg.Profile.Rules[0].Type = "http"
	cfg.Profile.Rules[0].Exposure = Exposure{RemotePort: 30000}
	if err := ValidateConfig(cfg); err == nil {
		t.Fatal("HTTP rule with remotePort accepted")
	}
}

func TestSubdomainRequiresConfiguredHost(t *testing.T) {
	cfg := testConfig(t)
	cfg.Profile.Rules[0].Type = "http"
	cfg.Profile.Rules[0].Exposure = Exposure{Subdomain: "app"}
	cfg.Profile.Server.SubdomainHost = "frp.example.test"
	if err := ValidateConfig(cfg); err != nil {
		t.Fatalf("valid subdomain rule rejected: %v", err)
	}
	cfg.Profile.Server.SubdomainHost = ""
	if err := ValidateConfig(cfg); err == nil {
		t.Fatal("subdomain rule without server subdomain host was accepted")
	}
}
func TestRenderP2HTTPAndLAN(t *testing.T) {
	cfg := testConfig(t)
	cfg.Profile.Rules[0] = Rule{
		ID: "rule-http", Name: "Web", Type: "http", Enabled: true,
		Target:   Target{Kind: "lan", Host: "192.168.1.20", Port: 8080},
		Exposure: Exposure{CustomDomains: []string{"app.example.com", "www.example.com"}},
	}
	rendered, err := RenderConfig(RenderInput{
		Config: cfg, DeviceID: "device-1", TokenPath: cfg.Profile.Server.TrustedCAPath,
		AdminPort: 17401, AdminUser: DefaultAdminUser, AdminPassword: strings.Repeat("a", 64),
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`type = "http"`,
		`localIP = "192.168.1.20"`,
		`customDomains = ["app.example.com", "www.example.com"]`,
	} {
		if !strings.Contains(rendered.TOML, want) {
			t.Fatalf("rendered TOML missing %q:\n%s", want, rendered.TOML)
		}
	}
	if strings.Contains(rendered.TOML, "remotePort =") {
		t.Fatal("HTTP rule rendered remotePort")
	}
}

func TestLegacySchemaIsAccepted(t *testing.T) {
	cfg := testConfig(t)
	cfg.SchemaVersion = LegacySchema
	cfg.Profile.Server.PublicHTTPPort = 0
	cfg.Profile.Server.PublicHTTPSPort = 0
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeConfig(strings.NewReader(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	if decoded.SchemaVersion != SchemaVersion || decoded.Profile.Server.PublicHTTPPort != DefaultHTTPPort || decoded.Profile.Server.PublicHTTPSPort != DefaultHTTPSPort || decoded.Profile.Server.PublicTCPMuxPort != DefaultTCPMuxPort {
		t.Fatalf("legacy schema migration failed: %+v", decoded.Profile.Server)
	}
}

func TestRenderPrivateProxyAndVisitor(t *testing.T) {
	cfg := testConfig(t)
	cfg.Profile.Rules[0] = Rule{
		ID: "rule-private", Name: "Private SSH", Type: "stcp", Enabled: true, SecretRef: "rule-private-secret",
		Target: Target{Kind: "loopback", Host: "127.0.0.1", Port: 22},
	}
	cfg.Profile.Visitors = []Visitor{{
		ID: "visitor-private", Name: "Private SSH access", Type: "stcp", Enabled: true,
		ServerName: "tlan_private_proxy", SecretRef: "visitor-private-secret",
		BindAddr: "127.0.0.1", BindPort: 9000,
	}}
	rendered, err := RenderConfig(RenderInput{
		Config: cfg, DeviceID: "device-1", TokenPath: cfg.Profile.Server.TrustedCAPath,
		AdminPort: 17401, AdminUser: DefaultAdminUser, AdminPassword: strings.Repeat("a", 64),
		Secrets: map[string]string{
			"rule-private-secret":    "proxy-secret",
			"visitor-private-secret": "visitor-secret",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`type = "stcp"`,
		`secretKey = "proxy-secret"`,
		`[[visitors]]`,
		`serverName = "tlan_private_proxy"`,
		`secretKey = "visitor-secret"`,
		`bindAddr = "127.0.0.1"`,
		`bindPort = 9000`,
	} {
		if !strings.Contains(rendered.TOML, want) {
			t.Fatalf("rendered TOML missing %q:\n%s", want, rendered.TOML)
		}
	}
	if strings.Contains(rendered.TOML, "virtual_net") || strings.Contains(rendered.TOML, "plugin") {
		t.Fatal("private rule rendered an unsupported plugin")
	}
}

func TestVisitorRequiresLoopbackBind(t *testing.T) {
	cfg := testConfig(t)
	cfg.Profile.Visitors = []Visitor{{
		ID: "visitor", Name: "Visitor", Type: "stcp", Enabled: true,
		ServerName: "remote", SecretRef: "visitor-secret", BindAddr: "0.0.0.0", BindPort: 9000,
	}}
	if err := ValidateConfig(cfg); err == nil {
		t.Fatal("non-loopback visitor bind accepted")
	}
}

func TestRenderExternalTransportCompatibility(t *testing.T) {
	cfg := testConfig(t)
	disabled := false
	cfg.Profile.Server.TCPMux = &disabled
	cfg.Profile.Server.DisableCustomTLSFirstByte = &disabled
	rendered, err := RenderConfig(RenderInput{
		Config: cfg, DeviceID: "device-1", TokenPath: cfg.Profile.Server.TrustedCAPath,
		AdminPort: 17401, AdminUser: DefaultAdminUser, AdminPassword: strings.Repeat("a", 64),
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"transport.tcpMux = false", "transport.tls.disableCustomTLSFirstByte = false"} {
		if !strings.Contains(rendered.TOML, want) {
			t.Fatalf("compatibility TOML missing %q:\n%s", want, rendered.TOML)
		}
	}
}
func TestManagedLeaseMetadata(t *testing.T) {
	cfg := testConfig(t)
	cfg.Profile.Server.Kind = "managed"
	cfg.Profile.Server.ServerID = "frps-managed-1"
	cfg.Profile.ID = "profile-office"
	cfg.Profile.Rules[0].Type = "tcp"
	lease := Lease{ID: "lease-1", Credential: "capability-1", ExpiresAt: time.Now().Add(time.Hour)}
	rendered, err := RenderConfig(RenderInput{
		Config: cfg, DeviceID: "device-1", TokenPath: cfg.Profile.Server.TrustedCAPath,
		AdminPort: 17401, AdminUser: DefaultAdminUser, AdminPassword: strings.Repeat("a", 64),
		Lease: &lease,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`metadatas.tlan_lease = "lease-1"`,
		`metadatas.tlan_capability = "{{ .Envs.TLAN_FRP_CAPABILITY }}"`,
		`metadatas.tlan_server = "frps-managed-1"`,
	} {
		if !strings.Contains(rendered.TOML, want) {
			t.Fatalf("managed TOML missing %q:\n%s", want, rendered.TOML)
		}
	}
	if strings.Contains(rendered.TOML, lease.Credential) {
		t.Fatal("managed capability was written to the runtime TOML")
	}
	if strings.Contains(rendered.TOML, lease.Credential) {
		t.Fatal("managed capability appears in another rendered field")
	}
}

func TestMeshPeerRenderRequiresPreparedLocalTarget(t *testing.T) {
	cfg := testConfig(t)
	cfg.Profile.Server.Kind = "managed"
	cfg.Profile.Server.ServerID = "frps-a"
	cfg.Profile.Rules[0] = Rule{
		ID: "rule-mesh", Name: "Mesh target", Type: "tcp", Enabled: true,
		Target:   Target{Kind: "mesh_peer", Host: "10.240.0.5", Port: 22, NetworkID: "net-a", DeviceID: "dev-b", PublicKey: base64.StdEncoding.EncodeToString(make([]byte, 32)), ServiceID: "svc-mesh"},
		Exposure: Exposure{RemotePort: 30001},
	}
	lease := &Lease{ID: "lease-mesh", Credential: "capability-mesh", ExpiresAt: time.Now().Add(time.Hour)}
	input := RenderInput{Config: cfg, DeviceID: "device-1", TokenPath: cfg.Profile.Server.TrustedCAPath, AdminPort: 17401, AdminUser: DefaultAdminUser, AdminPassword: strings.Repeat("a", 64), Lease: lease}
	if _, err := RenderConfig(input); ErrorCode(err) != CodeConfigurationInvalid {
		t.Fatalf("unprepared mesh target error = %v", err)
	}
	input.LocalTargets = map[string]Target{"rule-mesh": {Kind: "loopback", Host: "127.0.0.1", Port: 41000}}
	rendered, err := RenderConfig(input)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rendered.TOML, "localIP = \"127.0.0.1\"") || !strings.Contains(rendered.TOML, "localPort = 41000") {
		t.Fatalf("mesh gateway target missing:\n%s", rendered.TOML)
	}
}

func managedMeshTargetConfig(t *testing.T, host string) Config {
	t.Helper()
	cfg := testConfig(t)
	cfg.Profile.Server.Kind = "managed"
	cfg.Profile.Server.ServerID = "frps-policy"
	cfg.Profile.Rules[0] = Rule{
		ID: "rule-mesh-policy", Name: "Mesh policy target", Type: "tcp", Enabled: true,
		Target: Target{
			Kind: "mesh_peer", Host: host, Port: 22, NetworkID: "net-a", DeviceID: "dev-b",
			PublicKey: base64.StdEncoding.EncodeToString(make([]byte, 32)), ServiceID: "svc-mesh-policy",
		},
		Exposure: Exposure{RemotePort: 30001},
	}
	return cfg
}

func TestReservedTargetPolicyRejectsMetadataAndManagementEndpoints(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Config)
	}{
		{"LAN cloud metadata", func(cfg *Config) {
			cfg.Profile.Rules[0].Target = Target{Kind: "lan", Host: "169.254.169.254", Port: 80}
		}},
		{"LAN container metadata", func(cfg *Config) {
			cfg.Profile.Rules[0].Target = Target{Kind: "lan", Host: "169.254.170.2", Port: 80}
		}},
		{"Mesh cloud metadata inside TLAN pool", func(cfg *Config) {
			cfg.Profile.Server.Kind = "managed"
			cfg.Profile.Server.ServerID = "frps-policy"
			cfg.Profile.Rules[0].Type = "tcp"
			cfg.Profile.Rules[0].Target = Target{
				Kind: "mesh_peer", Host: "100.100.100.200", Port: 80, NetworkID: "net-a", DeviceID: "dev-b", ServiceID: "svc-metadata",
			}
			cfg.Profile.Rules[0].Exposure = Exposure{RemotePort: 30001}
		}},
		{"FRP plugin port", func(cfg *Config) {
			cfg.Profile.Rules[0].Target = Target{Kind: "loopback", Host: "127.0.0.1", Port: 9093}
		}},
		{"FRPS dashboard port", func(cfg *Config) {
			cfg.Profile.Rules[0].Target = Target{Kind: "loopback", Host: "127.0.0.1", Port: 7500}
		}},
		{"visitor management port", func(cfg *Config) {
			cfg.Profile.Visitors = []Visitor{{
				ID: "visitor-reserved", Name: "Reserved visitor", Type: "stcp", Enabled: true,
				ServerName: "remote-private", SecretRef: "visitor-secret", BindAddr: "127.0.0.1", BindPort: 7500,
			}}
		}},
		{"local FRPS vhost port", func(cfg *Config) {
			cfg.Profile.Rules[0].Target = Target{Kind: "loopback", Host: "127.0.0.1", Port: DefaultHTTPPort}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig(t)
			tc.mutate(&cfg)
			if err := ValidateConfig(cfg); err == nil || !IsReservedTargetError(err) {
				t.Fatalf("reserved target error = %v", err)
			}
		})
	}
}

func TestOrdinaryLoopbackBusinessTargetRemainsAllowed(t *testing.T) {
	cfg := testConfig(t)
	cfg.Profile.Rules[0].Target = Target{Kind: "loopback", Host: "127.0.0.1", Port: 8080}
	if err := ValidateConfig(cfg); err != nil {
		t.Fatalf("ordinary loopback business target rejected: %v", err)
	}
}

func TestTargetReservationsCoverDynamicManagementPorts(t *testing.T) {
	cfg := testConfig(t)
	cfg.Profile.Rules[0].Target = Target{Kind: "loopback", Host: "127.0.0.1", Port: 8080}
	if err := ValidateConfig(cfg); err != nil {
		t.Fatalf("ordinary loopback target rejected before reservation: %v", err)
	}
	dynamic := []TargetReservation{{Host: "127.0.0.1", Port: 8080, Purpose: "TLAN control API"}}
	if err := ValidateConfigWithReservations(cfg, dynamic); err == nil || !IsReservedTargetError(err) {
		t.Fatalf("dynamic management target error = %v", err)
	}

	cfg.Profile.Rules[0].Target = Target{Kind: "loopback", Host: "127.0.0.1", Port: 7777}
	cfg.Profile.Visitors = []Visitor{{
		ID: "visitor-dynamic", Name: "Dynamic visitor", Type: "stcp", Enabled: true,
		ServerName: "remote-private", SecretRef: "visitor-secret", BindAddr: "127.0.0.1", BindPort: 8080,
	}}
	if err := ValidateConfig(cfg); err != nil {
		t.Fatalf("valid independent visitor rejected: %v", err)
	}
	if err := ValidateConfigWithReservations(cfg, dynamic); err == nil || !IsReservedTargetError(err) {
		t.Fatalf("dynamic visitor reservation error = %v", err)
	}
}

func TestReservedTargetPolicyIsReusedBySaveStartAndApplyValidation(t *testing.T) {
	cfg := testConfig(t)
	cfg.Profile.Rules[0].Target = Target{Kind: "lan", Host: "169.254.169.254", Port: 80}

	if err := ValidateConfig(cfg); err == nil || !IsReservedTargetError(err) {
		t.Fatalf("base/Apply validation error = %v", err)
	}
	if err := ValidateRunInputs(cfg, "server-token"); err == nil || !IsReservedTargetError(err) {
		t.Fatalf("Start validation error = %v", err)
	}
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.Save(cfg, "server-token"); err == nil || !IsReservedTargetError(err) {
		t.Fatalf("Save validation error = %v", err)
	}
	if _, err = store.Load(); !errors.Is(err, ErrNoConfig) {
		t.Fatalf("rejected Save persisted a profile: %v", err)
	}
	if _, err = RenderConfig(RenderInput{
		Config: cfg, DeviceID: "device-1", TokenPath: cfg.Profile.Server.TrustedCAPath,
		AdminPort: 17401, AdminUser: DefaultAdminUser, AdminPassword: strings.Repeat("a", 64),
	}); err == nil || !IsReservedTargetError(err) {
		t.Fatalf("runtime render validation error = %v", err)
	}
}

func TestMeshTargetsSupportBothTLANPools(t *testing.T) {
	for _, host := range []string{"10.0.0.1", "10.255.255.254", "100.64.0.1", "100.127.255.254"} {
		t.Run("valid-"+strings.ReplaceAll(host, ".", "-"), func(t *testing.T) {
			if err := ValidateConfig(managedMeshTargetConfig(t, host)); err != nil {
				t.Fatalf("TLAN pool target %s rejected: %v", host, err)
			}
		})
	}
	for _, host := range []string{"9.255.255.255", "11.0.0.1", "100.63.255.255", "100.128.0.1", "172.16.0.2", "192.168.1.2"} {
		t.Run("invalid-"+strings.ReplaceAll(host, ".", "-"), func(t *testing.T) {
			if err := ValidateConfig(managedMeshTargetConfig(t, host)); err == nil {
				t.Fatalf("out-of-pool Mesh target %s accepted", host)
			}
		})
	}
}

func TestValidateMeshTargetPolicyUsesMembershipAndActivePrefix(t *testing.T) {
	cfg := managedMeshTargetConfig(t, "100.64.0.2")
	prefix := netip.MustParsePrefix("100.64.0.0/24")
	if err := ValidateMeshTargetPolicy(cfg, "net-a", "dev-a", prefix); err != nil {
		t.Fatalf("valid CGNAT Mesh member rejected: %v", err)
	}

	self := managedMeshTargetConfig(t, "10.240.0.2")
	self.Profile.Rules[0].Target.Kind = "mesh_self"
	self.Profile.Rules[0].Target.DeviceID = "dev-a"
	self.Profile.Rules[0].Target.ServiceID = ""
	if err := ValidateMeshTargetPolicy(self, "net-a", "dev-a", netip.MustParsePrefix("10.240.0.0/24")); err != nil {
		t.Fatalf("valid mesh_self target rejected: %v", err)
	}

	cases := []struct {
		name      string
		cfg       Config
		networkID string
		deviceID  string
		prefix    netip.Prefix
	}{
		{"wrong network", managedMeshTargetConfig(t, "100.64.0.2"), "net-b", "dev-a", prefix},
		{"peer is local device", managedMeshTargetConfig(t, "100.64.0.2"), "net-a", "dev-b", prefix},
		{"address outside active prefix", managedMeshTargetConfig(t, "100.64.1.2"), "net-a", "dev-a", prefix},
		{"network address", managedMeshTargetConfig(t, "100.64.0.0"), "net-a", "dev-a", prefix},
		{"broadcast address", managedMeshTargetConfig(t, "100.64.0.255"), "net-a", "dev-a", prefix},
		{"prefix outside TLAN pools", managedMeshTargetConfig(t, "192.168.1.2"), "net-a", "dev-a", netip.MustParsePrefix("192.168.1.0/24")},
		{"prefix straddles TLAN pool", managedMeshTargetConfig(t, "100.64.0.2"), "net-a", "dev-a", netip.MustParsePrefix("100.64.0.0/9")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateMeshTargetPolicy(tc.cfg, tc.networkID, tc.deviceID, tc.prefix); err == nil {
				t.Fatal("invalid Mesh membership scope accepted")
			}
		})
	}

	wrongSelf := managedMeshTargetConfig(t, "100.64.0.2")
	wrongSelf.Profile.Rules[0].Target.Kind = "mesh_self"
	wrongSelf.Profile.Rules[0].Target.DeviceID = "dev-b"
	if err := ValidateMeshTargetPolicy(wrongSelf, "net-a", "dev-a", prefix); err == nil {
		t.Fatal("mesh_self targeting another device accepted")
	}
}

func TestMeshProfileRejectsIndependentVisitor(t *testing.T) {
	cfg := managedMeshTargetConfig(t, "100.64.0.2")
	cfg.Profile.Visitors = []Visitor{{
		ID: "visitor-independent", Name: "Independent visitor", Type: "stcp", Enabled: true,
		ServerName: "remote-independent", SecretRef: "visitor-secret", BindAddr: "127.0.0.1", BindPort: 19000,
	}}
	err := ValidateConfig(cfg)
	if err == nil || !IsDependencyIsolationError(err) {
		t.Fatalf("Mesh/visitor dependency isolation error = %v", err)
	}
	if !strings.Contains(err.Error(), "separate profiles") || !strings.Contains(err.Error(), "visitor") {
		t.Fatalf("dependency isolation message is not actionable: %v", err)
	}

	independent := testConfig(t)
	independent.Profile.Visitors = cfg.Profile.Visitors
	if err := ValidateConfig(independent); err != nil {
		t.Fatalf("independent visitor profile rejected: %v", err)
	}
}

func TestLegacyMeshPeerWithoutServiceIDFailsClosed(t *testing.T) {
	cfg := managedMeshTargetConfig(t, "10.240.0.5")
	cfg.SchemaVersion = LegacySchema
	cfg.Profile.Rules[0].Target.ServiceID = ""
	normalized := NormalizeConfig(cfg)
	if normalized.Profile.Rules[0].Target.ServiceID != "" {
		t.Fatal("legacy migration invented a service ID")
	}
	if err := ValidateConfig(normalized); err == nil {
		t.Fatal("legacy mesh_peer without service ID passed validation")
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = DecodeConfig(strings.NewReader(string(data))); err == nil {
		t.Fatal("legacy persisted mesh_peer without service ID was accepted")
	}
}
