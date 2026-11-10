package config

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestLoadOrCreateGeneratesOnceThenLoads(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	first, created, err := LoadOrCreate(path)
	if err != nil {
		t.Fatal(err)
	}
	if !created {
		t.Fatal("first call did not report a newly generated configuration")
	}
	if first.Security.AdminToken != "Tmkmaj233" || first.Network.JoinCode != "TmkNetwork" || first.Server.AdminListen != "127.0.0.1:8081" {
		t.Fatalf("generated tokens/admin listener = %q/%q/%q", first.Security.AdminToken, first.Network.JoinCode, first.Server.AdminListen)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("generated configuration mode = %o, want 600", info.Mode().Perm())
	}

	second, created, err := LoadOrCreate(path)
	if err != nil {
		t.Fatal(err)
	}
	if created {
		t.Fatal("second call unexpectedly replaced the configuration")
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatal("configuration changed between first and second load")
	}
}

func TestLoadOrCreatePreservesExistingConfiguration(t *testing.T) {
	cfg, err := newDefault()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Network.Name = "Existing friends"
	path := writeConfig(t, cfg)

	loaded, created, err := LoadOrCreate(path)
	if err != nil {
		t.Fatal(err)
	}
	if created {
		t.Fatal("existing configuration was reported as newly created")
	}
	if !reflect.DeepEqual(loaded, cfg) {
		t.Fatalf("loaded configuration = %#v, want %#v", loaded, cfg)
	}
}

func TestLoadOrCreateDoesNotReplaceInvalidConfiguration(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	invalid := []byte("network: [\n")
	if err := os.WriteFile(path, invalid, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, created, err := LoadOrCreate(path); err == nil || created {
		t.Fatalf("LoadOrCreate returned created=%v, err=%v for invalid configuration", created, err)
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(contents) != string(invalid) {
		t.Fatal("invalid configuration was overwritten")
	}
}

func TestFirstRunPreservesLegacyStateInWorkingDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "state.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, created, err := LoadOrCreate(filepath.Join(dir, FileName))
	if err != nil {
		t.Fatal(err)
	}
	if !created {
		t.Fatal("expected a generated configuration")
	}
	if cfg.Storage.DataDir != "." {
		t.Fatalf("storage.data_dir = %q, want %q to preserve existing state", cfg.Storage.DataDir, ".")
	}
}

func TestLoadFileRejectsUnknownFields(t *testing.T) {
	cfg, err := newDefault()
	if err != nil {
		t.Fatal(err)
	}
	path := writeConfig(t, cfg)
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("\nunexpected_setting: true\n"); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(path); err == nil || !strings.Contains(err.Error(), "unexpected_setting") {
		t.Fatalf("unknown field error = %v", err)
	}
}

func TestValidationErrorsAreActionable(t *testing.T) {
	cases := []struct {
		name   string
		change func(*Config)
		want   string
	}{
		{"short admin token", func(c *Config) { c.Security.AdminToken = "short" }, "security.admin_token"},
		{"unpaired admin TLS", func(c *Config) { c.Server.AdminTLSCert = "admin.crt" }, "server.admin_tls_cert"},
		{"short join code", func(c *Config) { c.Network.JoinCode = "short" }, "network.join_code"},
		{"invalid listener", func(c *Config) { c.Server.Listen = "8080" }, "server.listen"},
		{"unpaired TLS", func(c *Config) { c.Server.TLSCert = "server.crt" }, "server.tls_cert"},
		{"unpaired relay TLS", func(c *Config) { c.Server.RelayCert = "relay.crt" }, "server.relay_cert"},
		{"public CIDR", func(c *Config) { c.Network.CIDR = "192.168.1.0/24" }, "network.cidr"},
		{"empty data directory", func(c *Config) { c.Storage.DataDir = " " }, "storage.data_dir"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := newDefault()
			if err != nil {
				t.Fatal(err)
			}
			tc.change(&cfg)
			err = cfg.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate() error = %v, want text %q", err, tc.want)
			}
		})
	}
}

func TestGeneratedTokensUseRequestedStableDefaults(t *testing.T) {
	first, err := newDefault()
	if err != nil {
		t.Fatal(err)
	}
	second, err := newDefault()
	if err != nil {
		t.Fatal(err)
	}
	if first.Security.AdminToken != "Tmkmaj233" || second.Security.AdminToken != "Tmkmaj233" {
		t.Fatalf("admin tokens = %q/%q", first.Security.AdminToken, second.Security.AdminToken)
	}
	if first.Network.JoinCode != "TmkNetwork" || second.Network.JoinCode != "TmkNetwork" {
		t.Fatalf("join codes = %q/%q", first.Network.JoinCode, second.Network.JoinCode)
	}
}

func TestAdminListenerAndTLSValidation(t *testing.T) {
	cfg, err := newDefault()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Server.AdminListen = "10.0.0.10:8081"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("admin listener rejected: %v", err)
	}
	cfg.Server.AdminTLSCert = "admin.crt"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "server.admin_tls_cert") {
		t.Fatalf("unpaired admin TLS error = %v", err)
	}
}
func TestFRPManagedConfigurationValidation(t *testing.T) {
	cfg, err := newDefault()
	if err != nil {
		t.Fatal(err)
	}
	cfg.FRP = FRPConfig{
		Mode:                "managed",
		CoreVersion:         "0.71.1",
		ServerID:            "frps-managed-1",
		PluginListen:        "127.0.0.1:9093",
		LeaseTTLSeconds:     900,
		LeaseStateFile:      "./data/frp-leases.json",
		MaxRulesPerLease:    16,
		MaxLeasesPerDevice:  4,
		MaxPortsPerDevice:   16,
		MaxDomainsPerDevice: 16,
		MaxDomainsPerRule:   16,
		AllowedPorts:        FRPPortList("30000-30099"),
		AllowedDomains:      FRPDomainList("frp.example.com"),
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("managed FRP config rejected: %v", err)
	}
	if got := cfg.FRPLeaseStateFile(); got != "./data/frp-leases.json" {
		t.Fatalf("lease state path = %q", got)
	}
	cfg.FRP.LeaseStateFile = "./data/state.json"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "storage.state_file") {
		t.Fatalf("shared lease/member state error = %v", err)
	}
	cfg.FRP.LeaseStateFile = "./data/frp-leases.json"
	cfg.FRP.PluginListen = "0.0.0.0:9093"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("public plugin listener error = %v", err)
	}
}

func TestFRPModeSeparationAndDefaults(t *testing.T) {
	cfg, err := newDefault()
	if err != nil {
		t.Fatal(err)
	}
	cfg.FRP = FRPConfig{Mode: "external"}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("external shared-token mode rejected: %v", err)
	}
	cfg.FRP.PluginListen = "127.0.0.1:9093"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "managed authorization fields") {
		t.Fatalf("external mode accepted managed fields: %v", err)
	}
	cfg.FRP = FRPConfig{Mode: "managed", ServerID: "frps-managed-1", PluginListen: "127.0.0.1:9093"}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("managed defaults rejected: %v", err)
	}
	if cfg.FRP.EffectiveLeaseTTLSeconds() != 900 || cfg.FRP.EffectiveCoreVersion() != "0.71.1" {
		t.Fatalf("FRP defaults were not applied")
	}
	if got := cfg.FRPLeaseStateFile(); got != filepath.Join("./data", "frp-leases.json") {
		t.Fatalf("default lease state path = %q", got)
	}
}

func TestFRPYAMLListRoundTrip(t *testing.T) {
	cfg, err := newDefault()
	if err != nil {
		t.Fatal(err)
	}
	cfg.FRP = FRPConfig{
		Mode:           "managed",
		CoreVersion:    "0.71.1",
		ServerID:       "frps-managed-1",
		PluginListen:   "127.0.0.1:9093",
		AllowedPorts:   FRPPortList("30000-30099,30100-30109"),
		AllowedDomains: FRPDomainList("frp.example.com,example.net"),
	}
	path := writeConfig(t, cfg)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "allowed_ports:") || !strings.Contains(string(raw), "allowed_domains:") {
		t.Fatalf("managed FRP YAML missing list fields:\n%s", raw)
	}
	loaded, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	ports, _ := loaded.FRP.AllowedPorts.Ranges()
	if len(ports) != 2 || ports[0].Start != 30000 || ports[1].Start != 30100 {
		t.Fatalf("round-trip ports = %+v", ports)
	}
	domains, _ := loaded.FRP.AllowedDomains.Domains()
	if len(domains) != 2 || domains[0] != "example.net" || domains[1] != "frp.example.com" {
		t.Fatalf("round-trip domains = %+v", domains)
	}
}

func writeConfig(t *testing.T, cfg Config) string {
	t.Helper()
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), FileName)
	if err := writeNew(path, cfg); err != nil {
		t.Fatal(err)
	}
	return path
}
