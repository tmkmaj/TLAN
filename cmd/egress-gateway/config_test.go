package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestLoadConfigStrictness(t *testing.T) {
	materials := writeTestMaterials(t)
	configPath := writeTestConfig(t, materials)

	if _, err := loadConfig(configPath); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}

	t.Run("top-level unknown field", func(t *testing.T) {
		data, err := os.ReadFile(configPath)
		if err != nil {
			t.Fatal(err)
		}
		data = append(data, []byte("\nunknown_field: true\n")...)
		path := filepath.Join(materials.dir, "unknown-top.yml")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadConfig(path); err == nil || !strings.Contains(strings.ToLower(err.Error()), "field") {
			t.Fatalf("unknown top-level field error = %v", err)
		}
	})

	t.Run("nested unknown field", func(t *testing.T) {
		data, err := os.ReadFile(configPath)
		if err != nil {
			t.Fatal(err)
		}
		data = []byte(strings.Replace(string(data), "  deny_metadata: true\n", "  deny_metadata: true\n  unknown_policy_field: true\n", 1))
		path := filepath.Join(materials.dir, "unknown-nested.yml")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadConfig(path); err == nil || !strings.Contains(strings.ToLower(err.Error()), "field") {
			t.Fatalf("unknown nested field error = %v", err)
		}
	})
}

func TestConfigRejectsUnknownPolicyValues(t *testing.T) {
	materials := writeTestMaterials(t)
	basePath := writeTestConfig(t, materials)
	base, err := os.ReadFile(basePath)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name        string
		old         string
		replacement string
	}{
		{name: "ipv6", old: `ipv6_policy: "block"`, replacement: `ipv6_policy: "proxy"`},
		{name: "dns", old: `dns_policy: "remote"`, replacement: `dns_policy: "local"`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data := strings.Replace(string(base), test.old, test.replacement, 1)
			path := filepath.Join(materials.dir, "unknown-policy-"+test.name+".yml")
			if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := loadConfig(path); err == nil {
				t.Fatal("unknown policy value was accepted")
			}
		})
	}
}

func TestConfigRejectsUnsupportedIPForwardDisable(t *testing.T) {
	materials := writeTestMaterials(t)
	basePath := writeTestConfig(t, materials)
	data, err := os.ReadFile(basePath)
	if err != nil {
		t.Fatal(err)
	}
	data = []byte(strings.Replace(string(data), "enable_ip_forward: true", "enable_ip_forward: false", 1))
	path := filepath.Join(materials.dir, "forward-disabled.yml")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(path); err == nil || !strings.Contains(err.Error(), "enable_ip_forward") {
		t.Fatalf("disabled forwarding error = %v", err)
	}
}

func TestExampleConfigLoads(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "deploy", "egress", "egress-gateway.yaml.example"))
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	if runtime.GOOS == "windows" {
		root := filepath.ToSlash(t.TempDir())
		content = strings.ReplaceAll(content, "/var/lib/tlan-egress", root+"/state")
		content = strings.ReplaceAll(content, "/etc/tlan-egress/", root+"/etc/")
	}
	path := filepath.Join(t.TempDir(), "egress-gateway.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("example config rejected: %v", err)
	}
	if cfg.Egress.Interface == "" || cfg.Limits.MaxSessions == 0 || len(cfg.Policy.AllowCIDRs) == 0 {
		t.Fatal("example config did not populate required gateway fields")
	}
}

func TestConfigRejectsHardDenyOverrides(t *testing.T) {
	materials := writeTestMaterials(t)
	basePath := writeTestConfig(t, materials)
	base, err := os.ReadFile(basePath)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		old  string
		repl string
	}{
		{name: "private", old: "deny_private: true", repl: "deny_private: false"},
		{name: "metadata", old: "deny_metadata: true", repl: "deny_metadata: false"},
	} {
		t.Run(test.name, func(t *testing.T) {
			data := strings.Replace(string(base), test.old, test.repl, 1)
			path := filepath.Join(materials.dir, "hard-deny-"+test.name+".yml")
			if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := loadConfig(path); err == nil {
				t.Fatal("hard-deny override was accepted")
			}
		})
	}
}

func TestConfigRejectsIPv6AllowPublic(t *testing.T) {
	materials := writeTestMaterials(t)
	basePath := writeTestConfig(t, materials)
	data, err := os.ReadFile(basePath)
	if err != nil {
		t.Fatal(err)
	}
	data = []byte(strings.Replace(string(data), `ipv6_policy: "block"`, `ipv6_policy: "allow_public"`, 1))
	path := filepath.Join(materials.dir, "ipv6-allow-public.yml")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(path); err == nil || !strings.Contains(err.Error(), "ipv6_policy") {
		t.Fatalf("allow_public error = %v", err)
	}
}
