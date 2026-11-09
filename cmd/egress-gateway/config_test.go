package main

import (
	"os"
	"path/filepath"
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
