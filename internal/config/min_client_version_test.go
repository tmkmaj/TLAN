package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadFileCarriesMinClientVersion(t *testing.T) {
	const document = `network:
  name: "gate"
  cidr: "10.240.0.0/24"
  join_code: "test-join-code"
server:
  listen: "127.0.0.1:8080"
  stun_listen: ":3478"
  min_client_version: "v0.7.0"
storage:
  data_dir: "./data"
security:
  admin_token: "test-admin-token"
frp:
  mode: "disabled"
  core_version: "0.71.1"
`
	path := filepath.Join(t.TempDir(), FileName)
	if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server.MinClientVersion != "v0.7.0" {
		t.Fatalf("min_client_version = %q", cfg.Server.MinClientVersion)
	}

	// The strict loader rejects a beta in the release gate, so an operator
	// cannot accidentally configure a gate that half-applies to the beta
	// channel.
	beta := strings.Replace(document, `"v0.7.0"`, `"v0.7.0-beta.1"`, 1)
	if err := os.WriteFile(path, []byte(beta), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(path); err == nil {
		t.Fatal("LoadFile accepted a beta min_client_version")
	}
}

func TestValidateMinClientVersion(t *testing.T) {
	for _, ok := range []string{"", "   ", "v0.7.0", "0.7.0"} {
		if err := validateMinClientVersion(ok); err != nil {
			t.Fatalf("validateMinClientVersion(%q) = %v, want nil", ok, err)
		}
	}
	// Beta and malformed values are rejected so the release gate can never be
	// configured to half-apply to the beta channel.
	for _, bad := range []string{"0.7", "latest", "v0.7.0-beta.1", "v0.7.0-rc.1", "v0.7.0+build.5", "1.2.3.4"} {
		if err := validateMinClientVersion(bad); err == nil {
			t.Fatalf("validateMinClientVersion(%q) accepted", bad)
		}
	}
}
