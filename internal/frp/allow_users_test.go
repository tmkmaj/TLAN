package frp

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestAllowUsersNormalizeValidateAndRender(t *testing.T) {
	cfg := testConfig(t)
	cfg.Profile.Rules[0].Type = "stcp"
	cfg.Profile.Rules[0].SecretRef = "private-secret"
	cfg.Profile.Rules[0].Exposure = Exposure{AllowUsers: []string{" peer-b ", "peer-a", "peer-a"}}
	cfg = NormalizeConfig(cfg)
	if got, want := strings.Join(cfg.Profile.Rules[0].Exposure.AllowUsers, ","), "peer-a,peer-b"; got != want {
		t.Fatalf("normalized allowUsers = %q, want %q", got, want)
	}
	if err := ValidateConfig(cfg); err != nil {
		t.Fatalf("valid allowUsers config rejected: %v", err)
	}
	data, err := EncodeConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeConfig(strings.NewReader(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(decoded.Profile.Rules[0].Exposure.AllowUsers, ",") != "peer-a,peer-b" {
		t.Fatalf("round-tripped allowUsers = %#v", decoded.Profile.Rules[0].Exposure.AllowUsers)
	}
	rendered, err := RenderConfig(RenderInput{
		Config: cfg, DeviceID: "device-1",
		TokenPath: filepath.Join(t.TempDir(), "token"),
		AdminPort: 17401, AdminUser: "tlan-manager", AdminPassword: strings.Repeat("a", 64),
		Secrets: map[string]string{"private-secret": strings.Repeat("b", 32)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rendered.TOML, "allowUsers = [\"peer-a\", \"peer-b\"]") {
		t.Fatalf("rendered TOML does not contain allowUsers: %s", rendered.TOML)
	}
}

func TestAllowUsersRejectedOnPublicProxyTypes(t *testing.T) {
	cfg := testConfig(t)
	cfg.Profile.Rules[0].Exposure.AllowUsers = []string{"peer-a"}
	if err := ValidateConfig(cfg); err == nil {
		t.Fatal("allowUsers accepted on UDP proxy")
	}
}

func TestAllowUsersRejectsInvalidEntry(t *testing.T) {
	cfg := testConfig(t)
	cfg.Profile.Rules[0].Type = "sudp"
	cfg.Profile.Rules[0].SecretRef = "private-secret"
	cfg.Profile.Rules[0].Exposure = Exposure{AllowUsers: []string{"bad user"}}
	if err := ValidateConfig(cfg); err == nil {
		t.Fatal("invalid allowUsers entry accepted")
	}
}
