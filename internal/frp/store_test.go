package frp

import (
	"errors"
	"os"
	"strings"
	"testing"
)

func TestStoreRoundTripKeepsTokenOutOfProfile(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cfg := testConfig(t)
	saved, err := store.Save(cfg, "super-secret-token")
	if err != nil {
		t.Fatal(err)
	}
	if saved.Profile.Revision != 1 {
		t.Fatalf("revision = %d, want 1", saved.Profile.Revision)
	}
	if saved.Profile.Server.TrustedCAPath != store.CAFile() {
		t.Fatalf("CA path = %q, want managed copy %q", saved.Profile.Server.TrustedCAPath, store.CAFile())
	}
	profile, err := os.ReadFile(store.root + "/profiles.json")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(profile), "super-secret-token") {
		t.Fatal("profiles.json contains plaintext token")
	}
	secrets, err := os.ReadFile(store.root + "/secrets.json")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(secrets), "super-secret-token") {
		t.Fatal("secrets.json contains plaintext token")
	}
	token, err := store.Token(DefaultCredential)
	if err != nil || token != "super-secret-token" {
		t.Fatalf("token round-trip = %q, %v", token, err)
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Profile.Revision != saved.Profile.Revision || loaded.Profile.Rules[0].Name != "游戏服务" {
		t.Fatal("loaded profile does not match saved profile")
	}
}

func TestStoreRetainsTokenAndRejectsStaleRevision(t *testing.T) {
	store, _ := NewStore(t.TempDir())
	cfg := testConfig(t)
	saved, err := store.Save(cfg, "token-one")
	if err != nil {
		t.Fatal(err)
	}
	next := CloneConfig(saved)
	next.Profile.Rules[0].Name = "新名称"
	next, err = store.Save(next, "")
	if err != nil {
		t.Fatal(err)
	}
	if next.Profile.Revision != 2 {
		t.Fatalf("revision = %d, want 2", next.Profile.Revision)
	}
	if token, _ := store.Token(DefaultCredential); token != "token-one" {
		t.Fatalf("token was not retained: %q", token)
	}
	stale := CloneConfig(next)
	stale.Profile.Revision = saved.Profile.Revision
	if _, err = store.Save(stale, "token-two"); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("stale revision error = %v", err)
	}
}

func TestStoreRequiresToken(t *testing.T) {
	store, _ := NewStore(t.TempDir())
	_, err := store.Save(testConfig(t), "")
	if ErrorCode(err) != CodeAuthRejected {
		t.Fatalf("missing token error = %v", err)
	}
}

func TestStoreProtectsRuleSecrets(t *testing.T) {
	store, _ := NewStore(t.TempDir())
	cfg := testConfig(t)
	cfg.Profile.Rules[0].Type = "stcp"
	cfg.Profile.Rules[0].SecretRef = "rule-secret"
	cfg.Profile.Rules[0].Exposure = Exposure{}
	saved, err := store.SaveWithSecrets(cfg, "server-token", map[string]string{"rule-secret": "visitor-secret"})
	if err != nil {
		t.Fatal(err)
	}
	if value, err := store.Secret("rule-secret"); err != nil || value != "visitor-secret" {
		t.Fatalf("rule secret = %q, %v", value, err)
	}
	profile, _ := os.ReadFile(store.root + "/profiles.json")
	if strings.Contains(string(profile), "visitor-secret") {
		t.Fatal("rule secret leaked into profiles.json")
	}
	saved.Profile.Rules[0].Name = "Private renamed"
	if _, err = store.Save(saved, ""); err != nil {
		t.Fatalf("retain rule secret: %v", err)
	}
	if value, _ := store.Secret("rule-secret"); value != "visitor-secret" {
		t.Fatalf("retained rule secret = %q", value)
	}
}
