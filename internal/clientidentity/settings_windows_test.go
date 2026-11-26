//go:build windows

package clientidentity

import (
	"bytes"
	"os"
	"testing"
)

func TestSaveSettingsPersistsResidentPreferences(t *testing.T) {
	t.Setenv("AppData", t.TempDir())
	want := Settings{ServerURL: "https://example.test", CloseToTray: true, LaunchAtLogin: true}
	if err := SaveSettings(want); err != nil {
		t.Fatal(err)
	}
	got, err := LoadSettings()
	if err != nil {
		t.Fatal(err)
	}
	if !got.CloseToTray || !got.LaunchAtLogin {
		t.Fatalf("resident preferences were not persisted: %+v", got)
	}
}

func TestSaveSettingsProtectsAdminToken(t *testing.T) {
	t.Setenv("AppData", t.TempDir())
	want := Settings{ServerURL: "https://example.test", Token: "member_test", AdminToken: "test-admin-token"}
	if err := SaveSettings(want); err != nil {
		t.Fatal(err)
	}
	got, err := LoadSettings()
	if err != nil {
		t.Fatal(err)
	}
	if got.Token != want.Token || got.AdminToken != want.AdminToken {
		t.Fatalf("credentials were not round-tripped: %+v", got)
	}
	path, err := settingsPath()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("test-admin-token")) {
		t.Fatal("admin token was persisted as plaintext")
	}
}
