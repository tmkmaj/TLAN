//go:build windows

package clientidentity

import "testing"

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
