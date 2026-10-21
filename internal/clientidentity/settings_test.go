package clientidentity

import (
	"encoding/json"
	"testing"
)

func TestSettingsResidentPreferencesBackwardCompatible(t *testing.T) {
	var settings Settings
	if err := json.Unmarshal([]byte(`{"server_url":"https://example.test","token":"legacy","relay_only":true}`), &settings); err != nil {
		t.Fatal(err)
	}
	if settings.CloseToTray || settings.LaunchAtLogin {
		t.Fatalf("new resident settings must default to false for old files: %+v", settings)
	}
}

func TestSettingsResidentPreferencesRoundTrip(t *testing.T) {
	encoded, err := json.Marshal(Settings{CloseToTray: true, LaunchAtLogin: true})
	if err != nil {
		t.Fatal(err)
	}
	var decoded Settings
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if !decoded.CloseToTray || !decoded.LaunchAtLogin {
		t.Fatalf("resident preferences were not preserved: %+v", decoded)
	}
}
