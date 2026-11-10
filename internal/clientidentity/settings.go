package clientidentity

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

type Settings struct {
	ServerURL     string `json:"server_url"`
	Token         string `json:"token"`
	AdminToken    string `json:"admin_token,omitempty"`
	STUNServer    string `json:"stun_server,omitempty"`
	RelayOnly     bool   `json:"relay_only"`
	NetworkID     string `json:"network_id,omitempty"`
	DeviceName    string `json:"device_name,omitempty"`
	NetworkName   string `json:"network_name,omitempty"`
	NetworkCIDR   string `json:"network_cidr,omitempty"`
	VirtualIP     string `json:"virtual_ip,omitempty"`
	CloseToTray   bool   `json:"close_to_tray,omitempty"`
	LaunchAtLogin bool   `json:"launch_at_login,omitempty"`
}

func settingsPath() (string, error) {
	directory, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("locate client settings directory: %w", err)
	}
	dir, err := configDirectory(directory)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "settings.json"), nil
}
func LoadSettings() (Settings, error) {
	path, err := settingsPath()
	if err != nil {
		return Settings{}, err
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Settings{}, nil
	}
	if err != nil {
		return Settings{}, err
	}
	var settings Settings
	if err = json.Unmarshal(data, &settings); err != nil {
		return settings, err
	}
	settings.Token, err = UnprotectSecret(settings.Token)
	if err != nil {
		return settings, err
	}
	settings.AdminToken, err = UnprotectSecret(settings.AdminToken)
	return settings, err
}
func SaveSettings(settings Settings) error {
	path, err := settingsPath()
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	settings.Token, err = ProtectSecret(settings.Token)
	if err != nil {
		return err
	}
	settings.AdminToken, err = ProtectSecret(settings.AdminToken)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}
