//go:build !windows

package frp

import (
	"os"
	"path/filepath"
)

func secureDirectory(path string) error { return os.Chmod(path, 0o700) }
func secureFile(path string) error      { return os.Chmod(path, 0o600) }
func currentUserSID() (string, error)   { return "local-user", nil }

func writePrivateFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := secureDirectory(dir); err != nil {
		return err
	}
	temp := path + ".tmp"
	_ = os.Remove(temp)
	if err := os.WriteFile(temp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(temp, path); err != nil {
		_ = os.Remove(temp)
		return err
	}
	return secureFile(path)
}
