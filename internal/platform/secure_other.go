//go:build !windows

package platform

import (
	"fmt"
	"os"
)

func ensurePrivateDirectory(directory string) error {
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create resource ledger directory: %w", err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return fmt.Errorf("restrict resource ledger directory: %w", err)
	}
	return nil
}

func securePrivateFile(path string) error {
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("restrict resource ledger file: %w", err)
	}
	return nil
}
