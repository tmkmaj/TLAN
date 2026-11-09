package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
)

// readPrivateSecretFile reads one bounded owner-only secret. The file must be
// a regular file, not a symlink, and have platform-appropriate private access.
func readPrivateSecretFile(path string, maxBytes int) (string, error) {
	if path == "" {
		return "", errors.New("secret file path is required")
	}
	if maxBytes <= 0 {
		return "", errors.New("secret file size limit must be positive")
	}
	linkInfo, err := os.Lstat(path)
	if err != nil {
		return "", fmt.Errorf("stat secret file: %w", err)
	}
	if linkInfo.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("secret file must not be a symlink")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open secret file: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return "", fmt.Errorf("stat secret file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("secret file must be a regular file")
	}
	if err := checkPrivateFile(path, info); err != nil {
		return "", fmt.Errorf("secret file is not private: %w", err)
	}
	if info.Size() > int64(maxBytes)+2 {
		return "", fmt.Errorf("secret file exceeds %d bytes", maxBytes)
	}
	data, err := io.ReadAll(io.LimitReader(file, int64(maxBytes)+3))
	if err != nil {
		return "", fmt.Errorf("read secret file: %w", err)
	}
	data = bytes.TrimRight(data, "\r\n")
	if len(data) == 0 {
		return "", errors.New("secret file is empty")
	}
	if len(data) > maxBytes {
		return "", fmt.Errorf("secret file exceeds %d bytes", maxBytes)
	}
	return string(data), nil
}
