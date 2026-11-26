//go:build windows

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/registry"
)

const (
	startupRunKeyPath = `Software\Microsoft\Windows\CurrentVersion\Run`
	startupValueName  = "TLAN"
	startupArgument   = "--startup"
)

// startupStore is deliberately small so registration logic can be exercised
// against an isolated fake instead of the real user's Run key.
type startupStore interface {
	SetStringValue(name, value string) error
	DeleteValue(name string) error
	Close() error
}

type registryStartupStore struct {
	key registry.Key
}

func (s registryStartupStore) SetStringValue(name, value string) error {
	return s.key.SetStringValue(name, value)
}

func (s registryStartupStore) DeleteValue(name string) error {
	return s.key.DeleteValue(name)
}

func (s registryStartupStore) Close() error {
	return s.key.Close()
}

func openStartupStore(create bool) (startupStore, error) {
	if create {
		key, _, err := registry.CreateKey(registry.CURRENT_USER, startupRunKeyPath, registry.QUERY_VALUE|registry.SET_VALUE)
		if err != nil {
			return nil, err
		}
		return registryStartupStore{key: key}, nil
	}

	key, err := registry.OpenKey(registry.CURRENT_USER, startupRunKeyPath, registry.QUERY_VALUE|registry.SET_VALUE)
	if errors.Is(err, registry.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return registryStartupStore{key: key}, nil
}

func updateStartupRegistration(enabled bool) error {
	if !enabled {
		store, err := openStartupStore(false)
		if err != nil {
			return fmt.Errorf("open current-user startup key: %w", err)
		}
		if store == nil {
			return nil
		}
		defer store.Close()
		return configureStartupRegistration(store, "", false)
	}

	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate client executable: %w", err)
	}
	store, err := openStartupStore(true)
	if err != nil {
		return fmt.Errorf("open current-user startup key: %w", err)
	}
	defer store.Close()
	return configureStartupRegistration(store, executable, true)
}

func configureStartupRegistration(store startupStore, executable string, enabled bool) error {
	if store == nil {
		return errors.New("startup registry store is nil")
	}
	if !enabled {
		if err := store.DeleteValue(startupValueName); err != nil && !errors.Is(err, registry.ErrNotExist) {
			return err
		}
		return nil
	}

	command, err := startupCommand(executable)
	if err != nil {
		return err
	}
	return store.SetStringValue(startupValueName, command)
}

func startupCommand(executable string) (string, error) {
	if executable == "" || !filepath.IsAbs(executable) {
		return "", fmt.Errorf("client executable path must be absolute")
	}
	if strings.ContainsAny(executable, "\"\x00\r\n") {
		return "", fmt.Errorf("client executable path contains unsupported characters")
	}
	return `"` + filepath.Clean(executable) + `" ` + startupArgument, nil
}
