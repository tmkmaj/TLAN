//go:build windows

package main

import (
	"errors"
	"testing"
)

type fakeStartupStore struct {
	values    map[string]string
	setErr    error
	deleteErr error
	closed    bool
}

func (s *fakeStartupStore) SetStringValue(name, value string) error {
	if s.setErr != nil {
		return s.setErr
	}
	if s.values == nil {
		s.values = make(map[string]string)
	}
	s.values[name] = value
	return nil
}

func (s *fakeStartupStore) DeleteValue(name string) error {
	if s.deleteErr != nil {
		return s.deleteErr
	}
	delete(s.values, name)
	return nil
}

func (s *fakeStartupStore) Close() error {
	s.closed = true
	return nil
}

func TestStartupCommandQuotesExecutablePath(t *testing.T) {
	got, err := startupCommand(`C:\Program Files\Tmk Network\TmkNetworkLAN.exe`)
	if err != nil {
		t.Fatal(err)
	}
	want := `"C:\Program Files\Tmk Network\TmkNetworkLAN.exe" --startup`
	if got != want {
		t.Fatalf("startup command = %q, want %q", got, want)
	}
}

func TestStartupCommandRejectsUnsafePaths(t *testing.T) {
	for _, path := range []string{"", `relative\client.exe`, `C:\bad"path\client.exe`, "C:\\bad\x00path.exe"} {
		if _, err := startupCommand(path); err == nil {
			t.Fatalf("unsafe startup path %q was accepted", path)
		}
	}
}

func TestStartupRegistrationOnlyTouchesOwnValue(t *testing.T) {
	store := &fakeStartupStore{values: map[string]string{"OtherApp": `"C:\Other\Other.exe"`}}
	if err := configureStartupRegistration(store, `C:\Apps\TmkNetworkLAN.exe`, true); err != nil {
		t.Fatal(err)
	}
	if got, want := store.values[startupValueName], `"C:\Apps\TmkNetworkLAN.exe" --startup`; got != want {
		t.Fatalf("own startup value = %q, want %q", got, want)
	}
	if store.values["OtherApp"] != `"C:\Other\Other.exe"` {
		t.Fatal("enabling startup changed another application's value")
	}
	if err := configureStartupRegistration(store, "", false); err != nil {
		t.Fatal(err)
	}
	if _, ok := store.values[startupValueName]; ok {
		t.Fatal("disabling startup did not remove the owned value")
	}
	if store.values["OtherApp"] != `"C:\Other\Other.exe"` {
		t.Fatal("disabling startup changed another application's value")
	}
}

func TestStartupRegistrationPropagatesSetFailure(t *testing.T) {
	want := errors.New("registry denied")
	store := &fakeStartupStore{setErr: want}
	if err := configureStartupRegistration(store, `C:\Apps\TmkNetworkLAN.exe`, true); !errors.Is(err, want) {
		t.Fatalf("startup set error = %v, want %v", err, want)
	}
}
