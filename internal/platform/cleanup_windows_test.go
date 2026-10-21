//go:build windows

package platform

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
	"unicode/utf16"
)

type fakeWindowsRunner struct {
	scripts []string
	handle  func(string) ([]byte, error)
}

func (r *fakeWindowsRunner) Run(_ string, args ...string) ([]byte, error) {
	script := decodePowerShellCommand(args)
	r.scripts = append(r.scripts, script)
	if r.handle == nil {
		return nil, nil
	}
	return r.handle(script)
}

func decodePowerShellCommand(args []string) string {
	for i := 0; i+1 < len(args); i++ {
		if args[i] != "-EncodedCommand" {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(args[i+1])
		if err != nil || len(raw)%2 != 0 {
			return ""
		}
		units := make([]uint16, len(raw)/2)
		for j := range units {
			units[j] = binary.LittleEndian.Uint16(raw[j*2:])
		}
		return string(utf16.Decode(units))
	}
	return ""
}

func TestWindowsCleanupFirewallRequiresExactInstanceID(t *testing.T) {
	record := makeOwnedRecord(t, "instance", ResourceFirewallRule, "LANMesh-LANMesh", "10.44.0.0/24", "{11111111-1111-1111-1111-111111111111}", "{22222222-2222-2222-2222-222222222222}")
	runner := &fakeWindowsRunner{handle: func(script string) ([]byte, error) {
		switch {
		case strings.Contains(script, "Get-NetFirewallRule"):
			return []byte("{11111111-1111-1111-1111-111111111111}\r\n"), nil
		case strings.Contains(script, "Remove-NetFirewallRule"):
			return nil, nil
		default:
			t.Fatalf("unexpected script: %s", script)
			return nil, nil
		}
	}}
	if err := CleanupResourceWithRunner(record, runner); err != nil {
		t.Fatal(err)
	}
	if len(runner.scripts) != 2 || !strings.Contains(runner.scripts[1], "Remove-NetFirewallRule") {
		t.Fatalf("cleanup scripts = %#v", runner.scripts)
	}
	if strings.Contains(strings.Join(runner.scripts, "\n"), "*") {
		t.Fatal("cleanup used a wildcard")
	}
}

func TestWindowsCleanupFirewallRejectsIdentityMismatch(t *testing.T) {
	record := makeOwnedRecord(t, "instance", ResourceFirewallRule, "LANMesh-LANMesh", "10.44.0.0/24", "{11111111-1111-1111-1111-111111111111}", "{22222222-2222-2222-2222-222222222222}")
	runner := &fakeWindowsRunner{handle: func(script string) ([]byte, error) {
		if strings.Contains(script, "Get-NetFirewallRule") {
			return []byte("{33333333-3333-3333-3333-333333333333}\r\n"), nil
		}
		t.Fatalf("mismatched rule must not be removed: %s", script)
		return nil, nil
	}}
	if err := CleanupResourceWithRunner(record, runner); !errors.Is(err, ErrResourceNotOwned) {
		t.Fatalf("cleanup error = %v, want ErrResourceNotOwned", err)
	}
}

func TestWindowsCleanupAdapterRequiresExactGUID(t *testing.T) {
	record := makeOwnedRecord(t, "instance", ResourceWintunInterface, "LANMesh", "10.44.0.1/24", "{11111111-1111-1111-1111-111111111111}", "{11111111-1111-1111-1111-111111111111}")
	runner := &fakeWindowsRunner{handle: func(script string) ([]byte, error) {
		switch {
		case strings.Contains(script, "Get-NetAdapter"):
			return []byte("{11111111-1111-1111-1111-111111111111}\r\n"), nil
		case strings.Contains(script, "Remove-NetAdapter"):
			return nil, nil
		default:
			t.Fatalf("unexpected script: %s", script)
			return nil, nil
		}
	}}
	if err := CleanupResourceWithRunner(record, runner); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsCleanupAdapterMismatchDoesNotRemove(t *testing.T) {
	record := makeOwnedRecord(t, "instance", ResourceWintunInterface, "LANMesh", "10.44.0.1/24", "{11111111-1111-1111-1111-111111111111}", "{11111111-1111-1111-1111-111111111111}")
	runner := &fakeWindowsRunner{handle: func(script string) ([]byte, error) {
		if strings.Contains(script, "Get-NetAdapter") {
			return []byte("{99999999-9999-9999-9999-999999999999}\r\n"), nil
		}
		t.Fatalf("mismatched adapter must not be removed: %s", script)
		return nil, nil
	}}
	if err := CleanupResourceWithRunner(record, runner); !errors.Is(err, ErrResourceNotOwned) {
		t.Fatalf("cleanup error = %v, want ErrResourceNotOwned", err)
	}
}

func TestWindowsCleanupRouteUsesExactPrefix(t *testing.T) {
	record := makeOwnedRecord(t, "instance", ResourceBroadcastRoute, "LANMesh", "255.255.255.255/32", "", "{11111111-1111-1111-1111-111111111111}")
	runner := &fakeWindowsRunner{handle: func(script string) ([]byte, error) {
		switch {
		case strings.Contains(script, "Get-NetAdapter"):
			return []byte("{11111111-1111-1111-1111-111111111111}\r\n"), nil
		case strings.Contains(script, "Get-NetRoute"):
			return []byte("255.255.255.255/32\r\n"), nil
		case strings.Contains(script, "Remove-NetRoute"):
			return nil, nil
		default:
			t.Fatalf("unexpected script: %s", script)
			return nil, nil
		}
	}}
	if err := CleanupResourceWithRunner(record, runner); err != nil {
		t.Fatal(err)
	}
	if len(runner.scripts) != 3 || !strings.Contains(runner.scripts[2], "255.255.255.255/32") {
		t.Fatalf("cleanup scripts = %#v", runner.scripts)
	}
}
