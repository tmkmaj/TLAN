package clientidentity

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConfigDirectoryPreservesExistingBrandingDirectory(t *testing.T) {
	root := t.TempDir()
	legacy := filepath.Join(root, "LANMesh")
	if err := os.MkdirAll(legacy, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(legacy, "settings.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	dir, err := configDirectory(root)
	if err != nil {
		t.Fatal(err)
	}
	if dir != legacy {
		t.Fatalf("settings directory = %q, want existing legacy directory %q", dir, legacy)
	}
}

func TestConfigDirectoryPrefersCurrentBrandingAfterUpgrade(t *testing.T) {
	root := t.TempDir()
	current := filepath.Join(root, "TmkNetworkLAN")
	legacy := filepath.Join(root, "LANMesh")
	for _, dir := range []string{current, legacy} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(legacy, "identity.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(current, "settings.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	dir, err := configDirectory(root)
	if err != nil {
		t.Fatal(err)
	}
	if dir != current {
		t.Fatalf("settings directory = %q, want current directory %q", dir, current)
	}
}
