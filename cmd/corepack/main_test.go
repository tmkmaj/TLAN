package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/private-radminlan/lanmesh/internal/coreupdate"
)

func TestCorepackSignAndVerify(t *testing.T) {
	dir := t.TempDir()
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "private.key")
	publicPath := filepath.Join(dir, "public.key")
	unsignedPath := filepath.Join(dir, "unsigned.json")
	signedPath := filepath.Join(dir, "signed.json")
	if err := os.WriteFile(keyPath, privateKey.Seed(), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(publicPath, publicKey, 0o600); err != nil {
		t.Fatal(err)
	}
	body := []byte("frpc")
	sum := sha256.Sum256(body)
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	manifest := coreupdate.Manifest{
		SchemaVersion:        coreupdate.ManifestSchemaVersion,
		Version:              "1.1.0",
		Platform:             "windows-amd64",
		URL:                  "https://example.test/frpc.exe",
		SHA256:               hex.EncodeToString(sum[:]),
		Size:                 int64(len(body)),
		PublishedAt:          now.Add(-time.Minute).Format(time.RFC3339),
		MinimumClientVersion: "1.0.0",
		ExpiresAt:            now.Add(time.Hour).Format(time.RFC3339),
	}
	unsigned, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(unsignedPath, unsigned, 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if code := run([]string{"sign", "-manifest", unsignedPath, "-key", keyPath, "-out", signedPath}, &stdout, &stderr); code != 0 {
		t.Fatalf("sign code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if strings.Contains(stdout.String()+stderr.String(), hex.EncodeToString(privateKey.Seed())) ||
		strings.Contains(stdout.String()+stderr.String(), base64.StdEncoding.EncodeToString(privateKey.Seed())) {
		t.Fatal("sign output leaked private key material")
	}
	signed, err := os.ReadFile(signedPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coreupdate.ParseManifest(signed, coreupdate.DefaultMaxManifestBytes); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{
		"verify",
		"-manifest", signedPath,
		"-public-key", publicPath,
		"-client-version", "1.0.0",
		"-platform", "windows-amd64",
		"-now", now.Format(time.RFC3339),
	}, &stdout, &stderr); code != 0 {
		t.Fatalf("verify code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "OK version=1.1.0") {
		t.Fatalf("verify output = %q", stdout.String())
	}
}

func TestCorepackVerifyRejectsTamperedManifest(t *testing.T) {
	dir := t.TempDir()
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "private.key")
	publicPath := filepath.Join(dir, "public.key")
	unsignedPath := filepath.Join(dir, "unsigned.json")
	signedPath := filepath.Join(dir, "signed.json")
	if err := os.WriteFile(keyPath, privateKey.Seed(), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(publicPath, publicKey, 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	manifest := coreupdate.Manifest{
		SchemaVersion:        coreupdate.ManifestSchemaVersion,
		Version:              "1.1.0",
		Platform:             "windows-amd64",
		URL:                  "https://example.test/frpc.exe",
		SHA256:               strings.Repeat("a", 64),
		Size:                 4,
		PublishedAt:          now.Add(-time.Minute).Format(time.RFC3339),
		MinimumClientVersion: "1.0.0",
	}
	unsigned, _ := json.Marshal(manifest)
	if err := os.WriteFile(unsignedPath, unsigned, 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"sign", "-manifest", unsignedPath, "-key", keyPath, "-out", signedPath}, &stdout, &stderr); code != 0 {
		t.Fatalf("sign failed: %s", stderr.String())
	}
	signed, err := os.ReadFile(signedPath)
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(signed), `"version": "1.1.0"`, `"version": "9.9.9"`, 1)
	if tampered == string(signed) {
		t.Fatal("tamper replacement failed")
	}
	if err := os.WriteFile(signedPath, []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"verify", "-manifest", signedPath, "-public-key", publicPath, "-platform", "windows-amd64"}, &stdout, &stderr); code == 0 {
		t.Fatal("tampered manifest unexpectedly verified")
	}
}

func TestCorepackVerifyRequiresPublicKey(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"verify", "-manifest", "missing.json"}, &stdout, &stderr); code != 2 {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
}

func TestCorepackRefusesToOverwritePrivateKey(t *testing.T) {
	dir := t.TempDir()
	_, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "private.key")
	if err := os.WriteFile(keyPath, privateKey.Seed(), 0o600); err != nil {
		t.Fatal(err)
	}
	unsignedPath := filepath.Join(dir, "unsigned.json")
	if err := os.WriteFile(unsignedPath, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"sign", "-manifest", unsignedPath, "-key", keyPath, "-out", keyPath}, &stdout, &stderr); code != 2 {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	got, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, privateKey.Seed()) {
		t.Fatal("private key was modified")
	}
}

func TestCorepackRefusesPrivateKeyThroughSymlink(t *testing.T) {
	dir := t.TempDir()
	_, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "private.key")
	if err := os.WriteFile(keyPath, privateKey.Seed(), 0o600); err != nil {
		t.Fatal(err)
	}
	unsignedPath := filepath.Join(dir, "unsigned.json")
	if err := os.WriteFile(unsignedPath, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	linkPath := filepath.Join(dir, "signed.json")
	if err := os.Symlink(keyPath, linkPath); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"sign", "-manifest", unsignedPath, "-key", keyPath, "-out", linkPath}, &stdout, &stderr); code != 2 {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	got, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, privateKey.Seed()) {
		t.Fatal("private key was modified through symlink")
	}
}

func TestCorepackVerifyRejectsExpiredManifest(t *testing.T) {
	dir := t.TempDir()
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "private.key")
	publicPath := filepath.Join(dir, "public.key")
	unsignedPath := filepath.Join(dir, "unsigned.json")
	signedPath := filepath.Join(dir, "signed.json")
	if err := os.WriteFile(keyPath, privateKey.Seed(), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(publicPath, publicKey, 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	manifest := coreupdate.Manifest{
		SchemaVersion:        coreupdate.ManifestSchemaVersion,
		Version:              "1.1.0",
		Platform:             "windows-amd64",
		URL:                  "https://example.test/frpc.exe",
		SHA256:               strings.Repeat("a", 64),
		Size:                 4,
		PublishedAt:          now.Add(-2 * time.Hour).Format(time.RFC3339),
		MinimumClientVersion: "1.0.0",
		ExpiresAt:            now.Add(-time.Hour).Format(time.RFC3339),
	}
	unsigned, _ := json.Marshal(manifest)
	if err := os.WriteFile(unsignedPath, unsigned, 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"sign", "-manifest", unsignedPath, "-key", keyPath, "-out", signedPath}, &stdout, &stderr); code != 0 {
		t.Fatalf("sign failed: %s", stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{
		"verify", "-manifest", signedPath, "-public-key", publicPath,
		"-client-version", "1.0.0", "-platform", "windows-amd64",
		"-now", now.Format(time.RFC3339),
	}, &stdout, &stderr); code == 0 {
		t.Fatal("expired manifest unexpectedly verified")
	}
}
