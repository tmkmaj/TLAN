package coreupdate

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"testing"
	"time"
)

var testNow = time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)

func newTestKeyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return publicKey, privateKey
}

func artifactSHA256(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func testManifest(version, platform, rawURL string, body []byte) Manifest {
	return Manifest{
		SchemaVersion:        ManifestSchemaVersion,
		Version:              version,
		Platform:             platform,
		URL:                  rawURL,
		SHA256:               artifactSHA256(body),
		Size:                 int64(len(body)),
		PublishedAt:          testNow.Add(-time.Minute).Format(time.RFC3339),
		MinimumClientVersion: "1.0.0",
		ExpiresAt:            testNow.Add(time.Hour).Format(time.RFC3339),
	}
}

func signedTestManifest(t *testing.T, manifest Manifest, privateKey ed25519.PrivateKey) []byte {
	t.Helper()
	signed, err := SignManifest(manifest, privateKey)
	if err != nil {
		t.Fatalf("sign manifest: %v", err)
	}
	data, err := MarshalSignedManifest(signed)
	if err != nil {
		t.Fatalf("marshal signed manifest: %v", err)
	}
	return data
}

func newTestInstaller(t *testing.T, root string, publicKey ed25519.PublicKey, client *http.Client, currentVersion, manifestVersion, platform, targetName string) *Installer {
	t.Helper()
	installer, err := NewInstaller(Config{
		CoreRoot:         root,
		PublicKey:        publicKey,
		CurrentVersion:   currentVersion,
		Platform:         platform,
		AllowedVersions:  []string{manifestVersion},
		AllowedPlatforms: []string{platform},
		TargetName:       targetName,
		MaxManifestBytes: DefaultMaxManifestBytes,
		MaxDownloadBytes: DefaultMaxDownloadBytes,
		HTTPClient:       client,
		Now:              func() time.Time { return testNow },
		ClockSkew:        time.Minute,
	})
	if err != nil {
		t.Fatalf("new installer: %v", err)
	}
	return installer
}

type failingBody struct {
	data []byte
	done bool
}

func (b *failingBody) Read(p []byte) (int, error) {
	if b.done {
		return 0, io.ErrUnexpectedEOF
	}
	b.done = true
	n := copy(p, b.data)
	return n, nil
}

func (b *failingBody) Close() error { return nil }

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
