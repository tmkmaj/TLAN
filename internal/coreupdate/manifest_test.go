package coreupdate

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestSignVerifyRoundTrip(t *testing.T) {
	publicKey, privateKey := newTestKeyPair(t)
	body := []byte("frpc-binary")
	manifest := testManifest("1.1.0", "windows-amd64", "https://example.test/frpc.exe", body)
	data := signedTestManifest(t, manifest, privateKey)
	got, err := VerifySignedManifest(data, VerifyOptions{
		PublicKey:        publicKey,
		CurrentVersion:   "1.0.0",
		Platform:         "windows-amd64",
		AllowedVersions:  []string{"1.1.0"},
		AllowedPlatforms: []string{"windows-amd64"},
		Now:              testNow,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != manifest.Version || got.SHA256 != manifest.SHA256 {
		t.Fatalf("unexpected manifest: %+v", got)
	}
}

func TestStrictJSONRejectsUnknownDuplicateAndTrailing(t *testing.T) {
	_, privateKey := newTestKeyPair(t)
	manifest := testManifest("1.1.0", "windows-amd64", "https://example.test/frpc.exe", []byte("x"))
	unsigned, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}

	var obj map[string]any
	if err := json.Unmarshal(unsigned, &obj); err != nil {
		t.Fatal(err)
	}
	obj["unexpected"] = true
	unknown, _ := json.Marshal(obj)
	if _, err := ParseManifest(unknown, DefaultMaxManifestBytes); !errors.Is(err, ErrInvalidManifest) {
		t.Fatalf("unknown field error = %v", err)
	}

	duplicate := strings.Replace(string(unsigned), `"schemaVersion":1`, `"schemaVersion":1,"schemaVersion":1`, 1)
	if _, err := ParseManifest([]byte(duplicate), DefaultMaxManifestBytes); !errors.Is(err, ErrInvalidManifest) {
		t.Fatalf("duplicate field error = %v", err)
	}

	trailing := append(append([]byte(nil), unsigned...), []byte(` {}`)...)
	if _, err := ParseManifest(trailing, DefaultMaxManifestBytes); !errors.Is(err, ErrInvalidManifest) {
		t.Fatalf("trailing value error = %v", err)
	}

	_ = privateKey
}

func TestVerifyRejectsTamperedManifestAndSignature(t *testing.T) {
	publicKey, privateKey := newTestKeyPair(t)
	manifest := testManifest("1.1.0", "windows-amd64", "https://example.test/frpc.exe", []byte("binary"))
	data := signedTestManifest(t, manifest, privateKey)
	tampered := strings.Replace(string(data), `"version": "1.1.0"`, `"version": "9.9.9"`, 1)
	if tampered == string(data) {
		t.Fatal("tamper replacement did not change manifest")
	}
	if _, err := VerifySignedManifest([]byte(tampered), VerifyOptions{PublicKey: publicKey, Now: testNow}); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("tampered manifest error = %v", err)
	}

	var parsed Manifest
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatal(err)
	}
	sig, err := base64.StdEncoding.DecodeString(parsed.Signature)
	if err != nil {
		t.Fatal(err)
	}
	sig[0] ^= 0xff
	parsed.Signature = base64.StdEncoding.EncodeToString(sig)
	tamperedSig, err := json.Marshal(parsed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySignedManifest(tamperedSig, VerifyOptions{PublicKey: publicKey, Now: testNow}); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("tampered signature error = %v", err)
	}
}

func TestVerifyWhitelistsAndMinimumClientVersion(t *testing.T) {
	publicKey, privateKey := newTestKeyPair(t)
	manifest := testManifest("1.2.3", "windows-amd64", "https://example.test/frpc.exe", []byte("binary"))
	data := signedTestManifest(t, manifest, privateKey)
	base := VerifyOptions{PublicKey: publicKey, Now: testNow, CurrentVersion: "1.0.0"}

	tooOld := base
	tooOld.CurrentVersion = "0.9.9"
	if _, err := VerifySignedManifest(data, tooOld); !errors.Is(err, ErrClientTooOld) {
		t.Fatalf("minimum client error = %v", err)
	}

	badVersion := base
	badVersion.AllowedVersions = []string{"1.2.2"}
	if _, err := VerifySignedManifest(data, badVersion); !errors.Is(err, ErrVersionNotAllowed) {
		t.Fatalf("version whitelist error = %v", err)
	}

	badPlatform := base
	badPlatform.AllowedPlatforms = []string{"linux-amd64"}
	if _, err := VerifySignedManifest(data, badPlatform); !errors.Is(err, ErrPlatformNotAllowed) {
		t.Fatalf("platform whitelist error = %v", err)
	}

	wrongTarget := base
	wrongTarget.Platform = "linux-amd64"
	if _, err := VerifySignedManifest(data, wrongTarget); !errors.Is(err, ErrPlatformNotAllowed) {
		t.Fatalf("target platform error = %v", err)
	}
}

func TestVerifyExpiryAndFutureManifest(t *testing.T) {
	publicKey, privateKey := newTestKeyPair(t)
	expired := testManifest("1.1.0", "windows-amd64", "https://example.test/frpc.exe", []byte("binary"))
	expired.PublishedAt = testNow.Add(-2 * time.Hour).Format(time.RFC3339)
	expired.ExpiresAt = testNow.Add(-time.Hour).Format(time.RFC3339)
	expiredData := signedTestManifest(t, expired, privateKey)
	if _, err := VerifySignedManifest(expiredData, VerifyOptions{PublicKey: publicKey, Now: testNow}); !errors.Is(err, ErrManifestExpired) {
		t.Fatalf("expired manifest error = %v", err)
	}

	future := testManifest("1.1.0", "windows-amd64", "https://example.test/frpc.exe", []byte("binary"))
	future.PublishedAt = testNow.Add(2 * time.Hour).Format(time.RFC3339)
	future.ExpiresAt = testNow.Add(3 * time.Hour).Format(time.RFC3339)
	futureData := signedTestManifest(t, future, privateKey)
	if _, err := VerifySignedManifest(futureData, VerifyOptions{PublicKey: publicKey, Now: testNow}); !errors.Is(err, ErrManifestNotYetValid) {
		t.Fatalf("future manifest error = %v", err)
	}
}

func TestVerifyFailsClosedWithoutPublicKey(t *testing.T) {
	_, privateKey := newTestKeyPair(t)
	data := signedTestManifest(t, testManifest("1.1.0", "windows-amd64", "https://example.test/frpc.exe", []byte("binary")), privateKey)
	if _, err := VerifySignedManifest(data, VerifyOptions{Now: testNow}); !errors.Is(err, ErrNoPublicKey) {
		t.Fatalf("missing public key error = %v", err)
	}
	if _, err := NewInstaller(Config{CoreRoot: t.TempDir(), CurrentVersion: "1.0.0", Platform: "windows-amd64", AllowedVersions: []string{"1.1.0"}, AllowedPlatforms: []string{"windows-amd64"}}); !errors.Is(err, ErrNoPublicKey) {
		t.Fatalf("installer missing public key error = %v", err)
	}
}

func TestManifestRequiresHTTPS(t *testing.T) {
	manifest := testManifest("1.1.0", "windows-amd64", "http://example.test/frpc.exe", []byte("binary"))
	_, privateKey := newTestKeyPair(t)
	if _, err := SignManifest(manifest, privateKey); !errors.Is(err, ErrHTTPSRequired) {
		t.Fatalf("HTTP manifest error = %v", err)
	}
}

func TestManifestSizeLimit(t *testing.T) {
	_, privateKey := newTestKeyPair(t)
	data := signedTestManifest(t, testManifest("1.1.0", "windows-amd64", "https://example.test/frpc.exe", []byte("binary")), privateKey)
	if _, err := ParseManifest(data, int64(len(data)-1)); !errors.Is(err, ErrManifestTooLarge) {
		t.Fatalf("size limit error = %v", err)
	}
}

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0.0", "1.0.0", 0},
		{"1.0.1", "1.0.0", 1},
		{"1.0.0", "2.0.0", -1},
		{"1.0.0-rc.1", "1.0.0", -1},
		{"1.0.0", "1.0.0-rc.1", 1},
		{"v1.2.3", "1.2.3+build.1", 0},
	}
	for _, tc := range cases {
		got, err := CompareVersions(tc.a, tc.b)
		if err != nil {
			t.Fatalf("compare %s %s: %v", tc.a, tc.b, err)
		}
		if got != tc.want {
			t.Fatalf("compare %s %s = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestKeyParsingAndPrivateKeyErrorsDoNotLeakMaterial(t *testing.T) {
	publicKey, privateKey := newTestKeyPair(t)
	if _, err := ParsePublicKey(publicKey); err != nil {
		t.Fatal(err)
	}
	if _, err := ParsePrivateKey(privateKey.Seed()); err != nil {
		t.Fatal(err)
	}
	_, err := ParsePrivateKey([]byte("not-a-key"))
	if err == nil {
		t.Fatal("expected invalid private key error")
	}
	if strings.Contains(err.Error(), "not-a-key") {
		t.Fatalf("error leaked key material: %v", err)
	}
}

func TestBinaryKeysWithWhitespaceBytesAreNotTrimmed(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	seed[0] = 0x20
	seed[len(seed)-1] = 0x0a
	want := ed25519.NewKeyFromSeed(seed)
	got, err := ParsePrivateKey(seed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("raw seed was modified before parsing")
	}
	public := want.Public().(ed25519.PublicKey)
	parsedPublic, err := ParsePublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(parsedPublic, public) {
		t.Fatal("raw public key was modified before parsing")
	}
	hexSeed, err := ParsePrivateKey([]byte(hex.EncodeToString(seed)))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(hexSeed, want) {
		t.Fatal("hex seed was not parsed correctly")
	}
	base64Seed, err := ParsePrivateKey([]byte(base64.StdEncoding.EncodeToString(seed)))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(base64Seed, want) {
		t.Fatal("base64 seed was not parsed correctly")
	}
}

func TestKeyParsingAcceptsPEM(t *testing.T) {
	publicKey, privateKey := newTestKeyPair(t)
	publicDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})
	parsedPublic, err := ParsePublicKey(publicPEM)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(parsedPublic, publicKey) {
		t.Fatal("PEM public key mismatch")
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
	parsedPrivate, err := ParsePrivateKey(privatePEM)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(parsedPrivate, privateKey) {
		t.Fatal("PEM private key mismatch")
	}
}
