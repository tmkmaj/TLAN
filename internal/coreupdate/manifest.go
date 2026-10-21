package coreupdate

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const (
	// ManifestSchemaVersion is the only manifest schema accepted by this package.
	ManifestSchemaVersion = 1
	// DefaultMaxManifestBytes is deliberately small: a manifest is metadata,
	// not an artifact.
	DefaultMaxManifestBytes int64 = 1 << 20
)

var (
	platformPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	sha256Pattern   = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Manifest is the signed release description. Signature covers the canonical
// JSON encoding of every field except Signature itself.
type Manifest struct {
	SchemaVersion        int    `json:"schemaVersion"`
	Version              string `json:"version"`
	Platform             string `json:"platform"`
	URL                  string `json:"url"`
	SHA256               string `json:"sha256"`
	Size                 int64  `json:"size"`
	PublishedAt          string `json:"publishedAt"`
	MinimumClientVersion string `json:"minimumClientVersion"`
	ExpiresAt            string `json:"expiresAt,omitempty"`
	Signature            string `json:"signature,omitempty"`
}

type signingPayload struct {
	SchemaVersion        int    `json:"schemaVersion"`
	Version              string `json:"version"`
	Platform             string `json:"platform"`
	URL                  string `json:"url"`
	SHA256               string `json:"sha256"`
	Size                 int64  `json:"size"`
	PublishedAt          string `json:"publishedAt"`
	MinimumClientVersion string `json:"minimumClientVersion"`
	ExpiresAt            string `json:"expiresAt,omitempty"`
}

// ParseManifest parses a strict JSON manifest without verifying its signature.
// Unknown fields, duplicate keys, trailing JSON values, and invalid required
// fields are rejected.
func ParseManifest(data []byte, maxBytes int64) (Manifest, error) {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxManifestBytes
	}
	if int64(len(data)) > maxBytes {
		return Manifest{}, fmt.Errorf("%w: got %d bytes, limit %d", ErrManifestTooLarge, len(data), maxBytes)
	}
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return Manifest{}, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var m Manifest
	if err := dec.Decode(&m); err != nil {
		return Manifest{}, fmt.Errorf("%w: %v", ErrInvalidManifest, err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return Manifest{}, fmt.Errorf("%w: trailing JSON value", ErrInvalidManifest)
		}
		return Manifest{}, fmt.Errorf("%w: %v", ErrInvalidManifest, err)
	}
	if err := validateManifest(m, false); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

func validateManifest(m Manifest, requireSignature bool) error {
	if m.SchemaVersion != ManifestSchemaVersion {
		return fmt.Errorf("%w: unsupported schemaVersion %d", ErrInvalidManifest, m.SchemaVersion)
	}
	if _, err := parseVersion(m.Version); err != nil {
		return err
	}
	if !platformPattern.MatchString(m.Platform) {
		return fmt.Errorf("%w: invalid platform", ErrInvalidManifest)
	}
	if err := validateHTTPSURL(m.URL); err != nil {
		return err
	}
	if !sha256Pattern.MatchString(m.SHA256) {
		return fmt.Errorf("%w: sha256 must be 64 lowercase hex characters", ErrInvalidManifest)
	}
	if _, err := hex.DecodeString(m.SHA256); err != nil {
		return fmt.Errorf("%w: invalid sha256", ErrInvalidManifest)
	}
	if m.Size <= 0 {
		return fmt.Errorf("%w: size must be positive", ErrInvalidManifest)
	}
	published, err := parseTimestamp(m.PublishedAt, "publishedAt")
	if err != nil {
		return err
	}
	if _, err := parseVersion(m.MinimumClientVersion); err != nil {
		return err
	}
	if m.ExpiresAt != "" {
		expires, err := parseTimestamp(m.ExpiresAt, "expiresAt")
		if err != nil {
			return err
		}
		if !expires.After(published) {
			return fmt.Errorf("%w: expiresAt must be after publishedAt", ErrInvalidManifest)
		}
	}
	if m.Signature != "" {
		sig, err := base64.StdEncoding.Strict().DecodeString(m.Signature)
		if err != nil || len(sig) != ed25519.SignatureSize {
			return fmt.Errorf("%w: signature must be base64-encoded Ed25519", ErrInvalidManifest)
		}
	}
	if requireSignature && m.Signature == "" {
		return fmt.Errorf("%w: signature is required", ErrInvalidManifest)
	}
	return nil
}

func parseTimestamp(raw, field string) (time.Time, error) {
	if raw == "" || raw != strings.TrimSpace(raw) {
		return time.Time{}, fmt.Errorf("%w: %s is empty or contains whitespace", ErrInvalidManifest, field)
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: invalid %s: %v", ErrInvalidManifest, field, err)
	}
	return t, nil
}

func validateHTTPSURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%w: invalid URL: %v", ErrInvalidManifest, err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("%w: got scheme %q", ErrHTTPSRequired, u.Scheme)
	}
	if u.Host == "" || u.Hostname() == "" || u.User != nil || u.Opaque != "" || u.Fragment != "" {
		return fmt.Errorf("%w: URL must contain only a normal HTTPS host and path", ErrInvalidManifest)
	}
	if strings.ContainsAny(u.Host, " \t\r\n") {
		return fmt.Errorf("%w: URL host contains whitespace", ErrInvalidManifest)
	}
	return nil
}

func (m Manifest) canonicalPayload() ([]byte, error) {
	if err := validateManifest(m, false); err != nil {
		return nil, err
	}
	return json.Marshal(signingPayload{
		SchemaVersion:        m.SchemaVersion,
		Version:              m.Version,
		Platform:             m.Platform,
		URL:                  m.URL,
		SHA256:               m.SHA256,
		Size:                 m.Size,
		PublishedAt:          m.PublishedAt,
		MinimumClientVersion: m.MinimumClientVersion,
		ExpiresAt:            m.ExpiresAt,
	})
}

// SignManifest signs the canonical manifest payload with an Ed25519 private
// key. It never logs or stores the private key.
func SignManifest(m Manifest, privateKey ed25519.PrivateKey) (Manifest, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return Manifest{}, fmt.Errorf("%w: invalid private key length", ErrInvalidPublicKey)
	}
	m.Signature = ""
	payload, err := m.canonicalPayload()
	if err != nil {
		return Manifest{}, err
	}
	sig := ed25519.Sign(privateKey, payload)
	m.Signature = base64.StdEncoding.EncodeToString(sig)
	if err := validateManifest(m, true); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

// MarshalSignedManifest validates and marshals a signed manifest for storage.
func MarshalSignedManifest(m Manifest) ([]byte, error) {
	if err := validateManifest(m, true); err != nil {
		return nil, err
	}
	return json.MarshalIndent(m, "", "  ")
}

// VerifyOptions controls signature, time, compatibility, and whitelist checks.
type VerifyOptions struct {
	PublicKey        ed25519.PublicKey
	AllowedVersions  []string
	AllowedPlatforms []string
	Platform         string
	CurrentVersion   string
	Now              time.Time
	ClockSkew        time.Duration
	MaxManifestBytes int64
}

// VerifySignedManifest verifies the signature and all configured policy
// constraints. A nil public key always fails closed. Nil whitelists mean "not
// checked by this lower-level helper"; Installer requires non-empty whitelists.
func VerifySignedManifest(data []byte, opts VerifyOptions) (Manifest, error) {
	m, err := ParseManifest(data, opts.MaxManifestBytes)
	if err != nil {
		return Manifest{}, err
	}
	if len(opts.PublicKey) == 0 {
		return Manifest{}, ErrNoPublicKey
	}
	if len(opts.PublicKey) != ed25519.PublicKeySize {
		return Manifest{}, ErrInvalidPublicKey
	}
	sig, err := base64.StdEncoding.Strict().DecodeString(m.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return Manifest{}, ErrInvalidSignature
	}
	payload, err := m.canonicalPayload()
	if err != nil {
		return Manifest{}, err
	}
	if !ed25519.Verify(opts.PublicKey, payload, sig) {
		return Manifest{}, ErrInvalidSignature
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	if opts.ClockSkew < 0 {
		return Manifest{}, fmt.Errorf("%w: negative clock skew", ErrInvalidManifest)
	}
	published, _ := parseTimestamp(m.PublishedAt, "publishedAt")
	if published.After(now.Add(opts.ClockSkew)) {
		return Manifest{}, ErrManifestNotYetValid
	}
	if m.ExpiresAt != "" {
		expires, _ := parseTimestamp(m.ExpiresAt, "expiresAt")
		if !now.Before(expires) {
			return Manifest{}, ErrManifestExpired
		}
	}
	if opts.AllowedVersions != nil {
		found := false
		for _, allowed := range opts.AllowedVersions {
			if _, err := parseVersion(allowed); err != nil {
				return Manifest{}, fmt.Errorf("%w: invalid allowed version", ErrInvalidManifest)
			}
			if allowed == m.Version {
				found = true
			}
		}
		if !found {
			return Manifest{}, fmt.Errorf("%w: %s", ErrVersionNotAllowed, m.Version)
		}
	}
	if opts.AllowedPlatforms != nil {
		found := false
		for _, allowed := range opts.AllowedPlatforms {
			if !platformPattern.MatchString(allowed) {
				return Manifest{}, fmt.Errorf("%w: invalid allowed platform", ErrInvalidManifest)
			}
			if allowed == m.Platform {
				found = true
			}
		}
		if !found {
			return Manifest{}, fmt.Errorf("%w: %s", ErrPlatformNotAllowed, m.Platform)
		}
	}
	if opts.Platform != "" && opts.Platform != m.Platform {
		return Manifest{}, fmt.Errorf("%w: got %s, want %s", ErrPlatformNotAllowed, m.Platform, opts.Platform)
	}
	if opts.CurrentVersion != "" {
		if _, err := parseVersion(opts.CurrentVersion); err != nil {
			return Manifest{}, fmt.Errorf("%w: invalid current version", ErrInvalidManifest)
		}
		cmp, err := CompareVersions(opts.CurrentVersion, m.MinimumClientVersion)
		if err != nil {
			return Manifest{}, err
		}
		if cmp < 0 {
			return Manifest{}, fmt.Errorf("%w: client %s < minimum %s", ErrClientTooOld, opts.CurrentVersion, m.MinimumClientVersion)
		}
	}
	return m, nil
}

func rejectDuplicateJSONKeys(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var walk func() error
	walk = func() error {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		delim, ok := tok.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := make(map[string]struct{})
			for dec.More() {
				keyToken, err := dec.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return fmt.Errorf("object key is not a string")
				}
				if _, exists := seen[key]; exists {
					return fmt.Errorf("duplicate key %q", key)
				}
				seen[key] = struct{}{}
				if err := walk(); err != nil {
					return err
				}
			}
			end, err := dec.Token()
			if err != nil {
				return err
			}
			if end != json.Delim('}') {
				return fmt.Errorf("unterminated object")
			}
		case '[':
			for dec.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			end, err := dec.Token()
			if err != nil {
				return err
			}
			if end != json.Delim(']') {
				return fmt.Errorf("unterminated array")
			}
		default:
			return fmt.Errorf("unexpected JSON delimiter %q", delim)
		}
		return nil
	}
	if err := walk(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidManifest, err)
	}
	if tok, err := dec.Token(); err != io.EOF {
		if err == nil {
			return fmt.Errorf("%w: trailing JSON value %v", ErrInvalidManifest, tok)
		}
		return fmt.Errorf("%w: %v", ErrInvalidManifest, err)
	}
	return nil
}
