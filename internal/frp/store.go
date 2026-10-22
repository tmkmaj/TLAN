package frp

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/private-radminlan/lanmesh/internal/clientidentity"
)

const (
	profileFileName = "profiles.json"
	secretsFileName = "secrets.json"
	caFileName      = "ca.pem"
	runtimeDirName  = "runtime"
	logsDirName     = "logs"
	frpLogFileName  = "frp.log"
)

type Store struct {
	root string
}

func DefaultStore() (*Store, error) {
	identityPath, err := clientidentity.DefaultPath()
	if err != nil {
		return nil, err
	}
	return NewStore(filepath.Join(filepath.Dir(identityPath), "frp"))
}

func NewStore(root string) (*Store, error) {
	if strings.TrimSpace(root) == "" {
		return nil, fmt.Errorf("FRP config directory is empty")
	}
	absolute, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve FRP config directory: %w", err)
	}
	return &Store{root: filepath.Clean(absolute)}, nil
}

func (s *Store) Root() string        { return s.root }
func (s *Store) RuntimeRoot() string { return filepath.Join(s.root, runtimeDirName) }
func (s *Store) CAFile() string      { return filepath.Join(s.root, caFileName) }

// LogRoot is deliberately outside RuntimeRoot. Runtime instance directories
// are removed as processes exit, while retained FRP logs must remain available
// for diagnostics and later export.
func (s *Store) LogRoot() string { return filepath.Join(s.root, logsDirName) }
func (s *Store) LogFile() string { return filepath.Join(s.LogRoot(), frpLogFileName) }

func (s *Store) Ensure() error {
	if err := os.MkdirAll(s.root, 0o700); err != nil {
		return fmt.Errorf("create FRP config directory: %w", err)
	}
	if err := secureDirectory(s.root); err != nil {
		return err
	}
	if err := os.MkdirAll(s.RuntimeRoot(), 0o700); err != nil {
		return fmt.Errorf("create FRP runtime directory: %w", err)
	}
	return secureDirectory(s.RuntimeRoot())
}

func (s *Store) Load() (Config, error) {
	data, err := os.ReadFile(filepath.Join(s.root, profileFileName))
	if errors.Is(err, os.ErrNotExist) {
		return Config{}, ErrNoConfig
	}
	if err != nil {
		return Config{}, fmt.Errorf("read FRP profile: %w", err)
	}
	cfg, err := DecodeConfig(bytes.NewReader(data))
	if err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Save persists a new revision. A non-empty token replaces the stored secret;
// an empty token keeps the existing value. The CA file is copied into the
// managed config directory and becomes the only path used for future starts.
func (s *Store) Save(cfg Config, token string) (Config, error) {
	return s.SaveWithSecrets(cfg, token, nil)
}

// SaveWithSecrets persists the profile and all secret references in one
// revision. Values in provided replace existing protected values; references
// not present in the profile are removed from the secret document.
func (s *Store) SaveWithSecrets(cfg Config, token string, provided map[string]string) (Config, error) {
	cfg = NormalizeConfig(cfg)
	if err := ValidateConfig(cfg); err != nil {
		return Config{}, err
	}
	if err := s.Ensure(); err != nil {
		return Config{}, err
	}
	current, err := s.Load()
	currentRevision := uint64(0)
	if err == nil {
		currentRevision = current.Profile.Revision
	} else if !errors.Is(err, ErrNoConfig) {
		return Config{}, err
	}
	if cfg.Profile.Revision != currentRevision {
		return Config{}, fmt.Errorf("%w: expected %d, got %d", ErrRevisionConflict, currentRevision, cfg.Profile.Revision)
	}

	existing, existingErr := s.loadSecrets()
	if existingErr != nil && !errors.Is(existingErr, os.ErrNotExist) {
		return Config{}, existingErr
	}
	if existing.Secrets == nil {
		existing.Secrets = map[string]string{}
	}

	ref := cfg.Profile.Server.CredentialRef
	if token == "" {
		token, err = s.Secret(ref)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return Config{}, err
		}
	}
	if token == "" {
		return Config{}, codedError(CodeAuthRejected, "FRP token is not configured")
	}
	if len(token) > MaxTokenBytes || strings.ContainsAny(token, "\x00\r\n") {
		return Config{}, codedError(CodeAuthRejected, "FRP token is invalid")
	}

	caSource := cfg.Profile.Server.TrustedCAPath
	if err = ValidateCAFile(caSource); err != nil {
		return Config{}, withCode(CodeTLSUntrusted, err)
	}
	caData, err := os.ReadFile(caSource)
	if err != nil {
		return Config{}, withCode(CodeTLSUntrusted, err)
	}

	next := CloneConfig(cfg)
	next.Profile.Revision = currentRevision + 1
	next.Profile.Server.TrustedCAPath = s.CAFile()
	if err = ValidateConfig(next); err != nil {
		return Config{}, err
	}

	protectedSecrets := make(map[string]string)
	required := requiredSecretRefs(next)
	for requiredRef := range required {
		if requiredRef == ref {
			protectedSecrets[requiredRef], err = clientidentity.ProtectSecret(token)
			if err != nil {
				return Config{}, fmt.Errorf("protect FRP token: %w", err)
			}
			continue
		}
		value := provided[requiredRef]
		if value == "" {
			value, err = s.Secret(requiredRef)
			if err != nil {
				if errors.Is(err, os.ErrNotExist) {
					return Config{}, codedError(CodeConfigurationInvalid, "secret %q is required", requiredRef)
				}
				return Config{}, err
			}
		}
		if value == "" || len(value) > MaxTokenBytes || strings.ContainsAny(value, "\x00\r\n") {
			return Config{}, codedError(CodeConfigurationInvalid, "secret %q is invalid", requiredRef)
		}
		protectedSecrets[requiredRef], err = clientidentity.ProtectSecret(value)
		if err != nil {
			return Config{}, fmt.Errorf("protect FRP secret %s: %w", requiredRef, err)
		}
	}
	secretDoc := secretDocument{SchemaVersion: SecretSchema, Secrets: protectedSecrets}
	secretData, err := json.MarshalIndent(secretDoc, "", "  ")
	if err != nil {
		return Config{}, fmt.Errorf("encode FRP secrets: %w", err)
	}
	secretData = append(secretData, '\n')
	profileData, err := EncodeConfig(next)
	if err != nil {
		return Config{}, err
	}

	secretPath := filepath.Join(s.root, secretsFileName)
	profilePath := filepath.Join(s.root, profileFileName)
	oldSecret, secretReadErr := os.ReadFile(secretPath)
	oldProfile, profileReadErr := os.ReadFile(profilePath)
	oldCA, caReadErr := os.ReadFile(s.CAFile())

	rollback := func() {
		restoreFile(secretPath, oldSecret, secretReadErr)
		restoreFile(profilePath, oldProfile, profileReadErr)
		restoreFile(s.CAFile(), oldCA, caReadErr)
	}
	if err = writePrivateFile(s.CAFile(), caData); err != nil {
		return Config{}, fmt.Errorf("save trusted CA: %w", err)
	}
	if err = writePrivateFile(secretPath, secretData); err != nil {
		rollback()
		return Config{}, fmt.Errorf("save FRP secret: %w", err)
	}
	if err = writePrivateFile(profilePath, profileData); err != nil {
		rollback()
		return Config{}, fmt.Errorf("save FRP profile: %w", err)
	}
	return next, nil
}

func requiredSecretRefs(cfg Config) map[string]struct{} {
	refs := map[string]struct{}{cfg.Profile.Server.CredentialRef: {}}
	for _, rule := range cfg.Profile.Rules {
		if rule.SecretRef != "" {
			refs[rule.SecretRef] = struct{}{}
		}
		if rule.Exposure.HTTPPasswordRef != "" {
			refs[rule.Exposure.HTTPPasswordRef] = struct{}{}
		}
	}
	for _, visitor := range cfg.Profile.Visitors {
		if visitor.SecretRef != "" {
			refs[visitor.SecretRef] = struct{}{}
		}
	}
	return refs
}

func restoreFile(path string, data []byte, readErr error) {
	if readErr == nil {
		_ = writePrivateFile(path, data)
		return
	}
	if errors.Is(readErr, os.ErrNotExist) {
		_ = os.Remove(path)
	}
}

func (s *Store) Token(ref string) (string, error) {
	return s.Secret(ref)
}

func (s *Store) Secret(ref string) (string, error) {
	doc, err := s.loadSecrets()
	if err != nil {
		return "", err
	}
	value, ok := doc.Secrets[ref]
	if !ok || value == "" {
		return "", os.ErrNotExist
	}
	token, err := clientidentity.UnprotectSecretStrict(value)
	if err != nil {
		return "", fmt.Errorf("decrypt FRP token: %w", err)
	}
	return token, nil
}

func (s *Store) HasToken(ref string) bool { return s.HasSecret(ref) }

func (s *Store) HasSecret(ref string) bool {
	value, err := s.Secret(ref)
	return err == nil && value != ""
}

func (s *Store) loadSecrets() (secretDocument, error) {
	data, err := os.ReadFile(filepath.Join(s.root, secretsFileName))
	if err != nil {
		return secretDocument{}, err
	}
	if len(data) > MaxConfigBytes {
		return secretDocument{}, unsupported("FRP secrets file is too large")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var doc secretDocument
	if err = decoder.Decode(&doc); err != nil {
		return secretDocument{}, fmt.Errorf("decode FRP secrets: %w", err)
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return secretDocument{}, fmt.Errorf("decode FRP secrets: trailing data")
	}
	if doc.SchemaVersion != SecretSchema || doc.Secrets == nil {
		return secretDocument{}, fmt.Errorf("unsupported FRP secrets schema")
	}
	return doc, nil
}

type secretDocument struct {
	SchemaVersion int               `json:"schemaVersion"`
	Secrets       map[string]string `json:"secrets"`
}
