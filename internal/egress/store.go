package egress

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/private-radminlan/lanmesh/internal/clientidentity"
)

const (
	profilesFileName = "profiles.json"
	secretsFileName  = "secrets.dat"
)

type secretDocument struct {
	SchemaVersion int               `json:"schemaVersion"`
	Secrets       map[string]string `json:"secrets"`
}

// Store owns only the independent egress configuration directory. It never
// shares a directory or file with Mesh or FRP.
type Store struct {
	root string
	mu   sync.Mutex
}

// DefaultStore returns <client config directory>/egress.
func DefaultStore() (*Store, error) {
	identityPath, err := clientidentity.DefaultPath()
	if err != nil {
		return nil, err
	}
	return NewStore(filepath.Dir(identityPath))
}

// NewStore creates a store rooted at <configDir>/egress.
func NewStore(configDir string) (*Store, error) {
	if configDir == "" || strings.TrimSpace(configDir) != configDir {
		return nil, codedError(CodeStore, ErrInvalidConfig, "egress config directory is invalid")
	}
	absolute, err := filepath.Abs(configDir)
	if err != nil {
		return nil, fmt.Errorf("resolve egress config directory: %w", err)
	}
	return &Store{root: filepath.Join(filepath.Clean(absolute), "egress")}, nil
}

func (s *Store) Root() string { return s.root }

func (s *Store) ProfilesPath() string { return filepath.Join(s.root, profilesFileName) }
func (s *Store) SecretsPath() string  { return filepath.Join(s.root, secretsFileName) }

func (s *Store) Ensure() error {
	if s == nil || s.root == "" {
		return codedError(CodeStore, ErrInvalidConfig, "egress store is nil")
	}
	if err := os.MkdirAll(s.root, 0o700); err != nil {
		return fmt.Errorf("create egress config directory: %w", err)
	}
	if err := secureDirectory(s.root); err != nil {
		return fmt.Errorf("secure egress config directory: %w", err)
	}
	return nil
}

// Load reads profiles.json. A missing file is an empty document; malformed or
// unknown-field JSON is always an error and is never treated as empty.
func (s *Store) Load() (ProfilesDocument, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadLocked()
}

func (s *Store) loadLocked() (ProfilesDocument, error) {
	data, err := os.ReadFile(s.ProfilesPath())
	if errors.Is(err, os.ErrNotExist) {
		return ProfilesDocument{SchemaVersion: SchemaVersion, Profiles: []EgressProfile{}}, nil
	}
	if err != nil {
		return ProfilesDocument{}, fmt.Errorf("read egress profiles: %w", err)
	}
	return DecodeProfiles(strings.NewReader(string(data)))
}

// Save validates, normalizes, and atomically replaces profiles.json.
func (s *Store) Save(doc ProfilesDocument) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveLocked(doc)
}

func (s *Store) saveLocked(doc ProfilesDocument) error {
	if doc.SchemaVersion == 0 {
		doc.SchemaVersion = SchemaVersion
	}
	normalized, err := ValidateProfilesDocumentNormalized(doc)
	if err != nil {
		return err
	}
	data, err := EncodeProfiles(normalized)
	if err != nil {
		return err
	}
	if err := s.Ensure(); err != nil {
		return err
	}
	if err := writePrivateAtomic(s.ProfilesPath(), data); err != nil {
		return fmt.Errorf("save egress profiles: %w", err)
	}
	return nil
}

// Upsert inserts or replaces one profile by id.
func (s *Store) Upsert(profile EgressProfile) (EgressProfile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	doc, err := s.loadLocked()
	if err != nil {
		return EgressProfile{}, err
	}
	profileID := strings.TrimSpace(profile.ID)
	if profile.Version == 0 {
		profile.Version = 1
		for i := range doc.Profiles {
			if doc.Profiles[i].ID == profileID {
				profile.Version = doc.Profiles[i].Version + 1
				break
			}
		}
	}
	normalized, err := NormalizeProfile(profile)
	if err != nil {
		return EgressProfile{}, err
	}
	replaced := false
	for i := range doc.Profiles {
		if doc.Profiles[i].ID != normalized.ID {
			continue
		}
		doc.Profiles[i] = normalized
		replaced = true
		break
	}
	if !replaced {
		doc.Profiles = append(doc.Profiles, normalized)
	}
	if err := s.saveLocked(doc); err != nil {
		return EgressProfile{}, err
	}
	return normalized, nil
}

// Delete removes one profile by id.
func (s *Store) Delete(id string) error {
	if !validIdentifier(id) {
		return codedError(CodeInvalidID, ErrInvalidID, "profile id %q is invalid", id)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	doc, err := s.loadLocked()
	if err != nil {
		return err
	}
	for i := range doc.Profiles {
		if doc.Profiles[i].ID != id {
			continue
		}
		doc.Profiles = append(doc.Profiles[:i], doc.Profiles[i+1:]...)
		return s.saveLocked(doc)
	}
	return codedError(CodeProfileNotFound, ErrProfileNotFound, "profile %q does not exist", id)
}

// Find returns one profile by exact id.
func (s *Store) Find(id string) (EgressProfile, error) {
	if !validIdentifier(id) {
		return EgressProfile{}, codedError(CodeInvalidID, ErrInvalidID, "profile id %q is invalid", id)
	}
	doc, err := s.Load()
	if err != nil {
		return EgressProfile{}, err
	}
	for _, profile := range doc.Profiles {
		if profile.ID == id {
			return profile, nil
		}
	}
	return EgressProfile{}, codedError(CodeProfileNotFound, ErrProfileNotFound, "profile %q does not exist", id)
}

// SetSecret protects and stores one secret in egress/secrets.dat.
func (s *Store) SetSecret(ref, value string) error {
	if err := validateSecretRef(ref); err != nil {
		return err
	}
	if value == "" || len(value) > MaxSecretBytes || strings.ContainsAny(value, "\x00\r\n") {
		return codedError(CodeInvalidConfig, ErrInvalidConfig, "secret %q is invalid", ref)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	doc, err := s.loadSecretsLocked()
	if err != nil {
		return err
	}
	protected, err := clientidentity.ProtectSecret(value)
	if err != nil {
		return fmt.Errorf("protect egress secret %q: %w", ref, err)
	}
	if protected == "" {
		return codedError(CodeStore, ErrInvalidConfig, "protected secret %q is empty", ref)
	}
	doc.Secrets[ref] = protected
	return s.saveSecretsLocked(doc)
}

// GetSecret loads and strictly verifies one DPAPI-protected secret.
func (s *Store) GetSecret(ref string) (string, error) {
	if err := validateSecretRef(ref); err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	doc, err := s.loadSecretsLocked()
	if err != nil {
		return "", err
	}
	protected, ok := doc.Secrets[ref]
	if !ok || protected == "" {
		return "", codedError(CodeSecretNotFound, ErrSecretNotFound, "secret %q does not exist", ref)
	}
	value, err := clientidentity.UnprotectSecretStrict(protected)
	if err != nil {
		return "", fmt.Errorf("decrypt egress secret %q: %w", ref, err)
	}
	return value, nil
}

// HasSecret reports whether a readable protected secret exists.
func (s *Store) HasSecret(ref string) (bool, error) {
	value, err := s.GetSecret(ref)
	if errors.Is(err, ErrSecretNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return value != "", nil
}

// DeleteSecret removes one secret. Missing secrets are already absent.
func (s *Store) DeleteSecret(ref string) error {
	if err := validateSecretRef(ref); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	doc, err := s.loadSecretsLocked()
	if err != nil {
		return err
	}
	if _, exists := doc.Secrets[ref]; !exists {
		return nil
	}
	delete(doc.Secrets, ref)
	return s.saveSecretsLocked(doc)
}

func (s *Store) loadSecretsLocked() (secretDocument, error) {
	data, err := os.ReadFile(s.SecretsPath())
	if errors.Is(err, os.ErrNotExist) {
		return secretDocument{SchemaVersion: SecretSchemaVersion, Secrets: map[string]string{}}, nil
	}
	if err != nil {
		return secretDocument{}, fmt.Errorf("read egress secrets: %w", err)
	}
	if len(data) > MaxConfigBytes {
		return secretDocument{}, codedError(CodeStore, ErrInvalidConfig, "egress secrets file exceeds %d bytes", MaxConfigBytes)
	}
	var doc secretDocument
	if err := decodeStrictJSON(strings.NewReader(string(data)), &doc, MaxConfigBytes); err != nil {
		return secretDocument{}, fmt.Errorf("decode egress secrets: %w", err)
	}
	if doc.SchemaVersion != SecretSchemaVersion || doc.Secrets == nil {
		return secretDocument{}, codedError(CodeStore, ErrInvalidConfig, "unsupported egress secrets schema")
	}
	return doc, nil
}

func (s *Store) saveSecretsLocked(doc secretDocument) error {
	if doc.SchemaVersion == 0 {
		doc.SchemaVersion = SecretSchemaVersion
	}
	if doc.SchemaVersion != SecretSchemaVersion || doc.Secrets == nil {
		return codedError(CodeStore, ErrInvalidConfig, "unsupported egress secrets schema")
	}
	data, err := encodeStrictJSON(doc)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := s.Ensure(); err != nil {
		return err
	}
	if err := writePrivateAtomic(s.SecretsPath(), data); err != nil {
		return fmt.Errorf("save egress secrets: %w", err)
	}
	return nil
}

func validateSecretRef(ref string) error {
	if !validIdentifier(ref) {
		return codedError(CodeInvalidID, ErrInvalidID, "secret reference %q is invalid", ref)
	}
	return nil
}
