package clientidentity

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/private-radminlan/lanmesh/core"
)

const identityFileName = "identity.json"

// Identity is the client-side device identity. PrivateKey is only persisted
// locally and is never included in a control-plane request.
type Identity struct {
	DeviceID    core.DeviceID `json:"device_id"`
	DisplayName string        `json:"display_name,omitempty"`
	PrivateKey  string        `json:"private_key"`
	PublicKey   string        `json:"public_key"`
}

func DefaultPath() (string, error) {
	directory, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("locate client config directory: %w", err)
	}
	dir, err := configDirectory(directory)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, identityFileName), nil
}

func configDirectory(userConfig string) (string, error) {
	current := filepath.Join(userConfig, "TmkNetworkLAN")
	legacy := filepath.Join(userConfig, "LANMesh")
	for _, name := range []string{"identity.json", "settings.json"} {
		if _, err := os.Stat(filepath.Join(current, name)); err == nil {
			return current, nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("inspect client configuration: %w", err)
		}
	}
	for _, name := range []string{"identity.json", "settings.json"} {
		if _, err := os.Stat(filepath.Join(legacy, name)); err == nil {
			return legacy, nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("inspect existing client configuration: %w", err)
		}
	}
	return current, nil
}

func LoadOrCreate(path string) (Identity, error) {
	if strings.TrimSpace(path) == "" {
		var err error
		path, err = DefaultPath()
		if err != nil {
			return Identity{}, err
		}
	}
	contents, err := os.ReadFile(path)
	if err == nil {
		var identity Identity
		if err := json.Unmarshal(contents, &identity); err != nil {
			return Identity{}, fmt.Errorf("decode client identity: %w", err)
		}
		identity.PrivateKey, err = UnprotectSecret(identity.PrivateKey)
		if err != nil {
			return Identity{}, fmt.Errorf("decrypt local identity: %w", err)
		}
		if err := identity.Validate(); err != nil {
			return Identity{}, fmt.Errorf("validate client identity: %w", err)
		}
		return identity, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return Identity{}, fmt.Errorf("read client identity: %w", err)
	}
	identity, err := newIdentity()
	if err != nil {
		return Identity{}, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return Identity{}, fmt.Errorf("create client config directory: %w", err)
	}
	stored := identity
	stored.PrivateKey, err = ProtectSecret(stored.PrivateKey)
	if err != nil {
		return Identity{}, err
	}
	encoded, err := json.MarshalIndent(stored, "", "  ")
	if err != nil {
		return Identity{}, fmt.Errorf("encode client identity: %w", err)
	}
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		return Identity{}, fmt.Errorf("write client identity: %w", err)
	}
	return identity, nil
}

func fmtSecretError() error { return errors.New("invalid protected secret") }

func (i Identity) Validate() error {
	if err := i.DeviceID.Validate(); err != nil {
		return err
	}
	privateKey, err := decodeKey(i.PrivateKey)
	if err != nil {
		return fmt.Errorf("private key: %w", err)
	}
	publicKey, err := decodeKey(i.PublicKey)
	if err != nil {
		return fmt.Errorf("public key: %w", err)
	}
	derived, err := ecdh.X25519().NewPrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("private key: %w", err)
	}
	if !equalBytes(derived.PublicKey().Bytes(), publicKey) {
		return errors.New("public key does not match private key")
	}
	return nil
}

func (i Identity) RegisterRequest() core.RegisterDeviceRequest {
	return core.RegisterDeviceRequest{DeviceID: i.DeviceID, WireGuardPublicKey: i.PublicKey, DisplayName: i.DisplayName}
}

func newIdentity() (Identity, error) {
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return Identity{}, fmt.Errorf("generate WireGuard key: %w", err)
	}
	deviceIDBytes := make([]byte, 8)
	if _, err := rand.Read(deviceIDBytes); err != nil {
		return Identity{}, fmt.Errorf("generate device ID: %w", err)
	}
	identity := Identity{
		DeviceID:   core.DeviceID("dev-" + hex.EncodeToString(deviceIDBytes)),
		PrivateKey: base64.StdEncoding.EncodeToString(privateKey.Bytes()),
		PublicKey:  base64.StdEncoding.EncodeToString(privateKey.PublicKey().Bytes()),
	}
	return identity, nil
}

func decodeKey(value string) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(decoded) != 32 || base64.StdEncoding.EncodeToString(decoded) != value {
		return nil, errors.New("must be canonical base64 encoding of 32 bytes")
	}
	return decoded, nil
}

func equalBytes(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}
