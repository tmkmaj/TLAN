package coreupdate

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
)

// ParsePublicKey accepts raw 32-byte Ed25519 keys, 64-character hex keys,
// base64 keys, or a PEM PKIX public key. Errors never include key material.
func ParsePublicKey(data []byte) (ed25519.PublicKey, error) {
	if len(data) == ed25519.PublicKeySize {
		return append(ed25519.PublicKey(nil), data...), nil
	}
	trimmed := bytes.TrimSpace(data)
	if block, _ := pem.Decode(trimmed); block != nil {
		if block.Type == "PUBLIC KEY" {
			if parsed, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
				if key, ok := parsed.(ed25519.PublicKey); ok && len(key) == ed25519.PublicKeySize {
					return append(ed25519.PublicKey(nil), key...), nil
				}
			}
		}
		if key, err := parseRawPublicKey(block.Bytes); err == nil {
			return key, nil
		}
	}
	if key, err := parseRawPublicKey(trimmed); err == nil {
		return key, nil
	}
	return nil, ErrInvalidPublicKey
}

// ParsePrivateKey accepts a raw 32-byte seed, a raw 64-byte Ed25519 private
// key, hex/base64 encodings of either, or a PKCS#8 PEM private key. It never
// includes the key material in an error.
func ParsePrivateKey(data []byte) (ed25519.PrivateKey, error) {
	if len(data) == ed25519.SeedSize {
		return ed25519.NewKeyFromSeed(data), nil
	}
	if len(data) == ed25519.PrivateKeySize {
		// A 64-character hex seed is text, while a 64-byte Ed25519 private
		// key is binary. Prefer the text interpretation only when the input is
		// unambiguously a hex-encoded 32-byte seed.
		if decoded, err := hex.DecodeString(string(data)); err == nil && len(decoded) == ed25519.SeedSize {
			return ed25519.NewKeyFromSeed(decoded), nil
		}
		return append(ed25519.PrivateKey(nil), data...), nil
	}
	trimmed := bytes.TrimSpace(data)
	if block, _ := pem.Decode(trimmed); block != nil {
		if parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
			if key, ok := parsed.(ed25519.PrivateKey); ok && len(key) == ed25519.PrivateKeySize {
				return append(ed25519.PrivateKey(nil), key...), nil
			}
		}
		if key, err := parseRawPrivateKey(block.Bytes); err == nil {
			return key, nil
		}
	}
	if key, err := parseRawPrivateKey(trimmed); err == nil {
		return key, nil
	}
	return nil, fmt.Errorf("%w: invalid private key", ErrInvalidPublicKey)
}

func parseRawPublicKey(data []byte) (ed25519.PublicKey, error) {
	if len(data) == ed25519.PublicKeySize {
		return append(ed25519.PublicKey(nil), data...), nil
	}
	if decoded, err := hex.DecodeString(string(data)); err == nil {
		if len(decoded) == ed25519.PublicKeySize {
			return ed25519.PublicKey(decoded), nil
		}
	}
	if decoded, err := base64.StdEncoding.Strict().DecodeString(string(data)); err == nil {
		if len(decoded) == ed25519.PublicKeySize {
			return ed25519.PublicKey(decoded), nil
		}
	}
	return nil, ErrInvalidPublicKey
}

func parseRawPrivateKey(data []byte) (ed25519.PrivateKey, error) {
	switch len(data) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(data), nil
	case ed25519.PrivateKeySize:
		return append(ed25519.PrivateKey(nil), data...), nil
	}
	if decoded, err := hex.DecodeString(string(data)); err == nil {
		if key, err := parseRawPrivateKey(decoded); err == nil {
			return key, nil
		}
	}
	if decoded, err := base64.StdEncoding.Strict().DecodeString(string(data)); err == nil {
		if key, err := parseRawPrivateKey(decoded); err == nil {
			return key, nil
		}
	}
	return nil, fmt.Errorf("%w: invalid private key", ErrInvalidPublicKey)
}

func ReadPublicKeyFile(path string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParsePublicKey(data)
}

func ReadPrivateKeyFile(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParsePrivateKey(data)
}
