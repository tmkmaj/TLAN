// Package enrollment protects member credentials with the existing device key.
package enrollment

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

type Envelope struct {
	PublicKey  string `json:"public_key"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

func Seal(publicKey string, plain []byte) (Envelope, error) {
	peerBytes, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		return Envelope{}, err
	}
	peer, err := ecdh.X25519().NewPublicKey(peerBytes)
	if err != nil {
		return Envelope{}, err
	}
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return Envelope{}, err
	}
	shared, err := key.ECDH(peer)
	if err != nil {
		return Envelope{}, err
	}
	aad := append(append([]byte("LANMesh enrollment v1\x00"), peerBytes...), key.PublicKey().Bytes()...)
	aeadKey := make([]byte, 32)
	if _, err = io.ReadFull(hkdf.New(sha256.New, shared, nil, aad), aeadKey); err != nil {
		return Envelope{}, err
	}
	aead, err := chacha20poly1305.New(aeadKey)
	if err != nil {
		return Envelope{}, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return Envelope{}, err
	}
	return Envelope{base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()), base64.StdEncoding.EncodeToString(nonce), base64.StdEncoding.EncodeToString(aead.Seal(nil, nonce, plain, aad))}, nil
}
func Open(privateKey string, envelope Envelope) ([]byte, error) {
	privateBytes, err := base64.StdEncoding.DecodeString(privateKey)
	if err != nil {
		return nil, err
	}
	key, err := ecdh.X25519().NewPrivateKey(privateBytes)
	if err != nil {
		return nil, err
	}
	peerBytes, err := base64.StdEncoding.DecodeString(envelope.PublicKey)
	if err != nil {
		return nil, err
	}
	peer, err := ecdh.X25519().NewPublicKey(peerBytes)
	if err != nil {
		return nil, err
	}
	shared, err := key.ECDH(peer)
	if err != nil {
		return nil, err
	}
	aad := append(append([]byte("LANMesh enrollment v1\x00"), key.PublicKey().Bytes()...), peerBytes...)
	aeadKey := make([]byte, 32)
	if _, err = io.ReadFull(hkdf.New(sha256.New, shared, nil, aad), aeadKey); err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.New(aeadKey)
	if err != nil {
		return nil, err
	}
	nonce, err := base64.StdEncoding.DecodeString(envelope.Nonce)
	if err != nil || len(nonce) != aead.NonceSize() {
		return nil, errors.New("invalid enrollment nonce")
	}
	ciphertext, err := base64.StdEncoding.DecodeString(envelope.Ciphertext)
	if err != nil || len(ciphertext) > 64*1024 {
		return nil, errors.New("invalid enrollment response")
	}
	return aead.Open(nil, nonce, ciphertext, aad)
}
