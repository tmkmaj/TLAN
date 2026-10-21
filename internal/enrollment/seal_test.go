package enrollment

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

func TestMemberCredentialOnlyOpensWithDeviceKey(t *testing.T) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte(`{"token":"member_private"}`)
	e, err := Seal(base64.StdEncoding.EncodeToString(k.PublicKey().Bytes()), plain)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Open(base64.StdEncoding.EncodeToString(k.Bytes()), e)
	if err != nil || string(decoded) != string(plain) {
		t.Fatalf("decrypt failed: %v", err)
	}
	other, _ := ecdh.X25519().GenerateKey(rand.Reader)
	if _, err = Open(base64.StdEncoding.EncodeToString(other.Bytes()), e); err == nil {
		t.Fatal("another device decrypted credential")
	}
	raw, _ := base64.StdEncoding.DecodeString(e.Ciphertext)
	raw[len(raw)-1] ^= 1
	e.Ciphertext = base64.StdEncoding.EncodeToString(raw)
	if _, err = Open(base64.StdEncoding.EncodeToString(k.Bytes()), e); err == nil {
		t.Fatal("tampered credential accepted")
	}
}
