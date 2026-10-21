package main

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/private-radminlan/lanmesh/internal/config"
)

func TestPreparePreservesExistingNetworkAndState(t *testing.T) {
	dir := t.TempDir()
	source, target := filepath.Join(dir, "config.yml"), filepath.Join(dir, "prepared.yml")
	before, _, err := config.LoadOrCreate(source)
	if err != nil {
		t.Fatal(err)
	}
	original, _ := os.ReadFile(source)
	if err := prepare(source, target); err != nil {
		t.Fatal(err)
	}
	after, err := config.LoadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if before != after {
		t.Fatalf("configuration unexpectedly changed: %+v", after.Server)
	}
	unchanged, _ := os.ReadFile(source)
	if !bytes.Equal(original, unchanged) {
		t.Fatal("source was modified")
	}
}

func TestPrepareMigratesOnlyControlTLS(t *testing.T) {
	dir := t.TempDir()
	source, target := filepath.Join(dir, "config.yml"), filepath.Join(dir, "prepared.yml")
	_, _, err := config.LoadOrCreate(source)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(source)
	b = bytes.Replace(b, []byte("listen: 127.0.0.1:8080"), []byte("listen: ':443'"), 1)
	b = bytes.Replace(b, []byte("tls_cert: \"\""), []byte("tls_cert: cert.pem"), 1)
	b = bytes.Replace(b, []byte("tls_key: \"\""), []byte("tls_key: key.pem"), 1)
	if err := os.WriteFile(source, b, 0600); err != nil {
		t.Fatal(err)
	}
	before, err := config.LoadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := prepare(source, target); err != nil {
		t.Fatal(err)
	}
	after, err := config.LoadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	before.Server.Listen, before.Server.TLSCert, before.Server.TLSKey = "127.0.0.1:8080", "", ""
	if before != after {
		t.Fatal("migration changed unrelated settings")
	}
}

func TestPrepareLegacyStateAndInvalidConfig(t *testing.T) {
	dir := t.TempDir()
	source, target := filepath.Join(dir, "config.yml"), filepath.Join(dir, "prepared.yml")
	if err := os.WriteFile(filepath.Join(dir, "state.json"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := prepare(source, target); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Storage.DataDir != "." {
		t.Fatal("legacy member state would be lost")
	}
	if _, err := os.Stat(source); !os.IsNotExist(err) {
		t.Fatal("preflight created source config")
	}
	if err := os.WriteFile(source, []byte("invalid: true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := prepare(source, target); err == nil {
		t.Fatal("accepted invalid config")
	}
}

func TestPrepareRejectsSharedStorage(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "config.yml")
	_, _, err := config.LoadOrCreate(source)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(source)
	b = bytes.Replace(b, []byte("data_dir: ./data"), []byte("data_dir: .."), 1)
	if err := os.WriteFile(source, b, 0600); err != nil {
		t.Fatal(err)
	}
	if err := prepare(source, filepath.Join(dir, "prepared.yml")); err == nil {
		t.Fatal("accepted a shared parent directory")
	}
}

func TestVerifyELFRejectsDynamicLoaderAndWrongArchitecture(t *testing.T) {
	for _, test := range []struct {
		name           string
		machine        uint16
		dynamic, valid bool
	}{
		{"static", uint16(elf.EM_X86_64), false, true},
		{"dynamic", uint16(elf.EM_X86_64), true, false},
		{"arm", uint16(elf.EM_AARCH64), false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			b := make([]byte, 120)
			copy(b, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
			binary.LittleEndian.PutUint16(b[16:], 2)
			binary.LittleEndian.PutUint16(b[18:], test.machine)
			binary.LittleEndian.PutUint32(b[20:], 1)
			binary.LittleEndian.PutUint64(b[32:], 64)
			binary.LittleEndian.PutUint16(b[52:], 64)
			binary.LittleEndian.PutUint16(b[54:], 56)
			if test.dynamic {
				binary.LittleEndian.PutUint16(b[56:], 1)
				binary.LittleEndian.PutUint32(b[64:], uint32(elf.PT_INTERP))
			}
			path := filepath.Join(t.TempDir(), "binary")
			if err := os.WriteFile(path, b, 0600); err != nil {
				t.Fatal(err)
			}
			err := verifyELF(path)
			if (err == nil) != test.valid {
				t.Fatalf("valid=%v err=%v", test.valid, err)
			}
		})
	}
}
