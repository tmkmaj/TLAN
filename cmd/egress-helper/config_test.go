package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/private-radminlan/lanmesh/internal/egress"
)

func writeTestCA(t *testing.T, path string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "egress-helper test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func validCLIOptions(t *testing.T) cliOptions {
	t.Helper()
	dir := t.TempDir()
	capabilityPath := filepath.Join(dir, "capability.txt")
	caPath := filepath.Join(dir, "ca.pem")
	writePrivateTestFile(t, capabilityPath, []byte("one-time-capability\n"))
	writeTestCA(t, caPath)
	return cliOptions{
		ListenAddr:     "127.0.0.1:1080",
		ServerAddr:     "gateway.example.com:443",
		ServerName:     "gateway.example.com",
		CAPath:         caPath,
		ProfileID:      "profile-test",
		RuleID:         "rule-test",
		DeviceID:       "device-test",
		LeaseID:        "lease-test",
		PolicyVersion:  1,
		CapabilityFile: capabilityPath,
		MaxConnections: 64,
	}
}

func TestLoadRuntimeConfigReadsPrivateSecretsAndCA(t *testing.T) {
	options := validCLIOptions(t)
	cfg, roots, err := loadRuntimeConfig(options)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Capability != "one-time-capability" {
		t.Fatalf("capability = %q, want trimmed token", cfg.Capability)
	}
	if cfg.Password != "" {
		t.Fatalf("password = %q, want empty", cfg.Password)
	}
	if roots == nil || len(roots.Subjects()) != 1 {
		t.Fatalf("root pool subjects = %d, want 1", len(roots.Subjects()))
	}
}

func TestLoadRuntimeConfigReadsOptionalPasswordFile(t *testing.T) {
	options := validCLIOptions(t)
	options.Username = "alice"
	options.PasswordFile = filepath.Join(t.TempDir(), "password.txt")
	writePrivateTestFile(t, options.PasswordFile, []byte("correct horse battery staple\r\n"))
	cfg, _, err := loadRuntimeConfig(options)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Password != "correct horse battery staple" {
		t.Fatalf("password = %q, want trimmed password", cfg.Password)
	}
}

func TestLoadRuntimeConfigRejectsInsecureCapabilityFile(t *testing.T) {
	options := validCLIOptions(t)
	writeInsecureTestFile(t, options.CapabilityFile, []byte("capability"))
	if _, _, err := loadRuntimeConfig(options); err == nil || !strings.Contains(strings.ToLower(err.Error()), "private") {
		t.Fatalf("loadRuntimeConfig error = %v, want private-file rejection", err)
	}
}

func TestLoadRuntimeConfigRejectsEmptyCapabilityFile(t *testing.T) {
	options := validCLIOptions(t)
	writePrivateTestFile(t, options.CapabilityFile, []byte("\r\n"))
	if _, _, err := loadRuntimeConfig(options); err == nil {
		t.Fatal("empty capability file was accepted")
	}
}

func TestLoadRuntimeConfigRejectsUnreadableCA(t *testing.T) {
	options := validCLIOptions(t)
	options.CAPath = filepath.Join(t.TempDir(), "missing.pem")
	if _, _, err := loadRuntimeConfig(options); err == nil {
		t.Fatal("missing CA file was accepted")
	}
}

func TestLoadRuntimeConfigRequiresPasswordFileForUsername(t *testing.T) {
	options := validCLIOptions(t)
	options.Username = "alice"
	if _, _, err := loadRuntimeConfig(options); err == nil {
		t.Fatal("username without password file was accepted")
	}
	options.PasswordFile = filepath.Join(t.TempDir(), "missing.txt")
	if _, _, err := loadRuntimeConfig(options); err == nil {
		t.Fatal("missing password file was accepted")
	}
}

func TestLoadRuntimeConfigRejectsPasswordWithoutUsername(t *testing.T) {
	options := validCLIOptions(t)
	options.PasswordFile = filepath.Join(t.TempDir(), "password.txt")
	writePrivateTestFile(t, options.PasswordFile, []byte("secret"))
	if _, _, err := loadRuntimeConfig(options); err == nil {
		t.Fatal("password file without username was accepted")
	}
}

func TestLoadRuntimeConfigValidatesServerAndIdentifiers(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*cliOptions)
	}{
		{name: "empty server", mutate: func(o *cliOptions) { o.ServerAddr = "" }},
		{name: "server without port", mutate: func(o *cliOptions) { o.ServerAddr = "gateway.example.com" }},
		{name: "empty server name", mutate: func(o *cliOptions) { o.ServerName = "" }},
		{name: "empty profile", mutate: func(o *cliOptions) { o.ProfileID = "" }},
		{name: "zero policy", mutate: func(o *cliOptions) { o.PolicyVersion = 0 }},
		{name: "zero max", mutate: func(o *cliOptions) { o.MaxConnections = 0 }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			options := validCLIOptions(t)
			tt.mutate(&options)
			if _, _, err := loadRuntimeConfig(options); err == nil {
				t.Fatal("invalid configuration was accepted")
			}
		})
	}
}

func TestParseCLIRejectsCapabilityOnCommandLine(t *testing.T) {
	_, err := parseCLI([]string{"-capability", "secret"})
	if err == nil {
		t.Fatal("unknown -capability flag was accepted")
	}
}

func TestParseCLICheckMode(t *testing.T) {
	args := []string{
		"-check",
		"-listen", "127.0.0.1:1080",
		"-server", "gateway.example.com:443",
		"-servername", "gateway.example.com",
		"-ca", "ca.pem",
		"-profile", "profile-test",
		"-rule", "rule-test",
		"-device", "device-test",
		"-lease", "lease-test",
		"-policy-version", "1",
		"-capability-file", "capability.txt",
	}
	options, err := parseCLI(args)
	if err != nil {
		t.Fatal(err)
	}
	if !options.Check || options.MaxConnections != 64 {
		t.Fatalf("options = %+v, want check mode and default max connections", options)
	}
}

func TestForwardUDPDatagramUsesEgressEnvelope(t *testing.T) {
	fake := &fakeTunnel{}
	p, err := newProxy(testProxyConfig(), fake)
	if err != nil {
		t.Fatal(err)
	}
	p.markReady()
	packet := []byte{0, 0, 0, 3, byte(len("dns.example")), 'd', 'n', 's', '.', 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0, 53, 'p', 'a', 'y'}
	if err := p.forwardSOCKS5UDPDatagram(context.Background(), packet); err != nil {
		t.Fatal(err)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.datagrams) != 1 {
		t.Fatalf("sent datagrams = %d, want 1", len(fake.datagrams))
	}
	target, payload, err := egress.DecodeDatagram(fake.datagrams[0])
	if err != nil {
		t.Fatal(err)
	}
	if target.Host != "dns.example" || target.Port != 53 || !bytes.Equal(payload, []byte("pay")) {
		t.Fatalf("decoded datagram = (%+v, %q)", target, payload)
	}
}

func TestMarkFailedClosesActiveConnections(t *testing.T) {
	p, err := newProxy(testProxyConfig(), &fakeTunnel{})
	if err != nil {
		t.Fatal(err)
	}
	p.markReady()
	client, server := net.Pipe()
	if !p.addConnection(server) {
		t.Fatal("could not track active connection")
	}
	p.markFailed(errors.New("session failed"))
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	buffer := make([]byte, 1)
	if _, readErr := client.Read(buffer); readErr == nil {
		t.Fatal("active connection remained open after session failure")
	}
	if p.isReady() {
		t.Fatal("proxy reports ready after failure")
	}
}

func TestConnectionSlotsAreBounded(t *testing.T) {
	cfg := testProxyConfig()
	cfg.MaxConnections = 2
	p, err := newProxy(cfg, &fakeTunnel{})
	if err != nil {
		t.Fatal(err)
	}
	if !p.acquireSlot() || !p.acquireSlot() {
		t.Fatal("could not acquire configured slots")
	}
	if p.acquireSlot() {
		t.Fatal("acquired more slots than configured")
	}
	p.releaseSlot()
	if !p.acquireSlot() {
		t.Fatal("slot was not released")
	}
}
