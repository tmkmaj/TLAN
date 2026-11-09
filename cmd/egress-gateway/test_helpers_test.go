package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/private-radminlan/lanmesh/internal/egressgateway"
)

type fakeNAT struct {
	mu            sync.Mutex
	detectCalls   int
	planCalls     int
	applyCalls    int
	rollbackCalls int
	capabilities  egressgateway.NATCapabilities
	plan          string
	detectErr     error
	planErr       error
	applyErr      error
	rollbackErr   error
}

func newFakeNAT() *fakeNAT {
	return &fakeNAT{
		capabilities: egressgateway.NATCapabilities{
			PlatformSupported:  true,
			NFTables:           true,
			IPForwardStateRead: true,
			Backend:            egressgateway.NATBackendNFTables,
		},
		plan: "backend: fake\nsource_cidr: 10.250.0.0/24\n",
	}
}

func (n *fakeNAT) DetectCapabilities(context.Context) (egressgateway.NATCapabilities, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.detectCalls++
	return n.capabilities, n.detectErr
}

func (n *fakeNAT) Plan(context.Context) (string, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.planCalls++
	return n.plan, n.planErr
}

func (n *fakeNAT) Apply(context.Context) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.applyCalls++
	return n.applyErr
}

func (n *fakeNAT) Rollback(context.Context) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.rollbackCalls++
	return n.rollbackErr
}

func (n *fakeNAT) counts() (detect, plan, apply, rollback int) {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.detectCalls, n.planCalls, n.applyCalls, n.rollbackCalls
}

type testMaterials struct {
	dir       string
	certPath  string
	keyPath   string
	tokenPath string
	token     string
}

func writeTestMaterials(t *testing.T) testMaterials {
	t.Helper()
	dir := t.TempDir()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate private key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	certPath := filepath.Join(dir, "server.crt")
	keyPath := filepath.Join(dir, "server.key")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("test-bearer-token-", 3)
	tokenPath := filepath.Join(dir, "lease-secret.txt")
	if err := os.WriteFile(tokenPath, []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return testMaterials{
		dir:       dir,
		certPath:  certPath,
		keyPath:   keyPath,
		tokenPath: tokenPath,
		token:     token,
	}
}

func writeTestConfig(t *testing.T, materials testMaterials) string {
	t.Helper()
	stateDir := filepath.Join(materials.dir, "state")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	config := fmt.Sprintf(`listen: "127.0.0.1:0"
state_dir: %q
tls_cert: %q
tls_key: %q
control:
  lease_url: "http://127.0.0.1:0"
  lease_secret_file: %q
egress:
  interface: "eth0"
  ipv4_cidr: "10.250.0.0/24"
  dns_servers: ["1.1.1.1"]
  enable_ip_forward: true
limits:
  max_sessions: 16
  max_connections_per_lease: 8
  max_bytes_per_lease: 1048576
  max_rate_bps: 1048576
policy:
  allow_cidrs: ["0.0.0.0/0"]
  deny_private: true
  deny_metadata: true
  deny_ports: [22, 25]
  ipv6_policy: "block"
  dns_policy: "remote"
`, stateDir, materials.certPath, materials.keyPath, materials.tokenPath)
	path := filepath.Join(materials.dir, "gateway.yml")
	if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func loadTestConfig(t *testing.T) (gatewayConfig, testMaterials) {
	t.Helper()
	materials := writeTestMaterials(t)
	path := writeTestConfig(t, materials)
	config, err := loadConfig(path)
	if err != nil {
		t.Fatalf("load test config: %v", err)
	}
	return config, materials
}

func testLeasePolicy() egressgateway.Policy {
	return egressgateway.Policy{
		Version:            1,
		AllowedProtocols:   []egressgateway.Protocol{egressgateway.ProtocolTCP, egressgateway.ProtocolUDP},
		AllowedTargetCIDRs: []string{"203.0.113.0/24"},
		IPv6Policy:         egressgateway.IPv6PolicyBlock,
		DNSPolicy:          egressgateway.DNSPolicyBlock,
		Limits: egressgateway.Limits{
			MaxConnections: 8,
			MaxBytes:       1048576,
			MaxRateBPS:     1048576,
		},
	}
}
