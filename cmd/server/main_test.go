package main

import (
	"net"
	"strings"
	"testing"

	"github.com/private-radminlan/lanmesh/internal/config"
)

func TestAdminListenerDisabled(t *testing.T) {
	listener, secure, err := adminListener(config.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if listener != nil {
		t.Fatalf("disabled admin listener = %v", listener)
	}
	if secure {
		t.Fatal("disabled admin listener reported TLS")
	}
}

func TestAdminListenerRequiresPairedTLSFiles(t *testing.T) {
	cfg := config.Config{}
	cfg.Server.AdminListen = "127.0.0.1:0"
	cfg.Server.AdminTLSCert = "admin.crt"
	if _, _, err := adminListener(cfg); err == nil || !strings.Contains(err.Error(), "must be set together") {
		t.Fatalf("unpaired admin TLS error = %v", err)
	}
}

func TestAdminListenerLoopbackPlaintext(t *testing.T) {
	cfg := config.Config{}
	cfg.Server.AdminListen = "127.0.0.1:0"
	listener, secure, err := adminListener(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if secure {
		t.Fatal("plaintext admin listener reported TLS")
	}
	if !isLoopbackAddress(listener.Addr().String()) {
		t.Fatalf("listener address %q is not loopback", listener.Addr())
	}
}

func TestIsLoopbackAddress(t *testing.T) {
	tests := []struct {
		address string
		want    bool
	}{
		{"127.0.0.1:8081", true},
		{"[::1]:8081", true},
		{"localhost:8081", true},
		{"10.10.0.20:8081", false},
		{":8081", false},
		{"not-an-address", false},
	}
	for _, test := range tests {
		if got := isLoopbackAddress(test.address); got != test.want {
			t.Errorf("isLoopbackAddress(%q) = %v, want %v", test.address, got, test.want)
		}
	}
}
func TestAdminListenerRequiresInsecureOptIn(t *testing.T) {
	cfg := config.Config{}
	cfg.Server.AdminListen = "0.0.0.0:0"
	if _, _, err := adminListener(cfg); err == nil || !strings.Contains(err.Error(), "admin_allow_insecure_http") {
		t.Fatalf("non-loopback plaintext error = %v", err)
	}
}

func TestAdminListenerAllowsExplicitInsecureOptIn(t *testing.T) {
	cfg := config.Config{}
	cfg.Server.AdminListen = "0.0.0.0:0"
	cfg.Server.AdminAllowInsecureHTTP = true
	listener, secure, err := adminListener(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if secure {
		t.Fatal("explicit plaintext listener reported TLS")
	}
}
func TestAdminListenerReportsAddressInUse(t *testing.T) {
	blocker, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close()
	cfg := config.Config{}
	cfg.Server.AdminListen = blocker.Addr().String()
	if _, _, err := adminListener(cfg); err == nil || !strings.Contains(err.Error(), "listen for admin console") {
		t.Fatalf("address-in-use error = %v", err)
	}
}
