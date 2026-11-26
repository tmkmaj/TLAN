package main

import (
	"testing"

	"github.com/private-radminlan/lanmesh/internal/clientidentity"
)

func TestBundledEndpointMigration(t *testing.T) {
	original := clientidentity.Settings{ServerURL: "https://tlan.example.com:8443", STUNServer: "tlan.example.com:3478", Token: "member_saved", NetworkID: "net-saved", VirtualIP: "10.240.0.2", RelayOnly: true}
	if got := migrateBundledSettings(original, defaultServerURL); got != original {
		t.Fatalf("migration unexpectedly changed settings: %#v", got)
	}
}

func TestEndpointMigrationIsScoped(t *testing.T) {
	for _, pair := range [][2]string{
		{"https://vpn.example.com:8443", "https://other.example:8443"},
		{"https://other.example:8443", defaultServerURL},
		{defaultServerURL, defaultServerURL},
	} {
		original := clientidentity.Settings{ServerURL: pair[0], Token: "member_saved"}
		if got := migrateBundledSettings(original, pair[1]); got != original {
			t.Fatalf("unexpected migration from %s to %s", pair[0], pair[1])
		}
	}
}

func TestNormalizeServerURL(t *testing.T) {
	tests := []struct{ name, input, want string }{
		{"https domain", "https://vpn.example.com:8443/", "https://vpn.example.com:8443"},
		{"http loopback", "http://127.0.0.1:8080/", "http://127.0.0.1:8080"},
		{"ipv6", "https://[2001:db8::1]:8443/", "https://[2001:db8::1]:8443"},
		{"default https port", "https://vpn.example.com", "https://vpn.example.com"},
		{"bare ipv4:port", "203.0.113.10:8443", "https://203.0.113.10:8443"},
		{"bare domain:port", "vpn.example.com:8443", "https://vpn.example.com:8443"},
		{"bare ipv6:port", "[2001:db8::1]:8443", "https://[2001:db8::1]:8443"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := normalizeServerURL(test.input)
			if err != nil || got != test.want {
				t.Fatalf("normalizeServerURL(%q)=%q, %v; want %q", test.input, got, err, test.want)
			}
		})
	}
	for _, input := range []string{"", "vpn.example.com", ":8443", "203.0.113.10:0", "203.0.113.10:70000", "ftp://vpn.example.com", "https://", "https://user:pass@vpn.example.com", "https://vpn.example.com/path", "https://vpn.example.com/?x=1", "https://vpn.example.com/#x", "https://vpn.example.com/a b"} {
		t.Run("reject "+input, func(t *testing.T) {
			if got, err := normalizeServerURL(input); err == nil {
				t.Fatalf("normalizeServerURL(%q)=%q accepted invalid input", input, got)
			}
		})
	}
}

func TestDisplayServerEndpoint(t *testing.T) {
	if got := displayServerEndpoint("https://203.0.113.10:8443/"); got != "203.0.113.10:8443" {
		t.Fatalf("displayServerEndpoint(https) = %q", got)
	}
	if got := displayServerEndpoint("http://127.0.0.1:8080/"); got != "http://127.0.0.1:8080" {
		t.Fatalf("displayServerEndpoint(http) = %q", got)
	}
}

func TestSTUNAddressForServer(t *testing.T) {
	for _, test := range []struct{ server, want string }{
		{"https://vpn.example.com:8443", "vpn.example.com:3478"},
		{"http://127.0.0.1:8080", "127.0.0.1:3478"},
		{"https://[2001:db8::1]:8443", "[2001:db8::1]:3478"},
	} {
		got, err := STUNAddressForServer(test.server)
		if err != nil || got != test.want {
			t.Fatalf("STUNAddressForServer(%q)=%q, %v; want %q", test.server, got, err, test.want)
		}
	}
}

func TestStartupServerPrefersExplicitFlag(t *testing.T) {
	saved := "https://saved.example:8443"
	if got := startupServer(saved, defaultServerURL, false); got != saved {
		t.Fatalf("saved startup server=%q", got)
	}
	if got := startupServer(saved, "https://flag.example:8443", true); got != "https://flag.example:8443" {
		t.Fatalf("flag startup server=%q", got)
	}
	if got := startupServer("", defaultServerURL, false); got != defaultServerURL {
		t.Fatalf("default startup server=%q", got)
	}
}

func TestConnectionEndpointsValidateAndDeriveSTUN(t *testing.T) {
	server, stun, err := connectionEndpoints("https://vpn.example.com:8443/", "")
	if err != nil || server != "https://vpn.example.com:8443" || stun != "vpn.example.com:3478" {
		t.Fatalf("connectionEndpoints=%q, %q, %v", server, stun, err)
	}
	server, stun, err = connectionEndpoints("http://127.0.0.1:8080", "127.0.0.1:4000")
	if err != nil || server != "http://127.0.0.1:8080" || stun != "127.0.0.1:4000" {
		t.Fatalf("explicit connectionEndpoints=%q, %q, %v", server, stun, err)
	}
	for _, value := range []string{"stun.example.com", "stun.example.com:0", "stun.example.com:65536", ":3478", "[2001:db8::1:3478", "stun example.com:3478", "stun.example.com: 3478"} {
		if _, _, err := connectionEndpoints("https://vpn.example.com", value); err == nil {
			t.Fatalf("accepted invalid STUN address %q", value)
		}
	}
}

func TestSavedCredentialsOnlyMatchNormalizedServer(t *testing.T) {
	settings := clientidentity.Settings{ServerURL: "https://vpn.example.com:8443/", Token: "member_saved", AdminToken: "admin_saved"}
	token, admin := savedCredentialsForServer(settings, "https://vpn.example.com:8443")
	if token != "member_saved" || admin != "admin_saved" {
		t.Fatalf("matching credentials=%q, %q", token, admin)
	}
	token, admin = savedCredentialsForServer(settings, "https://other.example:8443")
	if token != "" || admin != "" {
		t.Fatalf("cross-server credentials leaked=%q, %q", token, admin)
	}
}
