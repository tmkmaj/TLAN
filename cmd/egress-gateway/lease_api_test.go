package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveLeaseEndpoint(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    string
		wantErr bool
	}{
		{name: "empty local", raw: "", want: "http://127.0.0.1:0"},
		{name: "loopback http", raw: "http://127.0.0.1:0", want: "http://127.0.0.1:0"},
		{name: "loopback http ipv6", raw: "http://[::1]:8080", want: "http://[::1]:8080"},
		{name: "https hostname", raw: "https://gateway.example:7443", want: "https://gateway.example:7443"},
		{name: "http wildcard", raw: "http://0.0.0.0:8080", wantErr: true},
		{name: "http hostname", raw: "http://localhost:8080", wantErr: true},
		{name: "https unspecified", raw: "https://0.0.0.0:443", wantErr: true},
		{name: "missing host", raw: "https://:443", wantErr: true},
		{name: "unsupported scheme", raw: "ftp://127.0.0.1:21", wantErr: true},
		{name: "path", raw: "http://127.0.0.1:8080/api", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			endpoint, err := resolveLeaseEndpoint(test.raw)
			if test.wantErr {
				if err == nil {
					t.Fatalf("resolveLeaseEndpoint(%q) unexpectedly succeeded: %+v", test.raw, endpoint)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveLeaseEndpoint(%q): %v", test.raw, err)
			}
			got := endpoint.Scheme + "://" + endpoint.Addr
			if got != test.want {
				t.Fatalf("resolved endpoint = %q, want %q", got, test.want)
			}
		})
	}
}

func TestBearerAuthenticator(t *testing.T) {
	materials := writeTestMaterials(t)
	authenticator, err := loadBearerAuthenticator(materials.tokenPath)
	if err != nil {
		t.Fatalf("load bearer authenticator: %v", err)
	}

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("Authorization", "Bearer "+materials.token)
	deviceID, err := authenticator.Authenticate(request)
	if err != nil {
		t.Fatalf("authenticate valid token: %v", err)
	}
	if !strings.HasPrefix(deviceID, "bearer_") || len(deviceID) == len("bearer_") {
		t.Fatalf("unexpected derived device id %q", deviceID)
	}

	request.Header.Set("Authorization", "Bearer wrong-token")
	if _, err := authenticator.Authenticate(request); err == nil {
		t.Fatal("wrong bearer token was accepted")
	}
	request.Header.Set("Authorization", "Basic "+materials.token)
	if _, err := authenticator.Authenticate(request); err == nil {
		t.Fatal("non-bearer authorization was accepted")
	}
	if _, err := authenticator.Authenticate(httptest.NewRequest(http.MethodGet, "/", nil)); err == nil {
		t.Fatal("missing authorization was accepted")
	}
}

func TestBearerAuthenticatorRejectsShortToken(t *testing.T) {
	path := filepath.Join(t.TempDir(), "short-token")
	if err := os.WriteFile(path, []byte("short\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadBearerAuthenticator(path); err == nil {
		t.Fatal("short bearer token was accepted")
	}
}

func TestValidateLeaseBoundAddress(t *testing.T) {
	wildcard, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("listen on wildcard: %v", err)
	}
	defer wildcard.Close()
	if err := validateLeaseBoundAddress(wildcard); err == nil {
		t.Fatal("wildcard lease listener was accepted")
	}

	loopback, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen on loopback: %v", err)
	}
	defer loopback.Close()
	if err := validateLeaseBoundAddress(loopback); err != nil {
		t.Fatalf("loopback lease listener rejected: %v", err)
	}
}
