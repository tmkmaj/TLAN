package main

import (
	"testing"

	"github.com/private-radminlan/lanmesh/internal/clientidentity"
)

func TestBundledEndpointMigration(t *testing.T) {
	for _, oldURL := range []string{"https://relay.tmknetwork.online", "https://relay.tmknetwork.online:8443", "https://relay.tmknetwork.online:8443/"} {
		original := clientidentity.Settings{ServerURL: oldURL, STUNServer: "relay.tmknetwork.online:3478", Token: "member_saved", NetworkID: "net-saved", VirtualIP: "10.240.0.2", RelayOnly: true}
		got := migrateBundledSettings(original, defaultServerURL)
		want := original
		want.ServerURL = defaultServerURL
		want.STUNServer = "8.163.21.82:3478"
		if got != want {
			t.Fatalf("migration changed membership: %#v", got)
		}
	}
}

func TestEndpointMigrationIsScoped(t *testing.T) {
	for _, pair := range [][2]string{
		{"https://relay.tmknetwork.online:8443", "https://other.example:8443"},
		{"https://other.example:8443", defaultServerURL},
		{"http://relay.tmknetwork.online:8443", defaultServerURL},
		{"https://relay.tmknetwork.online:8443.evil.example", defaultServerURL},
		{defaultServerURL, defaultServerURL},
	} {
		original := clientidentity.Settings{ServerURL: pair[0], Token: "member_saved"}
		if got := migrateBundledSettings(original, pair[1]); got != original {
			t.Fatalf("unexpected migration from %s to %s", pair[0], pair[1])
		}
	}
}
