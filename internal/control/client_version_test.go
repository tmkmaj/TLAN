package control

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/private-radminlan/lanmesh/core"
	"github.com/private-radminlan/lanmesh/internal/clientapi"
	"github.com/private-radminlan/lanmesh/internal/clientidentity"
	"github.com/private-radminlan/lanmesh/internal/storage"
	"net/http/httptest"
)

func TestEvaluateClientVersion(t *testing.T) {
	tests := []struct {
		name     string
		required string
		reported string
		want     error
	}{
		{name: "gate disabled", required: "", reported: "v0.1.0", want: nil},
		{name: "exact match", required: "v0.7.0", reported: "v0.7.0", want: nil},
		{name: "newer", required: "v0.7.0", reported: "v0.8.1", want: nil},
		{name: "newer major", required: "v0.7.0", reported: "v1.0.0", want: nil},
		{name: "outdated patch", required: "v0.7.0", reported: "v0.6.9", want: errClientOutdated},
		{name: "outdated major", required: "v1.0.0", reported: "v0.9.9", want: errClientOutdated},
		{name: "unreported", required: "v0.7.0", reported: "", want: errClientVersionMissing},
		{name: "garbage", required: "v0.7.0", reported: "latest", want: errClientVersionUnreadable},
		{name: "beta below", required: "v1.0.0", reported: "v0.2.0-beta.1", want: nil},
		{name: "beta above", required: "v0.1.0", reported: "v0.2.0-rc.1", want: nil},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := evaluateClientVersion(test.required, test.reported)
			if test.want == nil {
				if err != nil {
					t.Fatalf("evaluateClientVersion(%q, %q) = %v, want nil", test.required, test.reported, err)
				}
				return
			}
			if !errors.Is(err, test.want) {
				t.Fatalf("evaluateClientVersion(%q, %q) = %v, want %v", test.required, test.reported, err, test.want)
			}
		})
	}
}

func TestServerRefusesOutdatedClients(t *testing.T) {
	store, err := storage.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.EnsurePrivateNetwork("Friends", "friends-secret-code", "10.245.0.0/24"); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer((&Server{Store: store, AdminToken: "admin-only", MinClientVersion: "v0.7.0"}).Handler())
	defer server.Close()

	identity, err := clientidentity.LoadOrCreate(filepath.Join(t.TempDir(), "identity.json"))
	if err != nil {
		t.Fatal(err)
	}
	api := clientapi.New(server.URL, "")
	membership, err := api.Enroll("friends-secret-code", identity.RegisterRequest(), identity.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	api.Token = membership.Token
	deviceID := core.DeviceID(membership.Member.ID)

	// A client that predates this feature reports nothing, so it cannot prove
	// it is current and must not be served.
	if _, err := api.Heartbeat(deviceID); err == nil {
		t.Fatal("gate let an unreported client through")
	}

	api.AgentVersion = "v0.6.0"
	if _, err := api.Heartbeat(deviceID); err == nil {
		t.Fatal("gate let an outdated client through")
	}
	if version, _ := store.ClientVersion(deviceID); version != "v0.6.0" {
		t.Fatalf("reported version was not recorded: %q", version)
	}

	api.AgentVersion = "v0.7.0"
	if _, err := api.Heartbeat(deviceID); err != nil {
		t.Fatalf("gate rejected a current client: %v", err)
	}

	// Beta builds are deliberately outside the release gate.
	api.AgentVersion = "v0.1.0-beta.1"
	if _, err := api.Heartbeat(deviceID); err != nil {
		t.Fatalf("gate rejected a beta client: %v", err)
	}
}
