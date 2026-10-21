package mesh

import (
	"context"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/private-radminlan/lanmesh/internal/clientapi"
	"github.com/private-radminlan/lanmesh/internal/clientidentity"
	"github.com/private-radminlan/lanmesh/internal/control"
	"github.com/private-radminlan/lanmesh/internal/network"
	"github.com/private-radminlan/lanmesh/internal/platform"
	"github.com/private-radminlan/lanmesh/internal/storage"
)

func TestEngineTracksTransportResourcesAndCleansThem(t *testing.T) {
	ledger := platform.NewMemoryLedger()
	engine := &Engine{
		instanceID: "instance-a",
		ledger:     ledger,
		options:    Options{Network: clientapi.Network{CIDR: "10.44.0.0/24"}},
	}
	if err := engine.registerTransportResources(); err != nil {
		t.Fatal(err)
	}
	resources := engine.Resources()
	if len(resources) != 2 {
		t.Fatalf("resources = %#v", resources)
	}
	seen := make(map[platform.ResourceType]bool)
	for _, record := range resources {
		if record.InstanceID != "instance-a" || record.Owner == "" || record.Prefix != "10.44.0.0/24" {
			t.Fatalf("resource = %#v", record)
		}
		seen[record.Type] = true
	}
	if !seen[platform.ResourceWireGuardTransport] || !seen[platform.ResourcePlainTransport] {
		t.Fatalf("transport types = %#v", seen)
	}
	if err := engine.closeTransportResources(); err != nil {
		t.Fatal(err)
	}
	if len(engine.Resources()) != 0 {
		t.Fatalf("resources after close = %#v", engine.Resources())
	}
}

func TestEngineResourcesOnlyReturnsCurrentInstance(t *testing.T) {
	ledger := platform.NewMemoryLedger()
	for _, instanceID := range []string{"instance-a", "instance-b"} {
		record, err := platform.NewResourceRecord(instanceID, platform.ResourcePlainTransport, "plain", "10.44.0.0/24", "")
		if err != nil {
			t.Fatal(err)
		}
		if err := ledger.Add(record); err != nil {
			t.Fatal(err)
		}
	}
	engine := &Engine{instanceID: "instance-a", ledger: ledger}
	resources := engine.Resources()
	if len(resources) != 1 || resources[0].InstanceID != "instance-a" {
		t.Fatalf("resources = %#v", resources)
	}
}

func TestEngineRecoveryStatusReturnsCopy(t *testing.T) {
	engine := &Engine{recovery: platform.RecoveryStatus{
		Failed: 1,
		Issues: []platform.ResourceRecoveryIssue{{Error: "original", Unproven: false}},
	}}
	status := engine.RecoveryStatus()
	status.Issues[0].Error = "mutated"
	if engine.recovery.Issues[0].Error != "original" {
		t.Fatal("RecoveryStatus exposed mutable ledger state")
	}
}

func TestEngineTransportRegistrationFailureDoesNotClaimResource(t *testing.T) {
	ledger := platform.NewMemoryLedger()
	ledger.SetPersistenceError(errTestPersistence)
	engine := &Engine{
		instanceID: "instance-a",
		ledger:     ledger,
		options:    Options{Network: clientapi.Network{CIDR: "10.44.0.0/24"}},
	}
	if err := engine.registerTransportResources(); err == nil {
		t.Fatal("registration unexpectedly succeeded")
	}
	if len(engine.Resources()) != 0 {
		t.Fatalf("failed registration claimed resources: %#v", engine.Resources())
	}
}

var errTestPersistence = &testError{"persistence failed"}

type testError struct{ message string }

func (e *testError) Error() string { return e.message }

func TestStartRecoversPriorInstanceBeforeRegisteringCurrentResources(t *testing.T) {
	store, err := storage.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.EnsurePrivateNetwork("resource-test", "resource-code", "10.245.0.0/24"); err != nil {
		t.Fatal(err)
	}
	broker := network.NewRelayBroker(4096)
	defer broker.Close()
	server := httptest.NewServer((&control.Server{Store: store, AdminToken: "test-admin", Relay: broker}).Handler())
	defer server.Close()
	identity, err := clientidentity.LoadOrCreate(filepath.Join(t.TempDir(), "identity.json"))
	if err != nil {
		t.Fatal(err)
	}
	api := clientapi.New(server.URL, "")
	membership, err := api.Enroll("resource-code", identity.RegisterRequest(), identity.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	api.Token = membership.Token

	ledger := platform.NewMemoryLedger()
	stale, err := platform.NewResourceRecord("prior-instance", platform.ResourcePlainTransport, "prior-plain", "10.245.0.0/24", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.Add(stale); err != nil {
		t.Fatal(err)
	}
	recovered := 0
	engine, err := Start(context.Background(), Options{
		API: api, Identity: identity, Network: membership.Network, Member: membership.Member,
		Native: newNIC(), RelayOnly: true, Ledger: ledger,
		Cleaner: func(platform.ResourceRecord) error {
			recovered++
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	status := engine.RecoveryStatus()
	if recovered != 1 || status.Recovered != 1 {
		t.Fatalf("recovery = %#v, cleaner calls=%d", status, recovered)
	}
	if resources := engine.Resources(); len(resources) != 2 {
		t.Fatalf("current resources = %#v", resources)
	}
}

func TestEngineRecoveryStatusIncludesTrackedCleanupFailure(t *testing.T) {
	ledger := platform.NewMemoryLedger()
	record, err := platform.NewResourceRecord("instance-a", platform.ResourcePlainTransport, "plain", "10.44.0.0/24", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.Add(record); err != nil {
		t.Fatal(err)
	}
	if err := platform.TrackedCleanup(ledger, record, func(platform.ResourceRecord) error { return errTestPersistence }); err == nil {
		t.Fatal("cleanup unexpectedly succeeded")
	}
	engine := &Engine{instanceID: "instance-a", ledger: ledger}
	status := engine.RecoveryStatus()
	if status.Failed != 1 || len(status.Remaining) != 1 || len(status.Issues) != 1 {
		t.Fatalf("recovery status = %#v", status)
	}
}
