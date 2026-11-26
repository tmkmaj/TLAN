//go:build windows

package frp

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/private-radminlan/lanmesh/internal/netpolicy"
)

func TestManagerSnapshotIncludesEndpointOwnership(t *testing.T) {
	cfg := testConfig(t)
	registry := NewEndpointRegistry()
	scope := endpointScopeFor(cfg.Profile.ID, 9)
	records := []EndpointRecord{
		testEndpoint(EndpointKindAdmin, EndpointProtocolTCP, 17401, cfg.Profile.ID, scope, 9),
		testEndpoint(EndpointKindVisitor, EndpointProtocolTCP, 19001, cfg.Profile.ID, scope, 9),
		testEndpoint(EndpointKindTargetGateway, EndpointProtocolUDP, 19002, cfg.Profile.ID, scope, 9),
		testEndpoint(EndpointKindEgressProxy, EndpointProtocolTCP, 19003, cfg.Profile.ID, scope, 9),
	}
	records[1].Owner.VisitorID = "visitor-one"
	records[2].Owner.RuleID = "rule-one"
	if err := registry.ReplaceScope(scope, records); err != nil {
		t.Fatal(err)
	}
	if !registry.MarkScopeRunning(scope, 9) {
		t.Fatal("endpoint scope was not marked running")
	}
	manager := &Manager{config: cfg, endpoints: registry, state: "stopped"}
	snapshot := manager.Snapshot(context.Background())
	if len(snapshot.Endpoints) != 4 {
		t.Fatalf("snapshot endpoints = %+v", snapshot.Endpoints)
	}
	seen := make(map[EndpointKind]EndpointRecord)
	for _, record := range snapshot.Endpoints {
		seen[record.Kind] = record
		if record.Owner.ProfileID != cfg.Profile.ID || record.Owner.InstanceGeneration != 9 || record.State != EndpointStateRunning {
			t.Fatalf("endpoint ownership was not preserved: %+v", record)
		}
	}
	if seen[EndpointKindVisitor].Owner.VisitorID != "visitor-one" || seen[EndpointKindTargetGateway].Owner.RuleID != "rule-one" {
		t.Fatalf("endpoint component ownership was lost: %+v", seen)
	}
	if diagnostics := manager.EndpointDiagnostics(); len(diagnostics) != 4 {
		t.Fatalf("endpoint diagnostics = %v", diagnostics)
	}
}

func TestValidatePolicyUsesSharedEndpointRegistry(t *testing.T) {
	cfg := testConfig(t)
	cfg.Profile.Rules[0].Target = Target{Kind: "loopback", Host: "127.0.0.1", Port: 17861}
	registry := NewEndpointRegistry()
	record := testEndpoint(EndpointKindAdmin, EndpointProtocolTCP, 17861, "other-profile", "other-instance", 3)
	if err := registry.ReplaceScope("other-instance", []EndpointRecord{record}); err != nil {
		t.Fatal(err)
	}
	manager := &Manager{endpoints: registry}
	if err := manager.validatePolicy(cfg); ErrorCode(err) != CodeUnsupportedFeature {
		t.Fatalf("shared registry reservation was not enforced: %v", err)
	}
}

func TestEgressWatcherDropsObservationFromSupersededGeneration(t *testing.T) {
	cfg := testConfig(t)
	cfg.Profile.Server.Host = "frps.example.test"
	cfg.Profile.Server.Port = 7000
	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	observer := &scriptedRouteObserver{routes: func(call int) ([]netpolicy.Route, error) {
		if call == 1 {
			once.Do(func() { close(started) })
			<-release
			return []netpolicy.Route{{
				Destination:       netip.MustParseAddr("203.0.113.20"),
				InterfaceName:     "TLAN",
				InterfacePrefixes: []netip.Prefix{netip.MustParsePrefix("10.50.0.2/16")},
			}}, nil
		}
		return []netpolicy.Route{{
			Destination:       netip.MustParseAddr("203.0.113.20"),
			InterfaceName:     "Ethernet",
			InterfacePrefixes: []netip.Prefix{netip.MustParsePrefix("203.0.113.1/24")},
		}}, nil
	}}
	inst := &managedInstance{done: make(chan struct{}), config: cfg, stopped: true}
	manager := &Manager{
		observer: observer, meshInterface: "TLAN", egressInterval: 10 * time.Millisecond,
		meshCIDRs: []netip.Prefix{netip.MustParsePrefix("10.50.0.0/16")},
		instance:  inst, state: "running", observationGate: netpolicy.NewObservationDebouncer(1),
	}
	manager.desiredRun.Store(true)
	manager.startEgressMonitor(inst)
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("route observer was not invoked")
	}
	manager.UpdateMeshCIDR("10.60.0.0/16")
	close(release)
	time.Sleep(80 * time.Millisecond)
	manager.mu.Lock()
	state := manager.state
	lastErr := manager.lastErr
	manager.mu.Unlock()
	if state != "running" || lastErr != nil || !manager.desiredRun.Load() {
		t.Fatalf("superseded observation stopped runtime: state=%s err=%v desired=%v", state, lastErr, manager.desiredRun.Load())
	}
	close(inst.done)
}
