//go:build windows

package frp

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/private-radminlan/lanmesh/internal/netpolicy"
)

type scriptedRouteObserver struct {
	mu     sync.Mutex
	calls  int
	routes func(int) ([]netpolicy.Route, error)
}

func (o *scriptedRouteObserver) ResolveRoutes(context.Context, string, int) ([]netpolicy.Route, error) {
	o.mu.Lock()
	o.calls++
	call := o.calls
	o.mu.Unlock()
	return o.routes(call)
}

func TestValidateMeshStartRejectsCapturedFRPS(t *testing.T) {
	cfg := testConfig(t)
	cfg.Profile.Server.Host = "frps.example.test"
	cfg.Profile.Server.Port = 7000
	manager := &Manager{
		config: cfg, hasConfig: true,
		meshInterface: "TLAN",
		observer: &scriptedRouteObserver{routes: func(int) ([]netpolicy.Route, error) {
			return []netpolicy.Route{{
				Destination:       netip.MustParseAddr("10.50.0.20"),
				InterfaceName:     "Ethernet",
				InterfacePrefixes: []netip.Prefix{netip.MustParsePrefix("192.0.2.2/24")},
			}}, nil
		}},
	}
	manager.desiredRun.Store(true)
	err := manager.ValidateMeshStart(context.Background(), "10.50.0.0/16")
	if ErrorCode(err) != CodeRouteConflict {
		t.Fatalf("Mesh start conflict = %v", err)
	}
}

func TestValidateMeshStartAllowsIndependentVPN(t *testing.T) {
	cfg := testConfig(t)
	cfg.Profile.Server.Host = "frps.example.test"
	cfg.Profile.Server.Port = 7000
	manager := &Manager{
		config: cfg, hasConfig: true,
		meshInterface: "TLAN",
		observer: &scriptedRouteObserver{routes: func(int) ([]netpolicy.Route, error) {
			return []netpolicy.Route{{
				Destination:       netip.MustParseAddr("203.0.113.20"),
				InterfaceName:     "Company VPN",
				InterfacePrefixes: []netip.Prefix{netip.MustParsePrefix("203.0.113.1/24")},
			}}, nil
		}},
	}
	manager.desiredRun.Store(true)
	if err := manager.ValidateMeshStart(context.Background(), "10.50.0.0/16"); err != nil {
		t.Fatalf("independent VPN rejected: %v", err)
	}
}

func TestValidateMeshStartRejectsCapturedLANBackend(t *testing.T) {
	cfg := testConfig(t)
	cfg.Profile.Server.Host = "frps.example.test"
	cfg.Profile.Server.Port = 7000
	cfg.Profile.Rules[0].Target = Target{Kind: "lan", Host: "10.50.4.20", Port: 8080}
	manager := &Manager{config: cfg, hasConfig: true}
	manager.desiredRun.Store(true)
	err := manager.ValidateMeshStart(context.Background(), "10.50.0.0/16")
	if ErrorCode(err) != CodeRouteConflict {
		t.Fatalf("LAN backend capture error = %v", err)
	}
}

func TestUpdateMeshCIDRDoesNotRequireStoppedInstance(t *testing.T) {
	manager := &Manager{
		instance:  &managedInstance{},
		meshCIDRs: []netip.Prefix{netip.MustParsePrefix("10.40.0.0/16")},
	}
	if err := manager.UpdateMeshCIDR("10.50.0.0/16"); err != nil {
		t.Fatal(err)
	}
	manager.meshMu.RLock()
	prefixes := append([]netip.Prefix(nil), manager.meshCIDRs...)
	manager.meshMu.RUnlock()
	if len(prefixes) != 1 || prefixes[0].String() != "10.50.0.0/16" {
		t.Fatalf("updated prefixes = %v", prefixes)
	}
}

func TestRuntimeEgressChangeStopsFRPAndClearsIntent(t *testing.T) {
	cfg := testConfig(t)
	cfg.Profile.Server.Host = "frps.example.test"
	cfg.Profile.Server.Port = 7000
	observer := &scriptedRouteObserver{routes: func(call int) ([]netpolicy.Route, error) {
		if call == 1 {
			return []netpolicy.Route{{
				Destination:       netip.MustParseAddr("203.0.113.20"),
				InterfaceName:     "Ethernet",
				InterfacePrefixes: []netip.Prefix{netip.MustParsePrefix("203.0.113.1/24")},
			}}, nil
		}
		return []netpolicy.Route{{
			Destination:       netip.MustParseAddr("203.0.113.20"),
			InterfaceName:     "TLAN",
			InterfacePrefixes: []netip.Prefix{netip.MustParsePrefix("10.50.0.2/16")},
		}}, nil
	}}
	inst := &managedInstance{done: make(chan struct{}), config: cfg, stopped: true}
	manager := &Manager{
		observer: observer, meshInterface: "TLAN", egressInterval: 10 * time.Millisecond,
		meshCIDRs: []netip.Prefix{netip.MustParsePrefix("10.50.0.0/16")},
		instance:  inst, state: "running",
	}
	manager.desiredRun.Store(true)
	manager.startEgressMonitor(inst)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		manager.mu.Lock()
		state := manager.state
		lastErr := manager.lastErr
		manager.mu.Unlock()
		if state == "failed" {
			if manager.desiredRun.Load() {
				t.Fatal("route conflict retained automatic run intent")
			}
			if ErrorCode(lastErr) != CodeRouteConflict {
				t.Fatalf("route conflict error = %v", lastErr)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("runtime egress watcher did not fail closed")
}

func TestRuntimeEgressMissingEvidenceFailsClosed(t *testing.T) {
	cfg := testConfig(t)
	cfg.Profile.Server.Host = "frps.example.test"
	cfg.Profile.Server.Port = 7000
	observer := &scriptedRouteObserver{routes: func(int) ([]netpolicy.Route, error) {
		return nil, errors.New("temporary resolver failure")
	}}
	inst := &managedInstance{done: make(chan struct{}), config: cfg, stopped: true}
	manager := &Manager{
		observer: observer, meshInterface: "TLAN", egressInterval: 10 * time.Millisecond,
		meshCIDRs: []netip.Prefix{netip.MustParsePrefix("10.50.0.0/16")},
		instance:  inst, state: "running",
	}
	manager.desiredRun.Store(true)
	manager.startEgressMonitor(inst)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		manager.mu.Lock()
		state := manager.state
		lastErr := manager.lastErr
		manager.mu.Unlock()
		if state == "failed" {
			if ErrorCode(lastErr) != CodeRouteObservationUnavailable {
				t.Fatalf("missing evidence error = %v", lastErr)
			}
			if manager.desiredRun.Load() {
				t.Fatal("missing evidence retained automatic run intent")
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("runtime route observer failure did not fail closed")
}

func TestVisitorReservationDoesNotMaskCrossProfileBindConflict(t *testing.T) {
	first := testConfig(t)
	first.Profile.ID = "profile-first"
	first.Profile.Visitors = []Visitor{{
		ID: "visitor-first", Name: "First visitor", Type: "stcp", Enabled: true,
		ServerName: "remote-first", SecretRef: "secret-first", BindAddr: "127.0.0.1", BindPort: 19002,
	}}
	second := CloneConfig(first)
	second.Profile.ID = "profile-second"
	second.Profile.Visitors[0].ID = "visitor-second"
	second.Profile.Visitors[0].Name = "Second visitor"
	second.Profile.Visitors[0].ServerName = "remote-second"
	if err := ValidateConfigWithReservations(second, configListenerReservations(first)); ErrorCode(err) != CodeUnsupportedFeature {
		t.Fatalf("cross-profile visitor bind conflict = %v", err)
	}
}

func TestValidatePolicyRejectsVisitorListenerAsBackendTarget(t *testing.T) {
	cfg := testConfig(t)
	cfg.Profile.Rules[0].Target = Target{Kind: "loopback", Host: "127.0.0.1", Port: 19001}
	cfg.Profile.Visitors = []Visitor{{
		ID: "visitor-self-loop", Name: "Self visitor", Type: "stcp", Enabled: true,
		ServerName: "remote-service", SecretRef: "visitor-secret", BindAddr: "127.0.0.1", BindPort: 19001,
	}}
	manager := &Manager{}
	if err := manager.validatePolicy(cfg); ErrorCode(err) != CodeUnsupportedFeature {
		t.Fatalf("visitor listener target error = %v", err)
	}
}

func TestValidatePolicyRejectsDynamicManagementReservation(t *testing.T) {
	cfg := testConfig(t)
	cfg.Profile.Rules[0].Target = Target{Kind: "loopback", Host: "127.0.0.1", Port: 17861}
	manager := &Manager{
		reservations: func() []TargetReservation {
			return []TargetReservation{{Host: "127.0.0.1", Port: 17861, Purpose: "dynamic frpc admin"}}
		},
	}
	if err := manager.validatePolicy(cfg); ErrorCode(err) != CodeUnsupportedFeature {
		t.Fatalf("dynamic reservation error = %v", err)
	}
}

func trueASBool() bool { return true }
