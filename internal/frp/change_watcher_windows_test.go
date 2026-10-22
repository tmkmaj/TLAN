//go:build windows

package frp

import (
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/private-radminlan/lanmesh/internal/netpolicy"
)

type fakeChangeNotifier struct {
	changes chan struct{}
	once    sync.Once
}

func (f *fakeChangeNotifier) Changes() <-chan struct{} { return f.changes }
func (f *fakeChangeNotifier) Err() error               { return nil }
func (f *fakeChangeNotifier) Close() error {
	f.once.Do(func() {})
	return nil
}

func TestWaitEgressTriggerWakesOnChange(t *testing.T) {
	done := make(chan struct{})
	tick := make(chan time.Time)
	changes := make(chan struct{}, 1)
	result := make(chan bool, 1)
	go func() {
		triggered, ok := waitEgressTrigger(done, tick, changes)
		result <- triggered && ok
	}()
	changes <- struct{}{}
	select {
	case got := <-result:
		if !got {
			t.Fatal("change notification did not trigger observation")
		}
	case <-time.After(time.Second):
		t.Fatal("change notification was not observed")
	}
}

func TestManagerEgressMonitorWakesOnChange(t *testing.T) {
	cfg := testConfig(t)
	called := make(chan struct{}, 1)
	observer := &scriptedRouteObserver{routes: func(int) ([]netpolicy.Route, error) {
		select {
		case called <- struct{}{}:
		default:
		}
		return []netpolicy.Route{{
			Destination:       netip.MustParseAddr("203.0.113.20"),
			InterfaceName:     "Ethernet",
			InterfacePrefixes: []netip.Prefix{netip.MustParsePrefix("203.0.113.1/24")},
		}}, nil
	}}
	notifier := &fakeChangeNotifier{changes: make(chan struct{}, 1)}
	inst := &managedInstance{done: make(chan struct{}), config: cfg, stopped: true}
	manager := &Manager{
		observer: observer, changes: notifier, meshInterface: "LANMesh",
		egressInterval: time.Hour, meshCIDRs: []netip.Prefix{netip.MustParsePrefix("10.50.0.0/16")},
		instance: inst, state: "running", observationGate: netpolicy.NewObservationDebouncer(1),
	}
	manager.desiredRun.Store(true)
	manager.startEgressMonitor(inst)
	notifier.changes <- struct{}{}
	select {
	case <-called:
	case <-time.After(2 * time.Second):
		t.Fatal("network change did not wake egress monitor")
	}
	close(inst.done)
}
