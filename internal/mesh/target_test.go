package mesh

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/private-radminlan/lanmesh/internal/clientapi"
	"github.com/private-radminlan/lanmesh/internal/clientidentity"
)

func TestLeaseTargetBindsIdentityAndGeneration(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e := &Engine{
		ctx: ctx,
		options: Options{
			Network:  clientapi.Network{ID: "net-a"},
			Identity: clientidentity.Identity{DeviceID: "dev-a"},
		},
		peers: map[string]clientapi.Device{
			"dev-b": {ID: "dev-b", VirtualIP: "10.240.0.5", PublicKey: "public-b"},
		},
		generation: 7,
	}
	target := TargetRequest{NetworkID: "net-a", DeviceID: "dev-b", IPv4: netip.MustParseAddr("10.240.0.5"), Port: 22, ServiceID: "rule-a"}
	generation, done, err := e.LeaseTarget(context.Background(), target)
	if err != nil || generation != 7 || done == nil {
		t.Fatalf("lease target = %d, %v, %v", generation, done, err)
	}
	if _, _, err = e.LeaseTarget(context.Background(), TargetRequest{NetworkID: "net-a", DeviceID: "dev-b", IPv4: netip.MustParseAddr("10.240.0.6"), Port: 22, ServiceID: "rule-a"}); err != ErrTargetChanged {
		t.Fatalf("changed target error = %v", err)
	}
	cancel()
	select {
	case <-done:
	default:
		t.Fatal("target done channel did not close with Mesh context")
	}
}

func TestLeaseSelfBindsLocalVirtualIP(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e := &Engine{
		ctx: ctx,
		options: Options{
			Member:   clientapi.Device{VirtualIP: "10.240.0.2"},
			Identity: clientidentity.Identity{DeviceID: "dev-a"},
		},
		peers:      map[string]clientapi.Device{},
		generation: 9,
	}
	generation, done, err := e.LeaseSelf(context.Background(), netip.MustParseAddr("10.240.0.2"), 8080)
	if err != nil || generation != 9 || done == nil {
		t.Fatalf("lease self = %d, %v, %v", generation, done, err)
	}
	if _, _, err = e.LeaseSelf(context.Background(), netip.MustParseAddr("10.240.0.3"), 8080); err != ErrTargetChanged {
		t.Fatalf("foreign self target error = %v", err)
	}
	var dialer net.Dialer
	if err := configureMeshDialer(&dialer, 0); !errors.Is(err, ErrTargetRouteUnavailable) {
		t.Fatalf("unpinned route error = %v", err)
	}
	cancel()
	select {
	case <-done:
	default:
		t.Fatal("self done channel did not close with Mesh context")
	}
}
func TestAdvanceGenerationClosesTargetDone(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e := &Engine{ctx: ctx, generation: 1, generationDone: make(chan struct{})}
	done := e.generationChannel()
	e.advanceGeneration()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("old generation done channel did not close")
	}
	if e.generation != 2 {
		t.Fatalf("generation = %d, want 2", e.generation)
	}
	select {
	case <-e.generationChannel():
		t.Fatal("new generation done channel was already closed")
	default:
	}
}
