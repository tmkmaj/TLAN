package frp

import (
	"errors"
	"testing"
)

func testEndpoint(kind EndpointKind, protocol EndpointProtocol, port int, profile, scope string, generation uint64) EndpointRecord {
	return EndpointRecord{
		Host: "127.0.0.1", Port: port, Protocol: protocol, Kind: kind,
		Owner: EndpointOwner{ProfileID: profile, InstanceScope: scope, InstanceGeneration: generation, Purpose: string(kind)},
	}
}

func TestEndpointRegistryRejectsCrossProfileConflictAtomically(t *testing.T) {
	registry := NewEndpointRegistry()
	first := testEndpoint(EndpointKindVisitor, EndpointProtocolTCP, 19001, "profile-a", "instance-a", 1)
	if err := registry.ReplaceScope("instance-a", []EndpointRecord{first}); err != nil {
		t.Fatal(err)
	}
	second := testEndpoint(EndpointKindTargetGateway, EndpointProtocolTCP, 19001, "profile-b", "instance-b", 1)
	if err := registry.ReplaceScope("instance-b", []EndpointRecord{second}); !errors.Is(err, ErrEndpointConflict) {
		t.Fatalf("cross-profile listener conflict = %v", err)
	}
	records := registry.Snapshot()
	if len(records) != 1 || records[0].Owner.ProfileID != "profile-a" {
		t.Fatalf("failed replacement mutated registry: %+v", records)
	}
}

func TestEndpointRegistryDistinguishesTCPAndUDP(t *testing.T) {
	registry := NewEndpointRegistry()
	if err := registry.ReplaceScope("instance-tcp", []EndpointRecord{
		testEndpoint(EndpointKindEgressProxy, EndpointProtocolTCP, 19002, "profile-a", "instance-tcp", 1),
	}); err != nil {
		t.Fatal(err)
	}
	if err := registry.ReplaceScope("instance-udp", []EndpointRecord{
		testEndpoint(EndpointKindTargetGateway, EndpointProtocolUDP, 19002, "profile-b", "instance-udp", 1),
	}); err != nil {
		t.Fatalf("same port on independent TCP/UDP listeners was rejected: %v", err)
	}
}

func TestEndpointRegistryTracksGenerationAndDiagnostics(t *testing.T) {
	registry := NewEndpointRegistry()
	record := testEndpoint(EndpointKindAdmin, EndpointProtocolTCP, 17401, "profile-a", "instance-a", 7)
	if err := registry.ReplaceScope("instance-a", []EndpointRecord{record}); err != nil {
		t.Fatal(err)
	}
	if !registry.MarkScopeRunning("instance-a", 7) {
		t.Fatal("current instance generation was not marked running")
	}
	if registry.MarkScopeRunning("instance-a", 6) {
		t.Fatal("stale generation changed endpoint state")
	}
	records := registry.Snapshot()
	if len(records) != 1 || records[0].State != EndpointStateRunning || records[0].Owner.InstanceGeneration != 7 {
		t.Fatalf("unexpected endpoint diagnostic snapshot: %+v", records)
	}
	reservations := registry.Reservations()
	if len(reservations) != 1 || reservations[0].Host != "127.0.0.1" || reservations[0].Port != 17401 {
		t.Fatalf("unexpected endpoint reservations: %+v", reservations)
	}
	if diagnostics := registry.Diagnostics(); len(diagnostics) != 1 {
		t.Fatalf("endpoint diagnostics = %v", diagnostics)
	}
}
