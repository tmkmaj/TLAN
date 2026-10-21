//go:build windows

package main

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/private-radminlan/lanmesh/internal/frp"
	"github.com/private-radminlan/lanmesh/internal/mesh"
)

type fakeMeshTargetEngine struct {
	localID string
	localIP netip.Addr
	request mesh.TargetRequest
}

func (f *fakeMeshTargetEngine) Status() mesh.Status        { return mesh.Status{} }
func (f *fakeMeshTargetEngine) LocalDeviceID() string      { return f.localID }
func (f *fakeMeshTargetEngine) LocalVirtualIP() netip.Addr { return f.localIP }
func (f *fakeMeshTargetEngine) LeaseTarget(_ context.Context, request mesh.TargetRequest) (uint64, <-chan struct{}, error) {
	f.request = request
	return 1, make(chan struct{}), nil
}
func (f *fakeMeshTargetEngine) DialTargetTCP(context.Context, mesh.TargetRequest, uint64) (net.Conn, error) {
	return nil, errors.New("not implemented")
}
func (f *fakeMeshTargetEngine) DialTargetUDP(context.Context, mesh.TargetRequest, uint64) (net.Conn, error) {
	return nil, errors.New("not implemented")
}
func (f *fakeMeshTargetEngine) LeaseSelf(context.Context, netip.Addr, uint16) (uint64, <-chan struct{}, error) {
	return 1, make(chan struct{}), nil
}
func (f *fakeMeshTargetEngine) DialSelfTCP(context.Context, netip.Addr, uint16, uint64) (net.Conn, error) {
	return nil, errors.New("not implemented")
}
func (f *fakeMeshTargetEngine) DialSelfUDP(context.Context, netip.Addr, uint16, uint64) (net.Conn, error) {
	return nil, errors.New("not implemented")
}

func TestMeshTargetProviderUsesApprovedServiceID(t *testing.T) {
	engine := &fakeMeshTargetEngine{localID: "dev-local", localIP: netip.MustParseAddr("10.0.0.2")}
	provider := &meshTargetProvider{
		engine:    func() meshTargetEngine { return engine },
		networkID: func() string { return "net-a" },
	}
	rule := frp.Rule{
		ID: "rule-local-id", Name: "Mesh peer", Type: "tcp", Enabled: true,
		Target: frp.Target{
			Kind: "mesh_peer", Host: "10.0.0.5", Port: 22, NetworkID: "net-a",
			DeviceID: "dev-peer", ServiceID: "svc-approved",
		},
	}
	target, lease, dialer, err := provider.PrepareTarget(context.Background(), rule)
	if err != nil {
		t.Fatal(err)
	}
	if target.ServiceID != "svc-approved" {
		t.Fatalf("target service ID = %q, want approved service ID", target.ServiceID)
	}
	if target.ServiceID == rule.ID {
		t.Fatal("target service ID fell back to rule ID")
	}
	if lease == nil || dialer == nil {
		t.Fatal("provider returned nil lease or dialer")
	}
	if _, err = lease.Validate(context.Background(), target); err != nil {
		t.Fatal(err)
	}
	if engine.request.ServiceID != "svc-approved" {
		t.Fatalf("mesh request service ID = %q, want svc-approved", engine.request.ServiceID)
	}
}

func TestMeshTargetProviderRejectsMissingApprovedServiceID(t *testing.T) {
	engine := &fakeMeshTargetEngine{localID: "dev-local", localIP: netip.MustParseAddr("10.0.0.2")}
	provider := &meshTargetProvider{engine: func() meshTargetEngine { return engine }}
	rule := frp.Rule{ID: "rule-local-id", Name: "Mesh peer", Type: "tcp", Target: frp.Target{
		Kind: "mesh_peer", Host: "10.0.0.5", Port: 22, NetworkID: "net-a", DeviceID: "dev-peer",
	}}
	if _, _, _, err := provider.PrepareTarget(context.Background(), rule); err == nil {
		t.Fatal("mesh_peer without approved service ID was accepted")
	}
}
