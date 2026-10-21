//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/private-radminlan/lanmesh/internal/frp"
	"github.com/private-radminlan/lanmesh/internal/mesh"
	"github.com/private-radminlan/lanmesh/internal/targetgateway"
)

type meshTargetEngine interface {
	Status() mesh.Status
	LocalDeviceID() string
	LocalVirtualIP() netip.Addr
	LeaseTarget(context.Context, mesh.TargetRequest) (uint64, <-chan struct{}, error)
	DialTargetTCP(context.Context, mesh.TargetRequest, uint64) (net.Conn, error)
	DialTargetUDP(context.Context, mesh.TargetRequest, uint64) (net.Conn, error)
	LeaseSelf(context.Context, netip.Addr, uint16) (uint64, <-chan struct{}, error)
	DialSelfTCP(context.Context, netip.Addr, uint16, uint64) (net.Conn, error)
	DialSelfUDP(context.Context, netip.Addr, uint16, uint64) (net.Conn, error)
}

type meshTargetProvider struct {
	engine    func() meshTargetEngine
	networkID func() string
}

func newMeshTargetProvider(a *desktop) *meshTargetProvider {
	if a == nil {
		return nil
	}
	return &meshTargetProvider{
		engine:    func() meshTargetEngine { return a.engine },
		networkID: func() string { return a.membership.Network.ID },
	}
}

func approvedMeshServiceID(rule frp.Rule) (string, error) {
	serviceID := strings.TrimSpace(rule.Target.ServiceID)
	if rule.Target.Kind == "mesh_peer" && serviceID == "" {
		return "", errors.New("mesh_peer target is missing the approved service ID")
	}
	if serviceID != "" && (len(serviceID) > 64 || strings.ContainsAny(serviceID, "\x00\r\n")) {
		return "", errors.New("Mesh target service ID is invalid")
	}
	return serviceID, nil
}

func (p *meshTargetProvider) TargetPath(rule frp.Rule) string {
	if p == nil || p.engine == nil {
		return ""
	}
	if rule.Target.Kind == "mesh_self" {
		return "本机 Mesh 地址"
	}
	engine := p.engine()
	if engine == nil {
		return ""
	}
	for _, peer := range engine.Status().Peers {
		if peer.ID == rule.Target.DeviceID {
			if peer.Path == "" {
				return "未连接"
			}
			return peer.Path
		}
	}
	return "未连接"
}
func (p *meshTargetProvider) PrepareTarget(_ context.Context, rule frp.Rule) (targetgateway.Target, targetgateway.LeaseValidator, targetgateway.Dialer, error) {
	if p == nil || p.engine == nil || p.engine() == nil {
		return targetgateway.Target{}, nil, nil, errors.New("TLAN Mesh must be running for a Mesh target")
	}
	serviceID, err := approvedMeshServiceID(rule)
	if err != nil {
		return targetgateway.Target{}, nil, nil, err
	}
	engine := p.engine()
	networkID := rule.Target.NetworkID
	if networkID == "" && p.networkID != nil {
		networkID = p.networkID()
	}
	ip, err := netip.ParseAddr(rule.Target.Host)
	if err != nil {
		return targetgateway.Target{}, nil, nil, fmt.Errorf("parse Mesh target address: %w", err)
	}
	if rule.Target.Kind == "mesh_self" {
		deviceID := rule.Target.DeviceID
		if deviceID == "" {
			deviceID = engine.LocalDeviceID()
		}
		if deviceID != engine.LocalDeviceID() || ip != engine.LocalVirtualIP() {
			return targetgateway.Target{}, nil, nil, errors.New("mesh_self target does not match the current Mesh identity")
		}
		target := targetgateway.Target{NetworkID: networkID, IPv4: ip, Port: uint16(rule.Target.Port), DeviceID: deviceID, PublicKey: rule.Target.PublicKey, ServiceID: serviceID}
		return target, meshSelfLease{engine: engine, ip: ip, port: uint16(rule.Target.Port), serviceID: serviceID, publicKey: rule.Target.PublicKey}, meshSelfDialer{engine: engine, ip: ip, port: uint16(rule.Target.Port), serviceID: serviceID, publicKey: rule.Target.PublicKey}, nil
	}
	if rule.Target.Kind != "mesh_peer" {
		return targetgateway.Target{}, nil, nil, fmt.Errorf("unsupported Mesh target kind %q", rule.Target.Kind)
	}
	request := mesh.TargetRequest{
		NetworkID: networkID, DeviceID: rule.Target.DeviceID, PublicKey: rule.Target.PublicKey,
		IPv4: ip, Port: uint16(rule.Target.Port), ServiceID: serviceID,
	}
	if err = request.Validate(); err != nil {
		return targetgateway.Target{}, nil, nil, err
	}
	target := targetgateway.Target{NetworkID: request.NetworkID, IPv4: request.IPv4, Port: request.Port, DeviceID: request.DeviceID, PublicKey: request.PublicKey, ServiceID: request.ServiceID}
	return target, meshTargetLease{engine: engine, request: request}, meshTargetDialer{engine: engine, request: request}, nil
}

type meshTargetLease struct {
	engine  meshTargetEngine
	request mesh.TargetRequest
}

func (l meshTargetLease) Validate(ctx context.Context, target targetgateway.Target) (targetgateway.Lease, error) {
	if l.engine == nil {
		return targetgateway.Lease{}, errors.New("Mesh engine is unavailable")
	}
	if target.DeviceID != l.request.DeviceID || target.IPv4 != l.request.IPv4 || target.Port != l.request.Port || target.ServiceID != l.request.ServiceID {
		return targetgateway.Lease{}, errors.New("Mesh target changed")
	}
	generation, done, err := l.engine.LeaseTarget(ctx, l.request)
	if err != nil {
		return targetgateway.Lease{}, err
	}
	return targetgateway.Lease{Generation: generation, Done: done}, nil
}

type meshTargetDialer struct {
	engine  meshTargetEngine
	request mesh.TargetRequest
}

func (d meshTargetDialer) DialTCP(ctx context.Context, target targetgateway.Target, generation uint64) (net.Conn, error) {
	if d.engine == nil {
		return nil, errors.New("Mesh engine is unavailable")
	}
	if target.DeviceID != d.request.DeviceID || target.IPv4 != d.request.IPv4 || target.Port != d.request.Port || target.ServiceID != d.request.ServiceID {
		return nil, errors.New("Mesh target changed")
	}
	return d.engine.DialTargetTCP(ctx, d.request, generation)
}

func (d meshTargetDialer) DialUDP(ctx context.Context, target targetgateway.Target, generation uint64) (net.Conn, error) {
	if d.engine == nil {
		return nil, errors.New("Mesh engine is unavailable")
	}
	if target.DeviceID != d.request.DeviceID || target.IPv4 != d.request.IPv4 || target.Port != d.request.Port || target.ServiceID != d.request.ServiceID {
		return nil, errors.New("Mesh target changed")
	}
	return d.engine.DialTargetUDP(ctx, d.request, generation)
}

type meshSelfLease struct {
	engine    meshTargetEngine
	ip        netip.Addr
	port      uint16
	serviceID string
	publicKey string
}

func (l meshSelfLease) Validate(ctx context.Context, target targetgateway.Target) (targetgateway.Lease, error) {
	if l.engine == nil || target.IPv4 != l.ip || target.Port != l.port || target.DeviceID != l.engine.LocalDeviceID() || target.ServiceID != l.serviceID || (l.publicKey != "" && !strings.EqualFold(target.PublicKey, l.publicKey)) {
		return targetgateway.Lease{}, errors.New("mesh_self target changed")
	}
	generation, done, err := l.engine.LeaseSelf(ctx, l.ip, l.port)
	if err != nil {
		return targetgateway.Lease{}, err
	}
	return targetgateway.Lease{Generation: generation, Done: done}, nil
}

type meshSelfDialer struct {
	engine    meshTargetEngine
	ip        netip.Addr
	port      uint16
	serviceID string
	publicKey string
}

func (d meshSelfDialer) DialTCP(ctx context.Context, target targetgateway.Target, generation uint64) (net.Conn, error) {
	if d.engine == nil || target.IPv4 != d.ip || target.Port != d.port || target.DeviceID != d.engine.LocalDeviceID() || target.ServiceID != d.serviceID || (d.publicKey != "" && !strings.EqualFold(target.PublicKey, d.publicKey)) {
		return nil, errors.New("mesh_self target changed")
	}
	return d.engine.DialSelfTCP(ctx, d.ip, d.port, generation)
}

func (d meshSelfDialer) DialUDP(ctx context.Context, target targetgateway.Target, generation uint64) (net.Conn, error) {
	if d.engine == nil || target.IPv4 != d.ip || target.Port != d.port || target.DeviceID != d.engine.LocalDeviceID() || target.ServiceID != d.serviceID || (d.publicKey != "" && !strings.EqualFold(target.PublicKey, d.publicKey)) {
		return nil, errors.New("mesh_self target changed")
	}
	return d.engine.DialSelfUDP(ctx, d.ip, d.port, generation)
}
