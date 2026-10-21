package mesh

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/private-radminlan/lanmesh/core"
)

var (
	ErrTargetNotMember        = errors.New("Mesh target is not a current network member")
	ErrTargetChanged          = errors.New("Mesh target identity or address changed")
	ErrTargetClosed           = errors.New("Mesh engine is closed")
	ErrTargetGeneration       = errors.New("Mesh target generation changed")
	ErrTargetRouteUnavailable = errors.New("Mesh target route is not pinned to the TLAN interface")
)

// TargetRequest identifies a member service by device identity and literal
// virtual IPv4. It never accepts a hostname or a physical-LAN fallback.
type TargetRequest struct {
	NetworkID string
	DeviceID  string
	PublicKey string
	IPv4      netip.Addr
	Port      uint16
	ServiceID string
}

func (t TargetRequest) Validate() error {
	if core.NetworkID(t.NetworkID).Validate() != nil {
		return errors.New("target network ID is invalid")
	}
	if core.DeviceID(t.DeviceID).Validate() != nil {
		return errors.New("target device ID is invalid")
	}
	if !t.IPv4.IsValid() || !t.IPv4.Is4() || t.IPv4.IsUnspecified() || t.IPv4.IsLoopback() || t.IPv4.IsMulticast() || t.IPv4.IsLinkLocalUnicast() {
		return errors.New("target virtual IPv4 is invalid")
	}
	if t.Port == 0 {
		return errors.New("target port is required")
	}
	if strings.TrimSpace(t.ServiceID) == "" || len(t.ServiceID) > 64 || strings.ContainsAny(t.ServiceID, "\x00\r\n") {
		return errors.New("target service ID is required")
	}
	if t.PublicKey != "" {
		if err := core.ValidateWireGuardPublicKey(t.PublicKey); err != nil {
			return fmt.Errorf("target public key: %w", err)
		}
	}
	return nil
}

// LeaseTarget revalidates a member target and returns the current Mesh
// generation plus a done channel. TargetGateway polls this method, so a member
// removal, virtual-IP change, public-key change, or engine shutdown invalidates
// existing data-plane streams.
func (e *Engine) LeaseTarget(ctx context.Context, target TargetRequest) (uint64, <-chan struct{}, error) {
	if err := target.Validate(); err != nil {
		return 0, nil, err
	}
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return 0, nil, err
		}
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.closed || e.ctx == nil || e.ctx.Err() != nil {
		return 0, nil, ErrTargetClosed
	}
	if target.NetworkID != e.options.Network.ID {
		return 0, nil, ErrTargetNotMember
	}
	if target.DeviceID == e.options.Identity.DeviceID.String() {
		local, err := netip.ParseAddr(e.options.Member.VirtualIP)
		if err != nil || local != target.IPv4 {
			return 0, nil, ErrTargetChanged
		}
		if target.PublicKey != "" && !strings.EqualFold(target.PublicKey, e.options.Member.PublicKey) {
			return 0, nil, ErrTargetChanged
		}
		return e.generation, e.generationChannel(), nil
	}
	peer, ok := e.peers[target.DeviceID]
	if !ok {
		return 0, nil, ErrTargetNotMember
	}
	peerIP, err := netip.ParseAddr(peer.VirtualIP)
	if err != nil || peerIP != target.IPv4 {
		return 0, nil, ErrTargetChanged
	}
	if target.PublicKey != "" && !strings.EqualFold(target.PublicKey, peer.PublicKey) {
		return 0, nil, ErrTargetChanged
	}
	return e.generation, e.generationChannel(), nil
}

// LocalDeviceID returns the authenticated local member identity.
func (e *Engine) LocalDeviceID() string {
	if e == nil {
		return ""
	}
	return e.options.Identity.DeviceID.String()
}

// LocalVirtualIP returns the currently assigned Mesh IPv4 address.
func (e *Engine) LocalVirtualIP() netip.Addr {
	if e == nil {
		return netip.Addr{}
	}
	addr, _ := netip.ParseAddr(e.options.Member.VirtualIP)
	return addr
}

// LeaseSelf validates that a service is bound to this engine's own virtual
// address. It is intentionally separate from peer lookup and never resolves a
// physical-LAN fallback.
func (e *Engine) LeaseSelf(ctx context.Context, ip netip.Addr, port uint16) (uint64, <-chan struct{}, error) {
	if e == nil {
		return 0, nil, ErrTargetClosed
	}
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return 0, nil, err
		}
	}
	if !ip.IsValid() || !ip.Is4() || ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || port == 0 {
		return 0, nil, ErrTargetChanged
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.closed || e.ctx == nil || e.ctx.Err() != nil {
		return 0, nil, ErrTargetClosed
	}
	if ip != e.LocalVirtualIP() {
		return 0, nil, ErrTargetChanged
	}
	return e.generation, e.generationChannel(), nil
}

func (e *Engine) DialSelfTCP(ctx context.Context, ip netip.Addr, port uint16, generation uint64) (net.Conn, error) {
	if err := e.checkSelfGeneration(ctx, ip, port, generation); err != nil {
		return nil, err
	}
	local := e.LocalVirtualIP()
	dialer := net.Dialer{Timeout: 5 * time.Second, LocalAddr: &net.TCPAddr{IP: net.IP(local.AsSlice())}}
	interfaceIndex, err := meshInterfaceIndex(e.options.InterfaceName)
	if err != nil {
		return nil, err
	}
	if err := configureMeshDialer(&dialer, interfaceIndex); err != nil {
		return nil, err
	}
	conn, err := dialer.DialContext(ctx, "tcp4", netip.AddrPortFrom(ip, port).String())
	if err != nil {
		return nil, err
	}
	if err := verifyMeshConnection(conn, local); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

func (e *Engine) DialSelfUDP(ctx context.Context, ip netip.Addr, port uint16, generation uint64) (net.Conn, error) {
	if err := e.checkSelfGeneration(ctx, ip, port, generation); err != nil {
		return nil, err
	}
	local := e.LocalVirtualIP()
	dialer := net.Dialer{Timeout: 5 * time.Second, LocalAddr: &net.UDPAddr{IP: net.IP(local.AsSlice())}}
	interfaceIndex, err := meshInterfaceIndex(e.options.InterfaceName)
	if err != nil {
		return nil, err
	}
	if err := configureMeshDialer(&dialer, interfaceIndex); err != nil {
		return nil, err
	}
	conn, err := dialer.DialContext(ctx, "udp4", netip.AddrPortFrom(ip, port).String())
	if err != nil {
		return nil, err
	}
	if err := verifyMeshConnection(conn, local); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

func (e *Engine) checkSelfGeneration(ctx context.Context, ip netip.Addr, port uint16, generation uint64) error {
	if generation == 0 {
		return ErrTargetGeneration
	}
	current, _, err := e.LeaseSelf(ctx, ip, port)
	if err != nil {
		return err
	}
	if current != generation {
		return ErrTargetGeneration
	}
	return nil
}

func (e *Engine) DialTargetTCP(ctx context.Context, target TargetRequest, generation uint64) (net.Conn, error) {
	if err := e.checkTargetGeneration(ctx, target, generation); err != nil {
		return nil, err
	}
	local, err := netip.ParseAddr(e.options.Member.VirtualIP)
	if err != nil {
		return nil, fmt.Errorf("parse local Mesh address: %w", err)
	}
	dialer := net.Dialer{Timeout: 5 * time.Second, LocalAddr: &net.TCPAddr{IP: net.IP(local.AsSlice())}}
	interfaceIndex, err := meshInterfaceIndex(e.options.InterfaceName)
	if err != nil {
		return nil, err
	}
	if err := configureMeshDialer(&dialer, interfaceIndex); err != nil {
		return nil, err
	}
	conn, err := dialer.DialContext(ctx, "tcp4", target.AddrPort().String())
	if err != nil {
		return nil, err
	}
	if err := verifyMeshConnection(conn, local); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

func (e *Engine) DialTargetUDP(ctx context.Context, target TargetRequest, generation uint64) (net.Conn, error) {
	if err := e.checkTargetGeneration(ctx, target, generation); err != nil {
		return nil, err
	}
	local, err := netip.ParseAddr(e.options.Member.VirtualIP)
	if err != nil {
		return nil, fmt.Errorf("parse local Mesh address: %w", err)
	}
	dialer := net.Dialer{Timeout: 5 * time.Second, LocalAddr: &net.UDPAddr{IP: net.IP(local.AsSlice())}}
	interfaceIndex, err := meshInterfaceIndex(e.options.InterfaceName)
	if err != nil {
		return nil, err
	}
	if err := configureMeshDialer(&dialer, interfaceIndex); err != nil {
		return nil, err
	}
	conn, err := dialer.DialContext(ctx, "udp4", target.AddrPort().String())
	if err != nil {
		return nil, err
	}
	if err := verifyMeshConnection(conn, local); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

func (e *Engine) checkTargetGeneration(ctx context.Context, target TargetRequest, generation uint64) error {
	if generation == 0 {
		return ErrTargetGeneration
	}
	current, _, err := e.LeaseTarget(ctx, target)
	if err != nil {
		return err
	}
	if current != generation {
		return ErrTargetGeneration
	}
	return nil
}

func (t TargetRequest) AddrPort() netip.AddrPort {
	return netip.AddrPortFrom(t.IPv4, t.Port)
}

func verifyMeshConnection(conn net.Conn, local netip.Addr) error {
	if conn == nil || !local.IsValid() {
		return ErrTargetRouteUnavailable
	}
	var source net.IP
	switch addr := conn.LocalAddr().(type) {
	case *net.TCPAddr:
		source = addr.IP
	case *net.UDPAddr:
		source = addr.IP
	default:
		return ErrTargetRouteUnavailable
	}
	if !source.Equal(net.IP(local.AsSlice())) {
		return ErrTargetRouteUnavailable
	}
	return nil
}
