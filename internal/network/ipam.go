// Package network contains transport-independent network primitives used by
// the control service and the client agent.
package network

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"sync"

	"github.com/private-radminlan/lanmesh/core"
)

var (
	ErrPoolExhausted      = errors.New("virtual IP pool is exhausted")
	ErrIPOutsidePool      = errors.New("IP is outside virtual network")
	ErrIPAlreadyUsed      = errors.New("IP is already assigned")
	ErrDeviceAlreadyHasIP = errors.New("device already has a virtual IP")
)

// VirtualIPAllocator assigns stable addresses from one IPv4 prefix. The
// allocator intentionally excludes the network and broadcast addresses and
// caps the address space to prevent accidental /0 or /8 allocations.
type VirtualIPAllocator struct {
	mu       sync.Mutex
	prefix   netip.Prefix
	reserved map[netip.Addr]struct{}
	byDevice map[core.DeviceID]netip.Addr
	byIP     map[netip.Addr]core.DeviceID
}

func NewVirtualIPAllocator(prefix netip.Prefix, reserved []netip.Addr) (*VirtualIPAllocator, error) {
	prefix = prefix.Masked()
	if !prefix.IsValid() || !prefix.Addr().Is4() {
		return nil, errors.New("virtual IP pool must be an IPv4 prefix")
	}
	hostBits := 32 - prefix.Bits()
	if hostBits < 2 || hostBits > 20 {
		return nil, errors.New("virtual IP pool must contain between 2 and 1,048,576 addresses")
	}
	a := &VirtualIPAllocator{
		prefix:   prefix,
		reserved: make(map[netip.Addr]struct{}, len(reserved)+2),
		byDevice: make(map[core.DeviceID]netip.Addr),
		byIP:     make(map[netip.Addr]core.DeviceID),
	}
	// Network and broadcast are never assignable, even for /31 pools.
	a.reserved[prefix.Addr()] = struct{}{}
	base := prefix.Addr().As4()
	hostMask := uint32(1<<hostBits) - 1
	baseNumber := uint32(base[0])<<24 | uint32(base[1])<<16 | uint32(base[2])<<8 | uint32(base[3])
	broadcastNumber := baseNumber | hostMask
	broadcast := [4]byte{byte(broadcastNumber >> 24), byte(broadcastNumber >> 16), byte(broadcastNumber >> 8), byte(broadcastNumber)}
	a.reserved[netip.AddrFrom4(broadcast)] = struct{}{}
	for _, ip := range reserved {
		if !prefix.Contains(ip) {
			return nil, fmt.Errorf("reserved address %s: %w", ip, ErrIPOutsidePool)
		}
		a.reserved[ip] = struct{}{}
	}
	return a, nil
}

func (a *VirtualIPAllocator) Prefix() netip.Prefix { return a.prefix }

// Allocate returns the existing assignment when a device reconnects. New
// assignments use the lowest available address, making allocation deterministic.
func (a *VirtualIPAllocator) Allocate(device core.DeviceID) (netip.Addr, error) {
	if err := device.Validate(); err != nil {
		return netip.Addr{}, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if ip, ok := a.byDevice[device]; ok {
		return ip, nil
	}
	for ip := a.prefix.Addr(); a.prefix.Contains(ip); ip = ip.Next() {
		if _, ok := a.reserved[ip]; ok {
			continue
		}
		if _, ok := a.byIP[ip]; ok {
			continue
		}
		a.byDevice[device] = ip
		a.byIP[ip] = device
		return ip, nil
	}
	return netip.Addr{}, ErrPoolExhausted
}

// Reserve binds a specific address, useful when restoring an allocation from
// durable storage. It is idempotent for the same device and address.
func (a *VirtualIPAllocator) Reserve(device core.DeviceID, ip netip.Addr) error {
	if err := device.Validate(); err != nil {
		return err
	}
	if !ip.IsValid() || !ip.Is4() || !a.prefix.Contains(ip) {
		return ErrIPOutsidePool
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if existing, ok := a.byDevice[device]; ok {
		if existing == ip {
			return nil
		}
		return ErrDeviceAlreadyHasIP
	}
	if _, blocked := a.reserved[ip]; blocked {
		return ErrIPAlreadyUsed
	}
	if _, used := a.byIP[ip]; used {
		return ErrIPAlreadyUsed
	}
	a.byDevice[device] = ip
	a.byIP[ip] = device
	return nil
}

func (a *VirtualIPAllocator) Release(device core.DeviceID) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	ip, ok := a.byDevice[device]
	if !ok {
		return false
	}
	delete(a.byDevice, device)
	delete(a.byIP, ip)
	return true
}

func (a *VirtualIPAllocator) LookupDevice(device core.DeviceID) (netip.Addr, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	ip, ok := a.byDevice[device]
	return ip, ok
}

func (a *VirtualIPAllocator) LookupIP(ip netip.Addr) (core.DeviceID, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	device, ok := a.byIP[ip]
	return device, ok
}

type IPAssignment struct {
	DeviceID core.DeviceID
	Address  netip.Addr
}

func (a *VirtualIPAllocator) Assignments() []IPAssignment {
	a.mu.Lock()
	defer a.mu.Unlock()
	result := make([]IPAssignment, 0, len(a.byDevice))
	for device, ip := range a.byDevice {
		result = append(result, IPAssignment{DeviceID: device, Address: ip})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].DeviceID < result[j].DeviceID })
	return result
}
