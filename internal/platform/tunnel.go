package platform

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"golang.zx2c4.com/wireguard/tun"
)

// TunnelOptions carries the ownership context for a Mesh-created tunnel.
// Ledger may be nil for legacy callers; production Mesh always supplies it.
type TunnelOptions struct {
	InstanceID string
	Ledger     ResourceLedger
	Cleaner    Cleaner
	Runner     Runner
}

// IPTunnel wraps the OS's layer-3 interface. Cleanup removes only resources
// recorded for this exact instance, then releases the driver handle.
type IPTunnel struct {
	tun.Device
	cleanup       func() error
	repair        func() error
	cleanupBefore func() error
	cleanupAfter  func() error
	ledger        ResourceLedger
	resources     []ResourceRecord
	closeOnce     sync.Once
	closeErr      error
}

func (t *IPTunnel) Repair() error {
	if t == nil || t.repair == nil {
		return nil
	}
	return t.repair()
}

func (t *IPTunnel) Close() error {
	if t == nil {
		return nil
	}
	t.closeOnce.Do(func() {
		var errs []error
		if t.cleanup != nil {
			errs = append(errs, t.cleanup())
		}
		if t.cleanupBefore != nil {
			errs = append(errs, t.cleanupBefore())
		}
		var deviceErr error
		if t.Device != nil {
			deviceErr = t.Device.Close()
			if deviceErr != nil {
				errs = append(errs, deviceErr)
			}
		}
		if t.cleanupAfter != nil {
			errs = append(errs, t.cleanupAfter())
		}
		if t.ledger != nil && t.cleanupBefore == nil && t.cleanupAfter == nil && len(t.resources) > 0 {
			if deviceErr != nil {
				for _, record := range t.resources {
					_ = t.ledger.UpdateState(record.Key(), CleanupFailed, deviceErr)
				}
			} else {
				for _, record := range t.resources {
					if cleanupErr := trackedCleanup(t.ledger, record, nil); cleanupErr != nil {
						errs = append(errs, cleanupErr)
					}
				}
			}
		}
		t.closeErr = errors.Join(errs...)
	})
	return t.closeErr
}

// Resources returns a copy of the exact records registered for this tunnel.
func (t *IPTunnel) Resources() []ResourceRecord {
	if t == nil {
		return nil
	}
	return append([]ResourceRecord(nil), t.resources...)
}

func OpenTunnel(name string, address netip.Prefix, mtu int) (*IPTunnel, error) {
	return OpenTunnelWithOptions(name, address, mtu, TunnelOptions{})
}

func OpenTunnelWithOptions(name string, address netip.Prefix, mtu int, options TunnelOptions) (*IPTunnel, error) {
	if !address.IsValid() || !address.Addr().Is4() || address.Bits() < 8 || address.Bits() > 30 {
		return nil, fmt.Errorf("invalid tunnel IPv4 prefix")
	}
	if mtu < 576 || mtu > 1500 {
		return nil, fmt.Errorf("MTU must be 576-1500")
	}
	interfaces, _ := net.Interfaces()
	for _, adapter := range interfaces {
		if adapter.Flags&net.FlagUp == 0 {
			continue
		}
		addresses, _ := adapter.Addrs()
		for _, value := range addresses {
			p, err := netip.ParsePrefix(value.String())
			if err == nil && p.Addr().Is4() && address.Overlaps(p) {
				return nil, fmt.Errorf("virtual range %s overlaps existing interface %s (%s)", address.Masked(), adapter.Name, p)
			}
		}
	}
	if options.InstanceID == "" {
		id, err := NewInstanceID()
		if err != nil {
			return nil, err
		}
		options.InstanceID = id
	}
	if options.Runner == nil {
		options.Runner = SystemRunner{}
	}
	return openTunnel(name, address, mtu, options)
}
