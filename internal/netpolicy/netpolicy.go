// Package netpolicy provides route observations used to keep FRPS traffic and
// TLAN virtual-network traffic on independent egress paths.
package netpolicy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
)

var ErrForbiddenRoute = errors.New("destination route uses a forbidden virtual-network interface")

// Route is one address-resolution result and the OS-selected interface for it.
type Route struct {
	Destination       netip.Addr
	InterfaceIndex    uint32
	InterfaceName     string
	InterfacePrefixes []netip.Prefix
}

// Observer resolves a hostname and reports the route selected by the OS.
type Observer interface {
	ResolveRoutes(ctx context.Context, host string, port int) ([]Route, error)
}

// CheckForbidden rejects a destination if its address or the selected
// interface belongs to one of the protected TLAN prefixes. A nil observer
// still performs the literal-address check.
func CheckForbidden(ctx context.Context, observer Observer, host string, port int, forbidden []netip.Prefix) error {
	if len(forbidden) == 0 {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return errors.New("destination host is empty")
	}
	if literal, err := netip.ParseAddr(host); err == nil {
		if containsAddress(forbidden, literal) {
			return fmt.Errorf("%w: destination %s is in protected TLAN range", ErrForbiddenRoute, literal)
		}
	}
	if observer == nil {
		return nil
	}
	routes, err := observer.ResolveRoutes(ctx, host, port)
	if err != nil {
		return err
	}
	for _, route := range routes {
		if containsAddress(forbidden, route.Destination) || prefixesOverlap(forbidden, route.InterfacePrefixes) {
			return fmt.Errorf("%w: destination %s selected interface %s", ErrForbiddenRoute, route.Destination, route.InterfaceName)
		}
	}
	return nil
}

func containsAddress(prefixes []netip.Prefix, addr netip.Addr) bool {
	for _, prefix := range prefixes {
		if prefix.IsValid() && prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func prefixesOverlap(forbidden, observed []netip.Prefix) bool {
	for _, left := range forbidden {
		if !left.IsValid() {
			continue
		}
		for _, right := range observed {
			if right.IsValid() && left.Overlaps(right) {
				return true
			}
		}
	}
	return false
}

func interfacePrefixes(iface *net.Interface) []netip.Prefix {
	if iface == nil {
		return nil
	}
	addresses, err := iface.Addrs()
	if err != nil {
		return nil
	}
	out := make([]netip.Prefix, 0, len(addresses))
	for _, value := range addresses {
		prefix, err := netip.ParsePrefix(value.String())
		if err == nil && prefix.Addr().Is4() {
			out = append(out, prefix.Masked())
		}
	}
	return out
}
