package netpolicy

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// ErrEvidenceUnavailable means the route observer could not produce enough
// evidence to prove that a connection avoids the protected TLAN prefixes.
var ErrEvidenceUnavailable = errors.New("route evidence is unavailable")

// Endpoint identifies a connection endpoint that must not depend on the TLAN
// virtual network.
type Endpoint struct {
	Host  string
	Port  int
	Label string
}

// MeshPlan describes the interface and address pool that a Mesh start would
// create. It is used for the reverse (Mesh-start) conflict check.
type MeshPlan struct {
	CIDR          netip.Prefix
	InterfaceName string
}

// Planner performs conservative route checks shared by FRP start, Mesh start,
// and runtime route-change monitoring.
type Planner struct {
	Observer Observer
}

// CheckControlEgress rejects an endpoint when its literal or resolved address
// is inside a protected TLAN prefix, or when the OS-selected interface is the
// TLAN interface. A failed DNS/route lookup fails closed with
// ErrEvidenceUnavailable rather than claiming that the path is independent.
func (p Planner) CheckControlEgress(ctx context.Context, endpoint Endpoint, protected []netip.Prefix, meshInterface string) error {
	_, err := p.ResolveControlRoutes(ctx, endpoint, protected, meshInterface)
	return err
}

// ResolveControlRoutes returns only routes that have passed the conservative
// egress policy. Callers that create sockets can then pin each dial to the
// already-observed interface, closing the DNS/route race between inspection
// and connect.
func (p Planner) ResolveControlRoutes(ctx context.Context, endpoint Endpoint, protected []netip.Prefix, meshInterface string) ([]Route, error) {
	if len(protected) == 0 {
		return []Route{{Destination: netip.Addr{}, InterfaceName: "unrestricted"}}, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	host := strings.TrimSpace(endpoint.Host)
	if host == "" {
		return nil, fmt.Errorf("%w: endpoint host is empty", ErrEvidenceUnavailable)
	}
	if endpoint.Port < 1 || endpoint.Port > 65535 {
		return nil, fmt.Errorf("%w: endpoint port is invalid", ErrEvidenceUnavailable)
	}
	label := strings.TrimSpace(endpoint.Label)
	if label == "" {
		label = host
	}
	if literal, err := netip.ParseAddr(host); err == nil {
		if containsAddress(protected, literal) {
			return nil, fmt.Errorf("%w: %s (%s:%d) is inside a protected TLAN prefix", ErrForbiddenRoute, label, host, endpoint.Port)
		}
		if p.Observer == nil {
			return []Route{{Destination: literal, InterfaceName: "literal"}}, nil
		}
	}
	if p.Observer == nil {
		return nil, fmt.Errorf("%w: no route observer for %s", ErrEvidenceUnavailable, label)
	}
	routes, err := p.Observer.ResolveRoutes(ctx, host, endpoint.Port)
	if err != nil {
		return nil, fmt.Errorf("%w: resolve %s: %v", ErrEvidenceUnavailable, label, err)
	}
	if len(routes) == 0 {
		return nil, fmt.Errorf("%w: no IPv4 route for %s", ErrEvidenceUnavailable, label)
	}
	for _, route := range routes {
		if containsAddress(protected, route.Destination) {
			return nil, fmt.Errorf("%w: %s resolved to %s inside a protected TLAN prefix", ErrForbiddenRoute, label, route.Destination)
		}
		if meshInterface != "" && strings.EqualFold(route.InterfaceName, meshInterface) {
			return nil, fmt.Errorf("%w: %s resolved to %s via TLAN interface %s", ErrForbiddenRoute, label, route.Destination, route.InterfaceName)
		}
		if prefixesOverlap(protected, route.InterfacePrefixes) {
			return nil, fmt.Errorf("%w: %s resolved to %s via interface %s carrying a protected TLAN prefix", ErrForbiddenRoute, label, route.Destination, route.InterfaceName)
		}
	}
	return routes, nil
}

// CheckMeshStart verifies that starting a Mesh plan would not capture any of
// the supplied active control endpoints. Unknown route evidence blocks the
// operation rather than silently changing an existing FRP egress path.
func (p Planner) CheckMeshStart(ctx context.Context, plan MeshPlan, endpoints []Endpoint) error {
	if len(endpoints) == 0 {
		return nil
	}
	var protected []netip.Prefix
	if plan.CIDR.IsValid() {
		protected = append(protected, plan.CIDR.Masked())
	}
	for _, endpoint := range endpoints {
		if err := p.CheckControlEgress(ctx, endpoint, protected, plan.InterfaceName); err != nil {
			return err
		}
	}
	return nil
}
