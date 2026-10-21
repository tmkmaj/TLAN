package frp

import (
	"context"
	"errors"
	"net/netip"

	"github.com/private-radminlan/lanmesh/internal/netpolicy"
)

const defaultMeshInterfaceName = "LANMesh"

// checkFRPSEgress rejects an FRPS endpoint whose destination or selected
// interface belongs to the TLAN virtual network. It is deliberately separate
// from backend target checks so the control connection cannot depend on the
// virtual network it is supposed to survive.
func checkFRPSEgress(ctx context.Context, observer netpolicy.Observer, cfg Config, prefixes []netip.Prefix) error {
	return checkFRPSEgressOnInterface(ctx, observer, cfg, prefixes, defaultMeshInterfaceName)
}

func checkFRPSEgressOnInterface(ctx context.Context, observer netpolicy.Observer, cfg Config, prefixes []netip.Prefix, meshInterface string) error {
	if len(prefixes) == 0 {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	planner := netpolicy.Planner{Observer: observer}
	err := planner.CheckControlEgress(ctx, netpolicy.Endpoint{
		Host: cfg.Profile.Server.Host, Port: cfg.Profile.Server.Port, Label: "FRPS control endpoint",
	}, prefixes, meshInterface)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, netpolicy.ErrForbiddenRoute):
		return codedError(CodeRouteConflict, "%v", err)
	case errors.Is(err, netpolicy.ErrEvidenceUnavailable):
		return codedError(CodeRouteObservationUnavailable, "%v", err)
	default:
		return codedError(CodeRouteObservationUnavailable, "observe FRPS egress: %v", err)
	}
}

func targetInsidePrefixes(target Target, prefixes []netip.Prefix) error {
	if target.Kind != "lan" {
		return nil
	}
	addr, err := netip.ParseAddr(target.Host)
	if err != nil {
		return nil
	}
	for _, prefix := range prefixes {
		if prefix.IsValid() && prefix.Contains(addr) {
			return codedError(CodeRouteConflict, "LAN target %s belongs to the active TLAN network %s", target.Host, prefix)
		}
	}
	return nil
}
