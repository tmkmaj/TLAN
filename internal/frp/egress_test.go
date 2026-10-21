package frp

import (
	"context"
	"net/netip"
	"testing"

	"github.com/private-radminlan/lanmesh/internal/netpolicy"
)

type egressTestObserver struct {
	routes []netpolicy.Route
}

func (o egressTestObserver) ResolveRoutes(context.Context, string, int) ([]netpolicy.Route, error) {
	return o.routes, nil
}

func TestFRPSEgressRejectsTLANLiteral(t *testing.T) {
	cfg := testConfig(t)
	cfg.Profile.Server.Host = "10.240.0.20"
	err := checkFRPSEgress(context.Background(), nil, cfg, []netip.Prefix{netip.MustParsePrefix("10.240.0.0/24")})
	if ErrorCode(err) != CodeRouteConflict {
		t.Fatalf("egress error = %v", err)
	}
}

func TestFRPSEgressRejectsObservedTLANInterface(t *testing.T) {
	cfg := testConfig(t)
	observer := egressTestObserver{routes: []netpolicy.Route{{
		Destination: netip.MustParseAddr("198.51.100.10"), InterfaceName: "LANMesh",
		InterfacePrefixes: []netip.Prefix{netip.MustParsePrefix("100.64.0.1/10")},
	}}}
	err := checkFRPSEgress(context.Background(), observer, cfg, []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10")})
	if ErrorCode(err) != CodeRouteConflict {
		t.Fatalf("observed egress error = %v", err)
	}
}

func TestFRPSEgressAllowsIndependentPhysicalRoute(t *testing.T) {
	cfg := testConfig(t)
	observer := egressTestObserver{routes: []netpolicy.Route{{
		Destination: netip.MustParseAddr("198.51.100.10"), InterfaceName: "Ethernet",
		InterfacePrefixes: []netip.Prefix{netip.MustParsePrefix("198.51.100.1/24")},
	}}}
	if err := checkFRPSEgress(context.Background(), observer, cfg, []netip.Prefix{netip.MustParsePrefix("10.240.0.0/24")}); err != nil {
		t.Fatalf("independent route rejected: %v", err)
	}
}
