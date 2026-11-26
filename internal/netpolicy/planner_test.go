package netpolicy

import (
	"context"
	"errors"
	"net/netip"
	"testing"
)

func TestPlannerRejectsResolvedAddressCapturedByMeshPlan(t *testing.T) {
	planner := Planner{Observer: staticObserver{routes: []Route{{
		Destination:       netip.MustParseAddr("10.240.0.20"),
		InterfaceName:     "Ethernet",
		InterfacePrefixes: []netip.Prefix{netip.MustParsePrefix("192.0.2.10/24")},
	}}}}
	err := planner.CheckMeshStart(context.Background(), MeshPlan{
		CIDR: netip.MustParsePrefix("10.240.0.0/24"), InterfaceName: "TLAN",
	}, []Endpoint{{Host: "frps.example.test", Port: 7000, Label: "FRPS control"}})
	if !errors.Is(err, ErrForbiddenRoute) {
		t.Fatalf("planned Mesh capture error = %v", err)
	}
}

func TestPlannerRejectsActiveMeshInterfaceForPublicAddress(t *testing.T) {
	planner := Planner{Observer: staticObserver{routes: []Route{{
		Destination:       netip.MustParseAddr("198.51.100.20"),
		InterfaceName:     "TLAN",
		InterfacePrefixes: []netip.Prefix{netip.MustParsePrefix("100.64.0.1/10")},
	}}}}
	err := planner.CheckControlEgress(context.Background(), Endpoint{Host: "frps.example.test", Port: 7000},
		[]netip.Prefix{netip.MustParsePrefix("100.64.0.0/10")}, "TLAN")
	if !errors.Is(err, ErrForbiddenRoute) {
		t.Fatalf("active Mesh interface error = %v", err)
	}
}

func TestPlannerAllowsIndependentThirdPartyVPN(t *testing.T) {
	planner := Planner{Observer: staticObserver{routes: []Route{{
		Destination:       netip.MustParseAddr("203.0.113.20"),
		InterfaceName:     "Company VPN",
		InterfacePrefixes: []netip.Prefix{netip.MustParsePrefix("203.0.113.1/24")},
	}}}}
	if err := planner.CheckControlEgress(context.Background(), Endpoint{Host: "frps.example.test", Port: 7000},
		[]netip.Prefix{netip.MustParsePrefix("10.240.0.0/24")}, "TLAN"); err != nil {
		t.Fatalf("independent VPN rejected: %v", err)
	}
}

func TestPlannerFailsClosedWithoutRouteEvidence(t *testing.T) {
	planner := Planner{}
	err := planner.CheckControlEgress(context.Background(), Endpoint{Host: "frps.example.test", Port: 7000},
		[]netip.Prefix{netip.MustParsePrefix("10.240.0.0/24")}, "TLAN")
	if !errors.Is(err, ErrEvidenceUnavailable) {
		t.Fatalf("missing evidence error = %v", err)
	}
}
