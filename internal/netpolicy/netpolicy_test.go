package netpolicy

import (
	"context"
	"errors"
	"net/netip"
	"testing"
)

type staticObserver struct {
	routes []Route
	err    error
}

func (o staticObserver) ResolveRoutes(context.Context, string, int) ([]Route, error) {
	return o.routes, o.err
}

func TestCheckForbiddenLiteralAddress(t *testing.T) {
	forbidden := []netip.Prefix{netip.MustParsePrefix("10.240.0.0/24")}
	if err := CheckForbidden(context.Background(), nil, "10.240.0.20", 443, forbidden); !errors.Is(err, ErrForbiddenRoute) {
		t.Fatalf("literal protected address error = %v", err)
	}
	if err := CheckForbidden(context.Background(), nil, "203.0.113.10", 443, forbidden); err != nil {
		t.Fatalf("public address rejected: %v", err)
	}
}

func TestCheckForbiddenRouteInterface(t *testing.T) {
	forbidden := []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10")}
	observer := staticObserver{routes: []Route{{
		Destination: netip.MustParseAddr("198.51.100.8"), InterfaceName: "LANMesh",
		InterfacePrefixes: []netip.Prefix{netip.MustParsePrefix("100.64.0.1/10")},
	}}}
	if err := CheckForbidden(context.Background(), observer, "frp.example.test", 7000, forbidden); !errors.Is(err, ErrForbiddenRoute) {
		t.Fatalf("protected interface error = %v", err)
	}
}
