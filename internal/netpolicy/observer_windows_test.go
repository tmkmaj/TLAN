//go:build windows

package netpolicy

import (
	"context"
	"testing"
)

func TestWindowsObserverResolvesLoopback(t *testing.T) {
	routes, err := NewObserver().ResolveRoutes(context.Background(), "127.0.0.1", 7000)
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 1 || routes[0].Destination.String() != "127.0.0.1" || routes[0].InterfaceName == "" {
		t.Fatalf("routes = %+v", routes)
	}
}
