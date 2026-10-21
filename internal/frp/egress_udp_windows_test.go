//go:build windows

package frp

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/private-radminlan/lanmesh/internal/netpolicy"
)

func TestUDPEgressProxyRelaysAndCloses(t *testing.T) {
	backend, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	go func() {
		buffer := make([]byte, 2048)
		for {
			n, addr, readErr := backend.ReadFromUDP(buffer)
			if readErr != nil {
				return
			}
			_, _ = backend.WriteToUDP(buffer[:n], addr)
		}
	}()

	cfg := testConfig(t)
	cfg.Profile.Server.Host = "127.0.0.1"
	cfg.Profile.Server.Port = backend.LocalAddr().(*net.UDPAddr).Port
	proxy, err := startUDPEgressProxy(context.Background(), nil, cfg, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	addr := proxy.Address()
	if !addr.IsValid() {
		t.Fatal("UDP egress proxy address is invalid")
	}
	client, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(addr.Port())})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	payload := []byte("tlan-udp-egress")
	if _, err = client.Write(payload); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 2048)
	n, err := client.Read(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if string(buffer[:n]) != string(payload) {
		t.Fatalf("UDP relay response = %q, want %q", buffer[:n], payload)
	}
	if err = proxy.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestUDPEgressProxyRejectsTLANRoute(t *testing.T) {
	backend, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	cfg := testConfig(t)
	cfg.Profile.Server.Host = "127.0.0.1"
	cfg.Profile.Server.Port = backend.LocalAddr().(*net.UDPAddr).Port
	observer := &scriptedRouteObserver{routes: func(int) ([]netpolicy.Route, error) {
		return []netpolicy.Route{{
			Destination:       netip.MustParseAddr("127.0.0.1"),
			InterfaceName:     "LANMesh",
			InterfacePrefixes: []netip.Prefix{netip.MustParsePrefix("10.50.0.0/16")},
		}}, nil
	}}
	proxy, err := startUDPEgressProxy(context.Background(), observer, cfg, []netip.Prefix{netip.MustParsePrefix("10.50.0.0/16")}, "LANMesh")
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	if _, err = proxy.dialUpstream(context.Background()); !errors.Is(err, netpolicy.ErrForbiddenRoute) {
		t.Fatalf("UDP TLAN route error = %v", err)
	}
}
