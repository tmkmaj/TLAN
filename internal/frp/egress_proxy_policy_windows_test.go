//go:build windows

package frp

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/private-radminlan/lanmesh/internal/netpolicy"
)

func TestEgressProxyRejectsTLANRoute(t *testing.T) {
	cfg := testConfig(t)
	cfg.Profile.Server.Host = "127.0.0.1"
	cfg.Profile.Server.Port = 17991
	observer := &scriptedRouteObserver{routes: func(int) ([]netpolicy.Route, error) {
		return []netpolicy.Route{{
			Destination:       netip.MustParseAddr("127.0.0.1"),
			InterfaceName:     "LANMesh",
			InterfacePrefixes: []netip.Prefix{netip.MustParsePrefix("10.50.0.2/16")},
		}}, nil
	}}
	proxy, err := startEgressProxy(context.Background(), observer, cfg, []netip.Prefix{netip.MustParsePrefix("10.50.0.0/16")}, "LANMesh")
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	proxyURL, _ := url.Parse(proxy.URL())
	conn, err := net.DialTimeout("tcp", proxyURL.Host, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	auth := base64.StdEncoding.EncodeToString([]byte(proxy.username + ":" + proxy.password))
	_, _ = fmt.Fprintf(conn, "CONNECT 127.0.0.1:17991 HTTP/1.1\r\nHost: 127.0.0.1:17991\r\nProxy-Authorization: Basic %s\r\n\r\n", auth)
	status, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(status, "502") {
		t.Fatalf("TLAN route CONNECT status = %q", status)
	}
	if connects, dials := proxy.Stats(); connects != 1 || dials != 0 {
		t.Fatalf("proxy route stats = %d/%d", connects, dials)
	}
}
