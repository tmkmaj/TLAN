package main

import (
	"context"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/private-radminlan/lanmesh/internal/egress"
	"github.com/private-radminlan/lanmesh/internal/egressgateway"
)

func newTestIssuer(t *testing.T) *egressgateway.LeaseIssuer {
	t.Helper()
	return egressgateway.NewLeaseIssuer(egressgateway.LeaseIssuerConfig{
		GatewayEndpoint: "https://egress.example:7443",
		DefaultTTL:      time.Minute,
		MaxTTL:          time.Hour,
		DefaultLimits: egressgateway.Limits{
			MaxConnections: 8,
			MaxBytes:       1048576,
			MaxRateBPS:     1048576,
		},
	})
}

func issueTestLease(t *testing.T, issuer *egressgateway.LeaseIssuer) egressgateway.Lease {
	t.Helper()
	lease, err := issuer.Issue("device-1", "profile-1", "rule-1", testLeasePolicy(), 5*time.Minute)
	if err != nil {
		t.Fatalf("issue lease: %v", err)
	}
	return lease
}

func newTestClientSession(t *testing.T, lease egressgateway.Lease, transport net.Conn) *egress.Session {
	t.Helper()
	client, err := egress.NewSession(egress.SessionConfig{
		Dialer:            egress.DialerFunc(func(context.Context) (net.Conn, error) { return transport, nil }),
		Secret:            egress.DeriveSessionSecret(lease.Capability),
		ProfileID:         lease.ProfileID,
		RuleID:            lease.RuleID,
		DeviceID:          lease.DeviceID,
		LeaseID:           lease.ID,
		Capability:        lease.Capability,
		PolicyVersion:     lease.PolicyVersion,
		KeepaliveInterval: 100 * time.Millisecond,
		PeerTimeout:       2 * time.Second,
		HandshakeTimeout:  2 * time.Second,
		MaxPayload:        8192,
	})
	if err != nil {
		t.Fatalf("create client session: %v", err)
	}
	return client
}

func echoPipe() (net.Conn, net.Conn) {
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		_, _ = io.Copy(server, server)
	}()
	return client, server
}

func TestGatewaySessionTCPEndToEnd(t *testing.T) {
	config, _ := loadTestConfig(t)
	issuer := newTestIssuer(t)
	lease := issueTestLease(t, issuer)

	var lookupCalls atomic.Int32
	var dialedAddress atomic.Value
	network := networkDependencies{
		lookupNetIP: func(_ context.Context, networkName, host string) ([]netip.Addr, error) {
			if networkName != "ip" || host != "public.example" {
				return nil, &net.DNSError{Err: "unexpected lookup", Name: host, IsNotFound: true}
			}
			lookupCalls.Add(1)
			return []netip.Addr{netip.MustParseAddr("203.0.113.10")}, nil
		},
		dialContext: func(_ context.Context, networkName, address string) (net.Conn, error) {
			if networkName != "tcp" {
				return nil, &net.OpError{Op: "dial", Net: networkName, Err: io.ErrUnexpectedEOF}
			}
			dialedAddress.Store(address)
			client, _ := echoPipe()
			return client, nil
		},
	}
	service, err := newGatewayService(config, issuer, network, nil)
	if err != nil {
		t.Fatalf("new gateway service: %v", err)
	}

	serverTransport, clientTransport := net.Pipe()
	serverCtx, cancelServer := context.WithCancel(context.Background())
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		service.serveConnection(serverCtx, serverTransport)
	}()

	client := newTestClientSession(t, lease, clientTransport)
	if err := client.Start(context.Background()); err != nil {
		t.Fatalf("start client: %v", err)
	}
	stream, err := client.OpenStream(1)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	target := egress.OpenTarget{Host: "public.example", Port: 443, Protocol: egress.ProtocolTCP}
	if err := egress.WriteTargetPreamble(stream, target); err != nil {
		t.Fatalf("write target preamble: %v", err)
	}
	payload := []byte("tcp-payload-through-authorized-address")
	if _, err := stream.Write(payload); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	echo := make([]byte, len(payload))
	if _, err := io.ReadFull(stream, echo); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(echo) != string(payload) {
		t.Fatalf("echo = %q, want %q", echo, payload)
	}
	if got := lookupCalls.Load(); got != 1 {
		t.Fatalf("lookup calls = %d, want 1", got)
	}
	if got, _ := dialedAddress.Load().(string); got != "203.0.113.10:443" {
		t.Fatalf("dialed address = %q, want resolved literal", got)
	}

	if err := client.Stop(context.Background()); err != nil {
		t.Fatalf("stop client: %v", err)
	}
	cancelServer()
	select {
	case <-serverDone:
	case <-time.After(3 * time.Second):
		t.Fatal("server session did not stop")
	}
}

func TestGatewaySessionUDPEndToEnd(t *testing.T) {
	config, _ := loadTestConfig(t)
	issuer := newTestIssuer(t)
	lease := issueTestLease(t, issuer)

	var dialedAddress atomic.Value
	network := networkDependencies{
		lookupNetIP: func(_ context.Context, networkName, host string) ([]netip.Addr, error) {
			if networkName != "ip" || host != "udp.example" {
				return nil, &net.DNSError{Err: "unexpected lookup", Name: host, IsNotFound: true}
			}
			return []netip.Addr{netip.MustParseAddr("203.0.113.11")}, nil
		},
		dialContext: func(_ context.Context, networkName, address string) (net.Conn, error) {
			if networkName != "udp" {
				return nil, &net.OpError{Op: "dial", Net: networkName, Err: io.ErrUnexpectedEOF}
			}
			dialedAddress.Store(address)
			client, _ := echoPipe()
			return client, nil
		},
	}
	service, err := newGatewayService(config, issuer, network, nil)
	if err != nil {
		t.Fatalf("new gateway service: %v", err)
	}
	serverTransport, clientTransport := net.Pipe()
	serverCtx, cancelServer := context.WithCancel(context.Background())
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		service.serveConnection(serverCtx, serverTransport)
	}()

	client := newTestClientSession(t, lease, clientTransport)
	if err := client.Start(context.Background()); err != nil {
		t.Fatalf("start client: %v", err)
	}
	target := egress.OpenTarget{Host: "udp.example", Port: 5353, Protocol: egress.ProtocolUDP}
	packet, err := egress.EncodeDatagram(target, []byte("udp-payload"))
	if err != nil {
		t.Fatalf("encode datagram: %v", err)
	}
	if err := client.SendDatagram(packet); err != nil {
		t.Fatalf("send datagram: %v", err)
	}
	receiveCtx, cancelReceive := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancelReceive()
	response, err := client.ReceiveDatagram(receiveCtx)
	if err != nil {
		t.Fatalf("receive datagram: %v", err)
	}
	responseTarget, responsePayload, err := egress.DecodeDatagram(response)
	if err != nil {
		t.Fatalf("decode datagram: %v", err)
	}
	if responseTarget != target || string(responsePayload) != "udp-payload" {
		t.Fatalf("response = %+v %q", responseTarget, responsePayload)
	}
	if got, _ := dialedAddress.Load().(string); got != "203.0.113.11:5353" {
		t.Fatalf("dialed address = %q, want resolved literal", got)
	}

	if err := client.Stop(context.Background()); err != nil {
		t.Fatalf("stop client: %v", err)
	}
	cancelServer()
	select {
	case <-serverDone:
	case <-time.After(3 * time.Second):
		t.Fatal("server session did not stop")
	}
}

func TestTargetAuthorizerRejectsMixedSafeAndBlockedResolution(t *testing.T) {
	config, _ := loadTestConfig(t)
	gatewayPolicy, err := config.gatewayPolicy()
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := egressgateway.NewSessionPolicy(gatewayPolicy, config.Limits.gatewayLimits())
	if err != nil {
		t.Fatal(err)
	}
	leasePolicy, err := egressgateway.NewSessionPolicy(testLeasePolicy(), testLeasePolicy().Limits)
	if err != nil {
		t.Fatal(err)
	}
	authorizer := newTargetAuthorizer(
		[]*egressgateway.SessionPolicy{baseline, leasePolicy},
		func(context.Context, string, string) ([]netip.Addr, error) {
			return []netip.Addr{
				netip.MustParseAddr("203.0.113.20"),
				netip.MustParseAddr("10.0.0.5"),
			}, nil
		},
		nil,
	)
	target := egress.OpenTarget{Host: "mixed.example", Port: 443, Protocol: egress.ProtocolTCP}
	if err := authorizer.authorize(context.Background(), target); err == nil {
		t.Fatal("mixed public/private resolution was accepted")
	}
	if _, err := authorizer.authorizedAddresses(target); err == nil {
		t.Fatal("partially authorized target was cached")
	}
}

func TestRegistryClosesTrackedSessionsByLease(t *testing.T) {
	config, _ := loadTestConfig(t)
	issuer := newTestIssuer(t)
	lease := issueTestLease(t, issuer)
	gatewayPolicy, err := config.gatewayPolicy()
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := egressgateway.NewSessionPolicy(gatewayPolicy, config.Limits.gatewayLimits())
	if err != nil {
		t.Fatal(err)
	}
	registry := newSessionRegistry(4)
	server, client := net.Pipe()
	defer client.Close()
	gateway, err := egress.NewGatewaySession(egress.GatewaySessionConfig{
		Conn: server,
		ValidateHandshake: func(context.Context, egress.HandshakeInfo) (egress.SessionGrant, error) {
			return egress.SessionGrant{}, nil
		},
		AuthorizeTarget: func(context.Context, egress.OpenTarget) error { return nil },
		DialTCP:         func(context.Context, egress.OpenTarget) (net.Conn, error) { return nil, io.EOF },
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.add(lease, gateway, baseline, config.Limits.gatewayLimits()); err != nil {
		t.Fatalf("register session: %v", err)
	}
	registry.closeLease(lease.ID)
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Fatal("tracked session remained open after lease revocation")
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if registry.total != 0 || len(registry.states) != 0 {
		t.Fatalf("registry state after close: total=%d states=%d", registry.total, len(registry.states))
	}
}
