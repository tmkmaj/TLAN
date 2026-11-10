package egress

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func gatewayTestConfig(conn net.Conn, sessionID SessionID, secret []byte, dialTCP func(context.Context, OpenTarget) (net.Conn, error)) GatewaySessionConfig {
	return GatewaySessionConfig{
		Conn: conn,
		ValidateHandshake: func(_ context.Context, info HandshakeInfo) (SessionGrant, error) {
			if info.Capability != "capability-one" {
				return SessionGrant{}, ErrHandshakeRejected
			}
			if info.ProfileID != "work" || info.RuleID != "browser" || info.DeviceID != "dev-1" || info.LeaseID != "lease-1" {
				return SessionGrant{}, ErrHandshakeRejected
			}
			return SessionGrant{SessionID: sessionID, Secret: secret}, nil
		},
		AuthorizeTarget: func(_ context.Context, target OpenTarget) error {
			if target.Port == 9 {
				return errors.New("target blocked")
			}
			return nil
		},
		DialTCP:          dialTCP,
		HandshakeTimeout: 2 * time.Second,
		MaxPayload:       8 * 1024,
	}
}

func newClientSession(transport net.Conn, secret []byte) SessionConfig {
	return SessionConfig{
		Dialer:            DialerFunc(func(context.Context) (net.Conn, error) { return transport, nil }),
		Secret:            secret,
		ProfileID:         "work",
		RuleID:            "browser",
		DeviceID:          "dev-1",
		LeaseID:           "lease-1",
		Capability:        "capability-one",
		PolicyVersion:     1,
		KeepaliveInterval: 50 * time.Millisecond,
		PeerTimeout:       2 * time.Second,
		HandshakeTimeout:  2 * time.Second,
		MaxPayload:        8 * 1024,
	}
}

func TestGatewaySessionTCPRoundTrip(t *testing.T) {
	clientTransport, serverTransport := net.Pipe()
	secret := DeriveSessionSecret("capability-one")
	sessionID := testSessionID(0x71)

	gateway, err := NewGatewaySession(gatewayTestConfig(serverTransport, sessionID, secret, func(context.Context, OpenTarget) (net.Conn, error) {
		backendClient, backendServer := net.Pipe()
		go func() {
			defer backendServer.Close()
			_, _ = io.Copy(backendServer, backendServer)
		}()
		return backendClient, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveErr := make(chan error, 1)
	go func() { serveErr <- gateway.Serve(ctx) }()

	client, err := NewSession(newClientSession(clientTransport, secret))
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Start(context.Background()); err != nil {
		t.Fatalf("client start: %v", err)
	}
	defer func() { _ = client.Stop(context.Background()) }()

	stream, err := client.OpenStream(1)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	target := OpenTarget{Host: "example.com", Port: 80, Protocol: ProtocolTCP}
	if err := WriteTargetPreamble(stream, target); err != nil {
		t.Fatalf("write preamble: %v", err)
	}
	payload := []byte("hello-through-gateway")
	if _, err := stream.Write(payload); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	echoed := make([]byte, len(payload))
	if _, err := io.ReadFull(stream, echoed); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(echoed) != string(payload) {
		t.Fatalf("echo mismatch: %q", echoed)
	}
	_ = client.Stop(context.Background())
	select {
	case <-serveErr:
	case <-time.After(3 * time.Second):
	}
}

func TestGatewaySessionRejectsBadCapability(t *testing.T) {
	clientTransport, serverTransport := net.Pipe()
	secret := DeriveSessionSecret("wrong-capability")
	gateway, err := NewGatewaySession(gatewayTestConfig(serverTransport, testSessionID(0x72), secret, func(context.Context, OpenTarget) (net.Conn, error) {
		return nil, errors.New("must not dial")
	}))
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = gateway.Serve(context.Background()) }()

	cfg := newClientSession(clientTransport, secret)
	cfg.Capability = "bad-capability"
	cfg.Secret = DeriveSessionSecret("bad-capability")
	client, err := NewSession(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Start(context.Background()); err == nil {
		t.Fatal("accepted a handshake with the wrong capability")
	}
}

func TestGatewaySessionBlocksForbiddenTarget(t *testing.T) {
	clientTransport, serverTransport := net.Pipe()
	secret := DeriveSessionSecret("capability-one")
	gateway, err := NewGatewaySession(gatewayTestConfig(serverTransport, testSessionID(0x73), secret, func(context.Context, OpenTarget) (net.Conn, error) {
		return nil, errors.New("must not dial a blocked target")
	}))
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = gateway.Serve(context.Background()) }()

	client, err := NewSession(newClientSession(clientTransport, secret))
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Stop(context.Background()) }()
	stream, err := client.OpenStream(2)
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteTargetPreamble(stream, OpenTarget{Host: "blocked.example", Port: 9, Protocol: ProtocolTCP}); err != nil {
		t.Fatal(err)
	}
	_ = stream.Close()
	time.Sleep(200 * time.Millisecond)
	if snapshot := client.Snapshot(); snapshot.State == StateStopped {
		t.Fatal("session silently stopped instead of reporting the blocked stream")
	}
}

func waitForGatewaySessionToStop(t *testing.T, session *Session) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		state := session.Snapshot().State
		if state != StateRunning && state != StateDegraded {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("session remained in state %s", session.Snapshot().State)
}

func TestGatewaySessionRejectsUDPTargetOnTCPStream(t *testing.T) {
	clientTransport, serverTransport := net.Pipe()
	secret := DeriveSessionSecret("capability-one")
	dialed := make(chan struct{}, 1)
	gateway, err := NewGatewaySession(gatewayTestConfig(serverTransport, testSessionID(0x74), secret, func(context.Context, OpenTarget) (net.Conn, error) {
		dialed <- struct{}{}
		return nil, errors.New("must not dial mismatched protocol")
	}))
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = gateway.Serve(context.Background()) }()

	client, err := NewSession(newClientSession(clientTransport, secret))
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Stop(context.Background()) }()
	stream, err := client.OpenStream(1)
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteTargetPreamble(stream, OpenTarget{Host: "example.com", Port: 80, Protocol: ProtocolUDP}); err != nil {
		t.Fatal(err)
	}
	waitForGatewaySessionToStop(t, client)
	select {
	case <-dialed:
		t.Fatal("gateway dialed a UDP target requested on a TCP stream")
	default:
	}
}

func TestGatewaySessionRejectsTCPTargetOnUDPDatagram(t *testing.T) {
	clientTransport, serverTransport := net.Pipe()
	secret := DeriveSessionSecret("capability-one")
	udpDialed := make(chan struct{}, 1)
	cfg := gatewayTestConfig(serverTransport, testSessionID(0x75), secret, func(context.Context, OpenTarget) (net.Conn, error) {
		return nil, errors.New("unexpected TCP dial")
	})
	cfg.DialUDP = func(context.Context, OpenTarget) (net.Conn, error) {
		udpDialed <- struct{}{}
		return nil, errors.New("must not dial mismatched protocol")
	}
	gateway, err := NewGatewaySession(cfg)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = gateway.Serve(context.Background()) }()

	client, err := NewSession(newClientSession(clientTransport, secret))
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Stop(context.Background()) }()
	packet, err := EncodeDatagram(OpenTarget{Host: "example.com", Port: 53, Protocol: ProtocolTCP}, []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	if err := client.SendDatagram(packet); err != nil {
		t.Fatal(err)
	}
	waitForGatewaySessionToStop(t, client)
	select {
	case <-udpDialed:
		t.Fatal("gateway dialed a TCP target requested as a UDP datagram")
	default:
	}
}
