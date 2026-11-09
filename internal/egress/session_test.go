package egress

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

type fakePeer struct {
	t         *testing.T
	conn      net.Conn
	secret    []byte
	sessionID SessionID
	reader    *FrameReader
	writer    *FrameWriter
	handshake chan handshakeRequest
}

func newFakePeer(t *testing.T, conn net.Conn, secret []byte, sessionID SessionID) *fakePeer {
	t.Helper()
	reader, err := NewFrameReader(conn, secret, DirectionClientToServer)
	if err != nil {
		t.Fatal(err)
	}
	writer, err := NewFrameWriter(conn, secret, DirectionServerToClient)
	if err != nil {
		t.Fatal(err)
	}
	return &fakePeer{
		t:         t,
		conn:      conn,
		secret:    secret,
		sessionID: sessionID,
		reader:    reader,
		writer:    writer,
		handshake: make(chan handshakeRequest, 1),
	}
}

func (p *fakePeer) readHandshake() (handshakeRequest, error) {
	frame, err := p.reader.ReadFrame()
	if err != nil {
		return handshakeRequest{}, err
	}
	if frame.Type != FrameHandshake {
		return handshakeRequest{}, fmt.Errorf("first frame type = %d, want handshake", frame.Type)
	}
	var request handshakeRequest
	if err := decodeStrictJSON(bytes.NewReader(frame.Payload), &request, MaxHandshakePayload); err != nil {
		return handshakeRequest{}, err
	}
	return request, nil
}

func (p *fakePeer) acceptHandshake() (handshakeRequest, error) {
	request, err := p.readHandshake()
	if err != nil {
		return handshakeRequest{}, err
	}
	p.handshake <- request
	ack := handshakeAck{SessionID: hex.EncodeToString(p.sessionID[:])}
	payload, err := encodeStrictJSON(ack)
	if err != nil {
		return handshakeRequest{}, err
	}
	if err := p.writer.WriteFrame(Frame{Type: FrameHandshakeAck, SessionID: p.sessionID, Payload: payload}); err != nil {
		return handshakeRequest{}, err
	}
	p.reader.SetExpectedSession(p.sessionID)
	return request, nil
}

func peerTransportClosed(ctx context.Context, err error) bool {
	return ctx.Err() != nil || errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe)
}

func (p *fakePeer) echoUntilClosed(ctx context.Context) error {
	for {
		frame, err := p.reader.ReadFrame()
		if err != nil {
			if peerTransportClosed(ctx, err) {
				return nil
			}
			return err
		}
		switch frame.Type {
		case FrameOpen, FrameClose:
			if frame.Type == FrameClose {
				if err := p.writer.WriteFrame(Frame{Type: FrameClose, Flags: FlagFIN, SessionID: p.sessionID, StreamID: frame.StreamID}); err != nil {
					if peerTransportClosed(ctx, err) {
						return nil
					}
					return err
				}
			}
		case FrameData:
			if err := p.writer.WriteFrame(Frame{Type: FrameData, SessionID: p.sessionID, StreamID: frame.StreamID, Payload: frame.Payload}); err != nil {
				if peerTransportClosed(ctx, err) {
					return nil
				}
				return err
			}
		case FrameUDP:
			if err := p.writer.WriteFrame(Frame{Type: FrameUDP, SessionID: p.sessionID, Payload: frame.Payload}); err != nil {
				if peerTransportClosed(ctx, err) {
					return nil
				}
				return err
			}
		case FrameKeepalive:
			if err := p.writer.WriteFrame(Frame{Type: FrameKeepalive, SessionID: p.sessionID}); err != nil {
				if peerTransportClosed(ctx, err) {
					return nil
				}
				return err
			}
		}
	}
}

func (p *fakePeer) acceptAndEcho(ctx context.Context) error {
	if _, err := p.acceptHandshake(); err != nil {
		return err
	}
	return p.echoUntilClosed(ctx)
}

func testSessionConfig(dialer Dialer) SessionConfig {
	return SessionConfig{
		Dialer:            dialer,
		Secret:            bytes.Repeat([]byte{0x5a}, 32),
		RuleID:            "browser",
		DeviceID:          "dev-test",
		LeaseID:           "lease-test",
		KeepaliveInterval: 40 * time.Millisecond,
		PeerTimeout:       2 * time.Second,
		HandshakeTimeout:  2 * time.Second,
		MaxPayload:        32 * 1024,
	}
}

func newPipePair() (net.Conn, net.Conn) { return net.Pipe() }

func waitForState(t *testing.T, session *Session, want EgressState, timeout time.Duration) EgressSnapshot {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		snapshot := session.Snapshot()
		if snapshot.State == want {
			return snapshot
		}
		time.Sleep(5 * time.Millisecond)
	}
	snapshot := session.Snapshot()
	t.Fatalf("state = %q (last error %q), want %q", snapshot.State, snapshot.LastError, want)
	return snapshot
}

func readExactly(t *testing.T, reader io.Reader, count int) []byte {
	t.Helper()
	result := make(chan []byte, 1)
	errCh := make(chan error, 1)
	go func() {
		data := make([]byte, count)
		if _, err := io.ReadFull(reader, data); err != nil {
			errCh <- err
			return
		}
		result <- data
	}()
	select {
	case data := <-result:
		return data
	case err := <-errCh:
		t.Fatalf("read %d bytes: %v", count, err)
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out reading %d bytes", count)
	}
	return nil
}

func stopWithTimeout(t *testing.T, session *Session) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := session.Stop(ctx); err != nil {
		t.Fatalf("Stop(): %v", err)
	}
}

func TestSessionHandshakeAndTCPEcho(t *testing.T) {
	t.Parallel()

	clientConn, serverConn := newPipePair()
	sessionID := testSessionID(0x30)
	cfg := testSessionConfig(DialerFunc(func(context.Context) (net.Conn, error) { return clientConn, nil }))
	peer := newFakePeer(t, serverConn, cfg.Secret, sessionID)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	peerErr := make(chan error, 1)
	go func() { peerErr <- peer.acceptAndEcho(ctx) }()

	session, err := NewSession(cfg)
	if err != nil {
		t.Fatal(err)
	}
	startCtx, startCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer startCancel()
	if err := session.Start(startCtx); err != nil {
		t.Fatalf("Start(): %v", err)
	}
	select {
	case request := <-peer.handshake:
		if request.RuleID != cfg.RuleID || request.DeviceID != cfg.DeviceID || request.LeaseID != cfg.LeaseID {
			t.Fatalf("handshake request = %+v", request)
		}
		nonce, err := base64.StdEncoding.DecodeString(request.Nonce)
		if err != nil || len(nonce) != 32 {
			t.Fatalf("handshake nonce = %q, err %v", request.Nonce, err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("peer did not receive handshake")
	}
	if snapshot := session.Snapshot(); snapshot.State != StateRunning {
		t.Fatalf("state after handshake = %q", snapshot.State)
	}
	if err := session.Start(startCtx); !errors.Is(err, ErrAlreadyRunning) {
		t.Fatalf("second Start() error = %v, want ErrAlreadyRunning", err)
	}

	stream, err := session.OpenStream(1)
	if err != nil {
		t.Fatalf("OpenStream(): %v", err)
	}
	if _, err := stream.Write([]byte("hello")); err != nil {
		t.Fatalf("Stream.Write(): %v", err)
	}
	if got := readExactly(t, stream, 5); string(got) != "hello" {
		t.Fatalf("echo = %q, want hello", got)
	}
	if err := stream.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite(): %v", err)
	}
	stopWithTimeout(t, session)
	stopWithTimeout(t, session)
	snapshot := session.Snapshot()
	if snapshot.State != StateStopped {
		t.Fatalf("state after Stop() = %q", snapshot.State)
	}
	if snapshot.BytesSent < 5 || snapshot.BytesReceived < 5 || snapshot.PacketsSent == 0 || snapshot.PacketsReceived == 0 {
		t.Fatalf("counters were not updated: %+v", snapshot)
	}
	cancel()
	select {
	case err := <-peerErr:
		if err != nil {
			t.Fatalf("peer: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("peer did not exit")
	}
}

func TestSessionUDPDatagram(t *testing.T) {
	t.Parallel()

	clientConn, serverConn := newPipePair()
	sessionID := testSessionID(0x40)
	cfg := testSessionConfig(DialerFunc(func(context.Context) (net.Conn, error) { return clientConn, nil }))
	peer := newFakePeer(t, serverConn, cfg.Secret, sessionID)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	peerErr := make(chan error, 1)
	go func() { peerErr <- peer.acceptAndEcho(ctx) }()

	session, err := NewSession(cfg)
	if err != nil {
		t.Fatal(err)
	}
	startCtx, startCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer startCancel()
	if err := session.Start(startCtx); err != nil {
		t.Fatalf("Start(): %v", err)
	}
	payload := []byte("dns-query")
	if err := session.SendDatagram(payload); err != nil {
		t.Fatalf("SendDatagram(): %v", err)
	}
	receiveCtx, receiveCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer receiveCancel()
	got, err := session.ReceiveDatagram(receiveCtx)
	if err != nil {
		t.Fatalf("ReceiveDatagram(): %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("ReceiveDatagram() = %q, want %q", got, payload)
	}
	stopWithTimeout(t, session)
	cancel()
	select {
	case err := <-peerErr:
		if err != nil {
			t.Fatalf("peer: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("peer did not exit")
	}
}
func expectEOF(t *testing.T, reader io.Reader) {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		var one [1]byte
		_, err := reader.Read(one[:])
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("Read() error = %v, want io.EOF", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for EOF")
	}
}

func TestSessionHalfClose(t *testing.T) {
	t.Parallel()

	clientConn, serverConn := newPipePair()
	sessionID := testSessionID(0x50)
	cfg := testSessionConfig(DialerFunc(func(context.Context) (net.Conn, error) { return clientConn, nil }))
	peer := newFakePeer(t, serverConn, cfg.Secret, sessionID)
	peerErr := make(chan error, 1)
	go func() {
		if _, err := peer.acceptHandshake(); err != nil {
			peerErr <- err
			return
		}
		for {
			frame, err := peer.reader.ReadFrame()
			if err != nil {
				peerErr <- err
				return
			}
			if frame.Type != FrameClose || frame.Flags&FlagFIN == 0 {
				continue
			}
			if err := peer.writer.WriteFrame(Frame{Type: FrameData, SessionID: sessionID, StreamID: frame.StreamID, Payload: []byte("bye")}); err != nil {
				peerErr <- err
				return
			}
			if err := peer.writer.WriteFrame(Frame{Type: FrameClose, Flags: FlagFIN, SessionID: sessionID, StreamID: frame.StreamID}); err != nil {
				peerErr <- err
				return
			}
			peerErr <- nil
			return
		}
	}()

	session, err := NewSession(cfg)
	if err != nil {
		t.Fatal(err)
	}
	startCtx, startCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer startCancel()
	if err := session.Start(startCtx); err != nil {
		t.Fatalf("Start(): %v", err)
	}
	stream, err := session.OpenStream(2)
	if err != nil {
		t.Fatalf("OpenStream(): %v", err)
	}
	if _, err := stream.Write([]byte("request")); err != nil {
		t.Fatalf("Write(): %v", err)
	}
	if err := stream.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite(): %v", err)
	}
	if got := readExactly(t, stream, 3); string(got) != "bye" {
		t.Fatalf("data after half-close = %q, want bye", got)
	}
	expectEOF(t, stream)
	stopWithTimeout(t, session)
	select {
	case err := <-peerErr:
		if err != nil && !errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("peer: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("peer did not exit")
	}
}

func TestSessionHandshakeFailure(t *testing.T) {
	t.Parallel()

	clientConn, serverConn := newPipePair()
	cfg := testSessionConfig(DialerFunc(func(context.Context) (net.Conn, error) { return clientConn, nil }))
	peer := newFakePeer(t, serverConn, cfg.Secret, testSessionID(0x60))
	go func() {
		_, _ = peer.readHandshake()
		_ = serverConn.Close()
	}()

	session, err := NewSession(cfg)
	if err != nil {
		t.Fatal(err)
	}
	startCtx, startCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer startCancel()
	if err := session.Start(startCtx); err == nil {
		t.Fatal("Start() succeeded after peer closed during handshake")
	}
	snapshot := waitForState(t, session, StateError, 2*time.Second)
	if snapshot.LastError == "" {
		t.Fatal("handshake failure did not record LastError")
	}
	stopWithTimeout(t, session)
}

func TestSessionKeepaliveTimeout(t *testing.T) {
	t.Parallel()

	clientConn, serverConn := newPipePair()
	sessionID := testSessionID(0x70)
	cfg := testSessionConfig(DialerFunc(func(context.Context) (net.Conn, error) { return clientConn, nil }))
	cfg.KeepaliveInterval = 15 * time.Millisecond
	cfg.PeerTimeout = 120 * time.Millisecond
	peer := newFakePeer(t, serverConn, cfg.Secret, sessionID)
	peerErr := make(chan error, 1)
	go func() {
		if _, err := peer.acceptHandshake(); err != nil {
			peerErr <- err
			return
		}
		for {
			if _, err := peer.reader.ReadFrame(); err != nil {
				peerErr <- err
				return
			}
		}
	}()

	session, err := NewSession(cfg)
	if err != nil {
		t.Fatal(err)
	}
	startCtx, startCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer startCancel()
	if err := session.Start(startCtx); err != nil {
		t.Fatalf("Start(): %v", err)
	}
	snapshot := waitForState(t, session, StateError, 2*time.Second)
	if !strings.Contains(strings.ToLower(snapshot.LastError), "timeout") && !strings.Contains(strings.ToLower(snapshot.LastError), "timed out") {
		t.Fatalf("LastError = %q, want peer timeout", snapshot.LastError)
	}
	stopWithTimeout(t, session)
	<-peerErr
}

func TestSessionConcurrentStopDuringStart(t *testing.T) {
	t.Parallel()

	clientConn, serverConn := newPipePair()
	cfg := testSessionConfig(DialerFunc(func(context.Context) (net.Conn, error) { return clientConn, nil }))
	cfg.HandshakeTimeout = 10 * time.Second
	peer := newFakePeer(t, serverConn, cfg.Secret, testSessionID(0x80))
	handshakeSeen := make(chan struct{})
	peerDone := make(chan struct{})
	go func() {
		defer close(peerDone)
		_, _ = peer.readHandshake()
		close(handshakeSeen)
		buffer := make([]byte, 1)
		_, _ = serverConn.Read(buffer)
	}()

	session, err := NewSession(cfg)
	if err != nil {
		t.Fatal(err)
	}
	startCtx, startCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer startCancel()
	startErr := make(chan error, 1)
	go func() { startErr <- session.Start(startCtx) }()
	select {
	case <-handshakeSeen:
	case <-time.After(3 * time.Second):
		t.Fatal("peer did not see handshake")
	}

	stopCtx, stopCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer stopCancel()
	if err := session.Stop(stopCtx); err != nil {
		t.Fatalf("Stop() during Start: %v", err)
	}
	select {
	case err := <-startErr:
		if err == nil {
			t.Fatal("Start() succeeded after concurrent Stop()")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Start() did not return after Stop()")
	}
	if snapshot := session.Snapshot(); snapshot.State != StateStopped {
		t.Fatalf("state = %q, want stopped", snapshot.State)
	}
	if err := session.Stop(context.Background()); err != nil {
		t.Fatalf("second Stop(): %v", err)
	}
	<-peerDone
}

func TestSessionRejectsWrongSessionFrame(t *testing.T) {
	t.Parallel()

	clientConn, serverConn := newPipePair()
	sessionID := testSessionID(0x90)
	cfg := testSessionConfig(DialerFunc(func(context.Context) (net.Conn, error) { return clientConn, nil }))
	peer := newFakePeer(t, serverConn, cfg.Secret, sessionID)
	peerErr := make(chan error, 1)
	go func() {
		if _, err := peer.acceptHandshake(); err != nil {
			peerErr <- err
			return
		}
		wrong := testSessionID(0xa0)
		err := peer.writer.WriteFrame(Frame{Type: FrameData, SessionID: wrong, StreamID: 1, Payload: []byte("wrong")})
		peerErr <- err
	}()

	session, err := NewSession(cfg)
	if err != nil {
		t.Fatal(err)
	}
	startCtx, startCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer startCancel()
	if err := session.Start(startCtx); err != nil {
		t.Fatalf("Start(): %v", err)
	}
	snapshot := waitForState(t, session, StateError, 2*time.Second)
	if !strings.Contains(strings.ToLower(snapshot.LastError), "session") {
		t.Fatalf("LastError = %q, want session mismatch", snapshot.LastError)
	}
	stopWithTimeout(t, session)
	<-peerErr
}

func TestNewSessionValidation(t *testing.T) {
	t.Parallel()

	dialer := DialerFunc(func(context.Context) (net.Conn, error) { return nil, errors.New("unused") })
	tests := []struct {
		name   string
		mutate func(*SessionConfig)
	}{
		{name: "nil dialer", mutate: func(c *SessionConfig) { c.Dialer = nil }},
		{name: "short secret", mutate: func(c *SessionConfig) { c.Secret = []byte("short") }},
		{name: "empty rule id", mutate: func(c *SessionConfig) { c.RuleID = "" }},
		{name: "invalid device id", mutate: func(c *SessionConfig) { c.DeviceID = "../device" }},
		{name: "empty lease id", mutate: func(c *SessionConfig) { c.LeaseID = "" }},
		{name: "negative keepalive", mutate: func(c *SessionConfig) { c.KeepaliveInterval = -time.Second }},
		{name: "timeout not greater than keepalive", mutate: func(c *SessionConfig) {
			c.KeepaliveInterval = 2 * time.Second
			c.PeerTimeout = 2 * time.Second
		}},
		{name: "negative handshake timeout", mutate: func(c *SessionConfig) { c.HandshakeTimeout = -time.Second }},
		{name: "payload too large", mutate: func(c *SessionConfig) { c.MaxPayload = MaxPayloadSize + 1 }},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := testSessionConfig(dialer)
			tc.mutate(&cfg)
			if _, err := NewSession(cfg); !errors.Is(err, ErrInvalidSessionConfig) {
				t.Fatalf("NewSession() error = %v, want ErrInvalidSessionConfig", err)
			}
		})
	}
}

func TestSessionRejectsInvalidDatagram(t *testing.T) {
	t.Parallel()

	session, err := NewSession(testSessionConfig(DialerFunc(func(context.Context) (net.Conn, error) {
		return nil, errors.New("unused")
	})))
	if err != nil {
		t.Fatal(err)
	}
	if err := session.SendDatagram(nil); !errors.Is(err, ErrSessionClosed) && !errors.Is(err, ErrInvalidFramePayload) {
		t.Fatalf("SendDatagram(nil) error = %v", err)
	}
}

func TestSessionLeaseRevokeBlocks(t *testing.T) {
	t.Parallel()

	clientConn, serverConn := newPipePair()
	sessionID := testSessionID(0xb0)
	cfg := testSessionConfig(DialerFunc(func(context.Context) (net.Conn, error) { return clientConn, nil }))
	peer := newFakePeer(t, serverConn, cfg.Secret, sessionID)
	peerErr := make(chan error, 1)
	go func() {
		if _, err := peer.acceptHandshake(); err != nil {
			peerErr <- err
			return
		}
		peerErr <- peer.writer.WriteFrame(Frame{Type: FrameRevoke, SessionID: sessionID})
	}()

	session, err := NewSession(cfg)
	if err != nil {
		t.Fatal(err)
	}
	startCtx, startCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer startCancel()
	if err := session.Start(startCtx); err != nil {
		t.Fatalf("Start(): %v", err)
	}
	snapshot := waitForState(t, session, StateBlocked, 2*time.Second)
	if !strings.Contains(strings.ToLower(snapshot.LastError), "revoked") {
		t.Fatalf("LastError = %q, want revoked lease", snapshot.LastError)
	}
	stopWithTimeout(t, session)
	<-peerErr
}

func TestSessionCanReconnectAfterTransportFailure(t *testing.T) {
	t.Parallel()

	firstClient, firstServer := newPipePair()
	secondClient, secondServer := newPipePair()
	sessionID := testSessionID(0xc0)
	dialCount := 0
	dialer := DialerFunc(func(context.Context) (net.Conn, error) {
		dialCount++
		if dialCount == 1 {
			return firstClient, nil
		}
		return secondClient, nil
	})
	cfg := testSessionConfig(dialer)
	firstPeer := newFakePeer(t, firstServer, cfg.Secret, sessionID)
	firstDone := make(chan struct{})
	go func() {
		defer close(firstDone)
		if _, err := firstPeer.acceptHandshake(); err != nil {
			return
		}
		_, _ = firstPeer.reader.ReadFrame()
		_ = firstServer.Close()
	}()

	session, err := NewSession(cfg)
	if err != nil {
		t.Fatal(err)
	}
	startCtx, startCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer startCancel()
	if err := session.Start(startCtx); err != nil {
		t.Fatalf("first Start(): %v", err)
	}
	waitForState(t, session, StateError, 2*time.Second)
	<-firstDone

	secondPeer := newFakePeer(t, secondServer, cfg.Secret, sessionID)
	peerCtx, peerCancel := context.WithCancel(context.Background())
	defer peerCancel()
	peerErr := make(chan error, 1)
	go func() { peerErr <- secondPeer.acceptAndEcho(peerCtx) }()
	if err := session.Start(startCtx); err != nil {
		t.Fatalf("second Start(): %v", err)
	}
	if snapshot := session.Snapshot(); snapshot.State != StateRunning {
		t.Fatalf("state after reconnect = %q, want running", snapshot.State)
	}
	stopWithTimeout(t, session)
	peerCancel()
	select {
	case err := <-peerErr:
		if err != nil {
			t.Fatalf("second peer: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("second peer did not exit")
	}
}

func TestSessionRejectsMismatchedHandshakeAck(t *testing.T) {
	t.Parallel()

	clientConn, serverConn := newPipePair()
	headerID := testSessionID(0xd0)
	payloadID := testSessionID(0xe0)
	cfg := testSessionConfig(DialerFunc(func(context.Context) (net.Conn, error) { return clientConn, nil }))
	peer := newFakePeer(t, serverConn, cfg.Secret, headerID)
	peerErr := make(chan error, 1)
	go func() {
		if _, err := peer.readHandshake(); err != nil {
			peerErr <- err
			return
		}
		payload, err := encodeStrictJSON(handshakeAck{SessionID: payloadID.String()})
		if err != nil {
			peerErr <- err
			return
		}
		peerErr <- peer.writer.WriteFrame(Frame{Type: FrameHandshakeAck, SessionID: headerID, Payload: payload})
	}()

	session, err := NewSession(cfg)
	if err != nil {
		t.Fatal(err)
	}
	startCtx, startCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer startCancel()
	if err := session.Start(startCtx); !errors.Is(err, ErrHandshakeRejected) {
		t.Fatalf("Start() error = %v, want ErrHandshakeRejected", err)
	}
	waitForState(t, session, StateError, 2*time.Second)
	stopWithTimeout(t, session)
	<-peerErr
}
