package egress

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

const (
	defaultGatewayMaxStreams = 128
	gatewayUDPIdleTimeout    = 60 * time.Second
)

// HandshakeInfo is the authenticated material presented by a client before any
// data frame is accepted.
type HandshakeInfo struct {
	ProfileID     string
	RuleID        string
	DeviceID      string
	LeaseID       string
	Capability    string
	PolicyVersion int
	Nonce         string
	RemoteAddr    net.Addr
}

// SessionGrant is returned by a handshake validator after it has verified the
// lease. Secret must be DeriveSessionSecret of the same capability.
type SessionGrant struct {
	SessionID SessionID
	Secret    []byte
}

// GatewaySessionConfig wires the server-side data plane to the lease and policy
// implementation. All callbacks are mandatory except DialUDP.
type GatewaySessionConfig struct {
	Conn              net.Conn
	ValidateHandshake func(ctx context.Context, info HandshakeInfo) (SessionGrant, error)
	AuthorizeTarget   func(ctx context.Context, target OpenTarget) error
	DialTCP           func(ctx context.Context, target OpenTarget) (net.Conn, error)
	DialUDP           func(ctx context.Context, target OpenTarget) (net.Conn, error)
	HandshakeTimeout  time.Duration
	MaxPayload        int
	MaxStreams        int
}

type gatewayStream struct {
	id       uint32
	mu       sync.Mutex
	preamble bytes.Buffer
	opened   bool
	target   OpenTarget
	conn     net.Conn
}

type gatewayUDP struct {
	conn   net.Conn
	target OpenTarget
}

// GatewaySession is the server half of one authenticated egress session.
type GatewaySession struct {
	cfg       GatewaySessionConfig
	conn      net.Conn
	reader    *FrameReader
	writer    *FrameWriter
	sessionID SessionID

	mu      sync.Mutex
	streams map[uint32]*gatewayStream
	udp     map[string]*gatewayUDP
	closed  bool
	once    sync.Once
}

// NewGatewaySession validates the configuration.
func NewGatewaySession(cfg GatewaySessionConfig) (*GatewaySession, error) {
	if cfg.Conn == nil {
		return nil, codedError(CodeInvalidSessionConfig, ErrInvalidSessionConfig, "connection is required")
	}
	if cfg.ValidateHandshake == nil {
		return nil, codedError(CodeInvalidSessionConfig, ErrInvalidSessionConfig, "handshake validator is required")
	}
	if cfg.AuthorizeTarget == nil {
		return nil, codedError(CodeInvalidSessionConfig, ErrInvalidSessionConfig, "target authorizer is required")
	}
	if cfg.DialTCP == nil {
		return nil, codedError(CodeInvalidSessionConfig, ErrInvalidSessionConfig, "TCP dialer is required")
	}
	if cfg.HandshakeTimeout <= 0 {
		cfg.HandshakeTimeout = defaultHandshakeTimeout
	}
	if cfg.MaxPayload <= 0 || cfg.MaxPayload > MaxPayloadSize {
		cfg.MaxPayload = MaxPayloadSize
	}
	if cfg.MaxStreams <= 0 {
		cfg.MaxStreams = defaultGatewayMaxStreams
	}
	return &GatewaySession{
		cfg:     cfg,
		conn:    cfg.Conn,
		streams: make(map[uint32]*gatewayStream),
		udp:     make(map[string]*gatewayUDP),
	}, nil
}

// SessionID returns the negotiated session identifier after Serve authenticates.
func (g *GatewaySession) SessionID() SessionID {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.sessionID
}

// Close terminates the session and every stream or UDP socket it owns.
func (g *GatewaySession) Close() error {
	var err error
	g.once.Do(func() {
		g.mu.Lock()
		g.closed = true
		streams := make([]*gatewayStream, 0, len(g.streams))
		for _, s := range g.streams {
			streams = append(streams, s)
		}
		g.streams = map[uint32]*gatewayStream{}
		udp := make([]*gatewayUDP, 0, len(g.udp))
		for _, u := range g.udp {
			udp = append(udp, u)
		}
		g.udp = map[string]*gatewayUDP{}
		g.mu.Unlock()
		for _, s := range streams {
			s.mu.Lock()
			if s.conn != nil {
				_ = s.conn.Close()
			}
			s.mu.Unlock()
		}
		for _, u := range udp {
			_ = u.conn.Close()
		}
		if g.conn != nil {
			err = g.conn.Close()
		}
	})
	return err
}

// Serve authenticates the handshake and then processes frames until the client
// disconnects, the context is cancelled or a protocol error occurs.
func (g *GatewaySession) Serve(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := g.handshake(ctx); err != nil {
		_ = g.Close()
		return err
	}
	defer g.Close()
	for {
		if err := ctx.Err(); err != nil {
			return nil
		}
		frame, err := g.reader.ReadFrame()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if err := g.handle(ctx, frame); err != nil {
			if errors.Is(err, ErrSessionClosed) || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
	}
}

func (g *GatewaySession) handshake(ctx context.Context) error {
	if err := g.conn.SetDeadline(time.Now().Add(g.cfg.HandshakeTimeout)); err != nil {
		return fmt.Errorf("set handshake deadline: %w", err)
	}
	handshakeSecret := DeriveHandshakeSecret()
	reader, err := NewFrameReader(g.conn, handshakeSecret, DirectionClientToServer)
	if err != nil {
		return err
	}
	writer, err := NewFrameWriter(g.conn, handshakeSecret, DirectionServerToClient)
	if err != nil {
		return err
	}
	frame, err := reader.ReadFrame()
	if err != nil {
		return fmt.Errorf("read handshake: %w", err)
	}
	if frame.Type != FrameHandshake {
		return codedError(CodeHandshakeRejected, ErrHandshakeRejected, "expected handshake, got frame type %d", frame.Type)
	}
	var request handshakeRequest
	if err := decodeStrictJSON(bytes.NewReader(frame.Payload), &request, MaxHandshakePayload); err != nil {
		return codedError(CodeHandshakeRejected, ErrHandshakeRejected, "decode handshake: %v", err)
	}
	grant, err := g.cfg.ValidateHandshake(ctx, HandshakeInfo{
		ProfileID:     request.ProfileID,
		RuleID:        request.RuleID,
		DeviceID:      request.DeviceID,
		LeaseID:       request.LeaseID,
		Capability:    request.Capability,
		PolicyVersion: request.PolicyVersion,
		Nonce:         request.Nonce,
		RemoteAddr:    g.conn.RemoteAddr(),
	})
	if err != nil {
		return err
	}
	if len(grant.Secret) != 32 {
		return codedError(CodeHandshakeRejected, ErrHandshakeRejected, "grant secret must be 32 bytes")
	}
	if grant.SessionID.IsZero() {
		return codedError(CodeHandshakeRejected, ErrHandshakeRejected, "grant session id must not be zero")
	}
	ackPayload, err := encodeStrictJSON(handshakeAck{SessionID: hex.EncodeToString(grant.SessionID[:])})
	if err != nil {
		return err
	}
	if err := writer.WriteFrame(Frame{Type: FrameHandshakeAck, SessionID: grant.SessionID, Payload: ackPayload}); err != nil {
		return fmt.Errorf("write handshake acknowledgement: %w", err)
	}
	sessionReader, err := NewFrameReader(g.conn, grant.Secret, DirectionClientToServer)
	if err != nil {
		return err
	}
	sessionWriter, err := NewFrameWriter(g.conn, grant.Secret, DirectionServerToClient)
	if err != nil {
		return err
	}
	sessionReader.SetExpectedSession(grant.SessionID)
	if err := g.conn.SetDeadline(time.Time{}); err != nil {
		return fmt.Errorf("clear handshake deadline: %w", err)
	}
	g.mu.Lock()
	g.reader = sessionReader
	g.writer = sessionWriter
	g.sessionID = grant.SessionID
	g.mu.Unlock()
	return nil
}

func (g *GatewaySession) handle(ctx context.Context, frame Frame) error {
	switch frame.Type {
	case FrameOpen:
		return g.open(frame.StreamID)
	case FrameData:
		return g.data(ctx, frame)
	case FrameClose:
		return g.closeStream(frame.StreamID)
	case FrameUDP:
		return g.datagram(ctx, frame)
	case FrameKeepalive:
		return g.write(Frame{Type: FrameKeepalive})
	case FrameRevoke:
		return ErrSessionClosed
	default:
		return codedError(CodeInvalidFrame, ErrInvalidFrame, "unsupported gateway frame type %d", frame.Type)
	}
}

func (g *GatewaySession) write(frame Frame) error {
	g.mu.Lock()
	writer := g.writer
	sessionID := g.sessionID
	closed := g.closed
	g.mu.Unlock()
	if closed || writer == nil {
		return ErrSessionClosed
	}
	frame.SessionID = sessionID
	return writer.WriteFrame(frame)
}

func (g *GatewaySession) open(streamID uint32) error {
	if streamID == 0 {
		return codedError(CodeInvalidFramePayload, ErrInvalidFramePayload, "stream id 0 is reserved")
	}
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return ErrSessionClosed
	}
	if _, exists := g.streams[streamID]; exists {
		g.mu.Unlock()
		return codedError(CodeInvalidFramePayload, ErrInvalidFramePayload, "stream %d already open", streamID)
	}
	if len(g.streams) >= g.cfg.MaxStreams {
		g.mu.Unlock()
		return codedError(CodeInvalidFramePayload, ErrInvalidFramePayload, "stream limit reached")
	}
	g.streams[streamID] = &gatewayStream{id: streamID}
	g.mu.Unlock()
	return nil
}

func (g *GatewaySession) stream(streamID uint32) *gatewayStream {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.streams[streamID]
}

func (g *GatewaySession) data(ctx context.Context, frame Frame) error {
	stream := g.stream(streamIDOrZero(frame))
	if stream == nil {
		return nil
	}
	stream.mu.Lock()
	if !stream.opened {
		stream.preamble.Write(frame.Payload)
		target, rest, ready, err := tryTargetPreamble(stream.preamble.Bytes())
		if err != nil {
			stream.mu.Unlock()
			g.failStream(stream.id, err)
			return nil
		}
		if !ready {
			stream.mu.Unlock()
			return nil
		}
		if target.Protocol != ProtocolTCP {
			stream.mu.Unlock()
			g.failStream(stream.id, codedError(CodeInvalidFramePayload, ErrInvalidFramePayload, "TCP stream target protocol must be %q, got %q", ProtocolTCP, target.Protocol))
			return nil
		}
		if err := g.cfg.AuthorizeTarget(ctx, target); err != nil {
			stream.mu.Unlock()
			g.failStream(stream.id, err)
			return nil
		}
		conn, err := g.cfg.DialTCP(ctx, target)
		if err != nil {
			stream.mu.Unlock()
			g.failStream(stream.id, err)
			return nil
		}
		stream.target = target
		stream.conn = conn
		stream.opened = true
		stream.preamble.Reset()
		stream.mu.Unlock()
		go g.pumpTarget(stream)
		if len(rest) > 0 {
			_, _ = conn.Write(rest)
		}
		return nil
	}
	conn := stream.conn
	stream.mu.Unlock()
	if conn == nil {
		return nil
	}
	if _, err := conn.Write(frame.Payload); err != nil {
		g.closeStream(stream.id)
	}
	return nil
}

func (g *GatewaySession) closeStream(streamID uint32) error {
	g.mu.Lock()
	stream := g.streams[streamID]
	delete(g.streams, streamID)
	g.mu.Unlock()
	if stream == nil {
		return nil
	}
	stream.mu.Lock()
	conn := stream.conn
	stream.mu.Unlock()
	if conn != nil {
		_ = conn.Close()
	}
	return nil
}

func (g *GatewaySession) pumpTarget(stream *gatewayStream) {
	buffer := make([]byte, g.cfg.MaxPayload)
	for {
		count, err := stream.conn.Read(buffer)
		if count > 0 {
			if writeErr := g.write(Frame{Type: FrameData, StreamID: stream.id, Payload: append([]byte(nil), buffer[:count]...)}); writeErr != nil {
				_ = g.closeStream(stream.id)
				return
			}
		}
		if err != nil {
			_ = g.write(Frame{Type: FrameClose, Flags: FlagFIN, StreamID: stream.id})
			_ = g.closeStream(stream.id)
			return
		}
	}
}

func (g *GatewaySession) datagram(ctx context.Context, frame Frame) error {
	target, payload, err := DecodeDatagram(frame.Payload)
	if err != nil {
		return err
	}
	if target.Protocol != ProtocolUDP {
		return codedError(CodeInvalidFramePayload, ErrInvalidFramePayload, "UDP datagram target protocol must be %q, got %q", ProtocolUDP, target.Protocol)
	}
	if err := g.cfg.AuthorizeTarget(ctx, target); err != nil {
		g.write(Frame{Type: FrameError, Payload: []byte(err.Error())})
		return nil
	}
	if g.cfg.DialUDP == nil {
		return codedError(CodeInvalidFramePayload, ErrInvalidFramePayload, "UDP is not enabled")
	}
	key := target.String()
	g.mu.Lock()
	endpoint := g.udp[key]
	if endpoint == nil {
		conn, dialErr := g.cfg.DialUDP(ctx, target)
		if dialErr != nil {
			g.mu.Unlock()
			return dialErr
		}
		endpoint = &gatewayUDP{conn: conn, target: target}
		g.udp[key] = endpoint
		go g.pumpUDP(endpoint)
	}
	g.mu.Unlock()
	_, err = endpoint.conn.Write(payload)
	return err
}

func (g *GatewaySession) pumpUDP(endpoint *gatewayUDP) {
	buffer := make([]byte, g.cfg.MaxPayload)
	_ = endpoint.conn.SetReadDeadline(time.Now().Add(gatewayUDPIdleTimeout))
	for {
		count, err := endpoint.conn.Read(buffer)
		if count > 0 {
			packet, encodeErr := EncodeDatagram(endpoint.target, buffer[:count])
			if encodeErr != nil {
				return
			}
			if writeErr := g.write(Frame{Type: FrameUDP, Payload: packet}); writeErr != nil {
				return
			}
		}
		if err != nil {
			return
		}
		_ = endpoint.conn.SetReadDeadline(time.Now().Add(gatewayUDPIdleTimeout))
	}
}

func (g *GatewaySession) failStream(streamID uint32, cause error) {
	message := "egress stream failed"
	if cause != nil {
		message = cause.Error()
	}
	_ = g.write(Frame{Type: FrameError, StreamID: streamID, Payload: []byte(message)})
	_ = g.closeStream(streamID)
}

// tryTargetPreamble returns the parsed target and the bytes after the header.
// ready is false when more data is required.
func tryTargetPreamble(data []byte) (OpenTarget, []byte, bool, error) {
	target, err := DecodeTargetHeader(bytes.NewReader(data))
	if err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
			return OpenTarget{}, nil, false, nil
		}
		return OpenTarget{}, nil, false, err
	}
	header, err := encodeTargetHeader(target)
	if err != nil {
		return OpenTarget{}, nil, false, err
	}
	return target, data[len(header):], true, nil
}

func streamIDOrZero(frame Frame) uint32 { return frame.StreamID }
