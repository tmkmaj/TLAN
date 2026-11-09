package egress

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	defaultKeepaliveInterval = 20 * time.Second
	defaultHandshakeTimeout  = 10 * time.Second
	defaultUDPQueueDepth     = 64
	defaultFrameRateLimit    = 8192
	MaxStreamBufferBytes     = 8 * 1024 * 1024
)

// Dialer opens the authenticated transport for one egress session. Tests use
// net.Pipe; production callers provide their TLS transport here.
type Dialer interface {
	Dial(ctx context.Context) (net.Conn, error)
}

// DialerFunc adapts a function to Dialer.
type DialerFunc func(ctx context.Context) (net.Conn, error)

func (f DialerFunc) Dial(ctx context.Context) (net.Conn, error) { return f(ctx) }

// SessionConfig is the immutable configuration for one rule/session.
type SessionConfig struct {
	Dialer            Dialer
	Secret            []byte
	RuleID            string
	DeviceID          string
	LeaseID           string
	KeepaliveInterval time.Duration
	PeerTimeout       time.Duration
	HandshakeTimeout  time.Duration
	MaxPayload        int
}

type handshakeRequest struct {
	RuleID   string `json:"ruleId"`
	DeviceID string `json:"deviceId"`
	LeaseID  string `json:"leaseId"`
	Nonce    string `json:"nonce"`
}

type handshakeAck struct {
	SessionID string `json:"sessionId"`
}

type sessionFailure struct {
	state EgressState
	err   error
}

// Session is one transport-agnostic client data session. It never falls back
// to local networking after a transport, authentication, or lease failure.
type Session struct {
	cfg    SessionConfig
	secret []byte

	mu              sync.Mutex
	state           EgressState
	conn            net.Conn
	writer          *FrameWriter
	reader          *FrameReader
	cancel          context.CancelFunc
	runDone         chan struct{}
	stopDone        chan struct{}
	stopDoneClosed  bool
	runFinished     bool
	stopRequested   bool
	sessionID       SessionID
	hasSession      bool
	streams         map[uint32]*Stream
	udpQueue        chan []byte
	lastError       string
	bytesSent       uint64
	bytesReceived   uint64
	packetsSent     uint64
	packetsReceived uint64
	startedAt       time.Time
	updatedAt       time.Time
	stoppedAt       time.Time
}

// NewSession validates and creates a stopped session.
func NewSession(cfg SessionConfig) (*Session, error) {
	if cfg.Dialer == nil {
		return nil, codedError(CodeInvalidSessionConfig, ErrInvalidSessionConfig, "dialer is required")
	}
	if len(cfg.Secret) != 32 {
		return nil, codedError(CodeInvalidSessionConfig, ErrInvalidSessionConfig, "secret must be exactly 32 bytes")
	}
	if !validIdentifier(cfg.RuleID) {
		return nil, codedError(CodeInvalidSessionConfig, ErrInvalidSessionConfig, "rule id is invalid")
	}
	if !validIdentifier(cfg.DeviceID) {
		return nil, codedError(CodeInvalidSessionConfig, ErrInvalidSessionConfig, "device id is invalid")
	}
	if !validIdentifier(cfg.LeaseID) {
		return nil, codedError(CodeInvalidSessionConfig, ErrInvalidSessionConfig, "lease id is invalid")
	}
	if cfg.KeepaliveInterval < 0 {
		return nil, codedError(CodeInvalidSessionConfig, ErrInvalidSessionConfig, "keepalive interval must not be negative")
	}
	if cfg.KeepaliveInterval == 0 {
		cfg.KeepaliveInterval = defaultKeepaliveInterval
	}
	if cfg.PeerTimeout < 0 {
		return nil, codedError(CodeInvalidSessionConfig, ErrInvalidSessionConfig, "peer timeout must not be negative")
	}
	if cfg.PeerTimeout == 0 {
		cfg.PeerTimeout = 3 * cfg.KeepaliveInterval
	}
	if cfg.PeerTimeout <= cfg.KeepaliveInterval {
		return nil, codedError(CodeInvalidSessionConfig, ErrInvalidSessionConfig, "peer timeout must be greater than keepalive interval")
	}
	if cfg.HandshakeTimeout < 0 {
		return nil, codedError(CodeInvalidSessionConfig, ErrInvalidSessionConfig, "handshake timeout must not be negative")
	}
	if cfg.HandshakeTimeout == 0 {
		cfg.HandshakeTimeout = defaultHandshakeTimeout
	}
	if cfg.MaxPayload < 0 || cfg.MaxPayload > MaxPayloadSize {
		return nil, codedError(CodeInvalidSessionConfig, ErrInvalidSessionConfig, "max payload must be between 0 and %d", MaxPayloadSize)
	}
	if cfg.MaxPayload == 0 {
		cfg.MaxPayload = MaxPayloadSize
	}
	now := time.Now()
	return &Session{
		cfg:       cfg,
		secret:    append([]byte(nil), cfg.Secret...),
		state:     StateStopped,
		streams:   make(map[uint32]*Stream),
		udpQueue:  make(chan []byte, defaultUDPQueueDepth),
		updatedAt: now,
	}, nil
}

// Start dials, performs the encrypted handshake, and starts frame processing.
// A second Start while starting/running/degraded/stopping returns
// ErrAlreadyRunning. Start may be retried after error or blocked.
func (s *Session) Start(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	s.mu.Lock()
	switch s.state {
	case StateStarting, StateRunning, StateDegraded, StateStopping:
		s.mu.Unlock()
		return codedError(CodeAlreadyRunning, ErrAlreadyRunning, "state is %s", s.state)
	}
	if (s.state == StateError || s.state == StateBlocked) && !s.runFinished {
		s.mu.Unlock()
		return codedError(CodeAlreadyRunning, ErrAlreadyRunning, "previous run is still finishing")
	}
	now := time.Now()
	s.state = StateStarting
	s.stopRequested = false
	s.runFinished = false
	s.stopDone = nil
	s.stopDoneClosed = false
	s.lastError = ""
	s.sessionID = SessionID{}
	s.hasSession = false
	s.streams = make(map[uint32]*Stream)
	s.udpQueue = make(chan []byte, defaultUDPQueueDepth)
	s.bytesSent = 0
	s.bytesReceived = 0
	s.packetsSent = 0
	s.packetsReceived = 0
	s.startedAt = now
	s.updatedAt = now
	s.stoppedAt = time.Time{}
	s.runDone = make(chan struct{})
	runCtx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	result := make(chan error, 1)
	s.mu.Unlock()

	stopPropagation := context.AfterFunc(ctx, cancel)
	go s.run(runCtx, stopPropagation, result)
	return <-result
}

// Stop cancels transport work, waits for the run goroutine, and releases all
// streams. Stop on a stopped session is a nil no-op and concurrent calls wait
// for the same completion.
func (s *Session) Stop(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	s.mu.Lock()
	if s.state == StateStopped {
		s.mu.Unlock()
		return nil
	}
	if s.state == StateStopping {
		done := s.stopDone
		s.mu.Unlock()
		if done == nil {
			return nil
		}
		select {
		case <-done:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	now := time.Now()
	s.state = StateStopping
	s.stopRequested = true
	s.updatedAt = now
	if s.stopDone == nil {
		s.stopDone = make(chan struct{})
	}
	if s.runFinished {
		s.state = StateStopped
		s.stoppedAt = now
		if !s.stopDoneClosed {
			close(s.stopDone)
			s.stopDoneClosed = true
		}
		streams := s.streams
		s.streams = make(map[uint32]*Stream)
		conn := s.conn
		s.conn = nil
		s.mu.Unlock()
		abortStreams(streams, ErrSessionClosed)
		if conn != nil {
			_ = conn.Close()
		}
		return nil
	}
	done := s.stopDone
	runDone := s.runDone
	cancel := s.cancel
	conn := s.conn
	s.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if conn != nil {
		_ = conn.Close()
	}
	if runDone != nil {
		select {
		case <-runDone:
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	s.mu.Lock()
	if s.state == StateStopping {
		s.state = StateStopped
		s.stoppedAt = time.Now()
		s.updatedAt = s.stoppedAt
	}
	if done != nil && !s.stopDoneClosed {
		close(done)
		s.stopDoneClosed = true
	}
	s.mu.Unlock()
	return nil
}

func (s *Session) run(ctx context.Context, stopPropagation func() bool, result chan<- error) {
	reader, writer, stopConn, failure, err := s.connectAndHandshake(ctx)
	if stopPropagation != nil {
		stopPropagation()
	}
	if failure != nil {
		if stopConn != nil {
			stopConn()
		}
		if err == nil {
			err = failure.err
		}
		s.finishRun(failure)
		result <- err
		return
	}

	result <- nil
	failure = s.serve(ctx, reader, writer)
	if stopConn != nil {
		stopConn()
	}
	s.finishRun(failure)
}

func (s *Session) connectAndHandshake(ctx context.Context) (*FrameReader, *FrameWriter, func() bool, *sessionFailure, error) {
	conn, err := s.cfg.Dialer.Dial(ctx)
	if err != nil {
		return nil, nil, nil, s.failure(StateError, fmt.Errorf("dial egress transport: %w", err)), err
	}
	if conn == nil {
		err = codedError(CodeSessionClosed, ErrSessionClosed, "dialer returned a nil connection")
		return nil, nil, nil, s.failure(StateError, err), err
	}
	s.mu.Lock()
	if s.stopRequested || ctx.Err() != nil {
		s.mu.Unlock()
		_ = conn.Close()
		err = ErrSessionClosed
		return nil, nil, nil, s.failure(StateError, err), err
	}
	s.conn = conn
	writer, err := NewFrameWriter(conn, s.secret, DirectionClientToServer)
	if err != nil {
		s.mu.Unlock()
		_ = conn.Close()
		return nil, nil, nil, &sessionFailure{state: StateError, err: err}, err
	}
	reader, err := NewFrameReader(conn, s.secret, DirectionServerToClient)
	if err != nil {
		s.mu.Unlock()
		_ = conn.Close()
		return nil, nil, nil, &sessionFailure{state: StateError, err: err}, err
	}
	guard, guardErr := NewFrameRateGuard(defaultFrameRateLimit, time.Second)
	if guardErr != nil {
		s.mu.Unlock()
		_ = conn.Close()
		return nil, nil, nil, &sessionFailure{state: StateError, err: guardErr}, guardErr
	}
	reader.SetRateGuard(guard)
	s.writer = writer
	s.reader = reader
	s.mu.Unlock()

	stopConn := context.AfterFunc(ctx, func() { _ = conn.Close() })
	deadline := time.Now().Add(s.cfg.HandshakeTimeout)
	if err := conn.SetDeadline(deadline); err != nil {
		s.mu.Lock()
		if s.stopRequested {
			s.mu.Unlock()
			return nil, nil, stopConn, s.failure(StateError, ErrSessionClosed), ErrSessionClosed
		}
		s.mu.Unlock()
		return nil, nil, stopConn, &sessionFailure{state: StateError, err: fmt.Errorf("set handshake deadline: %w", err)}, err
	}

	nonce := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, stopConn, &sessionFailure{state: StateError, err: fmt.Errorf("generate handshake nonce: %w", err)}, err
	}
	request := handshakeRequest{
		RuleID:   s.cfg.RuleID,
		DeviceID: s.cfg.DeviceID,
		LeaseID:  s.cfg.LeaseID,
		Nonce:    base64.StdEncoding.EncodeToString(nonce),
	}
	payload, err := encodeStrictJSON(request)
	if err != nil {
		return nil, nil, stopConn, &sessionFailure{state: StateError, err: err}, err
	}
	if err := writer.WriteFrame(Frame{Type: FrameHandshake, Payload: payload}); err != nil {
		if s.isStopRequested() {
			err = ErrSessionClosed
		}
		return nil, nil, stopConn, s.failure(StateError, fmt.Errorf("write handshake: %w", err)), err
	}
	frame, err := reader.ReadFrame()
	if err != nil {
		if s.isStopRequested() {
			err = ErrSessionClosed
		}
		return nil, nil, stopConn, s.failure(StateError, fmt.Errorf("read handshake acknowledgement: %w", err)), err
	}
	if frame.Type != FrameHandshakeAck {
		err = codedError(CodeHandshakeRejected, ErrHandshakeRejected, "expected handshake acknowledgement, got frame type %d", frame.Type)
		return nil, nil, stopConn, s.failure(StateError, err), err
	}
	var ack handshakeAck
	if err := decodeStrictJSON(bytes.NewReader(frame.Payload), &ack, MaxAckPayload); err != nil {
		err = codedError(CodeHandshakeRejected, ErrHandshakeRejected, "decode handshake acknowledgement: %v", err)
		return nil, nil, stopConn, s.failure(StateError, err), err
	}
	sessionID, err := ParseSessionID(ack.SessionID)
	if err != nil {
		err = codedError(CodeHandshakeRejected, ErrHandshakeRejected, "invalid acknowledged session: %v", err)
		return nil, nil, stopConn, s.failure(StateError, err), err
	}
	if frame.SessionID != sessionID {
		err = codedError(CodeHandshakeRejected, ErrHandshakeRejected, "acknowledged frame session does not match payload session")
		return nil, nil, stopConn, s.failure(StateError, err), err
	}
	reader.SetExpectedSession(sessionID)
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return nil, nil, stopConn, &sessionFailure{state: StateError, err: fmt.Errorf("clear handshake deadline: %w", err)}, err
	}

	now := time.Now()
	s.mu.Lock()
	if s.stopRequested {
		s.mu.Unlock()
		return nil, nil, stopConn, s.failure(StateError, ErrSessionClosed), ErrSessionClosed
	}
	s.sessionID = sessionID
	s.hasSession = true
	s.state = StateRunning
	s.updatedAt = now
	s.mu.Unlock()
	return reader, writer, stopConn, nil, nil
}

func (s *Session) failure(state EgressState, err error) *sessionFailure {
	if s.isStopRequested() {
		return &sessionFailure{state: StateStopped, err: err}
	}
	return &sessionFailure{state: state, err: err}
}

func (s *Session) isStopRequested() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stopRequested
}

func (s *Session) finishRun(failure *sessionFailure) {
	now := time.Now()
	s.mu.Lock()
	conn := s.conn
	streams := s.streams
	s.streams = make(map[uint32]*Stream)
	if s.stopRequested || s.state == StateStopping {
		s.state = StateStopped
		s.stoppedAt = now
	} else if failure != nil {
		s.state = failure.state
		if !s.state.Valid() {
			s.state = StateError
		}
		s.lastError = failure.err.Error()
		s.stoppedAt = now
	} else {
		s.state = StateError
		s.lastError = ErrSessionClosed.Error()
		s.stoppedAt = now
	}
	s.conn = nil
	s.writer = nil
	s.reader = nil
	s.runFinished = true
	s.updatedAt = now
	if s.runDone != nil {
		close(s.runDone)
	}
	if s.stopRequested && s.stopDone != nil && !s.stopDoneClosed {
		close(s.stopDone)
		s.stopDoneClosed = true
	}
	s.mu.Unlock()
	if conn != nil {
		_ = conn.Close()
	}
	abortStreams(streams, ErrSessionClosed)
}

// Snapshot returns an immutable copy of session state and counters.
func (s *Session) Snapshot() EgressSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	ruleState := RuleState{RuleID: s.cfg.RuleID, State: s.state, LastError: s.lastError}
	return EgressSnapshot{
		State:           s.state,
		RuleStates:      []RuleState{ruleState},
		BytesSent:       s.bytesSent,
		BytesReceived:   s.bytesReceived,
		PacketsSent:     s.packetsSent,
		PacketsReceived: s.packetsReceived,
		LastError:       s.lastError,
		StartedAt:       s.startedAt,
		UpdatedAt:       s.updatedAt,
		StoppedAt:       s.stoppedAt,
	}
}
func (s *Session) serve(ctx context.Context, reader *FrameReader, writer *FrameWriter) *sessionFailure {
	keepaliveErr := make(chan error, 1)
	go func() { keepaliveErr <- s.keepaliveLoop(ctx, writer) }()

	failure := s.readLoop(ctx, reader)
	stopped := ctx.Err() != nil || s.isStopRequested()

	s.mu.Lock()
	cancel := s.cancel
	conn := s.conn
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if conn != nil {
		_ = conn.Close()
	}

	var keepErr error
	select {
	case keepErr = <-keepaliveErr:
	case <-time.After(time.Second):
	}
	if !stopped && keepErr != nil {
		return &sessionFailure{state: StateError, err: fmt.Errorf("egress keepalive: %w", keepErr)}
	}
	return failure
}

func (s *Session) readLoop(ctx context.Context, reader *FrameReader) *sessionFailure {
	for {
		if ctx.Err() != nil || s.isStopRequested() {
			return nil
		}
		s.mu.Lock()
		conn := s.conn
		peerTimeout := s.cfg.PeerTimeout
		s.mu.Unlock()
		if conn == nil {
			return &sessionFailure{state: StateError, err: ErrSessionClosed}
		}
		if err := conn.SetReadDeadline(time.Now().Add(peerTimeout)); err != nil {
			if ctx.Err() != nil || s.isStopRequested() {
				return nil
			}
			return &sessionFailure{state: StateError, err: fmt.Errorf("set egress read deadline: %w", err)}
		}
		frame, err := reader.ReadFrame()
		if err != nil {
			if ctx.Err() != nil || s.isStopRequested() {
				return nil
			}
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				return &sessionFailure{state: StateError, err: ErrPeerTimeout}
			}
			return &sessionFailure{state: StateError, err: fmt.Errorf("read egress frame: %w", err)}
		}
		if failure := s.handleFrame(frame); failure != nil {
			return failure
		}
	}
}

func (s *Session) handleFrame(frame Frame) *sessionFailure {
	switch frame.Type {
	case FrameData:
		s.mu.Lock()
		stream := s.streams[frame.StreamID]
		s.mu.Unlock()
		if stream == nil {
			return &sessionFailure{state: StateError, err: codedError(CodeUnknownStream, ErrUnknownStream, "data for stream %d has no open stream", frame.StreamID)}
		}
		if err := stream.deliver(frame.Payload); err != nil {
			return &sessionFailure{state: StateError, err: err}
		}
		s.addReceived(uint64(len(frame.Payload)), 1)
		if frame.Flags&FlagFIN != 0 {
			stream.deliverEOF()
		}
		return nil
	case FrameClose:
		s.mu.Lock()
		stream := s.streams[frame.StreamID]
		s.mu.Unlock()
		if stream == nil {
			return &sessionFailure{state: StateError, err: codedError(CodeUnknownStream, ErrUnknownStream, "close for stream %d has no open stream", frame.StreamID)}
		}
		stream.deliverClose(frame.Flags)
		return nil
	case FrameUDP:
		if len(frame.Payload) == 0 {
			return &sessionFailure{state: StateError, err: codedError(CodeInvalidFramePayload, ErrInvalidFramePayload, "empty UDP datagram is not accepted")}
		}
		s.mu.Lock()
		queue := s.udpQueue
		s.mu.Unlock()
		payload := append([]byte(nil), frame.Payload...)
		select {
		case queue <- payload:
			s.addReceived(uint64(len(payload)), 1)
			return nil
		default:
			return &sessionFailure{state: StateError, err: ErrStreamBufferFull}
		}
	case FrameKeepalive:
		return nil
	case FrameError:
		message := strings.TrimSpace(string(frame.Payload))
		if message == "" {
			message = "peer reported an unspecified error"
		}
		return &sessionFailure{state: StateError, err: fmt.Errorf("%w: %s", ErrRemoteError, message)}
	case FrameRevoke:
		return &sessionFailure{state: StateBlocked, err: fmt.Errorf("%w: lease revoked", ErrRemoteError)}
	default:
		return &sessionFailure{state: StateError, err: codedError(CodeInvalidFrame, ErrInvalidFrame, "unexpected frame type %d after handshake", frame.Type)}
	}
}

func (s *Session) keepaliveLoop(ctx context.Context, writer *FrameWriter) error {
	if writer == nil {
		return ErrSessionClosed
	}
	ticker := time.NewTicker(s.cfg.KeepaliveInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			s.mu.Lock()
			active := s.state == StateRunning || s.state == StateDegraded
			sessionID := s.sessionID
			conn := s.conn
			s.mu.Unlock()
			if !active {
				continue
			}
			if err := writer.WriteFrame(Frame{Type: FrameKeepalive, SessionID: sessionID}); err != nil {
				if ctx.Err() != nil || s.isStopRequested() {
					return nil
				}
				if conn != nil {
					_ = conn.Close()
				}
				return err
			}
		}
	}
}

// OpenStream opens a logical TCP stream over the authenticated session.
func (s *Session) OpenStream(streamID uint32) (*Stream, error) {
	if streamID == 0 {
		return nil, codedError(CodeInvalidFramePayload, ErrInvalidFramePayload, "stream id 0 is reserved")
	}
	s.mu.Lock()
	if s.state != StateRunning && s.state != StateDegraded {
		s.mu.Unlock()
		return nil, codedError(CodeSessionClosed, ErrSessionClosed, "session state is %s", s.state)
	}
	if _, exists := s.streams[streamID]; exists {
		s.mu.Unlock()
		return nil, codedError(CodeDuplicateStream, ErrDuplicateStream, "stream %d is already open", streamID)
	}
	writer := s.writer
	sessionID := s.sessionID
	stream := newStream(s, streamID)
	s.streams[streamID] = stream
	s.mu.Unlock()

	if writer == nil {
		s.removeStream(stream)
		return nil, codedError(CodeSessionClosed, ErrSessionClosed, "session writer is unavailable")
	}
	if err := writer.WriteFrame(Frame{Type: FrameOpen, SessionID: sessionID, StreamID: streamID}); err != nil {
		s.removeStream(stream)
		s.closeTransport()
		return nil, fmt.Errorf("open egress stream: %w", err)
	}
	return stream, nil
}

// SendDatagram sends one UDP payload over the authenticated session.
func (s *Session) SendDatagram(payload []byte) error {
	if len(payload) == 0 {
		return codedError(CodeInvalidFramePayload, ErrInvalidFramePayload, "UDP datagram must not be empty")
	}
	if len(payload) > s.cfg.MaxPayload {
		return codedError(CodeFrameTooLarge, ErrFrameTooLarge, "UDP datagram is %d bytes, max %d", len(payload), s.cfg.MaxPayload)
	}
	if err := s.writeActive(Frame{Type: FrameUDP, Payload: append([]byte(nil), payload...)}); err != nil {
		return err
	}
	s.addSent(uint64(len(payload)), 1)
	return nil
}

// ReceiveDatagram waits for one return UDP payload.
func (s *Session) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	s.mu.Lock()
	queue := s.udpQueue
	done := s.runDone
	state := s.state
	s.mu.Unlock()
	if queue == nil || done == nil || state == StateStopped {
		return nil, codedError(CodeSessionClosed, ErrSessionClosed, "session is not running")
	}
	select {
	case payload := <-queue:
		return append([]byte(nil), payload...), nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-done:
		select {
		case payload := <-queue:
			return append([]byte(nil), payload...), nil
		default:
			return nil, codedError(CodeSessionClosed, ErrSessionClosed, "session closed before a datagram arrived")
		}
	}
}

func (s *Session) writeActive(frame Frame) error {
	s.mu.Lock()
	if s.state != StateRunning && s.state != StateDegraded {
		state := s.state
		s.mu.Unlock()
		return codedError(CodeSessionClosed, ErrSessionClosed, "session state is %s", state)
	}
	writer := s.writer
	frame.SessionID = s.sessionID
	s.mu.Unlock()
	if writer == nil {
		return codedError(CodeSessionClosed, ErrSessionClosed, "session writer is unavailable")
	}
	if err := writer.WriteFrame(frame); err != nil {
		s.closeTransport()
		return fmt.Errorf("write egress frame: %w", err)
	}
	return nil
}

func (s *Session) closeTransport() {
	s.mu.Lock()
	conn := s.conn
	s.mu.Unlock()
	if conn != nil {
		_ = conn.Close()
	}
}

func (s *Session) addSent(bytesCount, packets uint64) {
	s.mu.Lock()
	s.bytesSent += bytesCount
	s.packetsSent += packets
	s.updatedAt = time.Now()
	s.mu.Unlock()
}

func (s *Session) addReceived(bytesCount, packets uint64) {
	s.mu.Lock()
	s.bytesReceived += bytesCount
	s.packetsReceived += packets
	s.updatedAt = time.Now()
	s.mu.Unlock()
}

func (s *Session) removeStream(stream *Stream) {
	s.mu.Lock()
	if current := s.streams[stream.id]; current == stream {
		delete(s.streams, stream.id)
	}
	s.mu.Unlock()
}

func (s *Session) maybeRemoveStream(stream *Stream) {
	s.mu.Lock()
	current := s.streams[stream.id]
	s.mu.Unlock()
	if current != stream || !stream.closedForRemoval() {
		return
	}
	s.mu.Lock()
	if s.streams[stream.id] == stream && stream.closedForRemoval() {
		delete(s.streams, stream.id)
	}
	s.mu.Unlock()
}

func abortStreams(streams map[uint32]*Stream, err error) {
	for _, stream := range streams {
		stream.abort(err)
	}
}

// Stream is one bidirectional logical stream. CloseWrite sends FIN and leaves
// the receive direction open; Close is an alias for graceful CloseWrite.
// Session.Stop aborts both directions.
type Stream struct {
	session *Session
	id      uint32

	writeMu     sync.Mutex
	mu          sync.Mutex
	chunks      [][]byte
	offset      int
	buffered    int
	writeClosed bool
	remoteEOF   bool
	aborted     error
	notify      chan struct{}
}

func newStream(session *Session, id uint32) *Stream {
	return &Stream{session: session, id: id, notify: make(chan struct{}, 1)}
}

func (s *Stream) Write(payload []byte) (int, error) {
	if len(payload) == 0 {
		return 0, nil
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.mu.Lock()
	if s.aborted != nil {
		err := s.aborted
		s.mu.Unlock()
		return 0, err
	}
	if s.writeClosed {
		s.mu.Unlock()
		return 0, codedError(CodeStreamClosed, ErrStreamClosed, "stream %d write side is closed", s.id)
	}
	s.mu.Unlock()

	written := 0
	for len(payload) > 0 {
		chunkSize := len(payload)
		if chunkSize > s.session.cfg.MaxPayload {
			chunkSize = s.session.cfg.MaxPayload
		}
		chunk := append([]byte(nil), payload[:chunkSize]...)
		if err := s.session.writeActive(Frame{Type: FrameData, StreamID: s.id, Payload: chunk}); err != nil {
			return written, err
		}
		s.session.addSent(uint64(len(chunk)), 1)
		written += len(chunk)
		payload = payload[chunkSize:]
	}
	return written, nil
}

func (s *Stream) Read(destination []byte) (int, error) {
	if len(destination) == 0 {
		return 0, nil
	}
	for {
		s.mu.Lock()
		if len(s.chunks) == 0 {
			if s.aborted != nil {
				err := s.aborted
				s.mu.Unlock()
				return 0, err
			}
			if s.remoteEOF {
				s.mu.Unlock()
				return 0, io.EOF
			}
			notify := s.notify
			s.mu.Unlock()
			<-notify
			continue
		}
		chunk := s.chunks[0]
		n := copy(destination, chunk[s.offset:])
		s.offset += n
		s.buffered -= n
		if s.offset == len(chunk) {
			s.chunks[0] = nil
			s.chunks = s.chunks[1:]
			s.offset = 0
		}
		s.mu.Unlock()
		return n, nil
	}
}

// CloseWrite sends a FIN close frame. Data already sent in the other
// direction remains readable until the peer also closes or Session.Stop runs.
func (s *Stream) CloseWrite() error {
	if s == nil || s.session == nil {
		return codedError(CodeStreamClosed, ErrStreamClosed, "stream is nil")
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.mu.Lock()
	if s.aborted != nil {
		err := s.aborted
		s.mu.Unlock()
		return err
	}
	if s.writeClosed {
		s.mu.Unlock()
		return nil
	}
	s.mu.Unlock()

	if err := s.session.writeActive(Frame{Type: FrameClose, Flags: FlagFIN, StreamID: s.id}); err != nil {
		return err
	}
	s.mu.Lock()
	s.writeClosed = true
	s.signalLocked()
	s.mu.Unlock()
	s.session.maybeRemoveStream(s)
	return nil
}

// Close performs a graceful write half-close.
func (s *Stream) Close() error { return s.CloseWrite() }

func (s *Stream) deliver(payload []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.aborted != nil {
		return s.aborted
	}
	if s.remoteEOF {
		return nil
	}
	if s.buffered+len(payload) > MaxStreamBufferBytes {
		return codedError(CodeStreamBufferFull, ErrStreamBufferFull, "stream %d receive buffer exceeds %d bytes", s.id, MaxStreamBufferBytes)
	}
	s.chunks = append(s.chunks, append([]byte(nil), payload...))
	s.buffered += len(payload)
	s.signalLocked()
	return nil
}

func (s *Stream) deliverClose(flags uint16) {
	s.mu.Lock()
	if flags&FlagFIN == 0 {
		s.aborted = codedError(CodeStreamClosed, ErrStreamClosed, "peer aborted stream %d", s.id)
		s.chunks = nil
		s.buffered = 0
		s.offset = 0
	} else {
		s.remoteEOF = true
	}
	s.signalLocked()
	s.mu.Unlock()
	s.session.maybeRemoveStream(s)
}

func (s *Stream) deliverEOF() {
	s.mu.Lock()
	s.remoteEOF = true
	s.signalLocked()
	s.mu.Unlock()
	s.session.maybeRemoveStream(s)
}

func (s *Stream) abort(err error) {
	s.mu.Lock()
	if s.aborted == nil {
		s.aborted = err
	}
	s.chunks = nil
	s.buffered = 0
	s.offset = 0
	s.signalLocked()
	s.mu.Unlock()
}

func (s *Stream) closedForRemoval() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.aborted != nil || (s.writeClosed && s.remoteEOF)
}

func (s *Stream) signalLocked() {
	select {
	case s.notify <- struct{}{}:
	default:
	}
}
