package egress

import (
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	FrameMagic      = "TLNE"
	ProtocolVersion = byte(1)
	FrameHeaderSize = 36
	FrameTagSize    = 16
	MaxPayloadSize  = 64 * 1024

	MaxHandshakePayload = 8 * 1024
	MaxAckPayload       = 256
	MaxClosePayload     = 512
	MaxErrorPayload     = 4 * 1024

	FlagFIN uint16 = 1 << 0
)

// FrameType is the versioned protocol frame discriminator.
type FrameType byte

const (
	FrameHandshake FrameType = 1 + iota
	FrameHandshakeAck
	FrameOpen
	FrameData
	FrameClose
	FrameUDP
	FrameKeepalive
	FrameError
	FrameRevoke
)

// Valid reports whether t is supported by protocol version 1.
func (t FrameType) Valid() bool {
	return t >= FrameHandshake && t <= FrameRevoke
}

// SessionID is the authenticated 16-byte session identifier.
type SessionID [16]byte

func (id SessionID) IsZero() bool {
	var zero SessionID
	return id == zero
}

func (id SessionID) String() string { return hex.EncodeToString(id[:]) }

// ParseSessionID accepts the canonical 32-character hexadecimal form.
func ParseSessionID(value string) (SessionID, error) {
	if len(value) != 32 {
		return SessionID{}, codedError(CodeInvalidFrame, ErrInvalidFrame, "session id must be 32 lowercase hexadecimal characters")
	}
	data, err := hex.DecodeString(value)
	if err != nil || len(data) != len(SessionID{}) {
		return SessionID{}, codedError(CodeInvalidFrame, ErrInvalidFrame, "session id is invalid")
	}
	var id SessionID
	copy(id[:], data)
	if id.IsZero() {
		return SessionID{}, codedError(CodeInvalidFrame, ErrInvalidFrame, "session id must not be zero")
	}
	return id, nil
}

// Direction selects an independent HKDF-derived frame key for each traffic
// direction. Sharing a key across directions would reuse nonces for handshake
// and handshake-ack frames.
type Direction string

const (
	DirectionClientToServer Direction = "client-to-server"
	DirectionServerToClient Direction = "server-to-client"
)

func (d Direction) Valid() bool {
	return d == DirectionClientToServer || d == DirectionServerToClient
}

// Frame is the decoded protocol frame. The wire streamID field is the 64-bit
// tuple streamID(32)|sequence(32), giving each stream a monotonically
// increasing replay counter while retaining compact fixed headers.
type Frame struct {
	Type      FrameType
	Flags     uint16
	SessionID SessionID
	StreamID  uint32
	Sequence  uint32
	Payload   []byte
}

type frameAEAD struct {
	aead cipher.AEAD
}

func deriveFrameKey(secret []byte, direction Direction) ([]byte, error) {
	if len(secret) != 32 {
		return nil, codedError(CodeInvalidFrame, ErrInvalidFrame, "frame secret must be exactly 32 bytes")
	}
	if !direction.Valid() {
		return nil, codedError(CodeInvalidFrame, ErrInvalidFrame, "frame direction is invalid")
	}
	context := []byte("TLAN egress frame v1 " + string(direction))
	reader := hkdf.New(sha256.New, secret, []byte("TLAN egress frame v1 salt"), context)
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(reader, key); err != nil {
		return nil, fmt.Errorf("derive egress frame key: %w", err)
	}
	return key, nil
}

// DeriveHandshakeSecret returns the fixed key used only for the handshake
// frames. The handshake carries the capability; it is protected by TLS and by
// this key so a passive observer without TLS cannot read it. After the
// handshake both sides switch to DeriveSessionSecret.
func DeriveHandshakeSecret() []byte {
	sum := sha256.Sum256([]byte("TLAN egress handshake v1"))
	return sum[:]
}

// DeriveSessionSecret derives the 32-byte data-plane key from the one-time
// lease capability. The gateway stores only the capability hash and derives the
// same key after authenticating the handshake.
func DeriveSessionSecret(capability string) []byte {
	sum := sha256.Sum256([]byte("TLAN egress session capability v1\x00" + capability))
	return sum[:]
}
func newFrameAEAD(secret []byte, direction Direction) (frameAEAD, error) {
	key, err := deriveFrameKey(secret, direction)
	if err != nil {
		return frameAEAD{}, err
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return frameAEAD{}, fmt.Errorf("create egress frame AEAD: %w", err)
	}
	return frameAEAD{aead: aead}, nil
}

// FrameWriter serializes authenticated frames and assigns monotonically
// increasing sequence numbers per stream.
type FrameWriter struct {
	w    io.Writer
	aead frameAEAD
	mu   sync.Mutex
	next map[uint32]uint32
}

func NewFrameWriter(w io.Writer, secret []byte, direction Direction) (*FrameWriter, error) {
	if w == nil {
		return nil, codedError(CodeInvalidFrame, ErrInvalidFrame, "frame writer is nil")
	}
	aead, err := newFrameAEAD(secret, direction)
	if err != nil {
		return nil, err
	}
	return &FrameWriter{w: w, aead: aead, next: make(map[uint32]uint32)}, nil
}

func (w *FrameWriter) WriteFrame(frame Frame) error {
	if w == nil {
		return codedError(CodeInvalidFrame, ErrInvalidFrame, "frame writer is nil")
	}
	if err := validateFramePayload(frame.Type, frame.Flags, frame.Payload); err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	sequence, seen := w.next[frame.StreamID]
	if !seen {
		sequence = 0
	} else if sequence == ^uint32(0) {
		return codedError(CodeSequenceExhausted, ErrSequenceExhausted, "stream %d exhausted its frame sequence", frame.StreamID)
	}
	frame.Sequence = sequence
	wire, err := encodeFrame(w.aead.aead, frame)
	if err != nil {
		return err
	}
	if err := writeAll(w.w, wire); err != nil {
		return fmt.Errorf("write egress frame: %w", err)
	}
	w.next[frame.StreamID] = sequence + 1
	return nil
}

func encodeFrame(aead cipher.AEAD, frame Frame) ([]byte, error) {
	if !frame.Type.Valid() {
		return nil, codedError(CodeUnknownFrameType, ErrUnknownFrameType, "frame type %d is unknown", frame.Type)
	}
	if len(frame.Payload) > MaxPayloadSize {
		return nil, codedError(CodeFrameTooLarge, ErrFrameTooLarge, "payload is %d bytes, max %d", len(frame.Payload), MaxPayloadSize)
	}
	if err := validateFramePayload(frame.Type, frame.Flags, frame.Payload); err != nil {
		return nil, err
	}
	header := make([]byte, FrameHeaderSize)
	copy(header[0:4], FrameMagic)
	header[4] = ProtocolVersion
	header[5] = byte(frame.Type)
	binary.BigEndian.PutUint16(header[6:8], frame.Flags)
	copy(header[8:24], frame.SessionID[:])
	wireStream := uint64(frame.StreamID)<<32 | uint64(frame.Sequence)
	binary.BigEndian.PutUint64(header[24:32], wireStream)
	binary.BigEndian.PutUint32(header[32:36], uint32(len(frame.Payload)))
	nonce := frameNonce(frame.SessionID, wireStream)
	sealed := aead.Seal(nil, nonce[:], frame.Payload, header)
	wire := make([]byte, 0, len(header)+len(sealed))
	wire = append(wire, header...)
	wire = append(wire, sealed...)
	return wire, nil
}

func frameNonce(sessionID SessionID, wireStream uint64) [chacha20poly1305.NonceSize]byte {
	var input [24]byte
	copy(input[0:16], sessionID[:])
	binary.BigEndian.PutUint64(input[16:24], wireStream)
	sum := sha256.Sum256(input[:])
	var nonce [chacha20poly1305.NonceSize]byte
	copy(nonce[:], sum[:chacha20poly1305.NonceSize])
	return nonce
}

// FrameRateGuard is a bounded local frame counter. It is intentionally
// per-reader so no package-global mutable state is shared between sessions.
type FrameRateGuard struct {
	mu          sync.Mutex
	maxFrames   int
	window      time.Duration
	windowStart time.Time
	count       int
}

func NewFrameRateGuard(maxFrames int, window time.Duration) (*FrameRateGuard, error) {
	if maxFrames <= 0 || window <= 0 {
		return nil, codedError(CodeFrameRateLimited, ErrFrameRateLimited, "frame limit and window must be positive")
	}
	return &FrameRateGuard{maxFrames: maxFrames, window: window}, nil
}

func (g *FrameRateGuard) Allow(now time.Time) bool {
	if g == nil {
		return true
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.windowStart.IsZero() || now.Sub(g.windowStart) >= g.window {
		g.windowStart = now
		g.count = 0
	}
	if g.count >= g.maxFrames {
		return false
	}
	g.count++
	return true
}

// FrameReader performs bounded reads, authentication, session binding, rate
// limiting, and strict per-stream replay checks.
type FrameReader struct {
	r        io.Reader
	aead     frameAEAD
	expected *SessionID
	replay   map[uint32]uint32
	rate     *FrameRateGuard
}

func NewFrameReader(r io.Reader, secret []byte, direction Direction) (*FrameReader, error) {
	if r == nil {
		return nil, codedError(CodeInvalidFrame, ErrInvalidFrame, "frame reader is nil")
	}
	aead, err := newFrameAEAD(secret, direction)
	if err != nil {
		return nil, err
	}
	return &FrameReader{
		r:      r,
		aead:   aead,
		replay: make(map[uint32]uint32),
	}, nil
}

func (r *FrameReader) SetExpectedSession(id SessionID) {
	copied := id
	r.expected = &copied
}

func (r *FrameReader) ClearExpectedSession() { r.expected = nil }

func (r *FrameReader) SetRateGuard(guard *FrameRateGuard) { r.rate = guard }

func (r *FrameReader) ReadFrame() (Frame, error) {
	if r == nil || r.r == nil {
		return Frame{}, codedError(CodeInvalidFrame, ErrInvalidFrame, "frame reader is nil")
	}
	header := make([]byte, FrameHeaderSize)
	if _, err := io.ReadFull(r.r, header); err != nil {
		return Frame{}, fmt.Errorf("read egress frame header: %w", err)
	}
	if string(header[0:4]) != FrameMagic {
		return Frame{}, codedError(CodeInvalidFrame, ErrInvalidFrame, "frame magic is invalid")
	}
	if header[4] != ProtocolVersion {
		return Frame{}, codedError(CodeInvalidFrame, ErrInvalidFrame, "frame version %d is unsupported", header[4])
	}
	frameType := FrameType(header[5])
	if !frameType.Valid() {
		return Frame{}, codedError(CodeUnknownFrameType, ErrUnknownFrameType, "frame type %d is unknown", frameType)
	}
	flags := binary.BigEndian.Uint16(header[6:8])
	var sessionID SessionID
	copy(sessionID[:], header[8:24])
	if r.expected != nil && sessionID != *r.expected {
		return Frame{}, codedError(CodeSessionMismatch, ErrSessionMismatch, "frame session %s does not match authenticated session", sessionID.String())
	}
	payloadLen := binary.BigEndian.Uint32(header[32:36])
	if payloadLen > MaxPayloadSize {
		return Frame{}, codedError(CodeFrameTooLarge, ErrFrameTooLarge, "declared payload is %d bytes, max %d", payloadLen, MaxPayloadSize)
	}
	if payloadLen > framePayloadLimit(frameType) {
		return Frame{}, codedError(CodeInvalidFramePayload, ErrInvalidFramePayload, "frame type %d payload is %d bytes, max %d", frameType, payloadLen, framePayloadLimit(frameType))
	}
	if r.rate != nil && !r.rate.Allow(time.Now()) {
		return Frame{}, codedError(CodeFrameRateLimited, ErrFrameRateLimited, "frame rate limit exceeded")
	}
	sealed := make([]byte, int(payloadLen)+FrameTagSize)
	if _, err := io.ReadFull(r.r, sealed); err != nil {
		return Frame{}, fmt.Errorf("read egress frame payload: %w", err)
	}
	wireStream := binary.BigEndian.Uint64(header[24:32])
	nonce := frameNonce(sessionID, wireStream)
	payload, err := r.aead.aead.Open(nil, nonce[:], sealed, header)
	if err != nil {
		return Frame{}, codedError(CodeAuthentication, ErrAuthentication, "authenticate egress frame: %v", err)
	}
	frame := Frame{
		Type:      frameType,
		Flags:     flags,
		SessionID: sessionID,
		StreamID:  uint32(wireStream >> 32),
		Sequence:  uint32(wireStream),
		Payload:   payload,
	}
	if err := validateFramePayload(frame.Type, frame.Flags, frame.Payload); err != nil {
		return Frame{}, err
	}
	if previous, seen := r.replay[frame.StreamID]; seen && frame.Sequence <= previous {
		return Frame{}, codedError(CodeReplay, ErrReplay, "stream %d sequence %d follows %d", frame.StreamID, frame.Sequence, previous)
	}
	r.replay[frame.StreamID] = frame.Sequence
	return frame, nil
}

func framePayloadLimit(frameType FrameType) uint32 {
	switch frameType {
	case FrameKeepalive, FrameRevoke:
		return 0
	case FrameHandshakeAck:
		return MaxAckPayload
	case FrameClose:
		return MaxClosePayload
	case FrameError:
		return MaxErrorPayload
	case FrameHandshake:
		return MaxHandshakePayload
	default:
		return MaxPayloadSize
	}
}

func validateFramePayload(frameType FrameType, flags uint16, payload []byte) error {
	if !frameType.Valid() {
		return codedError(CodeUnknownFrameType, ErrUnknownFrameType, "frame type %d is unknown", frameType)
	}
	if flags & ^FlagFIN != 0 {
		return codedError(CodeInvalidFramePayload, ErrInvalidFramePayload, "frame flags %#x are unsupported", flags)
	}
	if len(payload) > MaxPayloadSize {
		return codedError(CodeFrameTooLarge, ErrFrameTooLarge, "payload is %d bytes, max %d", len(payload), MaxPayloadSize)
	}
	limit := framePayloadLimit(frameType)
	if len(payload) > int(limit) {
		return codedError(CodeInvalidFramePayload, ErrInvalidFramePayload, "frame type %d payload is %d bytes, max %d", frameType, len(payload), limit)
	}
	if (frameType == FrameKeepalive || frameType == FrameRevoke) && len(payload) != 0 {
		return codedError(CodeInvalidFramePayload, ErrInvalidFramePayload, "frame type %d must not carry a payload", frameType)
	}
	return nil
}

func writeAll(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		written, err := writer.Write(data)
		if err != nil {
			return err
		}
		if written <= 0 || written > len(data) {
			return io.ErrShortWrite
		}
		data = data[written:]
	}
	return nil
}

// IsClosedError reports whether err represents an expected stopped transport.
func IsClosedError(err error) bool {
	return err != nil && (errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed))
}
