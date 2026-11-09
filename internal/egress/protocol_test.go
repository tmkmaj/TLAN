package egress

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

func testSessionID(seed byte) SessionID {
	var id SessionID
	for i := range id {
		id[i] = seed + byte(i)
	}
	return id
}

func rawFrameHeader(magic string, version, frameType byte, flags uint16, sessionID SessionID, streamID, sequence, payloadLen uint32) []byte {
	header := make([]byte, FrameHeaderSize)
	copy(header[0:4], magic)
	header[4] = version
	header[5] = frameType
	binary.BigEndian.PutUint16(header[6:8], flags)
	copy(header[8:24], sessionID[:])
	binary.BigEndian.PutUint64(header[24:32], uint64(streamID)<<32|uint64(sequence))
	binary.BigEndian.PutUint32(header[32:36], payloadLen)
	return header
}

func newTestFrameWriter(t *testing.T, w io.Writer) *FrameWriter {
	t.Helper()
	writer, err := NewFrameWriter(w, bytes.Repeat([]byte{0x42}, 32), DirectionClientToServer)
	if err != nil {
		t.Fatal(err)
	}
	return writer
}

func newTestFrameReader(t *testing.T, r io.Reader) *FrameReader {
	t.Helper()
	reader, err := NewFrameReader(r, bytes.Repeat([]byte{0x42}, 32), DirectionClientToServer)
	if err != nil {
		t.Fatal(err)
	}
	return reader
}

func TestFrameRoundTrip(t *testing.T) {
	t.Parallel()

	var wire bytes.Buffer
	writer := newTestFrameWriter(t, &wire)
	want := Frame{
		Type:      FrameData,
		Flags:     FlagFIN,
		SessionID: testSessionID(1),
		StreamID:  7,
		Payload:   []byte("hello"),
	}
	if err := writer.WriteFrame(want); err != nil {
		t.Fatalf("WriteFrame(): %v", err)
	}
	reader := newTestFrameReader(t, bytes.NewReader(wire.Bytes()))
	reader.SetExpectedSession(want.SessionID)
	got, err := reader.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame(): %v", err)
	}
	if got.Type != want.Type || got.Flags != want.Flags || got.SessionID != want.SessionID || got.StreamID != want.StreamID || got.Sequence != 0 || !bytes.Equal(got.Payload, want.Payload) {
		t.Fatalf("ReadFrame() = %+v, want %+v", got, want)
	}
}

func TestFrameHeaderValidation(t *testing.T) {
	t.Parallel()

	sessionID := testSessionID(9)
	tests := []struct {
		name   string
		header []byte
		errIs  error
	}{
		{name: "wrong magic", header: rawFrameHeader("NOPE", ProtocolVersion, byte(FrameData), 0, sessionID, 1, 0, 0), errIs: ErrInvalidFrame},
		{name: "wrong version", header: rawFrameHeader(FrameMagic, ProtocolVersion+1, byte(FrameData), 0, sessionID, 1, 0, 0), errIs: ErrInvalidFrame},
		{name: "unknown type", header: rawFrameHeader(FrameMagic, ProtocolVersion, 0xff, 0, sessionID, 1, 0, 0), errIs: ErrUnknownFrameType},
		{name: "oversized before allocation", header: rawFrameHeader(FrameMagic, ProtocolVersion, byte(FrameData), 0, sessionID, 1, 0, MaxPayloadSize+1), errIs: ErrFrameTooLarge},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			reader := newTestFrameReader(t, bytes.NewReader(tc.header))
			reader.SetExpectedSession(sessionID)
			_, err := reader.ReadFrame()
			if !errors.Is(err, tc.errIs) {
				t.Fatalf("ReadFrame() error = %v, want %v", err, tc.errIs)
			}
		})
	}
}

func TestFrameWrongSessionAndTruncation(t *testing.T) {
	t.Parallel()

	var wire bytes.Buffer
	writer := newTestFrameWriter(t, &wire)
	frame := Frame{Type: FrameData, SessionID: testSessionID(1), StreamID: 3, Payload: []byte("payload")}
	if err := writer.WriteFrame(frame); err != nil {
		t.Fatal(err)
	}
	encoded := append([]byte(nil), wire.Bytes()...)

	reader := newTestFrameReader(t, bytes.NewReader(encoded))
	reader.SetExpectedSession(testSessionID(2))
	if _, err := reader.ReadFrame(); !errors.Is(err, ErrSessionMismatch) {
		t.Fatalf("wrong session error = %v, want ErrSessionMismatch", err)
	}

	truncated := encoded[:len(encoded)-1]
	reader = newTestFrameReader(t, bytes.NewReader(truncated))
	reader.SetExpectedSession(frame.SessionID)
	if _, err := reader.ReadFrame(); err == nil {
		t.Fatal("ReadFrame() accepted truncated frame")
	}
}

func TestFrameAuthenticationAndReplay(t *testing.T) {
	t.Parallel()

	var wire bytes.Buffer
	writer := newTestFrameWriter(t, &wire)
	frame := Frame{Type: FrameData, SessionID: testSessionID(3), StreamID: 1, Payload: []byte("authenticated")}
	if err := writer.WriteFrame(frame); err != nil {
		t.Fatal(err)
	}
	encoded := append([]byte(nil), wire.Bytes()...)

	tampered := append([]byte(nil), encoded...)
	tampered[len(tampered)-1] ^= 0xff
	reader := newTestFrameReader(t, bytes.NewReader(tampered))
	reader.SetExpectedSession(frame.SessionID)
	if _, err := reader.ReadFrame(); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("tampered frame error = %v, want ErrAuthentication", err)
	}

	reader = newTestFrameReader(t, bytes.NewReader(append(append([]byte(nil), encoded...), encoded...)))
	reader.SetExpectedSession(frame.SessionID)
	if _, err := reader.ReadFrame(); err != nil {
		t.Fatalf("first replay read: %v", err)
	}
	if _, err := reader.ReadFrame(); !errors.Is(err, ErrReplay) {
		t.Fatalf("replayed frame error = %v, want ErrReplay", err)
	}
}

func TestFrameRateGuard(t *testing.T) {
	t.Parallel()

	guard, err := NewFrameRateGuard(1, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	var wire bytes.Buffer
	writer := newTestFrameWriter(t, &wire)
	sessionID := testSessionID(4)
	for i := 0; i < 2; i++ {
		if err := writer.WriteFrame(Frame{Type: FrameKeepalive, SessionID: sessionID}); err != nil {
			t.Fatal(err)
		}
	}
	reader := newTestFrameReader(t, bytes.NewReader(wire.Bytes()))
	reader.SetExpectedSession(sessionID)
	reader.SetRateGuard(guard)
	if _, err := reader.ReadFrame(); err != nil {
		t.Fatalf("first ReadFrame(): %v", err)
	}
	if _, err := reader.ReadFrame(); !errors.Is(err, ErrFrameRateLimited) {
		t.Fatalf("second ReadFrame() error = %v, want ErrFrameRateLimited", err)
	}
}

func TestControlFramePayloadRule(t *testing.T) {
	t.Parallel()

	var wire bytes.Buffer
	writer := newTestFrameWriter(t, &wire)
	err := writer.WriteFrame(Frame{Type: FrameKeepalive, SessionID: testSessionID(5), Payload: []byte("not allowed")})
	if !errors.Is(err, ErrInvalidFramePayload) {
		t.Fatalf("WriteFrame(keepalive payload) error = %v, want ErrInvalidFramePayload", err)
	}
}

func TestFrameReaderDoesNotReadOversizedPayload(t *testing.T) {
	t.Parallel()

	header := rawFrameHeader(FrameMagic, ProtocolVersion, byte(FrameData), 0, testSessionID(6), 1, 0, MaxPayloadSize)
	reader := newTestFrameReader(t, &countingReader{data: header})
	reader.SetExpectedSession(testSessionID(6))
	if _, err := reader.ReadFrame(); err == nil {
		t.Fatal("ReadFrame() accepted a header without its payload")
	}
}

type countingReader struct {
	data []byte
	read int
}

func (r *countingReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.data)
	r.read += n
	r.data = r.data[n:]
	return n, nil
}

func TestFrameWriterRefusesSequenceWrap(t *testing.T) {
	t.Parallel()

	var wire bytes.Buffer
	writer := newTestFrameWriter(t, &wire)
	writer.next[1] = ^uint32(0)
	err := writer.WriteFrame(Frame{Type: FrameData, SessionID: testSessionID(7), StreamID: 1, Payload: []byte("x")})
	if !errors.Is(err, ErrSequenceExhausted) {
		t.Fatalf("WriteFrame() error = %v, want ErrSequenceExhausted", err)
	}
	if wire.Len() != 0 {
		t.Fatalf("writer produced %d bytes after sequence exhaustion", wire.Len())
	}
}

func TestParseSessionIDAcceptsUpperAndLowerHex(t *testing.T) {
	t.Parallel()

	lower := "00112233445566778899aabbccddeeff"
	for _, value := range []string{lower, strings.ToUpper(lower)} {
		if _, err := ParseSessionID(value); err != nil {
			t.Fatalf("ParseSessionID(%q): %v", value, err)
		}
	}
}
