package network

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

type partialWriter struct {
	bytes.Buffer
	chunk int
}

func (w *partialWriter) Write(p []byte) (int, error) {
	return w.Buffer.Write(p[:min(len(p), w.chunk)])
}

func TestRelayFramePartialWrites(t *testing.T) {
	w := &partialWriter{chunk: 2}
	for _, packet := range []string{"first packet", "second packet"} {
		if err := writeRelayPacket(w, []byte(packet), 64); err != nil {
			t.Fatal(err)
		}
	}
	for _, want := range []string{"first packet", "second packet"} {
		got, err := readRelayPacket(&w.Buffer, 64)
		if err != nil || string(got) != want {
			t.Fatalf("packet = %q, error = %v", got, err)
		}
	}
	if err := writeRelayPacket(&partialWriter{}, []byte("no progress"), 64); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("zero write error = %v", err)
	}
}

func TestRelayFrameRejectsInvalidLengths(t *testing.T) {
	for _, tc := range []struct {
		name  string
		frame []byte
		err   error
	}{
		{"empty", []byte{0, 0, 0, 0}, ErrRelayPacketTooLarge},
		{"oversized", []byte{0, 0, 0, 65}, ErrRelayPacketTooLarge},
		{"overflow", []byte{255, 255, 255, 255}, ErrRelayPacketTooLarge},
		{"short header", []byte{0, 0}, io.ErrUnexpectedEOF},
		{"short payload", []byte{0, 0, 0, 2, 1}, io.ErrUnexpectedEOF},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := readRelayPacket(bytes.NewReader(tc.frame), 64); !errors.Is(err, tc.err) {
				t.Fatalf("error = %v", err)
			}
		})
	}
	for _, size := range []int{0, 65} {
		var output bytes.Buffer
		if err := writeRelayPacket(&output, make([]byte, size), 64); !errors.Is(err, ErrRelayPacketTooLarge) || output.Len() != 0 {
			t.Fatalf("invalid payload size %d: error = %v, bytes = %d", size, err, output.Len())
		}
	}
}
