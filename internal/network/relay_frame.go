package network

import (
	"encoding/binary"
	"io"
)

// Both ends use the same bounded, length-prefixed framing. Keep validation
// before allocation and handle partial writes without dropping packet bytes.
func readRelayPacket(reader io.Reader, limit int) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(header[:])
	if length == 0 || uint64(length) > uint64(limit) {
		return nil, ErrRelayPacketTooLarge
	}
	packet := make([]byte, int(length))
	_, err := io.ReadFull(reader, packet)
	return packet, err
}

func writeRelayPacket(writer io.Writer, payload []byte, limit int) error {
	if len(payload) == 0 || len(payload) > limit {
		return ErrRelayPacketTooLarge
	}
	packet := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(packet, uint32(len(payload)))
	copy(packet[4:], payload)
	for len(packet) > 0 {
		n, err := writer.Write(packet)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		packet = packet[n:]
	}
	return nil
}
