package egress

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
)

// OpenTarget identifies the destination the gateway should reach on behalf of
// one TCP stream or UDP datagram. Host may be a literal IP or a DNS name; the
// gateway always resolves it and enforces policy on every resolved address.
type OpenTarget struct {
	Host     string   `json:"host"`
	Port     uint16   `json:"port"`
	Protocol Protocol `json:"protocol"`
}

const (
	targetHeaderVersion = byte(1)
	maxTargetHostBytes  = 253
)

// Validate checks the target shape only. Address policy is enforced by the
// gateway against every resolved address.
func (t OpenTarget) Validate() error {
	host := strings.TrimSpace(t.Host)
	if host == "" {
		return codedError(CodeInvalidFramePayload, ErrInvalidFramePayload, "target host is required")
	}
	if len(host) > maxTargetHostBytes {
		return codedError(CodeInvalidFramePayload, ErrInvalidFramePayload, "target host is too long")
	}
	if strings.ContainsAny(host, "\x00\r\n\t ") || strings.Contains(host, "/") {
		return codedError(CodeInvalidFramePayload, ErrInvalidFramePayload, "target host contains invalid characters")
	}
	if t.Port == 0 {
		return codedError(CodeInvalidFramePayload, ErrInvalidFramePayload, "target port is required")
	}
	switch t.Protocol {
	case ProtocolTCP, ProtocolUDP:
	default:
		return codedError(CodeInvalidFramePayload, ErrInvalidFramePayload, "unsupported target protocol %q", t.Protocol)
	}
	return nil
}

// Address renders host:port using net.JoinHostPort.
func (t OpenTarget) Address() string {
	return net.JoinHostPort(t.Host, strconv.Itoa(int(t.Port)))
}

func (t OpenTarget) String() string {
	return string(t.Protocol) + "://" + t.Address()
}

// encodeTargetHeader renders version|protocol|hostLen|host|port(2 BE).
func encodeTargetHeader(t OpenTarget) ([]byte, error) {
	if err := t.Validate(); err != nil {
		return nil, err
	}
	host := []byte(strings.TrimSpace(t.Host))
	if len(host) > maxTargetHostBytes {
		return nil, codedError(CodeInvalidFramePayload, ErrInvalidFramePayload, "target host is too long")
	}
	var protocolByte byte
	switch t.Protocol {
	case ProtocolTCP:
		protocolByte = 1
	case ProtocolUDP:
		protocolByte = 2
	}
	header := make([]byte, 0, 5+len(host))
	header = append(header, targetHeaderVersion, protocolByte, byte(len(host)))
	header = append(header, host...)
	header = append(header, byte(t.Port>>8), byte(t.Port))
	return header, nil
}

// DecodeTargetHeader reads one bounded target header and returns the target.
// It never allocates more than maxTargetHostBytes for the host.
func DecodeTargetHeader(r io.Reader) (OpenTarget, error) {
	var prefix [3]byte
	if _, err := io.ReadFull(r, prefix[:]); err != nil {
		return OpenTarget{}, fmt.Errorf("read target header: %w", err)
	}
	if prefix[0] != targetHeaderVersion {
		return OpenTarget{}, codedError(CodeInvalidFramePayload, ErrInvalidFramePayload, "unsupported target header version %d", prefix[0])
	}
	var protocol Protocol
	switch prefix[1] {
	case 1:
		protocol = ProtocolTCP
	case 2:
		protocol = ProtocolUDP
	default:
		return OpenTarget{}, codedError(CodeInvalidFramePayload, ErrInvalidFramePayload, "unsupported target protocol byte %d", prefix[1])
	}
	hostLen := int(prefix[2])
	if hostLen == 0 || hostLen > maxTargetHostBytes {
		return OpenTarget{}, codedError(CodeInvalidFramePayload, ErrInvalidFramePayload, "invalid target host length %d", hostLen)
	}
	host := make([]byte, hostLen)
	if _, err := io.ReadFull(r, host); err != nil {
		return OpenTarget{}, fmt.Errorf("read target host: %w", err)
	}
	var portBytes [2]byte
	if _, err := io.ReadFull(r, portBytes[:]); err != nil {
		return OpenTarget{}, fmt.Errorf("read target port: %w", err)
	}
	target := OpenTarget{
		Host:     string(host),
		Port:     binary.BigEndian.Uint16(portBytes[:]),
		Protocol: protocol,
	}
	if err := target.Validate(); err != nil {
		return OpenTarget{}, err
	}
	return target, nil
}

// WriteTargetPreamble writes the target header that precedes a TCP stream's
// payload. The gateway reads it before dialing.
func WriteTargetPreamble(w io.Writer, target OpenTarget) error {
	header, err := encodeTargetHeader(target)
	if err != nil {
		return err
	}
	_, err = w.Write(header)
	return err
}

// ReadTargetPreamble reads one target header from a buffered reader.
func ReadTargetPreamble(r *bufio.Reader) (OpenTarget, error) {
	return DecodeTargetHeader(r)
}

// EncodeDatagram renders one UDP datagram as targetHeader|payload.
func EncodeDatagram(target OpenTarget, payload []byte) ([]byte, error) {
	if len(payload) == 0 {
		return nil, codedError(CodeInvalidFramePayload, ErrInvalidFramePayload, "UDP datagram must not be empty")
	}
	header, err := encodeTargetHeader(target)
	if err != nil {
		return nil, err
	}
	if len(header)+len(payload) > MaxPayloadSize {
		return nil, codedError(CodeFrameTooLarge, ErrFrameTooLarge, "UDP datagram exceeds %d bytes", MaxPayloadSize)
	}
	out := make([]byte, 0, len(header)+len(payload))
	out = append(out, header...)
	out = append(out, payload...)
	return out, nil
}

// DecodeDatagram splits a UDP frame payload into target and payload.
func DecodeDatagram(data []byte) (OpenTarget, []byte, error) {
	target, err := DecodeTargetHeader(bytesReader(data))
	if err != nil {
		return OpenTarget{}, nil, err
	}
	header, err := encodeTargetHeader(target)
	if err != nil {
		return OpenTarget{}, nil, err
	}
	if len(data) <= len(header) {
		return OpenTarget{}, nil, codedError(CodeInvalidFramePayload, ErrInvalidFramePayload, "UDP datagram payload is empty")
	}
	return target, data[len(header):], nil
}

func bytesReader(data []byte) *bufio.Reader {
	return bufio.NewReader(bytes.NewReader(data))
}
