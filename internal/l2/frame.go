package l2

import (
	"encoding/binary"
	"errors"
)

const (
	EthernetHeaderSize = 14
	EtherTypeIPv4      = 0x0800
	EtherTypeARP       = 0x0806
	DefaultMTU         = 1500
	DefaultMaxFrame    = EthernetHeaderSize + DefaultMTU
)

var (
	ErrFrameTooShort = errors.New("ethernet frame is too short")
	ErrFrameTooLarge = errors.New("ethernet frame exceeds configured MTU")
	ErrInvalidMAC    = errors.New("ethernet frame contains an invalid MAC address")
)

// Frame is an Ethernet II frame without the optional FCS trailer.
type Frame struct {
	Destination MAC
	Source      MAC
	EtherType   uint16
	Payload     []byte
}

func ParseFrame(raw []byte, maxFrameSize int) (Frame, error) {
	if maxFrameSize <= 0 {
		maxFrameSize = DefaultMaxFrame
	}
	if len(raw) < EthernetHeaderSize {
		return Frame{}, ErrFrameTooShort
	}
	if len(raw) > maxFrameSize {
		return Frame{}, ErrFrameTooLarge
	}
	var frame Frame
	copy(frame.Destination[:], raw[0:6])
	copy(frame.Source[:], raw[6:12])
	if frame.Destination.IsZero() || !frame.Source.IsUnicast() {
		return Frame{}, ErrInvalidMAC
	}
	frame.EtherType = binary.BigEndian.Uint16(raw[12:14])
	frame.Payload = append([]byte(nil), raw[14:]...)
	return frame, nil
}

func (f Frame) Validate(maxFrameSize int) error {
	if maxFrameSize <= 0 {
		maxFrameSize = DefaultMaxFrame
	}
	if f.Destination.IsZero() || !f.Source.IsUnicast() {
		return ErrInvalidMAC
	}
	if EthernetHeaderSize+len(f.Payload) < EthernetHeaderSize {
		return ErrFrameTooShort
	}
	if EthernetHeaderSize+len(f.Payload) > maxFrameSize {
		return ErrFrameTooLarge
	}
	return nil
}

func (f Frame) MarshalBinary() ([]byte, error) {
	if err := f.Validate(DefaultMaxFrame); err != nil {
		return nil, err
	}
	raw := make([]byte, EthernetHeaderSize+len(f.Payload))
	copy(raw[0:6], f.Destination[:])
	copy(raw[6:12], f.Source[:])
	binary.BigEndian.PutUint16(raw[12:14], f.EtherType)
	copy(raw[14:], f.Payload)
	return raw, nil
}
