package network

// This file contains the small subset of RFC 5389 needed for a binding
// probe. It intentionally avoids a STUN dependency: the probe is used for
// diagnostics and candidate gathering, not as a complete ICE implementation.

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"time"
)

const (
	stunMagicCookie    uint32 = 0x2112A442
	stunHeaderSize            = 20
	stunBindingRequest        = 0x0001
	stunBindingSuccess        = 0x0101
	stunBindingError          = 0x0111

	stunAttrMappedAddress    = 0x0001
	stunAttrErrorCode        = 0x0009
	stunAttrXORMappedAddress = 0x0020
	stunMaxResponseSize      = 64 * 1024
	defaultSTUNProbeTimeout  = 5 * time.Second
)

// UDPSTUNClient performs a RFC 5389 Binding request over UDP. A zero Timeout
// uses a five second deadline. Dialer is optional and is useful for tests or
// callers that need a custom local interface.
type UDPSTUNClient struct {
	Dialer  *net.Dialer
	Timeout time.Duration
}

// NewUDPSTUNClient returns a client with conservative diagnostic defaults.
func NewUDPSTUNClient() *UDPSTUNClient {
	return &UDPSTUNClient{Timeout: defaultSTUNProbeTimeout}
}

// Probe sends one Binding request to server (host:port) and returns the
// server-observed address. The context bounds DNS, connect, write, and read.
func (c *UDPSTUNClient) Probe(ctx context.Context, server string) (STUNResult, error) {
	if ctx == nil {
		return STUNResult{}, errors.New("nil context")
	}
	if strings.TrimSpace(server) == "" {
		return STUNResult{}, errors.New("STUN server address is required")
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = defaultSTUNProbeTimeout
	}
	deadline := time.Now().Add(timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	if !deadline.After(time.Now()) {
		return STUNResult{}, context.DeadlineExceeded
	}

	dialer := c.Dialer
	if dialer == nil {
		dialer = &net.Dialer{}
	}
	conn, err := dialer.DialContext(ctx, "udp", server)
	if err != nil {
		if ctx.Err() != nil {
			return STUNResult{}, ctx.Err()
		}
		return STUNResult{}, fmt.Errorf("STUN dial %q: %w", server, err)
	}
	defer conn.Close()
	// Closing the connection on cancellation makes a blocked ReadFrom return
	// promptly even when the caller's context has no deadline.
	stopCancel := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-stopCancel:
		}
	}()
	defer close(stopCancel)

	txid, err := newSTUNTransactionID()
	if err != nil {
		return STUNResult{}, err
	}
	request := makeSTUNBindingRequest(txid)
	if err := conn.SetDeadline(deadline); err != nil {
		return STUNResult{}, fmt.Errorf("set STUN deadline: %w", err)
	}
	if _, err := conn.Write(request); err != nil {
		if ctx.Err() != nil {
			return STUNResult{}, ctx.Err()
		}
		return STUNResult{}, fmt.Errorf("send STUN binding request: %w", err)
	}
	response := make([]byte, stunMaxResponseSize)
	n, err := conn.Read(response)
	if err != nil {
		if ctx.Err() != nil {
			return STUNResult{}, ctx.Err()
		}
		if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
			return STUNResult{}, context.DeadlineExceeded
		}
		return STUNResult{}, fmt.Errorf("read STUN binding response: %w", err)
	}
	result, err := parseSTUNBindingResponse(response[:n], txid, conn.LocalAddr())
	if err != nil {
		return STUNResult{}, err
	}
	result.ServerAddress = server
	return result, nil
}

func newSTUNTransactionID() ([12]byte, error) {
	var txid [12]byte
	if _, err := io.ReadFull(rand.Reader, txid[:]); err != nil {
		return txid, fmt.Errorf("generate STUN transaction ID: %w", err)
	}
	return txid, nil
}

// DecodeSTUNMappedAddress validates a response received on an existing socket.
func DecodeSTUNMappedAddress(packet []byte, id [12]byte) (netip.AddrPort, error) {
	result, err := parseSTUNBindingResponse(packet, id, nil)
	if err != nil {
		return netip.AddrPort{}, err
	}
	return netip.ParseAddrPort(result.MappedAddress)
}

func makeSTUNBindingRequest(txid [12]byte) []byte {
	packet := make([]byte, stunHeaderSize)
	binary.BigEndian.PutUint16(packet[0:2], stunBindingRequest)
	binary.BigEndian.PutUint16(packet[2:4], 0)
	binary.BigEndian.PutUint32(packet[4:8], stunMagicCookie)
	copy(packet[8:], txid[:])
	return packet
}

func parseSTUNBindingResponse(packet []byte, txid [12]byte, local net.Addr) (STUNResult, error) {
	if len(packet) < stunHeaderSize {
		return STUNResult{}, errors.New("STUN response is shorter than the header")
	}
	messageType := binary.BigEndian.Uint16(packet[0:2])
	if messageType != stunBindingSuccess && messageType != stunBindingError {
		return STUNResult{}, fmt.Errorf("unexpected STUN message type 0x%04x", messageType)
	}
	messageLength := int(binary.BigEndian.Uint16(packet[2:4]))
	if messageLength%4 != 0 || stunHeaderSize+messageLength != len(packet) {
		return STUNResult{}, errors.New("invalid STUN message length")
	}
	if binary.BigEndian.Uint32(packet[4:8]) != stunMagicCookie {
		return STUNResult{}, errors.New("invalid STUN magic cookie")
	}
	if !equalBytes(packet[8:20], txid[:]) {
		return STUNResult{}, errors.New("STUN transaction ID mismatch")
	}
	if messageType == stunBindingError {
		return STUNResult{}, fmt.Errorf("STUN binding error: %s", stunErrorText(packet[20:20+messageLength]))
	}

	var mapped netip.AddrPort
	body := packet[stunHeaderSize : stunHeaderSize+messageLength]
	for offset := 0; offset < len(body); {
		if len(body)-offset < 4 {
			return STUNResult{}, errors.New("truncated STUN attribute header")
		}
		attrType := binary.BigEndian.Uint16(body[offset : offset+2])
		attrLength := int(binary.BigEndian.Uint16(body[offset+2 : offset+4]))
		valueStart := offset + 4
		valueEnd := valueStart + attrLength
		if valueEnd > len(body) {
			return STUNResult{}, errors.New("truncated STUN attribute")
		}
		value := body[valueStart:valueEnd]
		switch attrType {
		case stunAttrXORMappedAddress:
			addr, err := decodeSTUNAddress(value, true, txid)
			if err != nil {
				return STUNResult{}, fmt.Errorf("XOR-MAPPED-ADDRESS: %w", err)
			}
			mapped = addr
		case stunAttrMappedAddress:
			if !mapped.IsValid() {
				addr, err := decodeSTUNAddress(value, false, txid)
				if err != nil {
					return STUNResult{}, fmt.Errorf("MAPPED-ADDRESS: %w", err)
				}
				mapped = addr
			}
		}
		offset = valueStart + ((attrLength + 3) &^ 3)
	}
	if !mapped.IsValid() {
		return STUNResult{}, errors.New("STUN response has no mapped address")
	}
	result := STUNResult{MappedAddress: mapped.String(), SupportsUDP: true}
	if localAddr, ok := local.(*net.UDPAddr); ok && localAddr != nil {
		localIP, err := netip.ParseAddr(localAddr.IP.String())
		if err == nil && localIP.IsValid() && localAddr.Port == int(mapped.Port()) && localIP == mapped.Addr() {
			result.NAT = NATOpen
		} else {
			result.NAT = NATUnknown
		}
	} else {
		result.NAT = NATUnknown
	}
	return result, nil
}

func decodeSTUNAddress(value []byte, xor bool, txid [12]byte) (netip.AddrPort, error) {
	if len(value) != 8 && len(value) != 20 {
		return netip.AddrPort{}, errors.New("invalid address attribute length")
	}
	if value[0] != 0x00 {
		return netip.AddrPort{}, errors.New("invalid address zero byte")
	}
	family := value[1]
	port := binary.BigEndian.Uint16(value[2:4])
	if xor {
		port ^= uint16(stunMagicCookie >> 16)
	}
	if port == 0 {
		return netip.AddrPort{}, errors.New("mapped port must be nonzero")
	}
	switch family {
	case 0x01:
		if len(value) != 8 {
			return netip.AddrPort{}, errors.New("invalid IPv4 address length")
		}
		var ip [4]byte
		copy(ip[:], value[4:8])
		if xor {
			cookie := [4]byte{0x21, 0x12, 0xA4, 0x42}
			for i := range ip {
				ip[i] ^= cookie[i]
			}
		}
		return netip.AddrPortFrom(netip.AddrFrom4(ip), port), nil
	case 0x02:
		if len(value) != 20 {
			return netip.AddrPort{}, errors.New("invalid IPv6 address length")
		}
		var ip [16]byte
		copy(ip[:], value[4:20])
		if xor {
			var mask [16]byte
			binary.BigEndian.PutUint32(mask[0:4], stunMagicCookie)
			copy(mask[4:], txid[:])
			for i := range ip {
				ip[i] ^= mask[i]
			}
		}
		return netip.AddrPortFrom(netip.AddrFrom16(ip), port), nil
	default:
		return netip.AddrPort{}, fmt.Errorf("unsupported address family 0x%02x", family)
	}
}

func stunErrorText(body []byte) string {
	for offset := 0; offset+4 <= len(body); {
		attrType := binary.BigEndian.Uint16(body[offset : offset+2])
		attrLength := int(binary.BigEndian.Uint16(body[offset+2 : offset+4]))
		start := offset + 4
		end := start + attrLength
		if end > len(body) {
			break
		}
		if attrType == stunAttrErrorCode && attrLength >= 4 {
			class := body[start+2] & 0x07
			number := body[start+3]
			reason := strings.TrimSpace(string(body[start+4 : end]))
			return fmt.Sprintf("code %d%s", int(class)*100+int(number), formatSTUNReason(reason))
		}
		offset = start + ((attrLength + 3) &^ 3)
	}
	return "unknown error"
}

func formatSTUNReason(reason string) string {
	if reason == "" {
		return ""
	}
	return ": " + reason
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
