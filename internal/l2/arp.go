package l2

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"sync"
)

const arpPacketSize = 28

var (
	ErrInvalidARP  = errors.New("invalid Ethernet/IPv4 ARP packet")
	ErrARPTooShort = errors.New("ARP packet is too short")
)

type ARPOpcode uint16

const (
	ARPRequest ARPOpcode = 1
	ARPReply   ARPOpcode = 2
)

// ARP is the Ethernet/IPv4 portion of an ARP packet. Other hardware and
// protocol types are intentionally rejected at this layer.
type ARP struct {
	Operation ARPOpcode
	SenderMAC MAC
	SenderIP  netip.Addr
	TargetMAC MAC
	TargetIP  netip.Addr
}

func ParseARP(payload []byte) (ARP, error) {
	if len(payload) < arpPacketSize {
		return ARP{}, ErrARPTooShort
	}
	if binary.BigEndian.Uint16(payload[0:2]) != 1 || binary.BigEndian.Uint16(payload[2:4]) != EtherTypeIPv4 || payload[4] != 6 || payload[5] != 4 {
		return ARP{}, ErrInvalidARP
	}
	operation := ARPOpcode(binary.BigEndian.Uint16(payload[6:8]))
	if operation != ARPRequest && operation != ARPReply {
		return ARP{}, ErrInvalidARP
	}
	var result ARP
	result.Operation = operation
	copy(result.SenderMAC[:], payload[8:14])
	result.SenderIP = netip.AddrFrom4([4]byte{payload[14], payload[15], payload[16], payload[17]})
	copy(result.TargetMAC[:], payload[18:24])
	result.TargetIP = netip.AddrFrom4([4]byte{payload[24], payload[25], payload[26], payload[27]})
	if !result.SenderMAC.IsUnicast() || result.TargetMAC.IsZero() && operation == ARPReply {
		return ARP{}, ErrInvalidARP
	}
	return result, nil
}

func (a ARP) MarshalBinary() ([]byte, error) {
	if a.Operation != ARPRequest && a.Operation != ARPReply || !a.SenderMAC.IsUnicast() || !a.SenderIP.Is4() || !a.TargetIP.Is4() {
		return nil, ErrInvalidARP
	}
	if a.Operation == ARPReply && a.TargetMAC.IsZero() {
		return nil, ErrInvalidARP
	}
	raw := make([]byte, arpPacketSize)
	binary.BigEndian.PutUint16(raw[0:2], 1)
	binary.BigEndian.PutUint16(raw[2:4], EtherTypeIPv4)
	raw[4], raw[5] = 6, 4
	binary.BigEndian.PutUint16(raw[6:8], uint16(a.Operation))
	copy(raw[8:14], a.SenderMAC[:])
	senderIP := a.SenderIP.As4()
	targetIP := a.TargetIP.As4()
	copy(raw[14:18], senderIP[:])
	copy(raw[18:24], a.TargetMAC[:])
	copy(raw[24:28], targetIP[:])
	return raw, nil
}

func NewARPRequest(senderMAC MAC, senderIP, targetIP netip.Addr) (ARP, error) {
	result := ARP{Operation: ARPRequest, SenderMAC: senderMAC, SenderIP: senderIP, TargetIP: targetIP}
	_, err := result.MarshalBinary()
	return result, err
}

func NewARPReply(senderMAC MAC, senderIP netip.Addr, targetMAC MAC, targetIP netip.Addr) (ARP, error) {
	result := ARP{Operation: ARPReply, SenderMAC: senderMAC, SenderIP: senderIP, TargetMAC: targetMAC, TargetIP: targetIP}
	_, err := result.MarshalBinary()
	return result, err
}

// ARPTable is a bounded, thread-safe cache populated only after bridge
// validation. It is not an authorization source by itself.
type ARPTable struct {
	mu    sync.RWMutex
	limit int
	items map[netip.Addr]MAC
}

func NewARPTable(limit int) *ARPTable {
	if limit <= 0 {
		limit = 1024
	}
	return &ARPTable{limit: limit, items: make(map[netip.Addr]MAC)}
}

func (t *ARPTable) Learn(ip netip.Addr, mac MAC) bool {
	if t == nil || !ip.Is4() || !mac.IsUnicast() {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, exists := t.items[ip]; !exists && len(t.items) >= t.limit {
		return false
	}
	t.items[ip] = mac
	return true
}

func (t *ARPTable) Lookup(ip netip.Addr) (MAC, bool) {
	if t == nil {
		return MAC{}, false
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	mac, ok := t.items[ip]
	return mac, ok
}

func (t *ARPTable) Remove(ip netip.Addr) {
	if t != nil {
		t.mu.Lock()
		delete(t.items, ip)
		t.mu.Unlock()
	}
}
