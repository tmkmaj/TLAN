// Package mesh connects the virtual IPv4 interface to authenticated WireGuard
// peers. The inner packet is encapsulated so LAN broadcast destinations survive
// WireGuard's unicast AllowedIPs routing without rewriting application traffic.
package mesh

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

const MTU = 1280
const envelopeSize = 24

func ipv4(packet []byte) (netip.Addr, netip.Addr, error) {
	if len(packet) < 20 || packet[0]>>4 != 4 {
		return netip.Addr{}, netip.Addr{}, errors.New("invalid IPv4 packet")
	}
	header := int(packet[0]&15) * 4
	length := int(binary.BigEndian.Uint16(packet[2:4]))
	if header < 20 || header > len(packet) || length != len(packet) {
		return netip.Addr{}, netip.Addr{}, errors.New("invalid IPv4 length")
	}
	return netip.AddrFrom4([4]byte(packet[12:16])), netip.AddrFrom4([4]byte(packet[16:20])), nil
}

func broadcast(ip netip.Addr, prefix netip.Prefix) bool {
	if ip.IsMulticast() || ip == netip.MustParseAddr("255.255.255.255") {
		return true
	}
	base := prefix.Masked().Addr().As4()
	bits := binary.BigEndian.Uint32(base[:]) | ^uint32(0)>>prefix.Bits()
	var address [4]byte
	binary.BigEndian.PutUint32(address[:], bits)
	return ip == netip.AddrFrom4(address)
}

func encapsulate(packet []byte, source, target netip.Addr) []byte {
	result := make([]byte, envelopeSize+len(packet))
	result[0], result[8], result[9] = 0x45, 64, 253
	binary.BigEndian.PutUint16(result[2:4], uint16(len(result)))
	copy(result[12:16], source.AsSlice())
	copy(result[16:20], target.AsSlice())
	copy(result[20:24], "LM01")
	copy(result[24:], packet)
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(result[i : i+2]))
	}
	for sum > 65535 {
		sum = (sum & 65535) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(result[10:12], ^uint16(sum))
	return result
}

func decapsulate(packet []byte, local netip.Addr, prefix netip.Prefix, peers map[netip.Addr]bool) ([]byte, error) {
	return decapsulateWithLimit(packet, local, prefix, peers, MTU)
}

func decapsulateWithLimit(packet []byte, local netip.Addr, prefix netip.Prefix, peers map[netip.Addr]bool, maxPacket int) ([]byte, error) {
	if maxPacket <= 0 {
		maxPacket = MTU
	}
	source, dest, err := ipv4(packet)
	if err != nil || len(packet) < envelopeSize+20 || packet[0] != 0x45 || packet[9] != 253 ||
		string(packet[20:24]) != "LM01" || dest != local || !peers[source] {
		return nil, errors.New("invalid mesh envelope or nonmember source")
	}
	inner := packet[envelopeSize:]
	innerSource, innerDest, err := ipv4(inner)
	if err != nil || len(inner) > maxPacket || innerSource != source || (innerDest != local && !broadcast(innerDest, prefix)) {
		return nil, errors.New("invalid inner packet ownership or destination")
	}
	return inner, nil
}

func normalizeMeshMTU(value int) int {
	const minMeshMTU = 576
	const maxMeshMTU = 1500
	if value < minMeshMTU || value > maxMeshMTU {
		return MTU
	}
	return value
}
