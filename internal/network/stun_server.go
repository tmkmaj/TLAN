package network

import (
	"context"
	"encoding/binary"
	"net"
	"time"
)

// ServeSTUN handles only IPv4 Binding. It never forwards arbitrary UDP.
func ServeSTUN(ctx context.Context, socket *net.UDPConn) error {
	go func() { <-ctx.Done(); socket.Close() }()
	buffer := make([]byte, 2048)
	window := time.Now()
	counts := make(map[string]int)
	total := 0
	for {
		n, source, err := socket.ReadFromUDP(buffer)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		if n != 20 || binary.BigEndian.Uint16(buffer[:2]) != stunBindingRequest || binary.BigEndian.Uint16(buffer[2:4]) != 0 || binary.BigEndian.Uint32(buffer[4:8]) != stunMagicCookie {
			continue
		}
		if time.Since(window) >= time.Second {
			window = time.Now()
			clear(counts)
			total = 0
		}
		key := source.IP.String()
		if total >= 200 || counts[key] >= 10 {
			continue
		}
		total++
		counts[key]++
		ip := source.IP.To4()
		if ip == nil {
			continue
		}
		response := make([]byte, 32)
		copy(response, buffer[:20])
		binary.BigEndian.PutUint16(response, stunBindingSuccess)
		binary.BigEndian.PutUint16(response[2:], 12)
		binary.BigEndian.PutUint16(response[20:], stunAttrXORMappedAddress)
		binary.BigEndian.PutUint16(response[22:], 8)
		response[25] = 1
		binary.BigEndian.PutUint16(response[26:], uint16(source.Port)^uint16(stunMagicCookie>>16))
		for i, b := range ip {
			response[28+i] = b ^ byte(stunMagicCookie>>uint(24-i*8))
		}
		_, _ = socket.WriteToUDP(response, source)
	}
}
