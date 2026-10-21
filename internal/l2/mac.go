package l2

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// MAC is the canonical six-byte Ethernet address used by the overlay.
type MAC [6]byte

var ZeroMAC MAC

func ParseMAC(value string) (MAC, error) {
	var mac MAC
	clean := strings.ReplaceAll(strings.TrimSpace(value), "-", ":")
	decoded, err := hex.DecodeString(strings.ReplaceAll(clean, ":", ""))
	if err != nil || len(decoded) != len(mac) || strings.Count(clean, ":") != 5 {
		return mac, errors.New("MAC address must be six hexadecimal octets")
	}
	copy(mac[:], decoded)
	if mac.IsZero() {
		return mac, errors.New("zero MAC address is not allowed")
	}
	return mac, nil
}

func (m MAC) String() string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5])
}

func (m MAC) IsZero() bool { return m == ZeroMAC }

func (m MAC) IsBroadcast() bool {
	for _, b := range m {
		if b != 0xff {
			return false
		}
	}
	return true
}

func (m MAC) IsMulticast() bool { return m[0]&1 == 1 }

func (m MAC) IsUnicast() bool { return !m.IsZero() && !m.IsMulticast() }
