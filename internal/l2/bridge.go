package l2

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"sync"
)

var (
	ErrUnknownSource      = errors.New("source device is not registered")
	ErrIPMACMismatch      = errors.New("source IP and MAC are not bound to the same device")
	ErrUnknownDestination = errors.New("destination device is not registered")
	ErrBroadcastBlocked   = errors.New("broadcast is blocked by policy")
	ErrMalformedIPv4      = errors.New("malformed IPv4 payload")
)

type Endpoint struct {
	DeviceID string
	MAC      MAC
	IP       netip.Addr
}

type Delivery struct {
	DeviceID string
	Frame    Frame
}

// Bridge validates virtual endpoint ownership before routing a frame. It
// keeps a single network's membership boundary and never forwards between
// separate Bridge instances.
type Bridge struct {
	mu       sync.RWMutex
	maxFrame int
	policy   BroadcastPolicy
	byDevice map[string]Endpoint
	byMAC    map[MAC]string
	byIP     map[netip.Addr]string
}

func NewBridge(maxFrame int, policy BroadcastPolicy) (*Bridge, error) {
	if maxFrame <= 0 {
		maxFrame = DefaultMaxFrame
	}
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	return &Bridge{maxFrame: maxFrame, policy: policy, byDevice: make(map[string]Endpoint), byMAC: make(map[MAC]string), byIP: make(map[netip.Addr]string)}, nil
}

func (b *Bridge) Register(endpoint Endpoint) error {
	if b == nil || endpoint.DeviceID == "" || !endpoint.MAC.IsUnicast() || !endpoint.IP.Is4() {
		return errors.New("endpoint requires device ID, unicast MAC, and IPv4")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if existing, ok := b.byDevice[endpoint.DeviceID]; ok && existing != endpoint {
		return errors.New("device already registered with different endpoint")
	}
	if owner, ok := b.byMAC[endpoint.MAC]; ok && owner != endpoint.DeviceID {
		return errors.New("MAC address is already assigned")
	}
	if owner, ok := b.byIP[endpoint.IP]; ok && owner != endpoint.DeviceID {
		return errors.New("IP address is already assigned")
	}
	b.byDevice[endpoint.DeviceID], b.byMAC[endpoint.MAC], b.byIP[endpoint.IP] = endpoint, endpoint.DeviceID, endpoint.DeviceID
	return nil
}

func (b *Bridge) Unregister(deviceID string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	endpoint, ok := b.byDevice[deviceID]
	if !ok {
		return false
	}
	delete(b.byDevice, deviceID)
	delete(b.byMAC, endpoint.MAC)
	delete(b.byIP, endpoint.IP)
	return true
}

func (b *Bridge) Route(sourceDevice string, raw []byte) ([]Delivery, error) {
	b.mu.RLock()
	source, ok := b.byDevice[sourceDevice]
	b.mu.RUnlock()
	if !ok {
		return nil, ErrUnknownSource
	}
	frame, err := ParseFrame(raw, b.maxFrame)
	if err != nil {
		return nil, err
	}
	if frame.Source != source.MAC {
		return nil, ErrIPMACMismatch
	}
	if err := validateSourcePayload(source, frame); err != nil {
		return nil, err
	}
	return b.route(sourceDevice, frame)
}

func validateSourcePayload(source Endpoint, frame Frame) error {
	switch frame.EtherType {
	case EtherTypeARP:
		arp, err := ParseARP(frame.Payload)
		if err != nil {
			return err
		}
		if arp.SenderMAC != source.MAC || arp.SenderIP != source.IP {
			return ErrIPMACMismatch
		}
	case EtherTypeIPv4:
		if len(frame.Payload) < 20 || frame.Payload[0]>>4 != 4 {
			return ErrMalformedIPv4
		}
		headerLength := int(frame.Payload[0]&0x0f) * 4
		totalLength := int(binary.BigEndian.Uint16(frame.Payload[2:4]))
		if headerLength < 20 || headerLength > len(frame.Payload) || totalLength < headerLength || totalLength > len(frame.Payload) {
			return ErrMalformedIPv4
		}
		ip := netip.AddrFrom4([4]byte{frame.Payload[12], frame.Payload[13], frame.Payload[14], frame.Payload[15]})
		if ip != source.IP {
			return ErrIPMACMismatch
		}
	}
	return nil
}

func (b *Bridge) route(sourceDevice string, frame Frame) ([]Delivery, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if frame.Destination.IsBroadcast() || frame.Destination.IsMulticast() {
		if b.policy.Mode == BroadcastDisabled {
			return nil, ErrBroadcastBlocked
		}
		ids := make([]string, 0, len(b.byDevice))
		for id, endpoint := range b.byDevice {
			if id == sourceDevice {
				continue
			}
			if b.policy.Mode == BroadcastSelectedMembers {
				if _, allowed := b.policy.AllowedDestinations[endpoint.MAC]; !allowed {
					continue
				}
			}
			ids = append(ids, id)
		}
		sort.Strings(ids)
		if b.policy.MaxFanout > 0 && len(ids) > b.policy.MaxFanout {
			ids = ids[:b.policy.MaxFanout]
		}
		return deliveries(ids, frame), nil
	}
	destination, ok := b.byMAC[frame.Destination]
	if !ok {
		return nil, ErrUnknownDestination
	}
	if destination == sourceDevice {
		return nil, nil
	}
	return []Delivery{{DeviceID: destination, Frame: frame}}, nil
}

func deliveries(ids []string, frame Frame) []Delivery {
	result := make([]Delivery, 0, len(ids))
	for _, id := range ids {
		result = append(result, Delivery{DeviceID: id, Frame: frame})
	}
	return result
}

func (b *Bridge) String() string { return fmt.Sprintf("bridge endpoints=%d", len(b.byDevice)) }
