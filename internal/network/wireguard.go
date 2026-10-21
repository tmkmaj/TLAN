package network

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"sync"

	"github.com/private-radminlan/lanmesh/core"
)

// WireGuardPeer is a transport-independent peer description. An adapter can
// translate Snapshot into wireguard-go or the native Windows/Linux API.
type WireGuardPeer struct {
	DeviceID            core.DeviceID
	PublicKey           string
	AllowedIPs          []netip.Prefix
	Endpoint            string
	PersistentKeepalive uint16
}

func (p WireGuardPeer) Validate() error {
	if err := p.DeviceID.Validate(); err != nil {
		return err
	}
	if err := core.ValidateWireGuardPublicKey(p.PublicKey); err != nil {
		return fmt.Errorf("peer public key: %w", err)
	}
	if len(p.AllowedIPs) == 0 {
		return errors.New("peer must have at least one allowed IP")
	}
	for _, prefix := range p.AllowedIPs {
		if !prefix.IsValid() {
			return errors.New("peer contains invalid allowed IP")
		}
	}
	return nil
}

type WireGuardConfig struct {
	PrivateKey string
	ListenPort uint16
	Address    netip.Prefix
	Peers      []WireGuardPeer
}

func (c WireGuardConfig) Validate() error {
	if err := core.ValidateWireGuardPublicKey(c.PrivateKey); err != nil {
		return fmt.Errorf("private key: %w", err)
	}
	if !c.Address.IsValid() {
		return errors.New("interface address is required")
	}
	seen := make(map[core.DeviceID]struct{}, len(c.Peers))
	for _, peer := range c.Peers {
		if err := peer.Validate(); err != nil {
			return err
		}
		if _, ok := seen[peer.DeviceID]; ok {
			return fmt.Errorf("duplicate peer %s", peer.DeviceID)
		}
		seen[peer.DeviceID] = struct{}{}
	}
	return nil
}

// ConfigBuilder maintains an immutable-looking peer snapshot while allowing
// concurrent signal updates. It never invokes an OS or WireGuard API.
type ConfigBuilder struct {
	mu    sync.RWMutex
	local WireGuardConfig
	peers map[core.DeviceID]WireGuardPeer
}

func NewConfigBuilder(privateKey string, address netip.Prefix, listenPort uint16) (*ConfigBuilder, error) {
	if err := core.ValidateWireGuardPublicKey(privateKey); err != nil {
		return nil, fmt.Errorf("private key: %w", err)
	}
	if !address.IsValid() {
		return nil, errors.New("interface address is required")
	}
	return &ConfigBuilder{
		local: WireGuardConfig{PrivateKey: privateKey, Address: address, ListenPort: listenPort},
		peers: make(map[core.DeviceID]WireGuardPeer),
	}, nil
}

func (b *ConfigBuilder) UpsertPeer(peer WireGuardPeer) error {
	if err := peer.Validate(); err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.peers[peer.DeviceID] = clonePeer(peer)
	return nil
}

func (b *ConfigBuilder) RemovePeer(id core.DeviceID) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.peers, id)
}

func (b *ConfigBuilder) Snapshot() WireGuardConfig {
	b.mu.RLock()
	defer b.mu.RUnlock()
	result := b.local
	result.Peers = make([]WireGuardPeer, 0, len(b.peers))
	for _, peer := range b.peers {
		result.Peers = append(result.Peers, clonePeer(peer))
	}
	sort.Slice(result.Peers, func(i, j int) bool { return result.Peers[i].DeviceID < result.Peers[j].DeviceID })
	return result
}

func clonePeer(peer WireGuardPeer) WireGuardPeer {
	peer.AllowedIPs = append([]netip.Prefix(nil), peer.AllowedIPs...)
	return peer
}
