package mesh

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/private-radminlan/lanmesh/core"
	"github.com/private-radminlan/lanmesh/internal/clientapi"
	"github.com/private-radminlan/lanmesh/internal/network"
)

const relayRenewalMargin = 30 * time.Second
const maxRelayBackoff = 30 * time.Second

type relayRetryState struct {
	failures    uint32
	nextAttempt time.Time
}

func (e *Engine) syncPeers() error {
	items, err := e.options.API.ListDevices(core.NetworkID(e.options.Network.ID))
	if err != nil {
		return err
	}
	if len(items) > 128 {
		return errors.New("network exceeds the 128 device limit")
	}
	found := make(map[string]bool)
	selfFound := false
	addresses := make(map[netip.Addr]bool)
	generationChanged := false
	for _, peer := range items {
		if peer.ID == e.options.Identity.DeviceID.String() {
			selfFound = true
			continue
		}
		if core.ValidateWireGuardPublicKey(peer.PublicKey) != nil {
			continue
		}
		ip, err := netip.ParseAddr(peer.VirtualIP)
		if err != nil || !e.plain.prefix.Contains(ip) || ip == e.plain.local {
			continue
		}
		found[peer.ID] = true
		addresses[ip] = true
		var candidates []netip.AddrPort
		if record, err := e.options.API.GetCandidates(core.NetworkID(e.options.Network.ID), core.DeviceID(peer.ID)); err == nil && time.Since(record.UpdatedAt) < 2*time.Minute {
			for _, candidate := range record.Candidates {
				if candidate.Transport != core.TransportUDP || candidate.Kind == core.CandidateRelay {
					continue
				}
				ap, err := netip.ParseAddrPort(candidate.Address)
				if err == nil && ap.Addr().Is4() && ap.Port() > 0 && !ap.Addr().IsUnspecified() && !ap.Addr().IsMulticast() {
					candidates = append(candidates, ap)
				}
			}
		}
		if err = e.bind.updatePeer(ip, peer.PublicKey, candidates); err != nil {
			return err
		}
		e.mu.RLock()
		previous, exists := e.peers[peer.ID]
		e.mu.RUnlock()
		if !exists || previous.PublicKey != peer.PublicKey || previous.VirtualIP != peer.VirtualIP {
			generationChanged = true
			if exists {
				oldKey, _ := base64.StdEncoding.DecodeString(previous.PublicKey)
				_ = e.wg.IpcSet("public_key=" + hex.EncodeToString(oldKey) + "\nremove=true\n")
				oldIP, _ := netip.ParseAddr(previous.VirtualIP)
				if oldIP != ip {
					e.bind.removePeer(oldIP)
				}
			}
			key, _ := base64.StdEncoding.DecodeString(peer.PublicKey)
			config := fmt.Sprintf("public_key=%s\nreplace_allowed_ips=true\nallowed_ip=%s/32\nendpoint=%s:1\npersistent_keepalive_interval=15\n", hex.EncodeToString(key), peer.VirtualIP, peer.VirtualIP)
			if err = e.wg.IpcSet(config); err != nil {
				return err
			}
		}
		e.mu.Lock()
		e.peers[peer.ID] = peer
		e.mu.Unlock()
		e.ensureRelay(peer, ip)
	}
	if !selfFound {
		go e.Close()
		return errors.New("this device is no longer a member of the network")
	}
	e.mu.Lock()
	var removed []clientapi.Device
	var removedIDs []string
	for id, peer := range e.peers {
		if found[id] {
			continue
		}
		removed = append(removed, peer)
		removedIDs = append(removedIDs, id)
		delete(e.peers, id)
		generationChanged = true
	}
	e.mu.Unlock()
	for _, id := range removedIDs {
		e.clearRelayAttempt(id)
	}
	if generationChanged {
		e.advanceGeneration()
	}
	for _, peer := range removed {
		key, _ := base64.StdEncoding.DecodeString(peer.PublicKey)
		_ = e.wg.IpcSet("public_key=" + hex.EncodeToString(key) + "\nremove=true\n")
		ip, _ := netip.ParseAddr(peer.VirtualIP)
		e.bind.removePeer(ip)
	}
	e.plain.setPeers(addresses)
	return nil
}
func (e *Engine) ensureRelay(peer clientapi.Device, ip netip.Addr) {
	if e.bind.hasRelay(ip, relayRenewalMargin) {
		return
	}
	e.mu.Lock()
	if e.dialing == nil {
		e.dialing = make(map[string]bool)
	}
	if e.dialing[peer.ID] || e.closed || !e.relayAttemptAllowedLocked(peer.ID, time.Now()) {
		e.mu.Unlock()
		return
	}
	e.dialing[peer.ID] = true
	e.wgLoops.Add(1)
	e.mu.Unlock()
	go func() {
		defer e.wgLoops.Done()
		defer func() { e.mu.Lock(); delete(e.dialing, peer.ID); e.mu.Unlock() }()
		ticket, err := e.options.API.CreateRelaySession(core.NetworkID(e.options.Network.ID), e.options.Identity.DeviceID, core.DeviceID(peer.ID), 5*time.Minute)
		if err != nil {
			e.relayAttemptFailed(peer.ID, time.Now())
			e.setError(err)
			return
		}
		ctx, cancel := context.WithTimeout(e.ctx, 10*time.Second)
		defer cancel()
		relay, err := network.DialHTTPRelayWithRoots(ctx, e.options.API.BaseURL, e.options.API.Token, network.RelayTicket{SessionID: ticket.SessionID, Source: ticket.Source, Target: ticket.Target, Secret: ticket.Secret, ExpiresAt: ticket.ExpiresAt}, e.options.Identity.DeviceID, e.options.TrustedRoots)
		if err != nil {
			e.relayAttemptFailed(peer.ID, time.Now())
			e.setError(err)
			return
		}
		if !e.bind.attachRelay(ip, relay, ticket.ExpiresAt) {
			e.relayAttemptFailed(peer.ID, time.Now())
			return
		}
		e.relayAttemptSucceeded(peer.ID)
	}()
}

func relayBackoffDelay(failures uint32) time.Duration {
	delay := time.Second
	for i := uint32(1); i < failures; i++ {
		if delay >= maxRelayBackoff {
			return maxRelayBackoff
		}
		delay *= 2
	}
	if delay > maxRelayBackoff {
		return maxRelayBackoff
	}
	return delay
}

func (e *Engine) relayAttemptAllowed(peerID string, now time.Time) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.relayAttemptAllowedLocked(peerID, now)
}

func (e *Engine) relayAttemptAllowedLocked(peerID string, now time.Time) bool {
	state, ok := e.relayRetries[peerID]
	return !ok || !now.Before(state.nextAttempt)
}

func (e *Engine) relayAttemptFailed(peerID string, now time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.peers != nil {
		if _, ok := e.peers[peerID]; !ok {
			delete(e.relayRetries, peerID)
			return
		}
	}
	if e.relayRetries == nil {
		e.relayRetries = make(map[string]relayRetryState)
	}
	state := e.relayRetries[peerID]
	state.failures++
	state.nextAttempt = now.Add(relayBackoffDelay(state.failures))
	e.relayRetries[peerID] = state
}

func (e *Engine) relayAttemptSucceeded(peerID string) {
	e.clearRelayAttempt(peerID)
}

func (e *Engine) clearRelayAttempt(peerID string) {
	e.mu.Lock()
	delete(e.relayRetries, peerID)
	e.mu.Unlock()
}
