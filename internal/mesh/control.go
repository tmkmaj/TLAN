package mesh

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"time"

	"github.com/private-radminlan/lanmesh/core"
	"github.com/private-radminlan/lanmesh/internal/clientapi"
)

func (e *Engine) controlLoop() {
	defer e.wgLoops.Done()
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	lastGather := time.Now()
	for {
		select {
		case <-e.ctx.Done():
			return
		case <-ticker.C:
			if _, err := e.options.API.Heartbeat(e.options.Identity.DeviceID); err != nil {
				if e.handleControlError(err) {
					return
				}
				continue
			}
			if time.Since(lastGather) > time.Minute {
				e.gatherCandidates()
				lastGather = time.Now()
			}
			if _, err := e.options.API.SetCandidates(core.NetworkID(e.options.Network.ID), e.options.Identity.DeviceID, e.candidates); err != nil {
				if e.handleControlError(err) {
					return
				}
			}
			if err := e.syncPeers(); err != nil {
				if e.handleControlError(err) {
					return
				}
			}
		}
	}
}

// Only failures of our own membership operations are terminal. A missing
// candidate or relay for another peer must not stop the local engine.
func (e *Engine) handleControlError(err error) bool {
	e.setError(err)
	var response *clientapi.HTTPError
	if errors.As(err, &response) {
		switch response.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			// Close waits for this loop; cancellation delegates cleanup to the
			// lifecycle watcher instead of deadlocking inside the loop itself.
			e.cancel()
			return true
		}
	}
	return false
}

func (e *Engine) gatherCandidates() {
	e.bind.mu.RLock()
	port := e.bind.port
	e.bind.mu.RUnlock()
	var candidates []core.Candidate
	interfaces, _ := net.Interfaces()
adapters:
	for _, adapter := range interfaces {
		if adapter.Flags&net.FlagUp == 0 || adapter.Flags&net.FlagLoopback != 0 {
			continue
		}
		addresses, _ := adapter.Addrs()
		for _, value := range addresses {
			prefix, err := netip.ParsePrefix(value.String())
			if err != nil {
				continue
			}
			ip := prefix.Addr().Unmap()
			if !ip.Is4() || !ip.IsGlobalUnicast() || e.plain.prefix.Contains(ip) {
				continue
			}
			candidates = append(candidates, core.Candidate{Kind: core.CandidateHost, Transport: core.TransportUDP, Address: netip.AddrPortFrom(ip, port).String(), Priority: 100})
			if len(candidates) >= 32 {
				break adapters
			}
		}
	}
	if e.options.STUNServer != "" {
		ctx, cancel := context.WithTimeout(e.ctx, 3*time.Second)
		mapped, err := e.bind.probeSTUN(ctx, e.options.STUNServer)
		cancel()
		if err == nil {
			candidates = append(candidates, core.Candidate{Kind: core.CandidateServerReflexive, Transport: core.TransportUDP, Address: mapped.String(), Priority: 200})
		} else {
			e.setError(fmt.Errorf("STUN: %w", err))
		}
	}
	// No active physical interface is still a valid relay-only configuration.
	if len(candidates) == 0 {
		candidates = append(candidates, core.Candidate{Kind: core.CandidateHost, Transport: core.TransportUDP, Address: fmt.Sprintf("127.0.0.1:%d", port), Priority: 1})
	}
	e.candidates = candidates
}
