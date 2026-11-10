package mesh

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strings"
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
			now := time.Now()
			if e.refreshCandidatesIfNeeded(now, lastGather) {
				lastGather = now
			}
			if _, err := e.options.API.SetCandidates(core.NetworkID(e.options.Network.ID), e.options.Identity.DeviceID, e.candidatesForRequest()); err != nil {
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

type candidateInterfaceSnapshot struct {
	Name string
	Up   bool
	IPv4 []string
}

func (e *Engine) candidateSnapshot() []candidateInterfaceSnapshot {
	if e.options.candidateSnapshot != nil {
		return e.options.candidateSnapshot()
	}
	interfaces, _ := net.Interfaces()
	result := make([]candidateInterfaceSnapshot, 0, len(interfaces))
	for _, adapter := range interfaces {
		if adapter.Flags&net.FlagLoopback != 0 {
			continue
		}
		item := candidateInterfaceSnapshot{Name: adapter.Name, Up: adapter.Flags&net.FlagUp != 0}
		addresses, _ := adapter.Addrs()
		for _, value := range addresses {
			prefix, err := netip.ParsePrefix(value.String())
			if err != nil {
				continue
			}
			ip := prefix.Addr().Unmap()
			if ip.Is4() {
				item.IPv4 = append(item.IPv4, ip.String())
			}
		}
		sort.Strings(item.IPv4)
		result = append(result, item)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result
}

func candidateFingerprint(interfaces []candidateInterfaceSnapshot, stunAvailable bool) string {
	sorted := append([]candidateInterfaceSnapshot(nil), interfaces...)
	for i := range sorted {
		sorted[i].IPv4 = append([]string(nil), sorted[i].IPv4...)
		sort.Strings(sorted[i].IPv4)
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	var b strings.Builder
	fmt.Fprintf(&b, "stun=%t;", stunAvailable)
	for _, item := range sorted {
		fmt.Fprintf(&b, "iface=%q,up=%t,ipv4=%s;", item.Name, item.Up, strings.Join(item.IPv4, ","))
	}
	return b.String()
}

func (e *Engine) refreshCandidatesIfNeeded(now, lastGather time.Time) bool {
	snapshot := e.candidateSnapshot()
	e.candidateMu.Lock()
	fingerprint := candidateFingerprint(snapshot, e.stunAvailable)
	if (now.Sub(lastGather) <= time.Minute && fingerprint == e.candidateFingerprint) || e.candidateRefreshing {
		e.candidateMu.Unlock()
		return false
	}
	e.candidateRefreshing = true
	e.candidateMu.Unlock()
	go e.gatherCandidatesFromSnapshot(snapshot)
	return true
}

func (e *Engine) candidatesForRequest() []core.Candidate {
	e.candidateMu.Lock()
	defer e.candidateMu.Unlock()
	return append([]core.Candidate(nil), e.candidates...)
}

func (e *Engine) gatherCandidates() {
	e.gatherCandidatesFromSnapshot(e.candidateSnapshot())
}

func (e *Engine) gatherCandidatesFromSnapshot(interfaces []candidateInterfaceSnapshot) {
	e.bind.mu.RLock()
	port := e.bind.port
	e.bind.mu.RUnlock()
	var candidates []core.Candidate
adapters:
	for _, adapter := range interfaces {
		if !adapter.Up {
			continue
		}
		for _, value := range adapter.IPv4 {
			ip, err := netip.ParseAddr(value)
			if err != nil || !ip.Is4() || !ip.IsGlobalUnicast() || e.plain.prefix.Contains(ip) {
				continue
			}
			candidates = append(candidates, core.Candidate{Kind: core.CandidateHost, Transport: core.TransportUDP, Address: netip.AddrPortFrom(ip, port).String(), Priority: 100})
			if len(candidates) >= 32 {
				break adapters
			}
		}
	}
	stunAvailable := false
	if e.options.STUNServer != "" {
		ctx, cancel := context.WithTimeout(e.ctx, 3*time.Second)
		mapped, err := e.bind.probeSTUN(ctx, e.options.STUNServer)
		cancel()
		if err == nil {
			stunAvailable = true
			candidates = append(candidates, core.Candidate{Kind: core.CandidateServerReflexive, Transport: core.TransportUDP, Address: mapped.String(), Priority: 200})
		} else {
			e.setError(fmt.Errorf("STUN: %w", err))
		}
	}
	// No active physical interface is still a valid relay-only configuration.
	if len(candidates) == 0 {
		candidates = append(candidates, core.Candidate{Kind: core.CandidateHost, Transport: core.TransportUDP, Address: fmt.Sprintf("127.0.0.1:%d", port), Priority: 1})
	}
	e.candidateMu.Lock()
	e.candidates = candidates
	e.stunAvailable = stunAvailable
	e.candidateFingerprint = candidateFingerprint(interfaces, stunAvailable)
	e.candidateRefreshing = false
	e.candidateMu.Unlock()
}
