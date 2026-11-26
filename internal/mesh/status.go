package mesh

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/private-radminlan/lanmesh/internal/clientapi"
)

func (e *Engine) Status() Status {
	handshakes := make(map[string]time.Time)
	if state, err := e.wg.IpcGet(); err == nil {
		key := ""
		for _, line := range strings.Split(state, "\n") {
			pair := strings.SplitN(line, "=", 2)
			if len(pair) != 2 {
				continue
			}
			if pair[0] == "public_key" {
				key = pair[1]
			}
			if pair[0] == "last_handshake_time_sec" {
				if seconds, _ := strconv.ParseInt(pair[1], 10, 64); seconds > 0 {
					handshakes[key] = time.Unix(seconds, 0)
				}
			}
		}
	}
	e.mu.RLock()
	result := Status{Running: !e.closed, Address: e.options.Member.VirtualIP, LastError: e.lastError}
	var peers []clientapi.Device
	for _, p := range e.peers {
		peers = append(peers, p)
	}
	e.mu.RUnlock()
	e.bind.mu.RLock()
	for _, p := range peers {
		ip, _ := netip.ParseAddr(p.VirtualIP)
		path := "checking"
		rtt := time.Duration(0)
		if r := e.bind.routes[ip]; r != nil {
			// Report the path the sender actually chooses. Using a separate
			// "recently answered" rule here is what made the UI disagree with
			// itself and flip between direct and relay.
			if r.directPreferred(time.Now(), r.relay != nil) && !e.bind.relayOnly {
				path = "direct UDP"
				rtt = r.rtt
			} else if r.relay != nil {
				path = "relay TCP/TLS"
			}
		}
		key, _ := base64.StdEncoding.DecodeString(p.PublicKey)
		probeRTT, reachable := e.plain.peerLatency(ip)
		if reachable {
			rtt = probeRTT
		}
		var relayQueueDepth, relayQueueCapacity int
		if r := e.bind.routes[ip]; r != nil && r.relay != nil {
			relayStats := r.relay.Stats()
			relayQueueDepth, relayQueueCapacity = relayStats.QueueDepth, relayStats.QueueCapacity
		}
		result.Peers = append(result.Peers, PeerStatus{ID: p.ID, Name: p.Name, IP: p.VirtualIP, Path: path, RTT: rtt, Reachable: reachable, Handshake: handshakes[hex.EncodeToString(key)], RelayQueueDepth: relayQueueDepth, RelayQueueCapacity: relayQueueCapacity})
	}
	e.bind.mu.RUnlock()
	sort.Slice(result.Peers, func(i, j int) bool { return strings.Compare(result.Peers[i].IP, result.Peers[j].IP) < 0 })
	result.Sent = e.plain.Sent.Load()
	result.Received = e.plain.Received.Load()
	result.Dropped = e.plain.Dropped.Load()
	return result
}

func (e *Engine) Diagnostics() []clientapi.DiagnosticCheck {
	checks := diagnosticsForStatus(e.Status())
	recovery := e.RecoveryStatus()
	if recovery.HasIssues() {
		detail := fmt.Sprintf("recovered=%d failed=%d unproven=%d", recovery.Recovered, recovery.Failed, recovery.Unproven)
		if len(recovery.Issues) > 0 {
			detail += ": " + recovery.Issues[0].Error
		}
		checks = append(checks, clientapi.DiagnosticCheck{Name: "resource_recovery", Status: "warn", Detail: diagnosticDetail(detail), Checked: time.Now().UTC()})
	}
	if samples := e.Quality(); len(samples) > 0 {
		summary := e.QualitySummary()
		level := "pass"
		if summary.RelaySamples > summary.DirectSamples || summary.MaxRTTMillis > 250 || summary.DroppedDelta > 0 {
			level = "warn"
		}
		detail := fmt.Sprintf("samples=%d avg_rtt_ms=%d max_rtt_ms=%d dropped_delta=%d direct=%d relay=%d",
			summary.Samples, summary.AverageRTTMillis, summary.MaxRTTMillis, summary.DroppedDelta, summary.DirectSamples, summary.RelaySamples)
		checks = append(checks, clientapi.DiagnosticCheck{Name: "network_quality", Status: level, Detail: detail, Checked: time.Now().UTC()})
	}
	return checks
}

func diagnosticsForStatus(status Status) []clientapi.DiagnosticCheck {
	checks := []clientapi.DiagnosticCheck{{Name: "virtual_adapter", Status: "pass", Detail: status.Address, Checked: time.Now().UTC()}}
	for _, peer := range status.Peers {
		level := "pass"
		if peer.Path == "checking" || peer.Handshake.IsZero() || time.Since(peer.Handshake) > 3*time.Minute {
			level = "warn"
		}
		name, detail := "peer "+peer.Name, peer.IP+" "+peer.Path
		if len(name) > 128 {
			// A valid 128-byte device name exceeds the check-name limit once
			// prefixed. Preserve the full display name in the detail instead.
			name, detail = "peer "+peer.ID, peer.Name+" "+detail
		}
		checks = append(checks, clientapi.DiagnosticCheck{Name: name, Status: level, Detail: detail, Checked: time.Now().UTC()})
	}
	if status.LastError != "" {
		checks = append(checks, clientapi.DiagnosticCheck{Name: "last_error", Status: "warn", Detail: diagnosticDetail(status.LastError), Checked: time.Now().UTC()})
	}
	return checks
}

func diagnosticDetail(value string) string {
	const limit = 2048
	if len(value) <= limit {
		return value
	}
	end := limit
	for end > 0 && !utf8.RuneStart(value[end]) {
		end--
	}
	return value[:end]
}
