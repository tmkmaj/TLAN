package mesh

import (
	"sync"
	"time"
)

const (
	DefaultQualityCapacity = 300
	DefaultQualityMaxAge   = 5 * time.Minute
)

type QualitySample struct {
	At                 time.Time `json:"at"`
	Path               string    `json:"path,omitempty"`
	RTTMillis          int64     `json:"rtt_ms,omitempty"`
	Sent               uint64    `json:"sent_bytes"`
	Received           uint64    `json:"received_bytes"`
	Dropped            uint64    `json:"dropped_bytes"`
	ReachablePeers     int       `json:"reachable_peers"`
	TotalPeers         int       `json:"total_peers"`
	RelayQueueDepth    int       `json:"relay_queue_depth"`
	RelayQueueCapacity int       `json:"relay_queue_capacity"`
	RelayDrops         uint64    `json:"relay_drops"`
	RelayBackpressure  uint64    `json:"relay_backpressure"`
}

type QualitySummary struct {
	Samples          int    `json:"samples"`
	AverageRTTMillis int64  `json:"average_rtt_ms"`
	MaxRTTMillis     int64  `json:"max_rtt_ms"`
	DroppedDelta     uint64 `json:"dropped_delta"`
	DirectSamples    int    `json:"direct_samples"`
	RelaySamples     int    `json:"relay_samples"`
}

// QualityHistory is a fixed-capacity circular buffer. Record is O(1); the
// retained samples are kept in insertion order even if the wall clock moves.
type QualityHistory struct {
	mu       sync.RWMutex
	capacity int
	maxAge   time.Duration
	now      func() time.Time
	samples  []QualitySample
	start    int
	count    int
}

func NewQualityHistory(capacity int) *QualityHistory {
	return NewQualityHistoryWithClock(capacity, DefaultQualityMaxAge, time.Now)
}

func NewQualityHistoryWithClock(capacity int, maxAge time.Duration, now func() time.Time) *QualityHistory {
	if capacity <= 0 {
		capacity = DefaultQualityCapacity
	}
	if maxAge <= 0 {
		maxAge = DefaultQualityMaxAge
	}
	if now == nil {
		now = time.Now
	}
	return &QualityHistory{capacity: capacity, maxAge: maxAge, now: now, samples: make([]QualitySample, capacity)}
}

func (h *QualityHistory) Record(sample QualitySample) {
	if h == nil {
		return
	}
	now := h.now()
	if sample.At.IsZero() {
		sample.At = now
	}
	cutoff := now.Add(-h.maxAge)
	h.mu.Lock()
	h.expireLocked(cutoff)
	if h.count == h.capacity {
		h.samples[h.start] = sample
		h.start = (h.start + 1) % h.capacity
	} else {
		index := (h.start + h.count) % h.capacity
		h.samples[index] = sample
		h.count++
	}
	h.mu.Unlock()
}

func (h *QualityHistory) Snapshot() []QualitySample {
	if h == nil {
		return nil
	}
	now := h.now()
	cutoff := now.Add(-h.maxAge)
	h.mu.Lock()
	h.expireLocked(cutoff)
	result := make([]QualitySample, h.count)
	for i := 0; i < h.count; i++ {
		result[i] = h.samples[(h.start+i)%h.capacity]
	}
	h.mu.Unlock()

	return result
}

func (h *QualityHistory) Clear() {
	if h == nil {
		return
	}
	h.mu.Lock()
	h.start, h.count = 0, 0
	h.mu.Unlock()
}

func (h *QualityHistory) Summary() QualitySummary {
	samples := h.Snapshot()
	summary := QualitySummary{Samples: len(samples)}
	if len(samples) == 0 {
		return summary
	}
	var totalRTT, rttSamples int64
	for _, sample := range samples {
		if sample.RTTMillis > 0 {
			totalRTT += sample.RTTMillis
			rttSamples++
			if sample.RTTMillis > summary.MaxRTTMillis {
				summary.MaxRTTMillis = sample.RTTMillis
			}
		}
		switch sample.Path {
		case "direct UDP":
			summary.DirectSamples++
		case "relay TCP/TLS":
			summary.RelaySamples++
		}
	}
	if rttSamples > 0 {
		summary.AverageRTTMillis = totalRTT / rttSamples
	}
	if samples[len(samples)-1].Dropped >= samples[0].Dropped {
		summary.DroppedDelta = samples[len(samples)-1].Dropped - samples[0].Dropped
	}
	return summary
}

func (h *QualityHistory) expireLocked(cutoff time.Time) {
	if h.count == 0 {
		return
	}
	// Samples are normally appended in time order, but a clock correction must
	// not silently pin an old head at the front of the ring forever. Retain
	// any samples that are still in the window, preserving insertion order.
	kept := make([]QualitySample, 0, h.count)
	for i := 0; i < h.count; i++ {
		sample := h.samples[(h.start+i)%h.capacity]
		if !sample.At.Before(cutoff) {
			kept = append(kept, sample)
		}
	}
	h.start = 0
	h.count = len(kept)
	for i := range kept {
		h.samples[i] = kept[i]
	}
}

func qualitySampleFromStatus(at time.Time, status Status, relayDepth, relayCapacity int, relayDrops, relayBackpressure uint64) QualitySample {
	sample := QualitySample{
		At: at, Sent: status.Sent, Received: status.Received, Dropped: status.Dropped,
		TotalPeers: len(status.Peers), RelayQueueDepth: relayDepth, RelayQueueCapacity: relayCapacity,
		RelayDrops: relayDrops, RelayBackpressure: relayBackpressure,
	}
	direct, relay, rttSamples := 0, 0, 0
	var totalRTT time.Duration
	for _, peer := range status.Peers {
		if !peer.Reachable {
			continue
		}
		sample.ReachablePeers++
		switch peer.Path {
		case "direct UDP":
			direct++
		case "relay TCP/TLS":
			relay++
		}
		if peer.RTT > 0 {
			totalRTT += peer.RTT
			rttSamples++
		}
	}
	switch {
	case direct > 0 && relay == 0:
		sample.Path = "direct UDP"
	case relay > 0 && direct == 0:
		sample.Path = "relay TCP/TLS"
	case direct > 0 && relay > 0:
		sample.Path = "mixed"
	default:
		sample.Path = "checking"
	}
	if rttSamples > 0 {
		sample.RTTMillis = (totalRTT / time.Duration(rttSamples)).Milliseconds()
	}
	return sample
}

func (e *Engine) recordQualitySample() {
	if e == nil || e.quality == nil || e.bind == nil {
		return
	}
	drops, backpressure := e.bind.relayStats()
	status := e.Status()
	queueDepth, queueCapacity := 0, 0
	for _, peer := range status.Peers {
		queueDepth += peer.RelayQueueDepth
		queueCapacity += peer.RelayQueueCapacity
	}
	sample := qualitySampleFromStatus(time.Now().UTC(), status, queueDepth, queueCapacity, drops, backpressure)
	e.quality.Record(sample)
}

func (e *Engine) Quality() []QualitySample {
	if e == nil || e.quality == nil {
		return nil
	}
	return e.quality.Snapshot()
}

func (e *Engine) QualitySummary() QualitySummary {
	if e == nil || e.quality == nil {
		return QualitySummary{}
	}
	return e.quality.Summary()
}
