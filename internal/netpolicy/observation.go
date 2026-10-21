package netpolicy

import "sync"

// ObservationState is the stable result of one route-observation pass.
type ObservationState string

const (
	ObservationHealthy     ObservationState = "healthy"
	ObservationConflict    ObservationState = "conflict"
	ObservationUnavailable ObservationState = "unavailable"
)

// ObservationDecision reports whether a sample was accepted, ignored as
// stale, or promoted to a new stable state after debouncing.
type ObservationDecision struct {
	Accepted bool
	Stale    bool
	Apply    bool
	State    ObservationState
}

// ObservationStatus is a concurrency-safe diagnostic view of a debouncer.
type ObservationStatus struct {
	Generation     uint64
	StableState    ObservationState
	CandidateState ObservationState
	CandidateCount int
	StaleDropped   uint64
}

// ObservationDebouncer gives route observations a monotonic generation and
// requires repeated agreement before changing the stable state. A newer
// generation immediately invalidates pending samples from older generations;
// an older generation arriving late is dropped without affecting state.
//
// It deliberately has no timer. Callers decide the observation cadence, which
// keeps polling boundaries explicit and makes the policy deterministic in
// tests.
type ObservationDebouncer struct {
	mu       sync.Mutex
	required int
	status   ObservationStatus
}

func NewObservationDebouncer(requiredStable int) *ObservationDebouncer {
	if requiredStable < 1 {
		requiredStable = 1
	}
	return &ObservationDebouncer{required: requiredStable}
}

// Advance publishes a new current generation immediately, even before the
// first sample for that generation arrives. Any in-flight sample from an older
// generation is then rejected by Observe.
func (d *ObservationDebouncer) Advance(generation uint64) {
	if d == nil || generation == 0 {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if generation <= d.status.Generation {
		return
	}
	d.status.Generation = generation
	d.status.StableState = ""
	d.status.CandidateState = ""
	d.status.CandidateCount = 0
}

// Observe records one sample. Generation zero is treated as an unversioned
// sample and is never accepted, so an accidental caller cannot bypass stale
// event protection.
func (d *ObservationDebouncer) Observe(generation uint64, state ObservationState) ObservationDecision {
	if d == nil || generation == 0 {
		return ObservationDecision{State: state}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if generation < d.status.Generation {
		d.status.StaleDropped++
		return ObservationDecision{Stale: true, State: state}
	}
	if generation > d.status.Generation {
		d.status.Generation = generation
		d.status.StableState = ""
		d.status.CandidateState = ""
		d.status.CandidateCount = 0
	}
	if state == d.status.StableState {
		d.status.CandidateState = ""
		d.status.CandidateCount = 0
		return ObservationDecision{Accepted: true, State: state}
	}
	if state != d.status.CandidateState {
		d.status.CandidateState = state
		d.status.CandidateCount = 1
	} else {
		d.status.CandidateCount++
	}
	if d.status.CandidateCount < d.required {
		return ObservationDecision{Accepted: true, State: state}
	}
	d.status.StableState = state
	d.status.CandidateState = ""
	d.status.CandidateCount = 0
	return ObservationDecision{Accepted: true, Apply: true, State: state}
}

func (d *ObservationDebouncer) Status() ObservationStatus {
	if d == nil {
		return ObservationStatus{}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.status
}
