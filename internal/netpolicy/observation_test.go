package netpolicy

import "testing"

func TestObservationDebouncerRequiresStableSamples(t *testing.T) {
	debouncer := NewObservationDebouncer(2)
	if decision := debouncer.Observe(1, ObservationConflict); decision.Apply || decision.Stale {
		t.Fatalf("first conflict should be pending: %+v", decision)
	}
	if decision := debouncer.Observe(1, ObservationConflict); !decision.Apply {
		t.Fatalf("second identical conflict should apply: %+v", decision)
	}
	status := debouncer.Status()
	if status.StableState != ObservationConflict || status.Generation != 1 {
		t.Fatalf("unexpected observation status: %+v", status)
	}
}

func TestObservationDebouncerDropsStaleGeneration(t *testing.T) {
	debouncer := NewObservationDebouncer(1)
	if decision := debouncer.Observe(2, ObservationHealthy); !decision.Apply {
		t.Fatalf("current generation was not accepted: %+v", decision)
	}
	if decision := debouncer.Observe(1, ObservationConflict); !decision.Stale || decision.Apply {
		t.Fatalf("old generation was not dropped: %+v", decision)
	}
	status := debouncer.Status()
	if status.Generation != 2 || status.StableState != ObservationHealthy || status.StaleDropped != 1 {
		t.Fatalf("stale observation changed state: %+v", status)
	}
}

func TestObservationDebouncerResetsOnNewGeneration(t *testing.T) {
	debouncer := NewObservationDebouncer(2)
	_ = debouncer.Observe(3, ObservationConflict)
	if decision := debouncer.Observe(4, ObservationUnavailable); decision.Apply {
		t.Fatalf("new generation retained old pending sample: %+v", decision)
	}
	if decision := debouncer.Observe(4, ObservationUnavailable); !decision.Apply {
		t.Fatalf("new generation did not debounce independently: %+v", decision)
	}
}
func TestObservationDebouncerAdvanceRejectsInFlightOldGeneration(t *testing.T) {
	debouncer := NewObservationDebouncer(1)
	debouncer.Advance(7)
	if decision := debouncer.Observe(6, ObservationConflict); !decision.Stale || decision.Apply {
		t.Fatalf("in-flight old generation was accepted: %+v", decision)
	}
	if status := debouncer.Status(); status.Generation != 7 || status.StaleDropped != 1 {
		t.Fatalf("advanced generation was not preserved: %+v", status)
	}
}
