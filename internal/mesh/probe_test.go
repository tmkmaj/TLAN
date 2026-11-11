package mesh

import (
	"testing"
	"time"
)

// A successful round trip must always be reported as a positive duration so
// that a zero value stays reserved for "no measurement yet". Some platforms
// expose a monotonic clock too coarse to resolve fast loopback round trips.
func TestMeasuredRTTStaysPositive(t *testing.T) {
	tests := []struct {
		name string
		in   time.Duration
		want time.Duration
	}{
		{name: "zero sample", in: 0, want: time.Microsecond},
		{name: "negative sample", in: -5 * time.Millisecond, want: time.Microsecond},
		{name: "sub microsecond", in: 250 * time.Nanosecond, want: 250 * time.Nanosecond},
		{name: "positive sample", in: 12 * time.Millisecond, want: 12 * time.Millisecond},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := measuredRTT(test.in); got != test.want {
				t.Fatalf("measuredRTT(%v) = %v, want %v", test.in, got, test.want)
			}
			if test.in <= 0 && measuredRTT(test.in) <= 0 {
				t.Fatalf("measuredRTT(%v) did not become positive", test.in)
			}
		})
	}
}
