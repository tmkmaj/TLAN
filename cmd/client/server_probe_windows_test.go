//go:build windows

package main

import (
	"testing"
	"time"

	"github.com/lxn/win"
)

func TestServerProbeHistoryStatsAndRollingLoss(t *testing.T) {
	h := newServerProbeHistory(5)
	if _, empty := h.Snapshot(); empty.Count != 0 || empty.LatestRTTMillis != -1 {
		t.Fatalf("empty snapshot = %+v", empty)
	}

	now := time.Now()
	h.Record(serverProbeSample{At: now, RTTMillis: 20, Mode: "STUN UDP"})
	h.Record(serverProbeSample{At: now.Add(time.Second), Lost: true, Mode: "STUN UDP"})
	h.Record(serverProbeSample{At: now.Add(2 * time.Second), RTTMillis: 40, Mode: "STUN UDP"})
	h.Record(serverProbeSample{At: now.Add(3 * time.Second), RTTMillis: 60, Mode: "STUN UDP"})
	h.Record(serverProbeSample{At: now.Add(4 * time.Second), Lost: true, Mode: "STUN UDP"})
	h.Record(serverProbeSample{At: now.Add(5 * time.Second), RTTMillis: 30, Mode: "STUN UDP"})

	samples, stats := h.Snapshot()
	if len(samples) != 5 || stats.Count != 5 {
		t.Fatalf("capacity ring len = %d, stats.Count = %d, want 5", len(samples), stats.Count)
	}
	if stats.LatestRTTMillis != 30 {
		t.Fatalf("LatestRTTMillis = %.1f, want 30", stats.LatestRTTMillis)
	}
	if stats.LostCount != 2 || stats.LossPercent != 40 {
		t.Fatalf("LostCount=%d LossPercent=%.1f, want 2 / 40", stats.LostCount, stats.LossPercent)
	}
	if stats.MaxRTTMillis != 60 {
		t.Fatalf("MaxRTTMillis = %.1f, want 60", stats.MaxRTTMillis)
	}
	if got := computeChartCeilingMS(samples); got != 100 {
		t.Fatalf("computeChartCeilingMS = %.0f, want 100", got)
	}
	h.Reset()
	if samplesAfter, statsAfter := h.Snapshot(); len(samplesAfter) != 0 || statsAfter.LatestRTTMillis != -1 {
		t.Fatalf("after Reset = len %d stats %+v", len(samplesAfter), statsAfter)
	}
}

func TestSmoothMonotoneSplineClampsBoundsAndFormatsSpan(t *testing.T) {
	pts := []win.POINT{
		{X: 50, Y: 70},
		{X: 110, Y: 68},
		{X: 170, Y: 20},
		{X: 230, Y: 70},
		{X: 290, Y: 69},
	}
	smooth := smoothMonotoneSpline(pts, 15, 72)
	if len(smooth) <= len(pts) {
		t.Fatalf("expected interpolated curve points > %d, got %d", len(pts), len(smooth))
	}
	for _, p := range smooth {
		if p.Y < 15 || p.Y > 72 {
			t.Fatalf("spline overshot bounds [15, 72]: %+v", p)
		}
	}
	if got := formatProbeSpanText(12); got != "12秒" {
		t.Fatalf("formatProbeSpanText(12) = %q", got)
	}
	if got := formatProbeSpanText(118); got != "1分58秒" {
		t.Fatalf("formatProbeSpanText(118) = %q", got)
	}
	if got := formatProbeModeLabel("STUN UDP"); got != "STUN · UDP" {
		t.Fatalf("formatProbeModeLabel = %q", got)
	}
}
