//go:build windows

package main

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
	"github.com/lxn/win"
	"github.com/private-radminlan/lanmesh/internal/clientapi"
	"github.com/private-radminlan/lanmesh/internal/network"
	"golang.org/x/sys/windows"
)

const (
	serverProbeCapacity   = 60
	serverProbeLossWindow = 20
	serverProbeInterval   = 2 * time.Second
)

type serverProbeSample struct {
	At        time.Time
	RTTMillis float64
	Lost      bool
	Mode      string
}

type serverProbeStats struct {
	LatestRTTMillis float64
	AvgRTTMillis    float64
	MaxRTTMillis    float64
	LossPercent     float64
	Mode            string
	Count           int
	LostCount       int
}

type serverProbeHistory struct {
	mu      sync.RWMutex
	cap     int
	samples []serverProbeSample
}

func newServerProbeHistory(capacity int) *serverProbeHistory {
	if capacity <= 0 {
		capacity = serverProbeCapacity
	}
	return &serverProbeHistory{cap: capacity}
}

func (h *serverProbeHistory) Reset() {
	if h == nil {
		return
	}
	h.mu.Lock()
	h.samples = nil
	h.mu.Unlock()
}

func (h *serverProbeHistory) Record(sample serverProbeSample) {
	if h == nil {
		return
	}
	if sample.At.IsZero() {
		sample.At = time.Now()
	}
	h.mu.Lock()
	if len(h.samples) >= h.cap {
		copy(h.samples, h.samples[1:])
		h.samples[len(h.samples)-1] = sample
	} else {
		h.samples = append(h.samples, sample)
	}
	h.mu.Unlock()
}

func (h *serverProbeHistory) Snapshot() ([]serverProbeSample, serverProbeStats) {
	if h == nil {
		return nil, serverProbeStats{LatestRTTMillis: -1}
	}
	h.mu.RLock()
	out := append([]serverProbeSample(nil), h.samples...)
	h.mu.RUnlock()

	stats := serverProbeStats{LatestRTTMillis: -1, Count: len(out)}
	if len(out) == 0 {
		return out, stats
	}

	var sum float64
	var okCount int
	for _, s := range out {
		if s.Mode != "" {
			stats.Mode = s.Mode
		}
		if s.Lost {
			stats.LostCount++
			continue
		}
		okCount++
		sum += s.RTTMillis
		if s.RTTMillis > stats.MaxRTTMillis {
			stats.MaxRTTMillis = s.RTTMillis
		}
	}
	if okCount > 0 {
		stats.AvgRTTMillis = sum / float64(okCount)
	}
	last := out[len(out)-1]
	if !last.Lost {
		stats.LatestRTTMillis = last.RTTMillis
	}

	start := 0
	if len(out) > serverProbeLossWindow {
		start = len(out) - serverProbeLossWindow
	}
	winSamples := out[start:]
	winLost := 0
	for _, s := range winSamples {
		if s.Lost {
			winLost++
		}
	}
	if len(winSamples) > 0 {
		stats.LossPercent = float64(winLost) * 100 / float64(len(winSamples))
	}
	return out, stats
}

func rollingLossPercents(samples []serverProbeSample, window int) []float64 {
	if window <= 0 {
		window = serverProbeLossWindow
	}
	out := make([]float64, len(samples))
	for i := range samples {
		start := 0
		if i+1 > window {
			start = i + 1 - window
		}
		lost := 0
		total := i + 1 - start
		for j := start; j <= i; j++ {
			if samples[j].Lost {
				lost++
			}
		}
		out[i] = float64(lost) * 100 / float64(total)
	}
	return out
}

func computeChartCeilingMS(samples []serverProbeSample) float64 {
	peak := 0.0
	for _, s := range samples {
		if !s.Lost && s.RTTMillis > peak {
			peak = s.RTTMillis
		}
	}
	switch {
	case peak <= 40:
		return 50
	case peak <= 80:
		return 100
	case peak <= 160:
		return 200
	case peak <= 320:
		return 400
	default:
		step := 100.0
		return math.Ceil(peak*1.25/step) * step
	}
}

func formatLatencyText(rttMillis float64) string {
	if rttMillis < 0 {
		return "--"
	}
	if rttMillis < 1 {
		return "<1 ms"
	}
	return fmt.Sprintf("%.0f ms", rttMillis)
}

func (a *desktop) startServerProbeLoop() {
	if a == nil || a.smokeMode || a.ctx == nil {
		return
	}
	if a.serverProbe == nil {
		a.serverProbe = newServerProbeHistory(serverProbeCapacity)
	}
	httpClient := &http.Client{Timeout: 1500 * time.Millisecond}
	if a.api != nil && a.api.HTTP != nil && a.api.HTTP.Transport != nil {
		httpClient.Transport = a.api.HTTP.Transport
	}

	go func() {
		stunConsecutiveFails := 0
		tickCount := 0
		probeOnce := func() {
			if a.closing.Load() || a.ctx.Err() != nil {
				return
			}
			api := a.api
			stunAddr := strings.TrimSpace(a.stun)
			if api == nil || api.Token == "" || strings.TrimSpace(api.BaseURL) == "" {
				return
			}
			tickCount++
			useSTUN := stunAddr != "" && (stunConsecutiveFails < 3 || tickCount%15 == 0)
			var sample serverProbeSample
			if useSTUN {
				probeCtx, cancel := context.WithTimeout(a.ctx, 1500*time.Millisecond)
				client := network.NewUDPSTUNClient()
				client.Timeout = 1500 * time.Millisecond
				started := time.Now()
				_, err := client.Probe(probeCtx, stunAddr)
				cancel()
				if err == nil {
					stunConsecutiveFails = 0
					ms := float64(time.Since(started)) / float64(time.Millisecond)
					if ms <= 0 {
						ms = 0.2
					}
					sample = serverProbeSample{At: time.Now(), RTTMillis: ms, Mode: "STUN UDP"}
				} else {
					stunConsecutiveFails++
					if stunConsecutiveFails <= 2 {
						sample = serverProbeSample{At: time.Now(), Lost: true, Mode: "STUN UDP"}
					} else {
						sample = probeControlHealth(a.ctx, api, httpClient)
					}
				}
			} else {
				sample = probeControlHealth(a.ctx, api, httpClient)
			}
			if a.ctx.Err() != nil || a.closing.Load() {
				return
			}
			a.serverProbe.Record(sample)
			a.ui(a.refreshServerMetricsDisplay)
		}

		probeOnce()
		ticker := time.NewTicker(serverProbeInterval)
		defer ticker.Stop()
		for {
			select {
			case <-a.ctx.Done():
				return
			case <-ticker.C:
				probeOnce()
			}
		}
	}()
}

func probeControlHealth(ctx context.Context, api *clientapi.Client, httpClient *http.Client) serverProbeSample {
	probeCtx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer cancel()
	probeClient := clientapi.Client{BaseURL: api.BaseURL, HTTP: httpClient}
	rtt, err := probeClient.HealthProbe(probeCtx)
	if err != nil {
		return serverProbeSample{At: time.Now(), Lost: true, Mode: "HTTPS"}
	}
	ms := float64(rtt) / float64(time.Millisecond)
	if ms <= 0 {
		ms = 0.2
	}
	return serverProbeSample{At: time.Now(), RTTMillis: ms, Mode: "HTTPS"}
}

func formatProbeModeLabel(mode string) string {
	switch strings.TrimSpace(mode) {
	case "":
		return tr("待检测", "Pending")
	case "STUN UDP":
		return "STUN · UDP"
	case "HTTPS":
		return tr("HTTPS 链路", "HTTPS")
	default:
		return mode
	}
}

func formatProbeSpanText(seconds int) string {
	if seconds <= 0 {
		return tr("0秒", "0s")
	}
	if seconds < 60 {
		return trf("%d秒", "%ds", seconds)
	}
	mins := seconds / 60
	rem := seconds % 60
	if rem == 0 {
		return trf("%d分钟", "%dm", mins)
	}
	return trf("%d分%d秒", "%dm%ds", mins, rem)
}

func (a *desktop) refreshServerMetricsDisplay() {
	if a == nil || a.serverProbe == nil {
		return
	}
	samples, stats := a.serverProbe.Snapshot()
	if a.serverLatencyLabel != nil {
		if stats.Count == 0 {
			setLabelIfChanged(a.serverLatencyLabel, tr("延迟 --", "RTT --"))
			setLabelColorIfChanged(a.serverLatencyLabel, uiMuted)
		} else if len(samples) > 0 && samples[len(samples)-1].Lost {
			setLabelIfChanged(a.serverLatencyLabel, tr("延迟 超时", "RTT Timeout"))
			setLabelColorIfChanged(a.serverLatencyLabel, uiDanger)
		} else {
			setLabelIfChanged(a.serverLatencyLabel, tr("延迟 ", "RTT ")+formatLatencyText(stats.LatestRTTMillis))
			switch {
			case stats.LatestRTTMillis >= 150:
				setLabelColorIfChanged(a.serverLatencyLabel, uiWarning)
			default:
				setLabelColorIfChanged(a.serverLatencyLabel, uiBlue)
			}
		}
	}
	if a.serverAvgLabel != nil {
		if stats.Count == 0 || stats.AvgRTTMillis <= 0 {
			setLabelIfChanged(a.serverAvgLabel, tr("均值 --", "Avg --"))
			setLabelColorIfChanged(a.serverAvgLabel, uiMuted)
		} else {
			setLabelIfChanged(a.serverAvgLabel, tr("均值 ", "Avg ")+formatLatencyText(stats.AvgRTTMillis))
			setLabelColorIfChanged(a.serverAvgLabel, uiInk)
		}
	}
	if a.serverLossLabel != nil {
		if stats.Count == 0 {
			setLabelIfChanged(a.serverLossLabel, tr("丢包 --", "Loss --"))
			setLabelColorIfChanged(a.serverLossLabel, uiMuted)
		} else {
			setLabelIfChanged(a.serverLossLabel, trf("丢包 %.1f%%", "Loss %.1f%%", stats.LossPercent))
			switch {
			case stats.LossPercent >= 5:
				setLabelColorIfChanged(a.serverLossLabel, uiDanger)
			case stats.LossPercent > 0:
				setLabelColorIfChanged(a.serverLossLabel, uiWarning)
			default:
				setLabelColorIfChanged(a.serverLossLabel, uiSuccess)
			}
		}
	}
	if a.serverProbeModeLabel != nil {
		setLabelIfChanged(a.serverProbeModeLabel, formatProbeModeLabel(stats.Mode))
	}
	if a.serverChart != nil && !a.serverChart.IsDisposed() && a.page == pagePower {
		_ = a.serverChart.Invalidate()
	}
}

var (
	serverChartFontMu sync.Mutex
	serverChartFonts  = map[int]win.HFONT{}
)

func serverChartAxisFont(dpi int) uintptr {
	if dpi <= 0 {
		dpi = 96
	}
	serverChartFontMu.Lock()
	defer serverChartFontMu.Unlock()
	if font, ok := serverChartFonts[dpi]; ok && font != 0 {
		return uintptr(font)
	}
	var lf win.LOGFONT
	lf.LfHeight = -win.MulDiv(8, int32(dpi), 72)
	lf.LfWeight = win.FW_NORMAL
	lf.LfCharSet = win.DEFAULT_CHARSET
	lf.LfQuality = 5 // CLEARTYPE_QUALITY
	face, _ := windows.UTF16FromString("Microsoft YaHei UI")
	copy(lf.LfFaceName[:], face)
	font := win.CreateFontIndirect(&lf)
	serverChartFonts[dpi] = font
	return uintptr(font)
}

func (a *desktop) serverChartWidget() CustomWidget {
	return CustomWidget{
		AssignTo:            &a.serverChart,
		StretchFactor:       1,
		MinSize:             Size{Width: 200, Height: 98},
		PaintMode:           PaintNoErase,
		InvalidatesOnResize: true,
		PaintPixels: func(canvas *walk.Canvas, _ walk.Rectangle) error {
			if a.serverChart == nil || a.serverChart.IsDisposed() {
				return nil
			}
			cb := a.serverChart.ClientBoundsPixels()
			if cb.Width <= 0 || cb.Height <= 0 {
				return nil
			}
			r := win.RECT{Right: int32(cb.Width), Bottom: int32(cb.Height)}
			return drawBufferedDC(canvas.HDC(), r, uiWhite, func(dc win.HDC, c *smoothCanvas, local win.RECT) {
				paintServerChart(dc, c, local, a.serverChart.DPI(), a.serverProbe)
			})
		},
	}
}

func paintServerChart(dc win.HDC, canvas *smoothCanvas, local win.RECT, dpi int, history *serverProbeHistory) {
	w := local.Right - local.Left
	h := local.Bottom - local.Top
	if w < 12 || h < 12 {
		return
	}
	// Inset by 1px on all sides so the GDI+ 1px border stroke never clips on control edges.
	frame := win.RECT{
		Left:   local.Left + 1,
		Top:    local.Top + 1,
		Right:  local.Right - 2,
		Bottom: local.Bottom - 2,
	}
	rad := walk.IntFrom96DPI(10, dpi)
	fontH := serverChartAxisFont(dpi)

	plotBgTop := mixColor(uiWhite, uiTableAlt, 0.48)
	plotBgBot := mixColor(uiTableAlt, uiBlueSoft, 0.35)
	if activePalette == darkPalette {
		plotBgTop = mixColor(uiTableAlt, uiWhite, 0.04)
		plotBgBot = mixColor(uiBackground, uiTableAlt, 0.55)
	}
	border := uiBorder
	canvas.roundedGradient(frame, rad, plotBgTop, plotBgBot, &border, 1.0)

	padL := int32(walk.IntFrom96DPI(48, dpi))
	padR := int32(walk.IntFrom96DPI(14, dpi))
	padT := int32(walk.IntFrom96DPI(14, dpi))
	padB := int32(walk.IntFrom96DPI(22, dpi))

	plotLeft := int(frame.Left + padL)
	plotRight := int(frame.Right - padR)
	plotTop := int(frame.Top + padT)
	plotBot := int(frame.Bottom - padB)
	plotW := plotRight - plotLeft
	plotH := plotBot - plotTop
	if plotW < 28 || plotH < 20 {
		return
	}

	var samples []serverProbeSample
	var stats serverProbeStats
	if history != nil {
		samples, stats = history.Snapshot()
	}
	ceilMS := computeChartCeilingMS(samples)

	// Interior vertical dashed guides at 1/3 and 2/3 of the plot width.
	for _, frac := range []float64{1.0 / 3.0, 2.0 / 3.0} {
		vx := plotLeft + int(math.Round(float64(plotW)*frac))
		canvas.lineDashAlpha(vx, plotTop, vx, plotBot, uiBorderStrong, 90, 1.0, 2)
	}

	// Horizontal reference lines strictly inside [plotLeft, plotRight] so they never touch corners.
	canvas.lineDashAlpha(plotLeft, plotTop, plotRight, plotTop, uiBorderStrong, 125, 1.0, 2)
	canvas.lineDashAlpha(plotLeft, (plotTop+plotBot)/2, plotRight, (plotTop+plotBot)/2, uiBorderStrong, 125, 1.0, 2)
	canvas.lineAlpha(plotLeft, plotBot, plotRight, plotBot, uiBorderStrong, 185, 1.0)

	lblRight := int32(plotLeft - walk.IntFrom96DPI(6, dpi))
	lblH := int32(walk.IntFrom96DPI(14, dpi))
	drawYAxis := func(y int, text string) {
		rect := win.RECT{Left: frame.Left + 2, Top: int32(y) - lblH/2, Right: lblRight, Bottom: int32(y) + lblH/2}
		if rect.Top < frame.Top+2 {
			shift := frame.Top + 2 - rect.Top
			rect.Top += shift
			rect.Bottom += shift
		}
		if rect.Bottom > int32(plotBot)+lblH/2 {
			shift := rect.Bottom - (int32(plotBot) + lblH/2)
			rect.Top -= shift
			rect.Bottom -= shift
		}
		drawControlText(dc, fontH, text, rect, uiMuted, win.DT_RIGHT)
	}

	if len(samples) == 0 {
		canvas.dispose()
		drawYAxis(plotTop, fmt.Sprintf("%.0fms", ceilMS))
		drawYAxis((plotTop+plotBot)/2, fmt.Sprintf("%.0fms", ceilMS/2))
		drawYAxis(plotBot, "0ms")
		msgRect := win.RECT{Left: int32(plotLeft), Top: int32(plotTop), Right: int32(plotRight), Bottom: int32(plotBot)}
		drawControlText(dc, fontH, tr("正在等待首次探测样本…", "Waiting for probe samples…"), msgRect, uiMuted, win.DT_CENTER)
		return
	}

	lossRates := rollingLossPercents(samples, serverProbeLossWindow)
	maxLossSeen := 0.0
	for _, lr := range lossRates {
		if lr > maxLossSeen {
			maxLossSeen = lr
		}
	}

	n := len(samples)
	xFor := func(i int) int32 {
		if n <= 1 {
			return int32(plotRight)
		}
		return int32(math.Round(float64(plotLeft) + float64(i)*float64(plotW)/float64(n-1)))
	}
	yForMS := func(ms float64) int32 {
		ratio := ms / ceilMS
		if ratio < 0 {
			ratio = 0
		} else if ratio > 1 {
			ratio = 1
		}
		return int32(math.Round(float64(plotBot) - ratio*float64(plotH)))
	}
	yForLoss := func(pct float64) int32 {
		ratio := pct / 100.0
		if ratio < 0 {
			ratio = 0
		} else if ratio > 1 {
			ratio = 1
		}
		return int32(math.Round(float64(plotBot) - ratio*float64(plotH)))
	}

	// Draw subtle dashed average baseline when multiple valid samples exist.
	if n >= 2 && stats.AvgRTTMillis > 0 {
		avgY := int(yForMS(stats.AvgRTTMillis))
		canvas.lineDashAlpha(plotLeft, avgY, plotRight, avgY, uiBlueBorder, 140, 1.0, 1)
	}

	// Draw rolling packet loss curve when any loss is present.
	if maxLossSeen > 0 {
		lossPts := make([]win.POINT, n)
		for i := range samples {
			lossPts[i] = win.POINT{X: xFor(i), Y: yForLoss(lossRates[i])}
		}
		if len(lossPts) == 1 {
			lossPts = append([]win.POINT{{X: int32(plotLeft), Y: lossPts[0].Y}}, lossPts...)
		}
		smoothLoss := smoothMonotoneSpline(lossPts, int32(plotTop), int32(plotBot))
		canvas.polyLine(smoothLoss, uiDanger, 195, 1.6)
	}

	// Draw contiguous valid latency segments with monotone spline & layered glow fill.
	var segment []win.POINT
	flushSegment := func() {
		if len(segment) >= 2 {
			smooth := smoothMonotoneSpline(segment, int32(plotTop), int32(plotBot))
			topFade := uiBlue
			botFade := plotBgBot
			canvas.areaFill(smooth, int32(plotBot), topFade, botFade, 68, 2)
			canvas.polyLine(smooth, uiBlueBorder, 48, 4.4)
			canvas.polyLine(smooth, uiBlue, 245, 2.1)
		} else if len(segment) == 1 && n == 1 {
			py := int(segment[0].Y)
			canvas.lineDashAlpha(plotLeft, py, int(segment[0].X), py, uiBlueBorder, 165, 1.4, 1)
		} else if len(segment) == 1 {
			px, py := int(segment[0].X), int(segment[0].Y)
			canvas.circle(px-2, py-2, 5, uiBlue)
		}
		segment = segment[:0]
	}
	var lastValid *win.POINT
	for i, s := range samples {
		px := xFor(i)
		if s.Lost {
			flushSegment()
			canvas.lineDashAlpha(int(px), plotTop+2, int(px), plotBot, uiDanger, 165, 1.6, 1)
			canvas.circle(int(px)-2, plotTop, 5, uiDanger)
			continue
		}
		pt := win.POINT{X: px, Y: yForMS(s.RTTMillis)}
		segment = append(segment, pt)
		pCopy := pt
		lastValid = &pCopy
	}
	flushSegment()

	if lastValid != nil {
		lx, ly := int(lastValid.X), int(lastValid.Y)
		canvas.circleAlpha(lx-6, ly-6, 13, uiBlueBorder, 70)
		canvas.circle(lx-4, ly-4, 9, uiWhite)
		canvas.circle(lx-2, ly-2, 5, uiBlue)
	}

	canvas.dispose()

	// Left Y-axis scale labels
	drawYAxis(plotTop, fmt.Sprintf("%.0fms", ceilMS))
	drawYAxis((plotTop+plotBot)/2, fmt.Sprintf("%.0fms", ceilMS/2))
	drawYAxis(plotBot, "0ms")

	// Bottom X-axis time window labels cleanly separated under the 0ms baseline
	xTop := int32(plotBot + walk.IntFrom96DPI(3, dpi))
	xBot := frame.Bottom - int32(walk.IntFrom96DPI(2, dpi))
	if xBot > xTop+8 {
		spanSec := (n - 1) * int(serverProbeInterval/time.Second)
		leftText := tr("当前样本", "Current")
		if spanSec > 0 {
			leftText = "-" + formatProbeSpanText(spanSec)
		}
		leftRect := win.RECT{Left: int32(plotLeft), Top: xTop, Right: int32(plotLeft + plotW/3), Bottom: xBot}
		drawControlText(dc, fontH, leftText, leftRect, uiMuted, win.DT_LEFT)

		midRect := win.RECT{Left: int32(plotLeft + plotW/4), Top: xTop, Right: int32(plotRight - plotW/4), Bottom: xBot}
		midText := trf("最近 %d 次采样", "Last %d samples", n)
		if maxLossSeen > 0 {
			midText = trf("峰值 %.0f ms · 丢包 %.1f%%", "Peak %.0f ms · Loss %.1f%%", stats.MaxRTTMillis, stats.LossPercent)
		} else if n >= 3 && stats.MaxRTTMillis > 0 {
			midText = trf("峰值 %.0f ms · 每2秒", "Peak %.0f ms · 2s interval", stats.MaxRTTMillis)
		}
		drawControlText(dc, fontH, midText, midRect, uiMuted, win.DT_CENTER)

		rightRect := win.RECT{Left: int32(plotRight - plotW/3), Top: xTop, Right: int32(plotRight), Bottom: xBot}
		drawControlText(dc, fontH, tr("现在", "Now"), rightRect, uiMuted, win.DT_RIGHT)
	}
}
