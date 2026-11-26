//go:build windows

package main

import (
	"fmt"
	"math"
	"sync"
	"unsafe"

	"github.com/lxn/walk"
	"github.com/lxn/win"
	"golang.org/x/sys/windows"
)

// Windows GDI+ is part of the OS. It gives the native controls antialiased
// outlines without adding a browser runtime or shipping a separate UI engine.
var gdip = windows.NewLazySystemDLL("gdiplus.dll")
var drawingOnce sync.Once
var drawingToken uintptr
var drawingErr error
var (
	gpStartup         = gdip.NewProc("GdiplusStartup")
	gpShutdown        = gdip.NewProc("GdiplusShutdown")
	gpFromDC          = gdip.NewProc("GdipCreateFromHDC")
	gpDeleteGraphics  = gdip.NewProc("GdipDeleteGraphics")
	gpSmoothing       = gdip.NewProc("GdipSetSmoothingMode")
	gpSolid           = gdip.NewProc("GdipCreateSolidFill")
	gpDeleteBrush     = gdip.NewProc("GdipDeleteBrush")
	gpFillEllipse     = gdip.NewProc("GdipFillEllipseI")
	gpFillPie         = gdip.NewProc("GdipFillPieI")
	gpLineBrush       = gdip.NewProc("GdipCreateLineBrushI")
	gpPen             = gdip.NewProc("GdipCreatePen1")
	gpDeletePen       = gdip.NewProc("GdipDeletePen")
	gpSetPenDashStyle = gdip.NewProc("GdipSetPenDashStyle")
	gpStartCap        = gdip.NewProc("GdipSetPenStartCap")
	gpEndCap          = gdip.NewProc("GdipSetPenEndCap")
	gpDrawEllipse     = gdip.NewProc("GdipDrawEllipseI")
	gpDrawArc         = gdip.NewProc("GdipDrawArcI")
	gpDrawLine        = gdip.NewProc("GdipDrawLineI")
	gpPath            = gdip.NewProc("GdipCreatePath")
	gpAddArc          = gdip.NewProc("GdipAddPathArcI")
	gpAddLine         = gdip.NewProc("GdipAddPathLineI")
	gpClosePath       = gdip.NewProc("GdipClosePathFigure")
	gpDeletePath      = gdip.NewProc("GdipDeletePath")
	gpFillPath        = gdip.NewProc("GdipFillPath")
	gpDrawPath        = gdip.NewProc("GdipDrawPath")
)

func initSmoothDrawing() error {
	drawingOnce.Do(func() {
		input := struct {
			Version        uint32
			DebugCallback  uintptr
			SuppressThread int32
			SuppressCodecs int32
		}{Version: 1}
		status, _, _ := gpStartup.Call(uintptr(unsafe.Pointer(&drawingToken)), uintptr(unsafe.Pointer(&input)), 0)
		if status != 0 {
			drawingErr = fmt.Errorf("initialize smooth drawing: status %d", status)
		}
	})
	return drawingErr
}
func releaseSmoothDrawing() {
	if drawingToken != 0 {
		gpShutdown.Call(drawingToken)
		drawingToken = 0
	}
}

type smoothCanvas struct {
	graphics uintptr
	err      error
}

func newSmoothCanvas(dc win.HDC) *smoothCanvas {
	c := &smoothCanvas{}
	c.call(gpFromDC, uintptr(dc), uintptr(unsafe.Pointer(&c.graphics)))
	if c.graphics != 0 {
		c.call(gpSmoothing, c.graphics, 4)
	}
	return c
}
func (c *smoothCanvas) call(p *windows.LazyProc, args ...uintptr) {
	if c.err != nil {
		return
	}
	status, _, _ := p.Call(args...)
	if status != 0 {
		c.err = fmt.Errorf("%s: drawing status %d", p.Name, status)
	}
}
func (c *smoothCanvas) dispose() {
	if c.graphics != 0 {
		gpDeleteGraphics.Call(c.graphics)
		c.graphics = 0
	}
}
func argb(color walk.Color) uintptr {
	return argbAlpha(color, 255)
}
func argbAlpha(color walk.Color, alpha uint8) uintptr {
	return uintptr(uint32(alpha)<<24 | uint32(color&255)<<16 | uint32(color&0xff00) | uint32(color>>16)&255)
}
func real(v float32) uintptr { return uintptr(math.Float32bits(v)) }
func (c *smoothCanvas) brush(color walk.Color) uintptr {
	return c.brushAlpha(color, 255)
}
func (c *smoothCanvas) brushAlpha(color walk.Color, alpha uint8) uintptr {
	var brush uintptr
	c.call(gpSolid, argbAlpha(color, alpha), uintptr(unsafe.Pointer(&brush)))
	return brush
}
func (c *smoothCanvas) pen(color walk.Color, width float32) uintptr {
	return c.penAlpha(color, 255, width)
}
func (c *smoothCanvas) penAlpha(color walk.Color, alpha uint8, width float32) uintptr {
	var pen uintptr
	c.call(gpPen, argbAlpha(color, alpha), real(width), 2, uintptr(unsafe.Pointer(&pen)))
	if pen != 0 {
		c.call(gpStartCap, pen, 2)
		c.call(gpEndCap, pen, 2)
	}
	return pen
}
func (c *smoothCanvas) penDashAlpha(color walk.Color, alpha uint8, width float32, dashStyle uintptr) uintptr {
	pen := c.penAlpha(color, alpha, width)
	if pen != 0 {
		c.call(gpSetPenDashStyle, pen, dashStyle)
	}
	return pen
}
func (c *smoothCanvas) circle(x, y, d int, color walk.Color) {
	c.circleAlpha(x, y, d, color, 255)
}
func (c *smoothCanvas) circleAlpha(x, y, d int, color walk.Color, alpha uint8) {
	if d <= 0 || alpha == 0 {
		return
	}
	b := c.brushAlpha(color, alpha)
	if b == 0 {
		return
	}
	defer gpDeleteBrush.Call(b)
	c.call(gpFillEllipse, c.graphics, b, uintptr(x), uintptr(y), uintptr(d), uintptr(d))
}
func (c *smoothCanvas) pieAlpha(x, y, d int, startAngle, sweepAngle float32, color walk.Color, alpha uint8) {
	if d <= 0 || alpha == 0 || sweepAngle == 0 {
		return
	}
	b := c.brushAlpha(color, alpha)
	if b == 0 {
		return
	}
	defer gpDeleteBrush.Call(b)
	c.call(gpFillPie, c.graphics, b, uintptr(x), uintptr(y), uintptr(d), uintptr(d), real(startAngle), real(sweepAngle))
}
func (c *smoothCanvas) ring(x, y, d int, color walk.Color, width float32) {
	c.ringAlpha(x, y, d, color, 255, width)
}
func (c *smoothCanvas) ringAlpha(x, y, d int, color walk.Color, alpha uint8, width float32) {
	if d <= 0 || alpha == 0 {
		return
	}
	p := c.penAlpha(color, alpha, width)
	if p == 0 {
		return
	}
	defer gpDeletePen.Call(p)
	c.call(gpDrawEllipse, c.graphics, p, uintptr(x), uintptr(y), uintptr(d), uintptr(d))
}
func (c *smoothCanvas) lineAlpha(x1, y1, x2, y2 int, color walk.Color, alpha uint8, width float32) {
	if alpha == 0 {
		return
	}
	p := c.penAlpha(color, alpha, width)
	if p == 0 {
		return
	}
	defer gpDeletePen.Call(p)
	c.call(gpDrawLine, c.graphics, p, uintptr(x1), uintptr(y1), uintptr(x2), uintptr(y2))
}

func (c *smoothCanvas) lineDashAlpha(x1, y1, x2, y2 int, color walk.Color, alpha uint8, width float32, dashStyle uintptr) {
	if alpha == 0 {
		return
	}
	p := c.penDashAlpha(color, alpha, width, dashStyle)
	if p == 0 {
		return
	}
	defer gpDeletePen.Call(p)
	c.call(gpDrawLine, c.graphics, p, uintptr(x1), uintptr(y1), uintptr(x2), uintptr(y2))
}

// smoothMonotoneSpline builds a smooth Fritsch-Carlson monotonic cubic spline
// clamped strictly inside [minY, maxY] so sharp latency changes never overshoot.
func smoothMonotoneSpline(points []win.POINT, minY, maxY int32) []win.POINT {
	n := len(points)
	if n <= 2 {
		out := make([]win.POINT, n)
		copy(out, points)
		return out
	}
	xs := make([]float64, n)
	ys := make([]float64, n)
	for i, pt := range points {
		xs[i] = float64(pt.X)
		ys[i] = float64(pt.Y)
	}
	dx := make([]float64, n-1)
	slope := make([]float64, n-1)
	for i := 0; i < n-1; i++ {
		dx[i] = xs[i+1] - xs[i]
		if dx[i] <= 0 {
			dx[i] = 1
		}
		slope[i] = (ys[i+1] - ys[i]) / dx[i]
	}
	m := make([]float64, n)
	m[0] = slope[0]
	m[n-1] = slope[n-2]
	for i := 1; i < n-1; i++ {
		if slope[i-1]*slope[i] <= 0 {
			m[i] = 0
		} else {
			m[i] = (slope[i-1] + slope[i]) / 2
		}
	}
	for i := 0; i < n-1; i++ {
		if slope[i] == 0 {
			m[i], m[i+1] = 0, 0
			continue
		}
		a := m[i] / slope[i]
		b := m[i+1] / slope[i]
		s := a*a + b*b
		if s > 9 {
			t := 3.0 / math.Sqrt(s)
			m[i] = t * a * slope[i]
			m[i+1] = t * b * slope[i]
		}
	}

	out := make([]win.POINT, 0, n*8)
	out = append(out, points[0])
	lo, hi := float64(minY), float64(maxY)
	for i := 0; i < n-1; i++ {
		steps := int(math.Ceil(dx[i] / 3.0))
		if steps < 4 {
			steps = 4
		}
		if steps > 16 {
			steps = 16
		}
		for step := 1; step <= steps; step++ {
			t := float64(step) / float64(steps)
			t2 := t * t
			t3 := t2 * t
			h00 := 2*t3 - 3*t2 + 1
			h10 := t3 - 2*t2 + t
			h01 := -2*t3 + 3*t2
			h11 := t3 - t2
			x := xs[i] + t*dx[i]
			y := h00*ys[i] + h10*dx[i]*m[i] + h01*ys[i+1] + h11*dx[i]*m[i+1]
			if y < lo {
				y = lo
			} else if y > hi {
				y = hi
			}
			pt := win.POINT{X: int32(math.Round(x)), Y: int32(math.Round(y))}
			last := out[len(out)-1]
			if pt.X != last.X || pt.Y != last.Y {
				out = append(out, pt)
			}
		}
	}
	return out
}

func (c *smoothCanvas) polyLine(points []win.POINT, color walk.Color, alpha uint8, width float32) {
	if len(points) < 2 || alpha == 0 {
		return
	}
	var path uintptr
	c.call(gpPath, 0, uintptr(unsafe.Pointer(&path)))
	if path == 0 {
		return
	}
	defer gpDeletePath.Call(path)
	for i := 0; i < len(points)-1; i++ {
		c.call(gpAddLine, path, uintptr(points[i].X), uintptr(points[i].Y), uintptr(points[i+1].X), uintptr(points[i+1].Y))
	}
	if pen := c.penAlpha(color, alpha, width); pen != 0 {
		defer gpDeletePen.Call(pen)
		c.call(gpDrawPath, c.graphics, pen, path)
	}
}

func (c *smoothCanvas) areaFill(points []win.POINT, baselineY int32, topColor, botColor walk.Color, topAlpha, botAlpha uint8) {
	if len(points) < 2 {
		return
	}
	var path uintptr
	c.call(gpPath, 0, uintptr(unsafe.Pointer(&path)))
	if path == 0 {
		return
	}
	defer gpDeletePath.Call(path)
	minY := baselineY
	for i := 0; i < len(points); i++ {
		if points[i].Y < minY {
			minY = points[i].Y
		}
		if i > 0 {
			c.call(gpAddLine, path, uintptr(points[i-1].X), uintptr(points[i-1].Y), uintptr(points[i].X), uintptr(points[i].Y))
		}
	}
	last := points[len(points)-1]
	first := points[0]
	c.call(gpAddLine, path, uintptr(last.X), uintptr(last.Y), uintptr(last.X), uintptr(baselineY))
	c.call(gpAddLine, path, uintptr(last.X), uintptr(baselineY), uintptr(first.X), uintptr(baselineY))
	c.call(gpClosePath, path)
	p1 := win.POINT{X: first.X, Y: minY}
	p2 := win.POINT{X: first.X, Y: baselineY}
	if p2.Y <= p1.Y {
		p2.Y = p1.Y + 1
	}
	var brush uintptr
	c.call(gpLineBrush, uintptr(unsafe.Pointer(&p1)), uintptr(unsafe.Pointer(&p2)), argbAlpha(topColor, topAlpha), argbAlpha(botColor, botAlpha), 3, uintptr(unsafe.Pointer(&brush)))
	if brush != 0 {
		defer gpDeleteBrush.Call(brush)
		c.call(gpFillPath, c.graphics, brush, path)
	}
}
func (c *smoothCanvas) rounded(r win.RECT, radius int, fill walk.Color, border *walk.Color) {
	c.roundedAlpha(r, radius, fill, 255, border)
}
func (c *smoothCanvas) roundedAlpha(r win.RECT, radius int, fill walk.Color, alpha uint8, border *walk.Color) {
	c.roundedAlphaStroke(r, radius, fill, alpha, border, 1)
}

func (c *smoothCanvas) roundedStroke(r win.RECT, radius int, fill walk.Color, alpha uint8, border *walk.Color, penWidth float32) {
	c.roundedAlphaStroke(r, radius, fill, alpha, border, penWidth)
}

func (c *smoothCanvas) roundedAlphaStroke(r win.RECT, radius int, fill walk.Color, alpha uint8, border *walk.Color, penWidth float32) {
	var path uintptr
	c.call(gpPath, 0, uintptr(unsafe.Pointer(&path)))
	if path == 0 {
		return
	}
	defer gpDeletePath.Call(path)
	x, y, w, h := int(r.Left), int(r.Top), int(r.Right-r.Left), int(r.Bottom-r.Top)
	d := radius * 2
	if d > w {
		d = w
	}
	if d > h {
		d = h
	}
	if d < 1 {
		return
	}
	for _, a := range []struct {
		x, y  int
		angle float32
	}{{x, y, 180}, {x + w - d, y, 270}, {x + w - d, y + h - d, 0}, {x, y + h - d, 90}} {
		c.call(gpAddArc, path, uintptr(a.x), uintptr(a.y), uintptr(d), uintptr(d), real(a.angle), real(90))
	}
	c.call(gpClosePath, path)
	brush := c.brushAlpha(fill, alpha)
	if brush != 0 {
		defer gpDeleteBrush.Call(brush)
		c.call(gpFillPath, c.graphics, brush, path)
	}
	if border != nil {
		pen := c.pen(*border, penWidth)
		if pen != 0 {
			defer gpDeletePen.Call(pen)
			c.call(gpDrawPath, c.graphics, pen, path)
		}
	}
}

func (c *smoothCanvas) roundedGradient(r win.RECT, radius int, topColor, bottomColor walk.Color, border *walk.Color, penWidth float32) {
	var path uintptr
	c.call(gpPath, 0, uintptr(unsafe.Pointer(&path)))
	if path == 0 {
		return
	}
	defer gpDeletePath.Call(path)
	x, y, w, h := int(r.Left), int(r.Top), int(r.Right-r.Left), int(r.Bottom-r.Top)
	d := radius * 2
	if d > w {
		d = w
	}
	if d > h {
		d = h
	}
	if d < 1 {
		return
	}
	for _, a := range []struct {
		x, y  int
		angle float32
	}{{x, y, 180}, {x + w - d, y, 270}, {x + w - d, y + h - d, 0}, {x, y + h - d, 90}} {
		c.call(gpAddArc, path, uintptr(a.x), uintptr(a.y), uintptr(d), uintptr(d), real(a.angle), real(90))
	}
	c.call(gpClosePath, path)
	p1 := win.POINT{X: r.Left, Y: r.Top}
	p2 := win.POINT{X: r.Left, Y: r.Bottom}
	if p2.Y <= p1.Y {
		p2.Y = p1.Y + 1
	}
	var brush uintptr
	c.call(gpLineBrush, uintptr(unsafe.Pointer(&p1)), uintptr(unsafe.Pointer(&p2)), argb(topColor), argb(bottomColor), 3, uintptr(unsafe.Pointer(&brush)))
	if brush != 0 {
		defer gpDeleteBrush.Call(brush)
		c.call(gpFillPath, c.graphics, brush, path)
	}
	if border != nil {
		pen := c.pen(*border, penWidth)
		if pen != 0 {
			defer gpDeletePen.Call(pen)
			c.call(gpDrawPath, c.graphics, pen, path)
		}
	}
}

func (c *smoothCanvas) hudCorners(r win.RECT, radius int, color walk.Color, alpha uint8) {
	w := int(r.Right - r.Left)
	h := int(r.Bottom - r.Top)
	if w < 36 || h < 28 || alpha == 0 {
		return
	}
	arm := 7
	if h < 64 {
		arm = 5
	}
	inset := 5
	left := int(r.Left) + inset
	top := int(r.Top) + inset
	right := int(r.Right) - inset - 1
	bottom := int(r.Bottom) - inset - 1

	rimAlpha := uint8(float64(alpha) * 0.55)
	rimLeft := int(r.Left) + radius + 8
	rimRight := int(r.Right) - radius - 8
	if rimRight > rimLeft+16 {
		c.lineAlpha(rimLeft, int(r.Top)+1, rimRight, int(r.Top)+1, color, rimAlpha, 1.0)
	}

	pen := c.penAlpha(color, alpha, 1.3)
	if pen == 0 {
		return
	}
	defer gpDeletePen.Call(pen)
	// Four subtle tactical corner brackets
	c.call(gpDrawLine, c.graphics, pen, uintptr(left), uintptr(top+arm), uintptr(left), uintptr(top))
	c.call(gpDrawLine, c.graphics, pen, uintptr(left), uintptr(top), uintptr(left+arm), uintptr(top))
	c.call(gpDrawLine, c.graphics, pen, uintptr(right-arm), uintptr(top), uintptr(right), uintptr(top))
	c.call(gpDrawLine, c.graphics, pen, uintptr(right), uintptr(top), uintptr(right), uintptr(top+arm))
	c.call(gpDrawLine, c.graphics, pen, uintptr(left), uintptr(bottom-arm), uintptr(left), uintptr(bottom))
	c.call(gpDrawLine, c.graphics, pen, uintptr(left), uintptr(bottom), uintptr(left+arm), uintptr(bottom))
	c.call(gpDrawLine, c.graphics, pen, uintptr(right-arm), uintptr(bottom), uintptr(right), uintptr(bottom))
	c.call(gpDrawLine, c.graphics, pen, uintptr(right), uintptr(bottom), uintptr(right), uintptr(bottom-arm))
}

func (c *smoothCanvas) drawPowerDial(cx, cy, d, state int, hover bool) {
	h := 0.0
	if hover {
		h = 1.0
	}
	g := 0.0
	if state == 1 {
		g = 1.0
	} else if state == 2 {
		g = 0.55
	}
	c.drawPowerDialAnimated(cx, cy, d, state, h, g, 0.18)
}

func (c *smoothCanvas) drawPowerDialAnimated(cx, cy, d, state int, hover, glow, phase float64) {
	if d <= 8 {
		return
	}
	outerPad := int(math.Round(float64(d) * 0.06))
	bezelD := d - outerPad
	bezelX := cx - bezelD/2
	bezelY := cy - bezelD/2
	pad := int(math.Round(float64(d) * 0.13))
	if pad < 3 {
		pad = 3
	}
	discD := d - 2*pad
	if discD <= 4 {
		return
	}
	discX := cx - discD/2
	discY := cy - discD/2

	// Multi-layer radial energy halo
	energy := math.Max(glow, hover*0.48)
	if energy > 0.02 {
		c.circleAlpha(cx-d/2-3, cy-d/2-3, d+6, uiBlueBorder, uint8(math.Round(24*energy)))
		c.circleAlpha(cx-d/2, cy-d/2, d, uiBlue, uint8(math.Round(46*energy)))
	} else {
		c.circle(cx-d/2, cy-d/2, d, uiPowerTrack)
	}

	// Segmented aerospace rotating bezel arcs
	bezelCol := mixColor(uiBorderStrong, uiBlueBorder, math.Max(glow, hover*0.85))
	if state == 2 {
		bezelCol = uiWarning
	}
	bezelAlpha := uint8(math.Round(110 + 135*math.Max(glow, hover)))
	if bezelPen := c.penAlpha(bezelCol, bezelAlpha, float32(math.Max(1.5, float64(d)*0.028))); bezelPen != 0 {
		rot := phase * 120.0
		if state == 2 {
			rot = phase * 360.0
		}
		for i := 0; i < 3; i++ {
			start := float32(math.Mod(rot+float64(i)*120.0, 360.0))
			c.call(gpDrawArc, c.graphics, bezelPen, uintptr(bezelX), uintptr(bezelY), uintptr(bezelD), uintptr(bezelD), real(start), real(76))
		}
		gpDeletePen.Call(bezelPen)
	}

	restingFace := mixColor(uiWhite, uiBlueSoft, hover)
	topActive := mixColor(uiBlueSelected, uiBlueHover, 0.35+hover*0.35)
	botActive := uiBlueDeep
	if activePalette == lightPalette {
		topActive = mixColor(uiBlue, uiBlueHover, hover*0.55)
		botActive = uiBlueDeep
	}
	if state == 2 {
		topActive = mixColor(uiTableAlt, uiWarning, 0.28)
		botActive = uiTableAlt
	}
	topCol := mixColor(restingFace, topActive, glow)
	botCol := mixColor(restingFace, botActive, glow)
	ringCol := mixColor(mixColor(uiBorderStrong, uiBlueBorder, hover), uiBlueBorder, glow)
	if state == 2 {
		ringCol = uiWarning
	}
	iconCol := mixColor(mixColor(uiMuted, uiBlue, hover), uiOnAccent, glow)
	if state == 2 {
		iconCol = uiWarning
	}

	// Fill circular reactor core with gradient
	var path uintptr
	c.call(gpPath, 0, uintptr(unsafe.Pointer(&path)))
	if path != 0 {
		c.call(gpAddArc, path, uintptr(discX), uintptr(discY), uintptr(discD), uintptr(discD), real(0), real(360))
		c.call(gpClosePath, path)
		p1 := win.POINT{X: int32(cx), Y: int32(discY)}
		p2 := win.POINT{X: int32(cx), Y: int32(discY + discD)}
		if p2.Y <= p1.Y {
			p2.Y = p1.Y + 1
		}
		var gradBrush uintptr
		c.call(gpLineBrush, uintptr(unsafe.Pointer(&p1)), uintptr(unsafe.Pointer(&p2)), argb(topCol), argb(botCol), 3, uintptr(unsafe.Pointer(&gradBrush)))
		if gradBrush != 0 {
			c.call(gpFillPath, c.graphics, gradBrush, path)
			gpDeleteBrush.Call(gradBrush)
		}
		gpDeletePath.Call(path)
	}
	c.ring(discX, discY, discD, ringCol, float32(math.Max(1.4, float64(d)*0.025)))
	if glow > 0.25 {
		c.ringAlpha(discX+2, discY+2, discD-4, uiOnAccent, uint8(math.Round(68*glow)), 1.0)
	}

	arcD := int(math.Round(float64(discD) * 0.44))
	arcX := cx - arcD/2
	arcY := cy - arcD/2 + int(math.Round(float64(discD)*0.03))
	stroke := float32(math.Max(2.0, float64(discD)*0.072))
	pen := c.pen(iconCol, stroke)
	if pen == 0 {
		return
	}
	defer gpDeletePen.Call(pen)
	c.call(gpDrawArc, c.graphics, pen, uintptr(arcX), uintptr(arcY), uintptr(arcD), uintptr(arcD), real(-50), real(280))
	stemTop := cy - int(math.Round(float64(discD)*0.27))
	stemBot := cy - int(math.Round(float64(discD)*0.02))
	c.call(gpDrawLine, c.graphics, pen, uintptr(cx), uintptr(stemTop), uintptr(cx), uintptr(stemBot))
}

func (c *smoothCanvas) power(r win.RECT, state int, hover bool) {
	h := 0.0
	if hover {
		h = 1.0
	}
	g := 0.0
	if state == 1 {
		g = 1.0
	} else if state == 2 {
		g = 0.55
	}
	c.powerAnimated(r, state, h, g, 0.18)
}

func (c *smoothCanvas) powerAnimated(r win.RECT, state int, hover, glow, phase float64) {
	w := int(r.Right - r.Left)
	h := int(r.Bottom - r.Top)
	if w <= 0 || h <= 0 {
		return
	}
	if w > h*13/10 {
		hud := win.RECT{Left: r.Left + 1, Top: r.Top + 1, Right: r.Right - 1, Bottom: r.Bottom - 1}
		border := mixColor(uiBorder, uiBlueBorder, math.Max(hover*0.85, glow*0.55))
		if state == 2 {
			border = uiWarning
		}
		rad := int(math.Round(float64(h) * 0.085))
		topFill := uiTableAlt
		botFill := mixColor(uiTableAlt, uiBackground, 0.42)
		c.roundedGradient(hud, rad, topFill, botFill, &border, 1.0)

		topoW := int(math.Round(float64(w) * 0.60))
		for i := 1; i <= 3; i++ {
			gx := int(r.Left) + topoW*i/4
			c.lineAlpha(gx, int(r.Top)+10, gx, int(r.Bottom)-10, uiBorder, 145, 1.0)
		}
		for j := 1; j <= 2; j++ {
			gy := int(r.Top) + h*j/3
			c.lineAlpha(int(r.Left)+10, gy, int(r.Left)+topoW-10, gy, uiBorder, 145, 1.0)
		}
		divX := int(r.Left) + topoW
		c.lineAlpha(divX, int(r.Top)+14, divX, int(r.Bottom)-14, mixColor(uiBorder, uiBlueBorder, 0.35), 180, 1.0)

		tcx := int(r.Left) + topoW/2
		tcy := int(r.Top) + h/2
		ringD := int(math.Round(float64(h) * 0.72))
		innerD := int(math.Round(float64(h) * 0.44))
		c.ringAlpha(tcx-ringD/2, tcy-ringD/2, ringD, mixColor(uiBorderStrong, uiBlueBorder, glow*0.45+hover*0.3), 170, 1.0)
		c.ringAlpha(tcx-innerD/2, tcy-innerD/2, innerD, mixColor(uiBorder, uiBlueBorder, glow*0.5), 140, 1.0)
		// Cardinal ticks on outer radar circle
		radR := ringD / 2
		c.lineAlpha(tcx-radR-3, tcy, tcx-radR+3, tcy, uiBlueBorder, 150, 1.1)
		c.lineAlpha(tcx+radR-3, tcy, tcx+radR+3, tcy, uiBlueBorder, 150, 1.1)
		c.lineAlpha(tcx, tcy-radR-3, tcx, tcy-radR+3, uiBlueBorder, 150, 1.1)
		c.lineAlpha(tcx, tcy+radR-3, tcx, tcy+radR+3, uiBlueBorder, 150, 1.1)

		// Conical rotating radar sweep wedge
		sweepEnergy := math.Max(glow, hover*0.52)
		if sweepEnergy > 0.02 {
			ang := float32(math.Mod(phase, 1.0) * 360.0)
			for _, slice := range []struct {
				span  float32
				alpha float64
			}{{46, 14}, {32, 18}, {20, 22}, {10, 30}} {
				c.pieAlpha(tcx-radR, tcy-radR, ringD, ang-slice.span, slice.span, uiBlueBorder, uint8(math.Round(slice.alpha*sweepEnergy)))
			}
			radAngle := float64(ang) * math.Pi / 180.0
			bx := tcx + int(math.Round(math.Cos(radAngle)*float64(radR)))
			by := tcy + int(math.Round(math.Sin(radAngle)*float64(radR)))
			c.lineAlpha(tcx, tcy, bx, by, uiBlueBorder, uint8(math.Round(210*sweepEnergy)), 1.5)
		}

		linkColor := mixColor(uiBorderStrong, uiBlue, glow)
		nodeColor := mixColor(uiMuted, uiSuccess, glow)
		hubColor := mixColor(uiMuted, uiBlueHover, glow)
		if state == 2 {
			linkColor, nodeColor, hubColor = uiWarning, uiWarning, uiWarning
		}

		dx := int(math.Round(float64(topoW) * 0.28))
		dy := int(math.Round(float64(h) * 0.27))
		nodes := [][2]int{
			{tcx - dx, tcy - dy},
			{tcx + dx, tcy - dy/2},
			{tcx - dx/3, tcy + dy},
		}
		if linkPen := c.pen(linkColor, 1.8); linkPen != 0 {
			for _, pt := range nodes {
				c.call(gpDrawLine, c.graphics, linkPen, uintptr(tcx), uintptr(tcy), uintptr(pt[0]), uintptr(pt[1]))
			}
			gpDeletePen.Call(linkPen)
		}

		// Traveling cyber packet pulses along active mesh vectors
		if glow > 0.12 {
			for idx, pt := range nodes {
				pktT := math.Mod(phase*2.2+float64(idx)*0.33, 1.0)
				px := int(math.Round(float64(tcx) + float64(pt[0]-tcx)*pktT))
				py := int(math.Round(float64(tcy) + float64(pt[1]-tcy)*pktT))
				fade := 1.0
				if pktT > 0.85 {
					fade = (1.0 - pktT) / 0.15
				}
				pktAlpha := uint8(math.Round(220 * glow * fade))
				c.circleAlpha(px-5, py-5, 10, uiBlueBorder, uint8(float64(pktAlpha)*0.45))
				c.circleAlpha(px-2, py-2, 4, uiFocus, pktAlpha)
			}
			// Expanding hub ping wave
			pingT := math.Mod(phase*1.5, 1.0)
			pingD := 16 + int(math.Round(pingT*float64(ringD-18)))
			pingAlpha := uint8(math.Round((1.0 - pingT) * 140 * glow))
			c.ringAlpha(tcx-pingD/2, tcy-pingD/2, pingD, uiBlueBorder, pingAlpha, 1.2)
		}

		satD := int(math.Max(10, math.Round(float64(h)*0.095)))
		satCore := int(math.Max(4, math.Round(float64(satD)*0.45)))
		for _, pt := range nodes {
			if glow > 0.15 {
				c.circleAlpha(pt[0]-(satD+6)/2, pt[1]-(satD+6)/2, satD+6, nodeColor, uint8(math.Round(65*glow)))
			}
			c.circle(pt[0]-satD/2, pt[1]-satD/2, satD, nodeColor)
			c.circle(pt[0]-satCore/2, pt[1]-satCore/2, satCore, uiWhite)
		}
		hubHalo := int(math.Max(22, math.Round(float64(h)*0.22)))
		hubD := int(math.Max(14, math.Round(float64(h)*0.13)))
		if glow > 0.05 {
			c.circleAlpha(tcx-hubHalo/2, tcy-hubHalo/2, hubHalo, uiBlueBorder, uint8(math.Round(70*glow)))
		}
		c.circle(tcx-hubD/2, tcy-hubD/2, hubD, hubColor)
		c.circle(tcx-satCore/2, tcy-satCore/2, satCore, uiOnAccent)

		dialD := int(math.Round(float64(h) * 0.58))
		dialCX := int(r.Left) + topoW + (w-topoW)/2
		dialCY := int(r.Top) + h/2
		c.drawPowerDialAnimated(dialCX, dialCY, dialD, state, hover, glow, phase)
		return
	}

	d := w
	if h < d {
		d = h
	}
	c.drawPowerDialAnimated(int(r.Left)+w/2, int(r.Top)+h/2, d, state, hover, glow, phase)
}

func (c *smoothCanvas) joinBlueprint(r win.RECT) {
	c.joinBlueprintAnimated(r, 0.22)
}

func (c *smoothCanvas) joinBlueprintAnimated(r win.RECT, phase float64) {
	w := int(r.Right - r.Left)
	h := int(r.Bottom - r.Top)
	if w <= 16 || h <= 16 {
		return
	}
	plate := win.RECT{Left: r.Left + 1, Top: r.Top + 1, Right: r.Right - 1, Bottom: r.Bottom - 1}
	border := mixColor(uiBorder, uiBlueBorder, 0.35)
	c.roundedGradient(plate, 10, uiTableAlt, mixColor(uiTableAlt, uiBackground, 0.35), &border, 1.0)

	for i := 1; i <= 3; i++ {
		gx := int(r.Left) + w*i/4
		c.lineAlpha(gx, int(r.Top)+10, gx, int(r.Bottom)-10, uiBorder, 150, 1.0)
	}
	for j := 1; j <= 3; j++ {
		gy := int(r.Top) + h*j/4
		c.lineAlpha(int(r.Left)+10, gy, int(r.Right)-10, gy, uiBorder, 150, 1.0)
	}

	cx := int(r.Left) + w/2
	topY := int(r.Top) + h*22/100
	midY := int(r.Top) + h*52/100
	botY := int(r.Top) + h*80/100
	leftX := int(r.Left) + w*24/100
	rightX := int(r.Left) + w*76/100

	c.lineAlpha(leftX, botY, rightX, botY, mixColor(uiBorderStrong, uiBlueBorder, 0.45), 185, 1.5)
	if activePen := c.pen(uiBlue, 2.0); activePen != 0 {
		c.call(gpDrawLine, c.graphics, activePen, uintptr(cx), uintptr(topY), uintptr(cx), uintptr(midY))
		c.call(gpDrawLine, c.graphics, activePen, uintptr(cx), uintptr(midY), uintptr(leftX), uintptr(botY))
		c.call(gpDrawLine, c.graphics, activePen, uintptr(cx), uintptr(midY), uintptr(rightX), uintptr(botY))
		c.call(gpDrawLine, c.graphics, activePen, uintptr(cx), uintptr(midY), uintptr(cx), uintptr(botY))
		gpDeletePen.Call(activePen)
	}

	// Expanding radar ripple + animated packet pulses along blueprint vectors
	rippleT := math.Mod(phase*1.4, 1.0)
	rippleD := 26 + int(math.Round(rippleT*44))
	c.ringAlpha(cx-rippleD/2, midY-rippleD/2, rippleD, uiBlueBorder, uint8(math.Round((1.0-rippleT)*155)), 1.3)

	segments := [][4]int{
		{cx, topY, cx, midY},
		{cx, midY, leftX, botY},
		{cx, midY, cx, botY},
		{cx, midY, rightX, botY},
		{leftX, botY, rightX, botY},
	}
	for idx, seg := range segments {
		t := math.Mod(phase*2.0+float64(idx)*0.21, 1.0)
		px := int(math.Round(float64(seg[0]) + float64(seg[2]-seg[0])*t))
		py := int(math.Round(float64(seg[1]) + float64(seg[3]-seg[1])*t))
		c.circleAlpha(px-5, py-5, 10, uiBlueBorder, 100)
		c.circleAlpha(px-2, py-2, 4, uiFocus, 240)
	}

	c.circleAlpha(cx-24, midY-24, 48, uiBlueBorder, 36)
	c.ring(cx-18, midY-18, 36, uiBlueBorder, 1.6)
	c.circle(cx-8, midY-8, 16, uiBlue)
	c.circle(cx-3, midY-3, 6, uiOnAccent)

	c.circle(cx-11, topY-11, 22, uiBlueSoft)
	c.ring(cx-11, topY-11, 22, uiBlueBorder, 1.5)
	c.circle(cx-4, topY-4, 8, uiBlueHover)

	for _, px := range []int{leftX, cx, rightX} {
		c.circle(px-10, botY-10, 20, uiWhite)
		c.ring(px-10, botY-10, 20, uiSuccess, 1.8)
		c.circle(px-4, botY-4, 8, uiSuccess)
	}
}

func (c *smoothCanvas) brandEmblem(r win.RECT) {
	d := int(r.Right - r.Left)
	if h := int(r.Bottom - r.Top); h < d {
		d = h
	}
	if d <= 4 {
		return
	}
	x := int(r.Left) + (int(r.Right-r.Left)-d)/2
	y := int(r.Top) + (int(r.Bottom-r.Top)-d)/2
	badge := win.RECT{Left: int32(x + 1), Top: int32(y + 1), Right: int32(x + d - 1), Bottom: int32(y + d - 1)}
	radius := int(math.Round(float64(d) * 0.24))
	border := mixColor(uiBlueDeep, uiBlueBorder, 0.45)
	topGrad, botGrad := uiBlueHover, uiBlueDeep
	if activePalette == darkPalette {
		topGrad = uiBlueSelected
	}
	c.roundedGradient(badge, radius, topGrad, botGrad, &border, 1.0)

	cx := x + d/2
	cy := y + d/2
	span := float64(d) * 0.50
	leftX := cx - int(math.Round(span*0.44))
	rightX := cx + int(math.Round(span*0.44))
	topY := cy - int(math.Round(span*0.36))
	botY := cy + int(math.Round(span*0.42))

	orbitD := int(math.Round(float64(d) * 0.36))
	c.ringAlpha(cx-orbitD/2, topY-orbitD/2, orbitD, uiBlueBorder, 90, 1.1)

	barStroke := float32(math.Max(2.2, float64(d)*0.092))
	if pen := c.pen(uiOnAccent, barStroke); pen != 0 {
		c.call(gpDrawLine, c.graphics, pen, uintptr(leftX), uintptr(topY), uintptr(rightX), uintptr(topY))
		c.call(gpDrawLine, c.graphics, pen, uintptr(cx), uintptr(topY), uintptr(cx), uintptr(botY))
		gpDeletePen.Call(pen)
	}

	hubD := int(math.Round(float64(d) * 0.16))
	if hubD < 4 {
		hubD = 4
	}
	c.circle(cx-hubD/2, topY-hubD/2, hubD, uiOnAccent)

	nodeD := int(math.Round(float64(d) * 0.19))
	if nodeD < 5 {
		nodeD = 5
	}
	holeD := int(math.Round(float64(d) * 0.085))
	if holeD < 2 {
		holeD = 2
	}
	for _, pt := range [][2]int{{leftX, topY}, {rightX, topY}, {cx, botY}} {
		c.circle(pt[0]-nodeD/2, pt[1]-nodeD/2, nodeD, uiOnAccent)
		c.circle(pt[0]-holeD/2, pt[1]-holeD/2, holeD, uiBlueDeep)
	}
}
func (c *smoothCanvas) navIcon(r win.RECT, kind string, color walk.Color) {
	d := int(r.Right - r.Left)
	if h := int(r.Bottom - r.Top); h < d {
		d = h
	}
	iconSize := int(math.Round(float64(d) * 0.48))
	x := int(r.Left) + (int(r.Right-r.Left)-iconSize)/2
	y := int(r.Top) + (int(r.Bottom-r.Top)-iconSize)/2
	cx, cy := x+iconSize/2, y+iconSize/2
	switch kind {
	case "power":
		pen := c.pen(color, float32(math.Max(1.8, float64(iconSize)*0.095)))
		if pen != 0 {
			defer gpDeletePen.Call(pen)
			arc := int(float64(iconSize) * 0.78)
			arcX := cx - arc/2
			arcY := cy - arc/2 + int(float64(iconSize)*0.08)
			c.call(gpDrawArc, c.graphics, pen, uintptr(arcX), uintptr(arcY), uintptr(arc), uintptr(arc), real(-50), real(280))
			c.call(gpDrawLine, c.graphics, pen, uintptr(cx), uintptr(y), uintptr(cx), uintptr(cy+int(float64(iconSize)*0.02)))
		}
	case "network":
		node := int(math.Max(4, float64(iconSize)*0.22))
		leftX, rightX := x+int(float64(iconSize)*0.16), x+int(float64(iconSize)*0.84)-node
		topY, bottomY := y+int(float64(iconSize)*0.12), y+int(float64(iconSize)*0.66)
		pen := c.pen(color, 1.6)
		if pen != 0 {
			defer gpDeletePen.Call(pen)
			c.call(gpDrawLine, c.graphics, pen, uintptr(x+int(float64(iconSize)*0.38)), uintptr(y+int(float64(iconSize)*0.27)), uintptr(cx), uintptr(y+int(float64(iconSize)*0.46)))
			c.call(gpDrawLine, c.graphics, pen, uintptr(x+int(float64(iconSize)*0.72)), uintptr(y+int(float64(iconSize)*0.27)), uintptr(cx), uintptr(y+int(float64(iconSize)*0.46)))
			c.call(gpDrawLine, c.graphics, pen, uintptr(cx), uintptr(y+int(float64(iconSize)*0.55)), uintptr(cx), uintptr(y+int(float64(iconSize)*0.76)))
		}
		c.circle(leftX, topY, node, color)
		c.circle(rightX, topY, node, color)
		c.circle(cx-node/2, bottomY, node, color)
	case "frp":
		pen := c.pen(color, float32(math.Max(1.7, float64(iconSize)*0.085)))
		if pen != 0 {
			defer gpDeletePen.Call(pen)
			left := x + int(float64(iconSize)*0.20)
			right := x + int(float64(iconSize)*0.80)
			top := y + int(float64(iconSize)*0.28)
			bottom := y + int(float64(iconSize)*0.72)
			c.call(gpDrawLine, c.graphics, pen, uintptr(left), uintptr(top), uintptr(left), uintptr(bottom))
			c.call(gpDrawLine, c.graphics, pen, uintptr(right), uintptr(top), uintptr(right), uintptr(bottom))
			c.call(gpDrawLine, c.graphics, pen, uintptr(left), uintptr(cy), uintptr(right), uintptr(cy))
			c.call(gpDrawLine, c.graphics, pen, uintptr(right), uintptr(cy), uintptr(right-int(float64(iconSize)*0.16)), uintptr(cy-int(float64(iconSize)*0.12)))
			c.call(gpDrawLine, c.graphics, pen, uintptr(right), uintptr(cy), uintptr(right-int(float64(iconSize)*0.16)), uintptr(cy+int(float64(iconSize)*0.12)))
		}
	case "diag":
		ringSize := int(math.Round(float64(iconSize) * 0.86))
		rx := cx - ringSize/2
		ry := cy - ringSize/2
		c.ringAlpha(rx, ry, ringSize, color, 115, 1.3)
		pen := c.pen(color, 1.6)
		if pen != 0 {
			defer gpDeletePen.Call(pen)
			left := x + int(float64(iconSize)*0.16)
			p1x := x + int(float64(iconSize)*0.34)
			p2x := x + int(float64(iconSize)*0.48)
			p3x := x + int(float64(iconSize)*0.60)
			p4x := x + int(float64(iconSize)*0.72)
			right := x + int(float64(iconSize)*0.84)
			upY := y + int(float64(iconSize)*0.27)
			downY := y + int(float64(iconSize)*0.73)
			c.call(gpDrawLine, c.graphics, pen, uintptr(left), uintptr(cy), uintptr(p1x), uintptr(cy))
			c.call(gpDrawLine, c.graphics, pen, uintptr(p1x), uintptr(cy), uintptr(p2x), uintptr(upY))
			c.call(gpDrawLine, c.graphics, pen, uintptr(p2x), uintptr(upY), uintptr(p3x), uintptr(downY))
			c.call(gpDrawLine, c.graphics, pen, uintptr(p3x), uintptr(downY), uintptr(p4x), uintptr(cy))
			c.call(gpDrawLine, c.graphics, pen, uintptr(p4x), uintptr(cy), uintptr(right), uintptr(cy))
		}
	case "info":
		ringSize := int(math.Round(float64(iconSize) * 0.82))
		rx := cx - ringSize/2
		ry := cy - ringSize/2
		c.ring(rx, ry, ringSize, color, 1.7)
		dot := int(math.Max(2, float64(iconSize)*0.12))
		c.circle(cx-dot/2, y+int(float64(iconSize)*0.24)-dot/2, dot, color)
		pen := c.pen(color, 1.8)
		if pen != 0 {
			defer gpDeletePen.Call(pen)
			c.call(gpDrawLine, c.graphics, pen, uintptr(cx), uintptr(y+int(float64(iconSize)*0.38)), uintptr(cx), uintptr(y+int(float64(iconSize)*0.74)))
		}
	case "admin":
		pen := c.pen(color, float32(math.Max(1.6, float64(iconSize)*0.085)))
		if pen != 0 {
			defer gpDeletePen.Call(pen)
			left := x + int(float64(iconSize)*0.22)
			right := x + int(float64(iconSize)*0.78)
			top := y + int(float64(iconSize)*0.18)
			mid := y + int(float64(iconSize)*0.50)
			bottom := y + int(float64(iconSize)*0.80)
			c.call(gpDrawLine, c.graphics, pen, uintptr(left), uintptr(top), uintptr(right), uintptr(top))
			c.call(gpDrawLine, c.graphics, pen, uintptr(left), uintptr(top), uintptr(left), uintptr(mid))
			c.call(gpDrawLine, c.graphics, pen, uintptr(right), uintptr(top), uintptr(right), uintptr(mid))
			c.call(gpDrawLine, c.graphics, pen, uintptr(left), uintptr(mid), uintptr(cx), uintptr(bottom))
			c.call(gpDrawLine, c.graphics, pen, uintptr(right), uintptr(mid), uintptr(cx), uintptr(bottom))
			ring := int(float64(iconSize) * 0.16)
			c.ring(cx-ring/2, cy-ring/2, ring, color, 1.5)
		}
	case "settings":
		outerR := float64(iconSize) * 0.44
		innerR := float64(iconSize) * 0.25
		bodyD := int(math.Round(outerR * 1.45))
		c.ring(cx-bodyD/2, cy-bodyD/2, bodyD, color, float32(math.Max(1.6, float64(iconSize)*0.11)))
		coreD := int(math.Round(innerR * 1.25))
		if coreD < 3 {
			coreD = 3
		}
		c.circle(cx-coreD/2, cy-coreD/2, coreD, color)
		pen := c.pen(color, float32(math.Max(1.6, float64(iconSize)*0.11)))
		if pen != 0 {
			defer gpDeletePen.Call(pen)
			rStart := outerR * 0.68
			rEnd := outerR * 0.98
			for i := 0; i < 8; i++ {
				ang := float64(i) * math.Pi / 4.0
				x1 := cx + int(math.Round(math.Cos(ang)*rStart))
				y1 := cy + int(math.Round(math.Sin(ang)*rStart))
				x2 := cx + int(math.Round(math.Cos(ang)*rEnd))
				y2 := cy + int(math.Round(math.Sin(ang)*rEnd))
				c.call(gpDrawLine, c.graphics, pen, uintptr(x1), uintptr(y1), uintptr(x2), uintptr(y2))
			}
		}
	default:
		dot := int(math.Max(3, float64(iconSize)*0.18))
		gap := int(float64(iconSize) * 0.24)
		c.circle(cx-gap-dot/2, cy-dot/2, dot, color)
		c.circle(cx-dot/2, cy-dot/2, dot, color)
		c.circle(cx+gap-dot/2, cy-dot/2, dot, color)
	}
}
func (c *smoothCanvas) eyeIcon(r win.RECT, open bool, color walk.Color) {
	cx := int(r.Left+r.Right) / 2
	cy := int(r.Top+r.Bottom) / 2
	w, h := 16, 14
	pen := c.pen(color, 1.7)
	if pen == 0 {
		return
	}
	defer gpDeletePen.Call(pen)
	gpStartCap.Call(pen, 2)
	gpEndCap.Call(pen, 2)

	// Clean round eye outline with zero outer box/border.
	c.call(gpDrawEllipse, c.graphics, pen, uintptr(cx-w/2), uintptr(cy-h/2), uintptr(w), uintptr(h))
	if open {
		c.circle(cx-3, cy-3, 6, color)
		return
	}
	c.call(gpDrawLine, c.graphics, pen, uintptr(cx-6), uintptr(cy+6), uintptr(cx+6), uintptr(cy-6))
}
func fillNative(dc win.HDC, r win.RECT, color walk.Color) {
	brush := win.CreateBrushIndirect(&win.LOGBRUSH{LbStyle: win.BS_SOLID, LbColor: win.COLORREF(color)})
	if brush != 0 {
		saved := win.SaveDC(dc)
		win.SelectObject(dc, win.HGDIOBJ(brush))
		win.SelectObject(dc, win.GetStockObject(win.NULL_PEN))
		win.Rectangle_(dc, r.Left, r.Top, r.Right+1, r.Bottom+1)
		win.RestoreDC(dc, saved)
		win.DeleteObject(win.HGDIOBJ(brush))
	}
}

func drawBufferedDC(hdc win.HDC, r win.RECT, bg walk.Color, draw func(win.HDC, *smoothCanvas, win.RECT)) error {
	w := r.Right - r.Left
	h := r.Bottom - r.Top
	if w <= 0 || h <= 0 {
		return nil
	}
	if memDC := win.CreateCompatibleDC(hdc); memDC != 0 {
		bmi := win.BITMAPINFOHEADER{
			BiSize:        uint32(unsafe.Sizeof(win.BITMAPINFOHEADER{})),
			BiWidth:       w,
			BiHeight:      -h,
			BiPlanes:      1,
			BiBitCount:    32,
			BiCompression: win.BI_RGB,
		}
		var bits unsafe.Pointer
		if bmp := win.CreateDIBSection(hdc, &bmi, win.DIB_RGB_COLORS, &bits, 0, 0); bmp != 0 && bits != nil {
			oldBmp := win.SelectObject(memDC, win.HGDIOBJ(bmp))
			localRect := win.RECT{Left: 0, Top: 0, Right: w, Bottom: h}
			fillNative(memDC, localRect, bg)
			c := newSmoothCanvas(memDC)
			draw(memDC, c, localRect)
			c.dispose()
			win.GdiFlush()
			pixels := unsafe.Slice((*uint32)(bits), int(w)*int(h))
			for i := range pixels {
				pixels[i] |= 0xFF000000
			}
			win.BitBlt(hdc, r.Left, r.Top, w, h, memDC, 0, 0, win.SRCCOPY)
			win.SelectObject(memDC, oldBmp)
			win.DeleteObject(win.HGDIOBJ(bmp))
			win.DeleteDC(memDC)
			return c.err
		} else if bmp != 0 {
			win.DeleteObject(win.HGDIOBJ(bmp))
		}
		win.DeleteDC(memDC)
	}
	fillNative(hdc, r, bg)
	c := newSmoothCanvas(hdc)
	draw(hdc, c, r)
	c.dispose()
	return c.err
}

func drawBufferedSmooth(hdc win.HDC, r win.RECT, bg walk.Color, draw func(*smoothCanvas, win.RECT)) error {
	return drawBufferedDC(hdc, r, bg, func(_ win.HDC, c *smoothCanvas, local win.RECT) {
		draw(c, local)
	})
}
func nativeBackground(w walk.Widget) walk.Color {
	for p := w.Parent(); p != nil; {
		if b, ok := p.Background().(*walk.SystemColorBrush); ok {
			return b.Color()
		}
		if b, ok := p.Background().(*walk.SolidColorBrush); ok {
			return b.Color()
		}
		parent, ok := p.(walk.Widget)
		if !ok {
			break
		}
		p = parent.Parent()
	}
	return uiBackground
}
