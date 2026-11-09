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
	gpStartup        = gdip.NewProc("GdiplusStartup")
	gpShutdown       = gdip.NewProc("GdiplusShutdown")
	gpFromDC         = gdip.NewProc("GdipCreateFromHDC")
	gpDeleteGraphics = gdip.NewProc("GdipDeleteGraphics")
	gpSmoothing      = gdip.NewProc("GdipSetSmoothingMode")
	gpSolid          = gdip.NewProc("GdipCreateSolidFill")
	gpDeleteBrush    = gdip.NewProc("GdipDeleteBrush")
	gpFillEllipse    = gdip.NewProc("GdipFillEllipseI")
	gpPen            = gdip.NewProc("GdipCreatePen1")
	gpDeletePen      = gdip.NewProc("GdipDeletePen")
	gpStartCap       = gdip.NewProc("GdipSetPenStartCap")
	gpEndCap         = gdip.NewProc("GdipSetPenEndCap")
	gpDrawEllipse    = gdip.NewProc("GdipDrawEllipseI")
	gpDrawArc        = gdip.NewProc("GdipDrawArcI")
	gpDrawLine       = gdip.NewProc("GdipDrawLineI")
	gpPath           = gdip.NewProc("GdipCreatePath")
	gpAddArc         = gdip.NewProc("GdipAddPathArcI")
	gpClosePath      = gdip.NewProc("GdipClosePathFigure")
	gpDeletePath     = gdip.NewProc("GdipDeletePath")
	gpFillPath       = gdip.NewProc("GdipFillPath")
	gpDrawPath       = gdip.NewProc("GdipDrawPath")
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
	var pen uintptr
	c.call(gpPen, argb(color), real(width), 2, uintptr(unsafe.Pointer(&pen)))
	if pen != 0 {
		c.call(gpStartCap, pen, 2)
		c.call(gpEndCap, pen, 2)
	}
	return pen
}
func (c *smoothCanvas) circle(x, y, d int, color walk.Color) {
	b := c.brush(color)
	if b == 0 {
		return
	}
	defer gpDeleteBrush.Call(b)
	c.call(gpFillEllipse, c.graphics, b, uintptr(x), uintptr(y), uintptr(d), uintptr(d))
}
func (c *smoothCanvas) ring(x, y, d int, color walk.Color, width float32) {
	p := c.pen(color, width)
	if p == 0 {
		return
	}
	defer gpDeletePen.Call(p)
	c.call(gpDrawEllipse, c.graphics, p, uintptr(x), uintptr(y), uintptr(d), uintptr(d))
}
func (c *smoothCanvas) rounded(r win.RECT, radius int, fill walk.Color, border *walk.Color) {
	c.roundedAlpha(r, radius, fill, 255, border)
}
func (c *smoothCanvas) roundedAlpha(r win.RECT, radius int, fill walk.Color, alpha uint8, border *walk.Color) {
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
		pen := c.pen(*border, 1)
		if pen != 0 {
			defer gpDeletePen.Call(pen)
			c.call(gpDrawPath, c.graphics, pen, path)
		}
	}
}
func (c *smoothCanvas) power(r win.RECT, state int, hover bool) {
	d := int(r.Right - r.Left)
	h := int(r.Bottom - r.Top)
	if h < d {
		d = h
	}
	x := int(r.Left) + (int(r.Right-r.Left)-d)/2
	y := int(r.Top) + (h-d)/2
	scale := float64(d) / 168
	px := func(v float64) int { return int(math.Round(v * scale)) }
	icon := uiMuted
	if state == 1 {
		c.circle(x+px(1), y+px(1), d-px(2), uiBlueHalo)
		c.circle(x+px(8), y+px(8), d-px(16), uiWhite)
		c.ring(x+px(8), y+px(8), d-px(16), uiBlue, float32(4*scale))
		c.ring(x+px(16), y+px(16), d-px(32), uiBlueBorder, float32(1.25*scale))
		icon = uiBlue
	} else {
		face := uiWhite
		if hover {
			face = uiBlueSoft
		}
		c.circle(x+px(7), y+px(9), d-px(14), walk.RGB(232, 238, 248))
		c.circle(x+px(8), y+px(8), d-px(16), face)
		c.ring(x+px(8), y+px(8), d-px(16), uiBorderStrong, float32(2*scale))
		if state == 2 {
			icon = uiBlue
		}
	}
	pen := c.pen(icon, float32(5*scale))
	if pen == 0 {
		return
	}
	defer gpDeletePen.Call(pen)
	c.call(gpDrawArc, c.graphics, pen, uintptr(x+px(56)), uintptr(y+px(58)), uintptr(px(56)), uintptr(px(56)), real(-50), real(280))
	c.call(gpDrawLine, c.graphics, pen, uintptr(x+px(84)), uintptr(y+px(45)), uintptr(x+px(84)), uintptr(y+px(83)))
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
	case "egress":
		pen := c.pen(color, float32(math.Max(1.6, float64(iconSize)*0.09)))
		if pen != 0 {
			defer gpDeletePen.Call(pen)
			mid := cy
			c.call(gpDrawLine, c.graphics, pen, uintptr(x+int(float64(iconSize)*0.12)), uintptr(mid), uintptr(x+int(float64(iconSize)*0.84)), uintptr(mid))
			c.call(gpDrawLine, c.graphics, pen, uintptr(x+int(float64(iconSize)*0.64)), uintptr(mid-int(float64(iconSize)*0.16)), uintptr(x+int(float64(iconSize)*0.84)), uintptr(mid))
			c.call(gpDrawLine, c.graphics, pen, uintptr(x+int(float64(iconSize)*0.64)), uintptr(mid+int(float64(iconSize)*0.16)), uintptr(x+int(float64(iconSize)*0.84)), uintptr(mid))
			c.call(gpDrawLine, c.graphics, pen, uintptr(x+int(float64(iconSize)*0.12)), uintptr(mid-int(float64(iconSize)*0.20)), uintptr(x+int(float64(iconSize)*0.12)), uintptr(mid+int(float64(iconSize)*0.20)))
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
	d := int(r.Right - r.Left)
	if h := int(r.Bottom - r.Top); h < d {
		d = h
	}
	width := int(math.Round(float64(d) * 0.62))
	height := int(math.Round(float64(d) * 0.42))
	if width < 14 {
		width = 14
	}
	if height < 9 {
		height = 9
	}
	x := int(r.Left) + (int(r.Right-r.Left)-width)/2
	y := int(r.Top) + (int(r.Bottom-r.Top)-height)/2
	pen := c.pen(color, 1.6)
	if pen == 0 {
		return
	}
	defer gpDeletePen.Call(pen)
	c.call(gpDrawEllipse, c.graphics, pen, uintptr(x), uintptr(y), uintptr(width), uintptr(height))
	cx, cy := x+width/2, y+height/2
	if open {
		c.circle(cx-2, cy-2, 4, color)
		return
	}
	c.call(gpDrawLine, c.graphics, pen, uintptr(x+3), uintptr(y+height-2), uintptr(x+width-3), uintptr(y+2))
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
func nativeBackground(w walk.Widget) walk.Color {
	for p := w.Parent(); p != nil; {
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
