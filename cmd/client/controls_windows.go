//go:build windows

package main

import (
	"math"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
	"github.com/lxn/win"
)

// Painting wraps actual native controls; text editing, keyboard focus and
// accessibility remain supplied by Windows.
type actionView struct {
	PushButton
	primary bool
	power   func() int
}
type paintedButton struct {
	*walk.PushButton
	primary bool
	power   func() int
}

type navButtonView struct {
	PushButton
	icon     string
	selected func() bool
}
type paintedNavButton struct {
	*walk.PushButton
	icon               string
	selected           func() bool
	selectionProgress  float64
	selectionTarget    float64
	selectionKnown     bool
	selectionAnimating bool
}
type themeLabelView struct {
	Label
	color func() walk.Color
}

type themedLabel struct {
	*walk.Label
	color func() walk.Color
}

type eyeButtonView struct {
	PushButton
	open func() bool
}
type paintedEyeButton struct {
	*walk.PushButton
	open func() bool
}

type glowInputPanel struct {
	*walk.Composite
	focusTarget    float64
	focusProgress  float64
	focusAnimating bool
}

func actionButton(assign **walk.PushButton, text string, primary bool, width int, clicked func()) actionView {
	maximum := Size{Height: 40}
	if width > 0 {
		maximum.Width = width
	}
	return actionView{PushButton: PushButton{AssignTo: assign, Text: text, MinSize: Size{Width: width, Height: 40}, MaxSize: maximum, OnClicked: clicked}, primary: primary}
}
func highContrastEnabled() bool {
	var hc win.HIGHCONTRAST
	hc.CbSize = uint32(unsafe.Sizeof(hc))
	if !win.SystemParametersInfo(win.SPI_GETHIGHCONTRAST, hc.CbSize, unsafe.Pointer(&hc), 0) {
		return false
	}
	return hc.DwFlags&win.HCF_HIGHCONTRASTON != 0
}

func navSystemColor(index int) walk.Color {
	return walk.Color(win.GetSysColor(index))
}

func navButtonBorderColor(highlighted bool) walk.Color {
	if highContrastEnabled() {
		if highlighted {
			return navSystemColor(win.COLOR_HIGHLIGHTTEXT)
		}
		return navSystemColor(win.COLOR_WINDOWTEXT)
	}
	return uiBlue
}

func navDisabledTextColor() walk.Color {
	if highContrastEnabled() {
		return navSystemColor(win.COLOR_GRAYTEXT)
	}
	return walk.RGB(168, 178, 194)
}

func navSecondaryTextColor() walk.Color {
	if highContrastEnabled() {
		return navSystemColor(win.COLOR_WINDOWTEXT)
	}
	return uiMuted
}

func navButton(assign **walk.PushButton, icon, accessibleName string, selected func() bool, clicked func()) navButtonView {
	accessibility := Accessibility{Name: accessibleName, Description: "切换到" + accessibleName, Role: AccRolePagetab}
	switch accessibleName {
	case "更多操作":
		accessibility.Description = "打开更多操作菜单"
		accessibility.Role = AccRoleButtonMenu
	case "版本信息":
		accessibility.Description = "打开版本信息对话框"
		accessibility.Role = AccRolePushbutton
	}
	return navButtonView{
		PushButton: PushButton{AssignTo: assign, Text: accessibleName, MinSize: Size{Width: 44, Height: 44}, MaxSize: Size{Width: 44, Height: 44}, ToolTipText: accessibleName, OnClicked: clicked, Accessibility: accessibility},
		icon:       icon,
		selected:   selected,
	}
}

func eyeButton(assign **walk.PushButton, accessibleName string, open func() bool, clicked func()) eyeButtonView {
	return eyeButtonView{
		PushButton: PushButton{AssignTo: assign, Text: accessibleName, MinSize: Size{Width: 28, Height: 28}, MaxSize: Size{Width: 28, Height: 28}, ToolTipText: accessibleName, OnClicked: clicked, Accessibility: Accessibility{Name: accessibleName}},
		open:       open,
	}
}
func (v actionView) Create(builder *Builder) error {
	var b *walk.PushButton
	original := v.AssignTo
	v.AssignTo = &b
	if err := v.PushButton.Create(builder); err != nil {
		return err
	}
	if original != nil {
		*original = b
	}
	b.GraphicsEffects().Clear()
	return walk.InitWrapperWindow(&paintedButton{PushButton: b, primary: v.primary, power: v.power})
}
func (b *paintedButton) WndProc(hwnd win.HWND, msg uint32, w, l uintptr) uintptr {
	if msg == win.WM_NOTIFY && l != 0 {
		d := *(**win.NMCUSTOMDRAW)(unsafe.Pointer(&l))
		if d.Hdr.Code == win.NM_CUSTOMDRAW && d.DwDrawStage == win.CDDS_PREPAINT {
			bg, fg := uiWhite, uiBlue
			if b.primary {
				bg, fg = uiBlue, uiWhite
			}
			hover := d.UItemState&win.CDIS_HOT != 0 && b.Enabled()
			if hover {
				bg = uiBlueSoft
				if b.primary {
					bg = uiBlueHover
				}
			}
			if d.UItemState&win.CDIS_SELECTED != 0 {
				bg = uiBlueSelected
				if b.primary {
					bg = uiBlueDeep
				}
			}
			if !b.Enabled() {
				fg = uiMuted
				if b.primary {
					bg = walk.RGB(181, 202, 245)
				} else {
					bg = walk.RGB(247, 249, 252)
				}
			}
			fillNative(d.Hdc, d.Rc, nativeBackground(b))
			canvas := newSmoothCanvas(d.Hdc)
			r := d.Rc
			r.Left += 1
			r.Top += 1
			r.Right -= 1
			r.Bottom -= 1
			if b.power != nil {
				canvas.power(r, b.power(), hover)
			} else {
				var border *walk.Color
				if !b.primary && b.Enabled() {
					color := uiBorderStrong
					border = &color
				}
				canvas.rounded(r, walk.IntFrom96DPI(10, b.DPI()), bg, border)
			}
			if b.Focused() {
				border := walk.RGB(137, 180, 250)
				if b.power == nil {
					focus := r
					focus.Left += 3
					focus.Top += 3
					focus.Right -= 3
					focus.Bottom -= 3
					canvas.rounded(focus, walk.IntFrom96DPI(11, b.DPI()), bg, &border)
				} else {
					d := r.Right - r.Left
					if r.Bottom-r.Top < d {
						d = r.Bottom - r.Top
					}
					inset := int32(walk.IntFrom96DPI(3, b.DPI()))
					canvas.ring(int(r.Left+(r.Right-r.Left-d)/2+inset), int(r.Top+(r.Bottom-r.Top-d)/2+inset), int(d-2*inset), border, 1)
				}
			}
			canvas.dispose()
			if b.power == nil {
				saved := win.SaveDC(d.Hdc)
				win.SelectObject(d.Hdc, win.HGDIOBJ(b.SendMessage(win.WM_GETFONT, 0, 0)))
				win.SetBkMode(d.Hdc, win.TRANSPARENT)
				win.SetTextColor(d.Hdc, win.COLORREF(fg))
				win.DrawTextEx(d.Hdc, syscall.StringToUTF16Ptr(b.Text()), -1, &r, win.DT_CENTER|win.DT_VCENTER|win.DT_SINGLELINE|win.DT_NOPREFIX, nil)
				win.RestoreDC(d.Hdc, saved)
			}
			return win.CDRF_SKIPDEFAULT
		}
	}
	return b.PushButton.WndProc(hwnd, msg, w, l)
}

func (v navButtonView) Create(builder *Builder) error {
	var b *walk.PushButton
	original := v.AssignTo
	v.AssignTo = &b
	if err := v.PushButton.Create(builder); err != nil {
		return err
	}
	if original != nil {
		*original = b
	}
	b.GraphicsEffects().Clear()
	return walk.InitWrapperWindow(&paintedNavButton{PushButton: b, icon: v.icon, selected: v.selected})
}
func (v themeLabelView) Create(builder *Builder) error {
	var label *walk.Label
	original := v.Label.AssignTo
	v.Label.AssignTo = &label
	if err := v.Label.Create(builder); err != nil {
		return err
	}
	if original != nil {
		*original = label
	}
	if v.color != nil {
		label.SetTextColor(v.color())
	}
	return walk.InitWrapperWindow(&themedLabel{Label: label, color: v.color})
}

func (l *themedLabel) WndProc(hwnd win.HWND, msg uint32, w, lParam uintptr) uintptr {
	if msg == win.WM_SYSCOLORCHANGE || msg == win.WM_THEMECHANGED {
		if l.color != nil {
			l.SetTextColor(l.color())
		}
	}
	return l.Label.WndProc(hwnd, msg, w, lParam)
}

func (b *paintedNavButton) WndProc(hwnd win.HWND, msg uint32, w, l uintptr) uintptr {
	if msg == win.WM_NOTIFY && l != 0 {
		d := *(**win.NMCUSTOMDRAW)(unsafe.Pointer(&l))
		if d.Hdr.Code == win.NM_CUSTOMDRAW && d.DwDrawStage == win.CDDS_PREPAINT {
			b.animateSelection()
			selected := b.selected != nil && b.selected()
			hot := d.UItemState&win.CDIS_HOT != 0 && b.Enabled()
			pressed := d.UItemState&win.CDIS_SELECTED != 0 && b.Enabled()
			highlighted := selected || hot || pressed
			highContrast := highContrastEnabled()
			selectionFill := uiBlueHalo
			bg, fg := uiSidebar, uiMuted
			if highContrast {
				bg = navSystemColor(win.COLOR_WINDOW)
				fg = navSystemColor(win.COLOR_WINDOWTEXT)
				selectionFill = bg
				if highlighted {
					bg = navSystemColor(win.COLOR_HIGHLIGHT)
					fg = navSystemColor(win.COLOR_HIGHLIGHTTEXT)
					selectionFill = bg
				}
			} else {
				switch {
				case selected && pressed:
					selectionFill = uiBlueDeep
					bg, fg = selectionFill, uiWhite
				case selected && hot:
					selectionFill = uiBlueBorder
					bg, fg = selectionFill, uiBlueDeep
				case selected:
					bg, fg = selectionFill, uiBlueDeep
				case pressed:
					selectionFill = uiBlueBorder
					bg, fg = selectionFill, uiBlueDeep
				case hot:
					bg, fg = uiBlueSoft, uiBlue
				}
			}
			if !b.Enabled() {
				fg = navDisabledTextColor()
				if highContrast {
					bg = navSystemColor(win.COLOR_BTNFACE)
				}
			}
			parentBackground := nativeBackground(b)
			if highContrast {
				parentBackground = navSystemColor(win.COLOR_WINDOW)
			}
			fillNative(d.Hdc, d.Rc, parentBackground)
			canvas := newSmoothCanvas(d.Hdc)
			r := d.Rc
			r.Left += 3
			r.Top += 3
			r.Right -= 3
			r.Bottom -= 3
			radius := walk.IntFrom96DPI(12, b.DPI())
			canvas.rounded(r, radius, bg, nil)
			if b.selectionProgress > 0.01 {
				fill := r
				fill.Right = fill.Left + int32(float64(r.Right-r.Left)*b.selectionProgress)
				canvas.rounded(fill, radius, selectionFill, nil)
			}
			if b.Focused() {
				border := navButtonBorderColor(highlighted)
				stroke := float32(walk.IntFrom96DPI(1, b.DPI()))
				inset := int32(walk.IntFrom96DPI(1, b.DPI()))
				canvas.roundedStroke(r, radius, bg, 0, &border, stroke)
				inner := r
				inner.Left += inset
				inner.Top += inset
				inner.Right -= inset
				inner.Bottom -= inset
				canvas.roundedStroke(inner, radius-int(inset), bg, 0, &border, stroke)
			}
			canvas.navIcon(r, b.icon, fg)
			canvas.dispose()
			return win.CDRF_SKIPDEFAULT
		}
	}
	return b.PushButton.WndProc(hwnd, msg, w, l)
}

func (b *paintedNavButton) animateSelection() {
	target := 0.0
	if b.selected != nil && b.selected() {
		target = 1
	}
	if !b.selectionKnown {
		b.selectionKnown = true
		b.selectionTarget = target
		if b.selectionAnimating {
			return
		}
		b.selectionAnimating = true
		b.advanceSelection()
		return
	}
	if target == b.selectionTarget {
		return
	}
	b.selectionTarget = target
	if !b.selectionAnimating {
		b.selectionAnimating = true
		b.advanceSelection()
	}
}

func (b *paintedNavButton) advanceSelection() {
	if b.IsDisposed() {
		b.selectionAnimating = false
		return
	}
	diff := b.selectionTarget - b.selectionProgress
	if math.Abs(diff) < 0.025 {
		b.selectionProgress = b.selectionTarget
		b.selectionAnimating = false
	} else {
		b.selectionProgress += diff * 0.32
	}
	_ = b.Invalidate()
	if b.selectionAnimating {
		time.AfterFunc(16*time.Millisecond, func() {
			if !b.IsDisposed() {
				b.Synchronize(b.advanceSelection)
			}
		})
	}
}

func (v eyeButtonView) Create(builder *Builder) error {
	var button *walk.PushButton
	original := v.AssignTo
	v.AssignTo = &button
	if err := v.PushButton.Create(builder); err != nil {
		return err
	}
	if original != nil {
		*original = button
	}
	button.GraphicsEffects().Clear()
	return walk.InitWrapperWindow(&paintedEyeButton{PushButton: button, open: v.open})
}
func (b *paintedEyeButton) WndProc(hwnd win.HWND, msg uint32, w, l uintptr) uintptr {
	if msg == win.WM_NOTIFY && l != 0 {
		d := *(**win.NMCUSTOMDRAW)(unsafe.Pointer(&l))
		if d.Hdr.Code == win.NM_CUSTOMDRAW && d.DwDrawStage == win.CDDS_PREPAINT {
			fillNative(d.Hdc, d.Rc, nativeBackground(b))
			r := d.Rc
			r.Left += 2
			r.Top += 2
			r.Right -= 2
			r.Bottom -= 2
			isOpen := b.open != nil && b.open()
			canvas := newSmoothCanvas(d.Hdc)
			if d.UItemState&win.CDIS_HOT != 0 || b.Focused() || isOpen {
				canvas.rounded(r, walk.IntFrom96DPI(8, b.DPI()), uiBlueSoft, nil)
			}
			color := uiMuted
			if d.UItemState&win.CDIS_HOT != 0 || b.Focused() || isOpen {
				color = uiBlue
			}
			canvas.eyeIcon(r, isOpen, color)
			canvas.dispose()
			return win.CDRF_SKIPDEFAULT
		}
	}
	return b.PushButton.WndProc(hwnd, msg, w, l)
}

type roundView struct {
	Composite
	fill    walk.Color
	radius  int
	border  *walk.Color
	focused func() bool
}
type roundPanel struct {
	*walk.Composite
	fill    walk.Color
	radius  int
	border  *walk.Color
	focused func() bool
}

func (v roundView) Create(builder *Builder) error {
	var panel *walk.Composite
	original := v.AssignTo
	v.AssignTo = &panel
	if err := v.Composite.Create(builder); err != nil {
		return err
	}
	if original != nil {
		*original = panel
	}
	return walk.InitWrapperWindow(&roundPanel{Composite: panel, fill: v.fill, radius: v.radius, border: v.border, focused: v.focused})
}
func (p *roundPanel) WndProc(hwnd win.HWND, msg uint32, w, l uintptr) uintptr {
	if msg == win.WM_ERASEBKGND {
		var r win.RECT
		win.GetClientRect(p.Handle(), &r)
		dc := win.HDC(w)
		fillNative(dc, r, nativeBackground(p))
		r.Left++
		r.Top++
		r.Right--
		r.Bottom--
		border := p.border
		if p.focused != nil && p.focused() {
			color := walk.RGB(116, 166, 251)
			border = &color
		}
		c := newSmoothCanvas(dc)
		c.rounded(r, walk.IntFrom96DPI(p.radius, p.DPI()), p.fill, border)
		c.dispose()
		return 1
	}
	return p.Composite.WndProc(hwnd, msg, w, l)
}

type tokenInputView struct {
	assign **walk.LineEdit
	value  *string
	submit func()
}

func (v tokenInputView) Create(builder *Builder) error {
	controller := &secretTokenInput{value: v.value}
	var eye *walk.PushButton
	var panel *walk.Composite
	view := Composite{AssignTo: &panel, MinSize: Size{Height: 54}, MaxSize: Size{Height: 54}, Background: SolidColorBrush{Color: uiWhite}, OnMouseDown: func(_, _ int, button walk.MouseButton) {
		if button == walk.LeftButton && *v.assign != nil {
			(*v.assign).SetFocus()
		}
	}, Layout: HBox{MarginsZero: true}, Children: []Widget{
		LineEdit{AssignTo: v.assign, PasswordMode: false, MaxLength: 256, StretchFactor: 1, MinSize: Size{Height: 22}, MaxSize: Size{Height: 22}, CueBanner: "输入入网令牌", Font: Font{Family: "Microsoft YaHei UI", PointSize: 11}, TextColor: uiInk, Background: SolidColorBrush{Color: uiWhite}, Accessibility: Accessibility{Name: "入网令牌"}, OnKeyDown: func(k walk.Key) {
			if k == walk.KeyReturn {
				v.submit()
			} else if k == walk.KeyBack || k == walk.KeyDelete {
				controller.prepareDeletion(k)
			}
		}},
		eyeButton(&eye, "显示入网令牌", func() bool { return controller.showing }, controller.toggleVisibility),
	}}
	if err := view.Create(builder); err != nil {
		return err
	}
	wrapper := &glowInputPanel{Composite: panel}
	if err := walk.InitWrapperWindow(wrapper); err != nil {
		return err
	}
	edit := *v.assign
	controller.edit = edit
	controller.eye = eye
	positioning := false
	positionChildren := func() {
		if positioning || panel.IsDisposed() || edit.IsDisposed() || eye.IsDisposed() {
			return
		}
		width := panel.WidthPixels()
		if width <= 0 {
			return
		}
		positioning = true
		defer func() { positioning = false }()
		const eyeSize = 28
		const rightInset = 8
		const gap = 6
		_ = edit.SetBoundsPixels(walk.Rectangle{X: 18, Y: 20, Width: width - 18 - rightInset - eyeSize - gap, Height: 20})
		_ = eye.SetBoundsPixels(walk.Rectangle{X: width - rightInset - eyeSize, Y: 13, Width: eyeSize, Height: eyeSize})
	}
	panel.SizeChanged().Attach(positionChildren)
	edit.SizeChanged().Attach(positionChildren)
	eye.SizeChanged().Attach(positionChildren)
	positionChildren()
	time.AfterFunc(20*time.Millisecond, func() {
		if !panel.IsDisposed() {
			panel.Synchronize(positionChildren)
		}
	})
	style := win.GetWindowLong(edit.Handle(), win.GWL_STYLE)
	win.SetWindowLong(edit.Handle(), win.GWL_STYLE, style&^win.WS_BORDER)
	ex := win.GetWindowLong(edit.Handle(), win.GWL_EXSTYLE)
	win.SetWindowLong(edit.Handle(), win.GWL_EXSTYLE, ex&^win.WS_EX_CLIENTEDGE)
	win.SetWindowPos(edit.Handle(), 0, 0, 0, 0, 0, win.SWP_FRAMECHANGED|win.SWP_NOMOVE|win.SWP_NOSIZE|win.SWP_NOZORDER|win.SWP_NOACTIVATE)
	edit.GraphicsEffects().Clear()
	edit.TextChanged().Attach(controller.handleTextChanged)
	edit.FocusedChanged().Attach(func() {
		wrapper.focusTarget = 0
		if edit.Focused() {
			wrapper.focusTarget = 1
		}
		if !wrapper.focusAnimating {
			wrapper.focusAnimating = true
			wrapper.advanceGlow()
		}
	})
	return nil
}

type secretTokenInput struct {
	edit          *walk.LineEdit
	eye           *walk.PushButton
	value         *string
	actual        []rune
	displayed     []rune
	showing       bool
	suppress      bool
	revealRune    rune
	revealSeq     uint64
	revealUntil   time.Time
	deleteStart   int
	deleteEnd     int
	pendingDelete bool
}

func (c *secretTokenInput) handleTextChanged() {
	if c.suppress || c.edit == nil {
		return
	}
	if c.pendingDelete {
		start, end := c.deleteStart, c.deleteEnd
		c.pendingDelete = false
		if start < 0 {
			start = 0
		}
		if start > len(c.actual) {
			start = len(c.actual)
		}
		if end < start {
			end = start
		}
		if end > len(c.actual) {
			end = len(c.actual)
		}
		c.actual = append(c.actual[:start], c.actual[end:]...)
		c.revealRune = 0
		c.revealSeq++
		c.renderAt(start)
		return
	}
	next, inserted, caret := updateMaskedValue(c.actual, c.displayed, []rune(c.edit.Text()))
	c.actual = next
	if len(inserted) > 0 && !c.showing {
		c.revealRune = inserted[len(inserted)-1]
		c.revealUntil = time.Now().Add(time.Second)
		c.revealSeq++
		seq := c.revealSeq
		time.AfterFunc(time.Second+20*time.Millisecond, func() {
			if c.edit == nil || c.edit.IsDisposed() {
				return
			}
			c.edit.Synchronize(func() {
				if seq != c.revealSeq || c.showing {
					return
				}
				c.revealRune = 0
				start, _ := c.edit.TextSelection()
				c.renderAt(start)
			})
		})
	} else {
		c.revealRune = 0
		c.revealSeq++
	}
	c.renderAt(caret)
}

func (c *secretTokenInput) prepareDeletion(key walk.Key) {
	if c.edit == nil {
		return
	}
	start, end := c.edit.TextSelection()
	if start == end {
		if key == walk.KeyBack {
			if start <= 0 {
				return
			}
			end = start
			start--
		} else {
			if start >= len(c.actual) {
				return
			}
			end = start + 1
		}
	}
	c.deleteStart = start
	c.deleteEnd = end
	c.pendingDelete = true
}

func (c *secretTokenInput) toggleVisibility() {
	c.showing = !c.showing
	c.revealRune = 0
	c.revealSeq++
	c.renderAt(len(c.actual))
	if c.edit != nil {
		c.edit.SetFocus()
		c.edit.SetTextSelection(len(c.actual), len(c.actual))
	}
}

func (c *secretTokenInput) renderAt(caret int) {
	if c.edit == nil {
		return
	}
	display := append([]rune(nil), c.actual...)
	if !c.showing && len(c.actual) > 0 {
		display = []rune(strings.Repeat("●", len(c.actual)))
		if c.revealRune != 0 && time.Now().Before(c.revealUntil) {
			display[len(display)-1] = c.revealRune
		}
	}
	if caret < 0 {
		caret = 0
	}
	if caret > len(display) {
		caret = len(display)
	}
	c.suppress = true
	_ = c.edit.SetText(string(display))
	c.edit.SetTextSelection(caret, caret)
	c.displayed = append(c.displayed[:0], display...)
	c.suppress = false
	if c.value != nil {
		*c.value = string(c.actual)
	}
	if c.eye != nil {
		if c.showing {
			c.eye.SetText("隐藏入网令牌")
		} else {
			c.eye.SetText("显示入网令牌")
		}
		_ = c.eye.Invalidate()
	}
}

func (p *glowInputPanel) WndProc(hwnd win.HWND, msg uint32, w, l uintptr) uintptr {
	if msg == win.WM_ERASEBKGND {
		var r win.RECT
		win.GetClientRect(p.Handle(), &r)
		dc := win.HDC(w)
		fillNative(dc, r, nativeBackground(p))
		canvas := newSmoothCanvas(dc)
		glow := p.focusProgress
		const pad = int32(5)
		base := r
		base.Left += pad
		base.Top += pad
		base.Right -= pad
		base.Bottom -= pad
		if glow > 0.01 {
			layerAlpha := uint8(math.Round(9 * glow))
			for i := int32(4); i >= 1; i-- {
				layer := r
				inset := pad - i
				layer.Left += inset
				layer.Top += inset
				layer.Right -= inset
				layer.Bottom -= inset
				canvas.roundedAlpha(layer, walk.IntFrom96DPI(10+int(i), p.DPI()), uiBlue, layerAlpha, nil)
			}
		}
		border := mixColor(uiBorder, uiBlueBorder, glow)
		canvas.rounded(base, walk.IntFrom96DPI(10, p.DPI()), uiWhite, &border)
		canvas.dispose()
		return 1
	}
	return p.Composite.WndProc(hwnd, msg, w, l)
}

func (p *glowInputPanel) advanceGlow() {
	if p.IsDisposed() {
		p.focusAnimating = false
		return
	}
	diff := p.focusTarget - p.focusProgress
	if math.Abs(diff) < 0.025 {
		p.focusProgress = p.focusTarget
		p.focusAnimating = false
	} else {
		p.focusProgress += diff * 0.28
	}
	_ = p.Invalidate()
	if p.focusAnimating {
		time.AfterFunc(16*time.Millisecond, func() {
			if !p.IsDisposed() {
				p.Synchronize(p.advanceGlow)
			}
		})
	}
}

func mixColor(from, to walk.Color, amount float64) walk.Color {
	if amount < 0 {
		amount = 0
	} else if amount > 1 {
		amount = 1
	}
	channel := func(shift uint) uint8 {
		a := float64((uint32(from) >> shift) & 0xff)
		b := float64((uint32(to) >> shift) & 0xff)
		return uint8(math.Round(a + (b-a)*amount))
	}
	return walk.RGB(channel(0), channel(8), channel(16))
}
