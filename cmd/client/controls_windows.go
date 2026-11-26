//go:build windows

package main

import (
	"math"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
	"github.com/lxn/win"
	"golang.org/x/sys/windows"
)

type buttonVariant uint8

const (
	btnSecondary buttonVariant = iota
	btnPrimary
	btnDanger
	btnGhost
)

var (
	handCursorOnce   sync.Once
	cachedHandCursor win.HCURSOR
)

func handCursor() win.HCURSOR {
	handCursorOnce.Do(func() {
		cachedHandCursor = win.LoadCursor(0, win.MAKEINTRESOURCE(win.IDC_HAND))
	})
	return cachedHandCursor
}

var (
	user32TrackDLL        = windows.NewLazySystemDLL("user32.dll")
	procTrackMouseEventEx = user32TrackDLL.NewProc("TrackMouseEvent")
)

type winTrackMouseEvent struct {
	CbSize      uint32
	DwFlags     uint32
	HwndTrack   uintptr
	DwHoverTime uint32
}

func requestMouseLeave(hwnd win.HWND) {
	if hwnd == 0 || procTrackMouseEventEx.Find() != nil {
		return
	}
	tme := winTrackMouseEvent{
		CbSize:    uint32(unsafe.Sizeof(winTrackMouseEvent{})),
		DwFlags:   0x00000002, // TME_LEAVE
		HwndTrack: uintptr(hwnd),
	}
	procTrackMouseEventEx.Call(uintptr(unsafe.Pointer(&tme)))
}

type hoverTracker struct {
	hovered bool
	pressed bool
}

func (h *hoverTracker) handleMouseMessage(hwnd win.HWND, enabled bool, msg uint32, w uintptr) (handled bool, res uintptr, changed bool) {
	switch msg {
	case win.WM_SETCURSOR:
		if enabled {
			if cur := handCursor(); cur != 0 {
				win.SetCursor(cur)
				return true, 1, false
			}
		}
	case win.WM_MOUSEMOVE:
		if enabled && !h.hovered {
			h.hovered = true
			requestMouseLeave(hwnd)
			return false, 0, true
		}
	case win.WM_MOUSELEAVE:
		if h.hovered {
			h.hovered = false
			return false, 0, true
		}
	case win.WM_LBUTTONDOWN:
		if enabled && !h.pressed {
			h.pressed = true
			return false, 0, true
		}
	case win.WM_LBUTTONUP, win.WM_CAPTURECHANGED:
		if h.pressed {
			h.pressed = false
			return false, 0, true
		}
	case win.WM_ENABLE:
		if w == 0 && (h.pressed || h.hovered) {
			h.pressed = false
			h.hovered = false
			return false, 0, true
		}
	}
	return false, 0, false
}

// Painting wraps actual native controls; text editing, keyboard focus and
// accessibility remain supplied by Windows.
type actionView struct {
	PushButton
	primary bool
	variant buttonVariant
	radius  int
	power   func() int
}
type paintedButton struct {
	*walk.PushButton
	variant buttonVariant
	radius  int
	power   func() int
	tracker hoverTracker
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
	tracker            hoverTracker
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
	open    func() bool
	tracker hoverTracker
}

type comboBoxView struct {
	ComboBox
}

type paintedComboBox struct {
	*walk.ComboBox
	tracker hoverTracker
}

const (
	cbSetItemHeight   = 0x0153
	cbGetDroppedState = 0x0157
	cbGetComboBoxInfo = 0x0164
	cbSetCurSel       = 0x014E
)

type winComboBoxInfo struct {
	CbSize      uint32
	RcItem      win.RECT
	RcButton    win.RECT
	StateButton uint32
	HwndCombo   win.HWND
	HwndItem    win.HWND
	HwndList    win.HWND
}

var (
	comboBrushMu sync.Mutex
	comboBrushes = map[walk.Color]win.HBRUSH{}
)

func cachedSolidBrush(color walk.Color) win.HBRUSH {
	comboBrushMu.Lock()
	defer comboBrushMu.Unlock()
	if b, ok := comboBrushes[color]; ok && b != 0 {
		return b
	}
	b := win.CreateBrushIndirect(&win.LOGBRUSH{LbStyle: win.BS_SOLID, LbColor: win.COLORREF(color)})
	if b != 0 {
		comboBrushes[color] = b
	}
	return b
}

func setComboDropdownTheme(hwnd win.HWND, dark bool) {
	if hwnd == 0 {
		return
	}
	var info winComboBoxInfo
	info.CbSize = uint32(unsafe.Sizeof(info))
	if win.SendMessage(hwnd, cbGetComboBoxInfo, 0, uintptr(unsafe.Pointer(&info))) != 0 && info.HwndList != 0 {
		setNativeControlTheme(info.HwndList, dark)
	}
}

func (v comboBoxView) Create(builder *Builder) error {
	var cb *walk.ComboBox
	original := v.AssignTo
	v.AssignTo = &cb
	if err := v.ComboBox.Create(builder); err != nil {
		return err
	}
	if original != nil {
		*original = cb
	}
	cb.GraphicsEffects().Clear()
	if v.MinSize.Height > 0 {
		fieldH := v.MinSize.Height - 6
		if fieldH < 20 {
			fieldH = 20
		}
		cb.SendMessage(cbSetItemHeight, ^uintptr(0), uintptr(walk.IntFrom96DPI(fieldH, cb.DPI())))
	}
	setComboDropdownTheme(cb.Handle(), activePalette == darkPalette && !highContrastEnabled())
	return walk.InitWrapperWindow(&paintedComboBox{ComboBox: cb})
}

func (b *paintedComboBox) WndProc(hwnd win.HWND, msg uint32, w, l uintptr) uintptr {
	if handled, res, changed := b.tracker.handleMouseMessage(hwnd, b.Enabled(), msg, w); handled {
		return res
	} else if changed {
		_ = b.Invalidate()
	}
	switch msg {
	case win.WM_SETFOCUS, win.WM_KILLFOCUS, win.WM_ENABLE:
		_ = b.Invalidate()
	case cbSetCurSel:
		res := b.ComboBox.WndProc(hwnd, msg, w, l)
		_ = b.Invalidate()
		return res
	case win.WM_CTLCOLORLISTBOX, win.WM_CTLCOLORSTATIC, win.WM_CTLCOLOREDIT:
		dc := win.HDC(w)
		bg := currentThemeColor(uiWhite)
		win.SetTextColor(dc, win.COLORREF(currentThemeColor(uiInk)))
		win.SetBkColor(dc, win.COLORREF(bg))
		if brush := cachedSolidBrush(bg); brush != 0 {
			return uintptr(brush)
		}
	case win.WM_ERASEBKGND:
		if !b.Editable() {
			return 1
		}
	case win.WM_PAINT:
		if !b.Editable() {
			var ps win.PAINTSTRUCT
			hdc := win.BeginPaint(hwnd, &ps)
			defer win.EndPaint(hwnd, &ps)
			var r win.RECT
			win.GetClientRect(hwnd, &r)
			parentBg := nativeBackground(b)
			dpi := b.DPI()
			enabled := b.Enabled()
			focused := b.Focused()
			dropped := b.SendMessage(cbGetDroppedState, 0, 0) != 0
			fontHandle := b.SendMessage(win.WM_GETFONT, 0, 0)
			text := b.Text()
			_ = drawBufferedDC(hdc, r, parentBg, func(dc win.HDC, canvas *smoothCanvas, local win.RECT) {
				bg := currentThemeColor(uiWhite)
				fg := currentThemeColor(uiInk)
				border := currentThemeColor(uiBorder)
				chevronCol := currentThemeColor(uiMuted)
				if !enabled {
					bg = currentThemeColor(uiTableAlt)
					fg = currentThemeColor(uiMuted)
				} else if focused || dropped {
					border = currentThemeColor(uiFocus)
					chevronCol = currentThemeColor(uiBlue)
				} else if b.tracker.hovered {
					bg = mixColor(bg, currentThemeColor(uiBlueSoft), 0.35)
					border = currentThemeColor(uiBlueBorder)
					chevronCol = currentThemeColor(uiBlue)
				}
				rad := walk.IntFrom96DPI(6, dpi)
				stroke := float32(walk.IntFrom96DPI(1, dpi))
				box := win.RECT{Left: local.Left, Top: local.Top, Right: local.Right - 1, Bottom: local.Bottom - 1}
				if box.Right > box.Left && box.Bottom > box.Top {
					canvas.roundedStroke(box, rad, bg, 255, &border, stroke)
				}
				padX := int32(walk.IntFrom96DPI(10, dpi))
				chevW := int32(walk.IntFrom96DPI(10, dpi))
				chevRight := local.Right - padX
				chevLeft := chevRight - chevW
				chevMidX := (chevLeft + chevRight) / 2
				chevMidY := (local.Top + local.Bottom) / 2
				chevHalfH := int32(walk.IntFrom96DPI(2, dpi))
				if chevHalfH < 2 {
					chevHalfH = 2
				}
				canvas.lineAlpha(int(chevLeft+1), int(chevMidY-chevHalfH), int(chevMidX), int(chevMidY+chevHalfH), chevronCol, 240, 1.5)
				canvas.lineAlpha(int(chevMidX), int(chevMidY+chevHalfH), int(chevRight-1), int(chevMidY-chevHalfH), chevronCol, 240, 1.5)
				canvas.dispose()
				textRect := win.RECT{Left: local.Left + padX, Top: local.Top, Right: chevLeft - int32(walk.IntFrom96DPI(4, dpi)), Bottom: local.Bottom}
				drawControlText(dc, fontHandle, text, textRect, fg, win.DT_LEFT|win.DT_END_ELLIPSIS)
			})
			return 0
		}
	}
	return b.ComboBox.WndProc(hwnd, msg, w, l)
}

type clickableImageView struct {
	ImageView
}

type handCursorImageView struct {
	*walk.ImageView
}

func (v clickableImageView) Create(builder *Builder) error {
	var iv *walk.ImageView
	original := v.AssignTo
	v.AssignTo = &iv
	if err := v.ImageView.Create(builder); err != nil {
		return err
	}
	if original != nil {
		*original = iv
	}
	return walk.InitWrapperWindow(&handCursorImageView{ImageView: iv})
}

func (v *handCursorImageView) WndProc(hwnd win.HWND, msg uint32, w, l uintptr) uintptr {
	if msg == win.WM_SETCURSOR && v.Enabled() {
		if cur := handCursor(); cur != 0 {
			win.SetCursor(cur)
			return 1
		}
	}
	return v.ImageView.WndProc(hwnd, msg, w, l)
}

type glowInputPanel struct {
	*walk.Composite
	focusTarget    float64
	focusProgress  float64
	focusAnimating bool
}

func makeActionView(assign **walk.PushButton, text string, variant buttonVariant, width, height, radius, fontSize int, bold bool, clicked func()) actionView {
	minW := width
	maxSize := Size{Height: height}
	if width > 0 {
		maxSize.Width = width
	} else {
		minW = 120
	}
	return actionView{
		PushButton: PushButton{
			AssignTo:  assign,
			Text:      text,
			Font:      uiFont(fontSize, bold),
			MinSize:   Size{Width: minW, Height: height},
			MaxSize:   maxSize,
			OnClicked: clicked,
		},
		primary: variant == btnPrimary,
		variant: variant,
		radius:  radius,
	}
}

func heroButton(assign **walk.PushButton, text string, width int, clicked func()) actionView {
	return makeActionView(assign, text, btnPrimary, width, 40, 9, 10, true, clicked)
}

func actionButton(assign **walk.PushButton, text string, primary bool, width int, clicked func()) actionView {
	variant := btnSecondary
	if primary {
		variant = btnPrimary
	}
	return makeActionView(assign, text, variant, width, 34, 8, 9, primary, clicked)
}

func compactButton(assign **walk.PushButton, text string, variant buttonVariant, width int, clicked func()) actionView {
	return makeActionView(assign, text, variant, width, 30, 7, 9, variant == btnPrimary, clicked)
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

func navSelectedIconColor() walk.Color {
	if activePalette == darkPalette {
		return uiFocus
	}
	return uiBlueSelected
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
	return uiDisabled
}

func navSecondaryTextColor() walk.Color {
	if highContrastEnabled() {
		return navSystemColor(win.COLOR_WINDOWTEXT)
	}
	return uiMuted
}

func navButtonSize(icon string) Size {
	en := currentLang() == langEN
	switch icon {
	case "power":
		if en {
			return Size{Width: 128, Height: 36}
		}
		return Size{Width: 126, Height: 36}
	case "frp":
		if en {
			return Size{Width: 136, Height: 36}
		}
		return Size{Width: 112, Height: 36}
	case "admin":
		if en {
			return Size{Width: 132, Height: 36}
		}
		return Size{Width: 112, Height: 36}
	case "diag":
		if en {
			return Size{Width: 118, Height: 34}
		}
		return Size{Width: 104, Height: 34}
	case "settings", "more":
		if en {
			return Size{Width: 96, Height: 34}
		}
		return Size{Width: 84, Height: 34}
	case "info":
		return Size{Width: 84, Height: 34}
	default:
		return Size{Width: 116, Height: 36}
	}
}

func applyNavButtonSize(btn *walk.PushButton, icon string) {
	if btn == nil || btn.IsDisposed() {
		return
	}
	declSz := navButtonSize(icon)
	sz := btn.SizeFrom96DPI(walk.Size{Width: declSz.Width, Height: declSz.Height})
	_ = btn.SetMinMaxSizePixels(sz, sz)
}

func navButton(assign **walk.PushButton, icon, label string, selected func() bool, clicked func()) navButtonView {
	accessibility := Accessibility{Name: label, Description: tr("切换到", "Switch to ") + label, Role: AccRolePagetab}
	sz := navButtonSize(icon)
	bold := true
	switch icon {
	case "diag":
		accessibility.Description = tr("运行连接诊断", "Run connection diagnostics")
		accessibility.Role = AccRolePushbutton
		bold = false
	case "settings", "more":
		accessibility.Description = tr("打开设置菜单", "Open settings menu")
		accessibility.Role = AccRoleButtonMenu
		bold = false
	case "info":
		accessibility.Description = tr("打开版本信息对话框", "Open version info dialog")
		accessibility.Role = AccRolePushbutton
		bold = false
	}
	return navButtonView{
		PushButton: PushButton{
			AssignTo:      assign,
			Text:          label,
			Font:          uiFont(9, bold),
			MinSize:       sz,
			MaxSize:       sz,
			OnClicked:     clicked,
			Accessibility: accessibility,
		},
		icon:     icon,
		selected: selected,
	}
}

func eyeButton(assign **walk.PushButton, accessibleName string, open func() bool, clicked func()) eyeButtonView {
	return eyeButtonView{
		PushButton: PushButton{AssignTo: assign, Text: accessibleName, MinSize: Size{Width: 28, Height: 28}, MaxSize: Size{Width: 28, Height: 28}, OnClicked: clicked, Accessibility: Accessibility{Name: accessibleName}},
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
	variant := v.variant
	if v.primary && variant == btnSecondary {
		variant = btnPrimary
	}
	radius := v.radius
	if radius <= 0 {
		radius = 8
	}
	return walk.InitWrapperWindow(&paintedButton{PushButton: b, variant: variant, radius: radius, power: v.power})
}

func stepProgress(cur *float64, target, factor, eps float64) bool {
	diff := target - *cur
	if math.Abs(diff) < eps {
		*cur = target
		return true
	}
	*cur += diff * factor
	return false
}

func drawControlText(hdc win.HDC, fontHandle uintptr, text string, rect win.RECT, fg walk.Color, align uint32) {
	saved := win.SaveDC(hdc)
	if fontHandle == 0 {
		fontHandle = uintptr(win.GetStockObject(win.DEFAULT_GUI_FONT))
	}
	if fontHandle != 0 {
		win.SelectObject(hdc, win.HGDIOBJ(fontHandle))
	}
	win.SetBkMode(hdc, win.TRANSPARENT)
	win.SetTextColor(hdc, win.COLORREF(fg))
	win.DrawTextEx(hdc, syscall.StringToUTF16Ptr(text), -1, &rect, align|win.DT_VCENTER|win.DT_SINGLELINE|win.DT_NOPREFIX, nil)
	win.RestoreDC(hdc, saved)
}

func (b *paintedButton) WndProc(hwnd win.HWND, msg uint32, w, l uintptr) uintptr {
	if handled, res, changed := b.tracker.handleMouseMessage(hwnd, b.Enabled(), msg, w); handled {
		return res
	} else if changed {
		_ = b.Invalidate()
	}
	if msg == win.WM_NOTIFY && l != 0 {
		d := *(**win.NMCUSTOMDRAW)(unsafe.Pointer(&l))
		if d.Hdr.Code == win.NM_CUSTOMDRAW && d.DwDrawStage == win.CDDS_PREPAINT {
			enabled := b.Enabled()
			pressed := (b.tracker.pressed || d.UItemState&win.CDIS_SELECTED != 0) && enabled
			dpi := b.DPI()
			pad := int32(walk.IntFrom96DPI(2, dpi))
			rad := walk.IntFrom96DPI(b.radius, dpi)
			if rad < 4 {
				rad = 4
			}
			textInset := int32(walk.IntFrom96DPI(4, dpi))
			bgColor := nativeBackground(b)
			fontHandle := b.SendMessage(win.WM_GETFONT, 0, 0)
			text := b.Text()
			focused := b.Focused()
			highContrast := highContrastEnabled()

			_ = drawBufferedDC(d.Hdc, d.Rc, bgColor, func(dc win.HDC, canvas *smoothCanvas, local win.RECT) {
				r := win.RECT{Left: local.Left + pad, Top: local.Top + pad, Right: local.Right - pad, Bottom: local.Bottom - pad}
				if r.Right <= r.Left+4 || r.Bottom <= r.Top+4 {
					r = local
				}
				if !enabled {
					if b.power != nil {
						canvas.powerAnimated(r, b.power(), 0, 0, 0.18)
						return
					}
					fg := uiDisabled
					bg := uiTableAlt
					borderCol := uiBorder
					var borderPtr *walk.Color = &borderCol
					switch b.variant {
					case btnPrimary:
						bg = mixColor(uiTableAlt, uiBlueDeep, 0.24)
					case btnDanger:
						borderCol = mixColor(uiBorder, uiDanger, 0.20)
					case btnGhost:
						bg = bgColor
						borderPtr = nil
					}
					if highContrast {
						fg = navDisabledTextColor()
						bg = navSystemColor(win.COLOR_BTNFACE)
					}
					canvas.rounded(r, rad, bg, borderPtr)
					canvas.dispose()
					textRect := win.RECT{Left: r.Left + textInset, Top: r.Top, Right: r.Right - textInset, Bottom: r.Bottom}
					drawControlText(dc, fontHandle, text, textRect, fg, win.DT_CENTER)
					return
				}

				if b.power != nil {
					state := b.power()
					g := 0.0
					if state == 1 {
						g = 1.0
					} else if state == 2 {
						g = 0.55
					}
					canvas.powerAnimated(r, state, 0, g, 0.18)
					if focused {
						border := uiFocus
						sz := r.Right - r.Left
						if r.Bottom-r.Top < sz {
							sz = r.Bottom - r.Top
						}
						inset := int32(walk.IntFrom96DPI(3, dpi))
						canvas.ring(int(r.Left+(r.Right-r.Left-sz)/2+inset), int(r.Top+(r.Bottom-r.Top-sz)/2+inset), int(sz-2*inset), border, 1)
					}
					return
				}

				tPress := 0.0
				if pressed {
					tPress = 1.0
				}
				fg := uiInk
				var focusBG walk.Color

				if highContrast {
					focusBG = navSystemColor(win.COLOR_BTNFACE)
					fg = navSystemColor(win.COLOR_BTNTEXT)
					bc := navButtonBorderColor(pressed)
					if pressed || b.variant == btnPrimary {
						focusBG = navSystemColor(win.COLOR_HIGHLIGHT)
						fg = navSystemColor(win.COLOR_HIGHLIGHTTEXT)
					}
					canvas.rounded(r, rad, focusBG, &bc)
				} else {
					switch b.variant {
					case btnPrimary:
						fg = uiOnAccent
						topCol, botCol := uiBlue, uiBlueDeep
						if activePalette == darkPalette {
							topCol, botCol = uiBlueSelected, uiBlueDeep
						}
						if pressed {
							topCol = mixColor(topCol, uiBlueSelected, 0.45)
							botCol = mixColor(botCol, uiBlueSelected, 0.35)
						}
						bCol := mixColor(uiBlueSelected, uiBlueBorder, 0.35)
						canvas.roundedGradient(r, rad, topCol, botCol, &bCol, 1.0)
						focusBG = topCol

					case btnDanger:
						topRest, botRest := uiWhite, mixColor(uiWhite, uiTableAlt, 0.38)
						if activePalette == darkPalette {
							topRest, botRest = mixColor(uiTableAlt, uiWhite, 0.15), uiTableAlt
						}
						topCol := mixColor(topRest, uiDanger, tPress*0.24)
						botCol := mixColor(botRest, uiDanger, tPress*0.28)
						bCol := mixColor(uiBorderStrong, uiDanger, 0.36+0.40*tPress)
						canvas.roundedGradient(r, rad, topCol, botCol, &bCol, 1.0)
						fg = uiDanger
						focusBG = topCol

					case btnGhost:
						if pressed {
							topCol := mixColor(bgColor, uiButtonDown, 0.65)
							bCol := mixColor(bgColor, uiBlueBorder, 0.60)
							canvas.roundedGradient(r, rad, topCol, topCol, &bCol, 1.0)
							fg = uiInk
							focusBG = topCol
						} else {
							fg = uiMuted
							focusBG = bgColor
						}

					default:
						topRest, botRest := uiWhite, mixColor(uiWhite, uiTableAlt, 0.45)
						if activePalette == darkPalette {
							topRest, botRest = mixColor(uiTableAlt, uiWhite, 0.18), uiTableAlt
						}
						topCol := mixColor(topRest, uiButtonDown, tPress*0.70)
						botCol := mixColor(botRest, uiButtonDown, tPress*0.70)
						bCol := mixColor(uiBorderStrong, uiBlueBorder, 0.18+0.55*tPress)
						canvas.roundedGradient(r, rad, topCol, botCol, &bCol, 1.0)
						fg = uiInk
						focusBG = topCol
					}
				}

				if focused {
					border := uiFocus
					focus := win.RECT{Left: r.Left + 2, Top: r.Top + 2, Right: r.Right - 2, Bottom: r.Bottom - 2}
					focusRad := rad - 2
					if focusRad < 4 {
						focusRad = 4
					}
					canvas.roundedStroke(focus, focusRad, focusBG, 0, &border, float32(walk.IntFrom96DPI(1, dpi)))
				}
				canvas.dispose()
				textRect := win.RECT{Left: r.Left + textInset, Top: r.Top, Right: r.Right - textInset, Bottom: r.Bottom}
				if pressed {
					textRect.Top++
					textRect.Bottom++
				}
				drawControlText(dc, fontHandle, text, textRect, fg, win.DT_CENTER)
			})
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
	if handled, res, changed := b.tracker.handleMouseMessage(hwnd, b.Enabled(), msg, w); handled {
		return res
	} else if changed {
		_ = b.Invalidate()
	}
	if msg == win.WM_NOTIFY && l != 0 {
		d := *(**win.NMCUSTOMDRAW)(unsafe.Pointer(&l))
		if d.Hdr.Code == win.NM_CUSTOMDRAW && d.DwDrawStage == win.CDDS_PREPAINT {
			enabled := b.Enabled()
			selected := b.selected != nil && b.selected()
			pressed := (b.tracker.pressed || d.UItemState&win.CDIS_SELECTED != 0) && enabled
			b.animateSelection(selected)
			highlighted := selected || pressed
			highContrast := highContrastEnabled()
			tSel := b.selectionProgress
			tPress := 0.0
			if pressed {
				tPress = 1.0
			}
			parentBackground := nativeBackground(b)
			if highContrast {
				parentBackground = navSystemColor(win.COLOR_WINDOW)
			}
			dpi := b.DPI()
			fontHandle := b.SendMessage(win.WM_GETFONT, 0, 0)
			label := strings.TrimSpace(b.Text())
			focused := b.Focused()

			_ = drawBufferedDC(d.Hdc, d.Rc, parentBackground, func(dc win.HDC, canvas *smoothCanvas, local win.RECT) {
				bg, fg := parentBackground, uiMuted
				var pillBorder *walk.Color
				if highContrast {
					bg = navSystemColor(win.COLOR_WINDOW)
					fg = navSystemColor(win.COLOR_WINDOWTEXT)
					if highlighted {
						bg = navSystemColor(win.COLOR_HIGHLIGHT)
						fg = navSystemColor(win.COLOR_HIGHLIGHTTEXT)
					}
				} else {
					bg = mixColor(parentBackground, uiBlueHalo, tSel)
					fg = mixColor(uiMuted, navSelectedIconColor(), tSel)
					if pressed {
						bg = mixColor(bg, uiBlueSelected, 0.70*tPress)
						fg = mixColor(fg, uiOnAccent, 0.85*tPress)
					}
					if tSel > 0.02 {
						c := mixColor(parentBackground, uiBlueBorder, 0.65*tSel)
						pillBorder = &c
					}
				}
				if !enabled {
					fg = navDisabledTextColor()
					if highContrast {
						bg = navSystemColor(win.COLOR_BTNFACE)
					}
				}

				r := win.RECT{Left: local.Left + 2, Top: local.Top + 1, Right: local.Right - 2, Bottom: local.Bottom - 1}
				radius := walk.IntFrom96DPI(8, dpi)
				canvas.rounded(r, radius, bg, pillBorder)

				if !highContrast && tSel > 0.01 {
					barH := int32(walk.IntFrom96DPI(2, dpi))
					if barH < 2 {
						barH = 2
					}
					barInset := int32(walk.IntFrom96DPI(10, dpi))
					span := float64(r.Right - r.Left - barInset*2)
					half := int32(math.Round(span * 0.5 * tSel))
					midX := (r.Left + r.Right) / 2
					if half > 1 {
						barColor := uiBlue
						if activePalette == darkPalette {
							barColor = uiBlueBorder
						}
						if pressed {
							barColor = uiOnAccent
						}
						fillNative(dc, win.RECT{Left: midX - half, Top: r.Bottom - barH, Right: midX + half, Bottom: r.Bottom}, barColor)
					}
				}
				if focused {
					border := navButtonBorderColor(highlighted)
					stroke := float32(walk.IntFrom96DPI(1, dpi))
					canvas.roundedStroke(r, radius, bg, 0, &border, stroke)
				}
				yShift := int32(0)
				if pressed {
					yShift = 1
				}
				if label != "" {
					padL := int32(walk.IntFrom96DPI(8, dpi))
					iconBoxW := int32(walk.IntFrom96DPI(22, dpi))
					iconRect := win.RECT{Left: r.Left + padL, Top: r.Top + yShift, Right: r.Left + padL + iconBoxW, Bottom: r.Bottom + yShift}
					canvas.navIcon(iconRect, b.icon, fg)
					canvas.dispose()
					textRect := win.RECT{Left: iconRect.Right, Top: r.Top + yShift, Right: r.Right - int32(walk.IntFrom96DPI(4, dpi)), Bottom: r.Bottom + yShift}
					drawControlText(dc, fontHandle, label, textRect, fg, win.DT_LEFT)
				} else {
					iconRect := win.RECT{Left: r.Left, Top: r.Top + yShift, Right: r.Right, Bottom: r.Bottom + yShift}
					canvas.navIcon(iconRect, b.icon, fg)
					canvas.dispose()
				}
			})
			return win.CDRF_SKIPDEFAULT
		}
	}
	return b.PushButton.WndProc(hwnd, msg, w, l)
}

func (b *paintedNavButton) animateSelection(selected bool) {
	target := 0.0
	if selected {
		target = 1
	}
	if !uiAnimationsActive() {
		b.selectionKnown = true
		b.selectionTarget = target
		b.selectionProgress = target
		b.selectionAnimating = false
		return
	}
	if !b.selectionKnown {
		b.selectionKnown = true
		b.selectionTarget = target
		b.selectionProgress = target
		return
	}
	if target != b.selectionTarget {
		b.selectionTarget = target
		if !b.selectionAnimating {
			b.selectionAnimating = true
			b.advanceSelection()
		}
	}
}

func (b *paintedNavButton) advanceSelection() {
	if b.IsDisposed() || !uiAnimationsActive() {
		b.selectionProgress = b.selectionTarget
		b.selectionAnimating = false
		return
	}
	done := stepProgress(&b.selectionProgress, b.selectionTarget, 0.36, 0.025)
	b.selectionAnimating = !done
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
	if handled, res, changed := b.tracker.handleMouseMessage(hwnd, b.Enabled(), msg, w); handled {
		return res
	} else if changed {
		_ = b.Invalidate()
	}
	if msg == win.WM_SETFOCUS || msg == win.WM_KILLFOCUS {
		_ = b.Invalidate()
	}
	if msg == win.WM_NOTIFY && l != 0 {
		d := *(**win.NMCUSTOMDRAW)(unsafe.Pointer(&l))
		if d.Hdr.Code == win.NM_CUSTOMDRAW && d.DwDrawStage == win.CDDS_PREPAINT {
			isOpen := b.open != nil && b.open()
			bgColor := nativeBackground(b)
			_ = drawBufferedDC(d.Hdc, d.Rc, bgColor, func(_ win.HDC, canvas *smoothCanvas, local win.RECT) {
				color := uiMuted
				if b.tracker.hovered || b.tracker.pressed || b.Focused() {
					color = uiBlue
					if activePalette == darkPalette {
						color = uiFocus
					}
				} else if isOpen {
					color = mixColor(uiInk, uiMuted, 0.35)
				}
				canvas.eyeIcon(local, isOpen, color)
			})
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
	hud     bool
}
type roundPanel struct {
	*walk.Composite
	fill    walk.Color
	radius  int
	border  *walk.Color
	focused func() bool
	hud     bool
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
	return walk.InitWrapperWindow(&roundPanel{Composite: panel, fill: v.fill, radius: v.radius, border: v.border, focused: v.focused, hud: v.hud})
}
func (p *roundPanel) WndProc(hwnd win.HWND, msg uint32, w, l uintptr) uintptr {
	if msg == win.WM_SIZE {
		win.InvalidateRect(hwnd, nil, true)
	}
	if msg == win.WM_ERASEBKGND {
		var r win.RECT
		win.GetClientRect(p.Handle(), &r)
		dc := win.HDC(w)
		parentBg := nativeBackground(p)
		_ = drawBufferedDC(dc, r, parentBg, func(_ win.HDC, c *smoothCanvas, local win.RECT) {
			card := local
			card.Left++
			card.Top++
			card.Right--
			card.Bottom--
			border := p.border
			if border != nil {
				mapped := currentThemeColor(*border)
				border = &mapped
			}
			focused := p.focused != nil && p.focused()
			if focused {
				color := uiFocus
				border = &color
			}
			rad := walk.IntFrom96DPI(p.radius, p.DPI())
			c.rounded(card, rad, currentThemeColor(p.fill), border)
			if p.hud {
				hudAlpha := uint8(74)
				if activePalette == darkPalette {
					hudAlpha = 112
				}
				if focused {
					hudAlpha = 180
				}
				c.hudCorners(card, rad, uiBlueBorder, hudAlpha)
			}
		})
		return 1
	}
	return p.Composite.WndProc(hwnd, msg, w, l)
}

func themedCheckBox(assign **walk.CheckBox, text string, checked bool) Composite {
	return Composite{MinSize: Size{Height: 24}, Layout: HBox{MarginsZero: true, Spacing: 8}, Children: []Widget{
		CheckBox{AssignTo: assign, Checked: checked, MinSize: Size{Width: 20, Height: 20}, MaxSize: Size{Width: 20, Height: 20}, Accessibility: Accessibility{Name: text}},
		TextLabel{Text: text, TextColor: uiInk, Font: uiFont(9, false), NoPrefix: true, OnMouseDown: func(_, _ int, button walk.MouseButton) {
			if button == walk.LeftButton && assign != nil && *assign != nil && (*assign).Enabled() {
				(*assign).SetChecked(!(*assign).Checked())
			}
		}},
		HSpacer{},
	}}
}

type textInputView struct {
	assign     **walk.LineEdit
	text       string
	cue        string
	accessible string
	maxLength  int
	submit     func()
	changed    func()
}

func (v textInputView) Create(builder *Builder) error {
	var panel *walk.Composite
	view := Composite{AssignTo: &panel, MinSize: Size{Height: 44}, MaxSize: Size{Height: 44}, Background: SolidColorBrush{Color: uiWhite}, OnMouseDown: func(_, _ int, button walk.MouseButton) {
		if button == walk.LeftButton && *v.assign != nil {
			(*v.assign).SetFocus()
		}
	}, Layout: HBox{MarginsZero: true}, Children: []Widget{
		LineEdit{AssignTo: v.assign, Text: v.text, MaxLength: v.maxLength, StretchFactor: 1, CueBanner: v.cue, Font: uiFont(10, false), TextColor: uiInk, Background: SolidColorBrush{Color: uiWhite}, Accessibility: Accessibility{Name: v.accessible}, OnTextChanged: func() {
			if v.changed != nil {
				v.changed()
			}
		}, OnKeyDown: func(k walk.Key) {
			if k == walk.KeyReturn && v.submit != nil {
				v.submit()
			}
		}},
	}}
	if err := view.Create(builder); err != nil {
		return err
	}
	wrapper := &glowInputPanel{Composite: panel}
	if err := walk.InitWrapperWindow(wrapper); err != nil {
		return err
	}
	edit := *v.assign
	positioning := false
	positionChildren := func() {
		if positioning || panel.IsDisposed() || edit.IsDisposed() {
			return
		}
		width := panel.WidthPixels()
		height := panel.HeightPixels()
		if width <= 0 || height <= 0 {
			return
		}
		positioning = true
		defer func() { positioning = false }()
		editHeight := 20
		editY := (height - editHeight) / 2
		if editY < 8 {
			editY = 8
		}
		_ = edit.SetBoundsPixels(walk.Rectangle{X: 14, Y: editY, Width: width - 28, Height: editHeight})
	}
	panel.SizeChanged().Attach(positionChildren)
	edit.SizeChanged().Attach(positionChildren)
	positionChildren()
	style := win.GetWindowLong(edit.Handle(), win.GWL_STYLE)
	win.SetWindowLong(edit.Handle(), win.GWL_STYLE, style&^win.WS_BORDER)
	ex := win.GetWindowLong(edit.Handle(), win.GWL_EXSTYLE)
	win.SetWindowLong(edit.Handle(), win.GWL_EXSTYLE, ex&^win.WS_EX_CLIENTEDGE)
	win.SetWindowPos(edit.Handle(), 0, 0, 0, 0, 0, win.SWP_FRAMECHANGED|win.SWP_NOMOVE|win.SWP_NOSIZE|win.SWP_NOZORDER|win.SWP_NOACTIVATE)
	edit.GraphicsEffects().Clear()
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

type tokenInputView struct {
	assign **walk.LineEdit
	value  *string
	submit func()
}

func (v tokenInputView) Create(builder *Builder) error {
	controller := &secretTokenInput{value: v.value}
	var eye *walk.PushButton
	var panel *walk.Composite
	view := Composite{AssignTo: &panel, MinSize: Size{Height: 46}, MaxSize: Size{Height: 46}, Background: SolidColorBrush{Color: uiWhite}, OnMouseDown: func(_, _ int, button walk.MouseButton) {
		if button == walk.LeftButton && *v.assign != nil {
			(*v.assign).SetFocus()
		}
	}, Layout: HBox{MarginsZero: true}, Children: []Widget{
		LineEdit{AssignTo: v.assign, PasswordMode: false, MaxLength: 256, StretchFactor: 1, MinSize: Size{Height: 22}, MaxSize: Size{Height: 22}, CueBanner: tr("输入常规用户密钥或管理员密钥", "Enter join key or admin token"), Font: uiFont(10, false), TextColor: uiInk, Background: SolidColorBrush{Color: uiWhite}, Accessibility: Accessibility{Name: tr("入网密钥", "Join Key")}, OnKeyDown: func(k walk.Key) {
			if k == walk.KeyReturn {
				v.submit()
			} else if k == walk.KeyBack || k == walk.KeyDelete {
				controller.prepareDeletion(k)
			}
		}},
		eyeButton(&eye, tr("显示入网密钥", "Show join key"), func() bool { return controller.showing }, controller.toggleVisibility),
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
		height := panel.HeightPixels()
		if width <= 0 || height <= 0 {
			return
		}
		positioning = true
		defer func() { positioning = false }()
		const eyeSize = 28
		const rightInset = 10
		const gap = 6
		editHeight := 20
		editY := (height - editHeight) / 2
		if editY < 8 {
			editY = 8
		}
		eyeY := (height - eyeSize) / 2
		_ = edit.SetBoundsPixels(walk.Rectangle{X: 14, Y: editY, Width: width - 14 - rightInset - eyeSize - gap, Height: editHeight})
		_ = eye.SetBoundsPixels(walk.Rectangle{X: width - rightInset - eyeSize, Y: eyeY, Width: eyeSize, Height: eyeSize})
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
			c.eye.SetText(tr("隐藏入网令牌", "Hide join key"))
		} else {
			c.eye.SetText(tr("显示入网令牌", "Show join key"))
		}
		_ = c.eye.Invalidate()
	}
}

func (p *glowInputPanel) WndProc(hwnd win.HWND, msg uint32, w, l uintptr) uintptr {
	if msg == win.WM_SIZE {
		win.InvalidateRect(hwnd, nil, true)
	}
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
		canvas.rounded(base, walk.IntFrom96DPI(8, p.DPI()), uiWhite, &border)
		canvas.dispose()
		return 1
	}
	return p.Composite.WndProc(hwnd, msg, w, l)
}

func (p *glowInputPanel) advanceGlow() {
	if p.IsDisposed() || !uiAnimationsActive() {
		p.focusProgress = p.focusTarget
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

type deckScanBarView struct {
	Composite
	active   func() bool
	progress func() float64
}

type deckScanPanel struct {
	*walk.Composite
	active   func() bool
	progress func() float64
}

func (v deckScanBarView) Create(builder *Builder) error {
	var panel *walk.Composite
	original := v.AssignTo
	v.AssignTo = &panel
	if err := v.Composite.Create(builder); err != nil {
		return err
	}
	if original != nil {
		*original = panel
	}
	return walk.InitWrapperWindow(&deckScanPanel{Composite: panel, active: v.active, progress: v.progress})
}

func (p *deckScanPanel) WndProc(hwnd win.HWND, msg uint32, w, l uintptr) uintptr {
	if msg == win.WM_SIZE {
		win.InvalidateRect(hwnd, nil, true)
	}
	if msg == win.WM_ERASEBKGND {
		var r win.RECT
		win.GetClientRect(p.Handle(), &r)
		dc := win.HDC(w)
		_ = drawBufferedSmooth(dc, r, uiBorder, func(c *smoothCanvas, local win.RECT) {
			lw := int(local.Right - local.Left)
			lh := int(local.Bottom - local.Top)
			if lw <= 0 || lh <= 0 {
				return
			}
			c.lineAlpha(0, 0, lw, 0, uiBorderStrong, 220, 1.0)
			if lh > 1 {
				c.lineAlpha(0, 1, lw, 1, uiBackground, 255, 1.0)
			}
			if p.active != nil && p.active() {
				prog := 0.5
				if p.progress != nil {
					prog = p.progress()
				}
				fade := math.Sin(prog * math.Pi)
				if fade < 0.05 {
					fade = 0.05
				}
				beamW := lw / 3
				if beamW < 140 {
					beamW = 140
				}
				if beamW > lw {
					beamW = lw
				}
				cx := int(math.Round(float64(lw) * prog))
				c.lineAlpha(cx-beamW/2, 0, cx+beamW/2, 0, uiBlue, uint8(math.Round(190*fade)), 2.0)
				c.lineAlpha(cx-beamW/4, 0, cx+beamW/4, 0, uiBlueBorder, uint8(math.Round(240*fade)), 2.0)
				c.lineAlpha(cx-beamW/10, 0, cx+beamW/10, 0, uiFocus, uint8(math.Round(255*fade)), 2.0)
			}
		})
		return 1
	}
	return p.Composite.WndProc(hwnd, msg, w, l)
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
