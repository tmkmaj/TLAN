//go:build windows

package main

import (
	"strings"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
	"github.com/lxn/win"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	appearanceSystem = "system"
	appearanceLight  = "light"
	appearanceDark   = "dark"
)

var globalAnimationsEnabled atomic.Bool

func init() {
	globalAnimationsEnabled.Store(true)
	applyActivePaletteGlobals()
}

func setUIAnimationsEnabled(enabled bool) {
	globalAnimationsEnabled.Store(enabled)
}

func uiAnimationsActive() bool {
	return globalAnimationsEnabled.Load() && !highContrastEnabled()
}

type uiPalette struct {
	blue, blueDeep, blueHover, blueSelected  walk.Color
	blueSoft, blueHalo, blueBorder           walk.Color
	ink, muted, background, sidebar, surface walk.Color
	border, borderStrong, tableAlt           walk.Color
	onAccent, focus, buttonHover, buttonDown walk.Color
	disabled, danger, warning, success       walk.Color
	powerTrack                               walk.Color
}

var lightPalette = uiPalette{
	blue:         walk.RGB(37, 99, 235),
	blueDeep:     walk.RGB(29, 78, 216),
	blueHover:    walk.RGB(59, 130, 246),
	blueSelected: walk.RGB(30, 64, 175),
	blueSoft:     walk.RGB(235, 244, 255),
	blueHalo:     walk.RGB(219, 234, 254),
	blueBorder:   walk.RGB(56, 189, 248),
	ink:          walk.RGB(11, 21, 40),
	muted:        walk.RGB(82, 103, 138),
	background:   walk.RGB(236, 242, 252),
	sidebar:      walk.RGB(245, 249, 255),
	surface:      walk.RGB(255, 255, 255),
	border:       walk.RGB(205, 220, 244),
	borderStrong: walk.RGB(168, 192, 232),
	tableAlt:     walk.RGB(241, 246, 254),
	onAccent:     walk.RGB(254, 255, 255),
	focus:        walk.RGB(14, 165, 233),
	buttonHover:  walk.RGB(230, 239, 254),
	buttonDown:   walk.RGB(212, 227, 252),
	disabled:     walk.RGB(142, 160, 190),
	danger:       walk.RGB(220, 38, 38),
	warning:      walk.RGB(217, 119, 6),
	success:      walk.RGB(5, 150, 105),
	powerTrack:   walk.RGB(221, 232, 250),
}

var darkPalette = uiPalette{
	blue:         walk.RGB(59, 130, 246),
	blueDeep:     walk.RGB(29, 78, 216),
	blueHover:    walk.RGB(96, 165, 250),
	blueSelected: walk.RGB(37, 99, 235),
	blueSoft:     walk.RGB(16, 34, 68),
	blueHalo:     walk.RGB(22, 49, 96),
	blueBorder:   walk.RGB(56, 189, 248),
	ink:          walk.RGB(240, 246, 255),
	muted:        walk.RGB(138, 162, 198),
	background:   walk.RGB(6, 11, 22),
	sidebar:      walk.RGB(10, 17, 34),
	surface:      walk.RGB(14, 24, 46),
	border:       walk.RGB(29, 51, 92),
	borderStrong: walk.RGB(45, 78, 138),
	tableAlt:     walk.RGB(19, 32, 60),
	onAccent:     walk.RGB(255, 255, 255),
	focus:        walk.RGB(125, 211, 252),
	buttonHover:  walk.RGB(25, 44, 80),
	buttonDown:   walk.RGB(34, 59, 106),
	disabled:     walk.RGB(86, 108, 144),
	danger:       walk.RGB(248, 113, 113),
	warning:      walk.RGB(251, 191, 36),
	success:      walk.RGB(52, 211, 153),
	powerTrack:   walk.RGB(23, 39, 72),
}

var activePalette = lightPalette

var (
	monoFontOnce   sync.Once
	monoFontFamily = "Consolas"
)

func preferredMonoFamily() string {
	monoFontOnce.Do(func() {
		if fontFamilyInstalled("Cascadia Mono") {
			monoFontFamily = "Cascadia Mono"
		}
	})
	return monoFontFamily
}

func fontFamilyInstalled(family string) bool {
	var lf win.LOGFONT
	lf.LfHeight = -12
	lf.LfCharSet = win.DEFAULT_CHARSET
	if src, err := windows.UTF16FromString(family); err == nil {
		copy(lf.LfFaceName[:], src)
	}
	hFont := win.CreateFontIndirect(&lf)
	if hFont == 0 {
		return false
	}
	defer win.DeleteObject(win.HGDIOBJ(hFont))
	dc := win.GetDC(0)
	if dc == 0 {
		return false
	}
	defer win.ReleaseDC(0, dc)
	old := win.SelectObject(dc, win.HGDIOBJ(hFont))
	defer win.SelectObject(dc, old)
	buf := make([]uint16, 64)
	proc := windows.NewLazySystemDLL("gdi32.dll").NewProc("GetTextFaceW")
	if proc.Find() != nil {
		return false
	}
	ret, _, _ := proc.Call(uintptr(dc), uintptr(len(buf)), uintptr(unsafe.Pointer(&buf[0])))
	if ret == 0 {
		return false
	}
	return strings.EqualFold(windows.UTF16ToString(buf[:ret]), family)
}

func uiFont(pointSize int, bold bool) Font {
	return Font{Family: "Microsoft YaHei UI", PointSize: pointSize, Bold: bold}
}

func uiMonoFont(pointSize int, bold bool) Font {
	return Font{Family: preferredMonoFamily(), PointSize: pointSize, Bold: bold}
}

func formLabel(text string, width int) Label {
	return Label{
		Text:      text,
		TextColor: uiInk,
		Font:      uiFont(9, false),
		MinSize:   Size{Width: width},
		NoPrefix:  true,
	}
}

func applyTableViewTheme(tv *walk.TableView, dark bool) {
	if tv == nil || tv.IsDisposed() {
		return
	}
	const (
		lvmSetBkColor     = 0x1001
		lvmGetHeader      = 0x101f
		lvmSetTextColor   = 0x1024
		lvmSetTextBkColor = 0x1026
		gwChild           = 5
		gwHwndNext        = 2
	)
	for child := win.GetWindow(tv.Handle(), gwChild); child != 0; child = win.GetWindow(child, gwHwndNext) {
		setNativeControlTheme(child, dark)
		win.SendMessage(child, lvmSetBkColor, 0, uintptr(win.COLORREF(uiWhite)))
		win.SendMessage(child, lvmSetTextBkColor, 0, uintptr(win.COLORREF(uiWhite)))
		win.SendMessage(child, lvmSetTextColor, 0, uintptr(win.COLORREF(uiInk)))
		header := win.HWND(win.SendMessage(child, lvmGetHeader, 0, 0))
		if header != 0 {
			if dark && !highContrastEnabled() {
				_, _, _ = setWindowTheme.Call(uintptr(header), uintptr(unsafe.Pointer(windows.StringToUTF16Ptr("DarkMode"))), 0)
			} else {
				setNativeControlTheme(header, false)
			}
		}
		win.InvalidateRect(child, nil, true)
	}
	_ = tv.Invalidate()
}

func styleFramelessTable(tv *walk.TableView) {
	if tv == nil || tv.IsDisposed() {
		return
	}
	handle := tv.Handle()
	style := win.GetWindowLong(handle, win.GWL_STYLE)
	win.SetWindowLong(handle, win.GWL_STYLE, style&^win.WS_BORDER)
	ex := win.GetWindowLong(handle, win.GWL_EXSTYLE)
	win.SetWindowLong(handle, win.GWL_EXSTYLE, ex&^win.WS_EX_CLIENTEDGE)
	win.SetWindowPos(handle, 0, 0, 0, 0, 0, win.SWP_FRAMECHANGED|win.SWP_NOMOVE|win.SWP_NOSIZE|win.SWP_NOZORDER|win.SWP_NOACTIVATE)
	tv.SetGridlines(false)
	applyTableViewTheme(tv, activePalette == darkPalette)
}

func normalizeAppearance(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case appearanceLight:
		return appearanceLight
	case appearanceDark:
		return appearanceDark
	default:
		return appearanceSystem
	}
}

func appearanceIndex(value string) int {
	switch normalizeAppearance(value) {
	case appearanceLight:
		return 1
	case appearanceDark:
		return 2
	default:
		return 0
	}
}

func appearanceFromIndex(index int) string {
	switch index {
	case 1:
		return appearanceLight
	case 2:
		return appearanceDark
	default:
		return appearanceSystem
	}
}

func resolveAppearance(value string, systemDark bool) bool {
	switch normalizeAppearance(value) {
	case appearanceLight:
		return false
	case appearanceDark:
		return true
	default:
		return systemDark
	}
}

func systemPrefersDark() bool {
	key, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Themes\Personalize`, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer key.Close()
	value, _, err := key.GetIntegerValue("AppsUseLightTheme")
	return err == nil && value == 0
}

func applyAppearancePalette(value string) (uiPalette, uiPalette) {
	previous := activePalette
	if resolveAppearance(value, systemPrefersDark()) {
		activePalette = darkPalette
	} else {
		activePalette = lightPalette
	}
	applyActivePaletteGlobals()
	return previous, activePalette
}

func applyActivePaletteGlobals() {
	p := activePalette
	uiBlue, uiBlueDeep, uiBlueHover, uiBlueSelected = p.blue, p.blueDeep, p.blueHover, p.blueSelected
	uiBlueSoft, uiBlueHalo, uiBlueBorder = p.blueSoft, p.blueHalo, p.blueBorder
	uiInk, uiMuted, uiBackground, uiSidebar, uiWhite = p.ink, p.muted, p.background, p.sidebar, p.surface
	uiBorder, uiBorderStrong, uiTableAlt = p.border, p.borderStrong, p.tableAlt
	uiOnAccent, uiFocus, uiButtonHover, uiButtonDown = p.onAccent, p.focus, p.buttonHover, p.buttonDown
	uiDisabled, uiDanger, uiWarning, uiSuccess, uiPowerTrack = p.disabled, p.danger, p.warning, p.success, p.powerTrack
}

func paletteReplacements(from, to uiPalette) map[walk.Color]walk.Color {
	return map[walk.Color]walk.Color{
		from.blue: to.blue, from.blueDeep: to.blueDeep, from.blueHover: to.blueHover, from.blueSelected: to.blueSelected,
		from.blueSoft: to.blueSoft, from.blueHalo: to.blueHalo, from.blueBorder: to.blueBorder,
		from.ink: to.ink, from.muted: to.muted, from.background: to.background, from.sidebar: to.sidebar,
		from.border: to.border, from.borderStrong: to.borderStrong, from.tableAlt: to.tableAlt,
		from.onAccent: to.onAccent, from.focus: to.focus, from.buttonHover: to.buttonHover, from.buttonDown: to.buttonDown,
		from.surface:  to.surface,
		from.disabled: to.disabled, from.danger: to.danger, from.warning: to.warning, from.success: to.success, from.powerTrack: to.powerTrack,
	}
}

func currentThemeColor(color walk.Color) walk.Color {
	for _, palette := range []uiPalette{lightPalette, darkPalette} {
		if replacement, ok := paletteReplacements(palette, activePalette)[color]; ok {
			return replacement
		}
	}
	return color
}

func refreshThemeControls(container walk.Container, replacements map[walk.Color]walk.Color) {
	if container == nil || container.IsDisposed() {
		return
	}
	var paint func(walk.Widget)
	paint = func(widget walk.Widget) {
		if widget == nil || widget.IsDisposed() {
			return
		}
		if brush, ok := widget.Background().(*walk.SolidColorBrush); ok {
			if replacement, exists := replacements[brush.Color()]; exists {
				widget.SetBackground(solidThemeBrush(replacement))
			}
		}
		if text, ok := widget.(interface {
			TextColor() walk.Color
			SetTextColor(walk.Color)
		}); ok {
			if replacement, exists := replacements[text.TextColor()]; exists {
				text.SetTextColor(replacement)
			}
		}
		_ = widget.Invalidate()
		if children, ok := widget.(walk.Container); ok {
			list := children.Children()
			for index := 0; index < list.Len(); index++ {
				paint(list.At(index))
			}
		}
	}
	list := container.Children()
	for index := 0; index < list.Len(); index++ {
		paint(list.At(index))
	}
	if brush, ok := container.Background().(*walk.SolidColorBrush); ok {
		if replacement, exists := replacements[brush.Color()]; exists {
			container.SetBackground(solidThemeBrush(replacement))
		}
	}
	_ = container.Invalidate()
}

func solidThemeBrush(color walk.Color) walk.Brush {
	brush, _ := walk.NewSolidColorBrush(color)
	return brush
}

var (
	uxthemeDLL      = windows.NewLazySystemDLL("uxtheme.dll")
	setWindowTheme  = uxthemeDLL.NewProc("SetWindowTheme")
	dwmapiDLL       = windows.NewLazySystemDLL("dwmapi.dll")
	dwmSetAttribute = dwmapiDLL.NewProc("DwmSetWindowAttribute")
)

func setNativeControlTheme(handle win.HWND, dark bool) {
	if handle == 0 || highContrastEnabled() {
		return
	}
	name := ""
	if dark {
		name = "DarkMode_Explorer"
	}
	_, _, _ = setWindowTheme.Call(uintptr(handle), uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(name))), 0)
}

func applyNativeControlThemeTree(root walk.Container) {
	if root == nil || root.IsDisposed() {
		return
	}
	dark := activePalette == darkPalette
	if !highContrastEnabled() {
		enabled := int32(0)
		if dark {
			enabled = 1
		}
		const immersiveDarkMode = 20
		_, _, _ = dwmSetAttribute.Call(uintptr(root.Handle()), immersiveDarkMode, uintptr(unsafe.Pointer(&enabled)), unsafe.Sizeof(enabled))
	}
	var apply func(walk.Widget)
	apply = func(widget walk.Widget) {
		if widget == nil || widget.IsDisposed() {
			return
		}
		switch widget.(type) {
		case *walk.ComboBox:
			setComboDropdownTheme(widget.Handle(), dark && !highContrastEnabled())
			_ = widget.Invalidate()
		case *walk.CheckBox, *walk.NumberEdit, *walk.LineEdit, *walk.TextEdit:
			setNativeControlTheme(widget.Handle(), dark)
		case *walk.TableView:
			setNativeControlTheme(widget.Handle(), dark)
		}
		if table, ok := widget.(*walk.TableView); ok {
			applyTableViewTheme(table, dark)
		}
		if container, ok := widget.(walk.Container); ok {
			children := container.Children()
			for index := 0; index < children.Len(); index++ {
				apply(children.At(index))
			}
		}
	}
	children := root.Children()
	for index := 0; index < children.Len(); index++ {
		apply(children.At(index))
	}
}

var (
	tableHeaderFontOnce sync.Once
	tableHeaderFont     *walk.Font
)

func styleTableHeader(style *walk.CellStyle, title string, rightAligned bool) {
	if style == nil || style.Row() >= 0 {
		return
	}
	bounds := style.BoundsPixels()
	fillNative(style.Canvas().HDC(), win.RECT{Left: int32(bounds.X), Top: int32(bounds.Y), Right: int32(bounds.X + bounds.Width), Bottom: int32(bounds.Y + bounds.Height)}, uiTableAlt)
	fillNative(style.Canvas().HDC(), win.RECT{Left: int32(bounds.X), Top: int32(bounds.Y + bounds.Height - 1), Right: int32(bounds.X + bounds.Width), Bottom: int32(bounds.Y + bounds.Height)}, mixColor(uiBorder, uiBlueBorder, 0.38))
	tableHeaderFontOnce.Do(func() {
		tableHeaderFont, _ = walk.NewFont("Microsoft YaHei UI", 9, walk.FontBold)
	})
	if tableHeaderFont == nil {
		return
	}
	bounds.X += 8
	bounds.Width -= 16
	format := walk.TextSingleLine | walk.TextVCenter | walk.TextLeft
	if rightAligned {
		format = walk.TextSingleLine | walk.TextVCenter | walk.TextRight
	}
	_ = style.Canvas().DrawTextPixels(title, tableHeaderFont, uiInk, bounds, format)
}

func (a *desktop) applyNativeControlThemes() {
	if a.window != nil {
		applyNativeControlThemeTree(a.window)
	}
}

func runThemedDialog(dlg *walk.Dialog) {
	if dlg != nil {
		applyNativeControlThemeTree(dlg)
		dlg.Run()
	}
}

func (a *desktop) applyAppearance(value string) {
	value = normalizeAppearance(value)
	previous, next := applyAppearancePalette(value)
	if a.window != nil && !a.window.IsDisposed() && previous != next {
		visible := a.window.Visible()
		a.window.SetSuspended(true)
		refreshThemeControls(a.window, paletteReplacements(previous, next))
		a.window.SetBackground(solidThemeBrush(activePalette.background))
		_ = a.window.SetBoundsPixels(a.window.BoundsPixels())
		a.window.RequestLayout()
		if visible {
			a.window.SetVisible(false)
		}
		a.window.SetSuspended(false)
		win.RedrawWindow(a.window.Handle(), nil, 0, win.RDW_INVALIDATE|win.RDW_ERASE|win.RDW_FRAME|win.RDW_ALLCHILDREN|win.RDW_UPDATENOW|win.RDW_ERASENOW)
		if visible {
			a.window.SetVisible(true)
		}
	}
	a.updateThemeButton()
	a.applyNativeControlThemes()
}

func (a *desktop) changeAppearance(value string) error {
	value = normalizeAppearance(value)
	previous := a.settings.Appearance
	a.settings.Appearance = value
	a.applyAppearance(value)
	if err := a.remember(); err != nil {
		a.settings.Appearance = previous
		a.applyAppearance(previous)
		return err
	}
	return nil
}

func (a *desktop) cycleTheme() {
	next := appearanceDark
	if resolveAppearance(a.settings.Appearance, systemPrefersDark()) {
		next = appearanceLight
	}
	if err := a.changeAppearance(next); err != nil {
		a.showError(tr("保存外观设置", "Save appearance"), err)
	}
}

func (a *desktop) updateThemeButton() {
	if a.joinThemeButton == nil {
		return
	}
	if resolveAppearance(a.settings.Appearance, systemPrefersDark()) {
		a.joinThemeButton.SetText(tr("切换浅色", "Light"))
	} else {
		a.joinThemeButton.SetText(tr("切换深色", "Dark"))
	}
	_ = a.joinThemeButton.Invalidate()
}
