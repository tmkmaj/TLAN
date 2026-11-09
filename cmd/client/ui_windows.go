//go:build windows

package main

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
	"github.com/lxn/win"
	"github.com/private-radminlan/lanmesh/internal/clientui"
)

var (
	uiBlue         = walk.RGB(37, 99, 235)
	uiBlueDeep     = walk.RGB(29, 78, 216)
	uiBlueHover    = walk.RGB(31, 86, 214)
	uiBlueSelected = walk.RGB(24, 72, 184)
	uiBlueSoft     = walk.RGB(235, 242, 255)
	uiBlueHalo     = walk.RGB(225, 236, 255)
	uiBlueBorder   = walk.RGB(188, 210, 251)
	uiInk          = walk.RGB(17, 24, 39)
	uiMuted        = walk.RGB(107, 114, 128)
	uiBackground   = walk.RGB(244, 247, 252)
	uiSidebar      = walk.RGB(255, 255, 255)
	uiWhite        = walk.RGB(255, 255, 255)
	uiBorder       = walk.RGB(226, 232, 240)
	uiBorderStrong = walk.RGB(203, 213, 225)
	uiTableAlt     = walk.RGB(248, 250, 255)
)

const (
	pageJoin = iota
	pagePower
	pageFRP
	pageEgress
)

const (
	appName     = "TmkNetworkLAN"
	windowTitle = "TmkNetwork - TLAN"
	appVersion  = "v0.6.0"
)

type desktopTableModel struct {
	walk.TableModelBase
	rows [][]string
}

func (m *desktopTableModel) RowCount() int { return len(m.rows) }
func (m *desktopTableModel) Value(r, c int) interface{} {
	if r < 0 || r >= len(m.rows) || c < 0 || c >= len(m.rows[r]) {
		return ""
	}
	value := m.rows[r][c]
	if c == 2 && value == "在线" && len(m.rows[r]) > 3 && m.rows[r][3] != "—" {
		return "● 在线 · " + m.rows[r][3]
	}
	if c == 2 && value == "离线" {
		return "○ 离线"
	}
	return value
}
func (m *desktopTableModel) setRows(rows [][]string) {
	equal := len(rows) == len(m.rows)
	if equal {
		for i := range rows {
			if strings.Join(rows[i], "\x00") != strings.Join(m.rows[i], "\x00") {
				equal = false
				break
			}
		}
	}
	if equal {
		return
	}
	m.rows = rows
	m.PublishRowsReset()
}

func caption(text string) Label { return Label{Text: text, TextColor: uiMuted, NoPrefix: true} }
func heading(text string) Label {
	return Label{Text: text, TextColor: uiInk, Font: Font{PointSize: 12, Bold: true}, NoPrefix: true}
}

func pageHeader(title, glyph string, actions ...Widget) Composite {
	children := []Widget{
		roundView{Composite: Composite{MinSize: Size{Width: 34, Height: 34}, MaxSize: Size{Width: 34, Height: 34}, Background: SolidColorBrush{Color: uiBlueSoft}, Layout: VBox{MarginsZero: true}, Children: []Widget{
			TextLabel{Text: glyph, TextColor: uiBlue, Font: Font{Family: "Segoe UI Symbol", PointSize: 15, Bold: true}, TextAlignment: AlignHCenterVCenter},
		}}, fill: uiBlueSoft, radius: 9},
		Label{Text: title, TextColor: uiInk, Font: Font{Family: "Microsoft YaHei UI", PointSize: 14, Bold: true}, NoPrefix: true},
		HSpacer{},
	}
	children = append(children, actions...)
	return Composite{Background: SolidColorBrush{Color: uiBackground}, Layout: HBox{MarginsZero: true, Spacing: 10}, Children: children}
}

func (a *desktop) powerView(assign **walk.ImageView, size int) ImageView {
	image := walk.NewPaintFuncImagePixels(walk.Size{Width: size, Height: size}, func(canvas *walk.Canvas, bounds walk.Rectangle) error {
		r := win.RECT{Left: int32(bounds.X), Top: int32(bounds.Y), Right: int32(bounds.X + bounds.Width), Bottom: int32(bounds.Y + bounds.Height)}
		fillNative(canvas.HDC(), r, uiWhite)
		c := newSmoothCanvas(canvas.HDC())
		c.power(r, a.powerState, false)
		c.dispose()
		return c.err
	})
	return ImageView{
		AssignTo:      assign,
		Image:         image,
		MinSize:       Size{Width: size, Height: size},
		MaxSize:       Size{Width: size, Height: size},
		Mode:          ImageViewModeIdeal,
		ToolTipText:   "点击开启或关闭虚拟网络",
		Accessibility: Accessibility{Name: "虚拟网络电源状态", Description: "点击圆形图标开启或关闭虚拟网络"},
		OnMouseDown: func(_, _ int, button walk.MouseButton) {
			if button == walk.LeftButton {
				a.togglePower()
			}
		},
	}
}

func loadApplicationLogo() walk.Image {
	candidates := []string{}
	if executable, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(executable), "tmknetworklan-icon.png"))
	}
	candidates = append(candidates, filepath.Join("assets", "branding", "tmknetworklan-icon.png"))
	for _, path := range candidates {
		if _, err := os.Stat(path); err != nil {
			continue
		}
		image, err := walk.NewImageFromFileForDPI(path, 96)
		if err == nil {
			return image
		}
	}
	return nil
}

func (a *desktop) build() error {
	if err := initSmoothDrawing(); err != nil {
		return err
	}
	icon, err := walk.NewIconFromResource("APP")
	if err != nil {
		return fmt.Errorf("load application icon: %w", err)
	}
	a.appIcon = icon
	a.logoImage = loadApplicationLogo()
	a.peerModel = &desktopTableModel{}
	a.initializeFRPUI()
	a.initializeTrayActions()
	name := a.identity.DisplayName
	if name == "" {
		name = "我的电脑"
	}

	join := actionButton(&a.joinButton, "加入网络", true, 0, a.join)
	join.MinSize = Size{Width: 380, Height: 44}
	join.MaxSize = Size{Height: 44}
	join.Font = Font{Family: "Microsoft YaHei UI", PointSize: 11, Bold: true}
	frpEntry := actionButton(&a.frpEntryButton, "配置内网穿透", false, 0, a.openFRP)
	frpEntry.MinSize = Size{Width: 380, Height: 40}
	frpEntry.MaxSize = Size{Height: 40}
	joinCard := roundView{Composite: Composite{MinSize: Size{Width: 460}, MaxSize: Size{Width: 460}, Background: SolidColorBrush{Color: uiWhite}, Layout: VBox{Margins: Margins{Left: 40, Top: 34, Right: 40, Bottom: 32}, Spacing: 14}, Children: []Widget{
		ImageView{Image: a.logoImage, MinSize: Size{Width: 64, Height: 64}, MaxSize: Size{Width: 64, Height: 64}, Mode: ImageViewModeShrink, Alignment: AlignHCenterVCenter},
		Label{Text: "加入虚拟网卡组网", TextColor: uiInk, Font: Font{PointSize: 17, Bold: true}, TextAlignment: AlignCenter, NoPrefix: true},
		TextLabel{Text: "输入熟人分享的入网令牌，设备会自动分配虚拟 IP。", TextColor: uiMuted, MinSize: Size{Width: 380}, TextAlignment: AlignHCenterVCenter},
		tokenInputView{assign: &a.code, value: &a.token, submit: a.join},
		join,
		frpEntry,
		Label{Text: "内网穿透无需加入虚拟网络；令牌仅由当前 Windows 用户加密保存", TextColor: uiMuted, Font: Font{PointSize: 8}, TextAlignment: AlignCenter, NoPrefix: true},
	}}, fill: uiWhite, radius: 16, border: borderColor(uiBorder)}
	joinPage := Composite{AssignTo: &a.joinPage, StretchFactor: 1, Background: SolidColorBrush{Color: uiBackground}, Layout: VBox{Margins: Margins{Left: 28, Top: 28, Right: 28, Bottom: 28}, SpacingZero: true}, Children: []Widget{
		VSpacer{StretchFactor: 1},
		Composite{Layout: HBox{MarginsZero: true}, Children: []Widget{HSpacer{}, joinCard, HSpacer{}}},
		VSpacer{StretchFactor: 1},
	}}

	toggleAction := actionButton(&a.toggleButton, "启动网络", true, 178, a.togglePower)
	membersAction := actionButton(&a.membersButton, "刷新成员", false, 126, a.refreshMembers)
	powerCard := roundView{Composite: Composite{Background: SolidColorBrush{Color: uiWhite}, Layout: HBox{Margins: Margins{Left: 42, Top: 34, Right: 42, Bottom: 34}, Spacing: 48}, Children: []Widget{
		Composite{StretchFactor: 1, Background: SolidColorBrush{Color: uiWhite}, Layout: HBox{MarginsZero: true}, Children: []Widget{HSpacer{}, a.powerView(&a.powerVisual, 200), HSpacer{}}},
		Composite{MinSize: Size{Width: 390}, MaxSize: Size{Width: 390}, Background: SolidColorBrush{Color: uiWhite}, Layout: VBox{MarginsZero: true, Spacing: 10}, Children: []Widget{
			VSpacer{StretchFactor: 1},
			Label{AssignTo: &a.offState, Text: "虚拟网络已关闭", TextColor: uiInk, Font: Font{PointSize: 17, Bold: true}, NoPrefix: true, EllipsisMode: EllipsisEnd},
			TextLabel{AssignTo: &a.offHint, Text: "启动后，加入同一网络的设备可以通过虚拟 IP 互相访问。", TextColor: uiMuted, MinSize: Size{Width: 380}, MaxSize: Size{Height: 52}},
			Label{AssignTo: &a.offNetwork, Text: a.membership.Network.Name, TextColor: uiBlue, Font: Font{PointSize: 11, Bold: true}, NoPrefix: true, EllipsisMode: EllipsisEnd},
			VSpacer{Size: 6},
			Composite{Layout: HBox{MarginsZero: true, Spacing: 10}, Children: []Widget{toggleAction, membersAction, HSpacer{}}},
			VSpacer{StretchFactor: 1},
		}},
	}}, fill: uiWhite, radius: 12, border: borderColor(uiBorder)}
	powerHeader := pageHeader("虚拟网卡组网", "⚡", actionButton(nil, "连接诊断", false, 88, a.diagnose))
	powerHeader.Row = 0
	powerCard.Row = 1

	localCard := roundView{Composite: Composite{MinSize: Size{Width: 800}, Background: SolidColorBrush{Color: uiWhite}, Layout: HBox{Margins: Margins{Left: 14, Top: 10, Right: 16, Bottom: 10}, Spacing: 12}, Children: []Widget{
		Composite{MinSize: Size{Width: 4}, MaxSize: Size{Width: 4}, Background: SolidColorBrush{Color: uiBlue}},
		a.powerView(&a.compactPowerVisual, 52),
		Composite{StretchFactor: 1, Background: SolidColorBrush{Color: uiWhite}, Layout: VBox{MarginsZero: true, Spacing: 2}, Children: []Widget{
			Label{AssignTo: &a.deviceName, Text: name, TextColor: uiInk, Font: Font{PointSize: 10, Bold: true}, NoPrefix: true, EllipsisMode: EllipsisEnd},
			Label{AssignTo: &a.address, Text: a.membership.Member.VirtualIP, Font: Font{Family: "Consolas", PointSize: 17}, TextColor: uiBlue},
			Label{AssignTo: &a.badge, Text: "● 在线", TextColor: uiBlue, Font: Font{PointSize: 9}},
		}},
		HSpacer{},
		Label{Text: "本机设备", TextColor: uiMuted, Font: Font{PointSize: 9}, NoPrefix: true},
	}}, fill: uiWhite, radius: 11, border: borderColor(uiBorder)}
	membersCard := roundView{Composite: Composite{MinSize: Size{Width: 800}, Background: SolidColorBrush{Color: uiWhite}, StretchFactor: 1, Layout: VBox{Margins: Margins{Left: 16, Top: 12, Right: 16, Bottom: 12}, Spacing: 8}, Children: []Widget{
		Composite{Background: SolidColorBrush{Color: uiWhite}, Layout: HBox{MarginsZero: true, Spacing: 8}, Children: []Widget{
			Label{Text: "成员列表", TextColor: uiInk, Font: Font{PointSize: 11, Bold: true}, NoPrefix: true},
			Label{AssignTo: &a.networkTitle, Text: a.membership.Network.Name, TextColor: uiBlue, NoPrefix: true, EllipsisMode: EllipsisEnd, StretchFactor: 1},
			Label{AssignTo: &a.memberCount, TextColor: uiMuted},
			actionButton(nil, "刷新", false, 62, a.refreshMembers),
			actionButton(nil, "诊断", false, 62, a.diagnose),
		}},
		TableView{AssignTo: &a.peers, Visible: false, Model: a.peerModel, Background: SolidColorBrush{Color: uiWhite}, StretchFactor: 1, MinSize: Size{Height: 150}, CustomRowHeight: 30, CustomHeaderHeight: 28, LastColumnStretched: true, SelectionHiddenWithoutFocus: true, AlternatingRowBG: true, Columns: []TableViewColumn{
			{Title: "设备", Width: 230}, {Title: "虚拟 IP", Width: 160}, {Title: "连接状态", Width: 210}, {Title: "路径", Hidden: true}, {Title: "延迟", Width: 90, Alignment: AlignFar},
		}, StyleCell: func(s *walk.CellStyle) {
			s.TextColor = uiInk
			if s.Row()%2 == 1 {
				s.BackgroundColor = uiTableAlt
			} else {
				s.BackgroundColor = uiWhite
			}
			if s.Row() < 0 || s.Row() >= len(a.peerModel.rows) {
				return
			}
			row := a.peerModel.rows[s.Row()]
			if row[2] == "离线" {
				s.TextColor = uiMuted
			} else if s.Col() == 1 || s.Col() == 2 || s.Col() == 4 {
				s.TextColor = uiBlue
			}
		}},
		TextLabel{AssignTo: &a.empty, Text: "正在获取网络成员…", TextColor: uiMuted, MinSize: Size{Width: 360, Height: 160}, StretchFactor: 1, TextAlignment: AlignHCenterVCenter},
	}}, fill: uiWhite, radius: 12, border: borderColor(uiBorder)}
	membersCard.Composite.StretchFactor = 1
	membersFooter := Composite{Layout: HBox{MarginsZero: true}, Children: []Widget{
		Label{AssignTo: &a.traffic, Text: "↑ 0 B    ↓ 0 B", TextColor: uiMuted, StretchFactor: 1},
		Label{Text: "● 端到端加密", TextColor: uiBlue, Font: Font{PointSize: 9}, NoPrefix: true},
	}}
	connectedArea := Composite{AssignTo: &a.connectedArea, Visible: false, MinSize: Size{Width: 800}, Layout: VBox{MarginsZero: true, Spacing: 10}, Children: []Widget{
		localCard,
		membersCard,
		membersFooter,
	}}
	connectedArea.Row = 2
	powerPage := Composite{AssignTo: &a.powerPage, Visible: false, StretchFactor: 1, Background: SolidColorBrush{Color: uiBackground}, Layout: Grid{Columns: 1, Margins: Margins{Left: 20, Top: 16, Right: 20, Bottom: 18}, Spacing: 14}, Children: []Widget{
		powerHeader,
		powerCard,
		connectedArea,
	}}
	frpPage := a.buildFRPPage()
	a.egress = newEgressPanel(a)
	egressPage := a.egress.view()

	moreNav := navButton(&a.railMore, "more", "更多操作", nil, a.showRailMenu)
	moreNav.ContextMenuItems = []MenuItem{
		Action{Text: "连接诊断", OnTriggered: a.diagnose},
		Separator{},
		Action{Text: "客户端设置", OnTriggered: a.showClientSettings},
		Action{Text: "更换入网令牌", OnTriggered: a.changeCode},
		Action{Text: "退出当前网络", OnTriggered: a.leaveNetwork},
	}
	rail := Composite{MinSize: Size{Width: 68}, MaxSize: Size{Width: 68}, Alignment: AlignHNearVNear, Background: SolidColorBrush{Color: uiSidebar}, Layout: VBox{Margins: Margins{Left: 13, Top: 14, Right: 13, Bottom: 12}, SpacingZero: true}, Children: []Widget{
		ImageView{Image: a.logoImage, MinSize: Size{Width: 42, Height: 42}, MaxSize: Size{Width: 42, Height: 42}, Mode: ImageViewModeShrink, Alignment: AlignHCenterVCenter},
		VSpacer{Size: 22},
		navButton(&a.railPower, "power", "虚拟网卡组网", func() bool { return a.page == pagePower && a.railSelection == 0 }, func() {
			a.railSelection = 0
			a.invalidateRail()
			a.showPage(pagePower)
		}),
		VSpacer{Size: 8},
		navButton(&a.railFRP, "frp", "内网穿透", func() bool { return a.page == pageFRP && a.railSelection == 0 }, a.openFRP),
		VSpacer{Size: 8},
		navButton(&a.railEgress, "egress", "应用流量转发", func() bool { return a.page == pageEgress && a.railSelection == 0 }, func() {
			a.railSelection = 0
			a.invalidateRail()
			a.showPage(pageEgress)
		}),
		VSpacer{Size: 8},
		navButton(&a.railVersion, "info", "版本信息", func() bool { return a.railSelection == 2 }, a.openVersionInfo),
		VSpacer{StretchFactor: 1},
		moreNav,
		VSpacer{Size: 12},
		Label{Text: appVersion, TextColor: uiBlue, Font: Font{PointSize: 8, Bold: true}, TextAlignment: AlignCenter, NoPrefix: true},
	}}
	contentHost := Composite{StretchFactor: 1, Background: SolidColorBrush{Color: uiBackground}, Layout: VBox{MarginsZero: true, SpacingZero: true}, Children: []Widget{powerPage, frpPage, egressPage}}
	shellPage := Composite{AssignTo: &a.shellPage, Visible: false, StretchFactor: 1, Background: SolidColorBrush{Color: uiBackground}, Layout: HBox{MarginsZero: true, SpacingZero: true}, Children: []Widget{rail, contentHost}}

	err = (MainWindow{AssignTo: &a.window, Title: windowTitle, Icon: icon, Visible: !a.startHidden, Size: Size{Width: 1020, Height: 720}, MinSize: Size{Width: 940, Height: 620}, Font: Font{Family: "Microsoft YaHei UI", PointSize: 10}, Background: SolidColorBrush{Color: uiBackground}, Layout: VBox{MarginsZero: true, SpacingZero: true}, Children: []Widget{
		joinPage, shellPage,
		Composite{AssignTo: &a.notice, Visible: false, Background: SolidColorBrush{Color: uiBlueSoft}, Layout: HBox{Margins: Margins{Left: 22, Top: 12, Right: 22, Bottom: 12}, Spacing: 12}, Children: []Widget{
			Label{Text: "!", TextColor: uiWhite, Font: Font{Family: "Segoe UI", PointSize: 10, Bold: true}, TextAlignment: AlignCenter, MinSize: Size{Width: 22, Height: 22}, MaxSize: Size{Width: 22, Height: 22}, Background: SolidColorBrush{Color: uiBlue}, NoPrefix: true},
			Composite{StretchFactor: 1, Layout: VBox{MarginsZero: true, Spacing: 2}, Children: []Widget{
				Label{AssignTo: &a.noticeTitle, TextColor: uiInk, Font: Font{Bold: true, PointSize: 10}},
				TextLabel{AssignTo: &a.noticeMessage, MinSize: Size{Width: 320}, TextColor: uiMuted},
			}},
			actionButton(nil, "详情", false, 56, a.showErrorDetails),
			actionButton(nil, "收起", false, 56, a.dismissNotice),
		}},
		Label{AssignTo: &a.status, Visible: false},
	}}).Create()
	if err != nil {
		icon.Dispose()
		if a.logoImage != nil {
			a.logoImage.Dispose()
		}
		return err
	}
	a.window.Disposing().Attach(a.disposeTray)
	a.window.Disposing().Attach(icon.Dispose)
	if a.logoImage != nil {
		a.window.Disposing().Attach(a.logoImage.Dispose)
	}
	style := win.GetWindowLong(a.peers.Handle(), win.GWL_STYLE)
	win.SetWindowLong(a.peers.Handle(), win.GWL_STYLE, style&^win.WS_BORDER)
	ex := win.GetWindowLong(a.peers.Handle(), win.GWL_EXSTYLE)
	win.SetWindowLong(a.peers.Handle(), win.GWL_EXSTYLE, ex&^win.WS_EX_CLIENTEDGE)
	win.SetWindowPos(a.peers.Handle(), 0, 0, 0, 0, 0, win.SWP_FRAMECHANGED|win.SWP_NOMOVE|win.SWP_NOSIZE|win.SWP_NOZORDER|win.SWP_NOACTIVATE)
	a.peers.SetGridlines(false)
	a.configureFRPTable()
	a.animationsEnabled = true
	a.updatePowerButtons()
	if a.api.Token != "" {
		a.showPage(pagePower)
	} else {
		a.showPage(pageJoin)
	}
	return nil
}

func borderColor(color walk.Color) *walk.Color { return &color }

func (a *desktop) showRailMenu() {
	menu := a.railMore.ContextMenu()
	if menu == nil {
		return
	}
	var bounds win.RECT
	win.GetWindowRect(a.railMore.Handle(), &bounds)
	position := uintptr(uint32(uint16(bounds.Right)) | uint32(uint16(bounds.Top))<<16)
	a.railMore.SendMessage(win.WM_CONTEXTMENU, uintptr(a.railMore.Handle()), position)
}

func (a *desktop) invalidateRail() {
	for _, button := range []*walk.PushButton{a.railPower, a.railFRP, a.railEgress, a.railVersion, a.railMore} {
		if button != nil {
			button.Invalidate()
		}
	}
}

func (a *desktop) openVersionInfo() {
	a.railSelection = 2
	a.invalidateRail()
	a.showVersionInfo()
	a.railSelection = 0
	a.invalidateRail()
}

func (a *desktop) showVersionInfo() {
	var dlg *walk.Dialog
	var closeButton *walk.PushButton
	err := (Dialog{
		AssignTo:      &dlg,
		Title:         "版本信息",
		Icon:          a.appIcon,
		Size:          Size{Width: 520, Height: 380},
		MinSize:       Size{Width: 480, Height: 340},
		Font:          Font{Family: "Microsoft YaHei UI", PointSize: 10},
		Background:    SolidColorBrush{Color: uiWhite},
		Layout:        VBox{Margins: Margins{Left: 30, Top: 26, Right: 30, Bottom: 24}, Spacing: 12},
		CancelButton:  &closeButton,
		DefaultButton: &closeButton,
		Children: []Widget{
			ImageView{Image: a.logoImage, MinSize: Size{Width: 72, Height: 72}, MaxSize: Size{Width: 72, Height: 72}, Mode: ImageViewModeShrink, Alignment: AlignHCenterVCenter},
			Label{Text: appName, TextColor: uiInk, Font: Font{PointSize: 18, Bold: true}, TextAlignment: AlignCenter, NoPrefix: true},
			Label{Text: "版本 " + appVersion, TextColor: uiBlue, Font: Font{PointSize: 11, Bold: true}, TextAlignment: AlignCenter, NoPrefix: true},
			TextLabel{Text: "Windows 10/11 amd64 原生客户端\n功能：虚拟网卡组网、TCP/UDP 内网穿透", TextColor: uiMuted, MinSize: Size{Width: 400}, TextAlignment: AlignHCenterVCenter},
			VSpacer{StretchFactor: 1},
			Composite{Layout: HBox{MarginsZero: true}, Children: []Widget{
				HSpacer{},
				actionButton(&closeButton, "关闭", true, 92, func() { dlg.Accept() }),
			}},
		},
	}).Create(a.window)
	if err != nil {
		walk.MsgBox(a.window, "版本信息", appName+" "+appVersion, walk.MsgBoxOK|walk.MsgBoxIconInformation)
		return
	}
	defer dlg.Dispose()
	dlg.Run()
}

func (a *desktop) showPage(page int) {
	a.window.SetSuspended(true)
	shellVisible := page != pageJoin
	a.joinPage.SetVisible(!shellVisible)
	a.shellPage.SetVisible(shellVisible)
	a.powerPage.SetVisible(shellVisible && page == pagePower)
	a.frpPage.SetVisible(shellVisible && page == pageFRP)
	a.egress.page.SetVisible(shellVisible && page == pageEgress)
	a.page = page
	a.window.SetSuspended(false)
	a.invalidateRail()
	switch page {
	case pageJoin:
		a.code.SetFocus()
	case pagePower:
		a.toggleButton.SetFocus()
	case pageFRP:
		if a.frpToggleButton != nil {
			a.frpToggleButton.SetFocus()
		}
		a.refreshFRP()
	case pageEgress:
		if a.egress != nil {
			a.egress.refresh()
		}
	}
}

func (a *desktop) setConnectedVisible(show bool) {
	if a.connectedArea == nil || show == a.connectedArea.Visible() {
		return
	}
	if !a.animationsEnabled || !a.window.Visible() {
		a.connectedArea.SetVisible(show)
		return
	}
	a.connectedAnimToken++
	token := a.connectedAnimToken
	if show {
		a.connectedArea.SetVisible(true)
		time.AfterFunc(20*time.Millisecond, func() {
			if a.closing.Load() {
				return
			}
			a.window.Synchronize(func() {
				if a.closing.Load() || token != a.connectedAnimToken || !a.connectedArea.Visible() {
					return
				}
				final := a.connectedArea.BoundsPixels()
				if final.Width <= 0 || final.Height <= 0 {
					return
				}
				start := final
				start.Y = final.Y + final.Height + 10
				_ = a.connectedArea.SetBoundsPixels(start)
				a.slideConnectedArea(start, final, false, 0, token, walk.Rectangle{})
			})
		})
		return
	}
	current := a.connectedArea.BoundsPixels()
	end := current
	end.Y = current.Y + current.Height + 10
	a.slideConnectedArea(current, end, true, 0, token, current)
}

func (a *desktop) slideConnectedArea(start, end walk.Rectangle, hide bool, step int, token uint64, restore walk.Rectangle) {
	if a.closing.Load() || token != a.connectedAnimToken {
		return
	}
	const totalSteps = 12
	progress := float64(step+1) / totalSteps
	eased := 1 - math.Pow(1-progress, 3)
	bounds := start
	bounds.Y = int(math.Round(float64(start.Y) + float64(end.Y-start.Y)*eased))
	_ = a.connectedArea.SetBoundsPixels(bounds)
	if step+1 >= totalSteps {
		if hide {
			a.connectedArea.SetVisible(false)
			if restore.Width > 0 && restore.Height > 0 {
				_ = a.connectedArea.SetBoundsPixels(restore)
			}
		}
		return
	}
	time.AfterFunc(16*time.Millisecond, func() {
		if a.closing.Load() {
			return
		}
		a.window.Synchronize(func() {
			a.slideConnectedArea(start, end, hide, step+1, token, restore)
		})
	})
}

func (a *desktop) updatePowerButtons() {
	toggleText := "启动网络"
	if a.powerState == 1 {
		toggleText = "停止网络"
	} else if a.powerState == 2 {
		toggleText = "正在连接…"
	}
	for _, visual := range []*walk.ImageView{a.powerVisual, a.compactPowerVisual} {
		if visual != nil {
			visual.SetEnabled(!a.busy)
			visual.Invalidate()
		}
	}
	if a.toggleButton != nil {
		a.toggleButton.SetText(toggleText)
		a.toggleButton.SetEnabled(!a.busy)
		a.toggleButton.Invalidate()
	}
	if a.membersButton != nil {
		a.membersButton.SetEnabled(!a.busy && a.engine != nil)
		a.membersButton.Invalidate()
	}
	if a.connectedArea != nil {
		a.setConnectedVisible(a.engine != nil)
	}
	if a.railPower != nil {
		a.railPower.Invalidate()
	}
	a.updateTrayMenu()
}

func (a *desktop) showError(action string, err error) {
	f := clientui.Explain(action, err, a.api.Token)
	switch f.Title {
	case "网络密码不正确":
		f.Title = "入网令牌不正确"
		f.Message = "请确认令牌后重新输入。"
	case "访问令牌未通过验证":
		f.Title = "需要重新验证令牌"
		f.Message = "关闭电源后，从左侧菜单选择“更换入网令牌”。"
	case "找不到服务器地址", "暂时无法连接服务器", "服务器响应超时", "与服务器的连接中断":
		f.Message = "请检查当前网络后重试。若仍无法连接，请联系软件提供者检查服务。"
	case "无法验证服务器证书":
		f.Message = "请检查电脑日期和时间。若仍失败，请联系软件提供者检查证书。"
	case "服务器地址或响应不正确":
		f.Message = "入网服务未正确响应，请联系软件提供者检查服务端。"
	case "虚拟网段与现有网络冲突":
		f.Message = "请先关闭使用相同网段的其他 VPN。若仍冲突，请联系软件提供者调整配置。"
	case "无法读取本机加密配置":
		f.Message = "请使用原来的 Windows 用户运行客户端，或重新输入令牌加入网络。"
	case "本机已退出该网络":
		f.Message = "关闭电源后，从左侧菜单选择“更换入网令牌”。"
	case "网络成员已满", "虚拟网段格式不正确":
		f.Message = "请联系软件提供者调整私人网络配置。"
	}
	a.showNotice(f)
}
func (a *desktop) showNotice(f clientui.Feedback) {
	a.feedback = f
	a.noticeTitle.SetText(f.Title)
	a.noticeMessage.SetText(f.Message)
	a.notice.SetVisible(true)
	a.status.SetText(f.Title)
}
func (a *desktop) dismissNotice() { a.notice.SetVisible(false); a.feedback = clientui.Feedback{} }
func (a *desktop) showErrorDetails() {
	if a.feedback.Title != "" {
		detail := a.feedback.Detail
		if detail == "" {
			detail = "此提示没有额外技术详情。"
		}
		a.showTextDialog(a.feedback.Title, a.feedback.Message, detail)
	}
}
func (a *desktop) showTextDialog(title, message, detail string) {
	detail = clientui.Redact(detail, a.api.Token)
	var dlg *walk.Dialog
	var closeButton *walk.PushButton
	err := (Dialog{AssignTo: &dlg, Title: title, Icon: a.appIcon, Size: Size{Width: 620, Height: 400}, MinSize: Size{Width: 520, Height: 320}, Font: Font{Family: "Microsoft YaHei UI", PointSize: 10}, Background: SolidColorBrush{Color: uiWhite}, Layout: VBox{Margins: Margins{Left: 24, Top: 22, Right: 24, Bottom: 22}, Spacing: 16}, CancelButton: &closeButton, DefaultButton: &closeButton, Children: []Widget{heading(title), TextLabel{Text: message, MinSize: Size{Width: 440}, TextColor: uiMuted}, TextEdit{Text: detail, ReadOnly: true, VScroll: true, StretchFactor: 1}, Composite{Layout: HBox{MarginsZero: true}, Children: []Widget{caption("可选中并复制详情"), HSpacer{}, actionButton(&closeButton, "关闭", false, 88, func() { dlg.Accept() })}}}}).Create(a.window)
	if err != nil {
		walk.MsgBox(a.window, "提示", message, walk.MsgBoxOK|walk.MsgBoxIconInformation)
		return
	}
	defer dlg.Dispose()
	dlg.Run()
}
func formatTraffic(n uint64) string {
	if n < 1024 {
		return fmt.Sprintf("%d B", n)
	}
	if n < 1024*1024 {
		return fmt.Sprintf("%.1f KB", float64(n)/1024)
	}
	if n < 1024*1024*1024 {
		return fmt.Sprintf("%.1f MB", float64(n)/(1024*1024))
	}
	return fmt.Sprintf("%.2f GB", float64(n)/(1024*1024*1024))
}
