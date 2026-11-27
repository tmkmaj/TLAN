//go:build windows

package main

import (
	"fmt"
	"math"
	"strings"
	"time"
	"unsafe"

	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
	"github.com/lxn/win"
	"github.com/private-radminlan/lanmesh/core"
	"github.com/private-radminlan/lanmesh/internal/clientapi"
	"github.com/private-radminlan/lanmesh/internal/clientui"
	"golang.org/x/sys/windows"
)

var (
	uiBlue         walk.Color
	uiBlueDeep     walk.Color
	uiBlueHover    walk.Color
	uiBlueSelected walk.Color
	uiBlueSoft     walk.Color
	uiBlueHalo     walk.Color
	uiBlueBorder   walk.Color
	uiInk          walk.Color
	uiMuted        walk.Color
	uiBackground   walk.Color
	uiSidebar      walk.Color
	uiWhite        walk.Color
	uiBorder       walk.Color
	uiBorderStrong walk.Color
	uiTableAlt     walk.Color
	uiOnAccent     walk.Color
	uiFocus        walk.Color
	uiButtonHover  walk.Color
	uiButtonDown   walk.Color
	uiDisabled     walk.Color
	uiDanger       walk.Color
	uiWarning      walk.Color
	uiSuccess      walk.Color
	uiPowerTrack   walk.Color
)

const (
	pageJoin = iota
	pagePower
	pageFRP
	pageAdmin
)

const (
	appName     = "TLAN"
	windowTitle = "TLAN"
	appVersion  = core.CurrentVersionTag
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
	if c == 2 && (value == "在线" || value == "Online") && len(m.rows[r]) > 3 && m.rows[r][3] != "—" {
		return "● " + value + " · " + m.rows[r][3]
	}
	if c == 2 && (value == "离线" || value == "Offline") {
		return "○ " + value
	}
	return value
}
func (m *desktopTableModel) setRows(rows [][]string) {
	if len(rows) == len(m.rows) {
		for i := range rows {
			if strings.Join(rows[i], "\x00") != strings.Join(m.rows[i], "\x00") {
				m.rows[i] = rows[i]
				m.PublishRowChanged(i)
			}
		}
		return
	}
	m.rows = rows
	m.PublishRowsReset()
	if len(rows) > 0 {
		m.PublishRowsChanged(0, len(rows)-1)
	}
}

func caption(text string) Label {
	return Label{Text: text, TextColor: uiMuted, Font: uiFont(9, false), NoPrefix: true}
}
func heading(text string) Label {
	return Label{Text: text, TextColor: uiInk, Font: uiFont(12, true), NoPrefix: true}
}

func (a *desktop) brandLogoView(size int, bg func() walk.Color) ImageView {
	image := walk.NewPaintFuncImagePixels(walk.Size{Width: size, Height: size}, func(canvas *walk.Canvas, bounds walk.Rectangle) error {
		r := win.RECT{Left: int32(bounds.X), Top: int32(bounds.Y), Right: int32(bounds.X + bounds.Width), Bottom: int32(bounds.Y + bounds.Height)}
		return drawBufferedSmooth(canvas.HDC(), r, bg(), func(c *smoothCanvas, local win.RECT) {
			c.brandEmblem(local)
		})
	})
	return ImageView{
		Image:   image,
		MinSize: Size{Width: size, Height: size},
		MaxSize: Size{Width: size, Height: size},
		Mode:    ImageViewModeIdeal,
	}
}

func (a *desktop) joinBlueprintView(width, height int) ImageView {
	image := walk.NewPaintFuncImagePixels(walk.Size{Width: width, Height: height}, func(canvas *walk.Canvas, bounds walk.Rectangle) error {
		r := win.RECT{Left: int32(bounds.X), Top: int32(bounds.Y), Right: int32(bounds.X + bounds.Width), Bottom: int32(bounds.Y + bounds.Height)}
		return drawBufferedSmooth(canvas.HDC(), r, uiSidebar, func(c *smoothCanvas, local win.RECT) {
			c.joinBlueprintAnimated(local, a.animPhase)
		})
	})
	return ImageView{
		AssignTo: &a.joinBlueprint,
		Image:    image,
		MinSize:  Size{Width: width, Height: height},
		MaxSize:  Size{Width: width, Height: height},
		Mode:     ImageViewModeIdeal,
	}
}

func (a *desktop) powerView(assign **walk.ImageView, width, height int) clickableImageView {
	image := walk.NewPaintFuncImagePixels(walk.Size{Width: width, Height: height}, func(canvas *walk.Canvas, bounds walk.Rectangle) error {
		r := win.RECT{Left: int32(bounds.X), Top: int32(bounds.Y), Right: int32(bounds.X + bounds.Width), Bottom: int32(bounds.Y + bounds.Height)}
		return drawBufferedSmooth(canvas.HDC(), r, uiWhite, func(c *smoothCanvas, local win.RECT) {
			c.powerAnimated(local, a.powerState, a.powerHover, a.powerGlow, a.animPhase)
		})
	})
	return clickableImageView{ImageView: ImageView{
		AssignTo:      assign,
		Image:         image,
		MinSize:       Size{Width: width, Height: height},
		MaxSize:       Size{Width: width, Height: height},
		Mode:          ImageViewModeIdeal,
		Accessibility: Accessibility{Name: tr("虚拟网络开关", "Virtual LAN Switch"), Description: tr("点击开启或关闭虚拟局域网", "Click to toggle Virtual LAN")},
		OnMouseMove: func(_, _ int, _ walk.MouseButton) {
			a.ensureAnimLoop()
		},
		OnMouseDown: func(_, _ int, button walk.MouseButton) {
			if button == walk.LeftButton {
				a.togglePower()
			}
		},
	}}
}

func (a *desktop) build() error {
	if err := initSmoothDrawing(); err != nil {
		return err
	}
	if a.serverProbe == nil {
		a.serverProbe = newServerProbeHistory(serverProbeCapacity)
	}
	a.animPhase = 0.18
	a.animationsEnabled = !a.smokeMode
	setUIAnimationsEnabled(a.animationsEnabled)
	icon, err := walk.NewIconFromResource("APP")
	if err != nil {
		return fmt.Errorf("load application icon: %w", err)
	}
	a.appIcon = icon
	a.peerModel = &desktopTableModel{}
	a.initializeFRPUI()
	a.initializeTrayActions()
	name := a.identity.DisplayName
	if name == "" {
		name = tr("我的电脑", "My PC")
	}

	savedSTUN := ""
	if savedBase, _ := normalizeServerURL(a.settings.ServerURL); a.api != nil && savedBase == a.api.BaseURL {
		savedSTUN = a.settings.STUNServer
		if derived, err := STUNAddressForServer(savedBase); err == nil && (savedSTUN == "" || savedSTUN == derived) {
			a.stunAuto = true
		}
	}
	if a.settings.ServerURL == "" {
		a.stunAuto = true
	}
	serverValue := bundledServerURL
	if a.api != nil && a.api.BaseURL != "" {
		serverValue = a.api.BaseURL
	}

	var joinFeat1, joinFeat2, joinFeat3 *walk.Label
	var joinTitleLabel, joinServerLabel, joinSTUNLabel, joinUserLabel, joinKeyLabel *walk.Label
	var powerLocalIPLabel, powerUserLabel, powerTrafficLabel, membersHeading, serverMetricsHeading *walk.Label

	join := heroButton(&a.joinButton, tr("立即登录", "Sign In"), 0, a.join)
	join.MinSize = Size{Width: 400, Height: 40}

	advanced := compactButton(&a.advancedButton, tr("STUN 设置", "STUN"), btnGhost, 96, a.toggleAdvancedConnection)
	joinThemeButton := compactButton(&a.joinThemeButton, tr("切换深色", "Dark"), btnSecondary, 82, a.cycleTheme)
	joinLangButton := compactButton(&a.joinLangButton, tr("English", "中文"), btnSecondary, 74, a.toggleLanguage)

	serverInput := textInputView{
		assign:     &a.serverInput,
		text:       displayServerEndpoint(serverValue),
		cue:        tr("例如 203.0.113.10:8443（默认 HTTPS）", "e.g. 203.0.113.10:8443 (HTTPS)"),
		accessible: tr("服务器地址", "Server Address"),
		maxLength:  512,
		submit:     a.join,
		changed:    a.updateSTUNCue,
	}
	stunInput := textInputView{
		assign:     &a.stunInput,
		text:       savedSTUN,
		cue:        tr("留空自动跟随服务器", "Auto from server host if empty"),
		accessible: tr("STUN 地址", "STUN Address"),
		maxLength:  256,
		submit:     a.join,
		changed:    a.markSTUNInput,
	}
	usernameInput := textInputView{
		assign:     &a.usernameInput,
		text:       name,
		cue:        tr("输入自定义用户名", "Enter custom username"),
		accessible: tr("用户名", "Username"),
		maxLength:  64,
		submit:     a.join,
	}

	joinLeftPane := roundView{Composite: Composite{MinSize: Size{Width: 286}, MaxSize: Size{Width: 286}, Background: SolidColorBrush{Color: uiSidebar}, Layout: VBox{Margins: Margins{Left: 20, Top: 20, Right: 20, Bottom: 18}, Spacing: 10}, Children: []Widget{
		Composite{Background: SolidColorBrush{Color: uiSidebar}, Layout: HBox{MarginsZero: true, Spacing: 10}, Children: []Widget{
			a.brandLogoView(38, func() walk.Color { return uiSidebar }),
			Label{Text: appName, TextColor: uiInk, Font: uiFont(12, true), NoPrefix: true},
			HSpacer{},
		}},
		VSpacer{Size: 2},
		a.joinBlueprintView(242, 174),
		VSpacer{Size: 2},
		Label{AssignTo: &joinFeat1, Text: tr("· 普通密钥：加入虚拟局域网与端口映射", "· Join Key: Join LAN & port mapping"), TextColor: uiInk, Font: uiFont(9, false), NoPrefix: true},
		Label{AssignTo: &joinFeat2, Text: tr("· 管理员密钥：解锁成员与端口管理", "· Admin Token: Unlock member management"), TextColor: uiInk, Font: uiFont(9, false), NoPrefix: true},
		Label{AssignTo: &joinFeat3, Text: tr("· 优先 P2P 直连，受限时自动中继", "· P2P direct first, auto relay fallback"), TextColor: uiInk, Font: uiFont(9, false), NoPrefix: true},
		VSpacer{StretchFactor: 1},
		Composite{Background: SolidColorBrush{Color: uiSidebar}, Layout: HBox{MarginsZero: true, Spacing: 6}, Children: []Widget{
			Label{Text: appVersion, TextColor: uiMuted, Font: uiMonoFont(8, false), NoPrefix: true},
			HSpacer{},
			joinLangButton,
			joinThemeButton,
		}},
	}}, fill: uiSidebar, radius: 10, border: borderColor(uiBorder), hud: false}

	joinRightPane := Composite{StretchFactor: 1, Background: SolidColorBrush{Color: uiWhite}, Layout: VBox{Margins: Margins{Left: 30, Top: 22, Right: 30, Bottom: 20}, Spacing: 8}, Children: []Widget{
		Label{AssignTo: &joinTitleLabel, Text: tr("登录私有网络", "Sign In"), TextColor: uiInk, Font: uiFont(16, true), NoPrefix: true},
		VSpacer{Size: 2},
		Composite{Background: SolidColorBrush{Color: uiWhite}, Layout: HBox{MarginsZero: true, Spacing: 8}, Children: []Widget{
			Label{AssignTo: &joinServerLabel, Text: tr("服务器地址 (IP:端口)", "Server Address (Host:Port)"), TextColor: uiInk, Font: uiFont(9, true), NoPrefix: true},
			HSpacer{},
			advanced,
		}},
		serverInput,
		Composite{AssignTo: &a.advancedPanel, Visible: false, Background: SolidColorBrush{Color: uiWhite}, Layout: VBox{MarginsZero: true, Spacing: 4}, Children: []Widget{
			Label{AssignTo: &joinSTUNLabel, Text: tr("自定义 STUN 地址（可选）", "Custom STUN Address (Optional)"), TextColor: uiMuted, Font: uiFont(9, false), NoPrefix: true},
			stunInput,
		}},
		Label{AssignTo: &joinUserLabel, Text: tr("用户名", "Username"), TextColor: uiInk, Font: uiFont(9, true), NoPrefix: true},
		usernameInput,
		Label{AssignTo: &joinKeyLabel, Text: tr("入网密钥", "Join Key"), TextColor: uiInk, Font: uiFont(9, true), NoPrefix: true},
		tokenInputView{assign: &a.code, value: &a.token, submit: a.join},
		VSpacer{StretchFactor: 1},
		join,
	}}

	joinCard := roundView{Composite: Composite{MinSize: Size{Width: 780, Height: 470}, MaxSize: Size{Width: 780}, Background: SolidColorBrush{Color: uiWhite}, Layout: HBox{Margins: Margins{Left: 6, Top: 6, Right: 6, Bottom: 6}, Spacing: 6}, Children: []Widget{
		joinLeftPane,
		joinRightPane,
	}}, fill: uiWhite, radius: 14, border: borderColor(uiBorder)}

	joinPage := Composite{AssignTo: &a.joinPage, StretchFactor: 1, Alignment: AlignHNearVNear, Background: SolidColorBrush{Color: uiBackground}, Layout: VBox{Margins: Margins{Left: 28, Top: 20, Right: 28, Bottom: 20}, SpacingZero: true}, Children: []Widget{
		VSpacer{StretchFactor: 1},
		Composite{Background: SolidColorBrush{Color: uiBackground}, Layout: HBox{MarginsZero: true}, Children: []Widget{HSpacer{}, joinCard, HSpacer{}}},
		VSpacer{StretchFactor: 1},
	}}

	copyIPButton := compactButton(&a.copyLocalIPButton, tr("复制 IP", "Copy IP"), btnSecondary, 76, a.copyLocalIP)
	renameSelfButton := compactButton(&a.renameSelfButton, tr("改名", "Rename"), btnSecondary, 76, a.showRenameSelfDialog)
	toggleAction := heroButton(&a.toggleButton, tr("连接虚拟网络", "Connect"), 264, a.togglePower)

	subCard := func(margins Margins, spacing int, children []Widget) roundView {
		return roundView{
			Composite: Composite{
				Background: SolidColorBrush{Color: uiTableAlt},
				Layout:     VBox{Margins: margins, Spacing: spacing},
				Children:   children,
			},
			fill:   uiTableAlt,
			radius: 10,
			border: borderColor(uiBorder),
			hud:    false,
		}
	}

	localIPCard := subCard(Margins{Left: 14, Top: 8, Right: 12, Bottom: 9}, 4, []Widget{
		Composite{Background: SolidColorBrush{Color: uiTableAlt}, Layout: HBox{MarginsZero: true, Spacing: 6}, Children: []Widget{
			Label{AssignTo: &powerLocalIPLabel, Text: tr("本机虚拟 IPv4", "Local Virtual IPv4"), TextColor: uiMuted, Font: uiFont(8, false), NoPrefix: true},
			HSpacer{},
			Label{AssignTo: &a.badge, Text: "● " + tr("未连接", "Offline"), TextColor: uiMuted, Font: uiFont(8, true), NoPrefix: true},
		}},
		Composite{Background: SolidColorBrush{Color: uiTableAlt}, Layout: HBox{MarginsZero: true, Spacing: 8}, Children: []Widget{
			Label{AssignTo: &a.address, Text: a.membership.Member.VirtualIP, Font: uiMonoFont(15, true), TextColor: uiBlue, NoPrefix: true, EllipsisMode: EllipsisEnd},
			HSpacer{},
			copyIPButton,
		}},
	})

	localUserCard := subCard(Margins{Left: 14, Top: 8, Right: 12, Bottom: 9}, 4, []Widget{
		Composite{Background: SolidColorBrush{Color: uiTableAlt}, Layout: HBox{MarginsZero: true}, Children: []Widget{
			Label{AssignTo: &powerUserLabel, Text: tr("当前用户名", "Username"), TextColor: uiMuted, Font: uiFont(8, false), NoPrefix: true},
			HSpacer{},
		}},
		Composite{Background: SolidColorBrush{Color: uiTableAlt}, Layout: HBox{MarginsZero: true, Spacing: 8}, Children: []Widget{
			Label{AssignTo: &a.deviceName, Text: name, TextColor: uiInk, Font: uiFont(13, true), NoPrefix: true, EllipsisMode: EllipsisEnd},
			HSpacer{},
			renameSelfButton,
		}},
	})

	localTrafficCard := subCard(Margins{Left: 14, Top: 8, Right: 12, Bottom: 8}, 3, []Widget{
		Composite{Background: SolidColorBrush{Color: uiTableAlt}, Layout: HBox{MarginsZero: true}, Children: []Widget{
			Label{AssignTo: &powerTrafficLabel, Text: tr("上传与下载（速率 · 累计）", "Traffic (Rate · Total)"), TextColor: uiMuted, Font: uiFont(8, false), NoPrefix: true},
			HSpacer{},
		}},
		Composite{Background: SolidColorBrush{Color: uiTableAlt}, Layout: HBox{MarginsZero: true, Spacing: 0}, Children: []Widget{
			Label{AssignTo: &a.trafficUp, Text: formatTrafficLine(true, 0, 0), TextColor: uiInk, Font: uiMonoFont(11, true), TextAlignment: AlignNear, NoPrefix: true, EllipsisMode: EllipsisEnd, StretchFactor: 1},
		}},
		Composite{Background: SolidColorBrush{Color: uiTableAlt}, Layout: HBox{MarginsZero: true, Spacing: 0}, Children: []Widget{
			Label{AssignTo: &a.trafficDown, Text: formatTrafficLine(false, 0, 0), TextColor: uiInk, Font: uiMonoFont(11, true), TextAlignment: AlignNear, NoPrefix: true, EllipsisMode: EllipsisEnd, StretchFactor: 1},
		}},
	})

	serverDisplayCard := subCard(Margins{Left: 14, Top: 8, Right: 10, Bottom: 8}, 3, []Widget{
		Label{AssignTo: &a.serverDisplayTitle, Text: tr("当前连接服务器", "Connected Server"), TextColor: uiMuted, Font: uiFont(8, false), NoPrefix: true},
		Composite{Background: SolidColorBrush{Color: uiTableAlt}, Layout: HBox{MarginsZero: true, Spacing: 6}, Children: []Widget{
			Label{AssignTo: &a.serverIdentity, Text: displayEndpointOrDash(serverValue), TextColor: uiInk, Font: uiMonoFont(11, true), NoPrefix: true, EllipsisMode: EllipsisEnd},
			HSpacer{},
			eyeButton(&a.powerServerEye, tr("显示或隐藏服务器 IP", "Show or hide server IP"), func() bool { return !a.powerServerHidden }, a.togglePowerServerEye),
		}},
	})

	powerCard := roundView{Composite: Composite{MinSize: Size{Width: 300}, MaxSize: Size{Width: 300}, Background: SolidColorBrush{Color: uiWhite}, Layout: VBox{Margins: Margins{Left: 18, Top: 14, Right: 18, Bottom: 14}, Spacing: 8}, Children: []Widget{
		Composite{Background: SolidColorBrush{Color: uiWhite}, Layout: HBox{MarginsZero: true, Spacing: 8}, Children: []Widget{
			Label{AssignTo: &a.offNetwork, Text: a.membership.Network.Name, TextColor: uiInk, Font: uiFont(12, true), NoPrefix: true, EllipsisMode: EllipsisEnd},
			HSpacer{},
			Label{AssignTo: &a.offState, Text: tr("未连接", "Offline"), TextColor: uiDanger, Font: uiFont(10, true), NoPrefix: true},
		}},
		a.powerView(&a.powerVisual, 264, 98),
		Label{AssignTo: &a.offHint, Visible: false, Text: "", TextColor: uiMuted, Font: uiFont(8, false), NoPrefix: true, EllipsisMode: EllipsisEnd},
		localIPCard,
		localUserCard,
		localTrafficCard,
		serverDisplayCard,
		VSpacer{StretchFactor: 1},
		toggleAction,
	}}, fill: uiWhite, radius: 12, border: borderColor(uiBorder), hud: false}

	membersRefresh := compactButton(&a.membersButton, tr("刷新", "Refresh"), btnSecondary, 74, a.refreshMembers)

	peersTable := TableView{
		AssignTo:                    &a.peers,
		Visible:                     false,
		Model:                       a.peerModel,
		Background:                  SolidColorBrush{Color: uiWhite},
		Font:                        uiFont(9, false),
		StretchFactor:               1,
		MinSize:                     Size{Height: 150},
		CustomRowHeight:             32,
		CustomHeaderHeight:          28,
		LastColumnStretched:         true,
		SelectionHiddenWithoutFocus: true,
		AlternatingRowBG:            true,
		OnItemActivated:             a.copySelectedPeerIP,
		OnMouseUp: func(_, _ int, button walk.MouseButton) {
			a.handlePeerTableMouseUp(button)
		},
		ContextMenuItems: []MenuItem{
			Action{AssignTo: &a.peerCopyMenuAction, Text: tr("复制虚拟 IP", "Copy Virtual IP"), OnTriggered: a.copySelectedPeerIP},
			Separator{},
			Action{AssignTo: &a.peerRefreshMenuAction, Text: tr("刷新成员", "Refresh Members"), OnTriggered: a.refreshMembers},
		},
		Columns: []TableViewColumn{
			{Title: tr("设备", "User / Device"), Width: 156},
			{Title: tr("虚拟 IP", "Virtual IP"), Width: 132},
			{Title: tr("连接方式", "Connection"), Width: 126},
			{Title: tr("路径", "Path"), Hidden: true},
			{Title: tr("延迟", "Latency"), Width: 78, Alignment: AlignFar},
		},
		StyleCell: func(s *walk.CellStyle) {
			if s.Row() < 0 {
				titles := []string{tr("设备", "User / Device"), tr("虚拟 IP", "Virtual IP"), tr("连接方式", "Connection"), tr("路径", "Path"), tr("延迟", "Latency")}
				if s.Col() >= 0 && s.Col() < len(titles) {
					styleTableHeader(s, titles[s.Col()], s.Col() == 4)
				}
				return
			}
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
			switch row[2] {
			case "离线", "Offline":
				s.TextColor = uiMuted
			case "连接中", "Connecting":
				if s.Col() == 2 {
					s.TextColor = uiWarning
				} else if s.Col() == 1 {
					s.TextColor = uiBlue
				}
			default:
				if s.Col() == 1 {
					s.TextColor = uiBlue
				} else if s.Col() == 2 {
					s.TextColor = uiSuccess
				}
			}
		},
	}

	connectedArea := Composite{AssignTo: &a.connectedArea, Visible: false, StretchFactor: 1, Background: SolidColorBrush{Color: uiWhite}, Layout: VBox{MarginsZero: true, SpacingZero: true}, Children: []Widget{
		peersTable,
	}}

	membersCard := roundView{Composite: Composite{StretchFactor: 1, Background: SolidColorBrush{Color: uiWhite}, Layout: VBox{Margins: Margins{Left: 18, Top: 14, Right: 18, Bottom: 12}, Spacing: 8}, Children: []Widget{
		Composite{Background: SolidColorBrush{Color: uiWhite}, Layout: HBox{MarginsZero: true, Spacing: 8}, Children: []Widget{
			Label{AssignTo: &membersHeading, Text: tr("在线成员", "Members"), TextColor: uiInk, Font: uiFont(12, true), NoPrefix: true},
			Label{AssignTo: &a.memberCount, Text: tr("未连接", "Offline"), TextColor: uiBlue, Font: uiFont(9, true), NoPrefix: true},
			Label{AssignTo: &a.peerCopyHint, Visible: false, Text: "", TextColor: uiSuccess, Font: uiFont(9, true), NoPrefix: true},
			HSpacer{},
			Label{AssignTo: &a.networkTitle, Text: a.membership.Network.Name, TextColor: uiMuted, Font: uiFont(9, false), NoPrefix: true, EllipsisMode: EllipsisEnd},
			membersRefresh,
		}},
		connectedArea,
		Composite{AssignTo: &a.emptyArea, StretchFactor: 1, Background: SolidColorBrush{Color: uiWhite}, Layout: VBox{MarginsZero: true, SpacingZero: true}, Children: []Widget{
			VSpacer{StretchFactor: 1},
			Label{AssignTo: &a.empty, Text: tr("尚未连接\r\n连接后将显示成员列表与延迟", "Not connected\r\nConnect to view members and latency"), TextColor: uiMuted, Font: uiFont(9, false), NoPrefix: true, TextAlignment: AlignCenter},
			VSpacer{StretchFactor: 1},
		}},
	}}, fill: uiWhite, radius: 12, border: borderColor(uiBorder), hud: false}

	metricPill := func(fill, brd walk.Color, child Widget) roundView {
		return roundView{
			Composite: Composite{
				MinSize:    Size{Height: 24},
				MaxSize:    Size{Height: 24},
				Background: SolidColorBrush{Color: fill},
				Layout:     HBox{Margins: Margins{Left: 9, Top: 3, Right: 9, Bottom: 3}, SpacingZero: true},
				Children:   []Widget{child},
			},
			fill:   fill,
			radius: 6,
			border: borderColor(brd),
			hud:    false,
		}
	}

	serverMetricsCard := roundView{Composite: Composite{MinSize: Size{Height: 168}, MaxSize: Size{Height: 184}, Background: SolidColorBrush{Color: uiWhite}, Layout: VBox{Margins: Margins{Left: 18, Top: 14, Right: 18, Bottom: 12}, Spacing: 10}, Children: []Widget{
		Composite{Background: SolidColorBrush{Color: uiWhite}, Layout: HBox{MarginsZero: true, Spacing: 6}, Children: []Widget{
			Label{AssignTo: &serverMetricsHeading, Text: tr("服务器连接质量", "Server Link Quality"), TextColor: uiInk, Font: uiFont(11, true), NoPrefix: true},
			metricPill(uiBlueSoft, uiBorder, Label{AssignTo: &a.serverProbeModeLabel, Text: tr("待检测", "Pending"), TextColor: uiBlue, Font: uiFont(9, true), NoPrefix: true}),
			HSpacer{},
			metricPill(uiTableAlt, uiBorder, Label{AssignTo: &a.serverLatencyLabel, Text: tr("延迟 --", "RTT --"), TextColor: uiMuted, Font: uiFont(9, true), NoPrefix: true}),
			metricPill(uiTableAlt, uiBorder, Label{AssignTo: &a.serverAvgLabel, Text: tr("均值 --", "Avg --"), TextColor: uiMuted, Font: uiFont(9, false), NoPrefix: true}),
			metricPill(uiTableAlt, uiBorder, Label{AssignTo: &a.serverLossLabel, Text: tr("丢包 --", "Loss --"), TextColor: uiMuted, Font: uiFont(9, true), NoPrefix: true}),
		}},
		a.serverChartWidget(),
	}}, fill: uiWhite, radius: 12, border: borderColor(uiBorder), hud: false}

	rightColumn := Composite{StretchFactor: 1, Background: SolidColorBrush{Color: uiBackground}, Layout: VBox{MarginsZero: true, Spacing: 12}, Children: []Widget{
		membersCard,
		serverMetricsCard,
	}}

	powerPage := Composite{AssignTo: &a.powerPage, Visible: false, StretchFactor: 1, Background: SolidColorBrush{Color: uiBackground}, Layout: HBox{Margins: Margins{Left: 20, Top: 16, Right: 20, Bottom: 18}, Spacing: 14}, Children: []Widget{
		powerCard,
		rightColumn,
	}}

	frpPage := a.buildFRPPage()
	a.admin = newAdminPanel(a)
	adminPage := a.admin.view()

	adminNav := navButton(&a.railAdmin, "admin", tr("管理面板", "Admin Panel"), func() bool { return a.page == pageAdmin && a.railSelection == 0 }, func() {
		if !a.adminMode {
			return
		}
		a.railSelection = 0
		a.invalidateRail()
		a.showPage(pageAdmin)
	})
	adminNav.Visible = a.adminMode
	settingsNav := navButton(&a.railMore, "settings", tr("设置", "Settings"), nil, a.showRailMenu)
	settingsNav.ContextMenuItems = []MenuItem{
		Action{AssignTo: &a.menuSettingsAction, Text: tr("常规设置", "Settings"), OnTriggered: a.showClientSettings},
		Action{AssignTo: &a.menuAboutAction, Text: tr("关于 ", "About ") + appName, OnTriggered: a.showVersionInfo},
		Action{AssignTo: &a.menuSwitchAction, Text: tr("切换服务器 / 密钥", "Switch Server / Key"), OnTriggered: a.changeCode},
		Separator{},
		Action{AssignTo: &a.menuLeaveAction, Text: tr("退出当前网络", "Leave Network"), OnTriggered: a.leaveNetwork},
	}

	brandZone := Composite{MinSize: Size{Width: 236}, MaxSize: Size{Width: 236}, Background: SolidColorBrush{Color: uiSidebar}, Layout: HBox{MarginsZero: true, Spacing: 10}, Children: []Widget{
		a.brandLogoView(36, func() walk.Color { return uiSidebar }),
		Composite{Background: SolidColorBrush{Color: uiSidebar}, Layout: VBox{MarginsZero: true, Spacing: 1}, Children: []Widget{
			Label{Text: appName, TextColor: uiInk, Font: uiFont(10, true), NoPrefix: true},
			Label{Text: appVersion, TextColor: uiMuted, Font: uiMonoFont(8, false), NoPrefix: true},
		}},
		HSpacer{StretchFactor: 1},
		Composite{MinSize: Size{Width: 1, Height: 24}, MaxSize: Size{Width: 1, Height: 24}, Background: SolidColorBrush{Color: uiBorderStrong}},
	}}
	centerNavZone := Composite{StretchFactor: 1, Background: SolidColorBrush{Color: uiSidebar}, Layout: HBox{MarginsZero: true, Spacing: 8}, Children: []Widget{
		HSpacer{StretchFactor: 1},
		navButton(&a.railPower, "power", tr("虚拟局域网", "Virtual LAN"), func() bool { return a.page == pagePower && a.railSelection == 0 }, func() {
			a.railSelection = 0
			a.invalidateRail()
			a.showPage(pagePower)
		}),
		navButton(&a.railFRP, "frp", tr("端口映射", "Port Mapping"), func() bool { return a.page == pageFRP && a.railSelection == 0 }, a.openFRP),
		adminNav,
		HSpacer{StretchFactor: 1},
	}}
	utilityZone := Composite{MinSize: Size{Width: 236}, MaxSize: Size{Width: 236}, Background: SolidColorBrush{Color: uiSidebar}, Layout: HBox{MarginsZero: true, Spacing: 8}, Children: []Widget{
		HSpacer{StretchFactor: 1},
		navButton(&a.railDiag, "diag", tr("连接诊断", "Diagnostics"), nil, a.diagnose),
		settingsNav,
	}}
	topDeck := Composite{MinSize: Size{Height: 62}, MaxSize: Size{Height: 62}, Background: SolidColorBrush{Color: uiSidebar}, Layout: HBox{Margins: Margins{Left: 20, Top: 10, Right: 20, Bottom: 10}, Spacing: 10}, Children: []Widget{
		brandZone,
		centerNavZone,
		utilityZone,
	}}
	deckDivider := Composite{
		AssignTo:   &a.deckScanView,
		MinSize:    Size{Height: 1},
		MaxSize:    Size{Height: 1},
		Background: SolidColorBrush{Color: uiBorder},
	}
	contentHost := Composite{StretchFactor: 1, Background: SolidColorBrush{Color: uiBackground}, Layout: VBox{MarginsZero: true, SpacingZero: true, Alignment: AlignHNearVNear}, Children: []Widget{powerPage, frpPage, adminPage}}
	shellPage := Composite{AssignTo: &a.shellPage, Visible: false, StretchFactor: 1, Background: SolidColorBrush{Color: uiBackground}, Layout: VBox{MarginsZero: true, SpacingZero: true, Alignment: AlignHNearVNear}, Children: []Widget{topDeck, deckDivider, contentHost}}

	err = (MainWindow{AssignTo: &a.window, Title: windowTitle, Icon: icon, Visible: !a.startHidden, Size: Size{Width: 1020, Height: 720}, MinSize: Size{Width: 940, Height: 620}, OnSizeChanged: a.handleWindowResized, Font: uiFont(10, false), Background: SolidColorBrush{Color: uiBackground}, Layout: VBox{MarginsZero: true, SpacingZero: true, Alignment: AlignHNearVNear}, Children: []Widget{
		joinPage, shellPage,
		Composite{AssignTo: &a.notice, Visible: false, Background: SolidColorBrush{Color: uiBlueSoft}, Layout: HBox{Margins: Margins{Left: 22, Top: 12, Right: 22, Bottom: 12}, Spacing: 12}, Children: []Widget{
			Label{Text: "!", TextColor: uiOnAccent, Font: uiFont(10, true), TextAlignment: AlignCenter, MinSize: Size{Width: 22, Height: 22}, MaxSize: Size{Width: 22, Height: 22}, Background: SolidColorBrush{Color: uiBlue}, NoPrefix: true},
			Composite{StretchFactor: 1, Background: SolidColorBrush{Color: uiBlueSoft}, Layout: VBox{MarginsZero: true, Spacing: 2}, Children: []Widget{
				Label{AssignTo: &a.noticeTitle, TextColor: uiInk, Font: uiFont(10, true), NoPrefix: true},
				Label{AssignTo: &a.noticeMessage, MinSize: Size{Width: 320}, TextColor: uiMuted, Font: uiFont(9, false), NoPrefix: true, EllipsisMode: EllipsisEnd},
			}},
			compactButton(&a.noticeDetailButton, tr("详情", "Details"), btnSecondary, 74, a.showErrorDetails),
			compactButton(&a.noticeDismissButton, tr("收起", "Dismiss"), btnGhost, 74, a.dismissNotice),
		}},
		Label{AssignTo: &a.status, Visible: false},
	}}).Create()
	if err != nil {
		icon.Dispose()
		return err
	}
	if a.joinBlueprint != nil {
		a.joinBlueprint.SetPaintMode(walk.PaintNoErase)
	}
	a.installSizeMoveHook()

	a.onLang(func() {
		if a.window != nil && !a.window.IsDisposed() {
			_ = a.window.SetTitle(windowTitle)
		}
		if joinFeat1 != nil {
			_ = joinFeat1.SetText(tr("· 普通密钥：加入虚拟局域网与端口映射", "· Join Key: Join LAN & port mapping"))
		}
		if joinFeat2 != nil {
			_ = joinFeat2.SetText(tr("· 管理员密钥：解锁成员与端口管理", "· Admin Token: Unlock member management"))
		}
		if joinFeat3 != nil {
			_ = joinFeat3.SetText(tr("· 优先 P2P 直连，受限时自动中继", "· P2P direct first, auto relay fallback"))
		}
		if joinTitleLabel != nil {
			_ = joinTitleLabel.SetText(tr("登录私有网络", "Sign In"))
		}
		if joinServerLabel != nil {
			_ = joinServerLabel.SetText(tr("服务器地址 (IP:端口)", "Server Address (Host:Port)"))
		}
		if joinSTUNLabel != nil {
			_ = joinSTUNLabel.SetText(tr("自定义 STUN 地址（可选）", "Custom STUN Address (Optional)"))
		}
		if joinUserLabel != nil {
			_ = joinUserLabel.SetText(tr("用户名", "Username"))
		}
		if joinKeyLabel != nil {
			_ = joinKeyLabel.SetText(tr("入网密钥", "Join Key"))
		}
		if a.serverInput != nil {
			_ = a.serverInput.SetCueBanner(tr("例如 203.0.113.10:8443（默认 HTTPS）", "e.g. 203.0.113.10:8443 (HTTPS)"))
		}
		if a.usernameInput != nil {
			_ = a.usernameInput.SetCueBanner(tr("输入自定义用户名", "Enter custom username"))
		}
		if a.code != nil {
			_ = a.code.SetCueBanner(tr("输入常规用户密钥或管理员密钥", "Enter join key or admin token"))
		}
		if a.joinLangButton != nil {
			_ = a.joinLangButton.SetText(tr("English", "中文"))
			_ = a.joinLangButton.Invalidate()
		}
		if a.joinButton != nil {
			if a.busy {
				_ = a.joinButton.SetText(tr("正在验证并登录…", "Signing in…"))
			} else {
				_ = a.joinButton.SetText(tr("立即登录", "Sign In"))
			}
			_ = a.joinButton.Invalidate()
		}
		if a.advancedButton != nil {
			if a.advancedPanel != nil && a.advancedPanel.Visible() {
				_ = a.advancedButton.SetText(tr("收起 STUN", "Hide STUN"))
			} else {
				_ = a.advancedButton.SetText(tr("STUN 设置", "STUN"))
			}
			_ = a.advancedButton.Invalidate()
		}
		if powerLocalIPLabel != nil {
			_ = powerLocalIPLabel.SetText(tr("本机虚拟 IPv4", "Local Virtual IPv4"))
		}
		if powerUserLabel != nil {
			_ = powerUserLabel.SetText(tr("当前用户名", "Username"))
		}
		if powerTrafficLabel != nil {
			_ = powerTrafficLabel.SetText(tr("上传与下载（速率 · 累计）", "Traffic (Rate · Total)"))
		}
		if a.serverDisplayTitle != nil {
			_ = a.serverDisplayTitle.SetText(tr("当前连接服务器", "Connected Server"))
		}
		a.updateConnectedServerDisplays()
		if a.copyLocalIPButton != nil {
			_ = a.copyLocalIPButton.SetText(tr("复制 IP", "Copy IP"))
			_ = a.copyLocalIPButton.Invalidate()
		}
		if a.renameSelfButton != nil {
			_ = a.renameSelfButton.SetText(tr("改名", "Rename"))
			_ = a.renameSelfButton.Invalidate()
		}
		if membersHeading != nil {
			_ = membersHeading.SetText(tr("在线成员", "Members"))
		}
		if a.membersButton != nil {
			_ = a.membersButton.SetText(tr("刷新", "Refresh"))
			_ = a.membersButton.Invalidate()
		}
		if serverMetricsHeading != nil {
			_ = serverMetricsHeading.SetText(tr("服务器连接质量", "Server Link Quality"))
		}
		if a.peerCopyMenuAction != nil {
			_ = a.peerCopyMenuAction.SetText(tr("复制虚拟 IP", "Copy Virtual IP"))
		}
		if a.peerRefreshMenuAction != nil {
			_ = a.peerRefreshMenuAction.SetText(tr("刷新成员", "Refresh Members"))
		}
		if a.railPower != nil {
			_ = a.railPower.SetText(tr("虚拟局域网", "Virtual LAN"))
			applyNavButtonSize(a.railPower, "power")
			_ = a.railPower.Invalidate()
		}
		if a.railFRP != nil {
			_ = a.railFRP.SetText(tr("端口映射", "Port Mapping"))
			applyNavButtonSize(a.railFRP, "frp")
			_ = a.railFRP.Invalidate()
		}
		if a.engine == nil {
			setLabelIfChanged(a.trafficUp, formatTrafficLine(true, 0, 0))
			setLabelIfChanged(a.trafficDown, formatTrafficLine(false, 0, 0))
		}
		if a.railAdmin != nil {
			_ = a.railAdmin.SetText(tr("管理面板", "Admin Panel"))
			applyNavButtonSize(a.railAdmin, "admin")
			_ = a.railAdmin.Invalidate()
		}
		if a.railDiag != nil {
			_ = a.railDiag.SetText(tr("连接诊断", "Diagnostics"))
			applyNavButtonSize(a.railDiag, "diag")
			_ = a.railDiag.Invalidate()
		}
		if a.railMore != nil {
			_ = a.railMore.SetText(tr("设置", "Settings"))
			applyNavButtonSize(a.railMore, "settings")
			_ = a.railMore.Invalidate()
		}
		a.requestCleanRelayout()
		if a.menuSettingsAction != nil {
			_ = a.menuSettingsAction.SetText(tr("常规设置", "Settings"))
		}
		if a.menuAboutAction != nil {
			_ = a.menuAboutAction.SetText(tr("关于 ", "About ") + appName)
		}
		if a.menuSwitchAction != nil {
			_ = a.menuSwitchAction.SetText(tr("切换服务器 / 密钥", "Switch Server / Key"))
		}
		if a.menuLeaveAction != nil {
			_ = a.menuLeaveAction.SetText(tr("退出当前网络", "Leave Network"))
		}
		if a.noticeDetailButton != nil {
			_ = a.noticeDetailButton.SetText(tr("详情", "Details"))
			_ = a.noticeDetailButton.Invalidate()
		}
		if a.noticeDismissButton != nil {
			_ = a.noticeDismissButton.SetText(tr("收起", "Dismiss"))
			_ = a.noticeDismissButton.Invalidate()
		}
		if a.peers != nil && !a.peers.IsDisposed() {
			_ = a.peers.Invalidate()
		}
	})

	a.window.Disposing().Attach(func() {
		a.closing.Store(true)
		setUIAnimationsEnabled(false)
		a.disposeTray()
	})
	a.window.Disposing().Attach(icon.Dispose)
	styleFramelessTable(a.peers)
	a.configureFRPTable()
	if a.admin != nil {
		styleFramelessTable(a.admin.table)
	}
	a.updateThemeButton()
	a.applyNativeControlThemes()
	a.updatePowerButtons()
	if a.api.Token != "" {
		a.showPage(pagePower)
	} else {
		a.showPage(pageJoin)
	}
	if a.animationsEnabled {
		time.AfterFunc(150*time.Millisecond, func() {
			if a.closing.Load() || a.window == nil || a.window.IsDisposed() {
				return
			}
			a.window.Synchronize(func() {
				a.pageTransitionsReady = true
				a.ensureAnimLoop()
			})
		})
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
	position := uintptr(uint32(uint16(bounds.Left)) | uint32(uint16(bounds.Bottom))<<16)
	a.railMore.SendMessage(win.WM_CONTEXTMENU, uintptr(a.railMore.Handle()), position)
}

func (a *desktop) invalidateRail() {
	setState := func(button *walk.PushButton, state walk.AccState) {
		if button == nil {
			return
		}
		if !button.Enabled() {
			state |= walk.AccStateUnavailable
		}
		_ = button.Accessibility().SetState(state)
		button.Invalidate()
	}
	navState := func(selected bool) walk.AccState {
		state := walk.AccStateFocusable | walk.AccStateSelectable
		if selected {
			state |= walk.AccStateSelected
		}
		return state
	}
	setState(a.railPower, navState(a.page == pagePower && a.railSelection == 0))
	setState(a.railFRP, navState(a.page == pageFRP && a.railSelection == 0))
	setState(a.railAdmin, navState(a.page == pageAdmin && a.railSelection == 0))
	setState(a.railMore, walk.AccStateFocusable|walk.AccStateHasPopup)
}

func (a *desktop) showVersionInfo() {
	var dlg *walk.Dialog
	var closeButton *walk.PushButton
	err := (Dialog{
		AssignTo:      &dlg,
		Title:         tr("关于 ", "About ") + appName,
		Icon:          a.appIcon,
		Size:          Size{Width: 400, Height: 290},
		MinSize:       Size{Width: 360, Height: 260},
		Font:          uiFont(10, false),
		Background:    SolidColorBrush{Color: uiWhite},
		Layout:        VBox{Margins: Margins{Left: 28, Top: 24, Right: 28, Bottom: 22}, Spacing: 10},
		CancelButton:  &closeButton,
		DefaultButton: &closeButton,
		Children: []Widget{
			Composite{Background: SolidColorBrush{Color: uiWhite}, Layout: HBox{MarginsZero: true}, Children: []Widget{HSpacer{}, a.brandLogoView(64, func() walk.Color { return uiWhite }), HSpacer{}}},
			VSpacer{Size: 2},
			Label{Text: appName, TextColor: uiInk, Font: uiFont(16, true), TextAlignment: AlignCenter, NoPrefix: true},
			Label{Text: tr("版本 ", "Version ") + appVersion, TextColor: uiBlue, Font: uiFont(10, true), TextAlignment: AlignCenter, NoPrefix: true},
			VSpacer{StretchFactor: 1},
			Composite{Background: SolidColorBrush{Color: uiWhite}, Layout: HBox{MarginsZero: true}, Children: []Widget{
				HSpacer{},
				actionButton(&closeButton, tr("关闭", "Close"), true, 92, func() { dlg.Accept() }),
			}},
		},
	}).Create(a.window)
	if err != nil {
		walk.MsgBox(a.window, tr("版本信息", "Version"), appName+" "+appVersion, walk.MsgBoxOK|walk.MsgBoxIconInformation)
		return
	}
	defer dlg.Dispose()
	runThemedDialog(dlg)
}

func (a *desktop) repaintWindowTree() {
	if a.window == nil || a.window.IsDisposed() {
		return
	}
	win.RedrawWindow(a.window.Handle(), nil, 0, win.RDW_INVALIDATE|win.RDW_ERASE|win.RDW_FRAME|win.RDW_ALLCHILDREN)
}

func (a *desktop) requestCleanRelayout() {
	if a.window == nil || a.window.IsDisposed() {
		return
	}
	a.window.RequestLayout()
	a.repaintWindowTree()
}

var (
	dragUser32DLL   = windows.NewLazySystemDLL("user32.dll")
	procPrintWindow = dragUser32DLL.NewProc("PrintWindow")
	procIsWindow    = dragUser32DLL.NewProc("IsWindow")
)

func isValidWindow(h win.HWND) bool {
	if h == 0 {
		return false
	}
	ok, _, _ := procIsWindow.Call(uintptr(h))
	return ok != 0
}

// canEnterDragSnapshot reports whether this size-move gesture may still try to
// build the offscreen snapshot. A failed attempt latches until the next
// WM_ENTERSIZEMOVE so a failing PrintWindow does not rerun per mouse event.
func (a *desktop) canEnterDragSnapshot() bool {
	return !a.dragSnapActive && !a.dragSnapFailed
}

func (a *desktop) enterDragSnapshot(h win.HWND) {
	if !a.canEnterDragSnapshot() || h == 0 || win.IsZoomed(h) || win.IsIconic(h) {
		return
	}
	var cr win.RECT
	if !win.GetClientRect(h, &cr) {
		a.dragSnapFailed = true
		return
	}
	w, hgt := cr.Right-cr.Left, cr.Bottom-cr.Top
	if w <= 0 || hgt <= 0 {
		a.dragSnapFailed = true
		return
	}
	hdc := win.GetDC(h)
	if hdc == 0 {
		a.dragSnapFailed = true
		return
	}
	memDC := win.CreateCompatibleDC(hdc)
	bmp := win.CreateCompatibleBitmap(hdc, w, hgt)
	win.ReleaseDC(h, hdc)
	if memDC == 0 || bmp == 0 {
		if bmp != 0 {
			win.DeleteObject(win.HGDIOBJ(bmp))
		}
		if memDC != 0 {
			win.DeleteDC(memDC)
		}
		a.dragSnapFailed = true
		return
	}
	old := win.SelectObject(memDC, win.HGDIOBJ(bmp))
	const pwClientOnlyRenderFull = 0x00000001 | 0x00000002
	ok, _, _ := procPrintWindow.Call(uintptr(h), uintptr(memDC), pwClientOnlyRenderFull)
	if ok == 0 {
		win.SelectObject(memDC, old)
		win.DeleteObject(win.HGDIOBJ(bmp))
		win.DeleteDC(memDC)
		a.dragSnapFailed = true
		return
	}

	var children []dragDetachedChild
	for child := win.GetWindow(h, win.GW_CHILD); child != 0; child = win.GetWindow(child, win.GW_HWNDNEXT) {
		var wr win.RECT
		win.GetWindowRect(child, &wr)
		tl := win.POINT{X: wr.Left, Y: wr.Top}
		br := win.POINT{X: wr.Right, Y: wr.Bottom}
		win.ScreenToClient(h, &tl)
		win.ScreenToClient(h, &br)
		children = append(children, dragDetachedChild{
			hwnd: child,
			rect: win.RECT{Left: tl.X, Top: tl.Y, Right: br.X, Bottom: br.Y},
		})
	}
	if len(children) == 0 {
		win.SelectObject(memDC, old)
		win.DeleteObject(win.HGDIOBJ(bmp))
		win.DeleteDC(memDC)
		a.dragSnapFailed = true
		return
	}

	focus := win.GetFocus()
	if focus != 0 && win.IsChild(h, focus) {
		a.dragSnapFocus = focus
	} else {
		a.dragSnapFocus = 0
	}
	a.dragSnapDC = memDC
	a.dragSnapBMP = bmp
	a.dragSnapOldBMP = old
	a.dragSnapW = w
	a.dragSnapH = hgt
	a.dragSnapChildren = children
	a.dragSnapActive = true

	// Temporarily reparent direct children to HWND_MESSAGE (-3) so MainWindow
	// has 0 child HWNDs during move drag and DWM tracks at full native refresh rate.
	const hwndMessage = win.HWND(^uintptr(2))
	for _, ch := range children {
		win.SetParent(ch.hwnd, hwndMessage)
	}
	win.InvalidateRect(h, nil, false)
	win.UpdateWindow(h)
}

func (a *desktop) exitDragSnapshot(h win.HWND) {
	if !a.dragSnapActive {
		return
	}
	a.dragSnapActive = false

	children := a.dragSnapChildren
	a.dragSnapChildren = nil
	if isValidWindow(h) {
		for _, ch := range children {
			if isValidWindow(ch.hwnd) {
				win.SetParent(ch.hwnd, h)
				win.SetWindowPos(
					ch.hwnd,
					0,
					ch.rect.Left,
					ch.rect.Top,
					ch.rect.Right-ch.rect.Left,
					ch.rect.Bottom-ch.rect.Top,
					win.SWP_NOZORDER|win.SWP_NOACTIVATE,
				)
			}
		}
	}

	if a.dragSnapDC != 0 {
		if a.dragSnapOldBMP != 0 {
			win.SelectObject(a.dragSnapDC, a.dragSnapOldBMP)
			a.dragSnapOldBMP = 0
		}
		win.DeleteDC(a.dragSnapDC)
		a.dragSnapDC = 0
	}
	if a.dragSnapBMP != 0 {
		win.DeleteObject(win.HGDIOBJ(a.dragSnapBMP))
		a.dragSnapBMP = 0
	}
	a.dragSnapW = 0
	a.dragSnapH = 0

	focus := a.dragSnapFocus
	a.dragSnapFocus = 0
	if focus != 0 && isValidWindow(focus) && isValidWindow(h) && win.IsChild(h, focus) {
		win.SetFocus(focus)
	}
	if isValidWindow(h) {
		win.RedrawWindow(h, nil, 0, win.RDW_INVALIDATE|win.RDW_ALLCHILDREN|win.RDW_UPDATENOW)
	}
}

func (a *desktop) installSizeMoveHook() {
	if a.window == nil || a.window.IsDisposed() {
		return
	}
	hwnd := a.window.Handle()
	if hwnd == 0 {
		return
	}
	style := win.GetWindowLong(hwnd, win.GWL_STYLE)
	if style&win.WS_CLIPCHILDREN == 0 {
		win.SetWindowLong(hwnd, win.GWL_STYLE, style|win.WS_CLIPCHILDREN)
	}
	if a.wndProcCB == 0 {
		a.wndProcCB = windows.NewCallback(func(h win.HWND, msg uint32, wParam, lParam uintptr) uintptr {
			switch msg {
			case win.WM_ERASEBKGND:
				if a.dragSnapActive {
					return 1
				}
			case win.WM_PAINT:
				if a.dragSnapActive && a.dragSnapDC != 0 {
					var ps win.PAINTSTRUCT
					dc := win.BeginPaint(h, &ps)
					if dc != 0 {
						win.BitBlt(dc, 0, 0, a.dragSnapW, a.dragSnapH, a.dragSnapDC, 0, 0, win.SRCCOPY)
						win.EndPaint(h, &ps)
					}
					return 0
				}
			case win.WM_GETMINMAXINFO:
				if lParam != 0 && a.window != nil && !a.window.IsDisposed() {
					dpi := a.window.DPI()
					if a.minTrackValid.Load() && a.minTrackDPI == dpi && a.minTrackX > 0 && a.minTrackY > 0 {
						mmi := *(**win.MINMAXINFO)(unsafe.Pointer(&lParam))
						mmi.PtMinTrackSize = win.POINT{X: a.minTrackX, Y: a.minTrackY}
						return 0
					}
					if prev := a.origWndProc; prev != 0 {
						res := win.CallWindowProc(prev, h, msg, wParam, lParam)
						mmi := *(**win.MINMAXINFO)(unsafe.Pointer(&lParam))
						minW := int32(a.window.IntFrom96DPI(940))
						minH := int32(a.window.IntFrom96DPI(620))
						if mmi.PtMinTrackSize.X >= minW && mmi.PtMinTrackSize.Y >= minH {
							a.minTrackX = mmi.PtMinTrackSize.X
							a.minTrackY = mmi.PtMinTrackSize.Y
							a.minTrackDPI = dpi
							a.minTrackValid.Store(true)
						}
						return res
					}
				}
			case win.WM_DPICHANGED:
				a.exitDragSnapshot(h)
				a.minTrackValid.Store(false)
			case win.WM_ENTERSIZEMOVE:
				a.inSizeMove.Store(true)
				a.resizedDuringMove.Store(false)
				a.dragSnapFailed = false
			case win.WM_EXITSIZEMOVE:
				a.exitDragSnapshot(h)
				a.inSizeMove.Store(false)
				a.ensureAnimLoop()
				if a.resizedDuringMove.Swap(false) {
					a.requestCleanRelayout()
				}
			case win.WM_SIZING:
				a.exitDragSnapshot(h)
			case win.WM_MOVING:
				if a.inSizeMove.Load() && a.canEnterDragSnapshot() {
					a.enterDragSnapshot(h)
				}
				return win.DefWindowProc(h, msg, wParam, lParam)
			case win.WM_WINDOWPOSCHANGING:
				return win.DefWindowProc(h, msg, wParam, lParam)
			case win.WM_WINDOWPOSCHANGED:
				if lParam != 0 {
					wp := *(**win.WINDOWPOS)(unsafe.Pointer(&lParam))
					if wp.Flags&win.SWP_NOSIZE != 0 && wp.Flags&(win.SWP_SHOWWINDOW|win.SWP_HIDEWINDOW) == 0 {
						return 0
					}
				}
				a.exitDragSnapshot(h)
			case win.WM_SIZE:
				a.exitDragSnapshot(h)
			case win.WM_MOVE:
				if a.dragSnapActive {
					return 0
				}
			case win.WM_CLOSE, win.WM_DESTROY:
				a.exitDragSnapshot(h)
			case win.WM_NCDESTROY:
				a.exitDragSnapshot(h)
				if prev := a.origWndProc; prev != 0 {
					a.origWndProc = 0
					win.SetWindowLongPtr(h, win.GWLP_WNDPROC, prev)
					return win.CallWindowProc(prev, h, msg, wParam, lParam)
				}
			}
			if prev := a.origWndProc; prev != 0 {
				return win.CallWindowProc(prev, h, msg, wParam, lParam)
			}
			return win.DefWindowProc(h, msg, wParam, lParam)
		})
	}
	if a.origWndProc == 0 {
		a.origWndProc = win.SetWindowLongPtr(hwnd, win.GWLP_WNDPROC, a.wndProcCB)
	}
}

func (a *desktop) handleWindowResized() {
	if a.window == nil || a.window.IsDisposed() || a.closing.Load() {
		return
	}
	if a.inSizeMove.Load() {
		a.resizedDuringMove.Store(true)
		return
	}
	if !win.IsIconic(a.window.Handle()) {
		a.ensureAnimLoop()
	}
	a.resizeSyncSeq++
	seq := a.resizeSyncSeq
	if !a.animationsEnabled || !a.window.Visible() {
		a.repaintWindowTree()
		return
	}
	time.AfterFunc(24*time.Millisecond, func() {
		if a.closing.Load() || a.window == nil || a.window.IsDisposed() {
			return
		}
		a.window.Synchronize(func() {
			if a.closing.Load() || seq != a.resizeSyncSeq || a.window == nil || a.window.IsDisposed() {
				return
			}
			cb := a.window.ClientBoundsPixels()
			noticeHidden := a.notice == nil || !a.notice.Visible()
			if a.shellPage != nil && a.shellPage.Visible() {
				sb := a.shellPage.BoundsPixels()
				if sb.Width != cb.Width || (noticeHidden && sb.Height != cb.Height) || sb.Height > cb.Height {
					a.window.RequestLayout()
				}
			} else if a.joinPage != nil && a.joinPage.Visible() {
				jb := a.joinPage.BoundsPixels()
				if jb.Width != cb.Width || (noticeHidden && jb.Height != cb.Height) || jb.Height > cb.Height {
					a.window.RequestLayout()
				}
			}
			a.repaintWindowTree()
		})
	})
}

func (a *desktop) showPage(page int) {
	if page == pageAdmin && !a.adminMode {
		page = pagePower
	}
	a.window.SetSuspended(true)
	shellVisible := page != pageJoin
	a.joinPage.SetVisible(!shellVisible)
	a.shellPage.SetVisible(shellVisible)
	a.powerPage.SetVisible(shellVisible && page == pagePower)
	a.frpPage.SetVisible(shellVisible && page == pageFRP)
	if a.admin != nil && a.admin.page != nil {
		a.admin.page.SetVisible(shellVisible && page == pageAdmin)
	}
	a.page = page
	a.minTrackValid.Store(false)
	a.window.SetSuspended(false)
	a.requestCleanRelayout()
	a.invalidateRail()
	switch page {
	case pageJoin:
		a.code.SetFocus()
	case pagePower:
		a.toggleButton.SetFocus()
	case pageFRP:
		if a.frpQuickLocalPort != nil {
			_ = a.frpQuickLocalPort.SetFocus()
		} else if a.frpToggleButton != nil {
			a.frpToggleButton.SetFocus()
		}
		a.refreshFRP()
	case pageAdmin:
		if a.admin != nil {
			a.admin.refreshData()
		}
	}
	if page == pageJoin || page == pagePower {
		a.ensureAnimLoop()
	}
}

func (a *desktop) ensureAnimLoop() {
	if a.animLoopActive || a.inSizeMove.Load() || !a.animationsEnabled || a.closing.Load() || highContrastEnabled() || a.window == nil || a.window.IsDisposed() {
		return
	}
	if !win.IsWindowVisible(a.window.Handle()) || win.IsIconic(a.window.Handle()) {
		return
	}
	if a.page != pageJoin && a.page != pagePower {
		return
	}
	a.animLoopActive = true
	time.AfterFunc(16*time.Millisecond, func() {
		if a.closing.Load() || a.window == nil || a.window.IsDisposed() {
			return
		}
		a.window.Synchronize(a.stepAnimLoop)
	})
}

func (a *desktop) stepAnimLoop() {
	if a.closing.Load() || a.inSizeMove.Load() || !a.animationsEnabled || highContrastEnabled() || a.window == nil || a.window.IsDisposed() || !win.IsWindowVisible(a.window.Handle()) || win.IsIconic(a.window.Handle()) {
		a.animLoopActive = false
		return
	}
	nextDelay := 33 * time.Millisecond
	keepRunning := false
	switch a.page {
	case pageJoin:
		a.animPhase = math.Mod(a.animPhase+0.0085, 1.0)
		if a.joinBlueprint != nil && !a.joinBlueprint.IsDisposed() {
			win.InvalidateRect(a.joinBlueprint.Handle(), nil, false)
		}
		keepRunning = true
	case pagePower:
		hoverTarget := 0.0
		if a.powerVisual != nil && !a.powerVisual.IsDisposed() {
			var pt win.POINT
			var rect win.RECT
			if win.GetCursorPos(&pt) && win.GetWindowRect(a.powerVisual.Handle(), &rect) {
				if pt.X >= rect.Left && pt.X <= rect.Right && pt.Y >= rect.Top && pt.Y <= rect.Bottom {
					hoverTarget = 1.0
				}
			}
		}
		glowTarget := 0.0
		if a.powerState == 1 {
			glowTarget = 1.0
		} else if a.powerState == 2 {
			glowTarget = 0.55
		}
		transitioning := false
		if diff := hoverTarget - a.powerHover; math.Abs(diff) < 0.02 {
			a.powerHover = hoverTarget
		} else {
			a.powerHover += diff * 0.28
			transitioning = true
		}
		if diff := glowTarget - a.powerGlow; math.Abs(diff) < 0.02 {
			a.powerGlow = glowTarget
		} else {
			a.powerGlow += diff * 0.22
			transitioning = true
		}
		if a.powerState == 1 || a.powerState == 2 || a.powerHover > 0.02 || a.powerGlow > 0.02 || transitioning {
			step := 0.007
			if a.powerState == 2 {
				step = 0.016
				nextDelay = 16 * time.Millisecond
			} else if transitioning {
				nextDelay = 16 * time.Millisecond
			}
			a.animPhase = math.Mod(a.animPhase+step, 1.0)
			if a.powerVisual != nil && !a.powerVisual.IsDisposed() {
				win.InvalidateRect(a.powerVisual.Handle(), nil, false)
			}
			keepRunning = true
		}
	}
	if !keepRunning {
		a.animLoopActive = false
		return
	}
	time.AfterFunc(nextDelay, func() {
		if a.closing.Load() || a.window == nil || a.window.IsDisposed() {
			return
		}
		a.window.Synchronize(a.stepAnimLoop)
	})
}

func (a *desktop) setConnectedVisible(show bool) {
	if a.connectedArea == nil || show == widgetOwnVisible(a.connectedArea) {
		return
	}
	a.connectedArea.SetVisible(show)
	a.requestCleanRelayout()
}

func (a *desktop) updatePowerButtons() {
	toggleText := tr("连接虚拟网络", "Connect")
	if a.powerState == 1 {
		toggleText = tr("断开连接", "Disconnect")
	} else if a.powerState == 2 {
		toggleText = tr("连接中…", "Connecting…")
	}
	if a.powerVisual != nil {
		enabled := !a.busy
		if a.powerVisual.Enabled() != enabled {
			a.powerVisual.SetEnabled(enabled)
			_ = a.powerVisual.Invalidate()
		}
	}
	if a.toggleButton != nil {
		textChanged := setButtonTextIfChanged(a.toggleButton, toggleText)
		enabledChanged := setButtonEnabledIfChanged(a.toggleButton, !a.busy)
		if textChanged || enabledChanged {
			_ = a.toggleButton.Invalidate()
		}
	}
	if a.membersButton != nil {
		if setButtonEnabledIfChanged(a.membersButton, !a.busy && a.engine != nil) {
			_ = a.membersButton.Invalidate()
		}
	}
	if a.connectedArea != nil {
		a.setConnectedVisible(a.engine != nil)
	}
	if a.railPower != nil {
		a.railPower.Invalidate()
	}
	a.ensureAnimLoop()
	a.updateTrayMenu()
}

func (a *desktop) showError(action string, err error) {
	a.showErrorWithAPI(action, err, a.api)
}

func (a *desktop) showErrorWithAPI(action string, err error, api *clientapi.Client) {
	token := ""
	if api != nil {
		token = api.Token
	}
	f := clientui.ExplainLang(currentLang(), action, err, token, a.adminToken)
	switch f.Title {
	case "网络密码不正确":
		f.Title = "入网令牌不正确"
		f.Message = "请确认令牌后重新输入。"
	case "访问令牌未通过验证":
		f.Title = "需要重新验证密钥"
		f.Message = "断开连接后，点击右上角“设置 → 切换服务器 / 密钥”。"
	case "找不到服务器地址", "暂时无法连接服务器", "服务器响应超时", "与服务器的连接中断":
		f.Message = "请检查当前网络后重试，或联系服务器管理员。"
	case "无法验证服务器证书":
		f.Message = "请检查本机日期与时间，或联系服务器管理员检查证书。"
	case "服务器地址或响应不正确":
		f.Message = "控制服务未正确响应，请确认服务器地址。"
	case "虚拟网段与现有网络冲突":
		f.Message = "请先断开网段冲突的其他 VPN 后重试。"
	case "无法读取本机加密配置":
		f.Message = "请使用原有 Windows 用户运行，或重新输入入网密钥。"
	case "本机已退出该网络":
		f.Message = "断开连接后，点击右上角“设置 → 切换服务器 / 密钥”。"
	case "网络成员已满", "虚拟网段格式不正确":
		f.Message = "请联系服务器管理员调整网络配置。"
	}
	a.showNotice(f)
}
func (a *desktop) showNotice(f clientui.Feedback) {
	a.feedback = f
	a.noticeTitle.SetText(f.Title)
	a.noticeMessage.SetText(f.Message)
	a.notice.SetVisible(true)
	a.status.SetText(f.Title)
	a.requestCleanRelayout()
}
func (a *desktop) dismissNotice() {
	a.notice.SetVisible(false)
	a.feedback = clientui.Feedback{}
	a.requestCleanRelayout()
}
func (a *desktop) showErrorDetails() {
	if a.feedback.Title != "" {
		detail := a.feedback.Detail
		if detail == "" {
			detail = tr("没有额外技术详情。", "No additional technical details.")
		}
		a.showTextDialog(a.feedback.Title, a.feedback.Message, detail)
	}
}
func (a *desktop) showTextDialog(title, message, detail string) {
	detail = clientui.RedactLang(currentLang(), detail, a.api.Token, a.adminToken)
	var dlg *walk.Dialog
	var closeButton *walk.PushButton
	err := (Dialog{AssignTo: &dlg, Title: title, Icon: a.appIcon, Size: Size{Width: 620, Height: 400}, MinSize: Size{Width: 520, Height: 320}, Font: uiFont(10, false), Background: SolidColorBrush{Color: uiWhite}, Layout: VBox{Margins: Margins{Left: 24, Top: 22, Right: 24, Bottom: 22}, Spacing: 14}, CancelButton: &closeButton, DefaultButton: &closeButton, Children: []Widget{
		heading(title),
		TextLabel{Text: message, MinSize: Size{Width: 440}, TextColor: uiMuted, Font: uiFont(9, false)},
		TextEdit{Text: detail, ReadOnly: true, VScroll: true, StretchFactor: 1, Font: uiMonoFont(9, false), TextColor: uiInk, Background: SolidColorBrush{Color: uiWhite}},
		Composite{Background: SolidColorBrush{Color: uiWhite}, Layout: HBox{MarginsZero: true}, Children: []Widget{HSpacer{}, actionButton(&closeButton, tr("关闭", "Close"), false, 88, func() { dlg.Accept() })}},
	}}).Create(a.window)
	if err != nil {
		walk.MsgBox(a.window, tr("提示", "Notice"), message, walk.MsgBoxOK|walk.MsgBoxIconInformation)
		return
	}
	defer dlg.Dispose()
	runThemedDialog(dlg)
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
