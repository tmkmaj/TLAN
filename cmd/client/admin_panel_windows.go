//go:build windows

package main

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
	"github.com/private-radminlan/lanmesh/internal/clientapi"
	"github.com/private-radminlan/lanmesh/internal/clientui"
)

type adminPanel struct {
	desktop *desktop
	page    *walk.Composite

	overview *clientapi.AdminOverview
	members  []clientapi.AdminMember
	sessions []clientapi.AdminRelaySession

	model *desktopTableModel
	table *walk.TableView

	refresh    *walk.PushButton
	rename     *walk.PushButton
	disconnect *walk.PushButton
	kick       *walk.PushButton
	ban              *walk.PushButton
	unban            *walk.PushButton
	portRange        *walk.PushButton
	serverDisplayBtn *walk.PushButton
	networkNameBtn   *walk.PushButton

	serverCardCap     *walk.Label
	networkCardCap    *walk.Label
	countsCardCap     *walk.Label
	countsSubCap      *walk.Label
	relayCardCap      *walk.Label
	membersTitle      *walk.Label
	configBarTitle    *walk.Label
	networkConfigCap  *walk.Label
	networkConfigVal  *walk.Label
	portConfigCap     *walk.Label
	portConfigVal     *walk.Label
	displayConfigCap  *walk.Label
	displayConfigVal  *walk.Label

	service   *walk.Label
	network   *walk.Label
	counts    *walk.Label
	relay     *walk.Label
	frp       *walk.Label
	portLimit *walk.Label
	endpoint  *walk.Label
	updated   *walk.Label

	busy bool
}

func newAdminPanel(desktop *desktop) *adminPanel {
	return &adminPanel{desktop: desktop, model: &desktopTableModel{}}
}

func isAdminAuthFailure(err error) bool {
	var apiErr *clientapi.AdminAPIError
	if !errors.As(err, &apiErr) {
		return false
	}
	return apiErr.StatusCode == 401 || apiErr.StatusCode == 403 || apiErr.Code == "UNAUTHORIZED" || apiErr.Code == "FORBIDDEN"
}

func (p *adminPanel) view() Composite {
	overviewRow := Composite{Background: SolidColorBrush{Color: uiBackground}, Layout: HBox{MarginsZero: true, Spacing: 12}, Children: []Widget{
		roundView{Composite: Composite{MinSize: Size{Width: 225, Height: 94}, MaxSize: Size{Height: 94}, StretchFactor: 2, Background: SolidColorBrush{Color: uiWhite}, Layout: VBox{Margins: Margins{Left: 16, Top: 14, Right: 16, Bottom: 14}, Spacing: 4}, Children: []Widget{
			Composite{Background: SolidColorBrush{Color: uiWhite}, Layout: HBox{MarginsZero: true}, Children: []Widget{Label{AssignTo: &p.serverCardCap, Text: tr("服务端", "Server"), TextColor: uiMuted, Font: uiFont(9, false), NoPrefix: true}, HSpacer{}}},
			Label{AssignTo: &p.service, Text: tr("正在读取…", "Loading…"), TextColor: uiInk, Font: uiFont(12, true), NoPrefix: true, EllipsisMode: EllipsisEnd},
			VSpacer{StretchFactor: 1},
			Label{AssignTo: &p.endpoint, Text: "—", TextColor: uiMuted, Font: uiMonoFont(8, false), NoPrefix: true, EllipsisMode: EllipsisEnd},
		}}, fill: uiWhite, radius: 12, border: borderColor(uiBorder), hud: false},
		roundView{Composite: Composite{MinSize: Size{Width: 215, Height: 94}, MaxSize: Size{Height: 94}, StretchFactor: 2, Background: SolidColorBrush{Color: uiWhite}, Layout: VBox{Margins: Margins{Left: 16, Top: 14, Right: 16, Bottom: 14}, Spacing: 4}, Children: []Widget{
			Composite{Background: SolidColorBrush{Color: uiWhite}, Layout: HBox{MarginsZero: true}, Children: []Widget{Label{AssignTo: &p.networkCardCap, Text: tr("私有网络", "Network"), TextColor: uiMuted, Font: uiFont(9, false), NoPrefix: true}, HSpacer{}}},
			Label{AssignTo: &p.network, Text: "—", TextColor: uiBlue, Font: uiFont(12, true), NoPrefix: true, EllipsisMode: EllipsisEnd},
			VSpacer{StretchFactor: 1},
			Label{AssignTo: &p.updated, Text: "—", TextColor: uiMuted, Font: uiMonoFont(8, false), NoPrefix: true, EllipsisMode: EllipsisEnd},
		}}, fill: uiWhite, radius: 12, border: borderColor(uiBorder), hud: false},
		roundView{Composite: Composite{MinSize: Size{Width: 125, Height: 94}, MaxSize: Size{Height: 94}, StretchFactor: 1, Background: SolidColorBrush{Color: uiWhite}, Layout: VBox{Margins: Margins{Left: 16, Top: 14, Right: 16, Bottom: 14}, Spacing: 4}, Children: []Widget{
			Composite{Background: SolidColorBrush{Color: uiWhite}, Layout: HBox{MarginsZero: true}, Children: []Widget{Label{AssignTo: &p.countsCardCap, Text: tr("成员 / 在线", "Members / Online"), TextColor: uiMuted, Font: uiFont(9, false), NoPrefix: true}, HSpacer{}}},
			Label{AssignTo: &p.counts, Text: "—", TextColor: uiInk, Font: uiFont(15, true), NoPrefix: true},
			VSpacer{StretchFactor: 1},
			Label{AssignTo: &p.countsSubCap, Text: tr("总成员 / 在线数", "Total / Active"), TextColor: uiMuted, Font: uiMonoFont(8, false), NoPrefix: true, EllipsisMode: EllipsisEnd},
		}}, fill: uiWhite, radius: 12, border: borderColor(uiBorder), hud: false},
		roundView{Composite: Composite{MinSize: Size{Width: 165, Height: 94}, MaxSize: Size{Height: 94}, StretchFactor: 1, Background: SolidColorBrush{Color: uiWhite}, Layout: VBox{Margins: Margins{Left: 16, Top: 14, Right: 16, Bottom: 14}, Spacing: 4}, Children: []Widget{
			Label{AssignTo: &p.relayCardCap, Text: tr("中继 / 端口映射", "Relay / Port Maps"), TextColor: uiMuted, Font: uiFont(9, false), NoPrefix: true},
			Composite{Background: SolidColorBrush{Color: uiWhite}, Layout: HBox{MarginsZero: true, Spacing: 6}, Children: []Widget{
				Label{AssignTo: &p.relay, Text: "—", TextColor: uiInk, Font: uiFont(15, true), NoPrefix: true},
				Label{Text: "/", TextColor: uiMuted, Font: uiFont(12, false), NoPrefix: true},
				Label{AssignTo: &p.frp, Text: "—", TextColor: uiBlue, Font: uiFont(15, true), NoPrefix: true},
				HSpacer{},
			}},
			VSpacer{StretchFactor: 1},
			Label{AssignTo: &p.portLimit, Text: tr("映射端口 60000-61000", "Ports 60000-61000"), TextColor: uiMuted, Font: uiMonoFont(8, false), NoPrefix: true, EllipsisMode: EllipsisEnd},
		}}, fill: uiWhite, radius: 12, border: borderColor(uiBorder), hud: false},
	}}

	configTile := func(capAssign, valAssign **walk.Label, btnAssign **walk.PushButton, capText, valText, btnText string, valMono bool, btnW int, clicked func()) roundView {
		valFont := uiFont(10, true)
		if valMono {
			valFont = uiMonoFont(10, true)
		}
		return roundView{Composite: Composite{MinSize: Size{Height: 54}, MaxSize: Size{Height: 54}, StretchFactor: 1, Background: SolidColorBrush{Color: uiTableAlt}, Layout: HBox{Margins: Margins{Left: 14, Top: 8, Right: 12, Bottom: 8}, Spacing: 10}, Children: []Widget{
			Composite{StretchFactor: 1, MinSize: Size{Width: 130}, Background: SolidColorBrush{Color: uiTableAlt}, Layout: VBox{MarginsZero: true, Spacing: 2}, Children: []Widget{
				Composite{Background: SolidColorBrush{Color: uiTableAlt}, Layout: HBox{MarginsZero: true}, Children: []Widget{
					Label{AssignTo: capAssign, Text: capText, TextColor: uiMuted, Font: uiFont(8, false), NoPrefix: true},
					HSpacer{},
				}},
				Composite{Background: SolidColorBrush{Color: uiTableAlt}, Layout: HBox{MarginsZero: true}, Children: []Widget{
					Label{AssignTo: valAssign, Text: valText, TextColor: uiInk, Font: valFont, NoPrefix: true, EllipsisMode: EllipsisEnd},
					HSpacer{},
				}},
			}},
			compactButton(btnAssign, btnText, btnSecondary, btnW, clicked),
		}}, fill: uiTableAlt, radius: 10, border: borderColor(uiBorder), hud: false}
	}

	configCard := roundView{Composite: Composite{Background: SolidColorBrush{Color: uiWhite}, Layout: VBox{Margins: Margins{Left: 18, Top: 12, Right: 18, Bottom: 12}, Spacing: 10}, Children: []Widget{
		Composite{Background: SolidColorBrush{Color: uiWhite}, Layout: HBox{MarginsZero: true}, Children: []Widget{
			Label{AssignTo: &p.configBarTitle, Text: tr("服务端与网络配置", "Service & Network Settings"), TextColor: uiInk, Font: uiFont(11, true), NoPrefix: true},
			HSpacer{},
		}},
		Composite{Background: SolidColorBrush{Color: uiWhite}, Layout: HBox{MarginsZero: true, Spacing: 10}, Children: []Widget{
			configTile(&p.networkConfigCap, &p.networkConfigVal, &p.networkNameBtn, tr("网络名称", "Network Name"), "—", tr("修改名称", "Rename"), false, 84, p.editNetworkName),
			configTile(&p.portConfigCap, &p.portConfigVal, &p.portRange, tr("端口范围", "Port Range"), "60000–61000", tr("修改范围", "Edit Range"), true, 92, p.editPortRange),
			configTile(&p.displayConfigCap, &p.displayConfigVal, &p.serverDisplayBtn, tr("服务器显示", "Server Display"), tr("IP 地址", "IP Address"), tr("显示设置", "Configure"), false, 92, p.editServerDisplay),
		}},
	}}, fill: uiWhite, radius: 12, border: borderColor(uiBorder), hud: false}

	actions := Composite{Background: SolidColorBrush{Color: uiWhite}, Layout: HBox{MarginsZero: true, Spacing: 6}, Children: []Widget{
		compactButton(&p.rename, tr("重命名", "Rename"), btnSecondary, 76, p.renameSelected),
		compactButton(&p.disconnect, tr("断开", "Disconnect"), btnDanger, 90, p.disconnectSelected),
		compactButton(&p.kick, tr("踢出", "Kick"), btnDanger, 64, p.kickSelected),
		compactButton(&p.ban, tr("拉黑", "Ban"), btnDanger, 64, p.banSelected),
		compactButton(&p.unban, tr("解封", "Unban"), btnSecondary, 68, p.unbanSelected),
		compactButton(&p.refresh, tr("刷新", "Refresh"), btnSecondary, 76, p.refreshData),
	}}
	membersCard := roundView{Composite: Composite{MinSize: Size{Width: 760}, Background: SolidColorBrush{Color: uiWhite}, StretchFactor: 1, Layout: VBox{Margins: Margins{Left: 18, Top: 14, Right: 18, Bottom: 14}, Spacing: 10}, Children: []Widget{
		Composite{Background: SolidColorBrush{Color: uiWhite}, Layout: HBox{MarginsZero: true, Spacing: 8}, Children: []Widget{
			Label{AssignTo: &p.membersTitle, Text: tr("成员列表", "Members"), TextColor: uiInk, Font: uiFont(12, true), NoPrefix: true},
			HSpacer{},
			actions,
		}},
		TableView{AssignTo: &p.table, Model: p.model, Background: SolidColorBrush{Color: uiWhite}, Font: uiFont(9, false), StretchFactor: 1, MinSize: Size{Height: 240}, CustomRowHeight: 34, CustomHeaderHeight: 30, LastColumnStretched: true, SelectionHiddenWithoutFocus: true, AlternatingRowBG: true, OnCurrentIndexChanged: p.updateButtons, Columns: []TableViewColumn{
			{Title: tr("名称", "Name"), Width: 170},
			{Title: tr("设备 ID", "Device ID"), Width: 136},
			{Title: tr("虚拟 IP", "Virtual IP"), Width: 124},
			{Title: tr("状态", "Status"), Width: 86},
			{Title: "Relay", Width: 72},
			{Title: "FRP", Width: 72},
		}, StyleCell: p.styleCell},
	}}, fill: uiWhite, radius: 12, border: borderColor(uiBorder), hud: false}
	membersCard.Composite.StretchFactor = 1

	p.updateButtons()
	return Composite{AssignTo: &p.page, Visible: false, StretchFactor: 1, Background: SolidColorBrush{Color: uiBackground}, Layout: VBox{Margins: Margins{Left: 20, Top: 16, Right: 20, Bottom: 18}, Spacing: 12, Alignment: AlignHNearVNear}, Children: []Widget{
		overviewRow, configCard, membersCard,
	}}
}

func (p *adminPanel) retranslate() {
	if p == nil {
		return
	}
	if p.serverCardCap != nil {
		_ = p.serverCardCap.SetText(tr("服务端", "Server"))
	}
	if p.networkCardCap != nil {
		_ = p.networkCardCap.SetText(tr("私有网络", "Network"))
	}
	if p.countsCardCap != nil {
		_ = p.countsCardCap.SetText(tr("成员 / 在线", "Members / Online"))
	}
	if p.countsSubCap != nil {
		_ = p.countsSubCap.SetText(tr("总成员 / 在线数", "Total / Active"))
	}
	if p.relayCardCap != nil {
		_ = p.relayCardCap.SetText(tr("中继 / 端口映射", "Relay / Port Maps"))
	}
	if p.membersTitle != nil {
		_ = p.membersTitle.SetText(tr("成员列表", "Members"))
	}
	if p.configBarTitle != nil {
		_ = p.configBarTitle.SetText(tr("服务端与网络配置", "Service & Network Settings"))
	}
	if p.networkConfigCap != nil {
		_ = p.networkConfigCap.SetText(tr("网络名称", "Network Name"))
	}
	if p.portConfigCap != nil {
		_ = p.portConfigCap.SetText(tr("端口范围", "Port Range"))
	}
	if p.displayConfigCap != nil {
		_ = p.displayConfigCap.SetText(tr("服务器显示", "Server Display"))
	}
	for _, pair := range []struct {
		btn    *walk.PushButton
		zh, en string
	}{
		{p.rename, "重命名", "Rename"},
		{p.disconnect, "断开", "Disconnect"},
		{p.kick, "踢出", "Kick"},
		{p.ban, "拉黑", "Ban"},
		{p.unban, "解封", "Unban"},
		{p.networkNameBtn, "修改名称", "Rename"},
		{p.portRange, "修改范围", "Edit Range"},
		{p.serverDisplayBtn, "显示设置", "Configure"},
		{p.refresh, "刷新", "Refresh"},
	} {
		if pair.btn != nil {
			_ = pair.btn.SetText(tr(pair.zh, pair.en))
			_ = pair.btn.Invalidate()
		}
	}
	if p.overview != nil {
		p.apply(*p.overview, clientapi.AdminMembers{Members: p.members}, p.sessions)
	}
	if p.table != nil && !p.table.IsDisposed() {
		_ = p.table.Invalidate()
	}
}

func (p *adminPanel) styleCell(s *walk.CellStyle) {
	if s.Row() < 0 {
		titles := []string{tr("名称", "Name"), tr("设备 ID", "Device ID"), tr("虚拟 IP", "Virtual IP"), tr("状态", "Status"), "Relay", "FRP"}
		if s.Col() >= 0 && s.Col() < len(titles) {
			styleTableHeader(s, titles[s.Col()], false)
		}
		return
	}
	s.TextColor = uiInk
	if s.Row()%2 == 1 {
		s.BackgroundColor = uiTableAlt
	} else {
		s.BackgroundColor = uiWhite
	}
	if s.Row() < 0 || s.Row() >= len(p.members) {
		return
	}
	member := p.members[s.Row()]
	if member.Blocked {
		s.TextColor = uiDanger
	} else if member.Online && s.Col() == 3 {
		s.TextColor = uiSuccess
	} else if s.Col() == 2 {
		s.TextColor = uiBlue
	}
}

func (p *adminPanel) reset() {
	if p == nil {
		return
	}
	p.overview = nil
	p.members = nil
	p.sessions = nil
	p.busy = false
	if p.model != nil {
		p.model.setRows(nil)
	}
	for _, label := range []*walk.Label{p.service, p.network, p.counts, p.relay, p.frp, p.portLimit, p.endpoint, p.updated, p.networkConfigVal, p.portConfigVal, p.displayConfigVal} {
		if label != nil {
			label.SetText("—")
		}
	}
	p.setBusy(false)
}

func (p *adminPanel) setBusy(busy bool) {
	p.busy = busy
	if p.refresh != nil {
		p.refresh.SetEnabled(!busy)
		_ = p.refresh.Invalidate()
	}
	if p.networkNameBtn != nil {
		p.networkNameBtn.SetEnabled(!busy)
		_ = p.networkNameBtn.Invalidate()
	}
	if p.portRange != nil {
		p.portRange.SetEnabled(!busy)
		_ = p.portRange.Invalidate()
	}
	if p.serverDisplayBtn != nil {
		p.serverDisplayBtn.SetEnabled(!busy)
		_ = p.serverDisplayBtn.Invalidate()
	}
	p.refreshButtons()
}

func (p *adminPanel) refreshButtons() {
	member, selected := p.selectedMember()
	enabled := !p.busy && selected
	for _, button := range []*walk.PushButton{p.rename, p.disconnect, p.kick, p.ban, p.unban} {
		if button != nil {
			button.SetEnabled(enabled)
		}
	}
	if selected {
		if p.disconnect != nil {
			p.disconnect.SetEnabled(enabled && member.Online)
		}
		if p.ban != nil {
			p.ban.SetEnabled(enabled && !member.Blocked)
		}
		if p.unban != nil {
			p.unban.SetEnabled(enabled && member.Blocked)
		}
	}
	for _, button := range []*walk.PushButton{p.rename, p.disconnect, p.kick, p.ban, p.unban} {
		if button != nil {
			_ = button.Invalidate()
		}
	}
}

func (p *adminPanel) updateButtons() { p.refreshButtons() }

func (p *adminPanel) selectedMember() (clientapi.AdminMember, bool) {
	if p.table == nil {
		return clientapi.AdminMember{}, false
	}
	index := p.table.CurrentIndex()
	if index < 0 || index >= len(p.members) {
		return clientapi.AdminMember{}, false
	}
	return p.members[index], true
}

func (p *adminPanel) refreshData() {
	if p == nil || p.desktop == nil || p.desktop.adminAPI == nil {
		p.reset()
		return
	}
	if p.busy {
		return
	}
	p.setBusy(true)
	if p.updated != nil {
		p.updated.SetText(tr("正在刷新…", "Refreshing…"))
	}
	api := p.desktop.adminAPI
	go func() {
		overview, err := api.Overview()
		if err != nil {
			p.finishRefresh(err)
			return
		}
		members, err := api.Members()
		if err != nil {
			p.finishRefresh(err)
			return
		}
		sessions, sessionErr := api.RelaySessions()
		if sessionErr != nil && isAdminAuthFailure(sessionErr) {
			p.finishRefresh(sessionErr)
			return
		}
		p.desktop.ui(func() {
			p.apply(overview, members, sessions)
			p.setBusy(false)
		})
	}()
}

func (p *adminPanel) finishRefresh(err error) {
	p.desktop.ui(func() {
		p.setBusy(false)
		if isAdminAuthFailure(err) {
			p.desktop.setAdminMode(false, "")
			p.desktop.showNotice(clientui.Feedback{Title: tr("管理权限已失效", "Admin access expired"), Message: tr("请输入当前管理令牌重新加入网络。", "Re-enter the current admin token to restore access.")})
			return
		}
		p.showError(tr("刷新管理面板", "Refresh admin panel"), err)
	})
}

func (p *adminPanel) apply(overview clientapi.AdminOverview, members clientapi.AdminMembers, sessions []clientapi.AdminRelaySession) {
	p.overview = &overview
	p.members = append(p.members[:0], members.Members...)
	p.sessions = append(p.sessions[:0], sessions...)

	rows := make([][]string, 0, len(p.members))
	for _, member := range p.members {
		state := tr("离线", "Offline")
		if member.Blocked {
			state = tr("已拉黑", "Banned")
		} else if member.Online {
			state = tr("在线", "Online")
		}
		rows = append(rows, []string{
			member.Name,
			shortAdminID(member.ID),
			member.VirtualIP,
			state,
			strconv.Itoa(member.RelayCount),
			strconv.Itoa(member.FRPLeases),
		})
	}
	p.model.setRows(rows)

	p.service.SetText(tr("服务端 ", "Server ") + overview.Version)
	endpoint := strings.TrimSpace(overview.ControlListen)
	if !strings.Contains(strings.ToUpper(endpoint), "TLS") {
		if overview.ControlTLS {
			endpoint += " · TLS"
		} else {
			endpoint += tr(" · 明文", " · Plain")
		}
	}
	if strings.TrimSpace(overview.AdminListen) != "" {
		endpoint += tr(" · 管理 ", " · Admin ") + strings.TrimSpace(overview.AdminListen)
	}
	p.endpoint.SetText(endpoint)
	p.network.SetText(overview.Network.Name)
	p.counts.SetText(fmt.Sprintf("%d / %d", overview.MemberCount, overview.OnlineCount))
	p.relay.SetText(strconv.Itoa(overview.RelaySessions))
	p.frp.SetText(strconv.Itoa(overview.FRPLeaseCount))
	portStart, portEnd := overview.FRPPortStart, overview.FRPPortEnd
	if portStart < 1 || portEnd > 65535 || portStart > portEnd {
		portStart, portEnd = clientapi.DefaultFRPPortRange.Start, clientapi.DefaultFRPPortRange.End
	}
	if p.portLimit != nil {
		p.portLimit.SetText(trf("映射端口 %d-%d", "Ports %d-%d", portStart, portEnd))
	}
	if p.portConfigVal != nil {
		p.portConfigVal.SetText(fmt.Sprintf("%d–%d", portStart, portEnd))
	}
	if p.networkConfigVal != nil {
		netName := strings.TrimSpace(overview.Network.Name)
		if netName == "" {
			netName = "—"
		}
		p.networkConfigVal.SetText(netName)
	}
	if p.displayConfigVal != nil {
		mode := strings.ToLower(strings.TrimSpace(overview.ServerDisplay.Mode))
		alias := strings.TrimSpace(overview.ServerDisplay.Alias)
		if mode == "alias" && alias != "" {
			p.displayConfigVal.SetText(tr("别名: ", "Alias: ") + alias)
		} else {
			p.displayConfigVal.SetText(tr("IP 地址", "IP Address"))
		}
	}
	if p.desktop != nil {
		p.desktop.applyFRPPortRange(clientapi.PortRange{Start: portStart, End: portEnd})
		p.desktop.serverDisplay = overview.ServerDisplay
		p.desktop.updateConnectedServerDisplays()
	}
	updated := tr("更新于 ", "Updated ") + time.Now().Format("15:04:05")
	if strings.TrimSpace(overview.Network.CIDR) != "" {
		updated = overview.Network.CIDR + " · " + updated
	}
	p.updated.SetText(updated)
	p.refreshButtons()
}

func (p *adminPanel) renameSelected() {
	member, ok := p.selectedMember()
	if !ok {
		return
	}
	var dlg *walk.Dialog
	var name *walk.LineEdit
	var save, cancel *walk.PushButton
	err := (Dialog{
		AssignTo:      &dlg,
		Title:         tr("重命名成员", "Rename Member"),
		Icon:          p.desktop.appIcon,
		Size:          Size{Width: 440, Height: 185},
		MinSize:       Size{Width: 400, Height: 170},
		Font:          uiFont(10, false),
		Background:    SolidColorBrush{Color: uiWhite},
		Layout:        VBox{Margins: Margins{Left: 24, Top: 20, Right: 24, Bottom: 18}, Spacing: 12},
		CancelButton:  &cancel,
		DefaultButton: &save,
		Children: []Widget{
			heading(trf("重命名 “%s”", "Rename %q", member.Name)),
			LineEdit{AssignTo: &name, Text: member.Name, Font: uiFont(9, false), TextColor: uiInk, Background: SolidColorBrush{Color: uiWhite}, MinSize: Size{Width: 380}},
			Composite{Background: SolidColorBrush{Color: uiWhite}, Layout: HBox{MarginsZero: true, Spacing: 8}, Children: []Widget{
				HSpacer{},
				actionButton(&cancel, tr("取消", "Cancel"), false, 78, func() { dlg.Cancel() }),
				actionButton(&save, tr("保存", "Save"), true, 78, func() {
					next := strings.TrimSpace(name.Text())
					if next == "" {
						walk.MsgBox(dlg, tr("名称不能为空", "Name required"), tr("请输入成员名称。", "Please enter a member name."), walk.MsgBoxOK|walk.MsgBoxIconWarning)
						return
					}
					if len([]rune(next)) > 64 {
						walk.MsgBox(dlg, tr("名称过长", "Name too long"), tr("成员名称最多 64 个字符。", "Member name must be at most 64 characters."), walk.MsgBoxOK|walk.MsgBoxIconWarning)
						return
					}
					dlg.Accept()
					p.run(tr("重命名成员", "Rename member"), func(api *clientapi.AdminClient) error {
						_, err := api.RenameMember(member.ID, next)
						return err
					})
				}),
			}},
		},
	}).Create(p.desktop.window)
	if err != nil {
		p.showError(tr("打开重命名窗口", "Open rename dialog"), err)
		return
	}
	defer dlg.Dispose()
	runThemedDialog(dlg)
}

func (p *adminPanel) editNetworkName() {
	if p == nil || p.desktop == nil || p.desktop.adminAPI == nil || p.busy {
		return
	}
	currentName := strings.TrimSpace(p.desktop.membership.Network.Name)
	if p.overview != nil && strings.TrimSpace(p.overview.Network.Name) != "" {
		currentName = strings.TrimSpace(p.overview.Network.Name)
	}
	var dlg *walk.Dialog
	var nameEdit *walk.LineEdit
	var save, cancel *walk.PushButton
	err := (Dialog{
		AssignTo:      &dlg,
		Title:         tr("修改网络名称", "Edit Network Name"),
		Icon:          p.desktop.appIcon,
		Size:          Size{Width: 460, Height: 215},
		MinSize:       Size{Width: 420, Height: 195},
		Font:          uiFont(10, false),
		Background:    SolidColorBrush{Color: uiWhite},
		Layout:        VBox{Margins: Margins{Left: 24, Top: 20, Right: 24, Bottom: 18}, Spacing: 12},
		CancelButton:  &cancel,
		DefaultButton: &save,
		Children: []Widget{
			heading(tr("修改私人网络名称", "Edit Private Network Name")),
			Composite{Background: SolidColorBrush{Color: uiWhite}, Layout: HBox{MarginsZero: true, Spacing: 10}, Children: []Widget{
				formLabel(tr("当前名称", "Current"), 80),
				Label{Text: currentName, TextColor: uiMuted, Font: uiFont(9, true), NoPrefix: true, EllipsisMode: EllipsisEnd, StretchFactor: 1},
			}},
			Composite{Background: SolidColorBrush{Color: uiWhite}, Layout: HBox{MarginsZero: true, Spacing: 10}, Children: []Widget{
				formLabel(tr("新网络名称", "New Name"), 80),
				LineEdit{AssignTo: &nameEdit, Text: currentName, MaxLength: 64, CueBanner: tr("输入新的网络名称（最多 64 字）", "Enter new network name (max 64 chars)"), Font: uiFont(9, false), TextColor: uiInk, Background: SolidColorBrush{Color: uiWhite}, MinSize: Size{Width: 300}},
			}},
			VSpacer{StretchFactor: 1},
			Composite{Background: SolidColorBrush{Color: uiWhite}, Layout: HBox{MarginsZero: true, Spacing: 8}, Children: []Widget{
				HSpacer{},
				actionButton(&cancel, tr("取消", "Cancel"), false, 80, func() { dlg.Cancel() }),
				actionButton(&save, tr("保存", "Save"), true, 80, func() {
					next := strings.TrimSpace(nameEdit.Text())
					if next == "" {
						walk.MsgBox(dlg, tr("名称不能为空", "Name Required"), tr("请输入网络名称。", "Please enter a network name."), walk.MsgBoxOK|walk.MsgBoxIconWarning)
						return
					}
					if len([]rune(next)) > 64 {
						walk.MsgBox(dlg, tr("名称过长", "Name Too Long"), tr("网络名称最多 64 个字符。", "Network name must be at most 64 characters."), walk.MsgBoxOK|walk.MsgBoxIconWarning)
						return
					}
					dlg.Accept()
					p.run(tr("修改网络名称", "Rename network"), func(api *clientapi.AdminClient) error {
						updated, err := api.RenameNetwork(next)
						if err != nil {
							return err
						}
						p.desktop.ui(func() {
							p.desktop.membership.Network.Name = updated.Name
							setLabelIfChanged(p.desktop.networkTitle, updated.Name)
							setLabelIfChanged(p.desktop.offNetwork, updated.Name)
						})
						return nil
					})
				}),
			}},
		},
	}).Create(p.desktop.window)
	if err != nil {
		p.showError(tr("打开网络名称设置", "Open network name settings"), err)
		return
	}
	defer dlg.Dispose()
	runThemedDialog(dlg)
}

func (p *adminPanel) editPortRange() {
	if p == nil || p.desktop == nil || p.desktop.adminAPI == nil || p.busy {
		return
	}
	cur := p.desktop.activeFRPPortRange()
	if p.overview != nil && p.overview.FRPPortStart >= 1 && p.overview.FRPPortEnd <= 65535 && p.overview.FRPPortStart <= p.overview.FRPPortEnd {
		cur = clientapi.PortRange{Start: p.overview.FRPPortStart, End: p.overview.FRPPortEnd}
	}
	var dlg *walk.Dialog
	var startEdit, endEdit *walk.NumberEdit
	var save, cancel *walk.PushButton
	err := (Dialog{
		AssignTo:      &dlg,
		Title:         tr("设置端口映射范围", "Port Mapping Range"),
		Icon:          p.desktop.appIcon,
		Size:          Size{Width: 460, Height: 230},
		MinSize:       Size{Width: 420, Height: 210},
		Font:          uiFont(10, false),
		Background:    SolidColorBrush{Color: uiWhite},
		Layout:        VBox{Margins: Margins{Left: 24, Top: 20, Right: 24, Bottom: 18}, Spacing: 12},
		CancelButton:  &cancel,
		DefaultButton: &save,
		Children: []Widget{
			heading(tr("设置端口映射范围", "Port Mapping Range")),
			Composite{Background: SolidColorBrush{Color: uiWhite}, Layout: HBox{MarginsZero: true, Spacing: 10}, Children: []Widget{
				formLabel(tr("起始端口", "Start Port"), 76),
				NumberEdit{AssignTo: &startEdit, Value: float64(cur.Start), MinValue: 1, MaxValue: 65535, Decimals: 0, Font: uiFont(9, false), TextColor: uiInk, Background: SolidColorBrush{Color: uiWhite}, MinSize: Size{Width: 110}},
				formLabel(tr("结束端口", "End Port"), 76),
				NumberEdit{AssignTo: &endEdit, Value: float64(cur.End), MinValue: 1, MaxValue: 65535, Decimals: 0, Font: uiFont(9, false), TextColor: uiInk, Background: SolidColorBrush{Color: uiWhite}, MinSize: Size{Width: 110}},
				HSpacer{},
			}},
			VSpacer{StretchFactor: 1},
			Composite{Background: SolidColorBrush{Color: uiWhite}, Layout: HBox{MarginsZero: true, Spacing: 8}, Children: []Widget{
				compactButton(nil, tr("恢复默认", "Reset Default"), btnSecondary, 96, func() {
					_ = startEdit.SetValue(float64(clientapi.DefaultFRPPortRange.Start))
					_ = endEdit.SetValue(float64(clientapi.DefaultFRPPortRange.End))
				}),
				HSpacer{},
				actionButton(&cancel, tr("取消", "Cancel"), false, 80, func() { dlg.Cancel() }),
				actionButton(&save, tr("保存", "Save"), true, 80, func() {
					start := int(startEdit.Value())
					end := int(endEdit.Value())
					if start < 1 || end > 65535 || start > end {
						walk.MsgBox(dlg, tr("端口范围无效", "Invalid port range"), tr("请填写 1-65535 之间且起始端口不大于结束端口的区间。", "Use ports 1-65535 with start <= end."), walk.MsgBoxOK|walk.MsgBoxIconWarning)
						return
					}
					dlg.Accept()
					p.run(tr("设置端口范围", "Set port range"), func(api *clientapi.AdminClient) error {
						saved, err := api.SetFRPPortRange(start, end)
						if err != nil {
							return err
						}
						p.desktop.ui(func() {
							p.desktop.applyFRPPortRange(saved)
						})
						return nil
					})
				}),
			}},
		},
	}).Create(p.desktop.window)
	if err != nil {
		p.showError(tr("打开端口范围设置", "Open port range settings"), err)
		return
	}
	defer dlg.Dispose()
	runThemedDialog(dlg)
}

func (p *adminPanel) editServerDisplay() {
	if p == nil || p.desktop == nil || p.desktop.adminAPI == nil || p.busy {
		return
	}
	cur := p.desktop.serverDisplay
	if p.overview != nil && (p.overview.ServerDisplay.Mode != "" || p.overview.ServerDisplay.Alias != "") {
		cur = p.overview.ServerDisplay
	}
	modeIndex := 0
	if strings.EqualFold(strings.TrimSpace(cur.Mode), "alias") {
		modeIndex = 1
	}
	var dlg *walk.Dialog
	var modeBox *walk.ComboBox
	var aliasEdit *walk.LineEdit
	var save, cancel *walk.PushButton
	syncAliasState := func() {
		if aliasEdit == nil || modeBox == nil {
			return
		}
		isAlias := modeBox.CurrentIndex() == 1
		aliasEdit.SetEnabled(isAlias)
	}
	err := (Dialog{
		AssignTo:      &dlg,
		Title:         tr("设置连接服务器显示", "Connected Server Display"),
		Icon:          p.desktop.appIcon,
		Size:          Size{Width: 480, Height: 255},
		MinSize:       Size{Width: 440, Height: 235},
		Font:          uiFont(10, false),
		Background:    SolidColorBrush{Color: uiWhite},
		Layout:        VBox{Margins: Margins{Left: 24, Top: 20, Right: 24, Bottom: 18}, Spacing: 12},
		CancelButton:  &cancel,
		DefaultButton: &save,
		Children: []Widget{
			heading(tr("连接服务器显示方式", "Connected Server Display")),
			Composite{Background: SolidColorBrush{Color: uiWhite}, Layout: HBox{MarginsZero: true, Spacing: 10}, Children: []Widget{
				formLabel(tr("显示模式", "Display Mode"), 92),
				comboBoxView{ComboBox: ComboBox{
					AssignTo:              &modeBox,
					Model:                 []string{tr("显示 IP 地址（可切换隐藏）", "Show IP Address (Toggleable)"), tr("显示自定义别名", "Show Custom Alias")},
					CurrentIndex:          modeIndex,
					Font:                  uiFont(9, false),
					MinSize:               Size{Width: 280, Height: 30},
					MaxSize:               Size{Height: 30},
					OnCurrentIndexChanged: syncAliasState,
				}},
			}},
			Composite{Background: SolidColorBrush{Color: uiWhite}, Layout: HBox{MarginsZero: true, Spacing: 10}, Children: []Widget{
				formLabel(tr("服务器别名", "Server Alias"), 92),
				LineEdit{
					AssignTo:   &aliasEdit,
					Text:       cur.Alias,
					Enabled:    modeIndex == 1,
					CueBanner:  tr("例如：主控中继节点（最多 64 字）", "e.g. Primary Relay Node (max 64 chars)"),
					Font:       uiFont(9, false),
					TextColor:  uiInk,
					Background: SolidColorBrush{Color: uiWhite},
					MinSize:    Size{Width: 280},
				},
			}},
			VSpacer{StretchFactor: 1},
			Composite{Background: SolidColorBrush{Color: uiWhite}, Layout: HBox{MarginsZero: true, Spacing: 8}, Children: []Widget{
				HSpacer{},
				actionButton(&cancel, tr("取消", "Cancel"), false, 80, func() { dlg.Cancel() }),
				actionButton(&save, tr("保存", "Save"), true, 80, func() {
					mode := "ip"
					if modeBox.CurrentIndex() == 1 {
						mode = "alias"
					}
					alias := strings.TrimSpace(aliasEdit.Text())
					if mode == "alias" && alias == "" {
						walk.MsgBox(dlg, tr("别名不能为空", "Alias Required"), tr("选择自定义别名模式时，请输入服务器别名。", "Enter a server alias for custom alias mode."), walk.MsgBoxOK|walk.MsgBoxIconWarning)
						return
					}
					if len([]rune(alias)) > 64 {
						walk.MsgBox(dlg, tr("别名过长", "Alias Too Long"), tr("服务器别名最多 64 个字符。", "Server alias must be at most 64 characters."), walk.MsgBoxOK|walk.MsgBoxIconWarning)
						return
					}
					dlg.Accept()
					p.run(tr("设置连接服务器显示", "Set server display"), func(api *clientapi.AdminClient) error {
						saved, err := api.SetServerDisplay(mode, alias)
						if err != nil {
							return err
						}
						p.desktop.ui(func() {
							p.desktop.serverDisplay = saved
							p.desktop.updateConnectedServerDisplays()
						})
						return nil
					})
				}),
			}},
		},
	}).Create(p.desktop.window)
	if err != nil {
		p.showError(tr("打开服务器显示设置", "Open server display settings"), err)
		return
	}
	defer dlg.Dispose()
	runThemedDialog(dlg)
}

func (p *adminPanel) disconnectSelected() {
	member, ok := p.selectedMember()
	if !ok || !p.confirmAction(tr("断开", "Disconnect"), member, tr("这会关闭该成员当前的 Relay 连接并暂停 FRP 发布，不会撤销成员凭据。", "This closes active relay sessions and pauses FRP leases without revoking credentials.")) {
		return
	}
	p.run(tr("断开成员", "Disconnect member"), func(api *clientapi.AdminClient) error { return api.DisconnectMember(member.ID) })
}

func (p *adminPanel) kickSelected() {
	member, ok := p.selectedMember()
	if !ok || !p.confirmAction(tr("踢出", "Kick"), member, tr("这会撤销该成员当前凭据并清理 Relay/FRP 资源，成员需要重新输入令牌加入。", "This revokes the member's credentials and stops relay/FRP resources.")) {
		return
	}
	p.run(tr("踢出成员", "Kick member"), func(api *clientapi.AdminClient) error { return api.KickMember(member.ID) })
}

func (p *adminPanel) banSelected() {
	member, ok := p.selectedMember()
	if !ok || !p.confirmAction(tr("拉黑", "Ban"), member, tr("拉黑后该成员不能重新加入，直到管理员解封。", "Banned devices cannot rejoin until unbanned.")) {
		return
	}
	p.run(tr("拉黑成员", "Ban member"), func(api *clientapi.AdminClient) error { return api.BanMember(member.ID) })
}

func (p *adminPanel) unbanSelected() {
	member, ok := p.selectedMember()
	if !ok || !p.confirmAction(tr("解封", "Unban"), member, tr("解封只恢复重新申请资格，不会自动恢复旧凭据、Relay 或 FRP。", "Unbanning allows re-enrollment; old credentials are not restored.")) {
		return
	}
	p.run(tr("解封成员", "Unban member"), func(api *clientapi.AdminClient) error {
		_, err := api.UnbanMember(member.ID)
		return err
	})
}

func (p *adminPanel) confirmAction(action string, member clientapi.AdminMember, detail string) bool {
	extra := ""
	if member.ID == p.desktop.identity.DeviceID.String() {
		extra = tr("\n\n注意：这是当前客户端。操作管理身份可能导致管理面板暂时不可用。", "\n\nNote: This is the current device. Modifying it may revoke admin access.")
	}
	message := trf("确定%s成员“%s”（%s）吗？\n\n%s%s", "%s member %q (%s)?\n\n%s%s", action, member.Name, shortAdminID(member.ID), detail, extra)
	return walk.MsgBox(p.desktop.window, tr("确认", "Confirm ")+action, message, walk.MsgBoxYesNo|walk.MsgBoxIconQuestion) == walk.DlgCmdYes
}

func (p *adminPanel) run(action string, request func(*clientapi.AdminClient) error) {
	if p == nil || p.desktop == nil || p.desktop.adminAPI == nil || p.busy {
		return
	}
	p.setBusy(true)
	api := p.desktop.adminAPI
	go func() {
		err := request(api)
		p.desktop.ui(func() {
			p.setBusy(false)
			if err != nil {
				if isAdminAuthFailure(err) {
					p.desktop.setAdminMode(false, "")
					p.desktop.showNotice(clientui.Feedback{Title: tr("管理权限已失效", "Admin access expired"), Message: tr("请输入当前管理令牌重新加入网络。", "Re-enter the current admin token to restore access.")})
					return
				}
				p.showError(action, err)
				return
			}
			p.refreshData()
		})
	}()
}

func (p *adminPanel) showError(action string, err error) {
	if p == nil || p.desktop == nil {
		return
	}
	p.desktop.showError(action, err)
}

func shortAdminID(id string) string {
	if len(id) <= 12 {
		return id
	}
	return id[:8] + "…" + id[len(id)-3:]
}
