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
	ban        *walk.PushButton
	unban      *walk.PushButton

	service  *walk.Label
	network  *walk.Label
	counts   *walk.Label
	relay    *walk.Label
	frp      *walk.Label
	endpoint *walk.Label
	updated  *walk.Label

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
	refresh := actionButton(&p.refresh, "刷新", false, 72, p.refreshData)
	header := pageHeader("管理面板", "⚙", refresh)
	header.Row = 0

	banner := roundView{Composite: Composite{MinSize: Size{Width: 760}, Background: SolidColorBrush{Color: uiBlueSoft}, Layout: HBox{Margins: Margins{Left: 16, Top: 10, Right: 16, Bottom: 10}, Spacing: 10}, Children: []Widget{
		Label{Text: "A", TextColor: uiWhite, Background: SolidColorBrush{Color: uiBlue}, Font: Font{Bold: true, PointSize: 9}, TextAlignment: AlignCenter, MinSize: Size{Width: 20, Height: 20}, MaxSize: Size{Width: 20, Height: 20}, NoPrefix: true},
		Label{Text: "当前为管理令牌登录。成员管理操作通过控制面管理接口执行，不会替换当前成员凭据。", TextColor: uiInk, NoPrefix: true, StretchFactor: 1},
	}}, fill: uiBlueSoft, radius: 8}
	banner.Row = 1

	overviewCard := roundView{Composite: Composite{MinSize: Size{Width: 760}, Background: SolidColorBrush{Color: uiWhite}, Layout: VBox{Margins: Margins{Left: 20, Top: 16, Right: 20, Bottom: 16}, Spacing: 10}, Children: []Widget{
		Composite{Layout: HBox{MarginsZero: true, Spacing: 16}, Children: []Widget{
			Composite{MinSize: Size{Width: 380}, MaxSize: Size{Width: 430}, Background: SolidColorBrush{Color: uiWhite}, Layout: VBox{MarginsZero: true, Spacing: 2}, Children: []Widget{
				caption("服务器"),
				Label{AssignTo: &p.service, Text: "正在读取…", MinSize: Size{Width: 340}, TextColor: uiInk, Font: Font{PointSize: 13, Bold: true}, NoPrefix: true, EllipsisMode: EllipsisEnd},
				Label{AssignTo: &p.endpoint, Text: "", MinSize: Size{Width: 340}, TextColor: uiMuted, NoPrefix: true, EllipsisMode: EllipsisEnd},
			}},
			Composite{MinSize: Size{Width: 280}, MaxSize: Size{Width: 330}, Background: SolidColorBrush{Color: uiWhite}, Layout: VBox{MarginsZero: true, Spacing: 2}, Children: []Widget{
				caption("当前网络"),
				Label{AssignTo: &p.network, Text: "—", TextColor: uiBlue, Font: Font{PointSize: 12, Bold: true}, NoPrefix: true, EllipsisMode: EllipsisEnd},
				Label{AssignTo: &p.updated, Text: "", TextColor: uiMuted, NoPrefix: true},
			}},
		}},
		Composite{Layout: HBox{MarginsZero: true, Spacing: 12}, Children: []Widget{
			p.metric("成员 / 在线", &p.counts),
			p.metric("Relay 会话", &p.relay),
			p.metric("FRP 租约", &p.frp),
		}},
	}}, fill: uiWhite, radius: 12, border: borderColor(uiBorder)}
	overviewCard.Row = 2

	actions := Composite{Layout: HBox{MarginsZero: true, Spacing: 8}, Children: []Widget{
		actionButton(&p.rename, "重命名", false, 78, p.renameSelected),
		actionButton(&p.disconnect, "断开", false, 66, p.disconnectSelected),
		actionButton(&p.kick, "踢出", false, 66, p.kickSelected),
		actionButton(&p.ban, "拉黑", false, 66, p.banSelected),
		actionButton(&p.unban, "解封", false, 66, p.unbanSelected),
		HSpacer{},
		Label{Text: "Relay 和 FRP 数量为当前设备资源计数", TextColor: uiMuted, Font: Font{PointSize: 8}, NoPrefix: true},
	}}
	membersCard := roundView{Composite: Composite{MinSize: Size{Width: 760}, Background: SolidColorBrush{Color: uiWhite}, StretchFactor: 1, Layout: VBox{Margins: Margins{Left: 16, Top: 12, Right: 16, Bottom: 12}, Spacing: 8}, Children: []Widget{
		Composite{Layout: HBox{MarginsZero: true, Spacing: 8}, Children: []Widget{
			Label{Text: "成员管理", TextColor: uiInk, Font: Font{PointSize: 11, Bold: true}, NoPrefix: true},
			HSpacer{},
			actions,
		}},
		TableView{AssignTo: &p.table, Model: p.model, Background: SolidColorBrush{Color: uiWhite}, StretchFactor: 1, MinSize: Size{Height: 240}, CustomRowHeight: 30, CustomHeaderHeight: 28, LastColumnStretched: true, SelectionHiddenWithoutFocus: true, AlternatingRowBG: true, OnCurrentIndexChanged: p.updateButtons, Columns: []TableViewColumn{
			{Title: "名称", Width: 150},
			{Title: "设备 ID", Width: 126},
			{Title: "虚拟 IP", Width: 112},
			{Title: "状态", Width: 76},
			{Title: "Relay", Width: 66},
			{Title: "FRP", Width: 66},
		}, StyleCell: p.styleCell},
	}}, fill: uiWhite, radius: 12, border: borderColor(uiBorder)}
	membersCard.Composite.StretchFactor = 1
	membersCard.Row = 3

	p.updateButtons()
	return Composite{AssignTo: &p.page, Visible: false, StretchFactor: 1, Background: SolidColorBrush{Color: uiBackground}, Layout: VBox{Margins: Margins{Left: 20, Top: 14, Right: 20, Bottom: 16}, Spacing: 10, Alignment: AlignHNearVNear}, Children: []Widget{
		banner, header, overviewCard, membersCard,
	}}
}

func (p *adminPanel) metric(captionText string, assign **walk.Label) Composite {
	return Composite{StretchFactor: 1, Background: SolidColorBrush{Color: uiTableAlt}, Layout: VBox{Margins: Margins{Left: 12, Top: 9, Right: 12, Bottom: 9}, Spacing: 2}, Children: []Widget{
		caption(captionText),
		Label{AssignTo: assign, Text: "—", TextColor: uiInk, Font: Font{PointSize: 13, Bold: true}, NoPrefix: true, EllipsisMode: EllipsisEnd},
	}}
}

func (p *adminPanel) styleCell(s *walk.CellStyle) {
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
		s.TextColor = walk.RGB(185, 28, 28)
	} else if member.Online && s.Col() == 3 {
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
	for _, label := range []*walk.Label{p.service, p.network, p.counts, p.relay, p.frp, p.endpoint, p.updated} {
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
	if !selected {
		return
	}
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
		p.updated.SetText("正在刷新…")
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
			p.desktop.showNotice(clientui.Feedback{Title: "管理权限已失效", Message: "请输入当前管理令牌重新加入网络。"})
			return
		}
		p.showError("刷新管理面板", err)
	})
}

func (p *adminPanel) apply(overview clientapi.AdminOverview, members clientapi.AdminMembers, sessions []clientapi.AdminRelaySession) {
	p.overview = &overview
	p.members = append(p.members[:0], members.Members...)
	p.sessions = append(p.sessions[:0], sessions...)

	rows := make([][]string, 0, len(p.members))
	for _, member := range p.members {
		state := "离线"
		if member.Blocked {
			state = "已拉黑"
		} else if member.Online {
			state = "在线"
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

	p.service.SetText("服务端 " + overview.Version)
	endpoint := overview.Service + " · " + overview.ControlListen
	if overview.ControlTLS {
		endpoint += " · TLS"
	} else {
		endpoint += " · 明文"
	}
	p.endpoint.SetText(endpoint)
	p.network.SetText(fmt.Sprintf("%s · %s", overview.Network.Name, overview.Network.CIDR))
	p.counts.SetText(fmt.Sprintf("%d / %d", overview.MemberCount, overview.OnlineCount))
	p.relay.SetText(strconv.Itoa(overview.RelaySessions))
	p.frp.SetText(strconv.Itoa(overview.FRPLeaseCount))
	p.updated.SetText("刷新于 " + time.Now().Format("15:04:05"))
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
		Title:         "重命名成员",
		Icon:          p.desktop.appIcon,
		Size:          Size{Width: 460, Height: 190},
		MinSize:       Size{Width: 420, Height: 170},
		Font:          Font{Family: "Microsoft YaHei UI", PointSize: 10},
		Background:    SolidColorBrush{Color: uiWhite},
		Layout:        VBox{Margins: Margins{Left: 24, Top: 20, Right: 24, Bottom: 18}, Spacing: 12},
		CancelButton:  &cancel,
		DefaultButton: &save,
		Children: []Widget{
			heading("成员 “" + member.Name + "”"),
			TextLabel{Text: "名称会显示在成员列表和 FRP 授权中。", TextColor: uiMuted, MinSize: Size{Width: 380}},
			LineEdit{AssignTo: &name, Text: member.Name, MinSize: Size{Width: 380}},
			Composite{Layout: HBox{MarginsZero: true, Spacing: 8}, Children: []Widget{
				HSpacer{},
				actionButton(&cancel, "取消", false, 78, func() { dlg.Cancel() }),
				actionButton(&save, "保存", true, 78, func() {
					next := strings.TrimSpace(name.Text())
					if next == "" {
						walk.MsgBox(dlg, "名称不能为空", "请输入成员名称。", walk.MsgBoxOK|walk.MsgBoxIconWarning)
						return
					}
					if len([]rune(next)) > 64 {
						walk.MsgBox(dlg, "名称过长", "成员名称最多 64 个字符。", walk.MsgBoxOK|walk.MsgBoxIconWarning)
						return
					}
					dlg.Accept()
					p.run("重命名成员", func(api *clientapi.AdminClient) error {
						_, err := api.RenameMember(member.ID, next)
						return err
					})
				}),
			}},
		},
	}).Create(p.desktop.window)
	if err != nil {
		p.showError("打开重命名窗口", err)
		return
	}
	defer dlg.Dispose()
	dlg.Run()
}

func (p *adminPanel) disconnectSelected() {
	member, ok := p.selectedMember()
	if !ok || !p.confirmAction("断开", member, "这会关闭该成员当前的 Relay 连接并暂停 FRP 发布，不会撤销成员凭据。") {
		return
	}
	p.run("断开成员", func(api *clientapi.AdminClient) error { return api.DisconnectMember(member.ID) })
}

func (p *adminPanel) kickSelected() {
	member, ok := p.selectedMember()
	if !ok || !p.confirmAction("踢出", member, "这会撤销该成员当前凭据并清理 Relay/FRP 资源，成员需要重新输入令牌加入。") {
		return
	}
	p.run("踢出成员", func(api *clientapi.AdminClient) error { return api.KickMember(member.ID) })
}

func (p *adminPanel) banSelected() {
	member, ok := p.selectedMember()
	if !ok || !p.confirmAction("拉黑", member, "拉黑后该成员不能重新加入，直到管理员解封。") {
		return
	}
	p.run("拉黑成员", func(api *clientapi.AdminClient) error { return api.BanMember(member.ID) })
}

func (p *adminPanel) unbanSelected() {
	member, ok := p.selectedMember()
	if !ok || !p.confirmAction("解封", member, "解封只恢复重新申请资格，不会自动恢复旧凭据、Relay 或 FRP。") {
		return
	}
	p.run("解封成员", func(api *clientapi.AdminClient) error {
		_, err := api.UnbanMember(member.ID)
		return err
	})
}

func (p *adminPanel) confirmAction(action string, member clientapi.AdminMember, detail string) bool {
	extra := ""
	if member.ID == p.desktop.identity.DeviceID.String() {
		extra = "\n\n注意：这是当前客户端。操作管理身份可能导致管理面板暂时不可用。"
	}
	message := fmt.Sprintf("确定%s成员“%s”（%s）吗？\n\n%s%s", action, member.Name, shortAdminID(member.ID), detail, extra)
	return walk.MsgBox(p.desktop.window, "确认"+action, message, walk.MsgBoxYesNo|walk.MsgBoxIconQuestion) == walk.DlgCmdYes
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
					p.desktop.showNotice(clientui.Feedback{Title: "管理权限已失效", Message: "请输入当前管理令牌重新加入网络。"})
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
