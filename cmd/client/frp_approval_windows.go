//go:build windows

package main

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
	"github.com/private-radminlan/lanmesh/core"
	"github.com/private-radminlan/lanmesh/internal/clientui"
	"github.com/private-radminlan/lanmesh/internal/frpauth"
)

type frpServiceTableModel struct {
	walk.TableModelBase
	rows [][]string
}

func (m *frpServiceTableModel) RowCount() int { return len(m.rows) }

func (m *frpServiceTableModel) Value(row, col int) interface{} {
	if row < 0 || row >= len(m.rows) || col < 0 || col >= len(m.rows[row]) {
		return ""
	}
	return m.rows[row][col]
}

func (m *frpServiceTableModel) setRows(rows [][]string) {
	m.rows = rows
	m.PublishRowsReset()
}

func (a *desktop) showFRPServiceCenter() {
	if a.api == nil || a.api.Token == "" {
		a.showNotice(clientui.Feedback{Title: "需要先加入网络", Message: "目标成员服务授权只在已加入 TLAN 网络后可用。"})
		return
	}
	var dlg *walk.Dialog
	var pendingTable, requestedTable *walk.TableView
	var approveButton, denyButton, copyButton, requestButton, refreshButton, closeButton *walk.PushButton
	var statusLabel *walk.Label
	pendingModel := &frpServiceTableModel{}
	requestedModel := &frpServiceTableModel{}
	var pending, requested []frpauth.ServiceResponse
	busy := false

	updateButtons := func() {
		if busy {
			return
		}
		index := -1
		if pendingTable != nil {
			index = pendingTable.CurrentIndex()
		}
		enabled := index >= 0 && index < len(pending)
		if approveButton != nil {
			approveButton.SetEnabled(enabled)
		}
		if denyButton != nil {
			denyButton.SetEnabled(enabled)
		}
		if requestButton != nil {
			requestButton.SetEnabled(!a.frpBusy)
		}
		if copyButton != nil {
			requestIndex := -1
			if requestedTable != nil {
				requestIndex = requestedTable.CurrentIndex()
			}
			copyButton.SetEnabled(requestIndex >= 0 && requestIndex < len(requested))
		}
		if refreshButton != nil {
			refreshButton.SetEnabled(true)
		}
	}

	refresh := func() {
		if busy {
			return
		}
		busy = true
		if statusLabel != nil {
			statusLabel.SetText("正在读取目标成员授权…")
		}
		if refreshButton != nil {
			refreshButton.SetEnabled(false)
		}
		if approveButton != nil {
			approveButton.SetEnabled(false)
		}
		if denyButton != nil {
			denyButton.SetEnabled(false)
		}
		if copyButton != nil {
			copyButton.SetEnabled(false)
		}
		go func() {
			parent := a.ctx
			if parent == nil {
				parent = context.Background()
			}
			ctx, cancel := context.WithTimeout(parent, 10*time.Second)
			api := *a.api
			api.Context = ctx
			pendingServices, pendingErr := api.ListPendingFRPServices()
			requestedServices, requestedErr := api.ListRequestedFRPServices()
			cancel()
			a.ui(func() {
				busy = false
				if dlg == nil || !dlg.Visible() {
					return
				}
				if pendingErr != nil || requestedErr != nil {
					err := pendingErr
					if err == nil {
						err = requestedErr
					}
					statusLabel.SetText("读取失败")
					walk.MsgBox(dlg, "读取目标授权", clientui.Redact(err.Error(), a.api.Token), walk.MsgBoxOK|walk.MsgBoxIconError)
					updateButtons()
					return
				}
				pending = pendingServices
				pendingRows := make([][]string, 0, len(pendingServices))
				for _, service := range pendingServices {
					pendingRows = append(pendingRows, []string{
						service.ID, service.RequesterDeviceID, strings.ToUpper(service.Protocol), strconv.Itoa(service.Port),
						service.Description, service.CreatedAt.Local().Format("01-02 15:04"),
					})
				}
				requested = requestedServices
				requestedRows := make([][]string, 0, len(requestedServices))
				for _, service := range requestedServices {
					requestedRows = append(requestedRows, []string{
						service.ID, service.DeviceID, strings.ToUpper(service.Protocol), strconv.Itoa(service.Port),
						frpApprovalStatusText(service), service.CreatedAt.Local().Format("01-02 15:04"),
					})
				}
				pendingModel.setRows(pendingRows)
				requestedModel.setRows(requestedRows)
				statusLabel.SetText(fmt.Sprintf("待我确认 %d 项 · 我发起的申请 %d 项", len(pendingServices), len(requestedServices)))
				updateButtons()
			})
		}()
	}

	approveOrDeny := func(approve bool) {
		if busy || pendingTable == nil {
			return
		}
		index := pendingTable.CurrentIndex()
		if index < 0 || index >= len(pending) {
			return
		}
		service := pending[index]
		action := "拒绝"
		if approve {
			action = "同意"
		}
		if walk.MsgBox(dlg, action+"目标授权", fmt.Sprintf("确定%s成员 %s 发布 %s:%d 吗？", action, service.RequesterDeviceID, strings.ToUpper(service.Protocol), service.Port), walk.MsgBoxYesNo|walk.MsgBoxIconQuestion) != walk.DlgCmdYes {
			return
		}
		busy = true
		updateButtons()
		go func() {
			parent := a.ctx
			if parent == nil {
				parent = context.Background()
			}
			ctx, cancel := context.WithTimeout(parent, 10*time.Second)
			api := *a.api
			api.Context = ctx
			var err error
			if approve {
				_, err = api.ApproveFRPService(service.ID)
			} else {
				_, err = api.DenyFRPService(service.ID)
			}
			cancel()
			a.ui(func() {
				busy = false
				if dlg == nil || !dlg.Visible() {
					return
				}
				if err != nil {
					walk.MsgBox(dlg, action+"目标授权失败", clientui.Redact(err.Error(), a.api.Token), walk.MsgBoxOK|walk.MsgBoxIconError)
				} else {
					a.showNotice(clientui.Feedback{Title: "目标授权已更新", Message: fmt.Sprintf("服务 %s 已%s。", service.ID, action)})
				}
				refresh()
			})
		}()
	}

	err := (Dialog{
		AssignTo: &dlg, Title: "目标成员服务授权", Icon: a.appIcon,
		Size: Size{Width: 860, Height: 660}, MinSize: Size{Width: 760, Height: 560},
		Font: Font{Family: "Microsoft YaHei UI", PointSize: 10}, Background: SolidColorBrush{Color: uiWhite},
		Layout:       VBox{Margins: Margins{Left: 24, Top: 20, Right: 24, Bottom: 18}, Spacing: 10},
		CancelButton: &closeButton,
		Children: []Widget{
			heading("目标成员服务授权"),
			TextLabel{Text: "目标成员必须先确认，其他成员才能申请发布该成员的服务。拒绝或撤销后，相关 lease 会失效。", TextColor: uiMuted, MinSize: Size{Width: 760}},
			Label{AssignTo: &statusLabel, Text: "正在读取…", TextColor: uiInk, Font: Font{PointSize: 10, Bold: true}, NoPrefix: true},
			Composite{Layout: HBox{MarginsZero: true, Spacing: 8}, Children: []Widget{
				heading("待我确认"), HSpacer{},
				actionButton(&approveButton, "同意选中", true, 92, func() { approveOrDeny(true) }),
				actionButton(&denyButton, "拒绝选中", false, 92, func() { approveOrDeny(false) }),
			}},
			TableView{AssignTo: &pendingTable, Model: pendingModel, MinSize: Size{Height: 170}, StretchFactor: 1, CustomRowHeight: 28, AlternatingRowBG: true, OnCurrentIndexChanged: updateButtons, Columns: []TableViewColumn{
				{Title: "服务 ID", Width: 160}, {Title: "申请设备", Width: 150}, {Title: "协议", Width: 62},
				{Title: "端口", Width: 60}, {Title: "说明", Width: 250}, {Title: "申请时间", Width: 110},
			}},
			Composite{Layout: HBox{MarginsZero: true, Spacing: 8}, Children: []Widget{
				heading("我发起的申请"), HSpacer{},
				actionButton(&copyButton, "复制服务 ID", false, 100, func() {
					if requestedTable == nil {
						return
					}
					index := requestedTable.CurrentIndex()
					if index < 0 || index >= len(requested) {
						return
					}
					if err := walk.Clipboard().SetText(requested[index].ID); err != nil {
						walk.MsgBox(dlg, "复制服务 ID", err.Error(), walk.MsgBoxOK|walk.MsgBoxIconError)
					}
				}),
				actionButton(&requestButton, "申请发布成员服务", true, 150, a.showFRPServiceRequestDialog),
			}},
			TableView{AssignTo: &requestedTable, Model: requestedModel, MinSize: Size{Height: 140}, StretchFactor: 1, CustomRowHeight: 28, AlternatingRowBG: true, OnCurrentIndexChanged: updateButtons, Columns: []TableViewColumn{
				{Title: "服务 ID", Width: 160}, {Title: "目标设备", Width: 150}, {Title: "协议", Width: 62},
				{Title: "端口", Width: 60}, {Title: "状态", Width: 90}, {Title: "申请时间", Width: 110},
			}},
			Composite{Layout: HBox{MarginsZero: true}, Children: []Widget{
				actionButton(&refreshButton, "刷新", false, 78, refresh), HSpacer{},
				actionButton(&closeButton, "关闭", false, 92, func() { dlg.Accept() }),
			}},
		},
	}).Create(a.window)
	if err != nil {
		a.showFRPError("打开目标成员授权", err)
		return
	}
	defer dlg.Dispose()
	refresh()
	dlg.Run()
}

func (a *desktop) showFRPServiceRequestDialog() {
	if a.api == nil || a.api.Token == "" {
		a.showNotice(clientui.Feedback{Title: "需要先加入网络", Message: "申请目标成员服务授权需要已加入 TLAN 网络。"})
		return
	}
	if len(a.members) == 0 {
		if a.membership.Network.ID == "" {
			a.showNotice(clientui.Feedback{Title: "网络信息不可用", Message: "请先恢复或重新加入 TLAN 网络。"})
			return
		}
		networkID := a.membership.Network.ID
		go func() {
			parent := a.ctx
			if parent == nil {
				parent = context.Background()
			}
			ctx, cancel := context.WithTimeout(parent, 8*time.Second)
			api := *a.api
			api.Context = ctx
			devices, err := api.ListDevices(coreNetworkID(networkID))
			cancel()
			a.ui(func() {
				if err != nil {
					a.showError("读取网络成员", err)
					return
				}
				a.members = devices
				a.showFRPServiceRequestDialog()
			})
		}()
		return
	}
	targets := make([]string, 0, len(a.members))
	targetIDs := make([]string, 0, len(a.members))
	for _, member := range a.members {
		if member.ID == a.identity.DeviceID.String() {
			continue
		}
		targets = append(targets, member.Name+" · "+member.VirtualIP)
		targetIDs = append(targetIDs, member.ID)
	}
	if len(targetIDs) == 0 {
		a.showNotice(clientui.Feedback{Title: "没有可选成员", Message: "当前网络中没有其他成员可作为目标。"})
		return
	}
	var dlg *walk.Dialog
	var targetBox, protocolBox *walk.ComboBox
	var portEdit, descriptionEdit *walk.LineEdit
	var submitButton, closeButton *walk.PushButton
	err := (Dialog{
		AssignTo: &dlg, Title: "申请目标成员服务授权", Icon: a.appIcon,
		Size: Size{Width: 560, Height: 390}, MinSize: Size{Width: 500, Height: 350},
		Font: Font{Family: "Microsoft YaHei UI", PointSize: 10}, Background: SolidColorBrush{Color: uiWhite},
		Layout:       VBox{Margins: Margins{Left: 26, Top: 22, Right: 26, Bottom: 20}, Spacing: 12},
		CancelButton: &closeButton, DefaultButton: &submitButton,
		Children: []Widget{
			heading("申请发布成员服务"),
			TextLabel{Text: "申请会发送给目标成员确认。确认前不会签发 lease；批准后把返回的服务 ID 填入 Mesh 规则。", TextColor: uiMuted, MinSize: Size{Width: 500}},
			Composite{Layout: HBox{MarginsZero: true, Spacing: 10}, Children: []Widget{
				Label{Text: "目标成员", MinSize: Size{Width: 78}}, ComboBox{AssignTo: &targetBox, Model: targets, CurrentIndex: 0, MinSize: Size{Width: 390}},
			}},
			Composite{Layout: HBox{MarginsZero: true, Spacing: 10}, Children: []Widget{
				Label{Text: "协议", MinSize: Size{Width: 78}}, ComboBox{AssignTo: &protocolBox, Model: []string{"TCP", "UDP"}, CurrentIndex: 0, MinSize: Size{Width: 120}},
				Label{Text: "服务端口", MinSize: Size{Width: 78}}, LineEdit{AssignTo: &portEdit, CueBanner: "例如 25565", MinSize: Size{Width: 170}},
			}},
			Composite{Layout: HBox{MarginsZero: true, Spacing: 10}, Children: []Widget{
				Label{Text: "说明", MinSize: Size{Width: 78}}, LineEdit{AssignTo: &descriptionEdit, CueBanner: "例如：游戏服务器", MinSize: Size{Width: 390}},
			}},
			VSpacer{},
			Composite{Layout: HBox{MarginsZero: true}, Children: []Widget{
				HSpacer{}, actionButton(&closeButton, "取消", false, 92, func() { dlg.Cancel() }),
				actionButton(&submitButton, "发送申请", true, 110, func() {
					index := targetBox.CurrentIndex()
					if index < 0 || index >= len(targetIDs) {
						return
					}
					port, err := strconv.Atoi(strings.TrimSpace(portEdit.Text()))
					if err != nil || port < 1 || port > 65535 {
						walk.MsgBox(dlg, "端口不正确", "服务端口必须是 1-65535 的数字。", walk.MsgBoxOK|walk.MsgBoxIconWarning)
						return
					}
					protocol := "tcp"
					if protocolBox.CurrentIndex() == 1 {
						protocol = "udp"
					}
					submitButton.SetEnabled(false)
					go func() {
						parent := a.ctx
						if parent == nil {
							parent = context.Background()
						}
						ctx, cancel := context.WithTimeout(parent, 10*time.Second)
						api := *a.api
						api.Context = ctx
						service, err := api.RequestFRPService(targetIDs[index], "", protocol, port, strings.TrimSpace(descriptionEdit.Text()), time.Hour)
						cancel()
						a.ui(func() {
							submitButton.SetEnabled(true)
							if err != nil {
								walk.MsgBox(dlg, "发送申请失败", clientui.Redact(err.Error(), a.api.Token), walk.MsgBoxOK|walk.MsgBoxIconError)
								return
							}
							dlg.Accept()
							_ = walk.Clipboard().SetText(service.ID)
							a.showNotice(clientui.Feedback{Title: "申请已发送", Message: fmt.Sprintf("服务 ID：%s 已复制到剪贴板。目标成员确认后即可用于 Mesh 发布规则。", service.ID)})
						})
					}()
				}),
			}},
		},
	}).Create(a.window)
	if err != nil {
		a.showFRPError("申请目标成员服务", err)
		return
	}
	defer dlg.Dispose()
	dlg.Run()
}

func coreNetworkID(value string) core.NetworkID { return core.NetworkID(value) }

func frpApprovalStatusText(service frpauth.ServiceResponse) string {
	if service.ApprovalStatus == frpauth.ServiceApprovalDenied || service.DeniedAt != nil {
		return "已拒绝"
	}
	if service.RevokedAt != nil {
		return "已撤销"
	}
	if !service.ExpiresAt.IsZero() && !time.Now().Before(service.ExpiresAt) {
		return "已过期"
	}
	switch service.ApprovalStatus {
	case frpauth.ServiceApprovalPending:
		return "待确认"
	case frpauth.ServiceApprovalApproved:
		return "已批准"
	default:
		return service.ApprovalStatus
	}
}
