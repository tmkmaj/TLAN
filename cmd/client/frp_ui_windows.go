//go:build windows

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
	"github.com/private-radminlan/lanmesh/internal/clientui"
	frpctl "github.com/private-radminlan/lanmesh/internal/frp"
)

type frpEntryRef struct {
	kind  string
	index int
}

type frpRuleTableModel struct {
	walk.TableModelBase
	rows [][]string
}

func (m *frpRuleTableModel) RowCount() int { return len(m.rows) }

func (m *frpRuleTableModel) Value(row, col int) interface{} {
	if row < 0 || row >= len(m.rows) || col < 0 || col >= len(m.rows[row]) {
		return ""
	}
	return m.rows[row][col]
}

func (m *frpRuleTableModel) setRows(rows [][]string) {
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

func (a *desktop) initializeFRPUI() {
	a.frpConfig = frpctl.NewDefaultConfig()
	a.frpRuleModel = &frpRuleTableModel{}
	a.frpSnapshot = frpctl.Snapshot{State: "stopped", CoreVersion: frpctl.CoreVersion}
	a.frpProfiles = []frpctl.ProfileInfo{{ID: frpctl.DefaultProfileID, Name: "默认穿透服务器"}}
	a.frpManagers = make(map[string]*frpctl.Manager)
	a.frpLeaseProviders = make(map[string]*frpLeaseProvider)
	a.frpManagerErrors = make(map[string]error)
	a.frpEndpointRegistry = frpctl.NewEndpointRegistry()
	a.frpProfileID = frpctl.DefaultProfileID
	a.updateFRPRows()
}

func (a *desktop) initializeFRP() {
	executable, err := os.Executable()
	if err != nil {
		a.frpInitErr = fmt.Errorf("定位客户端程序: %w", err)
		a.renderFRPState()
		return
	}
	catalog, err := frpctl.DefaultCatalog()
	if err != nil {
		a.frpInitErr = err
		a.renderFRPState()
		return
	}
	profiles, err := catalog.List()
	if err != nil {
		a.frpInitErr = err
		a.renderFRPState()
		return
	}
	a.frpCatalog = catalog
	a.frpProfiles = profiles
	a.frpManagers = make(map[string]*frpctl.Manager, len(profiles))
	a.frpLeaseProviders = make(map[string]*frpLeaseProvider, len(profiles))
	a.frpManagerErrors = make(map[string]error)
	for _, info := range profiles {
		store, storeErr := catalog.Store(info.ID)
		if storeErr != nil {
			a.frpManagerErrors[info.ID] = storeErr
			continue
		}
		provider := newFRPLeaseProvider(a.api, a.membership.Network.ID, a.identity.DeviceID.String())
		manager, managerErr := frpctl.NewManager(frpctl.Options{
			Store:               store,
			ExecutableDir:       filepath.Dir(executable),
			DeviceID:            a.identity.DeviceID.String(),
			NetworkID:           a.membership.Network.ID,
			MeshCIDR:            a.membership.Network.CIDR,
			LeaseProvider:       provider,
			MeshTargetProvider:  newMeshTargetProvider(a),
			EndpointRegistry:    a.frpEndpointRegistry,
			ReservationProvider: a.frpReservations,
		})
		if provider != nil {
			a.frpLeaseProviders[info.ID] = provider
		}
		if managerErr != nil {
			a.frpManagerErrors[info.ID] = managerErr
			continue
		}
		a.frpManagers[info.ID] = manager
	}
	a.selectFRPProfile(profiles[0].ID)
}

func (a *desktop) refreshFRPIdentity() {
	for id, manager := range a.frpManagers {
		if manager == nil {
			continue
		}
		if err := manager.UpdateMembership(a.membership.Network.ID, a.identity.DeviceID.String(), a.membership.Network.CIDR); err != nil {
			a.frpManagerErrors[id] = err
			continue
		}
		delete(a.frpManagerErrors, id)
		if provider := a.frpLeaseProviders[id]; provider != nil {
			provider.UpdateIdentity(a.membership.Network.ID, a.identity.DeviceID.String())
		}
	}
}

func (a *desktop) profileNames() []string {
	names := make([]string, 0, len(a.frpProfiles))
	for _, info := range a.frpProfiles {
		names = append(names, info.Name)
	}
	return names
}

func (a *desktop) selectFRPProfile(id string) {
	a.frpProfileSwitching = true
	defer func() { a.frpProfileSwitching = false }()
	index := 0
	a.frpProfileID = id
	for i, info := range a.frpProfiles {
		if info.ID == id {
			index = i
			break
		}
	}
	if a.frpProfileBox != nil {
		_ = a.frpProfileBox.SetModel(a.profileNames())
		_ = a.frpProfileBox.SetCurrentIndex(index)
	}
	a.frpManager = a.frpManagers[id]
	a.frpInitErr = a.frpManagerErrors[id]
	if a.frpManager != nil {
		if cfg, ok := a.frpManager.Config(); ok {
			a.frpConfig = cfg
		} else {
			a.frpConfig = a.defaultProfileConfig(id)
		}
	} else {
		a.frpConfig = a.defaultProfileConfig(id)
	}
	a.frpSnapshot = frpctl.Snapshot{State: "stopped", CoreVersion: frpctl.CoreVersion}
	a.renderFRPState()
	a.updateFRPRows()
	a.updateFRPButtons()
	a.refreshFRP()
}

func (a *desktop) defaultProfileConfig(id string) frpctl.Config {
	cfg := frpctl.NewDefaultConfig()
	cfg.Profile.ID = id
	for _, info := range a.frpProfiles {
		if info.ID == id {
			cfg.Profile.Name = info.Name
			break
		}
	}
	return cfg
}

func (a *desktop) switchFRPProfile() {
	if a.frpProfileSwitching || a.frpProfileBox == nil {
		return
	}
	index := a.frpProfileBox.CurrentIndex()
	if index < 0 || index >= len(a.frpProfiles) {
		return
	}
	if a.frpProfiles[index].ID != a.frpProfileID {
		a.selectFRPProfile(a.frpProfiles[index].ID)
	}
}

func (a *desktop) buildFRPPage() Widget {
	refresh := actionButton(nil, "刷新", false, 68, a.refreshFRP)
	authorization := actionButton(&a.frpApprovalButton, "目标授权", false, 92, a.showFRPServiceCenter)
	importConfig := actionButton(&a.frpImportButton, "导入配置", false, 86, a.importFRPProfile)
	exportConfig := actionButton(&a.frpExportButton, "导出配置", false, 86, a.exportFRPProfile)
	settings := actionButton(&a.frpSettingsButton, "服务器设置", false, 108, a.showFRPSettings)
	header := pageHeader("内网穿透", "⇄", refresh, authorization, importConfig, exportConfig, settings)
	header.Row = 0

	serverCard := roundView{Composite: Composite{Background: SolidColorBrush{Color: uiWhite}, Layout: HBox{Margins: Margins{Left: 22, Top: 18, Right: 22, Bottom: 18}, Spacing: 16}, Children: []Widget{
		Composite{MinSize: Size{Width: 8}, MaxSize: Size{Width: 8}, Background: SolidColorBrush{Color: uiBlue}},
		Composite{StretchFactor: 1, Background: SolidColorBrush{Color: uiWhite}, Layout: VBox{MarginsZero: true, Spacing: 4}, Children: []Widget{
			Composite{Layout: HBox{MarginsZero: true, Spacing: 8}, Children: []Widget{
				Label{Text: "服务器配置", MinSize: Size{Width: 84}, TextColor: uiMuted, Font: Font{PointSize: 9}, NoPrefix: true},
				ComboBox{AssignTo: &a.frpProfileBox, Model: []string{"默认穿透服务器"}, CurrentIndex: 0, MinSize: Size{Width: 220}, OnCurrentIndexChanged: a.switchFRPProfile},
				actionButton(&a.frpNewProfileButton, "新建配置", false, 86, a.showNewFRPProfile),
				HSpacer{},
			}},
			Label{AssignTo: &a.frpStatus, Text: "● 未配置", TextColor: uiMuted, Font: Font{PointSize: 12, Bold: true}, NoPrefix: true},
			Label{AssignTo: &a.frpServer, Text: "先配置 FRP 服务器和令牌", TextColor: uiInk, Font: Font{PointSize: 10, Bold: true}, EllipsisMode: EllipsisEnd, NoPrefix: true},
			Label{AssignTo: &a.frpAuthNote, Text: "支持本机回环、物理 LAN、HTTP/HTTPS、TCPMUX 和 XTCP 受限代理；共享令牌仍不等同于设备级隔离。", TextColor: uiMuted, Font: Font{PointSize: 9}, NoPrefix: true},
		}},
		Composite{MinSize: Size{Width: 150}, MaxSize: Size{Width: 150}, Layout: VBox{MarginsZero: true, Spacing: 8}, Children: []Widget{
			actionButton(&a.frpToggleButton, "启动穿透", true, 150, a.toggleFRP),
			actionButton(nil, "查看日志", false, 150, a.showFRPLogs),
		}},
	}}, fill: uiWhite, radius: 12, border: borderColor(uiBorder)}
	serverCard.Row = 1

	add := actionButton(&a.frpAddButton, "添加规则", true, 96, a.showAddFRPRule)
	batch := actionButton(&a.frpBatchButton, "批量端口", false, 86, a.showFRPBatchRules)
	addVisitor := actionButton(&a.frpAddVisitorButton, "添加访问", false, 86, a.showAddFRPVisitor)
	edit := actionButton(&a.frpEditButton, "编辑", false, 68, a.showEditFRPRule)
	remove := actionButton(&a.frpDeleteButton, "删除", false, 68, a.deleteFRPRule)
	ruleHeader := Composite{Layout: HBox{MarginsZero: true, Spacing: 8}, Children: []Widget{
		heading("穿透规则"),
		HSpacer{},
		add,
		batch,
		addVisitor,
		edit,
		remove,
	}}
	ruleTable := TableView{AssignTo: &a.frpRules, Model: a.frpRuleModel, Background: SolidColorBrush{Color: uiWhite}, StretchFactor: 1, MinSize: Size{Height: 210}, CustomRowHeight: 30, CustomHeaderHeight: 28, LastColumnStretched: true, SelectionHiddenWithoutFocus: true, AlternatingRowBG: true, OnCurrentIndexChanged: a.updateFRPButtons, Columns: []TableViewColumn{
		{Title: "名称", Width: 110},
		{Title: "类型", Width: 60},
		{Title: "本地服务", Width: 118},
		{Title: "实际访问地址", Width: 165},
		{Title: "状态", Width: 68},
		{Title: "后端", Width: 58},
		{Title: "最近错误", Width: 120},
	}, StyleCell: func(s *walk.CellStyle) {
		s.TextColor = uiInk
		if s.Row()%2 == 1 {
			s.BackgroundColor = uiTableAlt
		} else {
			s.BackgroundColor = uiWhite
		}
		if s.Row() < 0 || s.Row() >= len(a.frpRuleModel.rows) {
			return
		}
		row := a.frpRuleModel.rows[s.Row()]
		if len(row) > 4 && row[4] == "已禁用" {
			s.TextColor = uiMuted
		} else if s.Col() == 3 || s.Col() == 4 {
			s.TextColor = uiBlue
		}
		if len(row) > 6 && row[6] != "—" && row[6] != "" {
			s.TextColor = walk.RGB(185, 28, 28)
		}
	}}
	rulesCard := roundView{Composite: Composite{Background: SolidColorBrush{Color: uiWhite}, Layout: VBox{Margins: Margins{Left: 18, Top: 16, Right: 18, Bottom: 14}, Spacing: 10}, Children: []Widget{
		ruleHeader,
		ruleTable,
	}}, fill: uiWhite, radius: 12, border: borderColor(uiBorder)}
	rulesCard.Composite.StretchFactor = 1
	rulesCard.Row = 2

	logsCard := roundView{Composite: Composite{Background: SolidColorBrush{Color: uiWhite}, Layout: VBox{Margins: Margins{Left: 18, Top: 12, Right: 18, Bottom: 12}, Spacing: 6}, Children: []Widget{
		Label{Text: "运行日志", TextColor: uiInk, Font: Font{PointSize: 10, Bold: true}, NoPrefix: true},
		TextEdit{AssignTo: &a.frpLogs, ReadOnly: true, VScroll: true, MinSize: Size{Height: 96}, TextColor: uiMuted, Font: Font{Family: "Consolas", PointSize: 9}},
	}}, fill: uiWhite, radius: 12, border: borderColor(uiBorder)}
	logsCard.Row = 3

	return Composite{AssignTo: &a.frpPage, Visible: false, StretchFactor: 1, Background: SolidColorBrush{Color: uiBackground}, Layout: Grid{Columns: 1, Margins: Margins{Left: 20, Top: 16, Right: 20, Bottom: 18}, Spacing: 12}, Children: []Widget{
		header,
		serverCard,
		rulesCard,
		logsCard,
	}}
}

func (a *desktop) configureFRPTable() {
	if a.frpRules == nil {
		return
	}
	a.frpRules.SetGridlines(false)
}

func (a *desktop) openFRP() {
	a.railSelection = 0
	a.showPage(pageFRP)
}

func (a *desktop) refreshFRP() {
	if a.frpManager == nil || a.frpRefreshing || a.closing.Load() {
		return
	}
	a.frpRefreshing = true
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		snapshot := a.frpManager.Snapshot(ctx)
		cancel()
		a.ui(func() {
			a.frpRefreshing = false
			a.frpSnapshot = snapshot
			if cfg, ok := a.frpManager.Config(); ok {
				a.frpConfig = cfg
			}
			a.renderFRPState()
			a.updateFRPRows()
			a.updateFRPButtons()
		})
	}()
}

func (a *desktop) renderFRPState() {
	if a.frpStatus == nil {
		return
	}
	if a.frpProfileBox != nil {
		a.frpProfileBox.SetEnabled(!a.frpBusy)
	}
	if a.frpNewProfileButton != nil {
		a.frpNewProfileButton.SetEnabled(!a.frpBusy && a.frpCatalog != nil)
	}
	if a.frpInitErr != nil {
		a.frpStatus.SetText("● 组件不可用")
		a.frpStatus.SetTextColor(walk.RGB(185, 28, 28))
		a.frpServer.SetText(clientui.Redact(a.frpInitErr.Error()))
		a.frpAuthNote.SetText("请完整解压客户端，并确认内置 frpc.exe 未被替换。")
		a.frpToggleButton.SetText("启动穿透")
		a.frpToggleButton.SetEnabled(false)
		a.frpSettingsButton.SetEnabled(false)
		a.frpAddButton.SetEnabled(false)
		a.frpAddVisitorButton.SetEnabled(false)
		a.frpEditButton.SetEnabled(false)
		a.frpDeleteButton.SetEnabled(false)
		return
	}
	if a.frpManager == nil {
		a.frpStatus.SetText("● 未配置")
		a.frpStatus.SetTextColor(uiMuted)
		a.frpServer.SetText("先配置 FRP 服务器和令牌")
		a.frpAuthNote.SetText("支持本机回环、物理 LAN、HTTP/HTTPS、TCPMUX 和 XTCP 受限代理；共享令牌仍不等同于设备级隔离。")
		a.frpToggleButton.SetText("启动穿透")
		a.frpToggleButton.SetEnabled(false)
		a.frpSettingsButton.SetEnabled(false)
		a.frpAddButton.SetEnabled(false)
		a.frpAddVisitorButton.SetEnabled(false)
		a.frpEditButton.SetEnabled(false)
		a.frpDeleteButton.SetEnabled(false)
		return
	}
	s := a.frpSnapshot
	switch {
	case !s.Configured:
		a.frpStatus.SetText("● 未配置")
		a.frpStatus.SetTextColor(uiMuted)
		a.frpServer.SetText("先配置 FRP 服务器和令牌")
	case s.Running:
		if s.Authenticated {
			a.frpStatus.SetText("● 已连接")
		} else {
			a.frpStatus.SetText("● 正在连接")
		}
		a.frpStatus.SetTextColor(uiBlue)
		a.frpServer.SetText(fmt.Sprintf("%s:%d · TLS 强制验证", s.ServerHost, s.ServerPort))
	case s.State == "starting":
		a.frpStatus.SetText("● 正在启动")
		a.frpStatus.SetTextColor(walk.RGB(180, 83, 9))
		a.frpServer.SetText("正在校验配置并连接 FRP 服务器，可随时取消。")
	case s.State == "waiting_dependency" || s.State == "retry_backoff":
		a.frpStatus.SetText("● 等待组网恢复")
		a.frpStatus.SetTextColor(walk.RGB(180, 83, 9))
		if s.LastError != "" {
			a.frpServer.SetText(s.LastError)
		} else {
			a.frpServer.SetText("TLAN 组网依赖不可用；可取消等待，恢复组网后不会自行重开已取消的任务")
		}
	case s.State == "failed":
		if s.DesiredRunning {
			a.frpStatus.SetText("● 正在重试")
			a.frpServer.SetText("后台仍保留运行意图，可点击“取消穿透”停止重试。")
		} else {
			a.frpStatus.SetText("● 需要处理")
			a.frpServer.SetText(s.LastError)
		}
		a.frpStatus.SetTextColor(walk.RGB(185, 28, 28))
	case s.State == "stopping":
		a.frpStatus.SetText("● 正在停止")
		a.frpStatus.SetTextColor(walk.RGB(180, 83, 9))
		a.frpServer.SetText("正在回收 FRP 进程和本地转发资源…")
	default:
		a.frpStatus.SetText("● 已停止")
		a.frpStatus.SetTextColor(uiMuted)
		a.frpServer.SetText(fmt.Sprintf("%s:%d · 点击启动", s.ServerHost, s.ServerPort))
	}
	if s.SharedToken {
		a.frpAuthNote.SetText("共享令牌模式：所有使用此令牌的客户端共享认证，不等同于设备级隔离。")
	} else {
		a.frpAuthNote.SetText("TLS 强制启用，必须使用可信 CA；不会提供跳过证书校验的选项。")
	}
	canStop := s.CanStop || s.Running || s.State == "stopping"
	if s.Running {
		a.frpToggleButton.SetText("停止穿透")
	} else if canStop {
		a.frpToggleButton.SetText("取消穿透")
	} else {
		a.frpToggleButton.SetText("启动穿透")
	}
	if canStop {
		a.frpToggleButton.SetEnabled(s.Configured && !a.frpStopping && (!a.frpBusy || a.frpStarting))
	} else {
		a.frpToggleButton.SetEnabled(s.Configured && !a.frpBusy)
	}
	a.frpSettingsButton.SetEnabled(!a.frpBusy && !a.frpStarting && !a.frpStopping)
	a.frpAddButton.SetEnabled(!a.frpBusy && !a.frpStarting && !a.frpStopping && a.frpManager != nil)
	a.frpAddVisitorButton.SetEnabled(!a.frpBusy && !a.frpStarting && !a.frpStopping && a.frpManager != nil)
	a.updateFRPButtons()
}

func (a *desktop) updateFRPRows() {
	if a.frpRuleModel == nil {
		return
	}
	rows := make([][]string, 0, len(a.frpConfig.Profile.Rules)+len(a.frpConfig.Profile.Visitors))
	a.frpRows = make([]frpEntryRef, 0, cap(rows))
	statuses := a.frpSnapshot.Rules
	for i, rule := range a.frpConfig.Profile.Rules {
		remote := "—"
		if len(rule.Exposure.CustomDomains) > 0 {
			remote = strings.Join(rule.Exposure.CustomDomains, ", ")
		}
		if rule.Exposure.Subdomain != "" {
			if remote == "—" {
				remote = "子域名 " + rule.Exposure.Subdomain
			} else {
				remote += " + 子域名 " + rule.Exposure.Subdomain
			}
		}
		if rule.Type == "stcp" || rule.Type == "sudp" || rule.Type == "xtcp" {
			remote = "私有代理"
		}
		row := []string{rule.Name, strings.ToUpper(rule.Type), fmt.Sprintf("%s:%d", rule.Target.Host, rule.Target.Port), remote, "未启动", "—", "—"}
		if i < len(statuses) {
			status := statuses[i]
			row[4] = status.State
			row[5] = status.Backend
			if status.GatewayStats != "" {
				row[5] = status.GatewayStats
			}
			if status.RemoteAddr != "" {
				row[3] = status.RemoteAddr
			}
			if status.ErrorDetail != "" {
				row[6] = status.ErrorDetail
			}
		}
		rows = append(rows, row)
		a.frpRows = append(a.frpRows, frpEntryRef{kind: "rule", index: i})
	}
	visitorStatuses := a.frpSnapshot.Visitors
	for i, visitor := range a.frpConfig.Profile.Visitors {
		remote := visitor.ServerName
		if visitor.Type == "xtcp" && visitor.Protocol != "" {
			remote += " (" + strings.ToUpper(visitor.Protocol) + ")"
		}
		row := []string{visitor.Name, strings.ToUpper(visitor.Type), fmt.Sprintf("%s:%d", visitor.BindAddr, visitor.BindPort), remote, "未启动", "访问", "—"}
		if i < len(visitorStatuses) {
			status := visitorStatuses[i]
			row[4] = status.State
			if status.ErrorDetail != "" {
				row[6] = status.ErrorDetail
			}
		}
		rows = append(rows, row)
		a.frpRows = append(a.frpRows, frpEntryRef{kind: "visitor", index: i})
	}
	a.frpRuleModel.setRows(rows)
	if a.frpLogs != nil {
		a.frpLogs.SetText(strings.Join(a.frpSnapshot.Logs, "\r\n"))
	}
}

func (a *desktop) updateFRPButtons() {
	if a.frpEditButton == nil || a.frpDeleteButton == nil {
		return
	}
	_, ok := a.selectedFRPEntry()
	a.frpEditButton.SetEnabled(!a.frpBusy && ok)
	a.frpDeleteButton.SetEnabled(!a.frpBusy && ok)
	if a.frpApprovalButton != nil {
		a.frpApprovalButton.SetEnabled(a.api != nil && a.api.Token != "")
	}
	if a.frpImportButton != nil {
		a.frpImportButton.SetEnabled(!a.frpBusy && a.frpManager != nil)
	}
	if a.frpExportButton != nil {
		a.frpExportButton.SetEnabled(!a.frpBusy && a.frpSnapshot.Configured)
	}
	if a.frpBatchButton != nil {
		a.frpBatchButton.SetEnabled(!a.frpBusy && a.frpManager != nil)
	}
	if a.frpRules != nil {
		a.frpRules.Invalidate()
	}
}

func (a *desktop) selectedFRPEntry() (frpEntryRef, bool) {
	if a.frpRules == nil {
		return frpEntryRef{}, false
	}
	index := a.frpRules.CurrentIndex()
	if index < 0 || index >= len(a.frpRows) {
		return frpEntryRef{}, false
	}
	return a.frpRows[index], true
}

func (a *desktop) selectedFRPIndex() int {
	entry, ok := a.selectedFRPEntry()
	if !ok || entry.kind != "rule" {
		return -1
	}
	return entry.index
}

func (a *desktop) startFRP() {
	if a.frpBusy || a.frpManager == nil {
		return
	}
	a.frpBusy = true
	a.frpStarting = true
	a.frpSnapshot.DesiredRunning = true
	a.frpSnapshot.CanStop = true
	a.frpSnapshot.State = "starting"
	a.frpSnapshot.LastError = ""
	startSeq := a.frpStartSeq.Add(1)
	a.renderFRPState()
	go func() {
		if a.frpStartSeq.Load() != startSeq {
			a.ui(func() {
				a.frpBusy = false
				a.frpStarting = false
				a.refreshFRP()
				a.renderFRPState()
			})
			return
		}
		parent := a.ctx
		if parent == nil {
			parent = context.Background()
		}
		ctx, cancel := context.WithTimeout(parent, 35*time.Second)
		err := a.frpManager.Start(ctx)
		cancel()
		a.ui(func() {
			if a.frpStartSeq.Load() != startSeq {
				a.refreshFRP()
				a.renderFRPState()
				return
			}
			a.frpBusy = false
			a.frpStarting = false
			if err != nil && !a.frpStopping {
				a.showFRPError("启动内网穿透", err)
			}
			a.refreshFRP()
			a.renderFRPState()
		})
	}()
}

func (a *desktop) stopFRP() {
	if a.frpManager == nil || a.frpStopping {
		return
	}
	a.frpStartSeq.Add(1)
	a.frpStopping = true
	a.frpSnapshot.DesiredRunning = false
	a.frpSnapshot.CanStop = true
	a.frpSnapshot.State = "stopping"
	a.renderFRPState()
	go func() {
		parent := a.ctx
		if parent == nil {
			parent = context.Background()
		}
		ctx, cancel := context.WithTimeout(parent, 15*time.Second)
		err := a.frpManager.Stop(ctx)
		cancel()
		a.ui(func() {
			a.frpStopping = false
			a.frpBusy = false
			a.frpStarting = false
			a.frpSnapshot.DesiredRunning = false
			a.frpSnapshot.CanStop = false
			if err != nil {
				a.showFRPError("停止内网穿透", err)
			}
			a.refreshFRP()
			a.renderFRPState()
		})
	}()
}

func (a *desktop) toggleFRP() {
	if a.frpManager == nil {
		a.showFRPError("启动内网穿透", a.frpInitErr)
		return
	}
	if !a.frpSnapshot.Configured {
		a.showFRPSettings()
		return
	}
	if a.frpSnapshot.Running || a.frpSnapshot.CanStop || a.frpSnapshot.State == "stopping" {
		a.stopFRP()
		return
	}
	a.startFRP()
}

func (a *desktop) applyFRPConfig(cfg frpctl.Config, token string) {
	a.applyFRPConfigWithSecrets(cfg, token, nil)
}

func (a *desktop) applyFRPConfigWithSecrets(cfg frpctl.Config, token string, secrets map[string]string) {
	if a.frpBusy || a.frpManager == nil {
		return
	}
	a.frpBusy = true
	a.renderFRPState()
	go func() {
		parent := a.ctx
		if parent == nil {
			parent = context.Background()
		}
		ctx, cancel := context.WithTimeout(parent, 40*time.Second)
		saved, err := a.frpManager.ApplyWithSecrets(ctx, cfg, token, secrets)
		cancel()
		a.ui(func() {
			a.frpBusy = false
			if err != nil {
				a.showFRPError("保存内网穿透配置", err)
			} else {
				a.frpConfig = saved
			}
			a.refreshFRP()
			a.renderFRPState()
		})
	}()
}

func (a *desktop) showFRPError(action string, err error) {
	if err == nil {
		return
	}
	f := clientui.Explain(action, err)
	a.showNotice(f)
}

func (a *desktop) showNewFRPProfile() {
	if a.frpCatalog == nil {
		a.showFRPError("新建穿透配置", a.frpInitErr)
		return
	}
	var dlg *walk.Dialog
	var name *walk.LineEdit
	var saveButton, closeButton *walk.PushButton
	err := (Dialog{
		AssignTo: &dlg, Title: "新建穿透服务器配置", Icon: a.appIcon,
		Size: Size{Width: 460, Height: 260}, MinSize: Size{Width: 420, Height: 230},
		Font: Font{Family: "Microsoft YaHei UI", PointSize: 10}, Background: SolidColorBrush{Color: uiWhite},
		Layout:       VBox{Margins: Margins{Left: 28, Top: 24, Right: 28, Bottom: 22}, Spacing: 12},
		CancelButton: &closeButton, DefaultButton: &saveButton,
		Children: []Widget{
			heading("新建独立服务器配置"),
			TextLabel{Text: "每个配置拥有独立的 token、CA、规则和运行目录，可以分别启动。", TextColor: uiMuted, MinSize: Size{Width: 390}},
			Composite{Layout: HBox{MarginsZero: true, Spacing: 10}, Children: []Widget{
				Label{Text: "配置名称", MinSize: Size{Width: 78}},
				LineEdit{AssignTo: &name, CueBanner: "例如：办公室穿透", MinSize: Size{Width: 300}},
			}},
			VSpacer{StretchFactor: 1},
			Composite{Layout: HBox{MarginsZero: true, Spacing: 10}, Children: []Widget{
				HSpacer{},
				actionButton(nil, "取消", false, 88, func() { dlg.Cancel() }),
				actionButton(&saveButton, "创建", true, 88, func() {
					profileName := strings.TrimSpace(name.Text())
					if profileName == "" {
						walk.MsgBox(dlg, "名称不能为空", "请输入配置名称。", walk.MsgBoxOK|walk.MsgBoxIconWarning)
						return
					}
					random, randomErr := frpctl.NewSecret(4)
					if randomErr != nil {
						walk.MsgBox(dlg, "创建失败", randomErr.Error(), walk.MsgBoxOK|walk.MsgBoxIconError)
						return
					}
					id := "profile-" + strings.ToLower(random[:8])
					info, createErr := a.frpCatalog.Create(id, profileName)
					if createErr != nil {
						walk.MsgBox(dlg, "创建失败", createErr.Error(), walk.MsgBoxOK|walk.MsgBoxIconError)
						return
					}
					store, storeErr := a.frpCatalog.Store(id)
					if storeErr != nil {
						walk.MsgBox(dlg, "创建失败", storeErr.Error(), walk.MsgBoxOK|walk.MsgBoxIconError)
						return
					}
					executable, executableErr := os.Executable()
					if executableErr != nil {
						walk.MsgBox(dlg, "创建失败", executableErr.Error(), walk.MsgBoxOK|walk.MsgBoxIconError)
						return
					}
					provider := newFRPLeaseProvider(a.api, a.membership.Network.ID, a.identity.DeviceID.String())
					manager, managerErr := frpctl.NewManager(frpctl.Options{Store: store, ExecutableDir: filepath.Dir(executable), DeviceID: a.identity.DeviceID.String(), NetworkID: a.membership.Network.ID, MeshCIDR: a.membership.Network.CIDR, LeaseProvider: provider, MeshTargetProvider: newMeshTargetProvider(a), EndpointRegistry: a.frpEndpointRegistry, ReservationProvider: a.frpReservations})
					if provider != nil {
						a.frpLeaseProviders[id] = provider
					}
					if managerErr != nil {
						a.frpManagerErrors[id] = managerErr
					} else {
						a.frpManagers[id] = manager
					}
					if profiles, listErr := a.frpCatalog.List(); listErr == nil {
						a.frpProfiles = profiles
					} else {
						a.frpProfiles = append(a.frpProfiles, info)
					}
					a.selectFRPProfile(id)
					dlg.Accept()
				}),
			}},
		},
	}).Create(a.window)
	if err != nil {
		a.showFRPError("打开新建配置窗口", err)
		return
	}
	defer dlg.Dispose()
	dlg.Run()
}
func (a *desktop) showFRPSettings() {
	if a.frpManager == nil {
		a.showFRPError("配置 FRP 服务器", a.frpInitErr)
		return
	}
	cfg := frpctl.CloneConfig(a.frpConfig)
	server := cfg.Profile.Server
	var dlg *walk.Dialog
	var host, tlsName, caPath, token, serverID, subdomainHost *walk.LineEdit
	var port, httpPort, httpsPort, tcpmuxPort *walk.NumberEdit
	var managed, tcpMux, disableFirstByte *walk.CheckBox
	var transportBox *walk.ComboBox
	var tcpOptions *walk.Composite
	var closeButton *walk.PushButton
	transportIndex := func() int {
		switch server.Transport {
		case "websocket":
			return 1
		case "wss":
			return 2
		case "quic":
			return 3
		case "kcp":
			return 4
		default:
			return 0
		}
	}
	lastTransport := transportIndex()
	setTransportFields := func() {
		if tcpOptions == nil || transportBox == nil {
			return
		}
		current := transportBox.CurrentIndex()
		if httpPort != nil && httpsPort != nil && tcpmuxPort != nil {
			if current == 2 && lastTransport != 2 {
				if int(httpPort.Value()) == frpctl.DefaultHTTPPort {
					_ = httpPort.SetValue(frpctl.DefaultWSSHTTPPort)
				}
				if int(httpsPort.Value()) == frpctl.DefaultHTTPSPort {
					_ = httpsPort.SetValue(frpctl.DefaultWSSHTTPSPort)
				}
				if int(tcpmuxPort.Value()) == frpctl.DefaultTCPMuxPort {
					_ = tcpmuxPort.SetValue(frpctl.DefaultWSSTCPMuxPort)
				}
			} else if current != 2 && lastTransport == 2 {
				if int(httpPort.Value()) == frpctl.DefaultWSSHTTPPort {
					_ = httpPort.SetValue(frpctl.DefaultHTTPPort)
				}
				if int(httpsPort.Value()) == frpctl.DefaultWSSHTTPSPort {
					_ = httpsPort.SetValue(frpctl.DefaultHTTPSPort)
				}
				if int(tcpmuxPort.Value()) == frpctl.DefaultWSSTCPMuxPort {
					_ = tcpmuxPort.SetValue(frpctl.DefaultTCPMuxPort)
				}
			}
		}
		lastTransport = current
		tcpOptions.SetVisible(current < 3)
	}
	err := (Dialog{
		AssignTo: &dlg, Title: "FRP 服务器设置", Icon: a.appIcon,
		Size: Size{Width: 700, Height: 900}, MinSize: Size{Width: 650, Height: 820},
		Font: Font{Family: "Microsoft YaHei UI", PointSize: 10}, Background: SolidColorBrush{Color: uiWhite},
		Layout:       VBox{Margins: Margins{Left: 28, Top: 24, Right: 28, Bottom: 22}, Spacing: 12},
		CancelButton: &closeButton, DefaultButton: &closeButton,
		Children: []Widget{
			heading("连接独立 FRP 服务器"),
			TextLabel{Text: "固定 frpc v0.71.1 支持 TCP、WebSocket、WSS、QUIC、KCP；TLS 证书校验始终开启。HTTP/HTTPS 域名规则还需要填写 FRPS 对外提供的 vhost 端口。WSS 必须指向已完成 TLS→WebSocket 路由的外部反向代理，不能直连裸 FRPS bindPort。", TextColor: uiMuted, MinSize: Size{Width: 560}},
			Composite{Layout: HBox{MarginsZero: true, Spacing: 10}, Children: []Widget{
				Label{Text: "服务器地址", MinSize: Size{Width: 88}},
				LineEdit{AssignTo: &host, Text: server.Host, CueBanner: "frp.example.com 或 IPv4", MinSize: Size{Width: 320}},
			}},
			Composite{Layout: HBox{MarginsZero: true, Spacing: 10}, Children: []Widget{
				Label{Text: "控制端口", MinSize: Size{Width: 88}},
				NumberEdit{AssignTo: &port, Value: float64(server.Port), MinValue: 1, MaxValue: 65535, Decimals: 0, MinSize: Size{Width: 130}},
				Label{Text: "TLS serverName", MinSize: Size{Width: 106}},
				LineEdit{AssignTo: &tlsName, Text: server.TLSServerName, CueBanner: "证书中的域名或 IP", MinSize: Size{Width: 180}},
			}},
			Composite{Layout: HBox{MarginsZero: true, Spacing: 10}, Children: []Widget{
				Label{Text: "传输协议", MinSize: Size{Width: 88}},
				ComboBox{AssignTo: &transportBox, Model: []string{"TCP", "WebSocket", "WSS", "QUIC", "KCP"}, CurrentIndex: transportIndex(), MinSize: Size{Width: 160}, OnCurrentIndexChanged: setTransportFields},
				TextLabel{Text: "必须与 FRPS 的 transport.protocol 一致", TextColor: uiMuted, MinSize: Size{Width: 300}},
			}},
			Composite{Layout: HBox{MarginsZero: true, Spacing: 10}, Children: []Widget{
				Label{Text: "公网 HTTP", MinSize: Size{Width: 88}},
				NumberEdit{AssignTo: &httpPort, Value: float64(server.PublicHTTPPort), MinValue: 1, MaxValue: 65535, Decimals: 0, MinSize: Size{Width: 130}},
				Label{Text: "公网 HTTPS", MinSize: Size{Width: 88}},
				NumberEdit{AssignTo: &httpsPort, Value: float64(server.PublicHTTPSPort), MinValue: 1, MaxValue: 65535, Decimals: 0, MinSize: Size{Width: 130}},
			}},
			Composite{Layout: HBox{MarginsZero: true, Spacing: 10}, Children: []Widget{
				Label{Text: "子域名后缀", MinSize: Size{Width: 88}},
				LineEdit{AssignTo: &subdomainHost, Text: func() string {
					if server.SubdomainHost != "" {
						return server.SubdomainHost
					}
					return frpctl.DefaultSubdomainHost
				}(), CueBanner: "例如 frp.example.com", MinSize: Size{Width: 300}},
				Label{Text: "TCPMUX 端口", MinSize: Size{Width: 96}},
				NumberEdit{AssignTo: &tcpmuxPort, Value: float64(server.PublicTCPMuxPort), MinValue: 1, MaxValue: 65535, Decimals: 0, MinSize: Size{Width: 120}},
			}},
			Composite{Layout: HBox{MarginsZero: true, Spacing: 10}, Children: []Widget{
				CheckBox{AssignTo: &managed, Text: "使用 TLAN 托管发布授权", Checked: server.Kind == "managed"},
				Label{Text: "托管服务器 ID", MinSize: Size{Width: 96}},
				LineEdit{AssignTo: &serverID, Text: func() string {
					if server.ServerID != "" {
						return server.ServerID
					}
					return "frps-managed-1"
				}(), CueBanner: "必须与 FRPS 配置的 server_id 一致", MinSize: Size{Width: 220}},
			}},
			Composite{AssignTo: &tcpOptions, Layout: HBox{MarginsZero: true, Spacing: 10}, Children: []Widget{
				CheckBox{AssignTo: &tcpMux, Text: "启用 TCP 多路复用 (tcpMux)", Checked: server.TCPMux == nil || *server.TCPMux},
				CheckBox{AssignTo: &disableFirstByte, Text: "标准 TLS 首字节", Checked: server.DisableCustomTLSFirstByte == nil || *server.DisableCustomTLSFirstByte},
			}},
			TextLabel{Text: "兼容档位必须与 FRPS 的 transport.tcpMux / transport.tls.disableCustomTLSFirstByte 一致；默认两项均为开启。QUIC/KCP 使用 UDP 端口，仍需 FRPS 对应端口与防火墙放行。", TextColor: uiMuted, MinSize: Size{Width: 560}},
			Composite{Layout: HBox{MarginsZero: true, Spacing: 10}, Children: []Widget{
				Label{Text: "可信 CA", MinSize: Size{Width: 88}},
				LineEdit{AssignTo: &caPath, Text: server.TrustedCAPath, ReadOnly: true, MinSize: Size{Width: 360}},
				actionButton(nil, "选择文件", false, 92, func() {
					fd := walk.FileDialog{Title: "选择 FRP 可信 CA", FilePath: caPath.Text(), Filter: "证书文件 (*.pem;*.crt)|*.pem;*.crt|所有文件 (*.*)|*.*", FilterIndex: 1}
					accepted, err := fd.ShowOpen(dlg)
					if err != nil {
						walk.MsgBox(dlg, "选择 CA 文件", err.Error(), walk.MsgBoxOK|walk.MsgBoxIconError)
					} else if accepted {
						caPath.SetText(fd.FilePath)
					}
				}),
			}},
			Composite{Layout: HBox{MarginsZero: true, Spacing: 10}, Children: []Widget{
				Label{Text: "FRP 令牌", MinSize: Size{Width: 88}},
				LineEdit{AssignTo: &token, PasswordMode: true, CueBanner: "留空表示保留已保存令牌", MinSize: Size{Width: 430}},
			}},
			TextLabel{Text: "共享令牌仅表示同一 FRP 服务器上的认证，不等同于设备级授权隔离。令牌由当前 Windows 用户使用 DPAPI 加密保存。", TextColor: uiMuted, MinSize: Size{Width: 520}},
			VSpacer{StretchFactor: 1},
			Composite{Layout: HBox{MarginsZero: true, Spacing: 10}, Children: []Widget{
				HSpacer{},
				actionButton(nil, "取消", false, 88, func() { dlg.Cancel() }),
				actionButton(&closeButton, "保存设置", true, 108, func() {
					hostValue := strings.TrimSpace(host.Text())
					tlsValue := strings.TrimSpace(tlsName.Text())
					caValue := strings.TrimSpace(caPath.Text())
					if hostValue == "" || tlsValue == "" || caValue == "" {
						walk.MsgBox(dlg, "设置不完整", "服务器地址、TLS serverName 和可信 CA 均不能为空。", walk.MsgBoxOK|walk.MsgBoxIconWarning)
						return
					}
					if managed.Checked() {
						cfg.Profile.Server.Kind = "managed"
						cfg.Profile.Server.ServerID = strings.TrimSpace(serverID.Text())
					} else {
						cfg.Profile.Server.Kind = "private_token"
						cfg.Profile.Server.ServerID = ""
					}
					cfg.Profile.Server.Host = hostValue
					cfg.Profile.Server.Port = int(port.Value())
					cfg.Profile.Server.Transport = []string{"tcp", "websocket", "wss", "quic", "kcp"}[transportBox.CurrentIndex()]
					cfg.Profile.Server.TLSServerName = tlsValue
					cfg.Profile.Server.TrustedCAPath = caValue
					cfg.Profile.Server.CredentialRef = frpctl.DefaultCredential
					cfg.Profile.Server.PublicHTTPPort = int(httpPort.Value())
					cfg.Profile.Server.PublicHTTPSPort = int(httpsPort.Value())
					cfg.Profile.Server.PublicTCPMuxPort = int(tcpmuxPort.Value())
					cfg.Profile.Server.SubdomainHost = strings.ToLower(strings.TrimSpace(subdomainHost.Text()))
					tcpMuxValue := tcpMux.Checked()
					disableFirstByteValue := disableFirstByte.Checked()
					cfg.Profile.Server.TCPMux = &tcpMuxValue
					cfg.Profile.Server.DisableCustomTLSFirstByte = &disableFirstByteValue
					if err := frpctl.ValidateConfig(cfg); err != nil {
						walk.MsgBox(dlg, "设置不正确", err.Error(), walk.MsgBoxOK|walk.MsgBoxIconWarning)
						return
					}
					a.applyFRPConfig(cfg, token.Text())
					dlg.Accept()
				}),
			}},
		},
	}).Create(a.window)
	if err != nil {
		a.showFRPError("打开服务器设置", err)
		return
	}
	setTransportFields()
	defer dlg.Dispose()
	dlg.Run()
}

func (a *desktop) showAddFRPRule() {
	a.showFRPRuleDialog(-1)
}

func (a *desktop) showEditFRPRule() {
	entry, ok := a.selectedFRPEntry()
	if !ok {
		return
	}
	if entry.kind == "visitor" {
		a.showFRPVisitorDialog(entry.index)
		return
	}
	a.showFRPRuleDialog(entry.index)
}

func (a *desktop) showFRPRuleDialog(index int) {
	if a.frpManager == nil {
		a.showFRPError("编辑穿透规则", a.frpInitErr)
		return
	}
	cfg := frpctl.CloneConfig(a.frpConfig)
	rule := frpctl.Rule{
		ID: "", Name: "", Type: "tcp", Enabled: true,
		Target:   frpctl.Target{Kind: "loopback", Host: "127.0.0.1", Port: 8080},
		Exposure: frpctl.Exposure{RemotePort: 30000},
	}
	if index >= 0 {
		rule = cfg.Profile.Rules[index]
	}
	var dlg *walk.Dialog
	var nameEdit, targetHost, targetNetworkID, targetDeviceID, targetPublicKey, targetServiceID, localPort, remotePort, domains, subdomain, locations, secretKey, httpUser, httpPassword, hostHeaderRewrite, routeByHTTPUser *walk.LineEdit
	var requestHeaders, responseHeaders, allowUsers *walk.TextEdit
	var typeBox, targetBox, proxyProtocolBox, multiplexerBox *walk.ComboBox
	var enabled, useEncryption, useCompression *walk.CheckBox
	var privateGroup, httpGroup, authGroup, muxGroup, transportGroup *walk.Composite
	var saveButton, closeButton *walk.PushButton
	typeIndex := func() int {
		switch rule.Type {
		case "udp":
			return 1
		case "http":
			return 2
		case "https":
			return 3
		case "stcp":
			return 4
		case "sudp":
			return 5
		case "tcpmux":
			return 6
		case "xtcp":
			return 7
		default:
			return 0
		}
	}
	targetIndex := 0
	if rule.Target.Kind == "lan" {
		targetIndex = 1
	} else if rule.Target.Kind == "mesh_peer" {
		targetIndex = 2
	} else if rule.Target.Kind == "mesh_self" {
		targetIndex = 3
	}
	if rule.Target.NetworkID == "" {
		rule.Target.NetworkID = a.membership.Network.ID
	}
	remoteValue := rule.Exposure.RemotePort
	if remoteValue == 0 {
		remoteValue = 30000
	}
	proxyProtocolIndex := 0
	if rule.Transport.ProxyProtocolVersion == "v1" {
		proxyProtocolIndex = 1
	} else if rule.Transport.ProxyProtocolVersion == "v2" {
		proxyProtocolIndex = 2
	}
	setFields := func() {
		if typeBox == nil || remotePort == nil || domains == nil || subdomain == nil || targetHost == nil || targetBox == nil || privateGroup == nil || httpGroup == nil || authGroup == nil || muxGroup == nil || transportGroup == nil {
			return
		}
		selected := typeBox.CurrentIndex()
		remoteRule := selected == 0 || selected == 1
		domainRule := selected == 2 || selected == 3 || selected == 6
		privateRule := selected == 4 || selected == 5 || selected == 7
		httpRule := selected == 2
		muxRule := selected == 6
		remotePort.SetEnabled(remoteRule)
		domains.SetEnabled(domainRule)
		subdomain.SetEnabled(domainRule)
		privateGroup.SetVisible(privateRule)
		httpGroup.SetVisible(httpRule)
		authGroup.SetVisible(httpRule || muxRule)
		muxGroup.SetVisible(muxRule)
		transportGroup.SetVisible(true)
		targetIndex := targetBox.CurrentIndex()
		targetHost.SetEnabled(targetIndex != 0)
		targetNetworkID.SetEnabled(targetIndex >= 2)
		targetDeviceID.SetEnabled(targetIndex >= 2)
		targetPublicKey.SetEnabled(targetIndex >= 2)
		targetServiceID.SetEnabled(targetIndex >= 2)
		switch targetIndex {
		case 0:
			targetHost.SetText("127.0.0.1")
		case 3:
			targetHost.SetText(a.membership.Member.VirtualIP)
			targetNetworkID.SetText(a.membership.Network.ID)
			targetDeviceID.SetText(a.identity.DeviceID.String())
		}
	}
	err := (Dialog{
		AssignTo: &dlg, Title: "内网穿透规则", Icon: a.appIcon,
		Size: Size{Width: 760, Height: 860}, MinSize: Size{Width: 700, Height: 760},
		Font: Font{Family: "Microsoft YaHei UI", PointSize: 10}, Background: SolidColorBrush{Color: uiWhite},
		Layout:       VBox{Margins: Margins{Left: 28, Top: 22, Right: 28, Bottom: 20}, Spacing: 12},
		CancelButton: &closeButton, DefaultButton: &saveButton,
		Children: []Widget{
			ScrollView{StretchFactor: 1, HorizontalFixed: true, Layout: VBox{MarginsZero: true, Spacing: 10}, Children: []Widget{
				heading("发布本机、LAN 或受控 TLAN 服务"),
				TextLabel{Text: "高级字段只映射到固定 frpc v0.71.1 的受限 schema，不会透传原始 TOML 或插件。Mesh 目标不能与 XTCP/tcpmux 混用；需要时请拆分成独立配置。", TextColor: uiMuted, MinSize: Size{Width: 680}},
				Composite{Layout: HBox{MarginsZero: true, Spacing: 10}, Children: []Widget{
					Label{Text: "规则名称", MinSize: Size{Width: 78}},
					LineEdit{AssignTo: &nameEdit, Text: rule.Name, CueBanner: "例如：家庭游戏服务", MinSize: Size{Width: 560}},
				}},
				Composite{Layout: HBox{MarginsZero: true, Spacing: 10}, Children: []Widget{
					Label{Text: "目标类型", MinSize: Size{Width: 78}},
					ComboBox{AssignTo: &targetBox, Model: []string{"本机回环", "物理 LAN IPv4", "TLAN 成员", "本机 Mesh 地址"}, CurrentIndex: targetIndex, MinSize: Size{Width: 150}, OnCurrentIndexChanged: setFields},
					Label{Text: "目标地址", MinSize: Size{Width: 78}},
					LineEdit{AssignTo: &targetHost, Text: rule.Target.Host, CueBanner: "例如 192.168.1.20", MinSize: Size{Width: 250}},
				}},
				Composite{Layout: HBox{MarginsZero: true, Spacing: 10}, Children: []Widget{
					Label{Text: "目标网络", MinSize: Size{Width: 78}},
					LineEdit{AssignTo: &targetNetworkID, Text: rule.Target.NetworkID, MinSize: Size{Width: 220}},
					Label{Text: "目标设备", MinSize: Size{Width: 78}},
					LineEdit{AssignTo: &targetDeviceID, Text: rule.Target.DeviceID, CueBanner: "设备 ID", MinSize: Size{Width: 220}},
				}},
				Composite{Layout: HBox{MarginsZero: true, Spacing: 10}, Children: []Widget{
					Label{Text: "目标公钥", MinSize: Size{Width: 78}},
					LineEdit{AssignTo: &targetPublicKey, Text: rule.Target.PublicKey, CueBanner: "可留空；服务器会按目标成员绑定公钥", MinSize: Size{Width: 560}},
				}},
				Composite{Layout: HBox{MarginsZero: true, Spacing: 10}, Children: []Widget{
					Label{Text: "服务授权", MinSize: Size{Width: 78}},
					LineEdit{AssignTo: &targetServiceID, Text: rule.Target.ServiceID, CueBanner: "目标成员已批准的服务 ID；mesh_peer 必填", MinSize: Size{Width: 420}},
					actionButton(nil, "申请/查看授权", false, 120, a.showFRPServiceCenter),
				}},
				Composite{Layout: HBox{MarginsZero: true, Spacing: 10}, Children: []Widget{
					Label{Text: "代理协议", MinSize: Size{Width: 78}},
					ComboBox{AssignTo: &typeBox, Model: []string{"TCP", "UDP", "HTTP", "HTTPS", "STCP", "SUDP", "TCPMUX", "XTCP"}, CurrentIndex: typeIndex(), MinSize: Size{Width: 150}, OnCurrentIndexChanged: setFields},
					CheckBox{AssignTo: &enabled, Text: "启用此规则", Checked: rule.Enabled},
				}},
				Composite{Layout: HBox{MarginsZero: true, Spacing: 10}, Children: []Widget{
					Label{Text: "本地端口", MinSize: Size{Width: 78}},
					LineEdit{AssignTo: &localPort, Text: strconv.Itoa(rule.Target.Port), MinSize: Size{Width: 120}},
					Label{Text: "公网端口", MinSize: Size{Width: 78}},
					LineEdit{AssignTo: &remotePort, Text: strconv.Itoa(remoteValue), MinSize: Size{Width: 120}},
				}},
				Composite{Layout: HBox{MarginsZero: true, Spacing: 10}, Children: []Widget{
					Label{Text: "自定义域名", MinSize: Size{Width: 78}},
					LineEdit{AssignTo: &domains, Text: strings.Join(rule.Exposure.CustomDomains, ", "), CueBanner: "多个域名用逗号分隔，例如 app.example.com", MinSize: Size{Width: 370}},
					Label{Text: "子域名", MinSize: Size{Width: 58}},
					LineEdit{AssignTo: &subdomain, Text: rule.Exposure.Subdomain, CueBanner: "例如 app（不能含点）", MinSize: Size{Width: 110}},
				}},
				Composite{AssignTo: &privateGroup, Visible: false, Layout: VBox{MarginsZero: true, Spacing: 8}, Children: []Widget{
					Composite{Layout: HBox{MarginsZero: true, Spacing: 10}, Children: []Widget{
						Label{Text: "私有密钥", MinSize: Size{Width: 78}},
						LineEdit{AssignTo: &secretKey, PasswordMode: true, CueBanner: "STCP/SUDP/XTCP 使用；留空保留已保存密钥", MinSize: Size{Width: 560}},
					}},
					Composite{Layout: HBox{MarginsZero: true, Spacing: 10}, Children: []Widget{
						Label{Text: "允许用户", MinSize: Size{Width: 78}},
						TextEdit{AssignTo: &allowUsers, Text: strings.Join(rule.Exposure.AllowUsers, ", "), VScroll: true, MinSize: Size{Width: 560, Height: 52}},
					}},
					TextLabel{Text: "allowUsers 仅对 STCP、SUDP、XTCP 生效；使用逗号或换行分隔。留空表示仅允许同一 FRP 用户；* 表示允许所有持密钥访问端，请谨慎使用。", TextColor: uiMuted, MinSize: Size{Width: 680}},
					TextLabel{Text: "私有协议不会分配公网端口；访问端需要单独配置对应的 STCP/SUDP/XTCP visitor。", TextColor: uiMuted, MinSize: Size{Width: 680}},
				}},
				Composite{AssignTo: &httpGroup, Visible: false, Layout: VBox{MarginsZero: true, Spacing: 8}, Children: []Widget{
					Composite{Layout: HBox{MarginsZero: true, Spacing: 10}, Children: []Widget{
						Label{Text: "HTTP 路径", MinSize: Size{Width: 78}},
						LineEdit{AssignTo: &locations, Text: strings.Join(rule.Exposure.Locations, ", "), CueBanner: "多个绝对路径用逗号分隔，例如 /, /api", MinSize: Size{Width: 560}},
					}},
					Composite{Layout: HBox{MarginsZero: true, Spacing: 10}, Children: []Widget{
						Label{Text: "Host 改写", MinSize: Size{Width: 78}},
						LineEdit{AssignTo: &hostHeaderRewrite, Text: rule.Exposure.HostHeaderRewrite, CueBanner: "可选；写入 hostHeaderRewrite", MinSize: Size{Width: 560}},
					}},
					Composite{Layout: HBox{MarginsZero: true, Spacing: 10}, Children: []Widget{
						Label{Text: "请求头", MinSize: Size{Width: 78}},
						TextEdit{AssignTo: &requestHeaders, Text: formatHeaderLines(rule.Exposure.RequestHeaders), VScroll: true, MinSize: Size{Width: 560, Height: 58}},
					}},
					Composite{Layout: HBox{MarginsZero: true, Spacing: 10}, Children: []Widget{
						Label{Text: "响应头", MinSize: Size{Width: 78}},
						TextEdit{AssignTo: &responseHeaders, Text: formatHeaderLines(rule.Exposure.ResponseHeaders), VScroll: true, MinSize: Size{Width: 560, Height: 58}},
					}},
					TextLabel{Text: "请求头/响应头每行填写 Name: value；只支持 v0.71.1 的 set 操作，不接受删除或替换整个 Header 表。", TextColor: uiMuted, MinSize: Size{Width: 680}},
				}},
				Composite{AssignTo: &authGroup, Visible: false, Layout: VBox{MarginsZero: true, Spacing: 8}, Children: []Widget{
					Composite{Layout: HBox{MarginsZero: true, Spacing: 10}, Children: []Widget{
						Label{Text: "HTTP 用户", MinSize: Size{Width: 78}},
						LineEdit{AssignTo: &httpUser, Text: rule.Exposure.HTTPUser, CueBanner: "可选；设置后必须同时设置密码", MinSize: Size{Width: 190}},
						Label{Text: "HTTP 密码", MinSize: Size{Width: 78}},
						LineEdit{AssignTo: &httpPassword, PasswordMode: true, CueBanner: "留空保留已保存密码", MinSize: Size{Width: 220}},
					}},
					Composite{Layout: HBox{MarginsZero: true, Spacing: 10}, Children: []Widget{
						Label{Text: "路由用户", MinSize: Size{Width: 78}},
						LineEdit{AssignTo: &routeByHTTPUser, Text: rule.Exposure.RouteByHTTPUser, CueBanner: "可选；对应 routeByHTTPUser", MinSize: Size{Width: 560}},
					}},
				}},
				Composite{AssignTo: &muxGroup, Visible: false, Layout: VBox{MarginsZero: true, Spacing: 8}, Children: []Widget{
					Composite{Layout: HBox{MarginsZero: true, Spacing: 10}, Children: []Widget{
						Label{Text: "Multiplexer", MinSize: Size{Width: 78}},
						ComboBox{AssignTo: &multiplexerBox, Model: []string{"HTTP CONNECT"}, CurrentIndex: 0, MinSize: Size{Width: 180}},
					}},
					TextLabel{Text: "TCPMUX 仅开放 v0.71.1 支持的 httpconnect multiplexer。", TextColor: uiMuted, MinSize: Size{Width: 680}},
				}},
				Composite{AssignTo: &transportGroup, Layout: VBox{MarginsZero: true, Spacing: 8}, Children: []Widget{
					Composite{Layout: HBox{MarginsZero: true, Spacing: 18}, Children: []Widget{
						CheckBox{AssignTo: &useEncryption, Text: "传输加密 (useEncryption)", Checked: rule.Transport.UseEncryption},
						CheckBox{AssignTo: &useCompression, Text: "传输压缩 (useCompression)", Checked: rule.Transport.UseCompression},
					}},
					Composite{Layout: HBox{MarginsZero: true, Spacing: 10}, Children: []Widget{
						Label{Text: "PROXY 协议", MinSize: Size{Width: 78}},
						ComboBox{AssignTo: &proxyProtocolBox, Model: []string{"自动", "v1", "v2"}, CurrentIndex: proxyProtocolIndex, MinSize: Size{Width: 130}},
						TextLabel{Text: "仅在本地业务服务确实支持 proxy protocol 时启用；默认自动。该字段是客户端本地 TOML 选项，FRPS 插件不可观察，不属于 managed 精确授权。", TextColor: uiMuted, MinSize: Size{Width: 430}},
					}},
				}},
				TextLabel{Text: "云元数据、TLAN/FRP 管理入口和内部网关不能作为目标；Mesh 目标必须使用托管授权。XTCP/tcpmux 与 Mesh 目标或 Mesh visitor 依赖冲突时会拒绝保存。", TextColor: uiMuted, MinSize: Size{Width: 680}},
			}},
			Composite{Layout: HBox{MarginsZero: true, Spacing: 10}, Children: []Widget{
				HSpacer{},
				actionButton(nil, "取消", false, 88, func() { dlg.Cancel() }),
				actionButton(&saveButton, "保存规则", true, 108, func() {
					local, err := strconv.Atoi(strings.TrimSpace(localPort.Text()))
					if err != nil {
						walk.MsgBox(dlg, "端口不正确", "本地端口必须是 1-65535 的数字。", walk.MsgBoxOK|walk.MsgBoxIconWarning)
						return
					}
					updated := rule
					if updated.ID == "" {
						updated.ID, err = frpctl.NewRuleID()
						if err != nil {
							walk.MsgBox(dlg, "保存规则", err.Error(), walk.MsgBoxOK|walk.MsgBoxIconError)
							return
						}
					}
					updated.Name = strings.TrimSpace(nameEdit.Text())
					updated.Type = []string{"tcp", "udp", "http", "https", "stcp", "sudp", "tcpmux", "xtcp"}[typeBox.CurrentIndex()]
					updated.Enabled = enabled.Checked()
					targetKind := "loopback"
					targetHostValue := "127.0.0.1"
					if targetBox.CurrentIndex() == 1 {
						targetKind = "lan"
						targetHostValue = strings.TrimSpace(targetHost.Text())
					} else if targetBox.CurrentIndex() == 2 {
						targetKind = "mesh_peer"
						targetHostValue = strings.TrimSpace(targetHost.Text())
					} else if targetBox.CurrentIndex() == 3 {
						targetKind = "mesh_self"
						targetHostValue = strings.TrimSpace(targetHost.Text())
					}
					updated.Target = frpctl.Target{Kind: targetKind, Host: targetHostValue, Port: local}
					if targetKind == "mesh_peer" || targetKind == "mesh_self" {
						updated.Target.NetworkID = strings.TrimSpace(targetNetworkID.Text())
						updated.Target.DeviceID = strings.TrimSpace(targetDeviceID.Text())
						updated.Target.PublicKey = strings.TrimSpace(targetPublicKey.Text())
						updated.Target.ServiceID = strings.TrimSpace(targetServiceID.Text())
						if targetKind == "mesh_peer" && updated.Target.ServiceID == "" {
							walk.MsgBox(dlg, "缺少服务授权", "请点击“申请/查看授权”，由目标成员确认后再把服务 ID 填入此处。", walk.MsgBoxOK|walk.MsgBoxIconWarning)
							return
						}
					}
					updated.Transport = frpctl.RuleTransport{
						UseEncryption:        useEncryption.Checked(),
						UseCompression:       useCompression.Checked(),
						ProxyProtocolVersion: []string{"", "v1", "v2"}[proxyProtocolBox.CurrentIndex()],
					}
					providedSecrets := map[string]string{}
					switch updated.Type {
					case "tcp", "udp":
						updated.SecretRef = ""
						updated.Exposure = frpctl.Exposure{}
						remote, parseErr := strconv.Atoi(strings.TrimSpace(remotePort.Text()))
						if parseErr != nil {
							walk.MsgBox(dlg, "端口不正确", "公网端口必须是 1-65535 的数字。", walk.MsgBoxOK|walk.MsgBoxIconWarning)
							return
						}
						updated.Exposure.RemotePort = remote
					case "http", "https":
						updated.SecretRef = ""
						updated.Exposure = frpctl.Exposure{
							CustomDomains: splitDomains(domains.Text()),
							Subdomain:     strings.TrimSpace(subdomain.Text()),
						}
						if updated.Type == "http" {
							updated.Exposure.Locations = splitDomains(locations.Text())
							updated.Exposure.HostHeaderRewrite = strings.TrimSpace(hostHeaderRewrite.Text())
							updated.Exposure.RouteByHTTPUser = strings.TrimSpace(routeByHTTPUser.Text())
							updated.Exposure.RequestHeaders, err = parseHeaderLines(requestHeaders.Text())
							if err != nil {
								walk.MsgBox(dlg, "请求头格式不正确", err.Error(), walk.MsgBoxOK|walk.MsgBoxIconWarning)
								return
							}
							updated.Exposure.ResponseHeaders, err = parseHeaderLines(responseHeaders.Text())
							if err != nil {
								walk.MsgBox(dlg, "响应头格式不正确", err.Error(), walk.MsgBoxOK|walk.MsgBoxIconWarning)
								return
							}
						}
						if updated.Type == "http" {
							user := strings.TrimSpace(httpUser.Text())
							password := httpPassword.Text()
							if user != "" && password == "" && rule.Exposure.HTTPPasswordRef == "" {
								walk.MsgBox(dlg, "HTTP 密码不能为空", "设置 HTTP 用户时必须填写密码。", walk.MsgBoxOK|walk.MsgBoxIconWarning)
								return
							}
							if user == "" && password != "" {
								walk.MsgBox(dlg, "HTTP 用户不能为空", "填写 HTTP 密码时必须同时填写用户名。", walk.MsgBoxOK|walk.MsgBoxIconWarning)
								return
							}
							if user != "" {
								ref := rule.Exposure.HTTPPasswordRef
								if ref == "" {
									ref = "http-password-" + updated.ID
								}
								updated.Exposure.HTTPUser = user
								updated.Exposure.HTTPPasswordRef = ref
								if password != "" {
									providedSecrets[ref] = password
								}
							}
						}
					case "tcpmux":
						updated.SecretRef = ""
						updated.Exposure = frpctl.Exposure{
							CustomDomains:   splitDomains(domains.Text()),
							Subdomain:       strings.TrimSpace(subdomain.Text()),
							Multiplexer:     "httpconnect",
							RouteByHTTPUser: strings.TrimSpace(routeByHTTPUser.Text()),
						}
						user := strings.TrimSpace(httpUser.Text())
						password := httpPassword.Text()
						if user != "" && password == "" && rule.Exposure.HTTPPasswordRef == "" {
							walk.MsgBox(dlg, "HTTP 密码不能为空", "设置 HTTP 用户时必须填写密码。", walk.MsgBoxOK|walk.MsgBoxIconWarning)
							return
						}
						if user == "" && password != "" {
							walk.MsgBox(dlg, "HTTP 用户不能为空", "填写 HTTP 密码时必须同时填写用户名。", walk.MsgBoxOK|walk.MsgBoxIconWarning)
							return
						}
						if user != "" {
							ref := rule.Exposure.HTTPPasswordRef
							if ref == "" {
								ref = "http-password-" + updated.ID
							}
							updated.Exposure.HTTPUser = user
							updated.Exposure.HTTPPasswordRef = ref
							if password != "" {
								providedSecrets[ref] = password
							}
						}
					default:
						updated.Exposure = frpctl.Exposure{AllowUsers: splitDomains(allowUsers.Text())}
						if updated.SecretRef == "" {
							updated.SecretRef = "rule-secret-" + updated.ID
						}
						value := secretKey.Text()
						if value != "" {
							providedSecrets[updated.SecretRef] = value
						} else if rule.SecretRef == "" {
							walk.MsgBox(dlg, "私有密钥不能为空", "STCP/SUDP/XTCP 规则需要设置访问密钥。", walk.MsgBoxOK|walk.MsgBoxIconWarning)
							return
						}
					}
					if index >= 0 {
						cfg.Profile.Rules[index] = updated
					} else {
						cfg.Profile.Rules = append(cfg.Profile.Rules, updated)
					}
					if err = frpctl.ValidateConfig(cfg); err != nil {
						showFRPValidationError(dlg, "规则不正确", err)
						return
					}
					a.applyFRPConfigWithSecrets(cfg, "", providedSecrets)
					dlg.Accept()
				}),
			}},
		},
	}).Create(a.window)
	if err != nil {
		a.showFRPError("打开内网穿透规则", err)
		return
	}
	setFields()
	defer dlg.Dispose()
	dlg.Run()
}

func formatHeaderLines(values map[string]string) string {
	if len(values) == 0 {
		return ""
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	lines := make([]string, 0, len(keys))
	for _, key := range keys {
		lines = append(lines, key+": "+values[key])
	}
	return strings.Join(lines, "\r\n")
}

func parseHeaderLines(value string) (map[string]string, error) {
	lines := strings.FieldsFunc(value, func(r rune) bool { return r == '\n' || r == '\r' })
	if len(lines) == 0 {
		return nil, nil
	}
	headers := make(map[string]string, len(lines))
	for lineNumber, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		index := strings.IndexByte(line, ':')
		if index <= 0 {
			return nil, fmt.Errorf("第 %d 行必须使用 Name: value 格式", lineNumber+1)
		}
		name := strings.TrimSpace(line[:index])
		value := strings.TrimSpace(line[index+1:])
		if name == "" || strings.ContainsAny(name, "\x00\r\n") || strings.ContainsAny(value, "\x00\r\n") {
			return nil, fmt.Errorf("第 %d 行的 Header 名称或值无效", lineNumber+1)
		}
		headers[name] = value
	}
	if len(headers) == 0 {
		return nil, nil
	}
	return headers, nil
}

func showFRPValidationError(dlg *walk.Dialog, title string, err error) {
	if err == nil {
		return
	}
	message := "配置未保存：" + err.Error()
	switch {
	case frpctl.IsDependencyIsolationError(err):
		title = "需要拆分配置"
		message = "当前配置混用了 Mesh 依赖与独立访问/高级代理，失败时可能错误停止无关服务。\n\n请新建独立穿透配置，把 Mesh 发布、XTCP/tcpmux 或 visitor 分开保存。\n\n技术信息：" + err.Error()
	case frpctl.IsReservedTargetError(err):
		title = "目标或监听端口被保留"
		message = "云元数据、TLAN/FRP 管理入口、内部网关和已分配的本机监听端口不能作为业务目标或访问端口。\n\n请改用普通业务服务端口。\n\n技术信息：" + err.Error()
	case strings.Contains(strings.ToLower(err.Error()), "subdomain"):
		title = "子域名不正确"
		message = "子域名只能填写一个 DNS 标签（不能含点、通配符或空格），例如 app。\n\n" + err.Error()
	case strings.Contains(strings.ToLower(err.Error()), "location"):
		title = "HTTP 路径不正确"
		message = "locations 必须是绝对路径，例如 / 或 /api；多个路径用逗号分隔，不能包含 ..。\n\n" + err.Error()
	case strings.Contains(strings.ToLower(err.Error()), "header"):
		title = "Header 改写不正确"
		message = "请求头/响应头必须每行使用 Name: value 格式，名称和值不能包含换行或控制字符。\n\n" + err.Error()
	case strings.Contains(strings.ToLower(err.Error()), "managed frps does not yet authorize"):
		title = "托管授权暂不支持此高级规则"
		message = "当前 TLAN 托管 FRPS 授权 schema 只覆盖 TCP/UDP/HTTP/HTTPS/STCP/SUDP。XTCP/tcpmux 请改用 private_token 服务器配置，不能绕过服务端授权直接发布。\n\n" + err.Error()
	case strings.Contains(strings.ToLower(err.Error()), "tcpmux"):
		title = "TCPMUX 配置不正确"
		message = "TCPMUX 只支持 httpconnect，并且必须填写 customDomains 或 subdomain；不能与 Mesh 目标混用。\n\n" + err.Error()
	case strings.Contains(strings.ToLower(err.Error()), "xtcp"):
		title = "XTCP 配置不正确"
		message = "XTCP 需要私有密钥；visitor 的 protocol 只能是 quic 或 kcp，且不能与 Mesh 目标混用。\n\n" + err.Error()
	case strings.Contains(strings.ToLower(err.Error()), "transport"):
		title = "传输协议配置不正确"
		message = "请检查 FRPS 的 transport.protocol 与客户端一致；QUIC/KCP 使用 UDP，WSS/WebSocket 使用 TCP，TLS 证书校验不可关闭。\n\n" + err.Error()
	case strings.Contains(strings.ToLower(err.Error()), "http"):
		title = "HTTP 认证配置不正确"
		message = "HTTP 用户名和密码必须同时设置；密码会通过 Windows DPAPI 保存，不会写入明文配置。\n\n" + err.Error()
	}
	walk.MsgBox(dlg, title, message, walk.MsgBoxOK|walk.MsgBoxIconWarning)
}

func splitDomains(value string) []string {
	fields := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\r' || r == '\t'
	})
	result := make([]string, 0, len(fields))
	for _, field := range fields {
		if field = strings.TrimSpace(field); field != "" {
			result = append(result, field)
		}
	}
	return result
}

func (a *desktop) deleteFRPRule() {
	entry, ok := a.selectedFRPEntry()
	if !ok {
		return
	}
	if entry.kind == "visitor" {
		a.deleteFRPVisitor(entry.index)
		return
	}
	rule := a.frpConfig.Profile.Rules[entry.index]
	if walk.MsgBox(a.window, "删除穿透规则", fmt.Sprintf("确定删除“%s”吗？", rule.Name), walk.MsgBoxYesNo|walk.MsgBoxIconQuestion) != walk.DlgCmdYes {
		return
	}
	cfg := frpctl.CloneConfig(a.frpConfig)
	cfg.Profile.Rules = append(cfg.Profile.Rules[:entry.index], cfg.Profile.Rules[entry.index+1:]...)
	a.applyFRPConfig(cfg, "")
}

func (a *desktop) showAddFRPVisitor() {
	a.showFRPVisitorDialog(-1)
}

func (a *desktop) showFRPVisitorDialog(index int) {
	if a.frpManager == nil {
		a.showFRPError("编辑私有访问", a.frpInitErr)
		return
	}
	cfg := frpctl.CloneConfig(a.frpConfig)
	visitor := frpctl.Visitor{
		ID: "", Name: "", Type: "stcp", Enabled: true,
		BindAddr: "127.0.0.1", BindPort: 9000, Protocol: "quic",
		MaxRetriesAnHour: 8, MinRetryInterval: 90, FallbackTimeoutMs: 1000,
	}
	if index >= 0 {
		visitor = cfg.Profile.Visitors[index]
	}
	var dlg *walk.Dialog
	var nameEdit, serverName, serverUser, bindPort, secretKey, maxRetries, minRetry, fallbackTo, fallbackTimeout *walk.LineEdit
	var typeBox, protocolBox *walk.ComboBox
	var enabled, keepTunnelOpen *walk.CheckBox
	var xtcpGroup *walk.Composite
	var saveButton, closeButton *walk.PushButton
	typeIndex := 0
	if visitor.Type == "sudp" {
		typeIndex = 1
	} else if visitor.Type == "xtcp" {
		typeIndex = 2
	}
	protocolIndex := 0
	if visitor.Protocol == "kcp" {
		protocolIndex = 1
	}
	setFields := func() {
		if typeBox == nil || xtcpGroup == nil {
			return
		}
		xtcpGroup.SetVisible(typeBox.CurrentIndex() == 2)
	}
	err := (Dialog{
		AssignTo: &dlg, Title: "私有访问规则", Icon: a.appIcon,
		Size: Size{Width: 640, Height: 700}, MinSize: Size{Width: 580, Height: 620},
		Font: Font{Family: "Microsoft YaHei UI", PointSize: 10}, Background: SolidColorBrush{Color: uiWhite},
		Layout:       VBox{Margins: Margins{Left: 28, Top: 24, Right: 28, Bottom: 22}, Spacing: 12},
		CancelButton: &closeButton, DefaultButton: &saveButton,
		Children: []Widget{
			ScrollView{StretchFactor: 1, HorizontalFixed: true, Layout: VBox{MarginsZero: true, Spacing: 12}, Children: []Widget{
				heading("通过 STCP/SUDP/XTCP 访问其他设备"),
				TextLabel{Text: "访问器只绑定 127.0.0.1，不向局域网或 TLAN 成员开放。XTCP 使用固定 frpc v0.71.1 的 P2P 打洞参数；访问器属于独立依赖域，不能与 TLAN Mesh 发布规则混在同一配置。", TextColor: uiMuted, MinSize: Size{Width: 570}},
				Composite{Layout: HBox{MarginsZero: true, Spacing: 10}, Children: []Widget{
					Label{Text: "访问名称", MinSize: Size{Width: 78}},
					LineEdit{AssignTo: &nameEdit, Text: visitor.Name, CueBanner: "例如：家里 SSH", MinSize: Size{Width: 460}},
				}},
				Composite{Layout: HBox{MarginsZero: true, Spacing: 10}, Children: []Widget{
					Label{Text: "协议", MinSize: Size{Width: 78}},
					ComboBox{AssignTo: &typeBox, Model: []string{"STCP", "SUDP", "XTCP"}, CurrentIndex: typeIndex, MinSize: Size{Width: 130}, OnCurrentIndexChanged: setFields},
					CheckBox{AssignTo: &enabled, Text: "启用此访问", Checked: visitor.Enabled},
				}},
				Composite{Layout: HBox{MarginsZero: true, Spacing: 10}, Children: []Widget{
					Label{Text: "服务器名", MinSize: Size{Width: 78}},
					LineEdit{AssignTo: &serverName, Text: visitor.ServerName, CueBanner: "发布端 raw 代理名（不要加 user. 前缀）", MinSize: Size{Width: 300}},
					Label{Text: "服务器用户", MinSize: Size{Width: 82}},
					LineEdit{AssignTo: &serverUser, Text: visitor.ServerUser, CueBanner: "可留空", MinSize: Size{Width: 120}},
				}},
				Composite{Layout: HBox{MarginsZero: true, Spacing: 10}, Children: []Widget{
					Label{Text: "本机端口", MinSize: Size{Width: 78}},
					LineEdit{AssignTo: &bindPort, Text: strconv.Itoa(visitor.BindPort), MinSize: Size{Width: 120}},
					Label{Text: "私有密钥", MinSize: Size{Width: 78}},
					LineEdit{AssignTo: &secretKey, PasswordMode: true, CueBanner: "留空保留已保存密钥", MinSize: Size{Width: 230}},
				}},
				Composite{AssignTo: &xtcpGroup, Visible: false, Layout: VBox{MarginsZero: true, Spacing: 8}, Children: []Widget{
					Composite{Layout: HBox{MarginsZero: true, Spacing: 10}, Children: []Widget{
						Label{Text: "XTCP 协议", MinSize: Size{Width: 78}},
						ComboBox{AssignTo: &protocolBox, Model: []string{"QUIC", "KCP"}, CurrentIndex: protocolIndex, MinSize: Size{Width: 130}},
						CheckBox{AssignTo: &keepTunnelOpen, Text: "保持隧道 (keepTunnelOpen)", Checked: visitor.KeepTunnelOpen},
					}},
					Composite{Layout: HBox{MarginsZero: true, Spacing: 10}, Children: []Widget{
						Label{Text: "每小时重试", MinSize: Size{Width: 78}},
						LineEdit{AssignTo: &maxRetries, Text: strconv.Itoa(visitor.MaxRetriesAnHour), MinSize: Size{Width: 90}},
						Label{Text: "最小间隔秒", MinSize: Size{Width: 82}},
						LineEdit{AssignTo: &minRetry, Text: strconv.Itoa(visitor.MinRetryInterval), MinSize: Size{Width: 90}},
						Label{Text: "回退超时 ms", MinSize: Size{Width: 82}},
						LineEdit{AssignTo: &fallbackTimeout, Text: strconv.Itoa(visitor.FallbackTimeoutMs), MinSize: Size{Width: 90}},
					}},
					Composite{Layout: HBox{MarginsZero: true, Spacing: 10}, Children: []Widget{
						Label{Text: "回退访问器", MinSize: Size{Width: 78}},
						LineEdit{AssignTo: &fallbackTo, Text: visitor.FallbackTo, CueBanner: "可选；填写另一个 visitor 的 FRP 名称", MinSize: Size{Width: 460}},
					}},
					TextLabel{Text: "XTCP 打洞失败时可回退到另一个访问器；这些参数只在 v0.71.1 visitor type=xtcp 下渲染。", TextColor: uiMuted, MinSize: Size{Width: 570}},
				}},
				TextLabel{Text: "访问器会把 127.0.0.1:本机端口 的连接转发到远端私有代理；不会自动开放给其他设备。", TextColor: uiMuted, MinSize: Size{Width: 570}},
			}},
			Composite{Layout: HBox{MarginsZero: true, Spacing: 10}, Children: []Widget{
				HSpacer{},
				actionButton(nil, "取消", false, 88, func() { dlg.Cancel() }),
				actionButton(&saveButton, "保存访问", true, 108, func() {
					port, err := strconv.Atoi(strings.TrimSpace(bindPort.Text()))
					if err != nil {
						walk.MsgBox(dlg, "端口不正确", "本机端口必须是 1-65535 的数字。", walk.MsgBoxOK|walk.MsgBoxIconWarning)
						return
					}
					updated := visitor
					if updated.ID == "" {
						updated.ID, err = frpctl.NewRuleID()
						if err != nil {
							walk.MsgBox(dlg, "保存访问", err.Error(), walk.MsgBoxOK|walk.MsgBoxIconError)
							return
						}
					}
					updated.Name = strings.TrimSpace(nameEdit.Text())
					updated.Type = []string{"stcp", "sudp", "xtcp"}[typeBox.CurrentIndex()]
					updated.ServerName = strings.TrimSpace(serverName.Text())
					updated.ServerUser = strings.TrimSpace(serverUser.Text())
					updated.BindAddr = "127.0.0.1"
					updated.BindPort = port
					updated.Enabled = enabled.Checked()
					updated.Protocol = ""
					updated.KeepTunnelOpen = false
					updated.MaxRetriesAnHour = 0
					updated.MinRetryInterval = 0
					updated.FallbackTo = ""
					updated.FallbackTimeoutMs = 0
					if updated.Type == "xtcp" {
						updated.Protocol = []string{"quic", "kcp"}[protocolBox.CurrentIndex()]
						updated.KeepTunnelOpen = keepTunnelOpen.Checked()
						updated.MaxRetriesAnHour, err = strconv.Atoi(strings.TrimSpace(maxRetries.Text()))
						if err != nil {
							walk.MsgBox(dlg, "重试参数不正确", "每小时重试次数必须是数字。", walk.MsgBoxOK|walk.MsgBoxIconWarning)
							return
						}
						updated.MinRetryInterval, err = strconv.Atoi(strings.TrimSpace(minRetry.Text()))
						if err != nil {
							walk.MsgBox(dlg, "重试参数不正确", "最小重试间隔必须是数字。", walk.MsgBoxOK|walk.MsgBoxIconWarning)
							return
						}
						updated.FallbackTimeoutMs, err = strconv.Atoi(strings.TrimSpace(fallbackTimeout.Text()))
						if err != nil {
							walk.MsgBox(dlg, "回退参数不正确", "回退超时必须是毫秒数字。", walk.MsgBoxOK|walk.MsgBoxIconWarning)
							return
						}
						updated.FallbackTo = strings.TrimSpace(fallbackTo.Text())
					}
					if updated.SecretRef == "" {
						updated.SecretRef = "visitor-secret-" + updated.ID
					}
					providedSecrets := map[string]string{}
					if value := secretKey.Text(); value != "" {
						providedSecrets[updated.SecretRef] = value
					} else if visitor.SecretRef == "" {
						walk.MsgBox(dlg, "私有密钥不能为空", "STCP/SUDP/XTCP 访问需要设置密钥。", walk.MsgBoxOK|walk.MsgBoxIconWarning)
						return
					}
					if index >= 0 {
						cfg.Profile.Visitors[index] = updated
					} else {
						cfg.Profile.Visitors = append(cfg.Profile.Visitors, updated)
					}
					if err = frpctl.ValidateConfig(cfg); err != nil {
						showFRPValidationError(dlg, "访问规则不正确", err)
						return
					}
					a.applyFRPConfigWithSecrets(cfg, "", providedSecrets)
					dlg.Accept()
				}),
			}},
		},
	}).Create(a.window)
	if err != nil {
		a.showFRPError("打开私有访问规则", err)
		return
	}
	setFields()
	defer dlg.Dispose()
	dlg.Run()
}

func (a *desktop) deleteFRPVisitor(index int) {
	if index < 0 || index >= len(a.frpConfig.Profile.Visitors) {
		return
	}
	visitor := a.frpConfig.Profile.Visitors[index]
	if walk.MsgBox(a.window, "删除私有访问", fmt.Sprintf("确定删除“%s”吗？", visitor.Name), walk.MsgBoxYesNo|walk.MsgBoxIconQuestion) != walk.DlgCmdYes {
		return
	}
	cfg := frpctl.CloneConfig(a.frpConfig)
	cfg.Profile.Visitors = append(cfg.Profile.Visitors[:index], cfg.Profile.Visitors[index+1:]...)
	a.applyFRPConfig(cfg, "")
}

func (a *desktop) showFRPLogs() {
	if a.frpLogs == nil {
		return
	}
	var dlg *walk.Dialog
	var closeButton *walk.PushButton
	err := (Dialog{
		AssignTo: &dlg, Title: "FRP 运行日志", Icon: a.appIcon,
		Size: Size{Width: 760, Height: 520}, MinSize: Size{Width: 620, Height: 400},
		Font: Font{Family: "Microsoft YaHei UI", PointSize: 10}, Background: SolidColorBrush{Color: uiWhite},
		Layout:       VBox{Margins: Margins{Left: 24, Top: 22, Right: 24, Bottom: 20}, Spacing: 12},
		CancelButton: &closeButton, DefaultButton: &closeButton,
		Children: []Widget{
			heading("最近运行日志"),
			TextLabel{Text: "日志只在内存中保留最近 500 行，令牌和管理密码会被脱敏。", TextColor: uiMuted, MinSize: Size{Width: 600}},
			TextEdit{Text: strings.Join(a.frpSnapshot.Logs, "\r\n"), ReadOnly: true, VScroll: true, HScroll: true, StretchFactor: 1, Font: Font{Family: "Consolas", PointSize: 9}},
			Composite{Layout: HBox{MarginsZero: true}, Children: []Widget{HSpacer{}, actionButton(&closeButton, "关闭", true, 92, func() { dlg.Accept() })}},
		},
	}).Create(a.window)
	if err != nil {
		a.showFRPError("打开运行日志", err)
		return
	}
	defer dlg.Dispose()
	dlg.Run()
}

func (a *desktop) frpReservations() []frpctl.TargetReservation {
	if a.frpEndpointRegistry != nil {
		return a.frpEndpointRegistry.Reservations()
	}
	managers := a.allFRPManagers()
	reservations := make([]frpctl.TargetReservation, 0)
	for _, manager := range managers {
		if manager == nil {
			continue
		}
		reservations = append(reservations, manager.ReservedTargets()...)
	}
	return reservations
}

func (a *desktop) allFRPManagers() []*frpctl.Manager {
	seen := make(map[*frpctl.Manager]struct{})
	result := make([]*frpctl.Manager, 0, len(a.frpManagers)+1)
	for _, manager := range a.frpManagers {
		if manager == nil {
			continue
		}
		if _, ok := seen[manager]; ok {
			continue
		}
		seen[manager] = struct{}{}
		result = append(result, manager)
	}
	if a.frpManager != nil {
		if _, ok := seen[a.frpManager]; !ok {
			result = append(result, a.frpManager)
		}
	}
	return result
}

func (a *desktop) beginFRPClose() {
	a.frpCloseOnce.Do(func() {
		managers := a.allFRPManagers()
		if len(managers) == 0 {
			return
		}
		a.frpStopDone = make(chan struct{})
		go func() {
			done := make(chan struct{}, len(managers))
			for _, manager := range managers {
				go func(manager *frpctl.Manager) {
					ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					_ = manager.Close(ctx)
					cancel()
					done <- struct{}{}
				}(manager)
			}
			for range managers {
				<-done
			}
			close(a.frpStopDone)
		}()
	})
}

func (a *desktop) waitFRPClose() {
	if a.frpStopDone == nil {
		for _, manager := range a.allFRPManagers() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			_ = manager.Close(ctx)
			cancel()
		}
		return
	}
	select {
	case <-a.frpStopDone:
	case <-time.After(12 * time.Second):
	}
}
