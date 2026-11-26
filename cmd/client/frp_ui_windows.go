//go:build windows

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
	"github.com/private-radminlan/lanmesh/internal/clientapi"
	"github.com/private-radminlan/lanmesh/internal/clientui"
	frpctl "github.com/private-radminlan/lanmesh/internal/frp"
	"github.com/private-radminlan/lanmesh/internal/frpauth"
)

type frpEntryRef struct {
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

func (a *desktop) frpServerHost() string {
	if a != nil && a.api != nil && strings.TrimSpace(a.api.BaseURL) != "" {
		if h := hostFromServerURL(a.api.BaseURL); h != "" {
			return h
		}
	}
	return hostFromServerURL(bundledServerURL)
}

func bindFRPServerToHost(cfg frpctl.Config, host string) frpctl.Config {
	out := frpctl.CloneConfig(cfg)
	host = strings.TrimSpace(host)
	if host != "" {
		prev := strings.TrimSpace(out.Profile.Server.Host)
		out.Profile.Server.Host = host
		if strings.TrimSpace(out.Profile.Server.TLSServerName) == "" || strings.EqualFold(strings.TrimSpace(out.Profile.Server.TLSServerName), prev) {
			out.Profile.Server.TLSServerName = host
		}
	}
	if out.Profile.Server.Port == 0 {
		out.Profile.Server.Port = 7000
	}
	if out.Profile.Server.Transport == "" {
		out.Profile.Server.Transport = "tcp"
	}
	if out.Profile.Server.CredentialRef == "" {
		out.Profile.Server.CredentialRef = frpctl.DefaultCredential
	}
	return out
}

func resolveFRPServerMode(caps frpauth.Capabilities, err error) (string, string) {
	if err == nil && strings.EqualFold(strings.TrimSpace(caps.Mode), frpauth.ModeManaged) && strings.TrimSpace(caps.ServerID) != "" {
		return "managed", strings.TrimSpace(caps.ServerID)
	}
	return "private_token", ""
}

func (a *desktop) activeFRPPortRange() clientapi.PortRange {
	if a != nil && a.frpPortRange.Start >= 1 && a.frpPortRange.End <= 65535 && a.frpPortRange.Start <= a.frpPortRange.End {
		return a.frpPortRange
	}
	return clientapi.DefaultFRPPortRange
}

func (a *desktop) applyFRPPortRange(r clientapi.PortRange) {
	if r.Start < 1 || r.End > 65535 || r.Start > r.End {
		r = clientapi.DefaultFRPPortRange
	}
	changed := a.frpPortRange != r
	a.frpPortRange = r
	setLabelIfChanged(a.frpPortRangeHint, trf("允许范围 %d-%d", "Allowed %d-%d", r.Start, r.End))
	if a.frpQuickRemotePort != nil {
		cue := strconv.Itoa(r.Start)
		if changed || a.frpQuickRemotePort.CueBanner() != cue {
			_ = a.frpQuickRemotePort.SetCueBanner(cue)
		}
		if cur, err := strconv.Atoi(strings.TrimSpace(a.frpQuickRemotePort.Text())); err != nil || cur < r.Start || cur > r.End {
			a.prefillQuickRemotePort(true)
		}
	}
}

func (a *desktop) refreshFRPPortRange() {
	if a == nil || a.smokeMode || a.frpPortRangeLoading || a.api == nil || strings.TrimSpace(a.api.BaseURL) == "" {
		return
	}
	a.frpPortRangeLoading = true
	apiCopy := *a.api
	go func() {
		parent := a.ctx
		if parent == nil {
			parent = context.Background()
		}
		ctx, cancel := context.WithTimeout(parent, 3*time.Second)
		apiCopy.Context = ctx
		got, err := apiCopy.FRPPortRange()
		cancel()
		a.ui(func() {
			a.frpPortRangeLoading = false
			if err == nil {
				a.applyFRPPortRange(got)
			}
		})
	}()
}

func (a *desktop) syncFRPServerHost() {
	if a == nil {
		return
	}
	a.frpConfig = bindFRPServerToHost(a.frpConfig, a.frpServerHost())
	a.renderFRPState()
	a.updateFRPRows()
	a.updateFRPButtons()
}

func (a *desktop) initializeFRPUI() {
	a.frpConfig = bindFRPServerToHost(frpctl.NewDefaultConfig(), a.frpServerHost())
	a.frpPortRange = clientapi.DefaultFRPPortRange
	a.frpRuleModel = &frpRuleTableModel{}
	a.frpSnapshot = frpctl.Snapshot{State: "stopped", CoreVersion: frpctl.CoreVersion}
	a.frpProfiles = []frpctl.ProfileInfo{{ID: frpctl.DefaultProfileID, Name: "默认端口映射"}}
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
			provider.UpdateClient(a.api)
			provider.UpdateIdentity(a.membership.Network.ID, a.identity.DeviceID.String())
		}
	}
}

func (a *desktop) selectFRPProfile(id string) {
	a.frpProfileSwitching = true
	defer func() { a.frpProfileSwitching = false }()
	a.frpProfileID = id
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
	a.frpConfig = bindFRPServerToHost(a.frpConfig, a.frpServerHost())
	a.frpSnapshot = frpctl.Snapshot{State: "stopped", CoreVersion: frpctl.CoreVersion}
	a.prefillQuickRemotePort(false)
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
	return bindFRPServerToHost(cfg, a.frpServerHost())
}

func (a *desktop) buildFRPPage() Widget {
	logsBtn := compactButton(&a.frpLogsButton, tr("运行日志", "Logs"), btnSecondary, 90, a.showFRPLogs)
	toggleBtn := compactButton(&a.frpToggleButton, tr("启动映射", "Start"), btnPrimary, 96, a.toggleFRP)

	var headerTitle, localIPLbl, localPortLbl, remotePortLbl, protoLbl, nameLbl, listTitle *walk.Label

	headerRow := Composite{Background: SolidColorBrush{Color: uiWhite}, Layout: HBox{MarginsZero: true, Spacing: 8}, Children: []Widget{
		Label{AssignTo: &headerTitle, Text: tr("添加端口映射", "Add Port Mapping"), TextColor: uiInk, Font: uiFont(12, true), NoPrefix: true},
		Label{AssignTo: &a.frpStatus, Text: tr("● 就绪", "● Ready"), TextColor: uiMuted, Font: uiFont(9, true), NoPrefix: true},
		Label{AssignTo: &a.frpServer, Text: "", TextColor: uiMuted, Font: uiFont(8, false), EllipsisMode: EllipsisEnd, StretchFactor: 1, NoPrefix: true},
		logsBtn,
		toggleBtn,
	}}

	serverEndpointBanner := roundView{Composite: Composite{Background: SolidColorBrush{Color: uiBlueSoft}, Layout: HBox{Margins: Margins{Left: 14, Top: 9, Right: 10, Bottom: 9}, Spacing: 10}, Children: []Widget{
		Label{AssignTo: &a.frpServerBannerTitle, Text: tr("当前连接服务器", "Connected Server"), TextColor: uiMuted, Font: uiFont(9, true), NoPrefix: true},
		Label{AssignTo: &a.frpServerAddrLabel, Text: "—", TextColor: uiBlue, Font: uiMonoFont(11, true), EllipsisMode: EllipsisEnd, StretchFactor: 1, NoPrefix: true},
		eyeButton(&a.frpServerEye, tr("显示或隐藏服务器地址", "Show or hide server address"), func() bool { return !a.frpServerHidden }, a.toggleFRPServerEye),
	}}, fill: uiBlueSoft, radius: 10, border: borderColor(uiBlueBorder), hud: false}

	quickField := func(label string, labelAssign **walk.Label, assign **walk.LineEdit, initial, cue string, minWidth, stretch int) Composite {
		return Composite{StretchFactor: stretch, Background: SolidColorBrush{Color: uiTableAlt}, Layout: VBox{MarginsZero: true, Spacing: 5}, Children: []Widget{
			Label{AssignTo: labelAssign, Text: label, TextColor: uiMuted, Font: uiFont(8, true), NoPrefix: true},
			LineEdit{AssignTo: assign, Text: initial, CueBanner: cue, MinSize: Size{Width: minWidth, Height: 32}, MaxSize: Size{Height: 32}, Font: uiFont(9, false), TextColor: uiInk, Background: SolidColorBrush{Color: uiWhite}, OnKeyDown: func(k walk.Key) {
				if k == walk.KeyReturn {
					a.quickAddFRPMapping()
				}
			}},
		}}
	}

	pickBtn := makeActionView(&a.frpPickProcessButton, tr("选择进程", "Processes"), btnSecondary, 88, 32, 7, 9, false, a.showLocalProcessPicker)
	quickAddBtn := makeActionView(&a.frpQuickAddButton, tr("+ 添加映射", "+ Add Rule"), btnPrimary, 108, 32, 8, 9, true, a.quickAddFRPMapping)

	quickComposer := roundView{Composite: Composite{Background: SolidColorBrush{Color: uiTableAlt}, Layout: HBox{Margins: Margins{Left: 14, Top: 11, Right: 14, Bottom: 12}, Spacing: 10}, Children: []Widget{
		quickField(tr("本地 IP", "Local IP"), &localIPLbl, &a.frpQuickLocalIP, "127.0.0.1", "127.0.0.1", 108, 0),
		quickField(tr("本地端口", "Local Port"), &localPortLbl, &a.frpQuickLocalPort, "", "25565", 74, 0),
		Composite{Background: SolidColorBrush{Color: uiTableAlt}, Layout: VBox{MarginsZero: true, Spacing: 5}, Children: []Widget{
			Label{Text: " ", Font: uiFont(8, true), NoPrefix: true},
			Label{Text: "→", TextColor: uiBlue, Font: uiFont(12, true), MinSize: Size{Width: 18, Height: 32}, MaxSize: Size{Width: 18, Height: 32}, TextAlignment: AlignCenter, NoPrefix: true},
		}},
		quickField(tr("服务器端口", "Remote Port"), &remotePortLbl, &a.frpQuickRemotePort, "60000", "60000", 80, 0),
		Composite{Background: SolidColorBrush{Color: uiTableAlt}, Layout: VBox{MarginsZero: true, Spacing: 5}, Children: []Widget{
			Label{AssignTo: &protoLbl, Text: tr("协议", "Proto"), TextColor: uiMuted, Font: uiFont(8, true), NoPrefix: true},
			comboBoxView{ComboBox: ComboBox{AssignTo: &a.frpQuickProto, Model: []string{"TCP", "UDP", "TCP+UDP"}, CurrentIndex: 0, MinSize: Size{Width: 92, Height: 32}, MaxSize: Size{Height: 32}, Font: uiFont(10, false)}},
		}},
		quickField(tr("名称（可选）", "Name (optional)"), &nameLbl, &a.frpQuickName, "", tr("自动生成或自定义", "Auto or custom"), 110, 1),
		Composite{Background: SolidColorBrush{Color: uiTableAlt}, Layout: VBox{MarginsZero: true, Spacing: 5}, Children: []Widget{
			Label{Text: " ", Font: uiFont(8, true), NoPrefix: true},
			Composite{Background: SolidColorBrush{Color: uiTableAlt}, Layout: HBox{MarginsZero: true, Spacing: 8}, Children: []Widget{
				pickBtn,
				quickAddBtn,
			}},
		}},
	}}, fill: uiTableAlt, radius: 10, border: borderColor(uiBorder), hud: false}

	quickCard := roundView{Composite: Composite{Background: SolidColorBrush{Color: uiWhite}, Layout: VBox{Margins: Margins{Left: 18, Top: 14, Right: 18, Bottom: 14}, Spacing: 10}, Children: []Widget{
		headerRow,
		serverEndpointBanner,
		quickComposer,
	}}, fill: uiWhite, radius: 12, border: borderColor(uiBorder), hud: false}

	copyBtn := compactButton(&a.frpCopyAddrButton, tr("复制地址", "Copy Addr"), btnSecondary, 86, a.copySelectedFRPAddress)
	toggleRuleBtn := compactButton(&a.frpToggleRuleButton, tr("停用/启用", "Enable/Disable"), btnSecondary, 112, a.toggleSelectedFRPRule)
	edit := compactButton(&a.frpEditButton, tr("编辑", "Edit"), btnSecondary, 64, a.showEditFRPRule)
	remove := compactButton(&a.frpDeleteButton, tr("删除", "Delete"), btnDanger, 64, a.deleteFRPRule)

	ruleHeader := Composite{Background: SolidColorBrush{Color: uiWhite}, Layout: HBox{MarginsZero: true, Spacing: 8}, Children: []Widget{
		Label{AssignTo: &listTitle, Text: tr("映射列表", "Mappings"), TextColor: uiInk, Font: uiFont(12, true), NoPrefix: true},
		Label{AssignTo: &a.frpRuleCount, Text: tr("0 条", "0"), TextColor: uiBlue, Font: uiFont(9, true), NoPrefix: true},
		Label{AssignTo: &a.frpPortRangeHint, Text: tr("允许范围 60000-61000", "Allowed 60000-61000"), TextColor: uiMuted, Font: uiMonoFont(8, false), NoPrefix: true},
		HSpacer{},
		copyBtn,
		toggleRuleBtn,
		edit,
		remove,
	}}
	ruleTable := TableView{
		AssignTo:                    &a.frpRules,
		Model:                       a.frpRuleModel,
		Background:                  SolidColorBrush{Color: uiWhite},
		Font:                        uiFont(9, false),
		StretchFactor:               1,
		MinSize:                     Size{Height: 260},
		CustomRowHeight:             34,
		CustomHeaderHeight:          30,
		LastColumnStretched:         true,
		SelectionHiddenWithoutFocus: true,
		AlternatingRowBG:            true,
		OnCurrentIndexChanged:       a.updateFRPButtons,
		OnItemActivated:             a.copySelectedFRPAddress,
		ContextMenuItems: []MenuItem{
			Action{Text: tr("复制服务器映射地址", "Copy Remote Address"), OnTriggered: a.copySelectedFRPAddress},
			Action{Text: tr("启用 / 停用", "Enable / Disable"), OnTriggered: a.toggleSelectedFRPRule},
			Action{Text: tr("编辑映射", "Edit Rule"), OnTriggered: a.showEditFRPRule},
			Separator{},
			Action{Text: tr("删除", "Delete"), OnTriggered: a.deleteFRPRule},
		},
		Columns: []TableViewColumn{
			{Title: tr("名称 / 进程", "Name / Process"), Width: 146},
			{Title: tr("协议", "Proto"), Width: 58},
			{Title: tr("本地地址", "Local Addr"), Width: 140},
			{Title: tr("服务器映射地址", "Remote Addr"), Width: 204},
			{Title: tr("状态", "Status"), Width: 80},
			{Title: tr("说明", "Details"), Width: 130},
		},
		StyleCell: func(s *walk.CellStyle) {
			if s.Row() < 0 {
				titles := []string{
					tr("名称 / 进程", "Name / Process"),
					tr("协议", "Proto"),
					tr("本地地址", "Local Addr"),
					tr("服务器映射地址", "Remote Addr"),
					tr("状态", "Status"),
					tr("说明", "Details"),
				}
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
			if s.Row() < 0 || s.Row() >= len(a.frpRuleModel.rows) {
				return
			}
			row := a.frpRuleModel.rows[s.Row()]
			if len(row) > 4 && (row[4] == "已禁用" || row[4] == "Disabled") {
				s.TextColor = uiMuted
			} else if len(row) > 4 && (row[4] == "已映射" || row[4] == "Mapped" || row[4] == "已发布" || row[4] == "Published" || row[4] == "已注册" || row[4] == "Registered" || row[4] == "监听中" || row[4] == "Listening") && s.Col() == 4 {
				s.TextColor = uiSuccess
			} else if s.Col() == 3 {
				s.TextColor = uiBlue
			}
			if len(row) > 5 && row[5] != "—" && row[5] != "" && row[5] != "可用" && row[5] != "Available" && row[5] != "未验证" && row[5] != "Unverified" && !strings.Contains(row[5], "正常") && !strings.Contains(row[5], "可达") && !strings.Contains(row[5], "Healthy") && !strings.Contains(row[5], "Reachable") {
				s.TextColor = uiDanger
			}
		},
	}
	a.onLang(func() {
		setLabelText(headerTitle, tr("添加端口映射", "Add Port Mapping"))
		setLabelText(localIPLbl, tr("本地 IP", "Local IP"))
		setLabelText(localPortLbl, tr("本地端口", "Local Port"))
		setLabelText(remotePortLbl, tr("服务器端口", "Remote Port"))
		setLabelText(protoLbl, tr("协议", "Proto"))
		setLabelText(nameLbl, tr("名称（可选）", "Name (optional)"))
		setLabelText(listTitle, tr("映射列表", "Mappings"))
		if a.frpQuickName != nil {
			_ = a.frpQuickName.SetCueBanner(tr("自动生成或自定义", "Auto or custom"))
		}
		if a.frpServerBannerTitle != nil {
			setLabelIfChanged(a.frpServerBannerTitle, tr("当前连接服务器", "Connected Server"))
		}
		setButtonText(a.frpLogsButton, tr("运行日志", "Logs"))
		a.updateConnectedServerDisplays()
		setButtonText(a.frpPickProcessButton, tr("选择进程", "Processes"))
		setButtonText(a.frpQuickAddButton, tr("+ 添加映射", "+ Add Rule"))
		setButtonText(a.frpCopyAddrButton, tr("复制地址", "Copy Addr"))
		setButtonText(a.frpEditButton, tr("编辑", "Edit"))
		setButtonText(a.frpDeleteButton, tr("删除", "Delete"))
		a.renderFRPState()
		a.updateFRPRows()
		a.updateFRPButtons()
	})
	rulesCard := roundView{Composite: Composite{Background: SolidColorBrush{Color: uiWhite}, StretchFactor: 1, Layout: VBox{Margins: Margins{Left: 18, Top: 14, Right: 18, Bottom: 14}, Spacing: 10}, Children: []Widget{
		ruleHeader,
		ruleTable,
	}}, fill: uiWhite, radius: 12, border: borderColor(uiBorder), hud: false}
	rulesCard.Composite.StretchFactor = 1

	logsCard := Composite{Visible: false, Layout: VBox{MarginsZero: true}, Children: []Widget{
		TextEdit{AssignTo: &a.frpLogs, ReadOnly: true},
	}}

	return Composite{AssignTo: &a.frpPage, Visible: false, StretchFactor: 1, Background: SolidColorBrush{Color: uiBackground}, Layout: VBox{Margins: Margins{Left: 20, Top: 16, Right: 20, Bottom: 18}, Spacing: 12, Alignment: AlignHNearVNear}, Children: []Widget{
		quickCard,
		rulesCard,
		logsCard,
	}}
}

func (a *desktop) configureFRPTable() {
	styleFramelessTable(a.frpRules)
}

func (a *desktop) requireMemberToken() bool {
	if a.api != nil && strings.HasPrefix(a.api.Token, "member_") {
		return true
	}
	if code := strings.TrimSpace(a.token); code != "" {
		a.joinAfter = func() {
			a.railSelection = 0
			a.showPage(pageFRP)
		}
		a.join()
		return false
	}
	a.showPage(pageJoin)
	a.code.SetFocus()
	a.showNotice(clientui.Feedback{
		Title:   tr("请先登录私有组网", "Sign In Required"),
		Message: tr("端口映射需要先输入有效入网密钥并加入网络。", "Port mapping requires joining the network with a valid join key first."),
	})
	return false
}

func (a *desktop) openFRP() {
	if !a.requireMemberToken() {
		return
	}
	a.railSelection = 0
	a.showPage(pageFRP)
	a.refreshFRPPortRange()
	a.updateConnectedServerDisplays()
	a.ensureFRPConfigured(nil)
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
				a.frpConfig = bindFRPServerToHost(cfg, a.frpServerHost())
			} else {
				a.frpConfig = bindFRPServerToHost(a.frpConfig, a.frpServerHost())
			}
			a.prefillQuickRemotePort(false)
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
	ready := a.frpInitErr == nil && a.frpManager != nil
	if a.frpInitErr != nil {
		setLabelIfChanged(a.frpStatus, tr("● 组件异常", "● Error"))
		setLabelColorIfChanged(a.frpStatus, uiDanger)
		setLabelIfChanged(a.frpServer, clientui.RedactLang(currentLang(), a.frpInitErr.Error()))
		setButtonTextIfChanged(a.frpToggleButton, tr("启动映射", "Start"))
		setButtonEnabledIfChanged(a.frpToggleButton, false)
		setButtonEnabledIfChanged(a.frpLogsButton, false)
		setButtonEnabledIfChanged(a.frpQuickAddButton, false)
		setButtonEnabledIfChanged(a.frpPickProcessButton, false)
		setButtonEnabledIfChanged(a.frpEditButton, false)
		setButtonEnabledIfChanged(a.frpDeleteButton, false)
		a.updateFRPButtons()
		a.updateConnectedServerDisplays()
		return
	}
	if a.frpManager == nil {
		setLabelIfChanged(a.frpStatus, tr("● 未就绪", "● Not Ready"))
		setLabelColorIfChanged(a.frpStatus, uiMuted)
		setLabelIfChanged(a.frpServer, tr("等待初始化端口映射组件", "Waiting for port mapping initialization"))
		setButtonTextIfChanged(a.frpToggleButton, tr("启动映射", "Start"))
		setButtonEnabledIfChanged(a.frpToggleButton, false)
		setButtonEnabledIfChanged(a.frpLogsButton, false)
		setButtonEnabledIfChanged(a.frpQuickAddButton, false)
		setButtonEnabledIfChanged(a.frpPickProcessButton, false)
		setButtonEnabledIfChanged(a.frpEditButton, false)
		setButtonEnabledIfChanged(a.frpDeleteButton, false)
		a.updateFRPButtons()
		a.updateConnectedServerDisplays()
		return
	}
	s := a.frpSnapshot
	var statusText, serverText string
	var statusColor walk.Color
	switch {
	case !s.Configured:
		statusText, statusColor = tr("● 就绪", "● Ready"), uiMuted
	case s.Running:
		if s.Authenticated {
			statusText, statusColor = tr("● 运行中", "● Running"), uiSuccess
		} else {
			statusText, statusColor = tr("● 连接中", "● Connecting"), uiWarning
		}
	case s.State == "starting":
		statusText, statusColor = tr("● 启动中", "● Starting"), uiWarning
		serverText = tr("正在建立安全映射隧道…", "Establishing mapping tunnel…")
	case s.State == "waiting_dependency" || s.State == "retry_backoff":
		statusText, statusColor = tr("● 等待重连", "● Reconnecting"), uiWarning
		if s.LastError != "" {
			serverText = s.LastError
		} else {
			serverText = tr("等待网络恢复", "Waiting for network recovery")
		}
	case s.State == "failed":
		if s.DesiredRunning {
			statusText = tr("● 重试中", "● Retrying")
			serverText = tr("正在自动重连，可点击“停止映射”取消", "Reconnecting automatically; click Stop to cancel")
		} else {
			statusText = tr("● 连接异常", "● Failed")
			serverText = s.LastError
		}
		statusColor = uiDanger
	case s.State == "stopping":
		statusText, statusColor = tr("● 停止中", "● Stopping"), uiWarning
		serverText = tr("正在停止端口映射服务…", "Stopping port mapping service...")
	default:
		statusText, statusColor = tr("● 已停止", "● Stopped"), uiMuted
	}
	setLabelIfChanged(a.frpStatus, statusText)
	setLabelColorIfChanged(a.frpStatus, statusColor)
	setLabelIfChanged(a.frpServer, serverText)

	canStop := s.CanStop || s.Running || s.State == "stopping"
	toggleText := tr("启动映射", "Start")
	if s.Running {
		toggleText = tr("停止映射", "Stop")
	} else if canStop {
		toggleText = tr("取消启动", "Cancel")
	}
	setButtonTextIfChanged(a.frpToggleButton, toggleText)

	toggleEnabled := ready && !a.frpBusy
	if canStop {
		toggleEnabled = ready && !a.frpStopping && (!a.frpBusy || a.frpStarting)
	}
	setButtonEnabledIfChanged(a.frpToggleButton, toggleEnabled)

	editable := !a.frpBusy && !a.frpStarting && !a.frpStopping && ready
	setButtonEnabledIfChanged(a.frpLogsButton, ready)
	setButtonEnabledIfChanged(a.frpQuickAddButton, editable)
	setButtonEnabledIfChanged(a.frpPickProcessButton, editable)
	a.updateFRPButtons()
	a.updateConnectedServerDisplays()
}

func (a *desktop) updateFRPRows() {
	if a.frpRuleModel == nil {
		return
	}
	host := a.frpServerHost()
	if host == "" {
		host = a.frpConfig.Profile.Server.Host
	}
	rows := make([][]string, 0, len(a.frpConfig.Profile.Rules))
	a.frpRows = make([]frpEntryRef, 0, len(a.frpConfig.Profile.Rules))
	statuses := a.frpSnapshot.Rules
	for i, rule := range a.frpConfig.Profile.Rules {
		remote := "—"
		if rule.Exposure.RemotePort > 0 && host != "" {
			remote = fmt.Sprintf("%s:%d", host, rule.Exposure.RemotePort)
		} else if rule.Exposure.RemotePort > 0 {
			remote = fmt.Sprintf(":%d", rule.Exposure.RemotePort)
		}
		state := tr("已停止", "Stopped")
		if !rule.Enabled {
			state = tr("已禁用", "Disabled")
		}
		note := "—"
		if i < len(statuses) {
			status := statuses[i]
			switch status.State {
			case "已发布":
				state = tr("已映射", "Mapped")
			case "已注册":
				state = tr("已注册", "Registered")
			case "监听中":
				state = tr("监听中", "Listening")
			case "注册失败":
				state = tr("注册失败", "Failed")
			case "等待注册":
				state = tr("等待注册", "Pending")
			case "等待组网恢复":
				state = tr("等待重连", "Waiting Mesh")
			case "已停止":
				state = tr("已停止", "Stopped")
			case "已禁用":
				state = tr("已禁用", "Disabled")
			case "":
			default:
				state = status.State
			}
			if status.RemoteAddr != "" {
				remote = status.RemoteAddr
			}
			if status.ErrorDetail != "" {
				note = status.ErrorDetail
			} else if status.Backend != "" && status.Backend != "—" {
				note = status.Backend
			}
		}
		rows = append(rows, []string{rule.Name, strings.ToUpper(rule.Type), fmt.Sprintf("%s:%d", rule.Target.Host, rule.Target.Port), remote, state, note})
		a.frpRows = append(a.frpRows, frpEntryRef{index: i})
	}
	a.frpRuleModel.setRows(rows)
	setLabelIfChanged(a.frpRuleCount, trf("%d 条", "%d", len(rows)))
	if a.frpLogs != nil {
		joinedLogs := strings.Join(a.frpSnapshot.Logs, "\r\n")
		if a.frpLogs.Text() != joinedLogs {
			a.frpLogs.SetText(joinedLogs)
		}
	}
}

func (a *desktop) updateFRPButtons() {
	if a.frpEditButton == nil || a.frpDeleteButton == nil {
		return
	}
	index := a.selectedFRPIndex()
	ok := index >= 0 && index < len(a.frpConfig.Profile.Rules)
	setButtonEnabledIfChanged(a.frpEditButton, !a.frpBusy && ok)
	setButtonEnabledIfChanged(a.frpDeleteButton, !a.frpBusy && ok)
	if a.frpToggleRuleButton != nil {
		setButtonEnabledIfChanged(a.frpToggleRuleButton, !a.frpBusy && ok)
		toggleText := tr("停用/启用", "Enable/Disable")
		if ok {
			if a.frpConfig.Profile.Rules[index].Enabled {
				toggleText = tr("停用规则", "Disable")
			} else {
				toggleText = tr("启用规则", "Enable")
			}
		}
		setButtonTextIfChanged(a.frpToggleRuleButton, toggleText)
	}
	if a.frpCopyAddrButton != nil {
		hasAddr := false
		if ok {
			row := a.frpRules.CurrentIndex()
			if row >= 0 && row < len(a.frpRuleModel.rows) {
				addr := a.frpRuleModel.rows[row][3]
				hasAddr = addr != "" && addr != "—"
			}
		}
		setButtonEnabledIfChanged(a.frpCopyAddrButton, hasAddr)
	}
}

func (a *desktop) selectedFRPIndex() int {
	if a.frpRules == nil {
		return -1
	}
	row := a.frpRules.CurrentIndex()
	if row < 0 || row >= len(a.frpRows) {
		return -1
	}
	idx := a.frpRows[row].index
	if idx < 0 || idx >= len(a.frpConfig.Profile.Rules) {
		return -1
	}
	return idx
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
				a.showFRPError(tr("启动端口映射", "Start port mapping"), err)
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
				a.showFRPError(tr("停止端口映射", "Stop port mapping"), err)
			}
			a.refreshFRP()
			a.renderFRPState()
		})
	}()
}

func (a *desktop) prefillQuickRemotePort(force bool) {
	if a.frpQuickRemotePort == nil {
		return
	}
	if !force && strings.TrimSpace(a.frpQuickRemotePort.Text()) != "" {
		return
	}
	r := a.activeFRPPortRange()
	cue := strconv.Itoa(r.Start)
	if a.frpQuickRemotePort.CueBanner() != cue {
		_ = a.frpQuickRemotePort.SetCueBanner(cue)
	}
	localPort := 0
	if a.frpQuickLocalPort != nil {
		localPort, _ = strconv.Atoi(strings.TrimSpace(a.frpQuickLocalPort.Text()))
	}
	nextPort := suggestRemotePortInRange(a.frpConfig.Profile.Rules, localPort, r.Start, r.End)
	nextText := strconv.Itoa(nextPort)
	if a.frpQuickRemotePort.Text() != nextText {
		_ = a.frpQuickRemotePort.SetText(nextText)
	}
}

func (a *desktop) showLocalProcessPicker() {
	entries, err := listLocalListeningPorts()
	if err != nil {
		a.showFRPError(tr("读取本地进程列表", "Load local processes"), err)
		return
	}
	a.showLocalProcessPickerWithEntries(entries)
}

func (a *desktop) showLocalProcessPickerWithEntries(entries []localPortEntry) {
	if len(entries) == 0 {
		if live, err := listLocalListeningPorts(); err == nil {
			entries = live
		}
	}
	var dlg *walk.Dialog
	var searchEdit *walk.LineEdit
	var protoBox *walk.ComboBox
	var table *walk.TableView
	var countLabel *walk.Label
	var selectButton, closeButton *walk.PushButton
	model := &frpRuleTableModel{}
	var filtered []localPortEntry

	applyFilter := func() {
		q := ""
		if searchEdit != nil {
			q = searchEdit.Text()
		}
		proto := ""
		if protoBox != nil {
			switch protoBox.CurrentIndex() {
			case 1:
				proto = "tcp"
			case 2:
				proto = "udp"
			}
		}
		filtered = filterLocalPortEntries(entries, q, proto)
		rows := make([][]string, 0, len(filtered))
		for _, item := range filtered {
			rows = append(rows, []string{
				item.ProcessName,
				strconv.FormatUint(uint64(item.PID), 10),
				strings.ToUpper(item.Protocol),
				item.BindIP,
				strconv.Itoa(item.Port),
			})
		}
		model.setRows(rows)
		if countLabel != nil {
			_ = countLabel.SetText(trf("%d 个监听端口", "%d listening", len(filtered)))
		}
		if selectButton != nil {
			selectButton.SetEnabled(table != nil && table.CurrentIndex() >= 0 && table.CurrentIndex() < len(filtered))
		}
	}

	pickSelected := func() {
		if table == nil {
			return
		}
		idx := table.CurrentIndex()
		if idx < 0 || idx >= len(filtered) {
			return
		}
		chosen := filtered[idx]
		if a.frpQuickLocalIP != nil {
			_ = a.frpQuickLocalIP.SetText(chosen.TargetIP)
		}
		if a.frpQuickLocalPort != nil {
			_ = a.frpQuickLocalPort.SetText(strconv.Itoa(chosen.Port))
		}
		if a.frpQuickProto != nil {
			if chosen.Protocol == "udp" {
				_ = a.frpQuickProto.SetCurrentIndex(1)
			} else {
				_ = a.frpQuickProto.SetCurrentIndex(0)
			}
		}
		if a.frpQuickName != nil {
			_ = a.frpQuickName.SetText(suggestRuleName(chosen.ProcessName, chosen.Port, a.frpConfig.Profile.Rules))
		}
		if a.frpQuickRemotePort != nil && strings.TrimSpace(a.frpQuickRemotePort.Text()) == "" {
			r := a.activeFRPPortRange()
			_ = a.frpQuickRemotePort.SetText(strconv.Itoa(suggestRemotePortInRange(a.frpConfig.Profile.Rules, chosen.Port, r.Start, r.End)))
		}
		dlg.Accept()
		if a.frpQuickRemotePort != nil {
			_ = a.frpQuickRemotePort.SetFocus()
		}
	}

	err := (Dialog{
		AssignTo: &dlg, Title: tr("选择本地监听进程", "Select Local Process"), Icon: a.appIcon,
		Size: Size{Width: 680, Height: 480}, MinSize: Size{Width: 580, Height: 380},
		Font: uiFont(10, false), Background: SolidColorBrush{Color: uiWhite},
		Layout:       VBox{Margins: Margins{Left: 22, Top: 18, Right: 22, Bottom: 18}, Spacing: 10},
		CancelButton: &closeButton, DefaultButton: &selectButton,
		Children: []Widget{
			Composite{Background: SolidColorBrush{Color: uiWhite}, Layout: HBox{MarginsZero: true, Spacing: 8}, Children: []Widget{
				Label{Text: tr("选择需要映射的本机进程", "Select Local Listening Process"), TextColor: uiInk, Font: uiFont(12, true), NoPrefix: true},
				HSpacer{},
				Label{AssignTo: &countLabel, Text: tr("0 个监听端口", "0 listening"), TextColor: uiBlue, Font: uiFont(9, true), NoPrefix: true},
			}},
			Composite{Background: SolidColorBrush{Color: uiWhite}, Layout: HBox{MarginsZero: true, Spacing: 8}, Children: []Widget{
				LineEdit{AssignTo: &searchEdit, StretchFactor: 1, CueBanner: tr("搜索进程名、端口、PID 或 IP…", "Search process, port, PID, or IP..."), Font: uiFont(9, false), TextColor: uiInk, Background: SolidColorBrush{Color: uiWhite}, OnTextChanged: applyFilter},
				comboBoxView{ComboBox: ComboBox{AssignTo: &protoBox, Model: []string{tr("全部协议", "All Protos"), tr("仅 TCP", "TCP Only"), tr("仅 UDP", "UDP Only")}, CurrentIndex: 0, MinSize: Size{Width: 100, Height: 30}, MaxSize: Size{Height: 30}, Font: uiFont(9, false), OnCurrentIndexChanged: applyFilter}},
				compactButton(nil, tr("刷新列表", "Refresh"), btnSecondary, 82, func() {
					if live, refreshErr := listLocalListeningPorts(); refreshErr == nil {
						entries = live
						applyFilter()
					}
				}),
			}},
			TableView{
				AssignTo:                    &table,
				Model:                       model,
				Background:                  SolidColorBrush{Color: uiWhite},
				Font:                        uiFont(9, false),
				StretchFactor:               1,
				CustomRowHeight:             32,
				CustomHeaderHeight:          28,
				LastColumnStretched:         true,
				SelectionHiddenWithoutFocus: true,
				AlternatingRowBG:            true,
				OnCurrentIndexChanged: func() {
					if selectButton != nil {
						selectButton.SetEnabled(table != nil && table.CurrentIndex() >= 0 && table.CurrentIndex() < len(filtered))
					}
				},
				OnItemActivated: pickSelected,
				Columns: []TableViewColumn{
					{Title: tr("进程名称", "Process"), Width: 170},
					{Title: "PID", Width: 66},
					{Title: tr("协议", "Proto"), Width: 56},
					{Title: tr("监听地址", "Listen Addr"), Width: 118},
					{Title: tr("本地端口", "Local Port"), Width: 78},
				},
				StyleCell: func(s *walk.CellStyle) {
					if s.Row() < 0 {
						titles := []string{tr("进程名称", "Process"), "PID", tr("协议", "Proto"), tr("监听地址", "Listen Addr"), tr("本地端口", "Local Port")}
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
					if s.Col() == 4 {
						s.TextColor = uiBlue
					} else if s.Col() == 2 {
						s.TextColor = uiMuted
					}
				},
			},
			Composite{Background: SolidColorBrush{Color: uiWhite}, Layout: HBox{MarginsZero: true, Spacing: 10}, Children: []Widget{
				HSpacer{},
				actionButton(&closeButton, tr("取消", "Cancel"), false, 80, func() { dlg.Cancel() }),
				actionButton(&selectButton, tr("填入选中进程", "Use Selected"), true, 114, pickSelected),
			}},
		},
	}).Create(a.window)
	if err != nil {
		a.showFRPError(tr("打开进程选择窗口", "Open process picker"), err)
		return
	}
	styleFramelessTable(table)
	applyFilter()
	if table != nil && len(filtered) > 0 {
		_ = table.SetCurrentIndex(0)
		if selectButton != nil {
			selectButton.SetEnabled(true)
			_ = selectButton.Invalidate()
		}
	}
	defer dlg.Dispose()
	runThemedDialog(dlg)
}

func (a *desktop) quickAddFRPMapping() {
	if a.frpManager == nil {
		a.showFRPError(tr("添加端口映射", "Add port mapping"), a.frpInitErr)
		return
	}
	if a.frpBusy {
		return
	}
	localIP := "127.0.0.1"
	if a.frpQuickLocalIP != nil {
		localIP = a.frpQuickLocalIP.Text()
	}
	localPortText := ""
	if a.frpQuickLocalPort != nil {
		localPortText = strings.TrimSpace(a.frpQuickLocalPort.Text())
	}
	localPort, err := strconv.Atoi(localPortText)
	if err != nil || localPort < 1 || localPort > 65535 {
		a.showNotice(clientui.Feedback{
			Title:   tr("请填写本地端口", "Local Port Required"),
			Message: tr("输入本机正在监听的端口（1-65535），或点击“选择进程”自动填入。", "Enter a local listening port (1-65535), or click Processes to pick one."),
		})
		if a.frpQuickLocalPort != nil {
			_ = a.frpQuickLocalPort.SetFocus()
		}
		return
	}
	portRange := a.activeFRPPortRange()
	remotePortText := ""
	if a.frpQuickRemotePort != nil {
		remotePortText = strings.TrimSpace(a.frpQuickRemotePort.Text())
	}
	remotePort, err := strconv.Atoi(remotePortText)
	if err != nil || remotePort < 1 || remotePort > 65535 {
		a.showNotice(clientui.Feedback{
			Title:   tr("请填写服务器端口", "Remote Port Required"),
			Message: trf("请输入允许范围内的服务器端口（当前：%d-%d）。", "Enter a remote port in the allowed range (%d-%d).", portRange.Start, portRange.End),
		})
		if a.frpQuickRemotePort != nil {
			_ = a.frpQuickRemotePort.SetFocus()
		}
		return
	}
	if remotePort < portRange.Start || remotePort > portRange.End {
		a.showNotice(clientui.Feedback{
			Title:   tr("服务器端口超出允许范围", "Remote Port Out of Range"),
			Message: trf("当前服务器允许的映射端口范围为 %d-%d（可由管理员在管理面板中修改）。", "Allowed remote port range is %d-%d (configurable by admin).", portRange.Start, portRange.End),
		})
		if a.frpQuickRemotePort != nil {
			_ = a.frpQuickRemotePort.SetFocus()
		}
		return
	}
	protoChoice := "tcp"
	if a.frpQuickProto != nil {
		switch a.frpQuickProto.CurrentIndex() {
		case 1:
			protoChoice = "udp"
		case 2:
			protoChoice = "tcp+udp"
		}
	}
	nameText := ""
	if a.frpQuickName != nil {
		nameText = a.frpQuickName.Text()
	}
	newRules, err := buildQuickFRPRules(a.frpConfig.Profile.Rules, nameText, localIP, localPort, remotePort, protoChoice)
	if err != nil {
		a.showNotice(clientui.Feedback{Title: tr("映射参数有误", "Invalid Rule Parameters"), Message: err.Error()})
		return
	}

	commitAndStart := func(baseCfg frpctl.Config, token string) {
		baseCfg = bindFRPServerToHost(baseCfg, a.frpServerHost())
		baseCfg.Profile.Rules = append(baseCfg.Profile.Rules, newRules...)
		if err := frpctl.ValidateConfigWithReservations(baseCfg, a.frpReservations()); err != nil {
			a.showFRPError(tr("校验映射配置", "Validate port mapping"), err)
			return
		}
		a.applyFRPConfigAndStart(baseCfg, token, true)
		if a.frpQuickLocalPort != nil {
			_ = a.frpQuickLocalPort.SetText("")
		}
		if a.frpQuickName != nil {
			_ = a.frpQuickName.SetText("")
		}
		if a.frpQuickRemotePort != nil {
			_ = a.frpQuickRemotePort.SetText(strconv.Itoa(suggestRemotePortInRange(baseCfg.Profile.Rules, 0, portRange.Start, portRange.End)))
		}
	}

	if !a.hasUsableFRPConfig() {
		a.ensureFRPConfigured(func() {
			commitAndStart(a.frpConfig, "")
		})
		return
	}
	cfg := frpctl.CloneConfig(a.frpConfig)
	commitAndStart(cfg, "")
}

func (a *desktop) copySelectedFRPAddress() {
	if a.frpRules == nil {
		return
	}
	row := a.frpRules.CurrentIndex()
	if row < 0 || row >= len(a.frpRuleModel.rows) {
		return
	}
	addr := strings.TrimSpace(a.frpRuleModel.rows[row][3])
	if addr == "" || addr == "—" {
		return
	}
	if err := walk.Clipboard().SetText(addr); err != nil {
		a.showError(tr("复制服务器映射地址", "Copy remote address"), err)
		return
	}
	a.setStatus(tr("已复制映射地址 ", "Copied mapped address ") + addr)
}

func (a *desktop) toggleSelectedFRPRule() {
	index := a.selectedFRPIndex()
	if index < 0 || a.frpBusy || a.frpManager == nil {
		return
	}
	cfg := bindFRPServerToHost(a.frpConfig, a.frpServerHost())
	cfg.Profile.Rules[index].Enabled = !cfg.Profile.Rules[index].Enabled
	a.applyFRPConfig(cfg, "")
}

func (a *desktop) toggleFRP() {
	if !a.requireMemberToken() {
		return
	}
	if a.frpManager == nil {
		a.showFRPError(tr("启动端口映射", "Start port mapping"), a.frpInitErr)
		return
	}
	if !a.hasUsableFRPConfig() {
		a.ensureFRPConfigured(func() {
			a.startFRP()
		})
		return
	}
	if a.frpSnapshot.Running || a.frpSnapshot.CanStop || a.frpSnapshot.State == "stopping" {
		a.stopFRP()
		return
	}
	if stored, ok := a.frpManager.Config(); ok && !strings.EqualFold(stored.Profile.Server.Host, a.frpServerHost()) {
		bound := bindFRPServerToHost(stored, a.frpServerHost())
		a.applyFRPConfigAndStart(bound, "", true)
		return
	}
	a.startFRP()
}

func (a *desktop) applyFRPConfig(cfg frpctl.Config, token string) {
	a.applyFRPConfigAndStart(cfg, token, false)
}

func (a *desktop) applyFRPConfigAndStart(cfg frpctl.Config, token string, autoStart bool) {
	if a.frpBusy || a.frpManager == nil {
		return
	}
	cfg = bindFRPServerToHost(cfg, a.frpServerHost())
	a.frpBusy = true
	a.renderFRPState()
	go func() {
		parent := a.ctx
		if parent == nil {
			parent = context.Background()
		}
		ctx, cancel := context.WithTimeout(parent, 40*time.Second)
		saved, err := a.frpManager.ApplyWithSecrets(ctx, cfg, token, nil)
		if err == nil && autoStart {
			if snap := a.frpManager.Snapshot(ctx); !snap.Running {
				err = a.frpManager.Start(ctx)
			}
		}
		cancel()
		a.ui(func() {
			a.frpBusy = false
			if err != nil {
				a.showFRPError(tr("应用端口映射", "Apply port mapping"), err)
			} else {
				a.frpConfig = bindFRPServerToHost(saved, a.frpServerHost())
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
	f := clientui.ExplainLang(currentLang(), action, err)
	a.showNotice(f)
}

func (a *desktop) hasUsableFRPConfig() bool {
	if a == nil || a.frpManager == nil || !a.frpManager.HasToken() {
		return false
	}
	srv := a.frpConfig.Profile.Server
	if strings.TrimSpace(srv.TrustedCAPath) == "" && !srv.UseSystemCA {
		return false
	}
	if host := a.frpServerHost(); host != "" && !strings.EqualFold(strings.TrimSpace(srv.Host), host) {
		return false
	}
	return a.frpSnapshot.Configured || strings.TrimSpace(srv.Host) != ""
}

func (a *desktop) ensureFRPConfigured(after func()) {
	if a.hasUsableFRPConfig() {
		if after != nil {
			after()
		}
		return
	}
	a.bootstrapFRPFromServer(after)
}

func (a *desktop) bootstrapFRPFromServer(after func()) {
	if a == nil || a.frpManager == nil || a.api == nil || !strings.HasPrefix(a.api.Token, "member_") || a.smokeMode {
		if after != nil {
			a.showNotice(clientui.Feedback{
				Title:   tr("端口映射凭据未就绪", "Port Mapping Not Provisioned"),
				Message: tr("未能从服务器获取端口映射配置，请确认服务端已开启端口映射并下发客户端凭据。", "Could not retrieve FRP bootstrap configuration from the server."),
			})
		}
		return
	}
	apiCopy := *a.api
	serverHost := a.frpServerHost()
	parentCtx := a.ctx
	if parentCtx == nil {
		parentCtx = context.Background()
	}
	baseCfg := frpctl.CloneConfig(a.frpConfig)
	if stored, ok := a.frpManager.Config(); ok {
		baseCfg = frpctl.CloneConfig(stored)
	}
	go func() {
		ctx, cancel := context.WithTimeout(parentCtx, 8*time.Second)
		apiCopy.Context = ctx
		boot, bootErr := apiCopy.FRPBootstrap()
		caps, capErr := apiCopy.FRPCapabilities()
		var saved frpctl.Config
		var saveErr error
		if bootErr == nil && boot.Enabled && strings.TrimSpace(boot.Token) != "" {
			host := strings.TrimSpace(boot.Host)
			if host == "" {
				host = serverHost
			}
			nextCfg := bindFRPServerToHost(baseCfg, host)
			if boot.Port > 0 {
				nextCfg.Profile.Server.Port = boot.Port
			}
			if trName := strings.ToLower(strings.TrimSpace(boot.Transport)); trName != "" {
				nextCfg.Profile.Server.Transport = trName
			}
			if sni := strings.TrimSpace(boot.TLSServerName); sni != "" {
				nextCfg.Profile.Server.TLSServerName = sni
			}
			kind, serverID := resolveFRPServerMode(caps, capErr)
			if strings.EqualFold(strings.TrimSpace(boot.Mode), frpauth.ModeManaged) && strings.TrimSpace(boot.ServerID) != "" {
				kind, serverID = "managed", strings.TrimSpace(boot.ServerID)
			}
			nextCfg.Profile.Server.Kind = kind
			nextCfg.Profile.Server.ServerID = serverID
			saved, saveErr = a.frpManager.SaveBootstrap(ctx, nextCfg, boot.Token, []byte(boot.CAPEM))
		}
		cancel()
		a.ui(func() {
			if bootErr != nil {
				if after != nil {
					a.showFRPError(tr("获取端口映射配置", "Fetch port mapping config"), bootErr)
				}
				return
			}
			if !boot.Enabled || strings.TrimSpace(boot.Token) == "" {
				if after != nil {
					a.showNotice(clientui.Feedback{
						Title:   tr("服务端未开启端口映射自动凭据", "Server FRP Bootstrap Disabled"),
						Message: tr("请联系管理员在服务端配置 frp.client_token / client_ca_file 后即可免配直接使用。", "Ask the server administrator to enable FRP client bootstrap on the server."),
					})
				}
				return
			}
			if saveErr != nil {
				if after != nil {
					a.showFRPError(tr("初始化端口映射配置", "Initialize port mapping config"), saveErr)
				}
				return
			}
			a.frpConfig = saved
			a.frpSnapshot.Configured = true
			a.frpSnapshot.ServerHost = saved.Profile.Server.Host
			a.frpSnapshot.ServerPort = saved.Profile.Server.Port
			a.renderFRPState()
			a.updateFRPRows()
			a.updateFRPButtons()
			if after != nil {
				after()
			}
		})
	}()
}

func (a *desktop) showEditFRPRule() {
	index := a.selectedFRPIndex()
	if index < 0 {
		return
	}
	a.showEditFRPRuleDialog(index)
}

func (a *desktop) showEditFRPRuleDialog(index int) {
	if a.frpManager == nil {
		a.showFRPError(tr("编辑端口映射", "Edit port mapping"), a.frpInitErr)
		return
	}
	if index < 0 || index >= len(a.frpConfig.Profile.Rules) {
		return
	}
	cfg := bindFRPServerToHost(a.frpConfig, a.frpServerHost())
	rule := cfg.Profile.Rules[index]
	if rule.Type != "tcp" && rule.Type != "udp" {
		a.showNotice(clientui.Feedback{
			Title:   tr("暂不支持编辑此旧规则", "Unsupported Legacy Rule"),
			Message: tr("当前仅保留 TCP/UDP 端口映射，请删除该条规则后直接重新添加。", "Only TCP/UDP rules can be edited here. Delete this rule and add a new one."),
		})
		return
	}
	var dlg *walk.Dialog
	var nameEdit, localIP, localPort, remotePort *walk.LineEdit
	var protoBox *walk.ComboBox
	var enabled *walk.CheckBox
	var saveButton, closeButton *walk.PushButton
	protoIdx := 0
	if rule.Type == "udp" {
		protoIdx = 1
	}

	err := (Dialog{
		AssignTo: &dlg, Title: tr("编辑端口映射", "Edit Port Mapping"), Icon: a.appIcon,
		Size: Size{Width: 480, Height: 310}, MinSize: Size{Width: 440, Height: 290},
		Font: uiFont(10, false), Background: SolidColorBrush{Color: uiWhite},
		Layout:       VBox{Margins: Margins{Left: 24, Top: 20, Right: 24, Bottom: 18}, Spacing: 12},
		CancelButton: &closeButton, DefaultButton: &saveButton,
		Children: []Widget{
			heading(tr("编辑端口映射", "Edit Port Mapping")),
			Composite{Background: SolidColorBrush{Color: uiWhite}, Layout: HBox{MarginsZero: true, Spacing: 10}, Children: []Widget{
				formLabel(tr("映射名称", "Rule Name"), 84),
				LineEdit{AssignTo: &nameEdit, Text: rule.Name, CueBanner: tr("例如：game_25565", "e.g. game_25565"), Font: uiFont(9, false), TextColor: uiInk, Background: SolidColorBrush{Color: uiWhite}, MinSize: Size{Width: 330}},
			}},
			Composite{Background: SolidColorBrush{Color: uiWhite}, Layout: HBox{MarginsZero: true, Spacing: 10}, Children: []Widget{
				formLabel(tr("协议", "Proto"), 84),
				comboBoxView{ComboBox: ComboBox{AssignTo: &protoBox, Model: []string{"TCP", "UDP"}, CurrentIndex: protoIdx, Font: uiFont(9, false), MinSize: Size{Width: 110, Height: 30}, MaxSize: Size{Height: 30}}},
				themedCheckBox(&enabled, tr("启用此条映射", "Enable rule"), rule.Enabled),
			}},
			Composite{Background: SolidColorBrush{Color: uiWhite}, Layout: HBox{MarginsZero: true, Spacing: 10}, Children: []Widget{
				formLabel(tr("本地 IP", "Local IP"), 84),
				LineEdit{AssignTo: &localIP, Text: rule.Target.Host, CueBanner: "127.0.0.1", Font: uiFont(9, false), TextColor: uiInk, Background: SolidColorBrush{Color: uiWhite}, MinSize: Size{Width: 160}},
				formLabel(tr("本地端口", "Local Port"), 68),
				LineEdit{AssignTo: &localPort, Text: strconv.Itoa(rule.Target.Port), Font: uiFont(9, false), TextColor: uiInk, Background: SolidColorBrush{Color: uiWhite}, MinSize: Size{Width: 90}},
			}},
			Composite{Background: SolidColorBrush{Color: uiWhite}, Layout: HBox{MarginsZero: true, Spacing: 10}, Children: []Widget{
				formLabel(tr("服务器端口", "Remote Port"), 84),
				LineEdit{AssignTo: &remotePort, Text: strconv.Itoa(rule.Exposure.RemotePort), Font: uiFont(9, false), TextColor: uiInk, Background: SolidColorBrush{Color: uiWhite}, MinSize: Size{Width: 110}},
				Label{Text: tr("映射服务器：", "Server: ") + a.frpServerHost(), TextColor: uiMuted, Font: uiMonoFont(8, false), NoPrefix: true, EllipsisMode: EllipsisEnd},
				HSpacer{},
			}},
			VSpacer{StretchFactor: 1},
			Composite{Background: SolidColorBrush{Color: uiWhite}, Layout: HBox{MarginsZero: true, Spacing: 10}, Children: []Widget{
				HSpacer{},
				actionButton(&closeButton, tr("取消", "Cancel"), false, 84, func() { dlg.Cancel() }),
				actionButton(&saveButton, tr("保存映射", "Save"), true, 96, func() {
					local, err := strconv.Atoi(strings.TrimSpace(localPort.Text()))
					if err != nil || local < 1 || local > 65535 {
						walk.MsgBox(dlg, tr("端口不正确", "Invalid Port"), tr("本地端口必须是 1-65535 的数字。", "Local port must be between 1 and 65535."), walk.MsgBoxOK|walk.MsgBoxIconWarning)
						return
					}
					portRange := a.activeFRPPortRange()
					remote, err := strconv.Atoi(strings.TrimSpace(remotePort.Text()))
					if err != nil || remote < 1 || remote > 65535 {
						walk.MsgBox(dlg, tr("端口不正确", "Invalid Port"), tr("服务器端口必须是 1-65535 的数字。", "Remote port must be between 1 and 65535."), walk.MsgBoxOK|walk.MsgBoxIconWarning)
						return
					}
					if remote < portRange.Start || remote > portRange.End {
						walk.MsgBox(dlg, tr("端口超出允许范围", "Port Out of Range"), trf("当前允许的服务器端口范围为 %d-%d。", "Allowed remote port range is %d-%d.", portRange.Start, portRange.End), walk.MsgBoxOK|walk.MsgBoxIconWarning)
						return
					}
					kind, hostVal, err := normalizeLocalTargetIP(localIP.Text())
					if err != nil {
						walk.MsgBox(dlg, tr("本地 IP 不正确", "Invalid Local IP"), err.Error(), walk.MsgBoxOK|walk.MsgBoxIconWarning)
						return
					}
					updated := rule
					updated.Name = strings.TrimSpace(nameEdit.Text())
					updated.Type = []string{"tcp", "udp"}[protoBox.CurrentIndex()]
					updated.Enabled = enabled.Checked()
					updated.Target = frpctl.Target{Kind: kind, Host: hostVal, Port: local}
					updated.Exposure = frpctl.Exposure{RemotePort: remote}
					updated.SecretRef = ""
					cfg.Profile.Rules[index] = updated
					if err = frpctl.ValidateConfigWithReservations(cfg, a.frpReservations()); err != nil {
						showFRPValidationError(dlg, tr("映射配置不正确", "Invalid Rule Configuration"), err)
						return
					}
					a.applyFRPConfig(cfg, "")
					dlg.Accept()
				}),
			}},
		},
	}).Create(a.window)
	if err != nil {
		a.showFRPError(tr("打开编辑窗口", "Open edit dialog"), err)
		return
	}
	defer dlg.Dispose()
	runThemedDialog(dlg)
}

func showFRPValidationError(dlg *walk.Dialog, title string, err error) {
	if err == nil {
		return
	}
	message := tr("配置未保存：", "Configuration not saved: ") + err.Error()
	if frpctl.IsReservedTargetError(err) {
		title = tr("目标或监听端口被保留", "Reserved Port")
		message = tr("系统保留端口（如控制端、FRP 控制端口）不能用于端口映射。\n\n请改用普通业务服务端口。\n\n技术信息：", "System reserved ports cannot be used for port mapping.\n\nChoose a regular service port.\n\nDetails: ") + err.Error()
	}
	walk.MsgBox(dlg, title, message, walk.MsgBoxOK|walk.MsgBoxIconWarning)
}

func (a *desktop) deleteFRPRule() {
	index := a.selectedFRPIndex()
	if index < 0 {
		return
	}
	rule := a.frpConfig.Profile.Rules[index]
	if walk.MsgBox(a.window, tr("删除端口映射", "Delete Rule"), trf("确定删除“%s”吗？", "Delete rule \"%s\"?", rule.Name), walk.MsgBoxYesNo|walk.MsgBoxIconQuestion) != walk.DlgCmdYes {
		return
	}
	cfg := bindFRPServerToHost(a.frpConfig, a.frpServerHost())
	cfg.Profile.Rules = append(cfg.Profile.Rules[:index], cfg.Profile.Rules[index+1:]...)
	a.applyFRPConfig(cfg, "")
}

func (a *desktop) showFRPLogs() {
	if a.frpLogs == nil {
		return
	}
	var dlg *walk.Dialog
	var closeButton *walk.PushButton
	err := (Dialog{
		AssignTo: &dlg, Title: tr("端口映射运行日志", "Port Mapping Logs"), Icon: a.appIcon,
		Size: Size{Width: 760, Height: 520}, MinSize: Size{Width: 620, Height: 400},
		Font: uiFont(10, false), Background: SolidColorBrush{Color: uiWhite},
		Layout:       VBox{Margins: Margins{Left: 24, Top: 22, Right: 24, Bottom: 20}, Spacing: 12},
		CancelButton: &closeButton, DefaultButton: &closeButton,
		Children: []Widget{
			heading(tr("最近运行日志", "Recent Logs")),
			TextEdit{Text: strings.Join(a.frpSnapshot.Logs, "\r\n"), ReadOnly: true, VScroll: true, HScroll: true, StretchFactor: 1, Font: uiMonoFont(9, false), TextColor: uiInk, Background: SolidColorBrush{Color: uiWhite}},
			Composite{Background: SolidColorBrush{Color: uiWhite}, Layout: HBox{MarginsZero: true}, Children: []Widget{HSpacer{}, actionButton(&closeButton, tr("关闭", "Close"), true, 88, func() { dlg.Accept() })}},
		},
	}).Create(a.window)
	if err != nil {
		a.showFRPError(tr("打开运行日志", "Open logs dialog"), err)
		return
	}
	defer dlg.Dispose()
	runThemedDialog(dlg)
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
