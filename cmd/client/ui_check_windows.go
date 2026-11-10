//go:build windows

package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/lxn/walk"
	"github.com/lxn/win"
	"github.com/private-radminlan/lanmesh/internal/clientapi"
	"github.com/private-radminlan/lanmesh/internal/clientidentity"
	frpctl "github.com/private-radminlan/lanmesh/internal/frp"
)

// This internal smoke mode constructs the real controls and exercises native
// painting APIs. It does not contact the service, create an adapter or read
// saved credentials. The window stays hidden throughout the check.
func checkDesktopUI() error {
	a := &desktop{identity: clientidentity.Identity{DeviceID: "dev-ui-smoke", DisplayName: "UI Check"}, api: clientapi.New(bundledServerURL, ""), ctx: context.Background()}
	if err := a.build(); err != nil {
		return err
	}
	a.animationsEnabled = false
	defer a.window.Dispose()
	if err := a.setupTray(); err != nil {
		return fmt.Errorf("tray setup: %w", err)
	}
	if a.trayIcon == nil || !a.trayIcon.Visible() || a.trayIcon.ContextMenu() == nil || a.trayIcon.ContextMenu().Actions().Len() < 7 {
		return fmt.Errorf("tray icon or menu was not initialized")
	}
	if a.settings.CloseToTray || a.settings.LaunchAtLogin {
		return fmt.Errorf("resident settings must default to disabled")
	}
	if a.frpApprovalButton == nil || a.frpImportButton == nil || a.frpExportButton == nil || a.frpBatchButton == nil {
		return fmt.Errorf("advanced FRP action controls were not initialized")
	}
	if a.trayShowAction == nil || a.trayMeshAction == nil || a.trayFRPAction == nil || a.traySettingsAction == nil || a.trayExitAction == nil {
		return fmt.Errorf("tray actions were not initialized")
	}
	if a.trayShowAction.Text() != "显示窗口" || a.trayMeshAction.Text() != "启动 Mesh" || a.trayFRPAction.Text() != "启动当前 FRP 配置" || a.trayExitAction.Text() != "退出程序" {
		return fmt.Errorf("tray action labels are inconsistent: show=%q mesh=%q frp=%q exit=%q", a.trayShowAction.Text(), a.trayMeshAction.Text(), a.trayFRPAction.Text(), a.trayExitAction.Text())
	}
	if a.trayMeshAction.Enabled() || a.trayFRPAction.Enabled() {
		return fmt.Errorf("tray actions must be disabled before credentials or FRP configuration exist")
	}
	if resolveCloseBehavior(false, false, true) != closeBehaviorExit || resolveCloseBehavior(true, false, true) != closeBehaviorTray || resolveCloseBehavior(true, true, true) != closeBehaviorExit || resolveCloseBehavior(true, false, false) != closeBehaviorExit {
		return fmt.Errorf("close behavior policy is inconsistent")
	}
	assertShell := func(visible bool) error {
		got := win.GetWindowLong(a.shellPage.Handle(), win.GWL_STYLE)&win.WS_VISIBLE != 0
		if got != visible {
			return fmt.Errorf("workspace shell visibility = %v, want %v", got, visible)
		}
		if a.railPower == nil || a.railFRP == nil || a.railVersion == nil || a.railMore == nil || a.admin == nil || a.admin.table == nil || a.admin.refresh == nil || a.admin.rename == nil || a.admin.ban == nil || a.toggleButton == nil || a.membersButton == nil || a.connectedArea == nil || a.frpPage == nil || a.frpRules == nil || a.frpToggleButton == nil || a.frpProfileBox == nil || a.frpAddVisitorButton == nil {
			return fmt.Errorf("redesigned navigation or action controls were not initialized")
		}
		return nil
	}
	assertPage := func(want int) error {
		for i, page := range []*walk.Composite{a.joinPage, a.powerPage, a.frpPage, a.admin.page} {
			// IsWindowVisible also considers the hidden root window, so check
			// each page's own native visibility flag instead.
			visible := win.GetWindowLong(page.Handle(), win.GWL_STYLE)&win.WS_VISIBLE != 0
			if visible != (i == want) || a.page != want {
				return fmt.Errorf("page %d visibility incorrect for active page %d", i, want)
			}
		}
		return nil
	}
	if err := assertPage(pageJoin); err != nil {
		return err
	}
	if err := assertShell(false); err != nil {
		return err
	}
	a.api.Token = "member_ui_fixture"
	a.membership = clientapi.Membership{Network: clientapi.Network{ID: "net-ui", Name: "私人网络"}, Member: clientapi.Device{ID: "dev-ui-smoke", Name: "UI Check", VirtualIP: "10.77.0.2"}}
	a.applyMembership()
	if err := assertPage(pagePower); err != nil {
		return err
	}
	if err := assertShell(true); err != nil {
		return err
	}
	a.powerState = 1
	a.updatePowerButtons()
	a.connectedArea.SetVisible(true)
	a.peerModel.setRows([][]string{{"UI Check（本机）", "10.77.0.2", "在线", "本机", "—"}, {"Friend-PC", "10.77.0.3", "在线", "直连", "12 ms"}, {"History-PC", "10.77.0.4", "离线", "—", "—"}})
	a.peers.SetVisible(true)
	a.empty.SetVisible(false)
	a.showPage(pagePower)
	if err := assertPage(pagePower); err != nil {
		return err
	}
	a.setPoweredOff()
	if err := assertPage(pagePower); err != nil {
		return err
	}
	if a.powerState != 0 || a.address.Text() != "10.77.0.2" {
		return fmt.Errorf("power-off state or assigned IP was lost")
	}
	if a.connectedArea.Visible() {
		return fmt.Errorf("connected member area remained visible after power-off")
	}
	a.frpConfig = frpctl.NewDefaultConfig()
	a.frpConfig.Profile.Server.Host = "frp.example.test"
	a.frpConfig.Profile.Server.TLSServerName = "frp.example.test"
	a.frpConfig.Profile.Rules = []frpctl.Rule{{ID: "rule-ui", Name: "UI 测试服务", Type: "tcp", Enabled: true, Target: frpctl.Target{Kind: "loopback", Host: "127.0.0.1", Port: 8080}, Exposure: frpctl.Exposure{RemotePort: 30000}}}
	a.frpSnapshot = frpctl.Snapshot{Configured: true, State: "running", ProfileName: "UI 测试服务", ServerHost: "frp.example.test", ServerPort: 7000, Rules: []frpctl.RuleRuntimeStatus{{RuleID: "rule-ui", Name: "UI 测试服务", Type: "TCP", Enabled: true, State: "已发布", RemoteAddr: "frp.example.test:30000", Backend: "可用"}}}
	a.updateFRPRows()
	a.showPage(pageFRP)
	if err := assertPage(pageFRP); err != nil {
		return err
	}
	if a.frpRules.CurrentIndex() != -1 {
		a.frpRules.SetCurrentIndex(-1)
	}
	a.setAdminMode(true, "Tmkmaj233")
	if !a.railAdmin.Visible() || a.adminAPI == nil {
		return fmt.Errorf("admin mode did not reveal the management panel entry")
	}
	a.admin.busy = true
	a.showPage(pageAdmin)
	a.admin.apply(clientapi.AdminOverview{Service: "tmknetworklan-control", Version: "0.2.0", Stage: "admin-ui-smoke", Network: clientapi.Network{Name: "私人网络", CIDR: "10.77.0.0/24"}, MemberCount: 3, OnlineCount: 2, BlockedCount: 1, RelayStatus: "enabled", RelaySessions: 1, FRPStatus: "managed", FRPLeaseCount: 1}, clientapi.AdminMembers{Members: []clientapi.AdminMember{{ID: "dev-ui-smoke", Name: "UI Check", VirtualIP: "10.77.0.2", Online: true}, {ID: "dev-ui-friend", Name: "Friend-PC", VirtualIP: "10.77.0.3", Online: true, RelayCount: 1}, {ID: "dev-ui-blocked", Name: "Blocked-PC", VirtualIP: "10.77.0.4", Blocked: true}}}, nil)
	a.admin.setBusy(false)
	if err := assertPage(pageAdmin); err != nil {
		return err
	}
	if len(a.admin.model.rows) != 3 || !strings.Contains(a.admin.counts.Text(), "3 / 2") {
		return fmt.Errorf("admin panel fixture did not render overview or members")
	}
	a.admin.table.SetCurrentIndex(2)
	a.admin.refreshButtons()
	if !a.admin.unban.Enabled() || a.admin.ban.Enabled() {
		return fmt.Errorf("admin member actions did not reflect blocked state")
	}
	a.setAdminMode(false, "")
	a.showPage(pagePower)
	if err := assertPage(pagePower); err != nil {
		return err
	}
	dc := win.GetDC(a.window.Handle())
	if dc == 0 {
		return fmt.Errorf("could not obtain UI drawing context")
	}
	defer win.ReleaseDC(a.window.Handle(), dc)
	c := newSmoothCanvas(dc)
	defer c.dispose()
	border := uiBlue
	c.rounded(win.RECT{Right: 340, Bottom: 56}, 16, uiWhite, &border)
	for _, kind := range []string{"power", "frp", "admin", "network", "more"} {
		c.navIcon(win.RECT{Right: 42, Bottom: 42}, kind, uiBlue)
	}
	for state := 0; state <= 2; state++ {
		c.power(win.RECT{Right: 168, Bottom: 168}, state, false)
		c.power(win.RECT{Right: 64, Bottom: 64}, state, true)
	}
	return c.err
}

// runUIPreview renders representative data for visual layout checks. It never
// reads saved credentials, contacts the service or creates a virtual adapter.
func runUIPreview(mode string) {
	a := &desktop{identity: clientidentity.Identity{DeviceID: "dev-ui-preview", DisplayName: "Tmk-PC"}, api: clientapi.New(bundledServerURL, "member_ui_preview"), ctx: context.Background()}
	if err := a.build(); err != nil {
		walk.MsgBox(nil, appName, err.Error(), walk.MsgBoxOK|walk.MsgBoxIconError)
		return
	}
	a.membership = clientapi.Membership{Network: clientapi.Network{ID: "net-ui-preview", Name: "朋友们的私人网络", CIDR: "10.77.0.0/24"}, Member: clientapi.Device{ID: "dev-ui-preview", Name: "Tmk-PC", VirtualIP: "10.77.0.2"}}
	a.applyMembership()
	a.powerState = 1
	a.updatePowerButtons()
	a.membersButton.SetEnabled(true)
	a.offState.SetText("虚拟网络已开启")
	a.offHint.SetText("加密转发已运行，可随时停止网络或查看成员。")
	a.address.SetText("10.77.0.2")
	a.networkTitle.SetText("朋友们的私人网络")
	a.badge.SetText("●  在线")
	a.badge.SetTextColor(uiBlue)
	a.peerModel.setRows([][]string{
		{"Tmk-PC（本机）", "10.77.0.2", "在线", "本机", "—"},
		{"DESKTOP-ALICE", "10.77.0.3", "在线", "直连", "12 ms"},
		{"LAPTOP-BOB", "10.77.0.4", "在线", "中继", "38 ms"},
		{"TABLE-PC", "10.77.0.5", "离线", "—", "—"},
	})
	a.memberCount.SetText("2 / 4 在线")
	a.traffic.SetText("↑ 1.8 MB    ↓ 6.4 MB")
	a.peers.SetVisible(true)
	a.empty.SetVisible(false)
	if mode == "join" {
		a.showPage(pageJoin)
	} else if mode == "frp" {
		a.frpConfig = frpctl.NewDefaultConfig()
		a.frpConfig.Profile.Server.Host = "frp.example.test"
		a.frpConfig.Profile.Server.Port = 7000
		a.frpConfig.Profile.Server.TLSServerName = "frp.example.test"
		a.frpConfig.Profile.Rules = []frpctl.Rule{
			{ID: "rule-game", Name: "家庭游戏服务", Type: "udp", Enabled: true, Target: frpctl.Target{Kind: "loopback", Host: "127.0.0.1", Port: 7777}, Exposure: frpctl.Exposure{RemotePort: 30001}},
			{ID: "rule-web", Name: "本机管理页面", Type: "tcp", Enabled: true, Target: frpctl.Target{Kind: "loopback", Host: "127.0.0.1", Port: 8080}, Exposure: frpctl.Exposure{RemotePort: 30002}},
			{ID: "rule-lan-http", Name: "家庭 Web", Type: "http", Enabled: true, Target: frpctl.Target{Kind: "lan", Host: "192.168.1.20", Port: 8080}, Exposure: frpctl.Exposure{CustomDomains: []string{"home.example.com"}}},
			{ID: "rule-private", Name: "私有 SSH", Type: "stcp", Enabled: true, SecretRef: "preview-private", Target: frpctl.Target{Kind: "loopback", Host: "127.0.0.1", Port: 22}},
			{ID: "rule-off", Name: "暂未启用", Type: "tcp", Enabled: false, Target: frpctl.Target{Kind: "loopback", Host: "127.0.0.1", Port: 9090}, Exposure: frpctl.Exposure{RemotePort: 30003}},
		}
		a.frpConfig.Profile.Visitors = []frpctl.Visitor{{ID: "visitor-preview", Name: "私有 SSH 访问", Type: "stcp", Enabled: true, ServerName: "tlan_preview_private", SecretRef: "preview-private", BindAddr: "127.0.0.1", BindPort: 9000}}
		a.frpSnapshot = frpctl.Snapshot{Configured: true, Running: true, Authenticated: true, SharedToken: true, State: "running", ProfileName: "我的穿透服务", ServerHost: "frp.example.test", ServerPort: 7000, Rules: []frpctl.RuleRuntimeStatus{
			{RuleID: "rule-game", Name: "家庭游戏服务", Type: "UDP", Enabled: true, State: "已发布", RemoteAddr: "frp.example.test:30001", Backend: "未验证"},
			{RuleID: "rule-web", Name: "本机管理页面", Type: "TCP", Enabled: true, State: "已发布", RemoteAddr: "frp.example.test:30002", Backend: "可用"},
			{RuleID: "rule-lan-http", Name: "家庭 Web", Type: "HTTP", Enabled: true, State: "已注册", RemoteAddr: "http://home.example.com:18080", Backend: "可用"},
			{RuleID: "rule-private", Name: "私有 SSH", Type: "STCP", Enabled: true, State: "已注册", Backend: "可用"},
			{RuleID: "rule-off", Name: "暂未启用", Type: "TCP", Enabled: false, State: "已禁用", Backend: "—"},
		}, Visitors: []frpctl.VisitorRuntimeStatus{
			{VisitorID: "visitor-preview", Name: "私有 SSH 访问", Type: "STCP", Enabled: true, State: "监听中", BindAddr: "127.0.0.1", BindPort: 9000},
		}, Logs: []string{"login to server success, get run id [preview]", "start proxy success: tlan_preview_rule_game", "start proxy success: tlan_preview_rule_web"}}

		a.updateFRPRows()
		a.frpStatus.SetText("● 已连接")
		a.frpStatus.SetTextColor(uiBlue)
		a.frpServer.SetText("frp.example.test:7000 · TLS 强制验证")
		a.frpAuthNote.SetText("共享令牌模式：所有使用此令牌的客户端共享认证，不等同于设备级隔离。")
		a.frpToggleButton.SetText("停止穿透")
		a.frpLogs.SetText(strings.Join(a.frpSnapshot.Logs, "\r\n"))
		a.showPage(pageFRP)

	} else if mode == "admin" {
		a.setAdminMode(true, "Tmkmaj233")
		a.admin.busy = true
		a.showPage(pageAdmin)
		a.admin.apply(clientapi.AdminOverview{Service: "tmknetworklan-control", Version: "0.2.0", Stage: "admin-console", ControlListen: "0.0.0.0:8080 / TLS", AdminListen: "127.0.0.1:8081", Network: clientapi.Network{Name: "朋友们的私人网络", CIDR: "10.77.0.0/24"}, MemberCount: 5, OnlineCount: 3, BlockedCount: 1, RelayStatus: "enabled", RelaySessions: 2, FRPStatus: "managed", FRPLeaseCount: 4}, clientapi.AdminMembers{Members: []clientapi.AdminMember{
			{ID: "dev-tmk-pc", Name: "Tmk-PC", VirtualIP: "10.77.0.2", Online: true, RelayCount: 1, FRPLeases: 2},
			{ID: "dev-alice", Name: "DESKTOP-ALICE", VirtualIP: "10.77.0.3", Online: true, RelayCount: 1, FRPLeases: 1},
			{ID: "dev-bob", Name: "LAPTOP-BOB", VirtualIP: "10.77.0.4", Online: false, RelayCount: 0, FRPLeases: 0},
			{ID: "dev-chen", Name: "手机热点", VirtualIP: "10.77.0.5", Online: true, RelayCount: 1, FRPLeases: 1},
			{ID: "dev-blocked", Name: "已拉黑设备", VirtualIP: "10.77.0.6", Blocked: true},
		}}, nil)
		a.admin.setBusy(false)
		a.admin.table.SetCurrentIndex(0)
		a.admin.refreshButtons()
	} else if mode == "rail-focus" {
		a.showPage(pagePower)
		a.connectedArea.SetVisible(true)
		go func() {
			time.Sleep(500 * time.Millisecond)
			a.window.Synchronize(func() {
				if a.railPower != nil {
					a.railPower.SetFocus()
				}
			})
		}()
	} else if mode == "off" {
		a.setPoweredOff()
		a.showPage(pagePower)
	} else if mode == "transition" {
		a.showPage(pagePower)
		a.connectedArea.SetVisible(false)
		go func() {
			time.Sleep(600 * time.Millisecond)
			a.window.Synchronize(func() {
				a.setConnectedVisible(true)
			})
		}()
	} else {
		a.showPage(pagePower)
		a.connectedArea.SetVisible(true)
	}
	if mode == "error" {
		go func() {
			time.Sleep(400 * time.Millisecond)
			a.window.Synchronize(func() {
				a.showTextDialog("连接诊断", "无法建立加密连接，请检查网络后重试。", "测试详情：这是一条不会上传的本地预览信息。")
			})
		}()
	}
	if mode == "version" {
		go func() {
			time.Sleep(400 * time.Millisecond)
			a.window.Synchronize(a.openVersionInfo)
		}()
	}
	a.window.Run()
}
