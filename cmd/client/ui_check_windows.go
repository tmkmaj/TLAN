//go:build windows

package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"syscall"
	"time"

	"github.com/lxn/walk"
	"github.com/lxn/win"
	"github.com/private-radminlan/lanmesh/internal/clientapi"
	"github.com/private-radminlan/lanmesh/internal/clientidentity"
	"github.com/private-radminlan/lanmesh/internal/clientui"
	frpctl "github.com/private-radminlan/lanmesh/internal/frp"
)

// This internal smoke mode constructs the real controls and exercises native
// painting APIs. It does not contact the service, create an adapter or read
// saved credentials. The window stays hidden throughout the check.
func checkDesktopUI() error {
	setActiveLanguage(langZH)
	applyAppearancePalette(appearanceLight)
	a := &desktop{identity: clientidentity.Identity{DeviceID: "dev-ui-smoke", DisplayName: "UI Check"}, api: clientapi.New(bundledServerURL, ""), stun: bundledSTUNAddress, ctx: context.Background(), smokeMode: true}
	if err := a.build(); err != nil {
		return err
	}
	defer a.window.Dispose()
	if err := a.setupTray(); err != nil {
		if win.FindWindow(syscall.StringToUTF16Ptr("Shell_TrayWnd"), nil) != 0 {
			return fmt.Errorf("tray setup: %w", err)
		}
		a.updateTrayMenu()
	} else if a.trayIcon == nil || !a.trayIcon.Visible() || a.trayIcon.ContextMenu() == nil || a.trayIcon.ContextMenu().Actions().Len() < 7 {
		return fmt.Errorf("tray icon or menu was not initialized")
	}
	if a.settings.CloseToTray || a.settings.LaunchAtLogin {
		return fmt.Errorf("resident settings must default to disabled")
	}
	if a.frpQuickLocalIP == nil || a.frpQuickLocalPort == nil || a.frpQuickRemotePort == nil || a.frpQuickProto == nil || a.frpQuickAddButton == nil || a.frpPickProcessButton == nil || a.frpCopyAddrButton == nil || a.frpToggleRuleButton == nil || a.frpLogsButton == nil || a.frpServerAddrLabel == nil || a.frpServerEye == nil || a.powerServerEye == nil {
		return fmt.Errorf("quick FRP mapping controls were not initialized")
	}
	if a.trayShowAction == nil || a.trayMeshAction == nil || a.trayFRPAction == nil || a.traySettingsAction == nil || a.trayExitAction == nil {
		return fmt.Errorf("tray actions were not initialized")
	}
	if a.trayShowAction.Text() != "显示窗口" || a.trayMeshAction.Text() != "启动虚拟局域网" || a.trayFRPAction.Text() != "启动端口映射" || a.trayExitAction.Text() != "退出程序" {
		return fmt.Errorf("tray action labels are inconsistent: show=%q mesh=%q frp=%q exit=%q", a.trayShowAction.Text(), a.trayMeshAction.Text(), a.trayFRPAction.Text(), a.trayExitAction.Text())
	}
	if a.trayMeshAction.Enabled() || a.trayFRPAction.Enabled() {
		return fmt.Errorf("tray actions must be disabled before credentials or FRP configuration exist")
	}
	if resolveCloseBehavior(false, false, true) != closeBehaviorMinimize || resolveCloseBehavior(true, false, true) != closeBehaviorTray || resolveCloseBehavior(true, true, true) != closeBehaviorExit || resolveCloseBehavior(false, true, true) != closeBehaviorExit || resolveCloseBehavior(true, false, false) != closeBehaviorMinimize {
		return fmt.Errorf("close behavior policy is inconsistent")
	}
	wantInitial := a.window.SizeFrom96DPI(walk.Size{Width: 1020, Height: 720})
	if gotInitial := a.window.SizePixels(); gotInitial != wantInitial {
		return fmt.Errorf("initial MainWindow size = %+v, want %+v", gotInitial, wantInitial)
	}
	assertShell := func(visible bool) error {
		got := win.GetWindowLong(a.shellPage.Handle(), win.GWL_STYLE)&win.WS_VISIBLE != 0
		if got != visible {
			return fmt.Errorf("workspace shell visibility = %v, want %v", got, visible)
		}
		if a.railPower == nil || a.railFRP == nil || a.railMore == nil || a.railMore.Text() != "设置" || a.railAdmin.Text() != "管理面板" || a.serverChart == nil || a.serverAvgLabel == nil || a.peerCopyHint == nil || a.admin == nil || a.admin.table == nil || a.admin.refresh == nil || a.admin.rename == nil || a.admin.ban == nil || a.admin.portRange == nil || a.admin.serverDisplayBtn == nil || a.admin.networkNameBtn == nil || a.toggleButton == nil || a.membersButton == nil || a.connectedArea == nil || a.frpPage == nil || a.frpRules == nil || a.frpToggleButton == nil || a.frpLogsButton == nil || a.frpQuickAddButton == nil {
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
	if a.serverInput == nil || a.stunInput == nil || a.advancedPanel == nil || a.joinThemeButton == nil || a.joinLangButton == nil || a.usernameInput == nil {
		return fmt.Errorf("self-hosted server, username, language or theme controls were not initialized")
	}
	if a.serverInput.Text() != displayServerEndpoint(bundledServerURL) || a.advancedPanel.Visible() {
		return fmt.Errorf("join page defaults are incorrect: got %q, want %q", a.serverInput.Text(), displayServerEndpoint(bundledServerURL))
	}
	a.toggleAdvancedConnection()
	if !a.advancedPanel.Visible() {
		return fmt.Errorf("advanced STUN panel did not open")
	}
	a.toggleAdvancedConnection()
	_ = a.stunInput.SetText(bundledSTUNAddress)
	a.stunAuto = true
	_ = a.serverInput.SetText("other.example:8443")
	if a.stunInput.Text() != "" {
		return fmt.Errorf("automatic STUN value remained pinned to the previous server")
	}
	_ = a.stunInput.SetText("stun.example:4000")
	_ = a.serverInput.SetText("https://third.example:8443")
	if a.stunInput.Text() != "stun.example:4000" || a.stunAuto {
		return fmt.Errorf("manual STUN override was not preserved")
	}
	_ = a.stunInput.SetText("")
	_ = a.serverInput.SetText(displayServerEndpoint(bundledServerURL))
	a.stunAuto = true
	a.applyAppearance(appearanceDark)
	if uiBackground != darkPalette.background || uiWhite != darkPalette.surface {
		return fmt.Errorf("dark palette was not applied")
	}
	if brush, ok := a.serverInput.Background().(*walk.SolidColorBrush); !ok || brush.Color() != darkPalette.surface {
		return fmt.Errorf("dark server input background was not refreshed")
	}
	a.applyAppearance(appearanceLight)
	if uiBackground != lightPalette.background || uiWhite != lightPalette.surface {
		return fmt.Errorf("light palette was not restored")
	}
	originalAPI, originalSettings := a.api, a.settings
	failedServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "offline", http.StatusServiceUnavailable) }))
	a.serverInput.SetText(failedServer.URL)
	a.token = "invalid_fixture_token"
	a.join()
	for deadline := time.Now().Add(3 * time.Second); a.busy && time.Now().Before(deadline); {
		time.Sleep(10 * time.Millisecond)
	}
	failedServer.Close()
	if a.api != originalAPI || a.settings != originalSettings {
		return fmt.Errorf("failed enrollment replaced the active server configuration")
	}
	a.serverInput.SetText(bundledServerURL)
	a.token = ""
	if err := assertPage(pageJoin); err != nil {
		return err
	}
	if err := assertShell(false); err != nil {
		return err
	}
	a.api.Token = "member_ui_fixture"
	a.api.BaseURL = "https://198.51.100.10:8443"
	a.membership = clientapi.Membership{Network: clientapi.Network{ID: "net-ui", Name: "私人网络"}, Member: clientapi.Device{ID: "dev-ui-smoke", Name: "UI Check", VirtualIP: "10.77.0.2"}}
	a.serverDisplay = clientapi.ServerDisplayConfig{Mode: "ip"}
	a.applyMembership()
	if err := assertPage(pagePower); err != nil {
		return err
	}
	if err := assertShell(true); err != nil {
		return err
	}
	a.togglePowerServerEye()
	if !a.powerServerHidden || !strings.Contains(a.serverIdentity.Text(), "•••") {
		return fmt.Errorf("power server IP mask toggle failed: %q", a.serverIdentity.Text())
	}
	a.togglePowerServerEye()
	if a.powerServerHidden {
		return fmt.Errorf("power server IP reveal toggle failed")
	}
	a.serverDisplay = clientapi.ServerDisplayConfig{Mode: "alias", Alias: "主控测试节点"}
	a.updateConnectedServerDisplays()
	if a.serverIdentity.Text() != "主控测试节点" || a.powerServerEye.Visible() {
		return fmt.Errorf("alias server display mode failed: text=%q eye=%v", a.serverIdentity.Text(), a.powerServerEye.Visible())
	}
	a.powerState = 1
	a.updatePowerButtons()
	a.connectedArea.SetVisible(true)
	a.peerModel.setRows([][]string{{"UI Check（本机）", "10.77.0.2", "在线", "本机", "—"}, {"Friend-PC", "10.77.0.3", "在线", "直连", "12 ms"}, {"History-PC", "10.77.0.4", "离线", "—", "—"}})
	a.peers.SetVisible(true)
	a.setEmptyState(false, "")
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
	a.frpConfig.Profile.Rules = []frpctl.Rule{{ID: "rule-ui", Name: "UI 测试服务", Type: "tcp", Enabled: true, Target: frpctl.Target{Kind: "loopback", Host: "127.0.0.1", Port: 8080}, Exposure: frpctl.Exposure{RemotePort: 60000}}}
	a.frpSnapshot = frpctl.Snapshot{Configured: true, State: "running", ProfileName: "UI 测试服务", ServerHost: "frp.example.test", ServerPort: 7000, Rules: []frpctl.RuleRuntimeStatus{{RuleID: "rule-ui", Name: "UI 测试服务", Type: "TCP", Enabled: true, State: "已发布", RemoteAddr: "frp.example.test:60000", Backend: "可用"}}}
	a.prefillQuickRemotePort(true)
	a.updateFRPRows()
	a.renderFRPState()
	a.showPage(pageFRP)
	if err := assertPage(pageFRP); err != nil {
		return err
	}
	if a.frpRuleCount == nil || a.frpRuleCount.Text() != "1 条" {
		return fmt.Errorf("quick FRP rule counter = %v", a.frpRuleCount)
	}
	if strings.Contains(a.frpServerAddrLabel.Text(), ":") {
		return fmt.Errorf("FRP server address unexpectedly contains port: %q", a.frpServerAddrLabel.Text())
	}
	a.toggleFRPServerEye()
	if !a.frpServerHidden || !strings.Contains(a.frpServerAddrLabel.Text(), "•••") {
		return fmt.Errorf("FRP server address eye toggle failed: %q", a.frpServerAddrLabel.Text())
	}
	a.toggleFRPServerEye()
	a.applyLocalRenameImmediate("测试改名同步")
	if a.deviceName.Text() != "测试改名同步" {
		return fmt.Errorf("immediate rename did not update local label: %q", a.deviceName.Text())
	}
	// Verify FRP quick-add composer controls declare identical height and ComboBox is themed.
	a.applyAppearance("dark")
	a.requestCleanRelayout()
	pickHint := a.frpPickProcessButton.MinSizePixels()
	addHint := a.frpQuickAddButton.MinSizePixels()
	ipHint := a.frpQuickLocalIP.MinSizePixels()
	protoHint := a.frpQuickProto.MinSizePixels()
	if pickHint.Height != addHint.Height || pickHint.Height != ipHint.Height || protoHint.Height != ipHint.Height {
		return fmt.Errorf("FRP composer height constraint mismatch: pick=%d add=%d ip=%d proto=%d", pickHint.Height, addHint.Height, ipHint.Height, protoHint.Height)
	}
	pickB := a.frpPickProcessButton.BoundsPixels()
	addB := a.frpQuickAddButton.BoundsPixels()
	ipB := a.frpQuickLocalIP.BoundsPixels()
	protoB := a.frpQuickProto.BoundsPixels()
	if ipB.Height > 0 && (pickB.Height != addB.Height || pickB.Height != ipB.Height || protoB.Height != ipB.Height) {
		return fmt.Errorf("FRP composer height mismatch: pick=%d add=%d ip=%d proto=%d", pickB.Height, addB.Height, ipB.Height, protoB.Height)
	}
	if a.frpQuickProto.Text() != "TCP" {
		return fmt.Errorf("FRP protocol ComboBox initial text = %q", a.frpQuickProto.Text())
	}
	// Verify repeated periodic FRP + server probe ticks while on pageFRP keep hidden pagePower visibility invariant.
	a.serverDisplay = clientapi.ServerDisplayConfig{Mode: "ip"}
	a.powerServerHidden = false
	a.updateConnectedServerDisplays()
	eyeBefore := widgetOwnVisible(a.powerServerEye)
	a.prefillQuickRemotePort(false)
	a.renderFRPState()
	a.updateFRPRows()
	a.updateFRPButtons()
	a.refreshServerMetricsDisplay()
	if widgetOwnVisible(a.powerServerEye) != eyeBefore {
		return fmt.Errorf("hidden powerServerEye own visibility drifted on pageFRP")
	}
	a.applyAppearance("light")
	if a.frpRules.CurrentIndex() != -1 {
		a.frpRules.SetCurrentIndex(-1)
	}
	assertCenteredNav := func(withAdmin bool) error {
		a.requestCleanRelayout()
		parent := a.railPower.Parent()
		if parent == nil {
			return fmt.Errorf("nav parent container missing")
		}
		pw := parent.ClientBoundsPixels().Width
		lastBtn := a.railFRP
		if withAdmin {
			lastBtn = a.railAdmin
		}
		lb := a.railPower.BoundsPixels()
		rb := lastBtn.BoundsPixels()
		leftGap := lb.X
		rightGap := pw - (rb.X + rb.Width)
		diff := leftGap - rightGap
		if diff < 0 {
			diff = -diff
		}
		if pw > 0 && diff > 8 {
			return fmt.Errorf("navigation is not centered (withAdmin=%v): leftGap=%d rightGap=%d parentW=%d", withAdmin, leftGap, rightGap, pw)
		}
		return nil
	}
	if err := assertCenteredNav(false); err != nil {
		return err
	}
	a.setAdminMode(true, "test-admin-token")
	if !a.railAdmin.Visible() || a.adminAPI == nil {
		return fmt.Errorf("admin mode did not reveal the management panel entry")
	}
	if err := assertCenteredNav(true); err != nil {
		return err
	}
	a.admin.busy = true
	a.showPage(pageAdmin)
	a.admin.apply(clientapi.AdminOverview{Service: "tlan-control", Version: "1.0.0", Stage: "admin-ui-smoke", Network: clientapi.Network{Name: "私人网络", CIDR: "10.77.0.0/24"}, MemberCount: 3, OnlineCount: 2, BlockedCount: 1, RelayStatus: "enabled", RelaySessions: 1, FRPStatus: "managed", FRPLeaseCount: 1, FRPPortStart: 60000, FRPPortEnd: 61000, ServerDisplay: clientapi.ServerDisplayConfig{Mode: "ip"}}, clientapi.AdminMembers{Members: []clientapi.AdminMember{{ID: "dev-ui-smoke", Name: "UI Check", VirtualIP: "10.77.0.2", Online: true}, {ID: "dev-ui-friend", Name: "Friend-PC", VirtualIP: "10.77.0.3", Online: true, RelayCount: 1}, {ID: "dev-ui-blocked", Name: "Blocked-PC", VirtualIP: "10.77.0.4", Blocked: true}}}, nil)
	a.admin.setBusy(false)
	a.requestCleanRelayout()
	if overviewContainer, ok := a.admin.page.Children().At(0).(walk.Container); ok {
		children := overviewContainer.Children()
		if children.Len() == 4 {
			h0 := children.At(0).BoundsPixels().Height
			for i := 1; i < 4; i++ {
				if hi := children.At(i).BoundsPixels().Height; hi != h0 {
					return fmt.Errorf("admin overview card %d height %d != card 0 height %d", i, hi, h0)
				}
			}
		}
	}
	if nnb, prb, sdb := a.admin.networkNameBtn.BoundsPixels(), a.admin.portRange.BoundsPixels(), a.admin.serverDisplayBtn.BoundsPixels(); nnb.Height != prb.Height || nnb.Height != sdb.Height {
		return fmt.Errorf("admin config buttons height mismatch: net=%d port=%d disp=%d", nnb.Height, prb.Height, sdb.Height)
	}
	if a.admin.portConfigVal.MinSizePixels().Width > a.admin.portRange.BoundsPixels().Width && a.admin.portConfigVal.BoundsPixels().Width > 0 && a.admin.portConfigVal.BoundsPixels().Width < 110 {
		return fmt.Errorf("admin port range value crushed: width=%d", a.admin.portConfigVal.BoundsPixels().Width)
	}
	if cfgCard, ok := a.admin.page.Children().At(1).(walk.Container); ok && cfgCard.Children().Len() >= 2 {
		if tilesRow, ok := cfgCard.Children().At(1).(walk.Container); ok && tilesRow.Children().Len() == 3 {
			th0 := tilesRow.Children().At(0).BoundsPixels().Height
			for i := 1; i < 3; i++ {
				if thi := tilesRow.Children().At(i).BoundsPixels().Height; thi != th0 {
					return fmt.Errorf("admin config tile %d height %d != tile 0 height %d", i, thi, th0)
				}
			}
		}
	}
	if err := assertPage(pageAdmin); err != nil {
		return err
	}
	if len(a.admin.model.rows) != 3 || !strings.Contains(a.admin.counts.Text(), "3 / 2") {
		return fmt.Errorf("admin panel fixture did not render overview or members")
	}
	a.applyLanguage(langEN)
	if a.railMore.Text() != "Settings" || a.frpRuleCount.Text() != "1" {
		return fmt.Errorf("english language toggle did not refresh labels: railMore=%q frpRuleCount=%q", a.railMore.Text(), a.frpRuleCount.Text())
	}
	if frpSz, admSz := a.railFRP.MinSizePixels(), a.railAdmin.MinSizePixels(); frpSz.Width < a.railFRP.IntFrom96DPI(136) || admSz.Width < a.railAdmin.IntFrom96DPI(132) {
		return fmt.Errorf("english nav button sizes too narrow: frp=%+v admin=%+v", frpSz, admSz)
	}
	a.applyLanguage(langZH)
	if a.offState.TextColor() != uiDanger {
		return fmt.Errorf("disconnected offState color = %v, want uiDanger (%v)", a.offState.TextColor(), uiDanger)
	}
	a.admin.table.SetCurrentIndex(2)
	a.admin.refreshButtons()
	if !a.admin.unban.Enabled() || a.admin.ban.Enabled() {
		return fmt.Errorf("admin member actions did not reflect blocked state")
	}
	a.setAdminMode(false, "")
	a.showPage(pagePower)
	a.requestCleanRelayout()
	cpb := a.copyLocalIPButton.BoundsPixels()
	rnb := a.renameSelfButton.BoundsPixels()
	if cpb.Width != rnb.Width || cpb.Height != rnb.Height {
		return fmt.Errorf("power card action buttons size mismatch: copyIP=%+v rename=%+v", cpb, rnb)
	}
	if a.powerPage.Children().Len() == 2 {
		ph := a.powerPage.Children().At(0).BoundsPixels().Height
		rh := a.powerPage.Children().At(1).BoundsPixels().Height
		if ph != rh {
			return fmt.Errorf("power page side-by-side column height mismatch: powerCard=%d rightColumn=%d", ph, rh)
		}
	}
	if err := assertPage(pagePower); err != nil {
		return err
	}
	a.showNotice(clientui.Feedback{Title: "测试通知", Message: "验证底部通知展开与收起后的干净重排"})
	if !a.notice.Visible() {
		return fmt.Errorf("notice banner did not become visible")
	}
	a.dismissNotice()
	if a.notice.Visible() {
		return fmt.Errorf("notice banner did not collapse on dismiss")
	}
	if err := a.window.SetSize(walk.Size{Width: 1120, Height: 760}); err != nil {
		return err
	}
	a.requestCleanRelayout()
	if err := a.window.SetBoundsPixels(walk.Rectangle{X: 40, Y: 40, Width: 800, Height: 500}); err != nil {
		return err
	}
	if err := a.window.SetSize(walk.Size{Width: 960, Height: 640}); err != nil {
		return err
	}
	a.requestCleanRelayout()
	cb := a.window.ClientBoundsPixels()
	if cc := a.window.AsContainerBase(); cc != nil {
		if ccb := cc.BoundsPixels(); ccb.Width != cb.Width || ccb.Height != cb.Height {
			return fmt.Errorf("clientComposite size %+v != window client size %+v after clamped resize", ccb.Size(), cb.Size())
		}
	}
	if scMin := a.serverChart.MinSizePixels(); scMin.Width < 150 || scMin.Height < 70 {
		return fmt.Errorf("serverChart min size too small: %+v", scMin)
	}
	dc := win.GetDC(a.window.Handle())
	if dc == 0 {
		return fmt.Errorf("could not obtain UI drawing context")
	}
	defer win.ReleaseDC(a.window.Handle(), dc)
	c := newSmoothCanvas(dc)
	defer c.dispose()
	c.brandEmblem(win.RECT{Right: 52, Bottom: 52})
	c.joinBlueprint(win.RECT{Right: 244, Bottom: 176})
	c.joinBlueprintAnimated(win.RECT{Right: 244, Bottom: 176}, 0.42)
	c.power(win.RECT{Right: 276, Bottom: 128}, 1, true)
	c.powerAnimated(win.RECT{Right: 276, Bottom: 128}, 1, 0.85, 1.0, 0.35)
	border := uiBlue
	c.rounded(win.RECT{Right: 340, Bottom: 56}, 16, uiWhite, &border)
	c.roundedGradient(win.RECT{Right: 264, Bottom: 40}, 8, uiBlueHover, uiBlueDeep, &border, 1.0)
	c.hudCorners(win.RECT{Right: 300, Bottom: 220}, 12, uiBlueBorder, 110)
	if err := drawBufferedSmooth(dc, win.RECT{Right: 242, Bottom: 174}, uiSidebar, func(sc *smoothCanvas, local win.RECT) {
		sc.joinBlueprintAnimated(local, 0.25)
	}); err != nil {
		return err
	}
	if err := drawBufferedDC(dc, win.RECT{Right: 112, Bottom: 36}, uiWhite, func(mdc win.HDC, sc *smoothCanvas, local win.RECT) {
		sc.roundedGradient(local, 8, uiBlueHover, uiBlueDeep, &border, 1.0)
		sc.dispose()
		drawControlText(mdc, 0, "测试", local, uiOnAccent, win.DT_CENTER)
	}); err != nil {
		return err
	}
	if a.serverProbe != nil {
		a.serverProbe.Record(serverProbeSample{At: time.Now(), RTTMillis: 24, Mode: "STUN UDP"})
		a.serverProbe.Record(serverProbeSample{At: time.Now().Add(time.Second), Lost: true, Mode: "STUN UDP"})
		a.serverProbe.Record(serverProbeSample{At: time.Now().Add(2 * time.Second), RTTMillis: 28, Mode: "STUN UDP"})
		if err := drawBufferedDC(dc, win.RECT{Right: 420, Bottom: 96}, uiWhite, func(mdc win.HDC, sc *smoothCanvas, local win.RECT) {
			paintServerChart(mdc, sc, local, a.serverChart.DPI(), a.serverProbe)
		}); err != nil {
			return err
		}
		a.serverProbe.Reset()
	}
	for _, kind := range []string{"power", "frp", "admin", "diag", "settings", "info", "network", "more"} {
		c.navIcon(win.RECT{Right: 42, Bottom: 42}, kind, uiBlue)
	}
	for state := 0; state <= 2; state++ {
		c.power(win.RECT{Right: 168, Bottom: 168}, state, false)
		c.power(win.RECT{Right: 64, Bottom: 64}, state, true)
	}
	closeHandle := a.window.Closing().Attach(a.handleWindowClosing)
	a.window.SendMessage(win.WM_CLOSE, 0, 0)
	a.window.Closing().Detach(closeHandle)
	if a.window.IsDisposed() || a.closing.Load() || !win.IsIconic(a.window.Handle()) {
		return fmt.Errorf("WM_CLOSE did not minimize main window without closing (disposed=%v closing=%v iconic=%v)", a.window.IsDisposed(), a.closing.Load(), win.IsIconic(a.window.Handle()))
	}
	return c.err
}

// runUIPreview renders representative data for visual layout checks. It never
// reads saved credentials, contacts the service or creates a virtual adapter.
func runUIPreview(mode string) {
	lang := langZH
	if strings.HasSuffix(mode, "-en") {
		lang = langEN
		mode = strings.TrimSuffix(mode, "-en")
	}
	setActiveLanguage(lang)
	appearance := appearanceSystem
	if strings.HasSuffix(mode, "-dark") {
		appearance = appearanceDark
		mode = strings.TrimSuffix(mode, "-dark")
	} else if strings.HasSuffix(mode, "-light") {
		appearance = appearanceLight
		mode = strings.TrimSuffix(mode, "-light")
	}
	applyAppearancePalette(appearance)
	a := &desktop{identity: clientidentity.Identity{DeviceID: "dev-ui-preview", DisplayName: "TLAN-PC"}, api: clientapi.New(bundledServerURL, "member_ui_preview"), stun: bundledSTUNAddress, settings: clientidentity.Settings{ServerURL: bundledServerURL, Appearance: appearance, Language: lang}, ctx: context.Background()}
	if err := a.build(); err != nil {
		walk.MsgBox(nil, appName, err.Error(), walk.MsgBoxOK|walk.MsgBoxIconError)
		return
	}
	a.membership = clientapi.Membership{Network: clientapi.Network{ID: "net-ui-preview", Name: "朋友们的私人网络", CIDR: "10.77.0.0/24"}, Member: clientapi.Device{ID: "dev-ui-preview", Name: "TLAN-PC", VirtualIP: "10.77.0.2"}}
	a.applyMembership()
	a.animPhase = 0.18
	a.powerState = 1
	a.powerGlow = 1.0
	a.updatePowerButtons()
	a.membersButton.SetEnabled(true)
	a.setOffState(tr("已连接", "Connected"), uiSuccess)
	a.offHint.SetText("已连接，点击 IP 可快速复制")
	a.address.SetText("10.77.0.2")
	a.networkTitle.SetText("朋友们的私人网络")
	a.badge.SetText("● 本机在线")
	a.badge.SetTextColor(uiSuccess)
	a.peerModel.setRows([][]string{
		{"TLAN-PC（本机）", "10.77.0.2", "在线", "本机", "—"},
		{"DESKTOP-ALICE", "10.77.0.3", "在线", "直连", "12 ms"},
		{"LAPTOP-BOB", "10.77.0.4", "在线", "中继", "38 ms"},
		{"TABLE-PC", "10.77.0.5", "离线", "—", "—"},
	})
	a.memberCount.SetText("2 / 4 在线")
	a.traffic.SetText("上传 ↑ 1.8 MB   下载 ↓ 6.4 MB")
	a.peers.SetVisible(true)
	a.setEmptyState(false, "")
	if a.serverProbe != nil {
		base := time.Now().Add(-40 * serverProbeInterval)
		sampleRTTs := []float64{24, 26, 23, 28, 31, 25, 22, 0, 29, 27, 24, 25, 26, 33, 28, 24, 22, 23, 25, 24}
		if mode == "connected-few" {
			sampleRTTs = []float64{29, 33, 33, 38, 33, 34, 32}
		}
		for i, rtt := range sampleRTTs {
			s := serverProbeSample{At: base.Add(time.Duration(i) * serverProbeInterval), RTTMillis: rtt, Mode: "STUN UDP"}
			if rtt == 0 {
				s.Lost = true
			}
			a.serverProbe.Record(s)
		}
		a.refreshServerMetricsDisplay()
	}
	if mode == "join" {
		a.showPage(pageJoin)
	} else if mode == "frp" || mode == "frp-picker" || mode == "frp-creds" {
		host := hostFromServerURL(bundledServerURL)
		if host == "" {
			host = "203.0.113.10"
		}
		a.frpConfig = bindFRPServerToHost(frpctl.NewDefaultConfig(), host)
		a.frpConfig.Profile.Server.Port = 7000
		a.frpConfig.Profile.Rules = []frpctl.Rule{
			{ID: "rule-game", Name: "mcserver_25565", Type: "tcp", Enabled: true, Target: frpctl.Target{Kind: "loopback", Host: "127.0.0.1", Port: 25565}, Exposure: frpctl.Exposure{RemotePort: 60001}},
			{ID: "rule-voice", Name: "Terraria_7777", Type: "udp", Enabled: true, Target: frpctl.Target{Kind: "loopback", Host: "127.0.0.1", Port: 7777}, Exposure: frpctl.Exposure{RemotePort: 60002}},
			{ID: "rule-lan", Name: "NAS管理面板", Type: "tcp", Enabled: true, Target: frpctl.Target{Kind: "lan", Host: "192.168.1.20", Port: 5000}, Exposure: frpctl.Exposure{RemotePort: 60003}},
			{ID: "rule-off", Name: "测试调试端口", Type: "tcp", Enabled: false, Target: frpctl.Target{Kind: "loopback", Host: "127.0.0.1", Port: 9090}, Exposure: frpctl.Exposure{RemotePort: 60004}},
		}
		a.frpSnapshot = frpctl.Snapshot{Configured: true, Running: true, Authenticated: true, SharedToken: true, State: "running", ProfileName: "默认端口映射", ServerHost: host, ServerPort: 7000, Rules: []frpctl.RuleRuntimeStatus{
			{RuleID: "rule-game", Name: "mcserver_25565", Type: "TCP", Enabled: true, State: "已发布", RemoteAddr: host + ":60001", Backend: "本地服务正常"},
			{RuleID: "rule-voice", Name: "Terraria_7777", Type: "UDP", Enabled: true, State: "已发布", RemoteAddr: host + ":60002", Backend: "未验证"},
			{RuleID: "rule-lan", Name: "NAS管理面板", Type: "TCP", Enabled: true, State: "已发布", RemoteAddr: host + ":60003", Backend: "内网可达"},
			{RuleID: "rule-off", Name: "测试调试端口", Type: "TCP", Enabled: false, State: "已禁用", Backend: "—"},
		}, Logs: []string{"login to server success, get run id [preview]", "start proxy success: mcserver_25565"}}

		a.frpManager = &frpctl.Manager{}
		a.frpRefreshing = true
		a.prefillQuickRemotePort(true)
		a.renderFRPState()
		a.updateFRPRows()
		a.updateFRPButtons()
		if a.frpQuickLocalPort != nil {
			_ = a.frpQuickLocalPort.SetText("25565")
		}
		a.showPage(pageFRP)
		_ = a.frpRules.SetCurrentIndex(0)
		a.updateFRPButtons()
		if mode == "frp-picker" {
			fixtureEntries := []localPortEntry{
				{PID: 14820, ProcessName: "javaw.exe", Protocol: "tcp", BindIP: "0.0.0.0", TargetIP: "127.0.0.1", Port: 25565},
				{PID: 9124, ProcessName: "TerrariaServer.exe", Protocol: "tcp", BindIP: "0.0.0.0", TargetIP: "127.0.0.1", Port: 7777},
				{PID: 9124, ProcessName: "TerrariaServer.exe", Protocol: "udp", BindIP: "0.0.0.0", TargetIP: "127.0.0.1", Port: 7777},
				{PID: 5312, ProcessName: "caddy.exe", Protocol: "tcp", BindIP: "127.0.0.1", TargetIP: "127.0.0.1", Port: 8080},
				{PID: 2048, ProcessName: "nginx.exe", Protocol: "tcp", BindIP: "192.168.1.20", TargetIP: "192.168.1.20", Port: 80},
			}
			go func() {
				time.Sleep(450 * time.Millisecond)
				a.window.Synchronize(func() {
					a.showLocalProcessPickerWithEntries(fixtureEntries)
				})
			}()
		}
	} else if mode == "admin" {
		a.setAdminMode(true, "test-admin-token")
		a.admin.busy = true
		a.showPage(pageAdmin)
		a.admin.apply(clientapi.AdminOverview{Service: "tlan-control", Version: "1.0.0", Stage: "admin-console", ControlListen: "0.0.0.0:8080 / TLS", AdminListen: "127.0.0.1:8081", Network: clientapi.Network{Name: "朋友们的私人网络", CIDR: "10.77.0.0/24"}, MemberCount: 5, OnlineCount: 3, BlockedCount: 1, RelayStatus: "enabled", RelaySessions: 2, FRPStatus: "managed", FRPLeaseCount: 4, FRPPortStart: 60000, FRPPortEnd: 61000, ServerDisplay: clientapi.ServerDisplayConfig{Mode: "ip"}}, clientapi.AdminMembers{Members: []clientapi.AdminMember{
			{ID: "dev-tlan-pc", Name: "TLAN-PC", VirtualIP: "10.77.0.2", Online: true, RelayCount: 1, FRPLeases: 2},
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
		a.powerGlow = 0
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
	if mode == "settings" {
		go func() {
			time.Sleep(400 * time.Millisecond)
			a.window.Synchronize(a.showClientSettings)
		}()
	}
	if mode == "version" {
		go func() {
			time.Sleep(400 * time.Millisecond)
			a.window.Synchronize(a.showVersionInfo)
		}()
	}
	if mode == "diag" {
		go func() {
			time.Sleep(400 * time.Millisecond)
			a.window.Synchronize(func() {
				_, stats := a.serverProbe.Snapshot()
				export := diagnosticExport{
					SchemaVersion: diagnosticSchemaVersion,
					AppVersion:    appVersion,
					GeneratedAt:   time.Now().UTC(),
					Checks: []clientapi.DiagnosticCheck{
						{Name: "control_health", Status: "pass", Detail: "控制服务响应耗时 21 ms"},
						{Name: "stun_probe", Status: "pass", Detail: "UDP 公网映射探测成功 (18 ms)"},
						{Name: "virtual_adapter", Status: "pass", Detail: "wintun 10.77.0.2/24"},
						{Name: "peer DESKTOP-ALICE", Status: "pass", Detail: "10.77.0.3 direct UDP"},
						{Name: "peer LAPTOP-BOB", Status: "pass", Detail: "10.77.0.4 relay TCP/TLS"},
						{Name: "peer TABLE-PC", Status: "warn", Detail: "10.77.0.5 checking"},
					},
				}
				summary := buildDiagnosticSummary(export, stats, bundledServerURL, bundledSTUNAddress)
				a.showDiagnosticsDialog(summary, "预览模式未上传诊断报告。", export.Text())
			})
		}()
	}
	a.window.Run()
}
