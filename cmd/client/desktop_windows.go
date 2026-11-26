//go:build windows

package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/lxn/walk"
	"github.com/lxn/win"
	"github.com/private-radminlan/lanmesh/core"
	"github.com/private-radminlan/lanmesh/internal/clientapi"
	"github.com/private-radminlan/lanmesh/internal/clientidentity"
	"github.com/private-radminlan/lanmesh/internal/clientui"
	"github.com/private-radminlan/lanmesh/internal/frp"
	"github.com/private-radminlan/lanmesh/internal/mesh"
	"github.com/private-radminlan/lanmesh/internal/network"
	"github.com/private-radminlan/lanmesh/internal/platform"
	"golang.org/x/sys/windows"
)

type desktopSession struct {
	done   chan struct{}
	engine *mesh.Engine
}
type desktop struct {
	window                                                                                                             *walk.MainWindow
	code                                                                                                               *walk.LineEdit
	serverInput, stunInput, usernameInput                                                                              *walk.LineEdit
	advancedPanel                                                                                                      *walk.Composite
	advancedButton                                                                                                     *walk.PushButton
	token                                                                                                              string
	joinButton, joinThemeButton, joinLangButton, toggleButton, membersButton                                           *walk.PushButton
	copyLocalIPButton, renameSelfButton, noticeDetailButton, noticeDismissButton                                       *walk.PushButton
	railPower, railFRP, railAdmin, railDiag, railMore                                                                  *walk.PushButton
	menuSettingsAction, menuAboutAction, menuSwitchAction, menuLeaveAction                                             *walk.Action
	peerCopyMenuAction, peerRefreshMenuAction                                                                          *walk.Action
	frpCopyMenuAction, frpToggleMenuAction, frpEditMenuAction, frpDeleteMenuAction                                     *walk.Action
	powerVisual                                                                                                        *walk.ImageView
	joinPage, shellPage, powerPage, frpPage, connectedArea, emptyArea, notice                                          *walk.Composite
	joinBlueprint                                                                                                      *walk.ImageView
	deckScanView                                                                                                       *walk.Composite
	serverChart                                                                                                        *walk.CustomWidget
	serverProbe                                                                                                        *serverProbeHistory
	serverLatencyLabel, serverAvgLabel, serverLossLabel, serverProbeModeLabel, peerCopyHint                            *walk.Label
	peerCopySeq                                                                                                        uint64
	offHintSeq                                                                                                         uint64
	animPhase, powerHover, powerGlow, deckScanProgress                                                                 float64
	animLoopActive, deckScanActive                                                                                     bool
	pageTransitionsReady                                                                                               bool
	smokeMode                                                                                                          bool
	admin                                                                                                              *adminPanel
	adminAPI                                                                                                           *clientapi.AdminClient
	adminToken                                                                                                         string
	adminMode                                                                                                          bool
	joinAfter                                                                                                          func()
	frpToggleButton, frpLogsButton                                                                                       *walk.PushButton
	powerServerEye, frpServerEye                                                                                       *walk.PushButton
	frpQuickAddButton, frpPickProcessButton                                                                            *walk.PushButton
	frpCopyAddrButton, frpToggleRuleButton, frpEditButton, frpDeleteButton                                             *walk.PushButton
	frpQuickName, frpQuickLocalIP, frpQuickLocalPort, frpQuickRemotePort                                               *walk.LineEdit
	frpQuickProto                                                                                                      *walk.ComboBox
	frpHeading, frpListHeading                                                                                         *walk.Label
	frpStatus, frpServer, frpServerBannerTitle, frpServerAddrLabel, frpRuleCount, frpPortRangeHint                     *walk.Label
	serverDisplayTitle                                                                                                 *walk.Label
	powerServerHidden, frpServerHidden                                                                                 bool
	serverDisplay                                                                                                      clientapi.ServerDisplayConfig
	renameSeq                                                                                                          uint64
	frpPortRange                                                                                                       clientapi.PortRange
	frpPortRangeLoading                                                                                                bool
	frpRules                                                                                                           *walk.TableView
	frpRuleModel                                                                                                       *frpRuleTableModel
	frpRows                                                                                                            []frpEntryRef
	frpLogs                                                                                                            *walk.TextEdit
	frpCatalog                                                                                                         *frp.Catalog
	frpProfiles                                                                                                        []frp.ProfileInfo
	frpManagers                                                                                                        map[string]*frp.Manager
	frpLeaseProviders                                                                                                  map[string]*frpLeaseProvider
	frpManagerErrors                                                                                                   map[string]error
	frpEndpointRegistry                                                                                                *frp.EndpointRegistry
	frpProfileID                                                                                                       string
	frpManager                                                                                                         *frp.Manager
	frpConfig                                                                                                          frp.Config
	frpSnapshot                                                                                                        frp.Snapshot
	frpInitErr                                                                                                         error
	frpBusy, frpRefreshing, frpProfileSwitching                                                                        bool
	frpStarting, frpStopping                                                                                           bool
	frpStartSeq                                                                                                        atomic.Uint64
	frpCloseOnce                                                                                                       sync.Once
	frpStopDone                                                                                                        chan struct{}
	page                                                                                                               int
	offState, offNetwork                                                                                               *walk.Label
	offHint                                                                                                            *walk.Label
	deviceName, address, badge, status, networkTitle, serverIdentity, memberCount, traffic, noticeTitle, noticeMessage *walk.Label
	empty                                                                                                              *walk.Label
	peers                                                                                                              *walk.TableView
	peerModel                                                                                                          *desktopTableModel
	feedback                                                                                                           clientui.Feedback
	identity                                                                                                           clientidentity.Identity
	api                                                                                                                *clientapi.Client
	membership                                                                                                         clientapi.Membership
	members                                                                                                            []clientapi.Device
	settings                                                                                                           clientidentity.Settings
	stun                                                                                                               string
	stunAuto                                                                                                           bool
	engine                                                                                                             *mesh.Engine
	busy, refreshing                                                                                                   bool
	powerState                                                                                                         int // 0 off, 1 on, 2 transitioning
	ctx                                                                                                                context.Context
	cancel                                                                                                             context.CancelFunc
	sessionCancel                                                                                                      context.CancelFunc
	session                                                                                                            *desktopSession
	appIcon                                                                                                            *walk.Icon
	deckScanToken                                                                                                      uint64
	resizeSyncSeq                                                                                                      uint64
	animationsEnabled                                                                                                  bool
	railSelection                                                                                                      int
	closing                                                                                                            atomic.Bool
	explicitExit                                                                                                       atomic.Bool
	shutdownOnce                                                                                                       sync.Once
	startHidden                                                                                                        bool
	settingsDialogOpen                                                                                                 bool
	trayIcon                                                                                                           *walk.NotifyIcon
	trayShowAction, trayMeshAction, trayFRPAction, traySettingsAction, trayExitAction                                  *walk.Action
	langRefreshers                                                                                                     []func()
}

func runDesktop() {
	server := flag.String("server", bundledServerURL, "developer override for bundled control service")
	stun := flag.String("stun", bundledSTUNAddress, "developer override for STUN")
	identityPath := flag.String("identity", "", "local identity file")
	adapterTest := flag.String("adapter-smoke-test", "", "privileged adapter check report")
	uiTest := flag.String("ui-smoke-test", "", "GUI initialization check report (no adapter)")
	uiPreview := flag.String("ui-preview", "", "show a local UI preview with fixture data (no network)")
	startup := flag.Bool("startup", false, "start hidden in the notification area after login")
	flag.Parse()
	defer releaseSmoothDrawing()
	if *adapterTest != "" {
		runAdapterTest(*adapterTest)
		return
	}
	if *uiTest != "" {
		runUITest(*uiTest)
		return
	}
	if *uiPreview != "" {
		runUIPreview(*uiPreview)
		return
	}
	settings, settingsErr := clientidentity.LoadSettings()
	setActiveLanguage(settings.Language)
	instance, err := windows.CreateMutex(nil, false, windows.StringToUTF16Ptr("Local\\TLAN-Desktop"))
	if instance != 0 {
		defer windows.CloseHandle(instance)
	}
	if err != nil {
		walk.MsgBox(nil, appName, tr("客户端已经运行，请使用已有窗口。", "TLAN is already running. Use the existing window."), walk.MsgBoxOK|walk.MsgBoxIconInformation)
		return
	}
	identity, err := clientidentity.LoadOrCreate(*identityPath)
	if err != nil {
		walk.MsgBox(nil, tr("无法读取本机身份", "Unable to read local identity"), tr("请使用原来的 Windows 用户运行，或检查本机配置文件权限。", "Run as the original Windows user or check local config permissions."), walk.MsgBoxOK|walk.MsgBoxIconError)
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	explicitServer, explicitSTUN := false, false
	flag.Visit(func(f *flag.Flag) {
		explicitServer = explicitServer || f.Name == "server"
		explicitSTUN = explicitSTUN || f.Name == "stun"
	})
	settings = migrateBundledSettings(settings, defaultServerURL)
	rawServer := startupServer(settings.ServerURL, *server, explicitServer)
	var base string
	var endpointErr error
	if rawServer != "" {
		base, endpointErr = normalizeServerURL(rawServer)
		if endpointErr != nil {
			base = defaultServerURL
			if settingsErr == nil {
				settingsErr = fmt.Errorf(tr("已保存的服务器地址无效，请重新填写: %w", "Saved server address is invalid: %w"), endpointErr)
			}
		}
	}
	token, savedAdmin := savedCredentialsForServer(settings, base)
	savedBase, _ := normalizeServerURL(settings.ServerURL)
	stunValue := strings.TrimSpace(*stun)
	if !explicitSTUN {
		stunValue = ""
		if savedBase == base {
			stunValue = settings.STUNServer
		}
	}
	effectiveSTUN := ""
	if base != "" {
		var stunErr error
		_, effectiveSTUN, stunErr = connectionEndpoints(base, stunValue)
		if stunErr != nil {
			effectiveSTUN, _ = STUNAddressForServer(base)
			if settingsErr == nil {
				settingsErr = fmt.Errorf(tr("STUN 地址无效，已使用服务器默认值: %w", "Invalid STUN address; using server default: %w"), stunErr)
			}
		}
	}
	name, _ := os.Hostname()
	if name == "" {
		name = tr("我的电脑", "My PC")
	}
	if settings.DeviceName != "" {
		name = settings.DeviceName
	}
	identity.DisplayName = name
	applyAppearancePalette(settings.Appearance)
	a := &desktop{identity: identity, api: clientapi.New(base, token), ctx: ctx, cancel: cancel, settings: settings, stun: effectiveSTUN, startHidden: *startup, serverProbe: newServerProbeHistory(serverProbeCapacity)}
	a.api.Context = ctx
	// Reported on every control request so an operator can gate outdated clients.
	a.api.AgentVersion = appVersion
	if savedAdmin != "" {
		a.adminMode = true
		a.adminToken = savedAdmin
		a.adminAPI = clientapi.NewAdmin(base, a.adminToken)
		a.adminAPI.Context = ctx
	}
	if token != "" {
		a.membership = clientapi.Membership{Network: clientapi.Network{ID: settings.NetworkID, Name: settings.NetworkName, CIDR: settings.NetworkCIDR}, Member: clientapi.Device{ID: identity.DeviceID.String(), Name: name, VirtualIP: settings.VirtualIP}}
	}
	if err = a.build(); err != nil {
		f := clientui.ExplainLang(currentLang(), tr("打开窗口", "Open window"), err)
		walk.MsgBox(nil, f.Title, f.Message, walk.MsgBoxOK|walk.MsgBoxIconError)
		return
	}
	a.initializeFRP()
	a.startServerProbeLoop()
	if err = a.setupTray(); err != nil {
		a.settings.CloseToTray = false
		a.showWindow()
		a.showError(tr("创建托盘图标", "Create tray icon"), err)
	}
	if settingsErr == nil {
		if err = a.syncLaunchAtLogin(); err != nil {
			a.showNotice(clientui.Feedback{
				Title:   tr("登录启动设置未同步", "Startup registration failed"),
				Message: tr("当前用户启动项未能更新，其他设置仍可正常使用。", "Failed to update Windows startup item. Other settings remain active."),
				Detail:  clientui.RedactLang(currentLang(), err.Error(), a.api.Token),
			})
		}
	}
	a.window.Closing().Attach(a.handleWindowClosing)
	if settingsErr != nil {
		a.showError(tr("读取本机配置", "Load local settings"), settingsErr)
	}
	if a.adminMode {
		a.restoreAdminAccess()
	}
	if token != "" {
		a.restoreMembership()
	}
	go func() {
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		n := 0
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				a.ui(func() {
					a.updateStatus()
					a.updateTrayMenu()
					n++
					if n%5 == 0 {
						a.refreshMembers()
					}
					if n%2 == 0 && a.page == pageFRP {
						a.refreshFRP()
					}
				})
			}
		}
	}()
	a.window.Run()
	a.waitFRPClose()
	if a.session != nil {
		<-a.session.done
		if a.session.engine != nil {
			a.session.engine.Close()
		}
	}
	if a.engine != nil {
		a.engine.Close()
	}
	if a.membership.Network.ID != "" {
		a.announceOff()
	}
}

func (a *desktop) onLang(fn func()) {
	if fn != nil {
		a.langRefreshers = append(a.langRefreshers, fn)
	}
}

func (a *desktop) toggleLanguage() {
	next := langEN
	if isEnglish() {
		next = langZH
	}
	a.settings.Language = next
	a.applyLanguage(next)
	_ = a.remember()
}

func (a *desktop) applyLanguage(lang string) {
	setActiveLanguage(lang)
	a.retranslateUI()
}

func (a *desktop) retranslateUI() {
	for _, fn := range a.langRefreshers {
		fn()
	}
	a.updateThemeButton()
	a.updateSTUNCue()
	a.updatePowerButtons()
	a.refreshPowerStateTexts()
	a.updateStatus()
	a.refreshServerMetricsDisplay()
	a.renderFRPState()
	a.updateFRPRows()
	a.updateFRPButtons()
	a.applyFRPPortRange(a.activeFRPPortRange())
	if a.admin != nil {
		a.admin.retranslate()
	}
	a.updateTrayMenu()
	a.requestCleanRelayout()
}

func (a *desktop) setOffState(text string, color walk.Color) {
	if a == nil || a.offState == nil {
		return
	}
	setLabelIfChanged(a.offState, text)
	setLabelColorIfChanged(a.offState, color)
}

func (a *desktop) refreshPowerStateTexts() {
	if a.offState == nil || a.badge == nil {
		return
	}
	if a.engine != nil {
		a.setOffState(tr("已连接", "Connected"), uiSuccess)
		setLabelIfChanged(a.badge, "● "+tr("本机在线", "Online"))
		setLabelColorIfChanged(a.badge, uiSuccess)
		return
	}
	if a.powerState == 2 {
		a.setOffState(tr("连接中…", "Connecting…"), uiWarning)
		setLabelIfChanged(a.badge, "● "+tr("连接中…", "Connecting…"))
		setLabelColorIfChanged(a.badge, uiWarning)
		return
	}
	a.setOffState(tr("未连接", "Offline"), uiDanger)
	setLabelIfChanged(a.badge, "● "+tr("未连接", "Offline"))
	setLabelColorIfChanged(a.badge, uiMuted)
	if a.memberCount != nil {
		setLabelIfChanged(a.memberCount, tr("未连接", "Offline"))
	}
	if a.empty != nil && (a.peers == nil || !widgetOwnVisible(a.peers)) {
		setLabelIfChanged(a.empty, tr("尚未连接\r\n连接后将显示成员列表与延迟", "Not connected\r\nConnect to view members and latency"))
	}
}

func (a *desktop) ui(fn func()) {
	if !a.closing.Load() {
		a.window.Synchronize(func() {
			if !a.closing.Load() {
				fn()
			}
		})
	}
}
func (a *desktop) setStatus(text string) { a.status.SetText(text) }
func (a *desktop) remember() error {
	if a.api != nil {
		a.settings.ServerURL = a.api.BaseURL
		a.settings.Token = a.api.Token
	}
	if a.adminMode {
		a.settings.AdminToken = a.adminToken
	} else {
		a.settings.AdminToken = ""
	}
	a.settings.NetworkID = a.membership.Network.ID
	a.settings.DeviceName = a.identity.DisplayName
	a.settings.STUNServer = a.stun
	a.settings.NetworkName = a.membership.Network.Name
	a.settings.NetworkCIDR = a.membership.Network.CIDR
	a.settings.VirtualIP = a.membership.Member.VirtualIP
	return clientidentity.SaveSettings(a.settings)
}
func (a *desktop) restoreMembership() {
	a.busy = true
	a.joinButton.SetEnabled(false)
	a.updatePowerButtons()
	a.offState.SetText(tr("恢复中…", "Restoring…"))
	a.offState.SetTextColor(uiWarning)
	a.setStatus(tr("正在恢复网络…", "Restoring network…"))
	go func() {
		m, err := a.api.Session()
		if err == nil && m.Member.ID != a.identity.DeviceID.String() {
			err = fmt.Errorf("membership identity mismatch")
		}
		if err == nil {
			// A temporary failure to announce offline must not erase the saved
			// identity or send a returning user back to the first-run screen.
			a.api.SetForwarding(core.NetworkID(m.Network.ID), a.identity.DeviceID, false)
		}
		a.ui(func() {
			a.busy = false
			a.joinButton.SetEnabled(true)
			a.updatePowerButtons()
			a.setOffState(tr("未连接", "Offline"), uiDanger)
			if err != nil {
				a.setStatus(tr("恢复失败，点击连接网络可重试。", "Restore failed. Click Connect to retry."))
				a.showError(tr("恢复网络", "Restore network"), err)
				return
			}
			a.membership = m
			a.serverDisplay = m.ServerDisplay
			if m.Member.Name != "" {
				a.identity.DisplayName = m.Member.Name
				if a.deviceName != nil {
					_ = a.deviceName.SetText(m.Member.Name)
				}
				if a.usernameInput != nil {
					_ = a.usernameInput.SetText(m.Member.Name)
				}
			}
			a.refreshFRPIdentity()
			a.refreshFRPPortRange()
			a.applyMembership()
			a.bootstrapFRPFromServer(nil)
			if err := a.remember(); err != nil {
				a.showError(tr("保存成员凭据", "Save credentials"), err)
			}
			a.setStatus(tr("已就绪，点击启动组网", "Ready to connect"))
		})
	}()
}
func (a *desktop) restoreAdminAccess() {
	if !a.adminMode || a.adminAPI == nil {
		return
	}
	go func() {
		_, err := a.adminAPI.Overview()
		a.ui(func() {
			if err == nil {
				a.setAdminMode(true, a.adminToken)
				return
			}
			if isAdminAuthFailure(err) {
				a.setAdminMode(false, "")
				a.showNotice(clientui.Feedback{Title: tr("管理权限已失效", "Admin access expired"), Message: tr("请输入当前管理令牌重新加入网络。", "Re-enter the current admin token to restore admin access.")})
				return
			}
			a.setStatus(tr("管理服务暂时不可用，打开管理面板后可重试。", "Admin service temporarily unavailable."))
		})
	}()
}

func (a *desktop) setAdminMode(enabled bool, token string) {
	token = strings.TrimSpace(token)
	enabled = enabled && token != ""
	a.adminMode = enabled
	if !enabled {
		a.adminToken = ""
		a.adminAPI = nil
		if a.admin != nil {
			a.admin.reset()
		}
		if a.railAdmin != nil {
			a.railAdmin.SetVisible(false)
		}
		if a.page == pageAdmin {
			a.showPage(pagePower)
		}
		a.invalidateRail()
		a.requestCleanRelayout()
		return
	}
	a.adminToken = token
	if a.api != nil {
		a.adminAPI = clientapi.NewAdmin(a.api.BaseURL, token)
		a.adminAPI.Context = a.ctx
	}
	if a.railAdmin != nil {
		a.railAdmin.SetVisible(true)
	}
	a.invalidateRail()
	a.requestCleanRelayout()
}

func (a *desktop) setJoinBusy(busy bool) {
	a.busy = busy
	if a.joinButton != nil {
		a.joinButton.SetEnabled(!busy)
		if busy {
			a.joinButton.SetText(tr("正在验证并登录…", "Signing in…"))
		} else {
			a.joinButton.SetText(tr("立即登录", "Sign In"))
		}
	}
	for _, input := range []*walk.LineEdit{a.serverInput, a.stunInput, a.usernameInput, a.code} {
		if input != nil {
			input.SetEnabled(!busy)
		}
	}
	if a.advancedButton != nil {
		a.advancedButton.SetEnabled(!busy)
	}
}

func (a *desktop) join() {
	if a.busy {
		return
	}
	if a.engine != nil {
		a.showNotice(clientui.Feedback{Title: tr("请先关闭虚拟网络", "Disconnect Virtual LAN first"), Message: tr("点击断开连接后，再切换服务器或密钥。", "Disconnect before switching servers or keys.")})
		return
	}
	if a.hasRunningFRP() {
		a.showNotice(clientui.Feedback{Title: tr("请先停止端口映射", "Stop Port Mapping first"), Message: tr("切换入网身份前需要先停止运行中的端口映射服务。", "Stop active port mappings before switching accounts.")})
		return
	}
	if a.usernameInput != nil {
		rawUser := strings.TrimSpace(a.usernameInput.Text())
		if rawUser != "" {
			validUser, uErr := validateCustomUsername(rawUser)
			if uErr != nil {
				a.showNotice(clientui.Feedback{Title: tr("用户名无效", "Invalid username"), Message: uErr.Error()})
				a.usernameInput.SetFocus()
				return
			}
			a.identity.DisplayName = validUser
		}
	}
	code := strings.TrimSpace(a.token)
	if code == "" {
		a.showNotice(clientui.Feedback{Title: tr("请输入入网密钥", "Join key required"), Message: tr("填写常规用户密钥或管理员密钥后点击登录。", "Enter a join key or admin token and click Sign In.")})
		a.code.SetFocus()
		return
	}
	serverValue, stunValue := "", ""
	if a.serverInput != nil {
		serverValue = a.serverInput.Text()
	}
	if a.stunInput != nil {
		stunValue = a.stunInput.Text()
	}
	base, effectiveSTUN, err := connectionEndpoints(serverValue, stunValue)
	if err != nil {
		a.showNotice(clientui.Feedback{Title: tr("服务器地址格式有误", "Invalid server address"), Message: err.Error(), Detail: tr("服务器示例：203.0.113.10:8443；STUN 示例：203.0.113.10:3478", "Server example: 203.0.113.10:8443; STUN example: 203.0.113.10:3478")})
		if a.serverInput != nil {
			a.serverInput.SetFocus()
		}
		return
	}
	after := a.joinAfter
	a.dismissNotice()
	a.setJoinBusy(true)
	a.setStatus(tr("正在连接服务器并验证令牌…", "Connecting and verifying key…"))
	candidate := clientapi.New(base, "")
	candidate.Context = a.ctx
	candidate.AgentVersion = appVersion
	go func() {
		m, err := candidate.Enroll(code, a.identity.RegisterRequest(), a.identity.PrivateKey)
		a.ui(func() {
			a.setJoinBusy(false)
			if err != nil {
				a.showErrorWithAPI(tr("加入网络", "Join network"), err, candidate)
				return
			}
			a.joinAfter = nil
			a.code.SetText("")
			a.token = ""
			candidate.Token = m.Token
			a.api = candidate
			a.stun = effectiveSTUN
			a.membership = m
			a.serverDisplay = m.ServerDisplay
			if m.Member.Name != "" {
				a.identity.DisplayName = m.Member.Name
			}
			if a.deviceName != nil {
				_ = a.deviceName.SetText(a.identity.DisplayName)
			}
			a.members = nil
			a.setAdminMode(m.Admin, code)
			a.frpPortRange = clientapi.DefaultFRPPortRange
			if a.serverProbe != nil {
				a.serverProbe.Reset()
				a.refreshServerMetricsDisplay()
			}
			a.refreshFRPIdentity()
			a.syncFRPServerHost()
			a.refreshFRPPortRange()
			a.applyMembership()
			a.bootstrapFRPFromServer(nil)
			if err := a.remember(); err != nil {
				a.showError(tr("保存成员凭据", "Save credentials"), err)
			}
			a.setStatus(tr("已加入网络，点击电源开启连接。", "Joined network. Click Connect to start."))
			if after != nil {
				after()
			}
		})
	}()
}
func displayEndpointOrDash(baseURL string) string {
	hostPort := strings.TrimSpace(baseURL)
	hostPort = strings.TrimPrefix(hostPort, "https://")
	hostPort = strings.TrimPrefix(hostPort, "http://")
	hostPort = strings.TrimSuffix(hostPort, "/")
	if slash := strings.IndexByte(hostPort, '/'); slash >= 0 {
		hostPort = hostPort[:slash]
	}
	if hostPort == "" {
		return "—"
	}
	return hostPort
}

func formatEndpointSummary(baseURL, stun string) string {
	hostPort := displayEndpointOrDash(baseURL)
	if hostPort == "—" {
		return "—"
	}
	stun = strings.TrimSpace(stun)
	if stun == "" {
		return hostPort
	}
	if apiHost, _, err := net.SplitHostPort(hostPort); err == nil {
		if stunHost, stunPort, err := net.SplitHostPort(stun); err == nil && strings.EqualFold(apiHost, stunHost) {
			return hostPort + " · STUN :" + stunPort
		}
	} else if stunHost, stunPort, err := net.SplitHostPort(stun); err == nil && strings.EqualFold(hostPort, stunHost) {
		return hostPort + " · STUN :" + stunPort
	}
	return hostPort + " · STUN " + stun
}

func maskServerAddress(addr string) string {
	trimmed := strings.TrimSpace(addr)
	if trimmed == "" || trimmed == "—" {
		return "—"
	}
	if host, port, err := net.SplitHostPort(trimmed); err == nil {
		if net.ParseIP(host) != nil {
			return "•••.•••.•••.•••:" + port
		}
		return "••••••:" + port
	}
	if net.ParseIP(trimmed) != nil {
		return "•••.•••.•••.•••"
	}
	return "••••••"
}

func (a *desktop) connectedControlEndpoint() string {
	if a != nil && a.api != nil {
		return displayEndpointOrDash(a.api.BaseURL)
	}
	return "—"
}

func formatTrafficSummary(sent, recv uint64) string {
	return trf("上传 ↑ %s   下载 ↓ %s", "Up ↑ %s   Down ↓ %s", formatTraffic(sent), formatTraffic(recv))
}

func setLabelIfChanged(lbl *walk.Label, text string) bool {
	if lbl == nil || lbl.IsDisposed() {
		return false
	}
	if lbl.Text() == text {
		return false
	}
	_ = lbl.SetText(text)
	return true
}

func setLabelColorIfChanged(lbl *walk.Label, color walk.Color) bool {
	if lbl == nil || lbl.IsDisposed() {
		return false
	}
	if lbl.TextColor() == color {
		return false
	}
	lbl.SetTextColor(color)
	return true
}

func setButtonTextIfChanged(btn *walk.PushButton, text string) bool {
	if btn == nil || btn.IsDisposed() {
		return false
	}
	if btn.Text() == text {
		return false
	}
	_ = btn.SetText(text)
	_ = btn.Invalidate()
	return true
}

func setButtonEnabledIfChanged(btn *walk.PushButton, enabled bool) bool {
	if btn == nil || btn.IsDisposed() {
		return false
	}
	if btn.Enabled() == enabled {
		return false
	}
	btn.SetEnabled(enabled)
	_ = btn.Invalidate()
	return true
}

func widgetOwnVisible(w walk.Widget) bool {
	if w == nil || w.IsDisposed() {
		return false
	}
	h := w.Handle()
	if h == 0 {
		return false
	}
	return win.GetWindowLong(h, win.GWL_STYLE)&win.WS_VISIBLE != 0
}

func (a *desktop) updateConnectedServerDisplays() {
	if a == nil {
		return
	}
	if a.serverIdentity != nil {
		mode := strings.ToLower(strings.TrimSpace(a.serverDisplay.Mode))
		alias := strings.TrimSpace(a.serverDisplay.Alias)
		showEye := true
		value := a.connectedControlEndpoint()
		if mode == "alias" && alias != "" {
			showEye = false
			value = alias
		} else if a.powerServerHidden {
			value = maskServerAddress(value)
		}
		setLabelIfChanged(a.serverIdentity, value)
		if a.powerServerEye != nil {
			prevVisible := widgetOwnVisible(a.powerServerEye)
			if prevVisible != showEye {
				a.powerServerEye.SetVisible(showEye)
				if a.page == pagePower {
					_ = a.powerServerEye.Invalidate()
					a.requestCleanRelayout()
				}
			}
		}
	}
	if a.frpServerAddrLabel != nil {
		host := strings.TrimSpace(a.frpServerHost())
		if host == "" {
			host = strings.TrimSpace(a.frpSnapshot.ServerHost)
		}
		endpoint := "—"
		if host != "" {
			endpoint = host
		}
		if a.frpServerHidden {
			endpoint = maskServerAddress(endpoint)
		}
		if setLabelIfChanged(a.frpServerAddrLabel, endpoint) && a.frpServerEye != nil {
			_ = a.frpServerEye.Invalidate()
		}
	}
}

func (a *desktop) togglePowerServerEye() {
	a.powerServerHidden = !a.powerServerHidden
	a.updateConnectedServerDisplays()
	if a.powerServerEye != nil {
		_ = a.powerServerEye.Invalidate()
	}
}

func (a *desktop) toggleFRPServerEye() {
	a.frpServerHidden = !a.frpServerHidden
	a.updateConnectedServerDisplays()
	if a.frpServerEye != nil {
		_ = a.frpServerEye.Invalidate()
	}
}

func (a *desktop) syncServerDisplay() {
	if a == nil || a.api == nil || a.api.Token == "" || a.smokeMode {
		return
	}
	api := *a.api
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		api.Context = ctx
		m, err := api.Session()
		cancel()
		if err != nil {
			return
		}
		a.ui(func() {
			a.serverDisplay = m.ServerDisplay
			a.updateConnectedServerDisplays()
		})
	}()
}

func (a *desktop) setEmptyState(visible bool, text string) {
	if a.empty != nil && text != "" {
		setLabelIfChanged(a.empty, text)
	}
	if a.empty != nil && widgetOwnVisible(a.empty) != visible {
		a.empty.SetVisible(visible)
	}
	if a.emptyArea != nil && widgetOwnVisible(a.emptyArea) != visible {
		a.emptyArea.SetVisible(visible)
	}
}

func (a *desktop) applyMembership() {
	a.address.SetText(a.membership.Member.VirtualIP)
	a.networkTitle.SetText(a.membership.Network.Name)
	a.badge.SetText("● " + tr("未连接", "Offline"))
	a.badge.SetTextColor(uiMuted)
	a.offNetwork.SetText(a.membership.Network.Name)
	if a.deviceName != nil && a.identity.DisplayName != "" {
		_ = a.deviceName.SetText(a.identity.DisplayName)
	}
	a.updateConnectedServerDisplays()
	a.setPoweredOff()
}
func (a *desktop) toggleAdvancedConnection() {
	if a.advancedPanel == nil {
		return
	}
	visible := !a.advancedPanel.Visible()
	a.advancedPanel.SetVisible(visible)
	if a.advancedButton != nil {
		if visible {
			a.advancedButton.SetText(tr("收起 STUN", "Hide STUN"))
		} else {
			a.advancedButton.SetText(tr("STUN 设置", "STUN"))
		}
	}
	a.requestCleanRelayout()
}

func (a *desktop) updateSTUNCue() {
	if a.stunInput == nil || a.serverInput == nil {
		return
	}
	if derived, err := STUNAddressForServer(a.serverInput.Text()); err == nil {
		if a.stunAuto && a.stunInput.Text() != "" {
			_ = a.stunInput.SetText("")
		}
		_ = a.stunInput.SetCueBanner(tr("留空自动：", "Auto: ") + derived)
	} else {
		_ = a.stunInput.SetCueBanner(tr("留空自动跟随服务器", "Auto from server host if empty"))
	}
}

func (a *desktop) markSTUNInput() {
	if a.advancedPanel == nil {
		return
	}
	if a.stunInput != nil {
		a.stunAuto = strings.TrimSpace(a.stunInput.Text()) == ""
	}
}

func (a *desktop) changeCode() {
	if a.busy || a.engine != nil {
		a.showNotice(clientui.Feedback{Title: tr("请先关闭虚拟网络", "Disconnect Virtual LAN first"), Message: tr("断开连接后即可重新输入服务器地址或入网密钥。", "Disconnect before changing server or join key.")})
		return
	}
	if a.hasRunningFRP() {
		a.showNotice(clientui.Feedback{Title: tr("请先停止端口映射", "Stop Port Mapping first"), Message: tr("切换入网身份前需要先停止所有运行中的端口映射。", "Stop active port mappings before switching accounts.")})
		return
	}
	a.dismissNotice()
	a.showPage(pageJoin)
	a.code.SetFocus()
}
func (a *desktop) togglePower() {
	if a.busy {
		return
	}
	if a.api.Token == "" {
		a.showPage(pageJoin)
		a.code.SetFocus()
		a.setStatus(tr("先输入服务器与密钥登录，再开启电源。", "Sign in with a server and join key first."))
		return
	}
	if a.engine != nil {
		a.stopPower()
	} else {
		a.startPower()
	}
}
func (a *desktop) startPower() {
	if a.busy || a.engine != nil || a.api.Token == "" {
		return
	}
	a.dismissNotice()
	a.busy = true
	a.powerState = 2
	a.updatePowerButtons()
	a.setOffState(tr("连接中…", "Connecting…"), uiWarning)
	a.badge.SetText("● " + tr("连接中…", "Connecting…"))
	a.badge.SetTextColor(uiWarning)
	ctx, cancel := context.WithCancel(a.ctx)
	a.sessionCancel = cancel
	session := &desktopSession{done: make(chan struct{})}
	a.session = session
	api := *a.api
	api.Context = ctx
	frpManagers := a.allFRPManagers()
	go func() {
		var engine *mesh.Engine
		defer func() { session.engine = engine; close(session.done) }()
		err := ctx.Err()
		var m clientapi.Membership
		if err == nil {
			m, err = api.Session()
			if err == nil && m.Member.ID != a.identity.DeviceID.String() {
				err = fmt.Errorf("membership identity mismatch")
			}
		}
		if err == nil {
			err = validateFRPMeshStart(ctx, frpManagers, m.Network.CIDR)
		}
		if err == nil {
			engine, err = mesh.Start(ctx, mesh.Options{API: &api, Identity: a.identity, Network: m.Network, Member: m.Member, InterfaceName: "TLAN", STUNServer: a.stun, RelayOnly: a.settings.RelayOnly, MTU: a.settings.MTU, ReplicateSmallPackets: a.settings.MultipathReplication})
		}
		if err == nil {
			err = updateFRPMeshCIDR(frpManagers, m.Network.CIDR)
		}
		if err == nil {
			// Re-check after the interface and routes exist. A DNS answer or
			// route can change between the preflight and interface creation.
			err = validateFRPMeshStart(ctx, frpManagers, m.Network.CIDR)
		}
		if err == nil {
			_, err = api.SetForwarding(core.NetworkID(m.Network.ID), a.identity.DeviceID, true)
		}
		if err != nil || a.closing.Load() || ctx.Err() != nil {
			cancel()
			if engine != nil {
				if closeErr := engine.Close(); closeErr != nil {
					if err != nil {
						err = fmt.Errorf("%w; adapter cleanup incomplete: %v", err, closeErr)
					} else {
						err = fmt.Errorf("adapter cleanup incomplete: %w", closeErr)
					}
				}
			}
			if m.Network.ID != "" {
				offAPI := api
				offCtx, offCancel := context.WithTimeout(context.Background(), 4*time.Second)
				offAPI.Context = offCtx
				offAPI.SetForwarding(core.NetworkID(m.Network.ID), a.identity.DeviceID, false)
				offCancel()
			}
			a.ui(func() {
				a.busy = false
				a.setPoweredOff()
				if err != nil {
					a.showError(tr("开启虚拟网络", "Connect Virtual LAN"), err)
				}
			})
			return
		}
		a.ui(func() {
			a.busy = false
			a.engine = engine
			a.membership = m
			a.powerState = 1
			a.updatePowerButtons()
			a.address.SetText(m.Member.VirtualIP)
			a.networkTitle.SetText(m.Network.Name)
			a.setOffState(tr("已连接", "Connected"), uiSuccess)
			a.offNetwork.SetText(m.Network.Name)
			a.showPage(pagePower)
			a.badge.SetText("● " + tr("本机在线", "Online"))
			a.badge.SetTextColor(uiSuccess)
			if err := a.remember(); err != nil {
				a.showError(tr("保存成员凭据", "Save credentials"), err)
			}
			a.setStatus(tr("虚拟局域网已连接", "Virtual LAN connected"))
			a.refreshMembers()
			a.updateStatus()
			if recovery := engine.RecoveryStatus(); recovery.HasIssues() {
				var detail strings.Builder
				for i, issue := range recovery.Issues {
					if i >= 8 {
						fmt.Fprintf(&detail, tr("…另有 %d 项\n", "…and %d more\n"), len(recovery.Issues)-i)
						break
					}
					fmt.Fprintf(&detail, "%s · %s/%s: %s\n", issue.Resource.Type, issue.Resource.Name, issue.Resource.Prefix, issue.Error)
				}
				a.showNotice(clientui.Feedback{
					Title:   tr("发现历史网络资源残留", "Stale virtual network resources detected"),
					Message: trf("已恢复 %d 项，失败 %d 项，无法证明归属 %d 项。请查看诊断。", "Recovered %d, failed %d, unproven %d. Check diagnostics for details.", recovery.Recovered, recovery.Failed, recovery.Unproven),
					Detail:  clientui.RedactLang(currentLang(), strings.TrimSpace(detail.String()), a.api.Token),
				})
			}
		})
	}()
}
func (a *desktop) announceOff() error {
	api := *a.api
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	api.Context = ctx
	_, err := api.SetForwarding(core.NetworkID(a.membership.Network.ID), a.identity.DeviceID, false)
	return err
}
func (a *desktop) stopPower() {
	if a.busy || a.engine == nil {
		return
	}
	a.dismissNotice()
	a.busy = true
	a.powerState = 2
	a.updatePowerButtons()
	a.setOffState(tr("断开中…", "Disconnecting…"), uiWarning)
	a.badge.SetText("● " + tr("断开中…", "Disconnecting…"))
	a.badge.SetTextColor(uiWarning)
	engine := a.engine
	a.engine = nil
	if a.sessionCancel != nil {
		a.sessionCancel()
		a.sessionCancel = nil
	}
	go func() {
		closeErr := engine.Close()
		err := a.announceOff()
		a.ui(func() {
			a.busy = false
			a.setPoweredOff()
			if closeErr != nil {
				a.setStatus(tr("虚拟网络已关闭，但本机资源清理不完整。", "Disconnected with incomplete local cleanup."))
				a.showNotice(clientui.Feedback{
					Title:   tr("虚拟网络已关闭，但资源清理不完整", "Disconnected with incomplete cleanup"),
					Message: tr("虚拟网卡、路由或防火墙规则可能仍有残留，重启客户端后可自动清理。", "Virtual adapter, route, or firewall rules may remain. Restart the client to retry cleanup."),
					Detail:  clientui.RedactLang(currentLang(), closeErr.Error(), a.api.Token),
				})
				return
			}
			a.setStatus(tr("转发已关闭，虚拟网卡和路由已释放。", "Disconnected and virtual adapter released."))
			if err != nil {
				a.showNotice(clientui.Feedback{Title: tr("本机转发已关闭", "Local forwarding stopped"), Message: tr("成员离线状态暂未同步，服务器会在心跳超时后标记离线。", "Offline status sync failed; server will mark offline after heartbeat timeout."), Detail: clientui.RedactLang(currentLang(), err.Error(), a.api.Token)})
			}
		})
	}()
}

func updateFRPMeshCIDR(managers []*frp.Manager, cidr string) error {
	for _, manager := range managers {
		if manager == nil {
			continue
		}
		if err := manager.UpdateMeshCIDR(cidr); err != nil {
			return err
		}
	}
	return nil
}

func validateFRPMeshStart(ctx context.Context, managers []*frp.Manager, cidr string) error {
	for _, manager := range managers {
		if manager == nil {
			continue
		}
		if err := manager.ValidateMeshStart(ctx, cidr); err != nil {
			name := tr("当前端口映射", "Port Mapping")
			if cfg, ok := manager.Config(); ok && cfg.Profile.Name != "" {
				name = cfg.Profile.Name
			}
			return fmt.Errorf(tr("端口映射“%s”与虚拟局域网网段冲突: %w", "port mapping %q conflicts with virtual LAN subnet: %w"), name, err)
		}
	}
	return nil
}
func (a *desktop) setPoweredOff() {
	a.powerState = 0
	a.updatePowerButtons()
	a.setOffState(tr("未连接", "Offline"), uiDanger)
	if a.offHint != nil {
		a.offHint.SetVisible(false)
		_ = a.offHint.SetText("")
	}
	a.offNetwork.SetText(a.membership.Network.Name)
	a.badge.SetText("● " + tr("未连接", "Offline"))
	a.badge.SetTextColor(uiMuted)
	a.peers.SetVisible(false)
	a.setEmptyState(true, tr("虚拟局域网未连接\r\n连接后此处将显示成员列表与延迟", "Virtual LAN not connected\r\nConnect to display members and latency"))
	setLabelIfChanged(a.traffic, formatTrafficSummary(0, 0))
	setLabelIfChanged(a.memberCount, tr("未连接", "Offline"))
	a.showPage(pagePower)
}

func (a *desktop) showTransientHint(text string) {
	if a.offHint == nil {
		return
	}
	a.offHintSeq++
	seq := a.offHintSeq
	_ = a.offHint.SetText(text)
	a.offHint.SetVisible(true)
	a.requestCleanRelayout()
	time.AfterFunc(2500*time.Millisecond, func() {
		a.ui(func() {
			if seq == a.offHintSeq && a.offHint != nil && !a.offHint.IsDisposed() {
				a.offHint.SetVisible(false)
				_ = a.offHint.SetText("")
				a.requestCleanRelayout()
			}
		})
	})
}

func (a *desktop) copyLocalIP() {
	ip := strings.TrimSpace(a.membership.Member.VirtualIP)
	if ip == "" && a.address != nil {
		ip = strings.TrimSpace(a.address.Text())
	}
	if ip == "" || ip == "尚未分配 IP" || ip == "No IP" {
		return
	}
	if err := walk.Clipboard().SetText(ip); err != nil {
		a.showError(tr("复制虚拟 IP", "Copy virtual IP"), err)
		return
	}
	a.setStatus(tr("已复制本机 IP: ", "Copied local IP: ") + ip)
	a.showTransientHint(tr("已复制本机 IP: ", "Copied local IP: ") + ip)
}

func (a *desktop) copySelectedPeerIP() {
	if a.peers == nil {
		return
	}
	a.copyPeerIPAt(a.peers.CurrentIndex())
}

func (a *desktop) copyPeerIPAt(index int) {
	if a.peerModel == nil || index < 0 || index >= len(a.peerModel.rows) {
		return
	}
	row := a.peerModel.rows[index]
	if len(row) < 2 {
		return
	}
	ip := strings.TrimSpace(row[1])
	if ip == "" || ip == "—" {
		return
	}
	if err := walk.Clipboard().SetText(ip); err != nil {
		a.showError(tr("复制成员 IP", "Copy member IP"), err)
		return
	}
	a.setStatus(tr("已复制 IP: ", "Copied IP: ") + ip)
	if a.peerCopyHint != nil {
		a.peerCopySeq++
		seq := a.peerCopySeq
		_ = a.peerCopyHint.SetText(tr("已复制 ", "Copied ") + ip)
		a.peerCopyHint.SetVisible(true)
		time.AfterFunc(2500*time.Millisecond, func() {
			a.ui(func() {
				if seq == a.peerCopySeq && a.peerCopyHint != nil {
					a.peerCopyHint.SetVisible(false)
					_ = a.peerCopyHint.SetText("")
				}
			})
		})
	}
}

func (a *desktop) handlePeerTableMouseUp(button walk.MouseButton) {
	if button != walk.LeftButton || a.peers == nil || a.peers.IsDisposed() {
		return
	}
	var pt win.POINT
	if !win.GetCursorPos(&pt) {
		return
	}
	const (
		gwChild    = 5
		gwHwndNext = 2
	)
	for child := win.GetWindow(a.peers.Handle(), gwChild); child != 0; child = win.GetWindow(child, gwHwndNext) {
		if !win.IsWindowVisible(child) {
			continue
		}
		var cr win.RECT
		win.GetClientRect(child, &cr)
		localPt := pt
		win.ScreenToClient(child, &localPt)
		if localPt.X < cr.Left || localPt.X >= cr.Right || localPt.Y < cr.Top || localPt.Y >= cr.Bottom {
			continue
		}
		hti := win.LVHITTESTINFO{Pt: localPt}
		win.SendMessage(child, win.LVM_SUBITEMHITTEST, 0, uintptr(unsafe.Pointer(&hti)))
		if hti.IItem >= 0 && hti.ISubItem == 1 {
			a.copyPeerIPAt(int(hti.IItem))
		}
		return
	}
}
func (a *desktop) refreshMembers() {
	if a.refreshing || a.membership.Network.ID == "" || a.engine == nil {
		return
	}
	a.refreshing = true
	api := *a.api
	nid := core.NetworkID(a.membership.Network.ID)
	go func() {
		members, err := api.ListDevices(nid)
		var sessionSnapshot *clientapi.Membership
		if s, sErr := api.Session(); sErr == nil {
			cp := s
			sessionSnapshot = &cp
		}
		a.ui(func() {
			a.refreshing = false
			if sessionSnapshot != nil {
				a.serverDisplay = sessionSnapshot.ServerDisplay
				if name := strings.TrimSpace(sessionSnapshot.Network.Name); name != "" && name != a.membership.Network.Name {
					a.membership.Network.Name = name
					setLabelIfChanged(a.networkTitle, name)
					setLabelIfChanged(a.offNetwork, name)
				}
				a.updateConnectedServerDisplays()
			}
			if a.engine == nil || core.NetworkID(a.membership.Network.ID) != nid {
				return
			}
			if err != nil {
				a.setStatus(tr("成员列表暂时无法更新，正在等待下次刷新。", "Unable to refresh member list; retrying soon."))
				return
			}
			a.members = members
			a.updateStatus()
		})
	}()
}
func (a *desktop) updateStatus() {
	if a.engine == nil {
		return
	}
	s := a.engine.Status()
	if !s.Running {
		if !a.busy {
			a.stopPower()
			a.showError(tr("运行虚拟网络", "Virtual LAN"), fmt.Errorf("%s", s.LastError))
		}
		return
	}
	peers := make(map[string]mesh.PeerStatus)
	for _, p := range s.Peers {
		peers[p.ID] = p
	}
	rows := [][]string{}
	online := 0
	// Keep the local device first, followed by active and historical members.
	members := append([]clientapi.Device(nil), a.members...)
	rank := func(d clientapi.Device) int {
		if d.ID == a.identity.DeviceID.String() {
			return 0
		}
		if d.Online {
			return 1
		}
		return 2
	}
	sort.SliceStable(members, func(i, j int) bool { return rank(members[i]) < rank(members[j]) })
	for _, member := range members {
		name, state, path, delay := member.Name, tr("离线", "Offline"), "—", "—"
		if member.ID == a.identity.DeviceID.String() {
			name += tr("（本机）", " (You)")
			state = tr("在线", "Online")
			path = tr("本机", "Local")
			online++
			if member.Name != "" && member.Name != a.identity.DisplayName {
				a.identity.DisplayName = member.Name
				if a.deviceName != nil {
					_ = a.deviceName.SetText(member.Name)
				}
			}
		} else if member.Online {
			state = tr("连接中", "Connecting")
			p, ok := peers[member.ID]
			if ok {
				path = map[string]string{
					"direct UDP":    tr("直连", "Direct"),
					"relay TCP/TLS": tr("中继", "Relay"),
					"checking":      tr("探测中", "Probing"),
				}[p.Path]
				if p.Reachable {
					state = tr("在线", "Online")
					delay = fmt.Sprintf("%.0f ms", float64(p.RTT)/float64(time.Millisecond))
					online++
				}
			}
		}
		rows = append(rows, []string{name, member.VirtualIP, state, path, delay})
	}
	a.peerModel.setRows(rows)
	if widgetOwnVisible(a.peers) != (len(rows) > 0) {
		a.peers.SetVisible(len(rows) > 0)
	}
	a.setEmptyState(len(rows) == 0, tr("正在获取在线成员…", "Loading members…"))
	setLabelIfChanged(a.memberCount, trf("%d / %d 在线", "%d / %d online", online, len(rows)))
	setLabelIfChanged(a.traffic, formatTrafficSummary(s.Sent, s.Received))
}
func (a *desktop) hasRunningFRP() bool {
	for _, manager := range a.frpManagers {
		if manager == nil {
			continue
		}
		if manager.RequiresIdentityStop() {
			return true
		}
	}
	return false
}
func (a *desktop) leaveNetwork() {
	if a.busy || a.engine != nil {
		a.showNotice(clientui.Feedback{Title: tr("请先关闭电源", "Disconnect first"), Message: tr("关闭转发后可退出当前网络。", "Disconnect Virtual LAN before leaving the network.")})
		return
	}
	if a.hasRunningFRP() {
		a.showNotice(clientui.Feedback{Title: tr("请先停止端口映射", "Stop Port Mapping first"), Message: tr("退出网络前需要先停止运行中的端口映射服务。", "Stop active port mappings before leaving the network.")})
		return
	}
	if a.membership.Network.ID == "" {
		return
	}
	a.busy = true
	api := *a.api
	nid := core.NetworkID(a.membership.Network.ID)
	go func() {
		err := api.RemoveDevice(nid, a.identity.DeviceID)
		a.ui(func() {
			a.busy = false
			if err != nil {
				a.showError(tr("退出网络", "Leave network"), err)
				return
			}
			a.setAdminMode(false, "")
			if a.serverProbe != nil {
				a.serverProbe.Reset()
				a.refreshServerMetricsDisplay()
			}
			a.membership = clientapi.Membership{}
			a.api.Token = ""
			a.members = nil
			a.code.SetText("")
			a.token = ""
			a.address.SetText(tr("尚未分配 IP", "No IP"))
			a.badge.SetText("● " + tr("未加入", "Not joined"))
			a.badge.SetTextColor(uiMuted)
			a.networkTitle.SetText(tr("私人网络", "Private Network"))
			a.memberCount.SetText("")
			a.showPage(pageJoin)
			a.setEmptyState(true, tr("虚拟局域网未连接", "Virtual LAN not connected"))
			a.dismissNotice()
			if err := a.remember(); err != nil {
				a.showError(tr("保存本机配置", "Save settings"), err)
			}
			a.setStatus(tr("已退出网络", "Left network"))
		})
	}()
}
func (a *desktop) diagnose() {
	var meshChecks []clientapi.DiagnosticCheck
	var meshQuality *meshQualityDiagnostic
	if a.engine != nil {
		meshChecks = a.engine.Diagnostics()
		samples := a.engine.Quality()
		if len(samples) > 0 {
			meshQuality = &meshQualityDiagnostic{
				SchemaVersion: 1,
				Summary:       a.engine.QualitySummary(),
				Samples:       samples,
			}
		}
	}
	frpSources := a.frpDiagnosticSources()
	api := clientapi.Client{}
	if a.api != nil {
		api = *a.api
	}
	stunAddr := strings.TrimSpace(a.stun)
	hasServer := strings.TrimSpace(api.BaseURL) != ""
	if a.engine == nil && len(frpSources) == 0 && !hasServer {
		a.showNotice(clientui.Feedback{Title: tr("暂无可诊断的连接", "Nothing to diagnose"), Message: tr("请先配置服务器，或开启虚拟局域网 / 端口映射后再运行诊断。", "Sign in or start Virtual LAN / Port Mapping before running diagnostics.")})
		return
	}
	_, probeStats := a.serverProbe.Snapshot()
	nid := core.NetworkID(a.membership.Network.ID)
	deviceID := a.identity.DeviceID
	secrets := frpDiagnosticSecretValues(frpSources, []string{api.Token})
	go func() {
		ctx := a.ctx
		if ctx == nil {
			ctx = context.Background()
		}
		var checks []clientapi.DiagnosticCheck
		if hasServer {
			healthCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			probeClient := clientapi.Client{BaseURL: api.BaseURL, HTTP: api.HTTP}
			rtt, healthErr := probeClient.HealthProbe(healthCtx)
			cancel()
			if healthErr != nil {
				checks = append(checks, clientapi.DiagnosticCheck{
					Name:   "control_health",
					Status: "fail",
					Detail: clientui.RedactLang(currentLang(), healthErr.Error(), secrets...),
				})
			} else {
				ms := float64(rtt) / float64(time.Millisecond)
				if ms < 1 {
					ms = 1
				}
				checks = append(checks, clientapi.DiagnosticCheck{
					Name:   "control_health",
					Status: "pass",
					Detail: trf("控制服务响应耗时 %.0f ms", "Control service responded in %.0f ms", ms),
				})
			}
		}
		if stunAddr != "" {
			stunCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			stunClient := network.NewUDPSTUNClient()
			stunClient.Timeout = 2 * time.Second
			started := time.Now()
			mapped, stunErr := stunClient.Probe(stunCtx, stunAddr)
			cancel()
			if stunErr != nil {
				checks = append(checks, clientapi.DiagnosticCheck{
					Name:   "stun_probe",
					Status: "warn",
					Detail: tr("UDP 打洞探测失败: ", "STUN UDP probe failed: ") + clientui.RedactLang(currentLang(), stunErr.Error(), secrets...),
				})
			} else {
				ms := float64(time.Since(started)) / float64(time.Millisecond)
				if ms < 1 {
					ms = 1
				}
				checks = append(checks, clientapi.DiagnosticCheck{
					Name:   "stun_probe",
					Status: "pass",
					Detail: trf("UDP 公网映射 %s (%.0f ms)", "UDP mapped %s (%.0f ms)", mapped.MappedAddress, ms),
				})
			}
		}
		if probeStats.Count > 0 {
			status := "pass"
			if probeStats.LatestRTTMillis < 0 {
				status = "fail"
			} else if probeStats.LossPercent >= 15 {
				status = "warn"
			}
			checks = append(checks, clientapi.DiagnosticCheck{
				Name:   "server_link",
				Status: status,
				Detail: trf("当前延迟 %s · 平均 %.0f ms · 丢包 %.1f%% (%s)", "RTT %s · Avg %.0f ms · Loss %.1f%% (%s)", formatLatencyText(probeStats.LatestRTTMillis), probeStats.AvgRTTMillis, probeStats.LossPercent, probeStats.Mode),
			})
		}
		frpReport, frpChecks := buildFRPDiagnosticExport(ctx, frpSources, secrets, time.Now().UTC())
		checks = append(checks, meshChecks...)
		checks = append(checks, frpChecks...)
		export := diagnosticExport{
			SchemaVersion: diagnosticSchemaVersion,
			AppVersion:    appVersion,
			GeneratedAt:   time.Now().UTC(),
			Checks:        checks,
			FRP:           frpReport,
			MeshQuality:   meshQuality,
		}
		summary := buildDiagnosticSummary(export, probeStats, api.BaseURL, stunAddr)
		identityPath, err := clientidentity.DefaultPath()
		var jsonPath, textPath string
		if err == nil {
			jsonPath, textPath, err = writeDiagnosticExport(filepath.Dir(identityPath), export, secrets)
		}
		var uploadErr error
		if err == nil && api.Token != "" && nid != "" && deviceID != "" {
			uploadErr = uploadFRPDiagnosticReport(&api, nid, deviceID, checks, frpReport, secrets)
		}
		detail := summary.plainText("") + tr("\r\n--- 详细报告 ---\r\n", "\r\n--- Raw Report ---\r\n") + export.Text() + "\r\nJSON: " + jsonPath + tr("\r\n文本: ", "\r\nText: ") + textPath
		a.ui(func() {
			if err != nil {
				a.showError(tr("保存诊断", "Save diagnostics"), err)
				return
			}
			message := tr("已保存至本地目录", "Saved locally")
			switch {
			case uploadErr != nil:
				message = tr("已保存至本地，同步失败：", "Saved locally; sync failed: ") + clientui.RedactLang(currentLang(), uploadErr.Error(), secrets...)
			case api.Token == "":
				message += tr("（未登录，未上传）", " (not signed in; not uploaded)")
			default:
				message += tr("，并已同步至服务器。", ", and synced to server.")
			}
			a.showDiagnosticsDialog(summary, message, clientui.RedactLang(currentLang(), detail, secrets...))
		})
	}()
}
func runUITest(path string) {
	if err := checkDesktopUI(); err != nil {
		os.WriteFile(path, []byte("FAIL: "+err.Error()), 0600)
		os.Exit(1)
	}
	os.WriteFile(path, []byte("PASS: self-hosted server validation, light/dark redraw, bilingual ZH/EN UI, custom username, enrollment rollback, integrated Mesh workspace, FRP page, admin panel, tray actions, close policy, member/rule tables, accessibility and antialiased drawing; no external network or adapter created\n"), 0600)
}
func runAdapterTest(path string) {
	os.WriteFile(path, []byte("RUNNING\n"), 0600)
	adapter, err := platform.OpenTunnel("TLAN-Test", netip.MustParsePrefix("10.254.253.1/30"), mesh.MTU)
	report := ""
	if err != nil {
		report = "FAIL: " + err.Error()
	} else {
		name, _ := adapter.Name()
		_, lookErr := net.InterfaceByName(name)
		desc, descErr := platform.QueryAdapterDescription(name)
		closeErr := adapter.Close()
		if lookErr != nil || descErr != nil || closeErr != nil {
			report = fmt.Sprintf("FAIL: lookup=%v descErr=%v close=%v", lookErr, descErr, closeErr)
		} else {
			report = fmt.Sprintf("PASS: created, configured and released %s (desc=%q)", name, desc)
		}
	}
	os.WriteFile(path, []byte(report+"\n"), 0600)
	if strings.HasPrefix(report, "FAIL") {
		os.Exit(1)
	}
}
