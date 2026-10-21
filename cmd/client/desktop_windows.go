//go:build windows

package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lxn/walk"
	"github.com/private-radminlan/lanmesh/core"
	"github.com/private-radminlan/lanmesh/internal/clientapi"
	"github.com/private-radminlan/lanmesh/internal/clientidentity"
	"github.com/private-radminlan/lanmesh/internal/clientui"
	"github.com/private-radminlan/lanmesh/internal/frp"
	"github.com/private-radminlan/lanmesh/internal/mesh"
	"github.com/private-radminlan/lanmesh/internal/platform"
	"golang.org/x/sys/windows"
)

type desktopSession struct {
	done   chan struct{}
	engine *mesh.Engine
}
type desktop struct {
	window                                                                                                *walk.MainWindow
	code                                                                                                  *walk.LineEdit
	token                                                                                                 string
	joinButton, toggleButton, membersButton, frpEntryButton                                               *walk.PushButton
	railPower, railFRP, railVersion, railMore                                                             *walk.PushButton
	powerVisual, compactPowerVisual                                                                       *walk.ImageView
	joinPage, shellPage, powerPage, frpPage, connectedArea, notice                                        *walk.Composite
	frpToggleButton, frpSettingsButton, frpAddButton, frpAddVisitorButton, frpEditButton, frpDeleteButton *walk.PushButton
	frpNewProfileButton, frpApprovalButton, frpImportButton, frpExportButton, frpBatchButton              *walk.PushButton
	frpProfileBox                                                                                         *walk.ComboBox
	frpStatus, frpServer, frpAuthNote                                                                     *walk.Label
	frpRules                                                                                              *walk.TableView
	frpRuleModel                                                                                          *frpRuleTableModel
	frpRows                                                                                               []frpEntryRef
	frpLogs                                                                                               *walk.TextEdit
	frpCatalog                                                                                            *frp.Catalog
	frpProfiles                                                                                           []frp.ProfileInfo
	frpManagers                                                                                           map[string]*frp.Manager
	frpLeaseProviders                                                                                     map[string]*frpLeaseProvider
	frpManagerErrors                                                                                      map[string]error
	frpEndpointRegistry                                                                                   *frp.EndpointRegistry
	frpProfileID                                                                                          string
	frpManager                                                                                            *frp.Manager
	frpConfig                                                                                             frp.Config
	frpSnapshot                                                                                           frp.Snapshot
	frpInitErr                                                                                            error
	frpBusy, frpRefreshing, frpProfileSwitching                                                           bool
	frpStarting, frpStopping                                                                              bool
	frpStartSeq                                                                                           atomic.Uint64
	frpCloseOnce                                                                                          sync.Once
	frpStopDone                                                                                           chan struct{}
	page                                                                                                  int
	offState, offNetwork                                                                                  *walk.Label
	offHint                                                                                               *walk.TextLabel
	deviceName, address, badge, status, networkTitle, memberCount, traffic, noticeTitle                   *walk.Label
	empty, noticeMessage                                                                                  *walk.TextLabel
	peers                                                                                                 *walk.TableView
	peerModel                                                                                             *desktopTableModel
	feedback                                                                                              clientui.Feedback
	identity                                                                                              clientidentity.Identity
	api                                                                                                   *clientapi.Client
	membership                                                                                            clientapi.Membership
	members                                                                                               []clientapi.Device
	settings                                                                                              clientidentity.Settings
	stun                                                                                                  string
	engine                                                                                                *mesh.Engine
	busy, refreshing                                                                                      bool
	powerState                                                                                            int // 0 off, 1 on, 2 transitioning
	ctx                                                                                                   context.Context
	cancel                                                                                                context.CancelFunc
	sessionCancel                                                                                         context.CancelFunc
	session                                                                                               *desktopSession
	appIcon                                                                                               *walk.Icon
	logoImage                                                                                             walk.Image
	connectedAnimToken                                                                                    uint64
	animationsEnabled                                                                                     bool
	railSelection                                                                                         int
	closing                                                                                               atomic.Bool
	explicitExit                                                                                          atomic.Bool
	shutdownOnce                                                                                          sync.Once
	startHidden                                                                                           bool
	settingsDialogOpen                                                                                    bool
	trayIcon                                                                                              *walk.NotifyIcon
	trayShowAction, trayMeshAction, trayFRPAction, traySettingsAction, trayExitAction                     *walk.Action
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
	instance, err := windows.CreateMutex(nil, false, windows.StringToUTF16Ptr("Local\\LANMesh-Desktop"))
	if instance != 0 {
		defer windows.CloseHandle(instance)
	}
	if err != nil {
		walk.MsgBox(nil, appName, "客户端已经运行，请使用已有窗口。", walk.MsgBoxOK|walk.MsgBoxIconInformation)
		return
	}
	identity, err := clientidentity.LoadOrCreate(*identityPath)
	if err != nil {
		walk.MsgBox(nil, "无法读取本机身份", "请使用原来的 Windows 用户运行，或检查本机配置文件权限。", walk.MsgBoxOK|walk.MsgBoxIconError)
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	base := strings.TrimRight(strings.TrimSpace(*server), "/")
	settings = migrateBundledSettings(settings, base)
	token := ""
	if settings.ServerURL == base && strings.HasPrefix(settings.Token, "member_") {
		token = settings.Token
	}
	name, _ := os.Hostname()
	if name == "" {
		name = "我的电脑"
	}
	if settings.DeviceName != "" {
		name = settings.DeviceName
	}
	identity.DisplayName = name
	a := &desktop{identity: identity, api: clientapi.New(base, token), ctx: ctx, cancel: cancel, settings: settings, stun: *stun, startHidden: *startup}
	a.api.Context = ctx
	if token != "" {
		a.membership = clientapi.Membership{Network: clientapi.Network{ID: settings.NetworkID, Name: settings.NetworkName, CIDR: settings.NetworkCIDR}, Member: clientapi.Device{ID: identity.DeviceID.String(), Name: name, VirtualIP: settings.VirtualIP}}
	}
	if err = a.build(); err != nil {
		f := clientui.Explain("打开窗口", err)
		walk.MsgBox(nil, f.Title, f.Message, walk.MsgBoxOK|walk.MsgBoxIconError)
		return
	}
	a.initializeFRP()
	if err = a.setupTray(); err != nil {
		a.settings.CloseToTray = false
		a.showWindow()
		a.showError("创建托盘图标", err)
	}
	if settingsErr == nil {
		if err = a.syncLaunchAtLogin(); err != nil {
			a.showNotice(clientui.Feedback{
				Title:   "登录启动设置未同步",
				Message: "当前用户启动项未能更新，其他设置仍可正常使用。",
				Detail:  clientui.Redact(err.Error(), a.api.Token),
			})
		}
	}
	a.window.Closing().Attach(a.handleWindowClosing)
	if settingsErr != nil {
		a.showError("读取本机配置", settingsErr)
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
	a.settings.ServerURL = a.api.BaseURL
	a.settings.Token = a.api.Token
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
	a.offState.SetText("正在恢复网络")
	a.offHint.SetText("正在读取已保存的成员身份…")
	a.setStatus("正在恢复已加入的网络…")
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
			a.offState.SetText("虚拟网络已关闭")
			if err != nil {
				a.setStatus("暂时无法恢复网络，可稍后点击电源重试。")
				a.showError("恢复网络", err)
				return
			}
			a.membership = m
			a.refreshFRPIdentity()
			a.applyMembership()
			if err := a.remember(); err != nil {
				a.showError("保存成员凭据", err)
			}
			a.setStatus("网络已恢复，点击电源按钮开启转发。")
		})
	}()
}
func (a *desktop) join() {
	if a.busy {
		return
	}
	if a.engine != nil {
		a.showNotice(clientui.Feedback{Title: "请先关闭虚拟网络", Message: "点击电源按钮关闭转发后，再输入新令牌。"})
		return
	}
	if a.hasRunningFRP() {
		a.showNotice(clientui.Feedback{Title: "请先停止内网穿透", Message: "切换入网身份前需要先停止所有受管内网穿透配置。"})
		return
	}
	code := strings.TrimSpace(a.token)
	if code == "" {
		a.showNotice(clientui.Feedback{Title: "请输入入网令牌", Message: "填入软件提供者给你的令牌，然后点击“加入”。"})
		a.code.SetFocus()
		return
	}
	if !validBundledURL(a.api.BaseURL) {
		a.showNotice(clientui.Feedback{Title: "客户端尚未配置连接服务", Message: "请向软件提供者获取配置好服务器地址的客户端。"})
		return
	}
	a.dismissNotice()
	a.busy = true
	a.joinButton.SetEnabled(false)
	a.joinButton.SetText("正在加入…")
	a.setStatus("正在验证令牌…")
	api := *a.api
	api.Token = ""
	go func() {
		m, err := api.Enroll(code, a.identity.RegisterRequest(), a.identity.PrivateKey)
		a.ui(func() {
			a.busy = false
			a.joinButton.SetEnabled(true)
			a.joinButton.SetText("加入网络")
			if err != nil {
				a.showError("加入网络", err)
				return
			}
			a.code.SetText("")
			a.token = ""
			a.api.Token = m.Token
			a.membership = m
			a.members = nil
			a.refreshFRPIdentity()
			a.applyMembership()
			if err := a.remember(); err != nil {
				a.showError("保存成员凭据", err)
			}
			a.setStatus("已加入网络，点击电源开启连接。")
		})
	}()
}
func validBundledURL(base string) bool {
	u, err := url.Parse(base)
	return err == nil && u.Host != "" && (u.Scheme == "https" || u.Scheme == "http") && u.User == nil && u.RawQuery == "" && u.Fragment == ""
}
func (a *desktop) applyMembership() {
	a.address.SetText(a.membership.Member.VirtualIP)
	a.networkTitle.SetText(a.membership.Network.Name)
	a.badge.SetText("已关闭")
	a.badge.SetTextColor(uiMuted)
	a.offNetwork.SetText(a.membership.Network.Name)
	a.setPoweredOff()
}
func (a *desktop) changeCode() {
	if a.busy || a.engine != nil {
		a.showNotice(clientui.Feedback{Title: "请先关闭虚拟网络", Message: "关闭电源后即可输入其他入网令牌。"})
		return
	}
	if a.hasRunningFRP() {
		a.showNotice(clientui.Feedback{Title: "请先停止内网穿透", Message: "切换入网身份前需要先停止所有受管内网穿透配置。"})
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
		a.setStatus("先输入令牌加入网络，再开启电源。")
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
	a.offState.SetText("正在连接网络")
	a.offHint.SetText("正在创建加密通道，请稍候…")
	a.badge.SetText("正在开启…")
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
			engine, err = mesh.Start(ctx, mesh.Options{API: &api, Identity: a.identity, Network: m.Network, Member: m.Member, InterfaceName: "LANMesh", STUNServer: a.stun, RelayOnly: a.settings.RelayOnly})
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
						err = fmt.Errorf("%w；虚拟网卡清理不完整: %v", err, closeErr)
					} else {
						err = fmt.Errorf("虚拟网卡清理不完整: %w", closeErr)
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
					a.showError("开启虚拟网络", err)
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
			a.offState.SetText("虚拟网络已开启")
			a.offHint.SetText("加密转发已运行，可随时停止网络或查看成员。")
			a.offNetwork.SetText(m.Network.Name)
			a.showPage(pagePower)
			a.badge.SetText("●  在线")
			a.badge.SetTextColor(uiBlue)
			if err := a.remember(); err != nil {
				a.showError("保存成员凭据", err)
			}
			a.setStatus("虚拟网络已开启")
			a.refreshMembers()
			a.updateStatus()
			if recovery := engine.RecoveryStatus(); recovery.HasIssues() {
				var detail strings.Builder
				for i, issue := range recovery.Issues {
					if i >= 8 {
						fmt.Fprintf(&detail, "…另有 %d 项\n", len(recovery.Issues)-i)
						break
					}
					fmt.Fprintf(&detail, "%s · %s/%s: %s\n", issue.Resource.Type, issue.Resource.Name, issue.Resource.Prefix, issue.Error)
				}
				a.showNotice(clientui.Feedback{
					Title:   "发现历史 Mesh 资源残留",
					Message: fmt.Sprintf("已恢复 %d 项，失败 %d 项，无法证明归属 %d 项。无法证明归属的资源不会被自动删除，请查看诊断后人工处理。", recovery.Recovered, recovery.Failed, recovery.Unproven),
					Detail:  clientui.Redact(strings.TrimSpace(detail.String()), a.api.Token),
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
	a.offState.SetText("正在关闭网络")
	a.offHint.SetText("正在释放虚拟网卡和路由，请稍候…")
	a.badge.SetText("正在关闭…")
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
				a.setStatus("虚拟网络已关闭，但本机资源清理不完整。")
				a.showNotice(clientui.Feedback{
					Title:   "虚拟网络已关闭，但资源清理不完整",
					Message: "虚拟网卡、路由或防火墙规则可能仍有残留。请勿继续依赖该网络，重启客户端后可重试幂等清理。",
					Detail:  clientui.Redact(closeErr.Error(), a.api.Token),
				})
				return
			}
			a.setStatus("转发已关闭，虚拟网卡和路由已释放。")
			if err != nil {
				a.showNotice(clientui.Feedback{Title: "本机转发已关闭", Message: "成员离线状态暂未同步，服务器会在心跳超时后标记离线。", Detail: clientui.Redact(err.Error(), a.api.Token)})
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
			name := "当前穿透配置"
			if cfg, ok := manager.Config(); ok && cfg.Profile.Name != "" {
				name = cfg.Profile.Name
			}
			return fmt.Errorf("穿透配置“%s”与待启动组网冲突: %w", name, err)
		}
	}
	return nil
}
func (a *desktop) setPoweredOff() {
	a.powerState = 0
	a.updatePowerButtons()
	a.offState.SetText("虚拟网络已关闭")
	a.offHint.SetText("点击圆形按钮或“启动网络”，开启设备间的加密转发。")
	a.offNetwork.SetText(a.membership.Network.Name)
	a.badge.SetText("已关闭")
	a.badge.SetTextColor(uiMuted)
	a.peers.SetVisible(false)
	a.empty.SetText("虚拟网络已关闭\r\n点击电源按钮，开启设备间的加密转发。")
	a.empty.SetVisible(true)
	a.traffic.SetText("转发已关闭")
	a.memberCount.SetText("转发已关闭")
	a.showPage(pagePower)
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
		a.ui(func() {
			a.refreshing = false
			if a.engine == nil || core.NetworkID(a.membership.Network.ID) != nid {
				return
			}
			if err != nil {
				a.setStatus("成员列表暂时无法更新，正在等待下次刷新。")
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
			a.showError("运行虚拟网络", fmt.Errorf("%s", s.LastError))
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
		name, state, path, delay := member.Name, "离线", "—", "—"
		if member.ID == a.identity.DeviceID.String() {
			name += "（本机）"
			state = "在线"
			path = "本机"
			online++
		} else if member.Online {
			state = "连接中"
			p, ok := peers[member.ID]
			if ok {
				path = map[string]string{"direct UDP": "直连", "relay TCP/TLS": "中继", "checking": "探测中"}[p.Path]
				if p.Reachable {
					state = "在线"
					delay = fmt.Sprintf("%.0f ms", float64(p.RTT)/float64(time.Millisecond))
					online++
				}
			}
		}
		rows = append(rows, []string{name, member.VirtualIP, state, path, delay})
	}
	a.peerModel.setRows(rows)
	a.peers.SetVisible(len(rows) > 0)
	a.empty.SetVisible(len(rows) == 0)
	a.empty.SetText("网络已开启\r\n正在获取加入成员…")
	a.memberCount.SetText(fmt.Sprintf("%d / %d 在线", online, len(rows)))
	a.traffic.SetText(fmt.Sprintf("↑ %s    ↓ %s", formatTraffic(s.Sent), formatTraffic(s.Received)))
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
		a.showNotice(clientui.Feedback{Title: "请先关闭电源", Message: "关闭转发后可退出当前网络。"})
		return
	}
	if a.hasRunningFRP() {
		a.showNotice(clientui.Feedback{Title: "请先停止内网穿透", Message: "退出网络前需要先停止所有受管内网穿透配置。"})
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
				a.showError("退出网络", err)
				return
			}
			a.membership = clientapi.Membership{}
			a.api.Token = ""
			a.members = nil
			a.code.SetText("")
			a.token = ""
			a.address.SetText("尚未分配 IP")
			a.badge.SetText("未加入网络")
			a.networkTitle.SetText("私人网络")
			a.memberCount.SetText("")
			a.showPage(pageJoin)
			a.empty.SetText("输入令牌，即可加入你的私人网络。")
			a.dismissNotice()
			if err := a.remember(); err != nil {
				a.showError("保存本机配置", err)
			}
			a.setStatus("已退出网络")
		})
	}()
}
func (a *desktop) diagnose() {
	var meshChecks []clientapi.DiagnosticCheck
	if a.engine != nil {
		meshChecks = a.engine.Diagnostics()
	}
	frpSources := a.frpDiagnosticSources()
	if a.engine == nil && len(frpSources) == 0 {
		a.showNotice(clientui.Feedback{Title: "暂无可诊断的连接", Message: "开启虚拟网络或配置内网穿透后，再生成连接诊断。"})
		return
	}
	api := clientapi.Client{}
	if a.api != nil {
		api = *a.api
	}
	nid := core.NetworkID(a.membership.Network.ID)
	deviceID := a.identity.DeviceID
	secrets := []string{api.Token}
	go func() {
		ctx := a.ctx
		if ctx == nil {
			ctx = context.Background()
		}
		frpReport, frpChecks := buildFRPDiagnosticExport(ctx, frpSources, secrets, time.Now().UTC())
		checks := append([]clientapi.DiagnosticCheck(nil), meshChecks...)
		checks = append(checks, frpChecks...)
		export := diagnosticExport{
			SchemaVersion: diagnosticSchemaVersion,
			AppVersion:    appVersion,
			GeneratedAt:   time.Now().UTC(),
			Checks:        checks,
			FRP:           frpReport,
		}
		identityPath, err := clientidentity.DefaultPath()
		var jsonPath, textPath string
		if err == nil {
			jsonPath, textPath, err = writeDiagnosticExport(filepath.Dir(identityPath), export, secrets)
		}
		var uploadErr error
		if err == nil && api.Token != "" && nid != "" && deviceID != "" {
			uploadErr = api.UploadDiagnostics(nid, deviceID, checks)
		}
		detail := export.Text() + "\r\nJSON: " + jsonPath + "\r\n文本: " + textPath
		a.ui(func() {
			if err != nil {
				a.showError("保存诊断", err)
				return
			}
			message := "报告已保存为 JSON 和文本"
			switch {
			case uploadErr != nil:
				message = "报告已保存，但同步失败：" + clientui.Redact(uploadErr.Error(), secrets...)
			case api.Token == "":
				message += "（当前未登录，未上传）"
			default:
				message += "并同步至私人服务器。"
			}
			a.showTextDialog("连接诊断", message, clientui.Redact(detail, secrets...))
		})
	}()
}
func runUITest(path string) {
	if err := checkDesktopUI(); err != nil {
		os.WriteFile(path, []byte("FAIL: "+err.Error()), 0600)
		os.Exit(1)
	}
	os.WriteFile(path, []byte("PASS: integrated Mesh workspace, FRP page, tray actions, close policy, version control, power-off transition, member/rule tables and antialiased drawing calls; no network or adapter created\n"), 0600)
}
func runAdapterTest(path string) {
	os.WriteFile(path, []byte("RUNNING\n"), 0600)
	adapter, err := platform.OpenTunnel("LANMesh-Test", netip.MustParsePrefix("10.254.253.1/30"), mesh.MTU)
	report := ""
	if err != nil {
		report = "FAIL: " + err.Error()
	} else {
		name, _ := adapter.Name()
		_, lookErr := net.InterfaceByName(name)
		closeErr := adapter.Close()
		if lookErr != nil || closeErr != nil {
			report = fmt.Sprintf("FAIL: lookup=%v close=%v", lookErr, closeErr)
		} else {
			report = "PASS: created, configured and released " + name
		}
	}
	os.WriteFile(path, []byte(report+"\n"), 0600)
	if strings.HasPrefix(report, "FAIL") {
		os.Exit(1)
	}
}
