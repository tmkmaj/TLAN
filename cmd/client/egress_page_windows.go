//go:build windows

package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
	"github.com/private-radminlan/lanmesh/internal/clientidentity"
	"github.com/private-radminlan/lanmesh/internal/clientui"
	"github.com/private-radminlan/lanmesh/internal/egress"
)

const (
	egressDefaultProxy = "127.0.0.1:1080"
	egressProfileID    = "egress-default"
)

// egressController owns the explicit-proxy helper process. It never touches the
// mesh or FRP lifecycle; stopping egress leaves both untouched.
type egressController struct {
	mu       sync.Mutex
	store    *egress.Store
	profile  egress.EgressProfile
	cmd      *exec.Cmd
	ready    bool
	lastErr  string
	listenOn string
}

func newEgressController() *egressController {
	controller := &egressController{}
	identityPath, err := clientidentity.DefaultPath()
	if err != nil {
		return controller
	}
	store, err := egress.NewStore(filepath.Dir(identityPath))
	if err != nil {
		return controller
	}
	controller.store = store
	return controller
}

func (c *egressController) available() bool { return c != nil && c.store != nil }

func (c *egressController) defaultProfile() egress.EgressProfile {
	return egress.EgressProfile{
		ID:      egressProfileID,
		Name:    "应用流量转发",
		Version: egress.SchemaVersion,
		Server: egress.EgressServer{
			Port:          7443,
			CredentialRef: "egress-credential",
			PolicyVersion: 1,
			ProxyListen:   egressDefaultProxy,
		},
		Policy: egress.EgressPolicy{
			IPv6Policy: egress.IPv6PolicyBlock,
			DNSPolicy:  egress.DNSPolicyRemote,
			KillSwitch: true,
		},
		DesiredState: egress.DesiredStopped,
	}
}

func (c *egressController) current() egress.EgressProfile {
	if c.profile.ID == "" {
		c.profile = c.defaultProfile()
	}
	return c.profile
}

func (c *egressController) load() error {
	if !c.available() {
		return nil
	}
	document, err := c.store.Load()
	if err != nil {
		return err
	}
	if len(document.Profiles) > 0 {
		c.profile = document.Profiles[0]
	}
	return nil
}

func (c *egressController) active() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cmd != nil
}

func (c *egressController) status() (bool, string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ready, c.lastErr
}

func (c *egressController) setProfile(profile egress.EgressProfile) error {
	if c.active() {
		return fmt.Errorf("请先停止应用流量转发再修改配置")
	}
	if err := egress.ValidateProfile(profile); err != nil {
		c.profile = profile
		return err
	}
	if _, err := c.store.Upsert(profile); err != nil {
		return err
	}
	c.profile = profile
	return nil
}

func (c *egressController) helperPath() (string, error) {
	executable, err := os.Executable()
	if err != nil {
		return "", err
	}
	path := filepath.Join(filepath.Dir(executable), "runtime", "egress", "egress-helper.exe")
	if _, err := os.Stat(path); err != nil {
		return "", fmt.Errorf("未找到内置转发 helper：%s", path)
	}
	return path, nil
}

func (c *egressController) start(ctx context.Context) error {
	c.mu.Lock()
	if c.cmd != nil {
		c.mu.Unlock()
		return fmt.Errorf("应用流量转发已在运行")
	}
	c.mu.Unlock()

	profile := c.current()
	if err := egress.ValidateProfile(profile); err != nil {
		return err
	}
	enabled := make([]egress.AppRule, 0, len(profile.Rules))
	for _, rule := range profile.Rules {
		if rule.Enabled {
			enabled = append(enabled, rule)
		}
	}
	if len(enabled) != 1 {
		return fmt.Errorf("显式代理模式一次只支持一条已启用规则，请先只保留一条")
	}
	if strings.TrimSpace(profile.Server.LeaseID) == "" {
		return fmt.Errorf("请在服务器设置中填写租约 ID")
	}
	if strings.TrimSpace(profile.Server.CapabilityFile) == "" {
		return fmt.Errorf("请在服务器设置中选择 capability 文件")
	}
	for _, path := range []string{profile.Server.CapabilityFile, profile.Server.CredentialRef} {
		if strings.TrimSpace(path) == "" {
			continue
		}
		if _, err := os.Stat(path); err != nil {
			return fmt.Errorf("文件不可用：%s", path)
		}
	}
	helper, err := c.helperPath()
	if err != nil {
		return err
	}
	listen := strings.TrimSpace(profile.Server.ProxyListen)
	if listen == "" {
		listen = egressDefaultProxy
	}
	args := []string{
		"-listen", listen,
		"-server", net.JoinHostPort(profile.Server.Endpoint, strconv.Itoa(profile.Server.Port)),
		"-servername", profile.Server.ServerName,
		"-ca", profile.Server.CredentialRef,
		"-profile", profile.ID,
		"-rule", enabled[0].ID,
		"-device", c.deviceID(),
		"-lease", profile.Server.LeaseID,
		"-policy-version", strconv.Itoa(profile.Server.PolicyVersion),
		"-capability-file", profile.Server.CapabilityFile,
	}
	command := exec.CommandContext(ctx, helper, args...)
	command.Dir = filepath.Dir(helper)
	command.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	if err := command.Start(); err != nil {
		return fmt.Errorf("启动转发 helper 失败: %w", err)
	}
	c.mu.Lock()
	c.cmd = command
	c.ready = false
	c.lastErr = ""
	c.listenOn = listen
	c.mu.Unlock()

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		conn, dialErr := net.DialTimeout("tcp", listen, 300*time.Millisecond)
		if dialErr == nil {
			_ = conn.Close()
			c.mu.Lock()
			if c.cmd == command {
				c.ready = true
			}
			c.mu.Unlock()
			go c.watch(command)
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	_ = command.Process.Kill()
	_, _ = command.Process.Wait()
	c.mu.Lock()
	if c.cmd == command {
		c.cmd = nil
		c.ready = false
		c.lastErr = "helper 未在 10 秒内开始监听代理端口"
	}
	message := c.lastErr
	c.mu.Unlock()
	return fmt.Errorf("%s", message)
}

func (c *egressController) watch(command *exec.Cmd) {
	err := command.Wait()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cmd != command {
		return
	}
	c.cmd = nil
	c.ready = false
	if err != nil {
		c.lastErr = err.Error()
	}
}

func (c *egressController) stop(context.Context) error {
	c.mu.Lock()
	command := c.cmd
	c.cmd = nil
	c.ready = false
	c.mu.Unlock()
	if command == nil || command.Process == nil {
		return nil
	}
	if err := command.Process.Kill(); err != nil && !strings.Contains(err.Error(), "process already finished") {
		return err
	}
	_, _ = command.Process.Wait()
	return nil
}

func (c *egressController) deviceID() string {
	path, err := clientidentity.DefaultPath()
	if err != nil {
		return "dev-unknown"
	}
	identity, err := clientidentity.LoadOrCreate(path)
	if err != nil {
		return "dev-unknown"
	}
	return identity.DeviceID.String()
}

// egressPanel renders the third module page.
type egressPanel struct {
	desktop    *desktop
	controller *egressController

	page *walk.Composite
	rail *walk.PushButton

	toggle, serverButton, addRule, editRule, deleteRule, copyProxy *walk.PushButton
	state, serverLabel, proxyLabel, modeLabel                      *walk.Label
	message                                                        *walk.TextLabel
	rules                                                          *walk.TableView
	model                                                          *desktopTableModel
	empty                                                          *walk.TextLabel
}

func newEgressPanel(a *desktop) *egressPanel {
	return &egressPanel{desktop: a, controller: newEgressController(), model: &desktopTableModel{}}
}

func (p *egressPanel) view() Composite {
	banner := roundView{Composite: Composite{MinSize: Size{Width: 800}, Background: SolidColorBrush{Color: uiBlueSoft}, Layout: HBox{Margins: Margins{Left: 16, Top: 10, Right: 16, Bottom: 10}, Spacing: 10}, Children: []Widget{
		Label{Text: "i", TextColor: uiWhite, Background: SolidColorBrush{Color: uiBlue}, Font: Font{Bold: true, PointSize: 9}, TextAlignment: AlignCenter, MinSize: Size{Width: 20, Height: 20}, MaxSize: Size{Width: 20, Height: 20}, NoPrefix: true},
		Label{AssignTo: &p.modeLabel, Text: "当前为显式代理模式：应用需手动设置 SOCKS5 代理；透明按进程转发需要签名的 WFP 组件，尚未启用。", TextColor: uiInk, NoPrefix: true, StretchFactor: 1},
	}}, fill: uiBlueSoft, radius: 8}
	banner.Row = 0

	header := pageHeader("应用流量转发", "⇄",
		actionButton(&p.serverButton, "服务器设置", false, 96, p.showServerDialog),
		actionButton(&p.toggle, "启动转发", true, 120, p.toggleTunnel),
	)
	header.Row = 1

	statusCard := roundView{Composite: Composite{MinSize: Size{Width: 800}, Background: SolidColorBrush{Color: uiWhite}, Layout: HBox{Margins: Margins{Left: 20, Top: 14, Right: 20, Bottom: 14}, Spacing: 24}, Children: []Widget{
		Composite{MinSize: Size{Width: 130}, Background: SolidColorBrush{Color: uiWhite}, Layout: VBox{MarginsZero: true, Spacing: 2}, Children: []Widget{
			caption("转发状态"),
			Label{AssignTo: &p.state, Text: "已停止", TextColor: uiInk, Font: Font{PointSize: 14, Bold: true}, NoPrefix: true},
		}},
		Composite{StretchFactor: 1, Background: SolidColorBrush{Color: uiWhite}, Layout: VBox{MarginsZero: true, Spacing: 2}, Children: []Widget{
			caption("出口服务器"),
			Label{AssignTo: &p.serverLabel, Text: "未配置", TextColor: uiInk, NoPrefix: true, EllipsisMode: EllipsisEnd},
			caption("本地代理地址"),
			Label{AssignTo: &p.proxyLabel, Text: egressDefaultProxy, TextColor: uiBlue, NoPrefix: true},
		}},
		actionButton(&p.copyProxy, "复制代理地址", false, 110, p.copyProxyAddress),
	}}, fill: uiWhite, radius: 12, border: borderColor(uiBorder)}
	statusCard.Row = 2

	message := TextLabel{AssignTo: &p.message, Text: "", TextColor: uiMuted, MinSize: Size{Width: 760}, MaxSize: Size{Height: 40}}
	message.Row = 3

	rulesCard := roundView{Composite: Composite{MinSize: Size{Width: 800}, Background: SolidColorBrush{Color: uiWhite}, StretchFactor: 1, Layout: VBox{Margins: Margins{Left: 16, Top: 12, Right: 16, Bottom: 12}, Spacing: 8}, Children: []Widget{
		Composite{Background: SolidColorBrush{Color: uiWhite}, Layout: HBox{MarginsZero: true, Spacing: 8}, Children: []Widget{
			Label{Text: "应用规则", TextColor: uiInk, Font: Font{PointSize: 11, Bold: true}, NoPrefix: true},
			HSpacer{},
			actionButton(&p.addRule, "添加应用", true, 92, func() { p.showRuleDialog(-1) }),
			actionButton(&p.editRule, "编辑", false, 66, p.editSelectedRule),
			actionButton(&p.deleteRule, "删除", false, 66, p.deleteSelectedRule),
		}},
		TableView{AssignTo: &p.rules, Visible: false, Model: p.model, Background: SolidColorBrush{Color: uiWhite}, StretchFactor: 1, MinSize: Size{Height: 140}, CustomRowHeight: 30, CustomHeaderHeight: 28, LastColumnStretched: true, SelectionHiddenWithoutFocus: true, AlternatingRowBG: true, Columns: []TableViewColumn{
			{Title: "名称", Width: 200}, {Title: "应用", Width: 300}, {Title: "子进程", Width: 80}, {Title: "状态", Width: 100},
		}},
		TextLabel{AssignTo: &p.empty, Text: "还没有应用规则。点击“添加应用”选择要转发的 exe。", TextColor: uiMuted, MinSize: Size{Width: 360, Height: 140}, StretchFactor: 1, TextAlignment: AlignHCenterVCenter},
		VSpacer{StretchFactor: 1},
	}}, fill: uiWhite, radius: 12, border: borderColor(uiBorder)}
	rulesCard.Composite.StretchFactor = 1
	rulesCard.Row = 4

	return Composite{AssignTo: &p.page, Visible: false, StretchFactor: 1, Background: SolidColorBrush{Color: uiBackground}, Layout: VBox{Margins: Margins{Left: 20, Top: 14, Right: 20, Bottom: 16}, Spacing: 10, Alignment: AlignHNearVNear}, Children: []Widget{
		banner, header, statusCard, message, rulesCard,
	}}
}

func (p *egressPanel) refresh() {
	if p == nil || p.desktop == nil {
		return
	}
	controller := p.controller
	if controller == nil || !controller.available() {
		p.state.SetText("不可用")
		p.message.SetText("无法定位本机配置目录，请检查当前用户的配置文件夹权限。")
		return
	}
	running, lastErr := controller.status()
	active := controller.active()
	profile := controller.current()

	switch {
	case running:
		p.state.SetText("运行中")
		p.state.SetTextColor(uiBlue)
	case active:
		p.state.SetText("启动中")
		p.state.SetTextColor(uiMuted)
	default:
		p.state.SetText("已停止")
		p.state.SetTextColor(uiMuted)
	}
	if running {
		p.toggle.SetText("停止转发")
	} else {
		p.toggle.SetText("启动转发")
	}
	if strings.TrimSpace(profile.Server.Endpoint) != "" {
		p.serverLabel.SetText(fmt.Sprintf("%s:%d（TLS：%s）", profile.Server.Endpoint, profile.Server.Port, profile.Server.ServerName))
	} else {
		p.serverLabel.SetText("未配置")
	}
	listen := strings.TrimSpace(profile.Server.ProxyListen)
	if listen == "" {
		listen = egressDefaultProxy
	}
	p.proxyLabel.SetText(listen)

	if lastErr != "" {
		p.message.SetText("上次错误：" + lastErr)
	} else if !running && len(profile.Rules) == 0 {
		p.message.SetText("先添加应用规则并完成服务器设置，再启动转发。")
	} else if running {
		p.message.SetText("显式代理已启动。将目标应用的 SOCKS5 代理设置为上方地址（不支持透明捕获）。")
	} else {
		p.message.SetText("配置就绪后点击“启动转发”。运行中不能修改配置。")
	}

	rows := make([][]string, 0, len(profile.Rules))
	for _, rule := range profile.Rules {
		status := "未启用"
		if rule.Enabled {
			status = "已停止"
			if running {
				status = "运行中"
			}
		}
		children := "否"
		if rule.IncludeChildren {
			children = "是"
		}
		rows = append(rows, []string{rule.Name, rule.ExePath, children, status})
	}
	p.model.setRows(rows)
	p.rules.SetVisible(len(rows) > 0)
	p.empty.SetVisible(len(rows) == 0)

	editable := !active
	p.serverButton.SetEnabled(editable)
	p.addRule.SetEnabled(editable)
	index := -1
	if p.rules != nil {
		index = p.rules.CurrentIndex()
	}
	selected := index >= 0 && index < len(profile.Rules)
	p.editRule.SetEnabled(editable && selected)
	p.deleteRule.SetEnabled(editable && selected)
}

func (p *egressPanel) toggleTunnel() {
	if p.controller == nil || !p.controller.available() {
		return
	}
	if p.controller.active() {
		go func() {
			_ = p.controller.stop(p.desktop.ctx)
			p.desktop.ui(p.refresh)
		}()
		return
	}
	go func() {
		if err := p.controller.start(p.desktop.ctx); err != nil {
			p.desktop.ui(func() {
				p.desktop.showError("启动应用流量转发", err)
				p.refresh()
			})
			return
		}
		p.desktop.ui(p.refresh)
	}()
}

func (p *egressPanel) copyProxyAddress() {
	listen := strings.TrimSpace(p.controller.current().Server.ProxyListen)
	if listen == "" {
		listen = egressDefaultProxy
	}
	if err := walk.Clipboard().SetText(listen); err != nil {
		p.desktop.showError("复制代理地址", err)
		return
	}
	p.desktop.showNotice(clientui.Feedback{Title: "代理地址已复制", Message: "把目标应用的 SOCKS5 代理设置为 " + listen + "。"})
}

func (p *egressPanel) editSelectedRule() {
	if p.rules == nil {
		return
	}
	p.showRuleDialog(p.rules.CurrentIndex())
}

func (p *egressPanel) deleteSelectedRule() {
	index := -1
	if p.rules != nil {
		index = p.rules.CurrentIndex()
	}
	profile := p.controller.current()
	if index < 0 || index >= len(profile.Rules) {
		return
	}
	if walk.MsgBox(p.desktop.window, "删除规则", "确定删除“"+profile.Rules[index].Name+"”吗？", walk.MsgBoxYesNo|walk.MsgBoxIconQuestion) != walk.DlgCmdYes {
		return
	}
	profile.Rules = append(append([]egress.AppRule{}, profile.Rules[:index]...), profile.Rules[index+1:]...)
	if err := p.controller.setProfile(profile); err != nil {
		p.desktop.showError("保存应用规则", err)
	}
	p.refresh()
}

func (p *egressPanel) showServerDialog() {
	profile := p.controller.current()
	var dlg *walk.Dialog
	var endpoint, serverName, caPath, leaseID, capabilityFile, proxyListen *walk.LineEdit
	var portEdit, policyEdit *walk.NumberEdit
	var cancel, save *walk.PushButton
	port := float64(profile.Server.Port)
	if port < 1 {
		port = 7443
	}
	policy := float64(profile.Server.PolicyVersion)
	if policy < 1 {
		policy = 1
	}
	listen := profile.Server.ProxyListen
	if listen == "" {
		listen = egressDefaultProxy
	}
	doSave := func() {
		updated := p.controller.current()
		updated.Server.Endpoint = strings.TrimSpace(endpoint.Text())
		updated.Server.Port = int(portEdit.Value())
		updated.Server.ServerName = strings.TrimSpace(serverName.Text())
		updated.Server.CredentialRef = strings.TrimSpace(caPath.Text())
		updated.Server.LeaseID = strings.TrimSpace(leaseID.Text())
		updated.Server.CapabilityFile = strings.TrimSpace(capabilityFile.Text())
		updated.Server.PolicyVersion = int(policyEdit.Value())
		updated.Server.ProxyListen = strings.TrimSpace(proxyListen.Text())
		if hosted, _, err := net.SplitHostPort(updated.Server.ProxyListen); err != nil || !isLoopbackHost(hosted) {
			walk.MsgBox(dlg, "服务器设置", "本地代理地址必须是 127.0.0.1 或 ::1 的回环地址。", walk.MsgBoxOK|walk.MsgBoxIconWarning)
			return
		}
		if err := p.controller.setProfile(updated); err != nil {
			walk.MsgBox(dlg, "服务器设置", err.Error(), walk.MsgBoxOK|walk.MsgBoxIconWarning)
			return
		}
		p.refresh()
		dlg.Accept()
	}
	err := (Dialog{
		AssignTo:   &dlg,
		Title:      "应用流量转发 - 服务器设置",
		Icon:       p.desktop.appIcon,
		Size:       Size{Width: 560, Height: 560},
		Font:       Font{Family: "Microsoft YaHei UI", PointSize: 10},
		Background: SolidColorBrush{Color: uiWhite},
		Layout:     VBox{Margins: Margins{Left: 24, Top: 20, Right: 24, Bottom: 18}, Spacing: 5},
		Children: []Widget{
			caption("Egress Gateway 地址（域名或 IP）"),
			LineEdit{AssignTo: &endpoint, Text: profile.Server.Endpoint},
			caption("TLS 端口"),
			NumberEdit{AssignTo: &portEdit, Value: port, MinValue: 1, MaxValue: 65535},
			caption("TLS 服务器名称（证书中的域名）"),
			LineEdit{AssignTo: &serverName, Text: profile.Server.ServerName},
			caption("服务器 CA 文件（PEM）"),
			LineEdit{AssignTo: &caPath, Text: profile.Server.CredentialRef},
			caption("租约 ID"),
			LineEdit{AssignTo: &leaseID, Text: profile.Server.LeaseID},
			caption("Capability 文件（0600，一次性）"),
			LineEdit{AssignTo: &capabilityFile, Text: profile.Server.CapabilityFile},
			caption("策略版本"),
			NumberEdit{AssignTo: &policyEdit, Value: policy, MinValue: 1, MaxValue: 1000000},
			caption("本地 SOCKS5 代理地址（仅回环）"),
			LineEdit{AssignTo: &proxyListen, Text: listen},
			VSpacer{StretchFactor: 1},
			Composite{Layout: HBox{MarginsZero: true, Spacing: 10}, Children: []Widget{
				HSpacer{},
				actionButton(&cancel, "取消", false, 88, func() { dlg.Cancel() }),
				actionButton(&save, "保存", true, 96, doSave),
			}},
		},
	}).Create(p.desktop.window)
	_ = cancel
	_ = save
	if err != nil {
		p.desktop.showError("打开服务器设置", err)
		return
	}
	defer dlg.Dispose()
	dlg.Run()
}

func (p *egressPanel) showRuleDialog(index int) {
	profile := p.controller.current()
	isNew := index < 0
	var rule egress.AppRule
	if isNew {
		rule = egress.AppRule{ID: nextEgressRuleID(profile.Rules), Enabled: true, Protocols: []egress.Protocol{egress.ProtocolTCP, egress.ProtocolUDP}}
	} else {
		if index >= len(profile.Rules) {
			return
		}
		rule = profile.Rules[index]
	}
	var dlg *walk.Dialog
	var nameEdit, exeEdit *walk.LineEdit
	var children, enabled *walk.CheckBox
	var tcpCheck, udpCheck *walk.CheckBox
	var cancel, save *walk.PushButton
	pickExe := func() {
		dialog := new(walk.FileDialog)
		dialog.Title = "选择要转发的应用"
		dialog.Filter = "可执行文件 (*.exe)|*.exe|所有文件 (*.*)|*.*"
		accepted, err := dialog.ShowOpen(dlg)
		if err != nil {
			p.desktop.showError("选择应用", err)
			return
		}
		if accepted {
			_ = exeEdit.SetText(dialog.FilePath)
		}
	}
	doSave := func() {
		updated := rule
		updated.Name = strings.TrimSpace(nameEdit.Text())
		updated.ExePath = strings.TrimSpace(exeEdit.Text())
		updated.IncludeChildren = children.CheckState() == walk.CheckChecked
		updated.Enabled = enabled.CheckState() == walk.CheckChecked
		protocols := []egress.Protocol{}
		if tcpCheck.CheckState() == walk.CheckChecked {
			protocols = append(protocols, egress.ProtocolTCP)
		}
		if udpCheck.CheckState() == walk.CheckChecked {
			protocols = append(protocols, egress.ProtocolUDP)
		}
		updated.Protocols = protocols
		if updated.Name == "" {
			updated.Name = filepath.Base(updated.ExePath)
		}
		rules := append([]egress.AppRule{}, profile.Rules...)
		if isNew {
			rules = append(rules, updated)
		} else {
			rules[index] = updated
		}
		next := p.controller.current()
		next.Rules = rules
		if err := egress.ValidateRule(updated); err != nil {
			walk.MsgBox(dlg, "应用规则", err.Error(), walk.MsgBoxOK|walk.MsgBoxIconWarning)
			return
		}
		if err := p.controller.setProfile(next); err != nil {
			walk.MsgBox(dlg, "应用规则", err.Error(), walk.MsgBoxOK|walk.MsgBoxIconWarning)
			return
		}
		p.refresh()
		dlg.Accept()
	}
	hasProtocol := func(protocol egress.Protocol) bool {
		for _, value := range rule.Protocols {
			if value == protocol {
				return true
			}
		}
		return false
	}
	err := (Dialog{
		AssignTo:   &dlg,
		Title:      map[bool]string{true: "添加应用规则", false: "编辑应用规则"}[isNew],
		Icon:       p.desktop.appIcon,
		Size:       Size{Width: 560, Height: 460},
		Font:       Font{Family: "Microsoft YaHei UI", PointSize: 10},
		Background: SolidColorBrush{Color: uiWhite},
		Layout:     VBox{Margins: Margins{Left: 24, Top: 20, Right: 24, Bottom: 18}, Spacing: 5},
		Children: []Widget{
			caption("规则名称"),
			LineEdit{AssignTo: &nameEdit, Text: rule.Name},
			caption("应用可执行文件"),
			Composite{Layout: HBox{MarginsZero: true, Spacing: 8}, Children: []Widget{
				LineEdit{AssignTo: &exeEdit, Text: rule.ExePath, StretchFactor: 1},
				actionButton(nil, "浏览…", false, 76, pickExe),
			}},
			CheckBox{AssignTo: &children, Text: "包含子进程（透明模式生效；显式代理模式仅记录）", Checked: rule.IncludeChildren},
			CheckBox{AssignTo: &enabled, Text: "启用这条规则", Checked: rule.Enabled},
			caption("协议（显式代理模式下由应用自行选择 TCP/UDP）"),
			Composite{Layout: HBox{MarginsZero: true, Spacing: 16}, Children: []Widget{
				CheckBox{AssignTo: &tcpCheck, Text: "TCP", Checked: len(rule.Protocols) == 0 || hasProtocol(egress.ProtocolTCP)},
				CheckBox{AssignTo: &udpCheck, Text: "UDP", Checked: len(rule.Protocols) == 0 || hasProtocol(egress.ProtocolUDP)},
			}},
			VSpacer{StretchFactor: 1},
			Composite{Layout: HBox{MarginsZero: true, Spacing: 10}, Children: []Widget{
				HSpacer{},
				actionButton(&cancel, "取消", false, 88, func() { dlg.Cancel() }),
				actionButton(&save, "保存", true, 96, doSave),
			}},
		},
	}).Create(p.desktop.window)
	_ = cancel
	_ = save
	if err != nil {
		p.desktop.showError("打开应用规则", err)
		return
	}
	defer dlg.Dispose()
	dlg.Run()
}

func isLoopbackHost(host string) bool {
	host = strings.Trim(host, "[]")
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func nextEgressRuleID(rules []egress.AppRule) string {
	used := map[string]bool{}
	for _, rule := range rules {
		used[rule.ID] = true
	}
	for index := 1; index <= len(rules)+1; index++ {
		candidate := "app-" + strconv.Itoa(index)
		if !used[candidate] {
			return candidate
		}
	}
	return "app-1"
}
