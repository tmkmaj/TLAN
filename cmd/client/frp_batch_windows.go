//go:build windows

package main

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
	frpctl "github.com/private-radminlan/lanmesh/internal/frp"
)

func (a *desktop) showFRPBatchRules() {
	if a.frpManager == nil || a.frpBusy {
		return
	}
	var dlg *walk.Dialog
	var targetBox, protocolBox *walk.ComboBox
	var targetHost, localStart, remoteStart, countEdit, namePrefix *walk.LineEdit
	var saveButton, closeButton *walk.PushButton
	setFields := func() {
		if targetHost == nil || targetBox == nil {
			return
		}
		lan := targetBox.CurrentIndex() == 1
		targetHost.SetEnabled(lan)
		if !lan {
			targetHost.SetText("127.0.0.1")
		}
	}
	err := (Dialog{
		AssignTo: &dlg, Title: "批量添加穿透端口", Icon: a.appIcon,
		Size: Size{Width: 600, Height: 520}, MinSize: Size{Width: 540, Height: 480},
		Font: Font{Family: "Microsoft YaHei UI", PointSize: 10}, Background: SolidColorBrush{Color: uiWhite},
		Layout:       VBox{Margins: Margins{Left: 28, Top: 24, Right: 28, Bottom: 22}, Spacing: 12},
		CancelButton: &closeButton, DefaultButton: &saveButton,
		Children: []Widget{
			heading("批量添加 TCP/UDP 端口"),
			TextLabel{Text: "按连续端口生成独立规则，每条规则仍经过完整目标策略和服务器端口授权校验。", TextColor: uiMuted, MinSize: Size{Width: 520}},
			Composite{Layout: HBox{MarginsZero: true, Spacing: 10}, Children: []Widget{
				Label{Text: "目标类型", MinSize: Size{Width: 78}}, ComboBox{AssignTo: &targetBox, Model: []string{"本机回环", "物理 LAN IPv4"}, CurrentIndex: 0, MinSize: Size{Width: 160}, OnCurrentIndexChanged: setFields},
				Label{Text: "目标地址", MinSize: Size{Width: 78}}, LineEdit{AssignTo: &targetHost, Text: "127.0.0.1", MinSize: Size{Width: 180}},
			}},
			Composite{Layout: HBox{MarginsZero: true, Spacing: 10}, Children: []Widget{
				Label{Text: "协议", MinSize: Size{Width: 78}}, ComboBox{AssignTo: &protocolBox, Model: []string{"TCP", "UDP", "TCP + UDP"}, CurrentIndex: 0, MinSize: Size{Width: 160}},
				Label{Text: "规则名称", MinSize: Size{Width: 78}}, LineEdit{AssignTo: &namePrefix, Text: "批量端口", MinSize: Size{Width: 180}},
			}},
			Composite{Layout: HBox{MarginsZero: true, Spacing: 10}, Children: []Widget{
				Label{Text: "本地起始端口", MinSize: Size{Width: 100}}, LineEdit{AssignTo: &localStart, CueBanner: "例如 25565", MinSize: Size{Width: 120}},
				Label{Text: "公网起始端口", MinSize: Size{Width: 100}}, LineEdit{AssignTo: &remoteStart, CueBanner: "例如 30000", MinSize: Size{Width: 120}},
				Label{Text: "数量", MinSize: Size{Width: 48}}, LineEdit{AssignTo: &countEdit, Text: "1", MinSize: Size{Width: 70}},
			}},
			TextLabel{Text: "单个配置最多 16 条规则；TCP + UDP 模式会为每个端口生成两条规则。端口递增时不能超过 65535。", TextColor: uiMuted, MinSize: Size{Width: 520}},
			VSpacer{StretchFactor: 1},
			Composite{Layout: HBox{MarginsZero: true, Spacing: 10}, Children: []Widget{
				HSpacer{}, actionButton(nil, "取消", false, 88, func() { dlg.Cancel() }),
				actionButton(&saveButton, "生成规则", true, 108, func() {
					localValue, err := strconv.Atoi(strings.TrimSpace(localStart.Text()))
					if err != nil || localValue < 1 || localValue > 65535 {
						walk.MsgBox(dlg, "本地端口不正确", "本地起始端口必须是 1-65535 的数字。", walk.MsgBoxOK|walk.MsgBoxIconWarning)
						return
					}
					remoteValue, err := strconv.Atoi(strings.TrimSpace(remoteStart.Text()))
					if err != nil || remoteValue < 1 || remoteValue > 65535 {
						walk.MsgBox(dlg, "公网端口不正确", "公网起始端口必须是 1-65535 的数字。", walk.MsgBoxOK|walk.MsgBoxIconWarning)
						return
					}
					count, err := strconv.Atoi(strings.TrimSpace(countEdit.Text()))
					if err != nil || count < 1 || count > frpctl.MaxRules {
						walk.MsgBox(dlg, "数量不正确", fmt.Sprintf("数量必须是 1-%d 的数字。", frpctl.MaxRules), walk.MsgBoxOK|walk.MsgBoxIconWarning)
						return
					}
					protocols := []string{"tcp"}
					switch protocolBox.CurrentIndex() {
					case 1:
						protocols = []string{"udp"}
					case 2:
						protocols = []string{"tcp", "udp"}
					}
					targetKind := "loopback"
					host := "127.0.0.1"
					if targetBox.CurrentIndex() == 1 {
						targetKind = "lan"
						host = strings.TrimSpace(targetHost.Text())
					}
					cfg, err := addBatchRules(a.frpConfig, targetKind, host, protocols, localValue, remoteValue, count, strings.TrimSpace(namePrefix.Text()))
					if err != nil {
						walk.MsgBox(dlg, "批量规则不正确", err.Error(), walk.MsgBoxOK|walk.MsgBoxIconWarning)
						return
					}
					a.applyFRPConfig(cfg, "")
					dlg.Accept()
				}),
			}},
		},
	}).Create(a.window)
	if err != nil {
		a.showFRPError("批量添加穿透端口", err)
		return
	}
	setFields()
	defer dlg.Dispose()
	dlg.Run()
}

func addBatchRules(base frpctl.Config, targetKind, host string, protocols []string, localStart, remoteStart, count int, prefix string) (frpctl.Config, error) {
	if count < 1 || count > frpctl.MaxRules {
		return frpctl.Config{}, fmt.Errorf("数量必须是 1-%d", frpctl.MaxRules)
	}
	if localStart < 1 || localStart > 65535 || remoteStart < 1 || remoteStart > 65535 {
		return frpctl.Config{}, fmt.Errorf("起始端口必须是 1-65535")
	}
	if len(protocols) == 0 {
		return frpctl.Config{}, fmt.Errorf("至少选择一种协议")
	}
	if localStart+count-1 > 65535 || remoteStart+count-1 > 65535 {
		return frpctl.Config{}, fmt.Errorf("递增后的端口不能超过 65535")
	}
	total := count * len(protocols)
	cfg := frpctl.CloneConfig(base)
	if len(cfg.Profile.Rules)+total > frpctl.MaxRules {
		return frpctl.Config{}, fmt.Errorf("当前已有 %d 条规则，本次需要 %d 条，最多 %d 条", len(cfg.Profile.Rules), total, frpctl.MaxRules)
	}
	prefix = strings.TrimSpace(prefix)
	if prefix == "" {
		prefix = "批量端口"
	}
	for i := 0; i < count; i++ {
		for _, protocol := range protocols {
			id, err := frpctl.NewRuleID()
			if err != nil {
				return frpctl.Config{}, err
			}
			cfg.Profile.Rules = append(cfg.Profile.Rules, frpctl.Rule{
				ID: id, Name: fmt.Sprintf("%s %s %d", prefix, strings.ToUpper(protocol), remoteStart+i), Type: protocol, Enabled: true,
				Target:   frpctl.Target{Kind: targetKind, Host: host, Port: localStart + i},
				Exposure: frpctl.Exposure{RemotePort: remoteStart + i},
			})
		}
	}
	if err := frpctl.ValidateConfig(cfg); err != nil {
		return frpctl.Config{}, err
	}
	return cfg, nil
}
