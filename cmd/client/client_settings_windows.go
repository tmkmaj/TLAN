//go:build windows

package main

import (
	"errors"
	"fmt"

	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
)

func (a *desktop) showClientSettings() {
	a.runOnUI(a.showClientSettingsDialog)
}

func (a *desktop) showClientSettingsDialog() {
	if a.window == nil || a.window.IsDisposed() || a.settingsDialogOpen {
		return
	}
	a.settingsDialogOpen = true
	defer func() { a.settingsDialogOpen = false }()

	var dlg *walk.Dialog
	var closeToTray, launchAtLogin *walk.CheckBox
	var saveButton, closeButton *walk.PushButton
	err := (Dialog{
		AssignTo: &dlg, Title: "客户端设置", Icon: a.appIcon,
		Size: Size{Width: 590, Height: 410}, MinSize: Size{Width: 530, Height: 370},
		Font:         Font{Family: "Microsoft YaHei UI", PointSize: 10},
		Background:   SolidColorBrush{Color: uiWhite},
		Layout:       VBox{Margins: Margins{Left: 28, Top: 24, Right: 28, Bottom: 22}, Spacing: 12},
		CancelButton: &closeButton, DefaultButton: &saveButton,
		Children: []Widget{
			heading("客户端设置"),
			TextLabel{Text: "以下设置仅作用于当前 Windows 用户。", TextColor: uiMuted, MinSize: Size{Width: 500}},
			CheckBox{AssignTo: &closeToTray, Text: "关闭窗口时最小化到托盘", Checked: a.settings.CloseToTray},
			TextLabel{Text: "开启后点击窗口关闭按钮会隐藏窗口，网络和穿透继续运行；请从托盘菜单选择“退出程序”结束进程。默认关闭时仍直接退出。", TextColor: uiMuted, MinSize: Size{Width: 500}},
			CheckBox{AssignTo: &launchAtLogin, Text: "登录 Windows 时自动启动 TmkNetworkLAN", Checked: a.settings.LaunchAtLogin},
			TextLabel{Text: "仅写入当前用户 HKCU 启动项，不创建系统服务，也不会影响其他用户。启动时使用当前程序路径。", TextColor: uiMuted, MinSize: Size{Width: 500}},
			VSpacer{StretchFactor: 1},
			Composite{Layout: HBox{MarginsZero: true, Spacing: 10}, Children: []Widget{
				HSpacer{},
				actionButton(nil, "取消", false, 88, func() { dlg.Cancel() }),
				actionButton(&saveButton, "保存设置", true, 108, func() {
					if err := a.applyClientSettings(closeToTray.Checked(), launchAtLogin.Checked()); err != nil {
						walk.MsgBox(dlg, "保存客户端设置失败", err.Error(), walk.MsgBoxOK|walk.MsgBoxIconError)
						return
					}
					dlg.Accept()
				}),
			}},
		},
	}).Create(a.window)
	if err != nil {
		a.showError("打开客户端设置", err)
		return
	}
	defer dlg.Dispose()
	dlg.Run()
}

func (a *desktop) applyClientSettings(closeToTray, launchAtLogin bool) error {
	previous := a.settings
	next := previous
	next.CloseToTray = closeToTray
	next.LaunchAtLogin = launchAtLogin

	if err := updateStartupRegistration(launchAtLogin); err != nil {
		return fmt.Errorf("更新登录启动项: %w", err)
	}
	a.settings = next
	if err := a.remember(); err != nil {
		a.settings = previous
		rollbackErr := updateStartupRegistration(previous.LaunchAtLogin)
		if rollbackErr != nil {
			return errors.Join(err, fmt.Errorf("回滚登录启动项: %w", rollbackErr))
		}
		return err
	}
	a.updateTrayMenu()
	a.setStatus("客户端设置已保存")
	return nil
}

func (a *desktop) syncLaunchAtLogin() error {
	return updateStartupRegistration(a.settings.LaunchAtLogin)
}
