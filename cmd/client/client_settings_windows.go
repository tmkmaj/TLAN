//go:build windows

package main

import (
	"errors"
	"fmt"
	"strings"
	"unicode"

	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
	"github.com/lxn/win"
	"github.com/private-radminlan/lanmesh/core"
)

func (a *desktop) showClientSettings() {
	a.runOnUI(a.showClientSettingsDialog)
}

func validateCustomUsername(raw string) (string, error) {
	name := strings.TrimSpace(raw)
	if name == "" {
		return "", errors.New(tr("用户名不能为空", "Username cannot be empty"))
	}
	if len([]byte(name)) > 128 || len([]rune(name)) > 64 || strings.ContainsFunc(name, unicode.IsControl) {
		return "", errors.New(tr("用户名长度不能超过 64 个字符且不能包含控制字符", "Username must be 1-64 non-control characters"))
	}
	return name, nil
}

func (a *desktop) showClientSettingsDialog() {
	if a.window == nil || a.window.IsDisposed() || a.settingsDialogOpen {
		return
	}
	a.settingsDialogOpen = true
	defer func() { a.settingsDialogOpen = false }()

	var dlg *walk.Dialog
	var usernameEdit *walk.LineEdit
	var closeToTray, launchAtLogin, multipath *walk.CheckBox
	var mtu *walk.NumberEdit
	var appearance, language *walk.ComboBox
	var saveButton, closeButton *walk.PushButton
	currentName := a.identity.DisplayName
	if currentName == "" {
		currentName = a.settings.DeviceName
	}
	err := (Dialog{
		AssignTo: &dlg, Title: tr("设置", "Settings"), Icon: a.appIcon,
		Size: Size{Width: 490, Height: 465}, MinSize: Size{Width: 450, Height: 430},
		Font:         uiFont(10, false),
		Background:   SolidColorBrush{Color: uiWhite},
		Layout:       VBox{Margins: Margins{Left: 24, Top: 22, Right: 24, Bottom: 20}, Spacing: 12},
		CancelButton: &closeButton, DefaultButton: &saveButton,
		Children: []Widget{
			heading(tr("客户端设置", "Client Settings")),
			Composite{Background: SolidColorBrush{Color: uiWhite}, Layout: HBox{MarginsZero: true, Spacing: 12}, Children: []Widget{
				formLabel(tr("用户名", "Username"), 118),
				LineEdit{AssignTo: &usernameEdit, Text: currentName, MaxLength: 64, CueBanner: tr("自定义显示名称", "Custom display name"), Font: uiFont(9, false), TextColor: uiInk, Background: SolidColorBrush{Color: uiWhite}, MinSize: Size{Width: 240}, Accessibility: Accessibility{Name: tr("用户名", "Username")}},
				HSpacer{},
			}},
			Composite{Background: SolidColorBrush{Color: uiWhite}, Layout: HBox{MarginsZero: true, Spacing: 12}, Children: []Widget{
				formLabel(tr("语言 / Language", "Language"), 118),
				comboBoxView{ComboBox: ComboBox{AssignTo: &language, Model: []string{tr("跟随系统", "Follow system"), "简体中文", "English"}, CurrentIndex: languageIndex(a.settings.Language), Font: uiFont(9, false), MinSize: Size{Width: 180, Height: 30}, MaxSize: Size{Height: 30}, Accessibility: Accessibility{Name: tr("界面语言", "Language")}}},
				HSpacer{},
			}},
			Composite{Background: SolidColorBrush{Color: uiWhite}, Layout: HBox{MarginsZero: true, Spacing: 12}, Children: []Widget{
				formLabel(tr("外观", "Appearance"), 118),
				comboBoxView{ComboBox: ComboBox{AssignTo: &appearance, Model: []string{tr("跟随系统", "Follow system"), tr("浅色", "Light"), tr("深色", "Dark")}, CurrentIndex: appearanceIndex(a.settings.Appearance), Font: uiFont(9, false), MinSize: Size{Width: 180, Height: 30}, MaxSize: Size{Height: 30}, Accessibility: Accessibility{Name: tr("界面外观", "Appearance")}}},
				HSpacer{},
			}},
			themedCheckBox(&closeToTray, tr("关闭窗口时最小化到托盘", "Minimize to tray on close"), a.settings.CloseToTray),
			themedCheckBox(&launchAtLogin, tr("开机时自动启动", "Launch at login"), a.settings.LaunchAtLogin),
			Composite{Background: SolidColorBrush{Color: uiWhite}, Layout: HBox{MarginsZero: true, Spacing: 12}, Children: []Widget{
				formLabel(tr("虚拟网卡 MTU", "Virtual Adapter MTU"), 118),
				NumberEdit{AssignTo: &mtu, Value: func() float64 {
					if a.settings.MTU >= 576 && a.settings.MTU <= 1500 {
						return float64(a.settings.MTU)
					}
					return 1280
				}(), MinValue: 576, MaxValue: 1500, Decimals: 0, Font: uiFont(9, false), TextColor: uiInk, Background: SolidColorBrush{Color: uiWhite}, MinSize: Size{Width: 100}},
				Label{Text: tr("默认 1280", "Default 1280"), TextColor: uiMuted, Font: uiFont(9, false), NoPrefix: true},
				HSpacer{},
			}},
			themedCheckBox(&multipath, tr("低延迟优化（小包双发）", "Low-latency multipath replication"), a.settings.MultipathReplication),
			Composite{MinSize: Size{Height: 1}, MaxSize: Size{Height: 1}, Background: SolidColorBrush{Color: uiBorder}},
			Composite{Background: SolidColorBrush{Color: uiWhite}, Layout: HBox{MarginsZero: true, Spacing: 10}, Children: []Widget{
				Label{Text: appName + " " + appVersion, TextColor: uiMuted, Font: uiFont(9, false), NoPrefix: true},
				HSpacer{},
				compactButton(nil, tr("关于本软件", "About"), btnSecondary, 90, a.showVersionInfo),
			}},
			VSpacer{StretchFactor: 1},
			Composite{Background: SolidColorBrush{Color: uiWhite}, Layout: HBox{MarginsZero: true, Spacing: 10}, Children: []Widget{
				HSpacer{},
				actionButton(nil, tr("取消", "Cancel"), false, 84, func() { dlg.Cancel() }),
				actionButton(&saveButton, tr("保存设置", "Save"), true, 96, func() {
					if err := a.applyClientSettings(usernameEdit.Text(), closeToTray.Checked(), launchAtLogin.Checked(), multipath.Checked(), int(mtu.Value()), appearanceFromIndex(appearance.CurrentIndex()), languageFromIndex(language.CurrentIndex())); err != nil {
						walk.MsgBox(dlg, tr("保存客户端设置失败", "Failed to save settings"), err.Error(), walk.MsgBoxOK|walk.MsgBoxIconError)
						return
					}
					dlg.Accept()
				}),
			}},
		},
	}).Create(a.window)
	if err != nil {
		a.showError(tr("打开客户端设置", "Open settings"), err)
		return
	}
	defer dlg.Dispose()
	runThemedDialog(dlg)
}

func (a *desktop) showRenameSelfDialog() {
	if a.window == nil || a.window.IsDisposed() {
		return
	}
	var dlg *walk.Dialog
	var nameEdit *walk.LineEdit
	var saveBtn, cancelBtn *walk.PushButton
	err := (Dialog{
		AssignTo:      &dlg,
		Title:         tr("修改用户名", "Edit Username"),
		Icon:          a.appIcon,
		Size:          Size{Width: 420, Height: 185},
		MinSize:       Size{Width: 380, Height: 170},
		Font:          uiFont(10, false),
		Background:    SolidColorBrush{Color: uiWhite},
		Layout:        VBox{Margins: Margins{Left: 24, Top: 20, Right: 24, Bottom: 18}, Spacing: 12},
		CancelButton:  &cancelBtn,
		DefaultButton: &saveBtn,
		Children: []Widget{
			heading(tr("自定义用户名", "Custom Username")),
			LineEdit{AssignTo: &nameEdit, Text: a.identity.DisplayName, MaxLength: 64, CueBanner: tr("输入新的用户名", "Enter a new username"), Font: uiFont(9, false), TextColor: uiInk, Background: SolidColorBrush{Color: uiWhite}, MinSize: Size{Width: 360}},
			Composite{Background: SolidColorBrush{Color: uiWhite}, Layout: HBox{MarginsZero: true, Spacing: 8}, Children: []Widget{
				HSpacer{},
				actionButton(&cancelBtn, tr("取消", "Cancel"), false, 78, func() { dlg.Cancel() }),
				actionButton(&saveBtn, tr("保存", "Save"), true, 78, func() {
					valid, vErr := validateCustomUsername(nameEdit.Text())
					if vErr != nil {
						walk.MsgBox(dlg, tr("用户名无效", "Invalid username"), vErr.Error(), walk.MsgBoxOK|walk.MsgBoxIconWarning)
						return
					}
					if err := a.updateCustomUsername(valid); err != nil {
						walk.MsgBox(dlg, tr("保存用户名失败", "Failed to save username"), err.Error(), walk.MsgBoxOK|walk.MsgBoxIconError)
						return
					}
					dlg.Accept()
				}),
			}},
		},
	}).Create(a.window)
	if err != nil {
		a.showError(tr("打开修改用户名窗口", "Open rename dialog"), err)
		return
	}
	defer dlg.Dispose()
	runThemedDialog(dlg)
}

func (a *desktop) applyLocalRenameImmediate(valid string) {
	a.identity.DisplayName = valid
	a.settings.DeviceName = valid
	a.membership.Member.Name = valid
	did := a.identity.DeviceID.String()
	for i := range a.members {
		if a.members[i].ID == did {
			a.members[i].Name = valid
		}
	}
	if a.usernameInput != nil {
		_ = a.usernameInput.SetText(valid)
	}
	if a.deviceName != nil && !a.deviceName.IsDisposed() {
		_ = a.deviceName.SetText(valid)
		_ = a.deviceName.Invalidate()
		if a.deviceName.Handle() != 0 {
			win.RedrawWindow(a.deviceName.Handle(), nil, 0, win.RDW_INVALIDATE|win.RDW_ERASE|win.RDW_UPDATENOW)
		}
	}
	a.updateStatus()
	a.requestCleanRelayout()
}

func (a *desktop) updateCustomUsername(name string) error {
	valid, err := validateCustomUsername(name)
	if err != nil {
		return err
	}
	prevName := a.identity.DisplayName
	prevSettingsName := a.settings.DeviceName
	a.identity.DisplayName = valid
	a.settings.DeviceName = valid
	if err := a.remember(); err != nil {
		a.identity.DisplayName = prevName
		a.settings.DeviceName = prevSettingsName
		return err
	}
	a.applyLocalRenameImmediate(valid)
	if a.api != nil && a.api.Token != "" && a.membership.Network.ID != "" {
		a.renameSeq++
		seq := a.renameSeq
		api := *a.api
		nid := core.NetworkID(a.membership.Network.ID)
		did := a.identity.DeviceID
		go func() {
			updated, renameErr := api.RenameSelf(nid, did, valid)
			a.ui(func() {
				if seq != a.renameSeq {
					return
				}
				if renameErr != nil {
					a.showError(tr("同步用户名", "Sync username"), renameErr)
					return
				}
				a.membership.Member = updated
				if updated.Name != "" {
					a.applyLocalRenameImmediate(updated.Name)
				}
				a.refreshMembers()
			})
		}()
	}
	return nil
}

func (a *desktop) applyClientSettings(rawName string, closeToTray, launchAtLogin, multipath bool, mtu int, appearance, language string) error {
	validName, err := validateCustomUsername(rawName)
	if err != nil {
		return err
	}
	previous := a.settings
	prevDisplayName := a.identity.DisplayName
	next := previous
	next.DeviceName = validName
	next.CloseToTray = closeToTray
	next.LaunchAtLogin = launchAtLogin
	next.MultipathReplication = multipath
	next.Appearance = normalizeAppearance(appearance)
	next.Language = normalizeLanguage(language)
	if mtu < 576 || mtu > 1500 {
		return errors.New(tr("MTU 必须在 576 到 1500 之间", "MTU must be between 576 and 1500"))
	}
	next.MTU = mtu

	if err := updateStartupRegistration(launchAtLogin); err != nil {
		return fmt.Errorf(tr("更新登录启动项: %w", "update startup entry: %w"), err)
	}
	a.identity.DisplayName = validName
	a.settings = next
	if err := a.remember(); err != nil {
		a.identity.DisplayName = prevDisplayName
		a.settings = previous
		rollbackErr := updateStartupRegistration(previous.LaunchAtLogin)
		if rollbackErr != nil {
			return errors.Join(err, fmt.Errorf(tr("回滚登录启动项: %w", "rollback startup entry: %w"), rollbackErr))
		}
		return err
	}
	a.applyLocalRenameImmediate(validName)
	if validName != prevDisplayName && a.api != nil && a.api.Token != "" && a.membership.Network.ID != "" {
		a.renameSeq++
		seq := a.renameSeq
		api := *a.api
		nid := core.NetworkID(a.membership.Network.ID)
		did := a.identity.DeviceID
		go func() {
			updated, renameErr := api.RenameSelf(nid, did, validName)
			a.ui(func() {
				if seq != a.renameSeq {
					return
				}
				if renameErr != nil {
					a.showError(tr("同步用户名", "Sync username"), renameErr)
					return
				}
				a.membership.Member = updated
				if updated.Name != "" {
					a.applyLocalRenameImmediate(updated.Name)
				}
				a.refreshMembers()
			})
		}()
	}
	a.applyAppearance(a.settings.Appearance)
	a.applyLanguage(a.settings.Language)
	a.updateTrayMenu()
	a.setStatus(tr("客户端设置已保存", "Settings saved"))
	return nil
}

func (a *desktop) syncLaunchAtLogin() error {
	return updateStartupRegistration(a.settings.LaunchAtLogin)
}
