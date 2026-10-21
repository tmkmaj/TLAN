//go:build windows

package main

import (
	"errors"
	"fmt"

	"github.com/lxn/walk"
	"github.com/lxn/win"
)

type closeBehavior uint8

const (
	closeBehaviorExit closeBehavior = iota
	closeBehaviorTray
)

// resolveCloseBehavior keeps the safe default: closing the window exits unless
// the user explicitly enabled tray residency and a tray icon is available.
func resolveCloseBehavior(closeToTray, explicitExit, trayAvailable bool) closeBehavior {
	if explicitExit || !closeToTray || !trayAvailable {
		return closeBehaviorExit
	}
	return closeBehaviorTray
}

func (a *desktop) initializeTrayActions() {
	if a.trayShowAction != nil {
		return
	}

	a.trayShowAction = walk.NewAction()
	a.trayMeshAction = walk.NewAction()
	a.trayFRPAction = walk.NewAction()
	a.traySettingsAction = walk.NewAction()
	a.trayExitAction = walk.NewAction()

	_ = a.trayShowAction.SetText("显示窗口")
	_ = a.trayMeshAction.SetText("启动 Mesh")
	_ = a.trayFRPAction.SetText("启动当前 FRP 配置")
	_ = a.traySettingsAction.SetText("客户端设置…")
	_ = a.trayExitAction.SetText("退出程序")

	a.trayShowAction.Triggered().Attach(func() {
		a.runOnUI(a.showWindow)
	})
	a.trayMeshAction.Triggered().Attach(func() {
		a.runOnUI(a.togglePower)
	})
	a.trayFRPAction.Triggered().Attach(func() {
		a.runOnUI(a.toggleFRP)
	})
	a.traySettingsAction.Triggered().Attach(func() {
		a.runOnUI(a.showClientSettings)
	})
	a.trayExitAction.Triggered().Attach(func() {
		a.runOnUI(a.requestExit)
	})
}

func (a *desktop) setupTray() error {
	a.initializeTrayActions()
	if a.trayIcon != nil {
		return nil
	}
	if a.window == nil {
		return errors.New("main window is not available")
	}

	icon, err := walk.NewNotifyIcon(a.window)
	if err != nil {
		return fmt.Errorf("create tray icon: %w", err)
	}
	a.trayIcon = icon

	fail := func(err error) error {
		a.disposeTray()
		return err
	}

	menu := icon.ContextMenu()
	if menu == nil {
		return fail(errors.New("tray menu is not available"))
	}
	items := []*walk.Action{
		a.trayShowAction,
		walk.NewSeparatorAction(),
		a.trayMeshAction,
		a.trayFRPAction,
		walk.NewSeparatorAction(),
		a.traySettingsAction,
		a.trayExitAction,
	}
	for _, action := range items {
		if err := menu.Actions().Add(action); err != nil {
			return fail(fmt.Errorf("add tray menu item: %w", err))
		}
	}

	if a.appIcon != nil {
		if err := icon.SetIcon(a.appIcon); err != nil {
			return fail(fmt.Errorf("set tray icon: %w", err))
		}
	}
	if err := icon.SetToolTip(windowTitle); err != nil {
		return fail(fmt.Errorf("set tray tooltip: %w", err))
	}
	icon.MouseUp().Attach(func(_, _ int, button walk.MouseButton) {
		if button == walk.LeftButton {
			a.runOnUI(a.showWindow)
		}
	})
	icon.MessageClicked().Attach(func() {
		a.runOnUI(a.showWindow)
	})
	if err := icon.SetVisible(true); err != nil {
		return fail(fmt.Errorf("show tray icon: %w", err))
	}

	a.updateTrayMenu()
	return nil
}

func (a *desktop) disposeTray() {
	icon := a.trayIcon
	a.trayIcon = nil
	if icon != nil {
		menu := icon.ContextMenu()
		_ = icon.Dispose()
		if menu != nil {
			menu.Dispose()
		}
	}
	a.trayShowAction = nil
	a.trayMeshAction = nil
	a.trayFRPAction = nil
	a.traySettingsAction = nil
	a.trayExitAction = nil
}

func (a *desktop) updateTrayMenu() {
	if a.trayMeshAction == nil || a.trayFRPAction == nil {
		return
	}

	meshText := "启动 Mesh"
	meshEnabled := a.api != nil && a.api.Token != "" && !a.busy
	switch {
	case a.engine != nil:
		meshText = "停止 Mesh"
		meshEnabled = !a.busy
	case a.powerState == 2:
		meshText = "Mesh 正在切换…"
		meshEnabled = false
	}

	s := a.frpSnapshot
	canStop := s.CanStop || s.Running || s.State == "stopping" || s.DesiredRunning
	frpText := "启动当前 FRP 配置"
	frpEnabled := s.Configured && !a.frpBusy && a.frpManager != nil
	if canStop {
		switch {
		case s.State == "stopping":
			frpText = "FRP 正在停止…"
		case s.Running:
			frpText = "停止当前 FRP 配置"
		default:
			frpText = "取消当前 FRP 启动"
		}
		frpEnabled = s.Configured && !a.frpStopping && (!a.frpBusy || a.frpStarting)
	}

	_ = a.trayMeshAction.SetText(meshText)
	_ = a.trayMeshAction.SetEnabled(meshEnabled)
	_ = a.trayFRPAction.SetText(frpText)
	_ = a.trayFRPAction.SetEnabled(frpEnabled)
	_ = a.traySettingsAction.SetEnabled(true)
	_ = a.trayExitAction.SetEnabled(true)

	if a.trayIcon != nil {
		meshState := "已停止"
		if a.engine != nil {
			meshState = "已开启"
		}
		frpState := "已停止"
		if s.Running {
			frpState = "已连接"
		}
		_ = a.trayIcon.SetToolTip(fmt.Sprintf("%s · Mesh %s · FRP %s", windowTitle, meshState, frpState))
	}
}

func (a *desktop) runOnUI(fn func()) {
	if a.window == nil || a.window.IsDisposed() || a.closing.Load() {
		return
	}
	var processID uint32
	threadID := win.GetWindowThreadProcessId(a.window.Handle(), &processID)
	if threadID == win.GetCurrentThreadId() {
		fn()
		return
	}
	a.ui(fn)
}

func (a *desktop) showWindow() {
	if a.window == nil || a.window.IsDisposed() {
		return
	}
	win.ShowWindow(a.window.Handle(), win.SW_RESTORE)
	a.window.Show()
	_ = a.window.Activate()
}

func (a *desktop) requestExit() {
	if a.window == nil || a.window.IsDisposed() {
		return
	}
	a.explicitExit.Store(true)
	_ = a.window.Close()
}

func (a *desktop) handleWindowClosing(canceled *bool, _ walk.CloseReason) {
	if resolveCloseBehavior(a.settings.CloseToTray, a.explicitExit.Load(), a.trayAvailable()) == closeBehaviorTray {
		if canceled != nil {
			*canceled = true
		}
		if a.window != nil {
			a.window.Hide()
		}
		return
	}
	a.shutdown()
}

func (a *desktop) trayAvailable() bool {
	return a.trayIcon != nil && a.trayIcon.Visible()
}

func (a *desktop) shutdown() {
	a.shutdownOnce.Do(func() {
		a.closing.Store(true)
		if a.cancel != nil {
			a.cancel()
		}
		if a.sessionCancel != nil {
			a.sessionCancel()
		}
		a.beginFRPClose()
	})
}
