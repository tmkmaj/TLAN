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
	closeBehaviorMinimize
	closeBehaviorTray
)

// resolveCloseBehavior keeps the client running in the background when the user
// closes the window: hide to tray if configured and available, otherwise
// minimize to the taskbar unless an explicit exit was requested.
func resolveCloseBehavior(closeToTray, explicitExit, trayAvailable bool) closeBehavior {
	if explicitExit {
		return closeBehaviorExit
	}
	if closeToTray && trayAvailable {
		return closeBehaviorTray
	}
	return closeBehaviorMinimize
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

	a.retranslateTrayActions()

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

func (a *desktop) retranslateTrayActions() {
	if a.trayShowAction != nil {
		_ = a.trayShowAction.SetText(tr("显示窗口", "Show Window"))
	}
	if a.trayMeshAction != nil {
		_ = a.trayMeshAction.SetText(tr("启动虚拟局域网", "Connect Virtual LAN"))
	}
	if a.trayFRPAction != nil {
		_ = a.trayFRPAction.SetText(tr("启动端口映射", "Start Port Mapping"))
	}
	if a.traySettingsAction != nil {
		_ = a.traySettingsAction.SetText(tr("客户端设置…", "Settings…"))
	}
	if a.trayExitAction != nil {
		_ = a.trayExitAction.SetText(tr("退出程序", "Exit"))
	}
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
	a.retranslateTrayActions()

	meshText := tr("启动虚拟局域网", "Connect Virtual LAN")
	meshEnabled := a.api != nil && a.api.Token != "" && !a.busy
	switch {
	case a.engine != nil:
		meshText = tr("停止虚拟局域网", "Disconnect Virtual LAN")
		meshEnabled = !a.busy
	case a.powerState == 2:
		meshText = tr("虚拟局域网切换中…", "Virtual LAN Switching…")
		meshEnabled = false
	}

	s := a.frpSnapshot
	canStop := s.CanStop || s.Running || s.State == "stopping" || s.DesiredRunning
	frpText := tr("启动端口映射", "Start Port Mapping")
	frpEnabled := s.Configured && !a.frpBusy && a.frpManager != nil
	if canStop {
		switch {
		case s.State == "stopping":
			frpText = tr("端口映射停止中…", "Stopping Port Mapping…")
		case s.Running:
			frpText = tr("停止端口映射", "Stop Port Mapping")
		default:
			frpText = tr("取消端口映射启动", "Cancel Port Mapping")
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
		meshState := tr("已停止", "Stopped")
		if a.engine != nil {
			meshState = tr("已开启", "Connected")
		}
		frpState := tr("已停止", "Stopped")
		if s.Running {
			frpState = tr("已连接", "Running")
		}
		_ = a.trayIcon.SetToolTip(trf("%s · 虚拟局域网 %s · 端口映射 %s", "%s · Virtual LAN %s · Port Mapping %s", windowTitle, meshState, frpState))
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
	a.requestCleanRelayout()
	a.ensureAnimLoop()
}

func (a *desktop) requestExit() {
	if a.window == nil || a.window.IsDisposed() {
		return
	}
	a.explicitExit.Store(true)
	_ = a.window.Close()
}

func (a *desktop) handleWindowClosing(canceled *bool, _ walk.CloseReason) {
	switch resolveCloseBehavior(a.settings.CloseToTray, a.explicitExit.Load(), a.trayAvailable()) {
	case closeBehaviorTray:
		if canceled != nil {
			*canceled = true
		}
		if a.window != nil && !a.window.IsDisposed() {
			a.window.Hide()
		}
		return
	case closeBehaviorMinimize:
		if canceled != nil {
			*canceled = true
		}
		if a.window != nil && !a.window.IsDisposed() {
			win.ShowWindow(a.window.Handle(), win.SW_MINIMIZE)
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
