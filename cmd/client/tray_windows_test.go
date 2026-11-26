//go:build windows

package main

import "testing"

func TestResolveCloseBehaviorDefaultsToMinimize(t *testing.T) {
	cases := []struct {
		name          string
		closeToTray   bool
		explicitExit  bool
		trayAvailable bool
		want          closeBehavior
	}{
		{name: "default close minimizes to taskbar", closeToTray: false, trayAvailable: true, want: closeBehaviorMinimize},
		{name: "explicit tray setting", closeToTray: true, trayAvailable: true, want: closeBehaviorTray},
		{name: "explicit exit wins over tray", closeToTray: true, explicitExit: true, trayAvailable: true, want: closeBehaviorExit},
		{name: "explicit exit wins over minimize", closeToTray: false, explicitExit: true, trayAvailable: true, want: closeBehaviorExit},
		{name: "tray unavailable falls back to minimize", closeToTray: true, trayAvailable: false, want: closeBehaviorMinimize},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := resolveCloseBehavior(tc.closeToTray, tc.explicitExit, tc.trayAvailable); got != tc.want {
				t.Fatalf("close behavior = %v, want %v", got, tc.want)
			}
		})
	}
}
