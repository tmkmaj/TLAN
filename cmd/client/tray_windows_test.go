//go:build windows

package main

import "testing"

func TestResolveCloseBehaviorDefaultsToExit(t *testing.T) {
	cases := []struct {
		name          string
		closeToTray   bool
		explicitExit  bool
		trayAvailable bool
		want          closeBehavior
	}{
		{name: "default close", closeToTray: false, trayAvailable: true, want: closeBehaviorExit},
		{name: "explicit tray setting", closeToTray: true, trayAvailable: true, want: closeBehaviorTray},
		{name: "explicit exit wins", closeToTray: true, explicitExit: true, trayAvailable: true, want: closeBehaviorExit},
		{name: "tray unavailable is safe", closeToTray: true, trayAvailable: false, want: closeBehaviorExit},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := resolveCloseBehavior(tc.closeToTray, tc.explicitExit, tc.trayAvailable); got != tc.want {
				t.Fatalf("close behavior = %v, want %v", got, tc.want)
			}
		})
	}
}
