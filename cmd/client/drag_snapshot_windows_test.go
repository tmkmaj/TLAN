//go:build windows

package main

import (
	"testing"

	"github.com/lxn/win"
)

func TestDragSnapshotFailureLatchesUntilNextSizeMove(t *testing.T) {
	d := &desktop{}
	// A stale HWND makes GetClientRect fail, which is one of the production
	// failure paths in enterDragSnapshot.
	d.enterDragSnapshot(win.HWND(0xdeadbeef))
	if !d.dragSnapFailed {
		t.Fatal("snapshot failure did not latch")
	}
	if d.canEnterDragSnapshot() {
		t.Fatal("snapshot retry allowed after a failure")
	}
	// WM_ENTERSIZEMOVE clears the latch for the next drag.
	d.dragSnapFailed = false
	if !d.canEnterDragSnapshot() {
		t.Fatal("snapshot retry blocked after the latch was cleared")
	}
}
