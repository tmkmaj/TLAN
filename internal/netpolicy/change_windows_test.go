//go:build windows

package netpolicy

import "testing"

func TestWindowsChangeNotifierRegistersAndCloses(t *testing.T) {
	notifier, err := NewChangeNotifier()
	if err != nil {
		t.Fatalf("create Windows change notifier: %v", err)
	}
	if notifier == nil || notifier.Changes() == nil {
		t.Fatal("notifier did not expose a change channel")
	}
	if err := notifier.Err(); err != nil {
		t.Fatalf("notifier registration error: %v", err)
	}
	if err := notifier.Close(); err != nil {
		t.Fatalf("close notifier: %v", err)
	}
	if err := notifier.Close(); err != nil {
		t.Fatalf("second close notifier: %v", err)
	}
}

func TestWindowsChangeNotifierCoalescesSignals(t *testing.T) {
	notifier := &windowsChangeNotifier{changes: make(chan struct{}, 1)}
	notifier.signal()
	notifier.signal()
	if got := len(notifier.changes); got != 1 {
		t.Fatalf("pending signals = %d, want 1", got)
	}
	<-notifier.changes
	notifier.closed.Store(true)
	notifier.signal()
	if got := len(notifier.changes); got != 0 {
		t.Fatalf("closed notifier queued %d signals", got)
	}
}
