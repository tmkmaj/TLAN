//go:build windows

package frp

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestManagerLogStorageLifecycleAndSnapshot(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	manager := &Manager{store: store, state: "stopped"}
	manager.logs.setPersistent(newPersistentLog(store.Root(), LogRetention{MaxFileBytes: 4096, MaxFiles: 2, MaxTotalBytes: 8192}))
	manager.logs.setSecrets("manager-secret")
	manager.logs.add("manager lifecycle token=manager-secret")

	snapshot := manager.Snapshot(context.Background())
	if snapshot.LogStorage.ActivePath != store.LogFile() {
		t.Fatalf("snapshot log path = %q, want %q", snapshot.LogStorage.ActivePath, store.LogFile())
	}
	if snapshot.LogStorage.LastError != "" {
		t.Fatalf("snapshot log storage error: %s", snapshot.LogStorage.LastError)
	}
	if len(snapshot.LogStorage.Files) != 1 || snapshot.LogStorage.Files[0].SizeBytes == 0 {
		t.Fatalf("snapshot log files = %+v", snapshot.LogStorage.Files)
	}

	if err = manager.Stop(context.Background()); err != nil {
		t.Fatalf("manager stop: %v", err)
	}
	if manager.LogStorage().Closed {
		t.Fatal("manager stop closed the persistent log; manager would not remain reusable")
	}
	manager.logs.add("manager still logging after stop")

	if err = manager.Close(context.Background()); err != nil {
		t.Fatalf("manager close: %v", err)
	}
	if err = manager.Close(context.Background()); err != nil {
		t.Fatalf("second manager close: %v", err)
	}
	closed := manager.LogStorage()
	if !closed.Closed {
		t.Fatal("manager close did not close the persistent log")
	}
	data, err := os.ReadFile(store.LogFile())
	if err != nil {
		t.Fatalf("persistent log was removed during manager cleanup: %v", err)
	}
	if strings.Contains(string(data), "manager-secret") {
		t.Fatal("manager persistent log contains a secret")
	}
	if !strings.Contains(string(data), "manager lifecycle") || !strings.Contains(string(data), "after stop") {
		t.Fatal("manager persistent log did not retain lines around the stop/close lifecycle")
	}
}
func TestNewManagerAttachesPersistentLog(t *testing.T) {
	frpcPath := filepath.Join("..", "..", "assets", "frp", "windows-amd64", "frpc.exe")
	if _, err := os.Stat(frpcPath); err != nil {
		t.Skipf("bundled FRPC binary unavailable: %v", err)
	}
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	manager, err := NewManager(Options{Store: store, CorePath: frpcPath, DeviceID: "log-test-device"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = manager.Close(context.Background()) }()
	if got := manager.LogStorage().ActivePath; got != store.LogFile() {
		t.Fatalf("manager log path = %q, want %q", got, store.LogFile())
	}
	manager.logs.add("constructor log lifecycle")
	if _, err = os.Stat(store.LogFile()); err != nil {
		t.Fatalf("constructor did not open persistent logging: %v", err)
	}
}
