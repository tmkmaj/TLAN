package frp

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

func TestLogRingRedactsAndBounds(t *testing.T) {
	var ring logRing
	ring.setSecrets("token-value")
	for i := 0; i < logRingCapacity+10; i++ {
		ring.add("line token=token-value password=secret")
	}
	lines := ring.snapshot()
	if len(lines) != logRingCapacity {
		t.Fatalf("ring length = %d", len(lines))
	}
	if strings.Contains(strings.Join(lines, "\n"), "token-value") {
		t.Fatal("secret remained in logs")
	}
	if !strings.Contains(lines[0], "[已隐藏]") {
		t.Fatal("log line was not redacted")
	}
}

func TestPersistentLogRotatesRedactsAndBounds(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	retention := LogRetention{MaxFileBytes: 4096, MaxFiles: 4, MaxTotalBytes: 12288}
	persistent := newPersistentLog(store.Root(), retention)
	ring := &logRing{}
	ring.setPersistent(persistent)
	ring.setSecrets("token-value")
	t.Cleanup(func() { _ = ring.closePersistent() })

	padding := strings.Repeat("x", 240)
	for index := 0; index < 120; index++ {
		ring.add(fmt.Sprintf("event=%03d token=token-value password=secret-value %s", index, padding))
	}

	status := ring.storageStatus()
	if status.LastError != "" {
		t.Fatalf("persistent log error: %s", status.LastError)
	}
	if len(status.Files) < 2 {
		t.Fatalf("expected rotated log files, got %+v", status.Files)
	}
	if len(status.Files) > retention.MaxFiles {
		t.Fatalf("retained files = %d, max = %d", len(status.Files), retention.MaxFiles)
	}
	if status.TotalBytes > retention.MaxTotalBytes {
		t.Fatalf("retained bytes = %d, max = %d", status.TotalBytes, retention.MaxTotalBytes)
	}
	if status.ActivePath != store.LogFile() {
		t.Fatalf("active path = %q, want %q", status.ActivePath, store.LogFile())
	}
	if len(status.Files) == 0 || !status.Files[0].Current {
		t.Fatalf("active file missing or not marked current: %+v", status.Files)
	}

	var combined strings.Builder
	for _, file := range status.Files {
		if file.SizeBytes > retention.MaxFileBytes {
			t.Fatalf("log file %s size = %d, max = %d", file.Name, file.SizeBytes, retention.MaxFileBytes)
		}
		data, readErr := os.ReadFile(file.Path)
		if readErr != nil {
			t.Fatalf("read %s: %v", file.Path, readErr)
		}
		combined.Write(data)
	}
	contents := combined.String()
	if strings.Contains(contents, "token-value") || strings.Contains(contents, "secret-value") {
		t.Fatal("secret remained in persistent FRP logs")
	}
	if !strings.Contains(contents, "event=119") {
		t.Fatal("newest persistent log line is missing")
	}
	if strings.Contains(strings.Join(ring.snapshot(), "\n"), "token-value") {
		t.Fatal("secret remained in the memory ring")
	}
}

func TestPersistentLogConcurrentWritesRemainAtomicAndRedacted(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	retention := LogRetention{MaxFileBytes: 1024 * 1024, MaxFiles: 2, MaxTotalBytes: 2 * 1024 * 1024}
	ring := &logRing{}
	ring.setPersistent(newPersistentLog(store.Root(), retention))
	ring.setSecrets("shared-secret")
	t.Cleanup(func() { _ = ring.closePersistent() })

	const workers = 12
	const linesPerWorker = 75
	var wait sync.WaitGroup
	wait.Add(workers)
	for worker := 0; worker < workers; worker++ {
		go func(worker int) {
			defer wait.Done()
			for sequence := 0; sequence < linesPerWorker; sequence++ {
				ring.add(fmt.Sprintf("worker=%02d sequence=%03d token=shared-secret payload=%s", worker, sequence, strings.Repeat("a", 80)))
			}
		}(worker)
	}
	wait.Wait()

	status := ring.storageStatus()
	if status.LastError != "" {
		t.Fatalf("persistent log error: %s", status.LastError)
	}
	var combined strings.Builder
	for _, file := range status.Files {
		data, readErr := os.ReadFile(file.Path)
		if readErr != nil {
			t.Fatalf("read %s: %v", file.Path, readErr)
		}
		combined.Write(data)
	}
	contents := combined.String()
	if count := strings.Count(contents, "worker="); count != workers*linesPerWorker {
		t.Fatalf("persistent line count = %d, want %d", count, workers*linesPerWorker)
	}
	if strings.Contains(contents, "shared-secret") {
		t.Fatal("concurrent writes leaked a secret")
	}
	if got := len(ring.snapshot()); got != logRingCapacity {
		t.Fatalf("memory ring length = %d, want %d", got, logRingCapacity)
	}
}

func TestPersistentLogUsesPrivatePermissionsAndStaysOutsideRuntime(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ring := &logRing{}
	ring.setPersistent(newPersistentLog(store.Root(), LogRetention{MaxFileBytes: 4096, MaxFiles: 2, MaxTotalBytes: 8192}))
	ring.add("permission-check")
	t.Cleanup(func() { _ = ring.closePersistent() })

	if pathWithinRoot(store.RuntimeRoot(), store.LogFile()) {
		t.Fatalf("persistent log %q is inside disposable runtime root %q", store.LogFile(), store.RuntimeRoot())
	}
	fileInfo, err := os.Stat(store.LogFile())
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if fileInfo.Mode().Perm() != 0o600 {
			t.Fatalf("log file permissions = %o, want 600", fileInfo.Mode().Perm())
		}
		dirInfo, statErr := os.Stat(store.LogRoot())
		if statErr != nil {
			t.Fatal(statErr)
		}
		if dirInfo.Mode().Perm() != 0o700 {
			t.Fatalf("log directory permissions = %o, want 700", dirInfo.Mode().Perm())
		}
	}
}

func TestPersistentLogRejectsUnsafeDirectoryAndSymlink(t *testing.T) {
	t.Run("regular file collision", func(t *testing.T) {
		store, err := NewStore(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		if err = os.MkdirAll(store.Root(), 0o700); err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(store.LogRoot(), []byte("do-not-touch"), 0o600); err != nil {
			t.Fatal(err)
		}
		ring := &logRing{}
		ring.setPersistent(newPersistentLog(store.Root(), LogRetention{MaxFileBytes: 4096, MaxFiles: 2, MaxTotalBytes: 8192}))
		ring.add("must not be written")
		status := ring.storageStatus()
		if status.LastError == "" {
			t.Fatal("unsafe log directory collision was not reported")
		}
		data, readErr := os.ReadFile(store.LogRoot())
		if readErr != nil || string(data) != "do-not-touch" {
			t.Fatalf("unsafe log directory was modified: %q, %v", data, readErr)
		}
	})

	t.Run("symlink escape", func(t *testing.T) {
		store, err := NewStore(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		if err = os.MkdirAll(store.Root(), 0o700); err != nil {
			t.Fatal(err)
		}
		outside := t.TempDir()
		if err = os.Symlink(outside, store.LogRoot()); err != nil {
			t.Skipf("symlink creation is unavailable: %v", err)
		}
		ring := &logRing{}
		ring.setPersistent(newPersistentLog(store.Root(), LogRetention{MaxFileBytes: 4096, MaxFiles: 2, MaxTotalBytes: 8192}))
		ring.add("must stay inside the profile store")
		status := ring.storageStatus()
		if status.LastError == "" {
			t.Fatal("symlink log directory was not rejected")
		}
		if _, statErr := os.Stat(filepath.Join(outside, frpLogFileName)); !os.IsNotExist(statErr) {
			t.Fatalf("log write escaped through symlink: %v", statErr)
		}
	})
}

func TestPersistentLogTruncatesOversizedRecord(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ring := &logRing{}
	ring.setPersistent(newPersistentLog(store.Root(), LogRetention{MaxFileBytes: 512, MaxFiles: 1, MaxTotalBytes: 512}))
	t.Cleanup(func() { _ = ring.closePersistent() })
	ring.add(strings.Repeat("超长日志", 1000))
	status := ring.storageStatus()
	if status.LastError != "" {
		t.Fatalf("persistent log error: %s", status.LastError)
	}
	if len(status.Files) != 1 || status.Files[0].SizeBytes > 512 {
		t.Fatalf("oversized log record was not bounded: %+v", status.Files)
	}
	data, err := os.ReadFile(store.LogFile())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "[truncated]") {
		t.Fatal("oversized log record was not marked as truncated")
	}
}
