//go:build windows

package frp

import (
	"os"
	"testing"

	"golang.org/x/sys/windows"
)

func TestPersistentLogWindowsDACLIsPrivate(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ring := &logRing{}
	ring.setPersistent(newPersistentLog(store.Root(), LogRetention{MaxFileBytes: 4096, MaxFiles: 2, MaxTotalBytes: 8192}))
	t.Cleanup(func() { _ = ring.closePersistent() })
	ring.add("private ACL check")

	for _, path := range []string{store.LogRoot(), store.LogFile()} {
		if _, err = os.Stat(path); err != nil {
			t.Fatalf("stat %s: %v", path, err)
		}
		descriptor, descriptorErr := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
		if descriptorErr != nil {
			t.Fatalf("read DACL for %s: %v", path, descriptorErr)
		}
		control, _, controlErr := descriptor.Control()
		if controlErr != nil {
			t.Fatalf("read security control for %s: %v", path, controlErr)
		}
		if control&windows.SE_DACL_PROTECTED == 0 {
			t.Fatalf("DACL for %s is not protected", path)
		}
		dacl, _, daclErr := descriptor.DACL()
		if daclErr != nil {
			t.Fatalf("read DACL for %s: %v", path, daclErr)
		}
		if dacl == nil || dacl.AceCount != 2 {
			t.Fatalf("DACL for %s has %v ACEs, want 2 (current user and SYSTEM)", path, dacl)
		}
	}
}
