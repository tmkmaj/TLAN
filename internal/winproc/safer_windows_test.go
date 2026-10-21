//go:build windows

package winproc

import (
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestSaferNormalUserTokenCanLaunch(t *testing.T) {
	parent, err := openCurrentProcessToken()
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	raw, err := createSaferNormalUserToken(parent)
	if err != nil {
		t.Fatalf("createSaferNormalUserToken: %v", err)
	}
	defer raw.Close()
	token, err := duplicateToken(raw)
	if err != nil {
		t.Fatal(err)
	}
	defer token.Close()
	if err := setTokenIntegrity(token, integrityMediumRID); err != nil {
		t.Fatalf("set integrity: %v", err)
	}
	snapshot, err := snapshotToken(token)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.integrityRID != integrityMediumRID || snapshot.adminGroup == "enabled" {
		t.Fatalf("SAFER token is not restricted: integrity=%s admin=%s", snapshot.integrityLevel, snapshot.adminGroup)
	}
	for _, privilege := range snapshot.enabledPrivilegeNames {
		if privilege != "SeChangeNotifyPrivilege" {
			t.Fatalf("SAFER token has unexpected privilege %s", privilege)
		}
	}
	t.Logf("SAFER token: integrity=%s elevated=%v admin=%s privileges=%v groups=%v",
		snapshot.integrityLevel, snapshot.elevated, snapshot.adminGroup, snapshot.enabledPrivilegeNames, snapshot.groupSIDs)

	cmdPath, _ := systemCommand(t, "")
	app, _ := windows.UTF16PtrFromString(cmdPath)
	cmd, _ := windows.UTF16PtrFromString(windows.EscapeArg(cmdPath) + " /d /c exit 0")
	cwd, _ := windows.UTF16PtrFromString(filepath.Dir(cmdPath))
	startup := &windows.StartupInfoEx{}
	startup.Cb = uint32(unsafe.Sizeof(*startup))
	var proc windows.ProcessInformation
	if err := windows.CreateProcessAsUser(token, app, cmd, nil, nil, false,
		windows.CREATE_SUSPENDED|windows.CREATE_NO_WINDOW|windows.EXTENDED_STARTUPINFO_PRESENT,
		nil, cwd, (*windows.StartupInfo)(unsafe.Pointer(startup)), &proc); err != nil {
		t.Fatal(err)
	}
	defer closeHandle(proc.Process)
	defer closeHandle(proc.Thread)
	if _, err = windows.ResumeThread(proc.Thread); err != nil {
		t.Fatal(err)
	}
	_, _ = windows.WaitForSingleObject(proc.Process, windows.INFINITE)
	var code uint32
	if err = windows.GetExitCodeProcess(proc.Process, &code); err != nil {
		t.Fatal(err)
	}
	if code != 0 {
		t.Fatalf("SAFER child exit=%#x", code)
	}
}
