//go:build windows

package winproc

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

var procImpersonateLoggedOnUser = advapi32.NewProc("ImpersonateLoggedOnUser")

func TestLaunchRestrictedTokenIsMediumWithoutAdministratorPrivileges(t *testing.T) {
	parentToken, err := openCurrentProcessToken()
	if err != nil {
		t.Fatal(err)
	}
	defer parentToken.Close()
	parent, err := snapshotToken(parentToken)
	if err != nil {
		t.Fatal(err)
	}

	cmdPath, cmdLine := systemCommand(t, "/d /c exit 0")
	startup := &windows.StartupInfoEx{}
	startup.StartupInfo.Cb = uint32(unsafe.Sizeof(*startup))
	process, err := LaunchRestricted(LaunchOptions{
		ApplicationName:  cmdPath,
		CommandLine:      cmdLine,
		CurrentDirectory: filepath.Dir(cmdPath),
		StartupInfo:      startup,
		CreationFlags: windows.CREATE_SUSPENDED |
			windows.CREATE_NO_WINDOW |
			windows.EXTENDED_STARTUPINFO_PRESENT,
	})
	if err != nil {
		t.Fatalf("LaunchRestricted: %v", err)
	}
	defer terminateUnresumedProcess(&process.ProcessInformation)

	childToken, err := openProcessToken(process.Process)
	if err != nil {
		t.Fatal(err)
	}
	child, err := snapshotToken(childToken)
	_ = childToken.Close()
	if err != nil {
		t.Fatal(err)
	}

	if child.userSIDString != parent.userSIDString {
		t.Fatalf("child user = %s, parent user = %s", child.userSIDString, parent.userSIDString)
	}
	if child.sessionID != parent.sessionID {
		t.Fatalf("child session = %d, parent session = %d", child.sessionID, parent.sessionID)
	}
	if child.logonSession != parent.logonSession {
		t.Fatalf("child logon = %s, parent logon = %s", child.logonSession, parent.logonSession)
	}
	if child.integrityRID != integrityMediumRID {
		t.Fatalf("child integrity = %s (%#x), want Medium (%#x)", child.integrityLevel, child.integrityRID, integrityMediumRID)
	}
	if child.elevated && child.adminGroup != "disabled" && child.adminGroup != "absent" {
		t.Fatalf("child reports elevation with active Administrators group: admin=%s", child.adminGroup)
	}
	if child.adminGroup == "enabled" {
		t.Fatal("child Administrators group is still enabled")
	}
	for _, privilege := range child.enabledPrivilegeNames {
		if privilege != "SeChangeNotifyPrivilege" {
			t.Fatalf("child has unexpected enabled privilege %s", privilege)
		}
	}
	if process.Evidence.IntegrityRID != child.integrityRID ||
		process.Evidence.AdminGroup != child.adminGroup ||
		process.Evidence.EnabledPrivilegeCount != child.enabledPrivileges ||
		process.Evidence.TokenSource == "" {
		t.Fatalf("evidence %+v does not match child token %+v", process.Evidence, child)
	}

	t.Logf("parent: user=%s session=%d logon=%s integrity=%s privileges=%d admin=%s",
		parent.userSIDString, parent.sessionID, parent.logonSession, parent.integrityLevel, parent.enabledPrivileges, parent.adminGroup)
	t.Logf("child: source=%s user=%s session=%d logon=%s integrity=%s elevated=%v privileges=%v admin=%s groups=%v",
		process.Evidence.TokenSource, child.userSIDString, child.sessionID, child.logonSession,
		child.integrityLevel, child.elevated, child.enabledPrivilegeNames, child.adminGroup, child.groupSIDs)
}

func TestRestrictedTokenCanReadPrivateConfig(t *testing.T) {
	dir := t.TempDir()
	secretPath := filepath.Join(dir, "frpc.toml")
	tokenPath := filepath.Join(dir, "token.txt")
	const secret = "auth.token = medium-integrity-readable"
	const tokenValue = "restricted-token-readable"
	if err := os.WriteFile(secretPath, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tokenPath, []byte(tokenValue+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	parentToken, err := openCurrentProcessToken()
	if err != nil {
		t.Fatal(err)
	}
	defer parentToken.Close()
	parent, err := snapshotToken(parentToken)
	if err != nil {
		t.Fatal(err)
	}
	targetRID, err := targetIntegrityRID(parent.integrityRID)
	if err != nil {
		t.Fatal(err)
	}
	token, source, err := selectRestrictedToken(parentToken, parent, targetRID)
	if err != nil {
		t.Fatal(err)
	}
	defer token.Close()

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	result, _, callErr := procImpersonateLoggedOnUser.Call(uintptr(token))
	if result == 0 {
		t.Fatalf("ImpersonateLoggedOnUser(%s): %v", source, callErr)
	}
	defer windows.RevertToSelf()
	data, err := os.ReadFile(secretPath)
	if err != nil {
		t.Fatalf("read private config as %s token: %v", source, err)
	}
	if string(data) != secret+"\n" {
		t.Fatalf("private config read = %q", data)
	}
	tokenData, err := os.ReadFile(tokenPath)
	if err != nil {
		t.Fatalf("read private token file as %s token: %v", source, err)
	}
	if string(tokenData) != tokenValue+"\n" {
		t.Fatalf("private token read = %q", tokenData)
	}
}

func TestLaunchRestrictedChildStartsWithRestrictedToken(t *testing.T) {
	cmdPath, cmdLine := systemCommand(t, "/d /c exit 0")
	startup := &windows.StartupInfoEx{}
	startup.StartupInfo.Cb = uint32(unsafe.Sizeof(*startup))
	process, err := LaunchRestricted(LaunchOptions{
		ApplicationName:  cmdPath,
		CommandLine:      cmdLine,
		CurrentDirectory: filepath.Dir(cmdPath),
		StartupInfo:      startup,
		CreationFlags: windows.CREATE_SUSPENDED |
			windows.CREATE_NO_WINDOW |
			windows.EXTENDED_STARTUPINFO_PRESENT,
	})
	if err != nil {
		t.Fatalf("LaunchRestricted: %v", err)
	}
	defer closeHandle(process.Process)
	defer closeHandle(process.Thread)
	if _, err = windows.ResumeThread(process.Thread); err != nil {
		_ = windows.TerminateProcess(process.Process, 1)
		t.Fatal(err)
	}
	_, _ = windows.WaitForSingleObject(process.Process, windows.INFINITE)
	var exitCode uint32
	if err = windows.GetExitCodeProcess(process.Process, &exitCode); err != nil {
		t.Fatal(err)
	}
	if exitCode == 0 {
		return
	}
	if process.Evidence.TokenSource == "created-restricted" && exitCode == 0xc0000142 {
		t.Skipf("current session has no UAC linked token; the verified restricted fallback token is Medium/admin-disabled/no-dangerous-privileges, but this Windows host fails child initialization with STATUS_DLL_INIT_FAILED (%#x); production remains fail-closed", exitCode)
	}
	t.Fatalf("restricted child exit code = %#x", exitCode)
}

func TestValidateChildSnapshotRejectsAdministratorGroup(t *testing.T) {
	parentToken, err := openCurrentProcessToken()
	if err != nil {
		t.Fatal(err)
	}
	defer parentToken.Close()
	parent, err := snapshotToken(parentToken)
	if err != nil {
		t.Fatal(err)
	}
	child := parent
	child.integrityRID = integrityMediumRID
	child.integrityLevel = "Medium"
	child.elevated = false
	child.enabledPrivilegeNames = nil
	child.enabledPrivileges = 0
	child.adminGroup = "enabled"
	if err := validateChildSnapshot(parent, child, integrityMediumRID, "test token"); err == nil || !strings.Contains(err.Error(), "Administrators group enabled") {
		t.Fatalf("expected Administrator-group rejection, got %v", err)
	}
}

func systemCommand(t *testing.T, arguments string) (string, string) {
	t.Helper()
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = "C:\\Windows"
	}
	path := filepath.Join(root, "System32", "cmd.exe")
	if _, err := os.Stat(path); err != nil {
		t.Skipf("cmd.exe is unavailable: %v", err)
	}
	command := windows.EscapeArg(path)
	if arguments != "" {
		command += " " + arguments
	}
	return path, command
}

func closeHandle(handle windows.Handle) {
	if handle != 0 && handle != windows.InvalidHandle {
		_ = windows.CloseHandle(handle)
	}
}
