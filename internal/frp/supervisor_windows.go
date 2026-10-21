//go:build windows

package frp

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf16"
	"unsafe"

	"github.com/private-radminlan/lanmesh/internal/winproc"
	"golang.org/x/sys/windows"
)

type launchedProcess struct {
	Process      windows.Handle
	Job          windows.Handle
	PID          uint32
	CreationTime uint64
	Stdout       windows.Handle
	Stderr       windows.Handle
	Stdin        windows.Handle
	Token        winproc.Evidence
}

func preflightRestrictedExecutable(exePath string) error {
	startup := windows.StartupInfoEx{}
	startup.StartupInfo.Cb = uint32(unsafe.Sizeof(startup))
	envBlock := restrictedEnvironmentBlock()
	launched, err := winproc.LaunchRestricted(winproc.LaunchOptions{
		ApplicationName:  exePath,
		CommandLine:      windows.EscapeArg(exePath) + " -v",
		CurrentDirectory: filepath.Dir(exePath),
		Environment:      &envBlock[0],
		StartupInfo:      &startup,
		CreationFlags: windows.CREATE_SUSPENDED | windows.CREATE_NO_WINDOW |
			windows.CREATE_UNICODE_ENVIRONMENT | windows.EXTENDED_STARTUPINFO_PRESENT,
	})
	if err != nil {
		return fmt.Errorf("restricted frpc preflight could not create a verified token: %w", err)
	}
	proc := launched.ProcessInformation
	if _, err = windows.ResumeThread(proc.Thread); err != nil {
		_ = windows.TerminateProcess(proc.Process, 1)
		closeHandles(proc.Thread, proc.Process)
		return fmt.Errorf("restricted frpc preflight resume failed: %w", err)
	}
	_ = windows.CloseHandle(proc.Thread)
	event, waitErr := windows.WaitForSingleObject(proc.Process, 10000)
	if waitErr != nil {
		_ = windows.TerminateProcess(proc.Process, 1)
		_, _ = windows.WaitForSingleObject(proc.Process, 3000)
		_ = windows.CloseHandle(proc.Process)
		return fmt.Errorf("restricted frpc preflight wait failed: %w", waitErr)
	}
	if event != uint32(windows.WAIT_OBJECT_0) {
		_ = windows.TerminateProcess(proc.Process, 1)
		_, _ = windows.WaitForSingleObject(proc.Process, 3000)
		_ = windows.CloseHandle(proc.Process)
		return fmt.Errorf("restricted frpc preflight wait result %#x; refusing administrator-token fallback", event)
	}
	var exitCode uint32
	if err = windows.GetExitCodeProcess(proc.Process, &exitCode); err != nil {
		_ = windows.CloseHandle(proc.Process)
		return fmt.Errorf("restricted frpc preflight exit status failed: %w", err)
	}
	_ = windows.CloseHandle(proc.Process)
	if exitCode != 0 {
		return fmt.Errorf(
			"restricted frpc preflight exited with %#x (token source=%s integrity=%s adminGroup=%s privileges=%v); refusing administrator-token fallback",
			exitCode, launched.Evidence.TokenSource, launched.Evidence.IntegrityLevel,
			launched.Evidence.AdminGroup, launched.Evidence.EnabledPrivileges,
		)
	}
	return nil
}
func launchRestricted(exePath, configPath, workingDir string, extraEnv map[string]string) (*launchedProcess, error) {
	if err := preflightRestrictedExecutable(exePath); err != nil {
		return nil, err
	}
	return launchRestrictedArgs(exePath, []string{"-c", configPath}, workingDir, extraEnv)
}

// launchRestrictedArgs is the single restricted-token process launcher used
// by both the long-lived frpc process and short-lived frpc verify. It never
// falls back to the administrator token.
func launchRestrictedArgs(exePath string, args []string, workingDir string, extraEnv map[string]string) (*launchedProcess, error) {
	if strings.TrimSpace(exePath) == "" {
		return nil, fmt.Errorf("restricted frpc executable path is empty")
	}
	if len(args) == 0 {
		return nil, fmt.Errorf("restricted frpc arguments are empty")
	}
	childStdin, parentStdin, err := inheritablePipe()
	if err != nil {
		return nil, err
	}
	parentStdout, childStdout, err := inheritablePipe()
	if err != nil {
		closeHandles(childStdin, parentStdin)
		return nil, err
	}
	parentStderr, childStderr, err := inheritablePipe()
	if err != nil {
		closeHandles(childStdin, parentStdin, parentStdout, childStdout)
		return nil, err
	}
	_ = windows.SetHandleInformation(parentStdin, windows.HANDLE_FLAG_INHERIT, 0)
	_ = windows.SetHandleInformation(parentStdout, windows.HANDLE_FLAG_INHERIT, 0)
	_ = windows.SetHandleInformation(parentStderr, windows.HANDLE_FLAG_INHERIT, 0)

	closeAll := func() error {
		return closeHandlesErr(childStdin, parentStdin, parentStdout, childStdout, parentStderr, childStderr)
	}

	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, withCleanupErrors(err, closeAll())
	}
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err = windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		closeErr := closeAll()
		closeErr = errors.Join(closeErr, windows.CloseHandle(job))
		return nil, withCleanupErrors(fmt.Errorf("configure FRP job object: %w", err), closeErr)
	}

	attrList, err := windows.NewProcThreadAttributeList(1)
	if err != nil {
		closeErr := closeAll()
		closeErr = errors.Join(closeErr, windows.CloseHandle(job))
		return nil, withCleanupErrors(fmt.Errorf("create restricted handle list: %w", err), closeErr)
	}
	defer attrList.Delete()
	handles := []windows.Handle{childStdin, childStdout, childStderr}
	if err = attrList.Update(windows.PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
		unsafe.Pointer(&handles[0]), uintptr(len(handles))*unsafe.Sizeof(handles[0])); err != nil {
		closeErr := closeAll()
		closeErr = errors.Join(closeErr, windows.CloseHandle(job))
		return nil, withCleanupErrors(fmt.Errorf("restrict FRP inherited handles: %w", err), closeErr)
	}

	startup := windows.StartupInfoEx{
		StartupInfo: windows.StartupInfo{
			Flags:     windows.STARTF_USESTDHANDLES,
			StdInput:  childStdin,
			StdOutput: childStdout,
			StdErr:    childStderr,
		},
		ProcThreadAttributeList: attrList.List(),
	}
	startup.StartupInfo.Cb = uint32(unsafe.Sizeof(startup))

	envBlock := restrictedEnvironmentBlock(extraEnv)
	flags := uint32(windows.CREATE_SUSPENDED | windows.CREATE_NO_WINDOW |
		windows.CREATE_UNICODE_ENVIRONMENT | windows.EXTENDED_STARTUPINFO_PRESENT)
	commandLine := windows.ComposeCommandLine(append([]string{exePath}, args...))
	launched, err := winproc.LaunchRestricted(winproc.LaunchOptions{
		ApplicationName:  exePath,
		CommandLine:      commandLine,
		CurrentDirectory: workingDir,
		Environment:      &envBlock[0],
		StartupInfo:      &startup,
		CreationFlags:    flags,
		InheritHandles:   true,
	})
	if err != nil {
		closeErr := closeAll()
		closeErr = errors.Join(closeErr, windows.CloseHandle(job))
		return nil, withCleanupErrors(fmt.Errorf("start bundled frpc with restricted token: %w", err), closeErr)
	}
	proc := launched.ProcessInformation
	closeHandles(childStdin, childStdout, childStderr)

	fail := func(cause error) (*launchedProcess, error) {
		var cleanup []error
		if err := windows.TerminateProcess(proc.Process, 1); err != nil {
			cleanup = append(cleanup, fmt.Errorf("terminate suspended frpc: %w", err))
		}
		if _, err := windows.WaitForSingleObject(proc.Process, 3000); err != nil {
			cleanup = append(cleanup, fmt.Errorf("wait for suspended frpc termination: %w", err))
		}
		cleanup = append(cleanup, closeHandlesErr(proc.Thread, proc.Process, job, parentStdin, parentStdout, parentStderr))
		return nil, withCleanupErrors(cause, cleanup...)
	}
	if err = windows.AssignProcessToJobObject(job, proc.Process); err != nil {
		return fail(fmt.Errorf("assign frpc to owned job object: %w", err))
	}
	if _, err = windows.ResumeThread(proc.Thread); err != nil {
		return fail(fmt.Errorf("resume suspended frpc: %w", err))
	}
	if err := windows.CloseHandle(proc.Thread); err != nil {
		return fail(fmt.Errorf("close suspended frpc thread handle: %w", err))
	}
	proc.Thread = 0

	var creation, exit, kernel, user windows.Filetime
	if err = windows.GetProcessTimes(proc.Process, &creation, &exit, &kernel, &user); err != nil {
		return fail(fmt.Errorf("read frpc creation time: %w", err))
	}
	return &launchedProcess{
		Process:      proc.Process,
		Job:          job,
		PID:          proc.ProcessId,
		CreationTime: uint64(creation.HighDateTime)<<32 | uint64(creation.LowDateTime),
		Stdout:       parentStdout,
		Stderr:       parentStderr,
		Stdin:        parentStdin,
		Token:        launched.Evidence,
	}, nil
}
func inheritablePipe() (read, write windows.Handle, err error) {
	sa := windows.SecurityAttributes{
		Length:        uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		InheritHandle: 1,
	}
	if err = windows.CreatePipe(&read, &write, &sa, 0); err != nil {
		return 0, 0, fmt.Errorf("create FRP process pipe: %w", err)
	}
	return read, write, nil
}

func closeHandles(handles ...windows.Handle) {
	_ = closeHandlesErr(handles...)
}

func closeHandlesErr(handles ...windows.Handle) error {
	var failures []error
	for _, handle := range handles {
		if handle == 0 || handle == windows.InvalidHandle {
			continue
		}
		if err := windows.CloseHandle(handle); err != nil {
			failures = append(failures, fmt.Errorf("close Windows handle %v: %w", handle, err))
		}
	}
	return errors.Join(failures...)
}

func restrictedEnvironment(extra ...map[string]string) []string {
	allow := []string{
		"SystemRoot", "WINDIR", "PATH", "PATHEXT", "TEMP", "TMP",
		"USERPROFILE", "LOCALAPPDATA", "APPDATA", "HOMEDRIVE", "HOMEPATH",
		"COMPUTERNAME", "USERNAME", "USERDOMAIN", "NUMBER_OF_PROCESSORS",
		"PROCESSOR_ARCHITECTURE", "PROCESSOR_IDENTIFIER", "OS", "LANG", "LC_ALL",
	}
	values := make(map[string]string, len(allow))
	for _, key := range allow {
		if value, ok := os.LookupEnv(key); ok {
			values[key] = value
		}
	}
	for _, additions := range extra {
		for key, value := range additions {
			if key != "" {
				values[key] = value
			}
		}
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return strings.ToUpper(keys[i]) < strings.ToUpper(keys[j]) })
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+"="+values[key])
	}
	return parts
}

func restrictedEnvironmentBlock(extra ...map[string]string) []uint16 {
	block := strings.Join(restrictedEnvironment(extra...), "\x00") + "\x00\x00"
	encoded := utf16.Encode([]rune(block))
	if len(encoded) == 0 {
		encoded = []uint16{0, 0}
	}
	return encoded
}

func waitProcess(handle windows.Handle) (uint32, error) {
	event, err := windows.WaitForSingleObject(handle, windows.INFINITE)
	if err != nil {
		return 0, err
	}
	if event != windows.WAIT_OBJECT_0 {
		return 0, fmt.Errorf("unexpected process wait result %#x", event)
	}
	var code uint32
	if err = windows.GetExitCodeProcess(handle, &code); err != nil {
		return 0, err
	}
	return code, nil
}

func processCreationTime(handle windows.Handle) (uint64, error) {
	var creation, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(handle, &creation, &exit, &kernel, &user); err != nil {
		return 0, err
	}
	return uint64(creation.HighDateTime)<<32 | uint64(creation.LowDateTime), nil
}

func terminateOwnedProcess(pid uint32, creationTime uint64) error {
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_TERMINATE|windows.SYNCHRONIZE, false, pid)
	if err != nil {
		if err == windows.ERROR_INVALID_PARAMETER {
			return nil
		}
		return err
	}
	defer windows.CloseHandle(handle)
	actual, err := processCreationTime(handle)
	if err != nil {
		return err
	}
	if actual != creationTime {
		return nil
	}
	if err = windows.TerminateProcess(handle, 1); err != nil && err != windows.ERROR_ACCESS_DENIED {
		return err
	}
	event, waitErr := windows.WaitForSingleObject(handle, 3000)
	if waitErr != nil {
		return fmt.Errorf("wait for owned process termination: %w", waitErr)
	}
	if event != uint32(windows.WAIT_OBJECT_0) {
		return fmt.Errorf("owned process did not terminate, wait result %#x", event)
	}
	return nil
}
