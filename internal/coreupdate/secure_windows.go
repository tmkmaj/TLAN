//go:build windows

package coreupdate

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

const (
	daclSecurityInformation          = 0x00000004
	protectedDaclSecurityInformation = 0x80000000
)

var (
	advapi32Secure      = syscall.NewLazyDLL("advapi32.dll")
	kernel32Secure      = syscall.NewLazyDLL("kernel32.dll")
	procConvertSD       = advapi32Secure.NewProc("ConvertStringSecurityDescriptorToSecurityDescriptorW")
	procSetFileSecurity = advapi32Secure.NewProc("SetFileSecurityW")
	procLocalFree       = kernel32Secure.NewProc("LocalFree")
)

func secureDirectory(path string) error {
	if err := os.Chmod(path, 0o700); err != nil {
		return err
	}
	return setCurrentUserDACL(path, true)
}

func secureFile(path string, mode os.FileMode) error {
	if err := os.Chmod(path, mode); err != nil {
		return err
	}
	return setCurrentUserDACL(path, false)
}

func setCurrentUserDACL(path string, directory bool) error {
	token, err := syscall.OpenCurrentProcessToken()
	if err != nil {
		return fmt.Errorf("open current process token: %w", err)
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		return fmt.Errorf("read current process user: %w", err)
	}
	sid, err := user.User.Sid.String()
	if err != nil {
		return fmt.Errorf("render current user SID: %w", err)
	}
	sddl := "D:P(A;;FA;;;" + sid + ")"
	if directory {
		sddl = "D:P(A;OICI;FA;;;" + sid + ")"
	}
	sddlPtr, err := syscall.UTF16PtrFromString(sddl)
	if err != nil {
		return fmt.Errorf("encode security descriptor: %w", err)
	}
	var descriptor uintptr
	ok, _, callErr := procConvertSD.Call(
		uintptr(unsafe.Pointer(sddlPtr)),
		1,
		uintptr(unsafe.Pointer(&descriptor)),
		0,
	)
	if ok == 0 {
		return windowsCallError("convert security descriptor", callErr)
	}
	defer procLocalFree.Call(descriptor)

	pathPtr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return fmt.Errorf("encode path for DACL: %w", err)
	}
	ok, _, callErr = procSetFileSecurity.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		uintptr(daclSecurityInformation|protectedDaclSecurityInformation),
		descriptor,
	)
	if ok == 0 {
		return windowsCallError("set protected DACL", callErr)
	}
	return nil
}

func windowsCallError(op string, err error) error {
	if err == nil || err == syscall.Errno(0) {
		return fmt.Errorf("%s failed", op)
	}
	return fmt.Errorf("%s: %w", op, err)
}
