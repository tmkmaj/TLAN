//go:build windows

package frp

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

func secureDirectory(path string) error {
	return securePath(path, true)
}

func secureFile(path string) error {
	return securePath(path, false)
}

func securePath(path string, directory bool) error {
	sid, err := currentUserSID()
	if err != nil {
		return err
	}
	ace := "A;;FA;;;"
	if directory {
		ace = "A;OICI;FA;;;"
	}
	sddl := fmt.Sprintf("D:P(%s%s)(%sSY)", ace, sid, ace)
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return fmt.Errorf("build private DACL: %w", err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return fmt.Errorf("read private DACL: %w", err)
	}
	if err = windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil); err != nil {
		return fmt.Errorf("apply private DACL to %s: %w", path, err)
	}
	return nil
}

func currentUserSID() (string, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return "", fmt.Errorf("read current user SID: %w", err)
	}
	if user == nil || user.User.Sid == nil {
		return "", fmt.Errorf("current user SID is unavailable")
	}
	return user.User.Sid.String(), nil
}

func writePrivateFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if err := secureDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	temp := path + ".tmp"
	_ = os.Remove(temp)
	file, err := os.OpenFile(temp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	cleanup := true
	defer func() {
		_ = file.Close()
		if cleanup {
			_ = os.Remove(temp)
		}
	}()
	if err = secureFile(temp); err != nil {
		return err
	}
	if _, err = file.Write(data); err != nil {
		return err
	}
	if err = file.Sync(); err != nil {
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	if err = os.Rename(temp, path); err != nil {
		return err
	}
	cleanup = false
	return secureFile(path)
}
