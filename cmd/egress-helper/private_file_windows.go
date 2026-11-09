//go:build windows

package main

import (
	"errors"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

func checkPrivateFile(path string, _ os.FileInfo) error {
	descriptor, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return fmt.Errorf("read owner or DACL: %w", err)
	}
	owner, _, err := descriptor.Owner()
	if err != nil {
		return fmt.Errorf("read file owner: %w", err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return fmt.Errorf("read current user: %w", err)
	}
	if user == nil || user.User.Sid == nil || owner == nil {
		return errors.New("file owner or current user is unavailable")
	}
	systemSID, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return fmt.Errorf("create SYSTEM SID: %w", err)
	}
	administratorsSID, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return fmt.Errorf("create Administrators SID: %w", err)
	}
	if !owner.Equals(user.User.Sid) && !owner.Equals(systemSID) && !owner.Equals(administratorsSID) {
		return errors.New("file owner is not the current user, SYSTEM, or Administrators")
	}
	control, _, err := descriptor.Control()
	if err != nil {
		return fmt.Errorf("read DACL control: %w", err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		return errors.New("DACL is not protected from inheritance")
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return fmt.Errorf("read DACL: %w", err)
	}
	if dacl == nil || dacl.AceCount == 0 {
		return errors.New("DACL is empty or absent")
	}
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, index, &ace); err != nil {
			return fmt.Errorf("read DACL ACE %d: %w", index, err)
		}
		if ace == nil {
			return fmt.Errorf("DACL ACE %d is nil", index)
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return fmt.Errorf("ACE %d has unsupported type %d", index, ace.Header.AceType)
		}
		if ace.Header.AceFlags&windows.INHERITED_ACE != 0 {
			return fmt.Errorf("ACE %d is inherited", index)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.Equals(user.User.Sid) && !sid.Equals(systemSID) {
			return fmt.Errorf("ACE %d grants access to a principal other than the current user or SYSTEM", index)
		}
	}
	return nil
}
