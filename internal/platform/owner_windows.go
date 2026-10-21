//go:build windows

package platform

import (
	"errors"
	"fmt"

	"golang.org/x/sys/windows"
)

// CurrentOwner returns the current user's SID. A SID is stable across display
// name changes and is stronger than matching a process or account name.
func CurrentOwner() (string, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return "", fmt.Errorf("read current user token: %w", err)
	}
	if user == nil || user.User.Sid == nil || !user.User.Sid.IsValid() {
		return "", errors.New("current user token has no valid SID")
	}
	return user.User.Sid.String(), nil
}
