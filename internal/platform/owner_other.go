//go:build !windows

package platform

import (
	"fmt"
	"os/user"
)

// CurrentOwner returns a stable local user identity on non-Windows systems.
// Windows production builds use the SID implementation instead.
func CurrentOwner() (string, error) {
	current, err := user.Current()
	if err != nil {
		return "", fmt.Errorf("read current user: %w", err)
	}
	if current.Uid != "" {
		return "uid:" + current.Uid, nil
	}
	if current.Username != "" {
		return "user:" + current.Username, nil
	}
	return "", fmt.Errorf("current user has no stable identity")
}
