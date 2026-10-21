package main

import (
	"bytes"
	"fmt"

	"golang.org/x/sys/unix"
)

func setBindCapability(path string) error {
	// Linux VFS_CAP_REVISION_2 | VFS_CAP_FLAGS_EFFECTIVE, with only
	// CAP_NET_BIND_SERVICE (bit 10) in the permitted set. Works on kernel 3.10.
	value := []byte{1, 0, 0, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	if err := unix.Setxattr(path, "security.capability", value, 0); err != nil {
		return fmt.Errorf("set Caddy port-binding capability (filesystem must support file capabilities): %w", err)
	}
	got := make([]byte, 64)
	n, err := unix.Getxattr(path, "security.capability", got)
	if err != nil {
		return err
	}
	if !bytes.Equal(got[:n], value) {
		return fmt.Errorf("Caddy capability verification failed")
	}
	return nil
}
