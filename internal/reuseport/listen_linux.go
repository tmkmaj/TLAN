//go:build linux

package reuseport

import (
	"context"
	"fmt"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// Enabled reports whether listeners can share a TCP port across processes.
func Enabled() bool { return true }

// Listen creates a TCP listener with SO_REUSEADDR and SO_REUSEPORT. Service
// upgrades can therefore start the replacement process before the old process
// stops accepting, then let the old process drain its existing sessions.
func Listen(network, address string) (net.Listener, error) {
	config := net.ListenConfig{Control: func(_, _ string, raw syscall.RawConn) error {
		var socketErr error
		if err := raw.Control(func(fd uintptr) {
			if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
				socketErr = err
				return
			}
			if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
				socketErr = err
			}
		}); err != nil {
			return err
		}
		if socketErr != nil {
			return fmt.Errorf("configure SO_REUSEPORT: %w", socketErr)
		}
		return nil
	}}
	return config.Listen(context.Background(), network, address)
}
