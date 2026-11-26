//go:build windows

package mesh

import (
	"fmt"
	"net"

	"golang.org/x/sys/windows"
)

const (
	dscpExpeditedForwardingTOS = 0xb8 // DSCP EF (46) << 2
	windowsIPDontFragment      = 14
)

// configureGameSocket marks the WireGuard UDP socket for low-latency delivery
// and enables DF so an oversized datagram fails visibly instead of silently
// fragmenting into a worse path.
func configureGameSocket(conn *net.UDPConn) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		handle := windows.Handle(fd)
		if err := windows.SetsockoptInt(handle, windows.IPPROTO_IP, windows.IP_TOS, dscpExpeditedForwardingTOS); err != nil {
			socketErr = fmt.Errorf("set UDP DSCP EF: %w", err)
			return
		}
		if err := windows.SetsockoptInt(handle, windows.IPPROTO_IP, windowsIPDontFragment, 1); err != nil {
			socketErr = fmt.Errorf("set UDP don't-fragment: %w", err)
		}
	}); err != nil {
		return err
	}
	return socketErr
}
