//go:build !linux

package reuseport

import "net"

// Enabled reports whether listeners can share a TCP port across processes.
func Enabled() bool { return false }

// Listen is the portable fallback. Windows has no SO_REUSEPORT equivalent for
// TCP, so upgrades there remain subject to the operating system's listener
// handoff behavior.
func Listen(network, address string) (net.Listener, error) {
	return net.Listen(network, address)
}
