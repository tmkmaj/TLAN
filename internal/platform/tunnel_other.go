//go:build !linux && !windows

package platform

import "net/netip"

func openTunnel(string, netip.Prefix, int, TunnelOptions) (*IPTunnel, error) {
	return nil, ErrAdapterUnavailable
}
