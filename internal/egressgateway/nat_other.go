//go:build !linux

package egressgateway

// platformNATSupported reports that the NAT lifecycle is unavailable on
// non-Linux hosts.
func platformNATSupported() bool {
	return false
}
