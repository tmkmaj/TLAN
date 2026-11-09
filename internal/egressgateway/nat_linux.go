//go:build linux

package egressgateway

// platformNATSupported reports that the NAT lifecycle is available on Linux.
func platformNATSupported() bool {
	return true
}
