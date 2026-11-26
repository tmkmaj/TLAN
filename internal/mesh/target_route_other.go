//go:build !windows

package mesh

import (
	"net"
)

func meshInterfaceIndex(name string) (uint32, error) {
	if name == "" {
		name = "TLAN"
	}
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return 0, err
	}
	return uint32(iface.Index), nil
}

func configureMeshDialer(_ *net.Dialer, _ uint32) error {
	return ErrTargetRouteUnavailable
}
