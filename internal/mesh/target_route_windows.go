//go:build windows

package mesh

import (
	"encoding/binary"
	"net"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func meshInterfaceIndex(name string) (uint32, error) {
	if name == "" {
		name = "TLAN"
	}
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return 0, err
	}
	if iface.Index <= 0 {
		return 0, ErrTargetRouteUnavailable
	}
	return uint32(iface.Index), nil
}

func configureMeshDialer(dialer *net.Dialer, interfaceIndex uint32) error {
	if dialer == nil || interfaceIndex == 0 {
		return ErrTargetRouteUnavailable
	}
	dialer.Control = func(_, _ string, raw syscall.RawConn) error {
		var socketErr error
		if err := raw.Control(func(fd uintptr) {
			socketErr = bindSocketToMeshInterface(windows.Handle(fd), interfaceIndex)
		}); err != nil {
			return err
		}
		return socketErr
	}
	return nil
}

func bindSocketToMeshInterface(handle windows.Handle, interfaceIndex uint32) error {
	const ipUnicastIf = 31
	var networkOrder [4]byte
	binary.BigEndian.PutUint32(networkOrder[:], interfaceIndex)
	value := *(*uint32)(unsafe.Pointer(&networkOrder[0]))
	return windows.SetsockoptInt(handle, windows.IPPROTO_IP, ipUnicastIf, int(value))
}
