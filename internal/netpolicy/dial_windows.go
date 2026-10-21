//go:build windows

package netpolicy

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// DialPinned resolves an endpoint, rejects forbidden TLAN paths, and pins the
// TCP socket to the interface selected by the same route observation. This
// prevents a DNS answer or system route change between checking and dialing
// from silently moving the connection onto the TLAN interface.
func DialPinned(ctx context.Context, observer Observer, endpoint Endpoint, protected []netip.Prefix, meshInterface string) (net.Conn, error) {
	planner := Planner{Observer: observer}
	routes, err := planner.ResolveControlRoutes(ctx, endpoint, protected, meshInterface)
	if err != nil {
		return nil, err
	}
	var lastErr error
	for _, route := range routes {
		conn, err := dialRoute(ctx, endpoint, route)
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("no route was available")
	}
	return nil, lastErr
}

func dialRoute(ctx context.Context, endpoint Endpoint, route Route) (net.Conn, error) {
	address := net.JoinHostPort(endpoint.Host, fmt.Sprint(endpoint.Port))
	if route.Destination.IsValid() {
		address = net.JoinHostPort(route.Destination.String(), fmt.Sprint(endpoint.Port))
	}
	dialer := net.Dialer{Timeout: 10 * time.Second}
	if route.InterfaceIndex != 0 && !route.Destination.IsLoopback() {
		index := route.InterfaceIndex
		dialer.Control = func(_, _ string, raw syscall.RawConn) error {
			var socketErr error
			if err := raw.Control(func(fd uintptr) {
				socketErr = bindSocketToInterface(windows.Handle(fd), index)
			}); err != nil {
				return err
			}
			return socketErr
		}
	}
	return dialer.DialContext(ctx, "tcp4", address)
}

func bindSocketToInterface(handle windows.Handle, interfaceIndex uint32) error {
	const ipUnicastIf = 31
	var networkOrder [4]byte
	binary.BigEndian.PutUint32(networkOrder[:], interfaceIndex)
	value := *(*uint32)(unsafe.Pointer(&networkOrder[0]))
	return windows.SetsockoptInt(handle, windows.IPPROTO_IP, ipUnicastIf, int(value))
}
