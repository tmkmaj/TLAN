//go:build !windows

package netpolicy

import (
	"context"
	"errors"
	"net"
	"net/netip"
)

func DialPinned(context.Context, Observer, Endpoint, []netip.Prefix, string) (net.Conn, error) {
	return nil, errors.New("interface-pinned TCP dialing is only supported on Windows")
}
