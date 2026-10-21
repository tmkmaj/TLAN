//go:build windows

package netpolicy

import (
	"context"
	"net"
	"net/netip"

	"golang.org/x/sys/windows"
)

type windowsObserver struct{}

func NewObserver() Observer { return windowsObserver{} }

func (windowsObserver) ResolveRoutes(ctx context.Context, host string, port int) ([]Route, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
	if err != nil {
		return nil, err
	}
	seen := make(map[netip.Addr]struct{}, len(addresses))
	out := make([]Route, 0, len(addresses))
	for _, address := range addresses {
		address = address.Unmap()
		if !address.Is4() {
			continue
		}
		if _, exists := seen[address]; exists {
			continue
		}
		seen[address] = struct{}{}
		if address.IsLoopback() {
			out = append(out, Route{Destination: address, InterfaceName: "Loopback"})
			continue
		}
		var index uint32
		if err := windows.GetBestInterfaceEx(&windows.SockaddrInet4{
			Port: port,
			Addr: address.As4(),
		}, &index); err != nil {
			return nil, err
		}
		iface, err := net.InterfaceByIndex(int(index))
		if err != nil {
			return nil, err
		}
		out = append(out, Route{
			Destination: address, InterfaceIndex: index, InterfaceName: iface.Name,
			InterfacePrefixes: interfacePrefixes(iface),
		})
	}
	if len(out) == 0 {
		return nil, &net.AddrError{Err: "no IPv4 address", Addr: host}
	}
	return out, nil
}
