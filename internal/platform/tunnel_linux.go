//go:build linux

package platform

import (
	"fmt"
	"net/netip"
	"os/exec"
	"strconv"

	"golang.zx2c4.com/wireguard/tun"
)

func openTunnel(name string, address netip.Prefix, mtu int, _ TunnelOptions) (*IPTunnel, error) {
	if name == "" {
		name = "tmklan0"
	}
	device, err := tun.CreateTUN(name, mtu)
	if err != nil {
		return nil, fmt.Errorf("create Linux TUN (CAP_NET_ADMIN required): %w", err)
	}
	actual, err := device.Name()
	if err != nil {
		device.Close()
		return nil, err
	}
	for _, args := range [][]string{{"address", "add", address.String(), "dev", actual}, {"link", "set", "dev", actual, "mtu", strconv.Itoa(mtu), "up"}, {"route", "add", "255.255.255.255/32", "dev", actual, "metric", "5"}, {"route", "add", "224.0.0.0/4", "dev", actual, "metric", "5"}} {
		if output, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			device.Close()
			return nil, fmt.Errorf("configure Linux TUN: %w: %s", err, output)
		}
	}
	return &IPTunnel{Device: device}, nil
}
