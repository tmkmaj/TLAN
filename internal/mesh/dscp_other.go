//go:build !windows

package mesh

import "net"

func configureGameSocket(_ *net.UDPConn) error { return nil }
