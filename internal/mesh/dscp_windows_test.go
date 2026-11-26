//go:build windows

package mesh

import (
	"net"
	"testing"
)

func TestConfigureGameSocketMarksUDPForLowLatency(t *testing.T) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := configureGameSocket(conn); err != nil {
		t.Fatal(err)
	}
}
