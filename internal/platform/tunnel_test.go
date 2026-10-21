package platform

import (
	"errors"
	"testing"
)

func TestIPTunnelCloseReturnsCleanupError(t *testing.T) {
	sentinel := errors.New("cleanup failed")
	tunnel := &IPTunnel{cleanup: func() error { return sentinel }}
	if err := tunnel.Close(); !errors.Is(err, sentinel) {
		t.Fatalf("Close error = %v", err)
	}
}
