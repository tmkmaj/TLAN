package control

import (
	"bufio"
	"github.com/private-radminlan/lanmesh/core"
	"net"
	"net/http"
	"strings"

	"github.com/private-radminlan/lanmesh/internal/network"
)

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

// relayStream carries encrypted WireGuard datagrams over the same HTTPS
// origin as the control API. It needs HTTP/1.1 Upgrade support in the proxy.
func (s *Server) relayStream(w http.ResponseWriter, r *http.Request) {
	s.relaySlotsOnce.Do(func() { s.relaySlots = make(chan struct{}, 512) })
	select {
	case s.relaySlots <- struct{}{}:
		defer func() { <-s.relaySlots }()
	default:
		writeError(w, 503, "relay stream capacity reached")
		return
	}
	if s.Relay == nil {
		writeError(w, 503, "relay disabled")
		return
	}
	if r.Method != http.MethodGet || !strings.EqualFold(r.Header.Get("Upgrade"), "lanmesh-relay") {
		writeError(w, 400, "HTTP Upgrade lanmesh-relay required")
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		writeError(w, 505, "HTTP/1.1 required")
		return
	}
	connection, rw, err := hijacker.Hijack()
	if err != nil {
		return
	}
	if _, err = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: lanmesh-relay\r\n\r\n"); err != nil {
		connection.Close()
		return
	}
	if err = rw.Flush(); err != nil {
		connection.Close()
		return
	}
	relayServer := &network.RelayServer{Broker: s.Relay}
	if member, ok := memberIdentity(r); ok {
		relayServer.AllowedDevice = core.DeviceID(member.DeviceID)
	}
	_ = relayServer.ServeConn(&bufferedConn{connection, rw.Reader})
}
