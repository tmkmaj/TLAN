package network

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/private-radminlan/lanmesh/core"
)

type StreamRelay struct {
	conn   net.Conn
	reader *bufio.Reader
	mu     sync.Mutex
}

func DialHTTPRelay(ctx context.Context, baseURL, token string, ticket RelayTicket, device core.DeviceID) (*StreamRelay, error) {
	return DialHTTPRelayWithRoots(ctx, baseURL, token, ticket, device, nil)
}

// WithRoots supports a private CA without disabling certificate validation.
func DialHTTPRelayWithRoots(ctx context.Context, baseURL, token string, ticket RelayTicket, device core.DeviceID, roots *x509.CertPool) (*StreamRelay, error) {
	u, err := url.Parse(baseURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return nil, errors.New("invalid control URL")
	}
	address := u.Host
	if u.Port() == "" {
		port := "80"
		if u.Scheme == "https" {
			port = "443"
		}
		address = net.JoinHostPort(u.Hostname(), port)
	}
	dialer := &net.Dialer{Timeout: 8 * time.Second}
	var c net.Conn
	if u.Scheme == "https" {
		c, err = (&tls.Dialer{NetDialer: dialer, Config: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12, ServerName: u.Hostname(), NextProtos: []string{"http/1.1"}}}).DialContext(ctx, "tcp", address)
	} else {
		c, err = dialer.DialContext(ctx, "tcp", address)
	}
	if err != nil {
		return nil, err
	}
	success := false
	// DialContext only covers connection establishment. Keep cancellation active
	// through HTTP Upgrade and ticket authentication, then hand off ownership.
	stopCancel := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer func() {
		stopCancel()
		if !success {
			c.Close()
		}
	}()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	u.Path = "/api/v1/relay/stream"
	u.RawQuery = ""
	u.Fragment = ""
	req, _ := http.NewRequest(http.MethodGet, u.String(), nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "lanmesh-relay")
	if strings.HasPrefix(token, "member_") {
		req.Header.Set("Authorization", "Bearer "+token)
	} else {
		req.Header.Set("X-Admin-Token", token)
	}
	if err = req.Write(c); err != nil {
		return nil, err
	}
	r := bufio.NewReader(c)
	response, err := http.ReadResponse(r, req)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != 101 {
		return nil, fmt.Errorf("relay upgrade: %s", response.Status)
	}
	if err = json.NewEncoder(c).Encode(RelayHandshake{Ticket: ticket, Device: device}); err != nil {
		return nil, err
	}
	line, err := readHandshakeLine(r, 4096)
	if err != nil {
		return nil, err
	}
	var answer relayHandshakeResponse
	if err = json.Unmarshal(line, &answer); err != nil {
		return nil, err
	}
	if !answer.OK {
		return nil, fmt.Errorf("relay rejected: %s", answer.Error)
	}
	_ = c.SetDeadline(time.Time{})
	if !stopCancel() || ctx.Err() != nil {
		return nil, ctx.Err()
	}
	success = true
	return &StreamRelay{conn: c, reader: r}, nil
}
func (c *StreamRelay) Send(payload []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	return writeRelayPacket(c.conn, payload, defaultRelayPacketLimit)
}
func (c *StreamRelay) ReceivePacket() ([]byte, error) {
	return readRelayPacket(c.reader, defaultRelayPacketLimit)
}
func (c *StreamRelay) Close() error { return c.conn.Close() }
