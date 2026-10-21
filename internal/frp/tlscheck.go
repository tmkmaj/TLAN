package frp

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

// preflightTLS proves the configured CA and serverName can authenticate the
// actual FRPS endpoint before a managed frpc process is created.
func preflightTLS(ctx context.Context, cfg Config) error {
	data, err := os.ReadFile(cfg.Profile.Server.TrustedCAPath)
	if err != nil {
		return withCode(CodeTLSUntrusted, fmt.Errorf("read trusted CA: %w", err))
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return codedError(CodeTLSUntrusted, "trusted CA file contains no usable certificate")
	}
	switch cfg.Profile.Server.Transport {
	case "kcp", "quic":
		// KCP and QUIC carry TLS inside their UDP transport. The fixed frpc
		// process performs that handshake; a TCP net/tls preflight cannot
		// represent it and must not turn a valid UDP endpoint into a false
		// failure. CA parsing above still fails closed before launch.
		return nil
	}
	address := net.JoinHostPort(cfg.Profile.Server.Host, fmt.Sprint(cfg.Profile.Server.Port))
	dialer := net.Dialer{Timeout: 6 * time.Second}
	raw, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return withCode(CodeServerUnreachable, fmt.Errorf("connect to FRP server: %w", err))
	}
	defer raw.Close()
	tlsConn := tls.Client(raw, &tls.Config{
		ServerName: cfg.Profile.Server.TLSServerName,
		RootCAs:    pool,
		MinVersion: tls.VersionTLS12,
	})
	handshakeCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	if err = tlsConn.HandshakeContext(handshakeCtx); err != nil {
		lower := strings.ToLower(err.Error())
		if strings.Contains(lower, "certificate") || strings.Contains(lower, "x509") || strings.Contains(lower, "unknown authority") {
			return withCode(CodeTLSUntrusted, err)
		}
		return withCode(CodeServerUnreachable, fmt.Errorf("TLS handshake with FRP server: %w", err))
	}
	return nil
}
