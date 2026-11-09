package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/private-radminlan/lanmesh/internal/egress"
)

const (
	tlsHandshakeTimeout = 15 * time.Second
	sessionPollInterval = 200 * time.Millisecond
	maxCABundleBytes    = 4 << 20
)

var errSessionUnavailable = errors.New("egress session is not ready")

// proxyConfig is the fully loaded runtime configuration. Secret bytes stay in
// memory only and are never included in command-line arguments or logs.
type proxyConfig struct {
	ListenAddr     string
	ServerAddr     string
	ServerName     string
	CAPath         string
	ProfileID      string
	RuleID         string
	DeviceID       string
	LeaseID        string
	PolicyVersion  int
	CapabilityFile string
	Capability     string
	Username       string
	PasswordFile   string
	Password       string
	MaxConnections int
}

type tunnelStream interface {
	io.Reader
	io.Writer
	CloseWrite() error
	Close() error
}

type tunnelSession interface {
	OpenStream(streamID uint32) (tunnelStream, error)
	SendDatagram(payload []byte) error
	ReceiveDatagram(ctx context.Context) ([]byte, error)
	Snapshot() egress.EgressSnapshot
}

type tlsDialer struct {
	address    string
	serverName string
	roots      *x509.CertPool
}

func (d *tlsDialer) Dial(ctx context.Context) (net.Conn, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	handshakeCtx, cancel := context.WithTimeout(ctx, tlsHandshakeTimeout)
	defer cancel()

	raw, err := (&net.Dialer{
		Timeout:   tlsHandshakeTimeout,
		KeepAlive: 30 * time.Second,
	}).DialContext(handshakeCtx, "tcp", d.address)
	if err != nil {
		return nil, fmt.Errorf("dial egress gateway: %w", err)
	}
	tlsConn := tls.Client(raw, &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: d.serverName,
		RootCAs:    d.roots,
	})
	if err := tlsConn.HandshakeContext(handshakeCtx); err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("TLS handshake with egress gateway: %w", err)
	}
	return tlsConn, nil
}

func loadCAPool(path string) (*x509.CertPool, error) {
	if path == "" {
		return nil, errors.New("CA bundle path is required")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open CA bundle: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat CA bundle: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("CA bundle must be a regular file")
	}
	if info.Size() <= 0 || info.Size() > maxCABundleBytes {
		return nil, fmt.Errorf("CA bundle size must be between 1 and %d bytes", maxCABundleBytes)
	}
	pemData, err := io.ReadAll(io.LimitReader(file, maxCABundleBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read CA bundle: %w", err)
	}
	if len(pemData) > maxCABundleBytes {
		return nil, fmt.Errorf("CA bundle exceeds %d bytes", maxCABundleBytes)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemData) {
		return nil, errors.New("CA bundle contains no usable PEM certificate")
	}
	return pool, nil
}

func newEgressSession(cfg proxyConfig, roots *x509.CertPool) (*egress.Session, error) {
	if roots == nil {
		return nil, errors.New("TLS root pool is required")
	}
	dialer := &tlsDialer{
		address:    cfg.ServerAddr,
		serverName: cfg.ServerName,
		roots:      roots,
	}
	session, err := egress.NewSession(egress.SessionConfig{
		Dialer:            dialer,
		Secret:            egress.DeriveSessionSecret(cfg.Capability),
		ProfileID:         cfg.ProfileID,
		RuleID:            cfg.RuleID,
		DeviceID:          cfg.DeviceID,
		LeaseID:           cfg.LeaseID,
		Capability:        cfg.Capability,
		PolicyVersion:     cfg.PolicyVersion,
		HandshakeTimeout:  tlsHandshakeTimeout,
		KeepaliveInterval: 20 * time.Second,
		PeerTimeout:       60 * time.Second,
	})
	if err != nil {
		return nil, fmt.Errorf("create egress session: %w", err)
	}
	return session, nil
}

type egressTunnel struct {
	session *egress.Session
}

func (t *egressTunnel) OpenStream(streamID uint32) (tunnelStream, error) {
	if err := ensureSessionActive(t.session); err != nil {
		return nil, err
	}
	stream, err := t.session.OpenStream(streamID)
	if err != nil {
		return nil, err
	}
	return stream, nil
}

func (t *egressTunnel) SendDatagram(payload []byte) error {
	if err := ensureSessionActive(t.session); err != nil {
		return err
	}
	return t.session.SendDatagram(payload)
}

func (t *egressTunnel) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	if err := ensureSessionActive(t.session); err != nil {
		return nil, err
	}
	return t.session.ReceiveDatagram(ctx)
}

func (t *egressTunnel) Snapshot() egress.EgressSnapshot {
	return t.session.Snapshot()
}

func ensureSessionActive(session *egress.Session) error {
	if session == nil {
		return errSessionUnavailable
	}
	state := session.Snapshot().State
	if state != egress.StateRunning && state != egress.StateDegraded {
		return fmt.Errorf("%w: state is %s", errSessionUnavailable, state)
	}
	return nil
}

// monitorSession makes readiness fail-closed as soon as the underlying session
// leaves an active state. markFailed closes the listener and all live clients.
func monitorSession(ctx context.Context, session *egress.Session, proxy *proxy) {
	ticker := time.NewTicker(sessionPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-proxy.done:
			return
		case <-ticker.C:
			snapshot := session.Snapshot()
			if snapshot.State != egress.StateRunning && snapshot.State != egress.StateDegraded {
				detail := snapshot.LastError
				if detail == "" {
					detail = "session stopped unexpectedly"
				}
				proxy.markFailed(fmt.Errorf("%w: state=%s: %s", errSessionUnavailable, snapshot.State, detail))
				return
			}
			proxy.updateReadiness(snapshot)
		}
	}
}
