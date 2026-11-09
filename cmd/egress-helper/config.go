package main

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/private-radminlan/lanmesh/internal/egress"
)

const (
	maxCapabilityBytes = 4096
	maxPasswordBytes   = 255
)

func loadRuntimeConfig(options cliOptions) (proxyConfig, *x509.CertPool, error) {
	cfg := proxyConfig{
		ListenAddr:     strings.TrimSpace(options.ListenAddr),
		ServerAddr:     strings.TrimSpace(options.ServerAddr),
		ServerName:     strings.TrimSpace(options.ServerName),
		CAPath:         strings.TrimSpace(options.CAPath),
		ProfileID:      strings.TrimSpace(options.ProfileID),
		RuleID:         strings.TrimSpace(options.RuleID),
		DeviceID:       strings.TrimSpace(options.DeviceID),
		LeaseID:        strings.TrimSpace(options.LeaseID),
		PolicyVersion:  options.PolicyVersion,
		CapabilityFile: strings.TrimSpace(options.CapabilityFile),
		Username:       options.Username,
		PasswordFile:   strings.TrimSpace(options.PasswordFile),
		MaxConnections: options.MaxConnections,
	}
	if err := validateLoopbackListen(cfg.ListenAddr); err != nil {
		return proxyConfig{}, nil, err
	}
	if err := validateServerAddress(cfg.ServerAddr); err != nil {
		return proxyConfig{}, nil, err
	}
	if cfg.ServerName == "" {
		return proxyConfig{}, nil, errors.New("-servername is required")
	}
	if strings.ContainsAny(cfg.ServerName, "\x00\r\n\t ") {
		return proxyConfig{}, nil, errors.New("-servername contains invalid characters")
	}
	roots, err := loadCAPool(cfg.CAPath)
	if err != nil {
		return proxyConfig{}, nil, err
	}
	capability, err := readPrivateSecretFile(cfg.CapabilityFile, maxCapabilityBytes)
	if err != nil {
		return proxyConfig{}, nil, fmt.Errorf("capability: %w", err)
	}
	cfg.Capability = capability
	if cfg.Username == "" {
		if cfg.PasswordFile != "" {
			return proxyConfig{}, nil, errors.New("-password-file requires -username")
		}
	} else {
		if len(cfg.Username) > maxPasswordBytes {
			return proxyConfig{}, nil, fmt.Errorf("-username exceeds %d bytes", maxPasswordBytes)
		}
		if cfg.PasswordFile == "" {
			return proxyConfig{}, nil, errors.New("-password-file is required when -username is set")
		}
		password, err := readPrivateSecretFile(cfg.PasswordFile, maxPasswordBytes)
		if err != nil {
			return proxyConfig{}, nil, fmt.Errorf("SOCKS5 password: %w", err)
		}
		if len(password) > maxPasswordBytes {
			return proxyConfig{}, nil, fmt.Errorf("SOCKS5 password exceeds %d bytes", maxPasswordBytes)
		}
		cfg.Password = password
	}
	if _, err := newEgressSession(cfg, roots); err != nil {
		return proxyConfig{}, nil, err
	}
	if _, err := newProxy(cfg, &discardTunnel{}); err != nil {
		return proxyConfig{}, nil, err
	}
	return cfg, roots, nil
}

func validateServerAddress(address string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("invalid -server address: %w", err)
	}
	if host == "" {
		return errors.New("-server host is required")
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return fmt.Errorf("-server has invalid port %q", port)
	}
	return nil
}

// discardTunnel is used only for local configuration validation.
type discardTunnel struct{}

func (*discardTunnel) OpenStream(uint32) (tunnelStream, error) {
	return nil, errSessionUnavailable
}
func (*discardTunnel) SendDatagram([]byte) error { return errSessionUnavailable }
func (*discardTunnel) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	return nil, errSessionUnavailable
}
func (*discardTunnel) Snapshot() egress.EgressSnapshot {
	return egress.EgressSnapshot{State: egress.StateStopped}
}
