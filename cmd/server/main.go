package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/private-radminlan/lanmesh/internal/config"
	"github.com/private-radminlan/lanmesh/internal/control"
	"github.com/private-radminlan/lanmesh/internal/frpauth"
	"github.com/private-radminlan/lanmesh/internal/network"
	"github.com/private-radminlan/lanmesh/internal/observability"
	"github.com/private-radminlan/lanmesh/internal/reuseport"
	"github.com/private-radminlan/lanmesh/internal/storage"
)

const gracefulRelayDrainTimeout = 30 * time.Second

func main() {
	logger := observability.NewLogger(os.Stderr, slog.LevelInfo)
	slog.SetDefault(logger)
	if err := run(); err != nil {
		slog.Error("server exited", "error", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, created, err := config.LoadOrCreate(config.FileName)
	if err != nil {
		return err
	}
	if created {
		path, pathErr := filepath.Abs(config.FileName)
		if pathErr != nil {
			path = config.FileName
		}
		fmt.Printf("TLAN initialized default configuration: %s\n", path)
		fmt.Println("Review the listen addresses, network CIDR, join_code, and admin_token, then start tlan-server again.")
		fmt.Println("Keep security.admin_token private; share only network.join_code with members.")
		return nil
	}
	if len([]byte(cfg.Security.AdminToken)) < 24 {
		slog.Warn("admin token is shorter than 24 bytes", "reason", "weak_secret", "advice", "keep the admin listener private and protect it with TLS or a firewall")
	}
	if err := cfg.EnsureDataDir(); err != nil {
		return err
	}
	store, err := storage.Open(cfg.StateFile())
	if err != nil {
		return err
	}
	if cfg.Network.JoinCode != "" {
		n, err := store.EnsurePrivateNetwork(cfg.Network.Name, cfg.Network.JoinCode, cfg.Network.CIDR)
		if err != nil {
			return fmt.Errorf("configure private join network: %w", err)
		}
		slog.Info("private code enrollment enabled", "network", n.Name)
	}
	if !store.HasServerDisplay() && (strings.TrimSpace(cfg.Network.DisplayMode) != "" || strings.TrimSpace(cfg.Network.DisplayAlias) != "") {
		if _, err := store.SetServerDisplay(cfg.Network.DisplayMode, cfg.Network.DisplayAlias); err != nil {
			return fmt.Errorf("configure server display: %w", err)
		}
	}
	var frpStore *frpauth.Store
	var frpPlugin *http.Server
	if cfg.FRP.EffectiveMode() == frpauth.ModeManaged {
		opts := frpAuthOptions(cfg)
		if store.HasFRPPortRange() || len(opts.AllowedPorts) == 0 {
			portRange := store.FRPPortRange()
			opts.AllowedPorts = []frpauth.PortRange{{Start: portRange.Start, End: portRange.End}}
		}
		frpStore, err = frpauth.NewStore(opts)
		if err != nil {
			return fmt.Errorf("open managed FRP authorization store: %w", err)
		}
		pluginListener, err := net.Listen("tcp", cfg.FRP.PluginListen)
		if err != nil {
			return fmt.Errorf("listen for managed FRP plugin: %w", err)
		}
		frpPlugin = &http.Server{
			Handler:           frpauth.NewPluginHandler(frpStore),
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       15 * time.Second,
			IdleTimeout:       30 * time.Second,
			MaxHeaderBytes:    16 * 1024,
		}
		go func() {
			if serveErr := frpPlugin.Serve(pluginListener); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
				slog.Error("managed FRP plugin listener stopped", "error", serveErr)
			}
		}()
		defer frpPlugin.Close()
		slog.Info("managed FRP plugin listening", "listen", cfg.FRP.PluginListen)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, terminationSignal())
	defer stop()
	// HTTPS Upgrade relay is always available on the control service. The
	// optional legacy dedicated TCP listener shares this same broker.
	relayQueueDepth := cfg.Server.RelayQueueDepth
	if relayQueueDepth == 0 {
		relayQueueDepth = 64
	}
	relay := network.NewRelayBrokerWithLimits(network.RelayLimits{PacketLimit: 64 * 1024, QueueDepth: relayQueueDepth, MaxSessions: 4096, IdleTimeout: 2 * time.Minute})
	defer relay.Close()
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				relay.CleanupExpired()
			}
		}
	}()
	if cfg.Server.RelayListen != "" {
		listener, err := relayListener(cfg)
		if err != nil {
			return err
		}
		defer listener.Close()
		slog.Info("optional TCP relay listening", "listen", cfg.Server.RelayListen)
		go serveRelay(ctx, listener, relay)
	}
	stunSetting := strings.TrimSpace(cfg.Server.STUNListen)
	if stunSetting != "" && !strings.EqualFold(stunSetting, "off") {
		address, err := net.ResolveUDPAddr("udp4", cfg.Server.STUNListen)
		if err != nil {
			return err
		}
		socket, err := net.ListenUDP("udp4", address)
		if err != nil {
			return err
		}
		defer socket.Close()
		slog.Info("STUN binding listening", "network", "udp", "listen", cfg.Server.STUNListen)
		go func() {
			if err := network.ServeSTUN(ctx, socket); err != nil {
				slog.Error("STUN stopped", "error", err)
			}
		}()
	}
	adminNet, adminTLS, err := adminListener(cfg)
	if err != nil {
		return err
	}
	if adminNet != nil {
		defer adminNet.Close()
	}
	service := &control.Server{
		Store: store, AdminToken: cfg.Security.AdminToken, Relay: relay, FRP: frpStore,
		FRPBootstrap:      func() (control.FRPBootstrapConfig, error) { return buildFRPBootstrap(cfg) },
		DisableEnrollment: cfg.Network.JoinCode == "", StartedAt: time.Now().UTC(),
		ControlListen: cfg.Server.Listen, ControlTLS: cfg.Server.TLSCert != "",
		AdminListen: cfg.Server.AdminListen, AdminTLS: adminTLS,
		MinClientVersion: cfg.Server.MinClientVersion,
		DataDirSummary:   dataDirSummary(cfg.Storage.DataDir),
	}
	controlServer := &http.Server{Addr: cfg.Server.Listen, Handler: service.Handler(), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, IdleTimeout: 90 * time.Second, MaxHeaderBytes: 32 * 1024}
	// TLSNextProto disables HTTP/2 for the native HTTP/1.1 Upgrade relay.
	controlServer.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}}
	controlServer.TLSNextProto = make(map[string]func(*http.Server, *tls.Conn, http.Handler))
	controlNet, err := reuseport.Listen("tcp", cfg.Server.Listen)
	if err != nil {
		return fmt.Errorf("listen for control service: %w", err)
	}
	defer controlNet.Close()
	if cfg.Server.TLSCert != "" {
		cert, loadErr := tls.LoadX509KeyPair(cfg.Server.TLSCert, cfg.Server.TLSKey)
		if loadErr != nil {
			return fmt.Errorf("load control TLS certificate: %w", loadErr)
		}
		controlNet = tls.NewListener(controlNet, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}})
	}
	controlDone := make(chan error, 1)
	go func() {
		serveErr := controlServer.Serve(controlNet)
		if errors.Is(serveErr, http.ErrServerClosed) {
			serveErr = nil
		}
		controlDone <- serveErr
	}()
	slog.Info("control and relay listening", "listen", cfg.Server.Listen, "reuseport", reuseport.Enabled(), "relay_queue_depth", relayQueueDepth)
	var adminServer *http.Server
	var adminDone <-chan error
	if adminNet != nil {
		adminServer = &http.Server{
			Handler:           service.AdminHandlerForListen(cfg.Security.AdminToken, adminTLS, cfg.Server.AdminListen),
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			IdleTimeout:       90 * time.Second,
			MaxHeaderBytes:    32 * 1024,
		}
		if adminTLS {
			adminServer.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		}
		adminErrCh := make(chan error, 1)
		adminDone = adminErrCh
		go func() {
			serveErr := adminServer.Serve(adminNet)
			if errors.Is(serveErr, http.ErrServerClosed) {
				serveErr = nil
			}
			adminErrCh <- serveErr
		}()
		if adminTLS {
			slog.Info("admin console listening", "listen", cfg.Server.AdminListen, "tls", true)
		} else {
			slog.Info("admin console listening", "listen", cfg.Server.AdminListen, "tls", false)
		}
	}
	var runErr error
	select {
	case err := <-controlDone:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			runErr = err
		}
	case err := <-adminDone:
		if err != nil {
			runErr = fmt.Errorf("admin console stopped: %w", err)
		}
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := controlServer.Shutdown(shutdown); err != nil {
		slog.Error("control server shutdown failed", "error", err)
		if runErr == nil {
			runErr = err
		}
	}
	if adminServer != nil {
		if err := adminServer.Shutdown(shutdown); err != nil {
			slog.Error("admin console shutdown failed", "error", err)
			if runErr == nil {
				runErr = err
			}
		}
	}
	if frpPlugin != nil {
		if err := frpPlugin.Shutdown(shutdown); err != nil {
			slog.Error("managed FRP plugin shutdown failed", "error", err)
			if runErr == nil {
				runErr = err
			}
		}
	}
	drainCtx, drainCancel := context.WithTimeout(context.Background(), gracefulRelayDrainTimeout)
	defer drainCancel()
	waitRelayDrain(drainCtx, relay)
	return runErr
}

func adminListener(cfg config.Config) (net.Listener, bool, error) {
	address := strings.TrimSpace(cfg.Server.AdminListen)
	if address == "" {
		return nil, false, nil
	}
	certPath := strings.TrimSpace(cfg.Server.AdminTLSCert)
	keyPath := strings.TrimSpace(cfg.Server.AdminTLSKey)
	if (certPath == "") != (keyPath == "") {
		return nil, false, fmt.Errorf("server.admin_tls_cert and server.admin_tls_key must be set together")
	}
	if certPath == "" {
		if !isLoopbackAddress(address) {
			if !cfg.Server.AdminAllowInsecureHTTP {
				return nil, false, fmt.Errorf("server.admin_allow_insecure_http must be true to bind %s without TLS", address)
			}
			slog.Warn("admin console is listening without TLS", "listen", address, "reason", "plaintext_admin_listener", "advice", "restrict it to a private network and firewall")
		}
		listener, err := reuseport.Listen("tcp", address)
		if err != nil {
			return nil, false, fmt.Errorf("listen for admin console: %w", err)
		}
		return listener, false, nil
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, false, fmt.Errorf("load admin TLS certificate: %w", err)
	}
	raw, err := reuseport.Listen("tcp", address)
	if err != nil {
		return nil, false, fmt.Errorf("listen for admin console: %w", err)
	}
	return tls.NewListener(raw, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}), true, nil
}

func isLoopbackAddress(address string) bool {
	host, _, err := net.SplitHostPort(strings.TrimSpace(address))
	if err != nil {
		return false
	}
	host = strings.TrimSpace(strings.Trim(host, "[]"))
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func frpAuthOptions(cfg config.Config) frpauth.Options {
	configuredPorts, _ := cfg.FRP.AllowedPorts.Ranges()
	ports := make([]frpauth.PortRange, 0, len(configuredPorts))
	for _, item := range configuredPorts {
		ports = append(ports, frpauth.PortRange{Start: item.Start, End: item.End})
	}
	domains, _ := cfg.FRP.AllowedDomains.Domains()
	return frpauth.Options{
		StatePath:   cfg.FRPLeaseStateFile(),
		ServerID:    cfg.FRP.ServerID,
		CoreVersion: cfg.FRP.EffectiveCoreVersion(),
		LeaseTTL:    time.Duration(cfg.FRP.EffectiveLeaseTTLSeconds()) * time.Second,
		Limits: frpauth.Limits{
			MaxRulesPerLease:    cfg.FRP.MaxRulesPerLease,
			MaxLeasesPerDevice:  cfg.FRP.MaxLeasesPerDevice,
			MaxPortsPerDevice:   cfg.FRP.MaxPortsPerDevice,
			MaxDomainsPerDevice: cfg.FRP.MaxDomainsPerDevice,
			MaxDomainsPerRule:   cfg.FRP.MaxDomainsPerRule,
		},
		AllowedPorts:   ports,
		AllowedDomains: append([]string(nil), domains...),
	}
}

func relayListener(cfg config.Config) (net.Listener, error) {
	if (cfg.Server.RelayCert == "") != (cfg.Server.RelayKey == "") {
		return nil, fmt.Errorf("server.relay_cert and server.relay_key must be set together")
	}
	if cfg.Server.RelayCert == "" {
		slog.Warn("dedicated relay port is plaintext", "reason", "plaintext_relay_listener", "advice", "use a private network or TLS")
		return reuseport.Listen("tcp", cfg.Server.RelayListen)
	}
	cert, err := tls.LoadX509KeyPair(cfg.Server.RelayCert, cfg.Server.RelayKey)
	if err != nil {
		return nil, err
	}
	raw, err := reuseport.Listen("tcp", cfg.Server.RelayListen)
	if err != nil {
		return nil, err
	}
	return tls.NewListener(raw, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}), nil
}

func serveRelay(ctx context.Context, listener net.Listener, broker *network.RelayBroker) {
	defer listener.Close()
	go func() { <-ctx.Done(); listener.Close() }()
	server := &network.RelayServer{Broker: broker}
	slots := make(chan struct{}, 512)
	for {
		c, err := listener.Accept()
		if err != nil {
			return
		}
		select {
		case slots <- struct{}{}:
			go func(c net.Conn) { defer func() { <-slots }(); _ = server.ServeConn(c) }(c)
		default:
			c.Close()
		}
	}
}

func dataDirSummary(dir string) string {
	base := filepath.Base(filepath.Clean(dir))
	if base == "." || base == string(filepath.Separator) {
		return "."
	}
	return base
}
func buildFRPBootstrap(cfg config.Config) (control.FRPBootstrapConfig, error) {
	mode := cfg.FRP.EffectiveMode()
	if mode == "disabled" {
		return control.FRPBootstrapConfig{Enabled: false}, nil
	}
	token := strings.TrimSpace(cfg.FRP.ClientToken)
	if token == "" && strings.TrimSpace(cfg.FRP.ClientTokenFile) != "" {
		data, err := os.ReadFile(strings.TrimSpace(cfg.FRP.ClientTokenFile))
		if err != nil {
			return control.FRPBootstrapConfig{}, fmt.Errorf("read frp client token file: %w", err)
		}
		token = strings.TrimSpace(string(data))
	}
	if token == "" {
		return control.FRPBootstrapConfig{Enabled: false}, nil
	}
	var caPEM string
	if path := strings.TrimSpace(cfg.FRP.ClientCAFile); path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return control.FRPBootstrapConfig{}, fmt.Errorf("read frp client CA file: %w", err)
		}
		caPEM = strings.TrimSpace(string(data))
	}
	port := cfg.FRP.ClientPort
	if port <= 0 {
		port = 7000
	}
	transport := strings.ToLower(strings.TrimSpace(cfg.FRP.ClientTransport))
	if transport == "" {
		transport = "tcp"
	}
	return control.FRPBootstrapConfig{
		Enabled:       true,
		Mode:          mode,
		Host:          strings.TrimSpace(cfg.FRP.ClientHost),
		Port:          port,
		Transport:     transport,
		TLSServerName: strings.TrimSpace(cfg.FRP.ClientTLSServerName),
		ServerID:      cfg.FRP.ServerID,
		Token:         token,
		CAPEM:         caPEM,
	}, nil
}

func waitRelayDrain(ctx context.Context, relay *network.RelayBroker) {
	if relay == nil {
		return
	}
	sessions := len(relay.Snapshot())
	if sessions == 0 {
		slog.Info("server drain complete", "relay_sessions", 0)
		return
	}
	started := time.Now()
	slog.Info("server draining existing relay sessions", "relay_sessions", sessions, "timeout", gracefulRelayDrainTimeout)
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			remaining := len(relay.Snapshot())
			slog.Warn("relay drain timed out", "remaining_sessions", remaining, "elapsed_ms", time.Since(started).Milliseconds())
			return
		case <-ticker.C:
			relay.CleanupExpired()
			remaining := len(relay.Snapshot())
			if remaining == 0 {
				slog.Info("server drain complete", "elapsed_ms", time.Since(started).Milliseconds())
				return
			}
		}
	}
}
