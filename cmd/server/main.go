package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
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
	"github.com/private-radminlan/lanmesh/internal/storage"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
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
		fmt.Printf("TmkNetworkLAN 首次启动：已生成配置 %s\n", path)
		fmt.Println("请检查配置中的监听地址、网络和令牌，然后再次运行程序。")
		fmt.Println("生成的管理员令牌仅供服务器维护使用；network.join_code 可以分享给熟人。")
		return nil
	}
	if len([]byte(cfg.Security.AdminToken)) < 24 {
		log.Print("warning: security.admin_token is shorter than 24 bytes; keep the admin listener private and protect it with TLS or a firewall")
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
		log.Printf("private code enrollment enabled for network %s", n.Name)
	}
	var frpStore *frpauth.Store
	var frpPlugin *http.Server
	if cfg.FRP.EffectiveMode() == frpauth.ModeManaged {
		frpStore, err = frpauth.NewStore(frpAuthOptions(cfg))
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
				log.Printf("managed FRP plugin listener stopped: %v", serveErr)
			}
		}()
		defer frpPlugin.Close()
		log.Printf("managed FRP plugin listening on %s", cfg.FRP.PluginListen)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, terminationSignal())
	defer stop()
	// HTTPS Upgrade relay is always available on the control service. The
	// optional legacy dedicated TCP listener shares this same broker.
	relay := network.NewRelayBrokerWithLimits(network.RelayLimits{PacketLimit: 64 * 1024, QueueDepth: 64, MaxSessions: 4096, IdleTimeout: 2 * time.Minute})
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
		log.Printf("optional TCP relay listening on %s", cfg.Server.RelayListen)
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
		log.Printf("STUN Binding listening on UDP %s", cfg.Server.STUNListen)
		go func() {
			if err := network.ServeSTUN(ctx, socket); err != nil {
				log.Printf("STUN stopped: %v", err)
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
		DisableEnrollment: cfg.Network.JoinCode == "", StartedAt: time.Now().UTC(),
		ControlListen: cfg.Server.Listen, ControlTLS: cfg.Server.TLSCert != "",
		AdminListen: cfg.Server.AdminListen, AdminTLS: adminTLS,
		DataDirSummary: dataDirSummary(cfg.Storage.DataDir),
	}
	controlServer := &http.Server{Addr: cfg.Server.Listen, Handler: service.Handler(), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, IdleTimeout: 90 * time.Second, MaxHeaderBytes: 32 * 1024}
	// TLSNextProto disables HTTP/2 for the native HTTP/1.1 Upgrade relay.
	controlServer.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}}
	controlServer.TLSNextProto = make(map[string]func(*http.Server, *tls.Conn, http.Handler))
	controlDone := make(chan error, 1)
	go func() {
		if cfg.Server.TLSCert != "" {
			controlDone <- controlServer.ListenAndServeTLS(cfg.Server.TLSCert, cfg.Server.TLSKey)
		} else {
			controlDone <- controlServer.ListenAndServe()
		}
	}()
	log.Printf("TmkNetworkLAN control + Upgrade relay listening on %s", cfg.Server.Listen)
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
			log.Printf("admin console listening on %s with TLS", cfg.Server.AdminListen)
		} else {
			log.Printf("admin console listening on %s (plaintext)", cfg.Server.AdminListen)
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
	relay.Close()
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if adminServer != nil {
		if err := adminServer.Shutdown(shutdown); err != nil {
			log.Printf("admin console shutdown: %v", err)
			if runErr == nil {
				runErr = err
			}
		}
	}
	if frpPlugin != nil {
		if err := frpPlugin.Shutdown(shutdown); err != nil {
			log.Printf("managed FRP plugin shutdown: %v", err)
			if runErr == nil {
				runErr = err
			}
		}
	}
	if err := controlServer.Shutdown(shutdown); err != nil {
		log.Printf("control server shutdown: %v", err)
		if runErr == nil {
			runErr = err
		}
	}
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
			log.Printf("warning: admin console is listening on %s without TLS; restrict it to a private network and firewall", address)
		}
		listener, err := net.Listen("tcp", address)
		if err != nil {
			return nil, false, fmt.Errorf("listen for admin console: %w", err)
		}
		return listener, false, nil
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, false, fmt.Errorf("load admin TLS certificate: %w", err)
	}
	raw, err := net.Listen("tcp", address)
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
		log.Print("warning: dedicated Relay port is plaintext; use a private network or TLS")
		return net.Listen("tcp", cfg.Server.RelayListen)
	}
	cert, err := tls.LoadX509KeyPair(cfg.Server.RelayCert, cfg.Server.RelayKey)
	if err != nil {
		return nil, err
	}
	return tls.Listen("tcp", cfg.Server.RelayListen, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
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
