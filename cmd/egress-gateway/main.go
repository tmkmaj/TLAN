package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/private-radminlan/lanmesh/internal/egressgateway"
)

type natLifecycle interface {
	DetectCapabilities(context.Context) (egressgateway.NATCapabilities, error)
	Plan(context.Context) (string, error)
	Apply(context.Context) error
	Rollback(context.Context) error
}

type natManagerAdapter struct {
	manager *egressgateway.NatManager
}

func (a *natManagerAdapter) DetectCapabilities(ctx context.Context) (egressgateway.NATCapabilities, error) {
	return a.manager.DetectCapabilities(ctx)
}

func (a *natManagerAdapter) Plan(ctx context.Context) (string, error) {
	return a.manager.Plan(ctx)
}

func (a *natManagerAdapter) Apply(ctx context.Context) error {
	return a.manager.Apply(ctx)
}

func (a *natManagerAdapter) Rollback(ctx context.Context) error {
	return a.manager.Rollback(ctx)
}

type runtimeDependencies struct {
	newNAT  func(egressgateway.NATConfig) (natLifecycle, error)
	network networkDependencies
}

func defaultRuntimeDependencies() runtimeDependencies {
	return runtimeDependencies{
		newNAT: func(config egressgateway.NATConfig) (natLifecycle, error) {
			manager, err := egressgateway.NewNATManager(config, nil)
			if err != nil {
				return nil, err
			}
			return &natManagerAdapter{manager: manager}, nil
		},
		network: defaultNetworkDependencies(),
	}
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr, defaultRuntimeDependencies())
	stop()
	os.Exit(code)
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer, dependencies runtimeDependencies) int {
	if ctx == nil {
		ctx = context.Background()
	}
	if stdout == nil {
		stdout = io.Discard
	}
	if stderr == nil {
		stderr = io.Discard
	}
	logger := log.New(stderr, "", log.LstdFlags)

	flags := flag.NewFlagSet("egress-gateway", flag.ContinueOnError)
	flags.SetOutput(stderr)
	configPath := flags.String("config", defaultConfigPath, "path to the YAML gateway configuration")
	check := flags.Bool("check", false, "validate configuration and NAT capabilities without applying rules")
	printPlan := flags.Bool("print-plan", false, "print the NAT dry-run plan without applying rules")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 1
	}
	if flags.NArg() != 0 {
		logger.Printf("unexpected positional arguments: %s", strings.Join(flags.Args(), " "))
		return 1
	}
	if *check && *printPlan {
		logger.Printf("-check and -print-plan are mutually exclusive")
		return 1
	}

	config, err := loadConfig(*configPath)
	if err != nil {
		logger.Printf("configuration error: %v", err)
		return 1
	}
	tlsConfig, err := loadServerTLSConfig(config)
	if err != nil {
		logger.Printf("TLS configuration error: %v", err)
		return 1
	}
	authenticator, err := loadBearerAuthenticator(config.Control.LeaseSecretFile)
	if err != nil {
		logger.Printf("lease authentication error: %v", err)
		return 1
	}
	newNAT := dependencies.newNAT
	if newNAT == nil {
		newNAT = defaultRuntimeDependencies().newNAT
	}
	nat, err := newNAT(config.natConfig())
	if err != nil {
		logger.Printf("NAT configuration error: %v", err)
		return 1
	}

	if *check {
		if err := checkNATCapabilities(ctx, nat); err != nil {
			logger.Printf("configuration check failed: %v", err)
			return 1
		}
		fmt.Fprintln(stderr, "configuration check passed")
		return 0
	}
	if *printPlan {
		plan, err := nat.Plan(ctx)
		if err != nil {
			logger.Printf("NAT plan failed: %v", err)
			return 1
		}
		fmt.Fprint(stdout, plan)
		if !strings.HasSuffix(plan, "\n") {
			fmt.Fprintln(stdout)
		}
		return 0
	}

	if err := ensureStateDir(config.StateDir); err != nil {
		logger.Printf("state directory error: %v", err)
		return 1
	}
	issuer := egressgateway.NewLeaseIssuer(egressgateway.LeaseIssuerConfig{
		GatewayEndpoint: config.Listen,
		DefaultTTL:      egressgateway.DefaultLeaseTTL,
		MaxTTL:          egressgateway.MaxLeaseTTL,
		DefaultLimits:   config.Limits.gatewayLimits(),
	})
	service, err := newGatewayService(config, issuer, dependencies.network, logger)
	if err != nil {
		logger.Printf("gateway policy error: %v", err)
		return 1
	}
	leaseEndpoint, err := resolveLeaseEndpoint(config.Control.LeaseURL)
	if err != nil {
		logger.Printf("lease listener error: %v", err)
		return 1
	}
	if err := serveGateway(ctx, config, issuer, service, nat, tlsConfig, authenticator, leaseEndpoint, logger); err != nil {
		logger.Printf("gateway stopped with error: %v", err)
		return 1
	}
	return 0
}

func loadServerTLSConfig(config gatewayConfig) (*tls.Config, error) {
	certificate, err := tls.LoadX509KeyPair(config.TLSCert, config.TLSKey)
	if err != nil {
		return nil, fmt.Errorf("load server certificate and key: %w", err)
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{certificate},
	}, nil
}

func checkNATCapabilities(ctx context.Context, nat natLifecycle) error {
	if nat == nil {
		return errors.New("NAT manager is not configured")
	}
	capabilities, err := nat.DetectCapabilities(ctx)
	if err != nil {
		return err
	}
	if !capabilities.PlatformSupported {
		return errors.New("NAT is not supported on this platform")
	}
	if capabilities.Backend == egressgateway.NATBackendNone {
		return errors.New("no supported NAT backend is available")
	}
	if !capabilities.IPForwardStateRead {
		return errors.New("IPv4 forwarding state is not readable")
	}
	_, err = nat.Plan(ctx)
	return err
}

func serveGateway(
	ctx context.Context,
	config gatewayConfig,
	issuer *egressgateway.LeaseIssuer,
	service *gatewayService,
	nat natLifecycle,
	tlsConfig *tls.Config,
	authenticator *bearerAuthenticator,
	leaseEndpoint leaseEndpoint,
	logger *log.Logger,
) (returnErr error) {
	if nat == nil || service == nil || issuer == nil || tlsConfig == nil || authenticator == nil {
		return errors.New("gateway runtime dependencies are incomplete")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil
	}
	capabilities, err := nat.DetectCapabilities(ctx)
	if err != nil {
		return fmt.Errorf("detect NAT capabilities: %w", err)
	}
	if !capabilities.PlatformSupported || capabilities.Backend == egressgateway.NATBackendNone {
		return errors.New("no supported NAT backend is available")
	}
	if !capabilities.IPForwardStateRead {
		return errors.New("IPv4 forwarding state is not readable")
	}
	plan, err := nat.Plan(ctx)
	if err != nil {
		return fmt.Errorf("build NAT plan: %w", err)
	}
	logger.Printf("NAT plan:\n%s", strings.TrimSpace(plan))
	if err := nat.Apply(ctx); err != nil {
		return fmt.Errorf("apply NAT rules: %w", err)
	}
	applied := true
	defer func() {
		if !applied {
			return
		}
		rollbackCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if rollbackErr := nat.Rollback(rollbackCtx); rollbackErr != nil {
			logger.Printf("NAT rollback failed: %v", rollbackErr)
			if returnErr == nil {
				returnErr = fmt.Errorf("rollback NAT rules: %w", rollbackErr)
			}
		}
	}()

	leaseRawListener, err := net.Listen("tcp", leaseEndpoint.Addr)
	if err != nil {
		return fmt.Errorf("listen for lease API on %s: %w", leaseEndpoint.Addr, err)
	}
	if err := validateLeaseBoundAddress(leaseRawListener); err != nil {
		_ = leaseRawListener.Close()
		return err
	}
	leaseListener := net.Listener(leaseRawListener)
	if leaseEndpoint.Scheme == "https" {
		leaseListener = tls.NewListener(leaseRawListener, tlsConfig)
	}
	dataRawListener, err := net.Listen("tcp", config.Listen)
	if err != nil {
		_ = leaseListener.Close()
		return fmt.Errorf("listen for egress data on %s: %w", config.Listen, err)
	}
	dataListener := tls.NewListener(dataRawListener, tlsConfig)
	defer dataListener.Close()
	defer leaseListener.Close()

	leaseHTTPHandler := &leaseRevocationHandler{
		next:     egressgateway.NewLeaseHandler(issuer, authenticator),
		registry: service.registry,
	}
	leaseServer := &http.Server{
		Handler:           leaseHTTPHandler,
		ErrorLog:          logger,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	errCh := make(chan error, 3)
	reportError := func(err error) {
		if err == nil {
			return
		}
		select {
		case errCh <- err:
		default:
		}
	}

	var workers sync.WaitGroup
	var sessions sync.WaitGroup
	workers.Add(3)
	go func() {
		defer workers.Done()
		err := acceptDataConnections(runCtx, dataListener, func(connection net.Conn) {
			sessions.Add(1)
			go func() {
				defer sessions.Done()
				service.serveConnection(runCtx, connection)
			}()
		})
		if err != nil && runCtx.Err() == nil {
			reportError(fmt.Errorf("accept egress data connections: %w", err))
		}
	}()
	go func() {
		defer workers.Done()
		err := leaseServer.Serve(leaseListener)
		if err != nil && !errors.Is(err, http.ErrServerClosed) && runCtx.Err() == nil {
			reportError(fmt.Errorf("serve lease API: %w", err))
		}
	}()
	go func() {
		defer workers.Done()
		service.registry.monitor(runCtx, issuer, logger)
	}()

	logger.Printf("egress data listener on %s", dataListener.Addr())
	logger.Printf("lease API listener on %s://%s", leaseEndpoint.Scheme, leaseRawListener.Addr())

	var serveErr error
	select {
	case <-ctx.Done():
	case serveErr = <-errCh:
	}

	cancel()
	service.registry.closeAll()
	_ = dataListener.Close()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
	if err := leaseServer.Shutdown(shutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		if serveErr == nil {
			serveErr = fmt.Errorf("shut down lease API: %w", err)
		}
		logger.Printf("lease API shutdown failed: %v", err)
	}
	shutdownCancel()
	_ = leaseListener.Close()

	workers.Wait()
	sessions.Wait()
	return serveErr
}

func acceptDataConnections(ctx context.Context, listener net.Listener, accept func(net.Conn)) error {
	if listener == nil || accept == nil {
		return errors.New("data listener and accept callback are required")
	}
	for {
		connection, err := listener.Accept()
		if err != nil {
			if ctx != nil && ctx.Err() != nil {
				return nil
			}
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		accept(connection)
	}
}
