package main

import (
	"context"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/private-radminlan/lanmesh/internal/egress"
)

const explicitProxyBanner = "egress-helper: EXPLICIT PROXY MODE (SOCKS5; apps must be configured), not transparent forwarding"

type cliOptions struct {
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
	Username       string
	PasswordFile   string
	MaxConnections int
	Check          bool
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(runMain(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

func runMain(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fmt.Fprintln(stderr, explicitProxyBanner)
	options, err := parseCLI(args)
	if err != nil {
		fmt.Fprintf(stderr, "egress-helper: %v\n", err)
		return 1
	}
	cfg, roots, err := loadRuntimeConfig(options)
	if err != nil {
		fmt.Fprintf(stderr, "egress-helper: configuration error: %v\n", err)
		return 1
	}
	if options.Check {
		fmt.Fprintln(stdout, "egress-helper: configuration and private files are valid (check mode; no network connection made)")
		return 0
	}
	if err := runExplicitProxy(ctx, cfg, roots, stderr); err != nil {
		fmt.Fprintf(stderr, "egress-helper: %v\n", err)
		return 1
	}
	return 0
}

func parseCLI(args []string) (cliOptions, error) {
	var options cliOptions
	flags := flag.NewFlagSet("egress-helper", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&options.ListenAddr, "listen", "127.0.0.1:1080", "loopback SOCKS5 listen address")
	flags.StringVar(&options.ServerAddr, "server", "", "egress gateway TLS host:port")
	flags.StringVar(&options.ServerName, "servername", "", "required TLS ServerName")
	flags.StringVar(&options.CAPath, "ca", "", "required PEM CA bundle")
	flags.StringVar(&options.ProfileID, "profile", "", "egress profile identifier")
	flags.StringVar(&options.RuleID, "rule", "", "egress rule identifier")
	flags.StringVar(&options.DeviceID, "device", "", "egress device identifier")
	flags.StringVar(&options.LeaseID, "lease", "", "egress lease identifier")
	flags.IntVar(&options.PolicyVersion, "policy-version", 0, "egress policy version")
	flags.StringVar(&options.CapabilityFile, "capability-file", "", "private 0600 file containing the one-time capability")
	flags.StringVar(&options.Username, "username", "", "optional SOCKS5 username")
	flags.StringVar(&options.PasswordFile, "password-file", "", "private 0600 file containing the optional SOCKS5 password")
	flags.IntVar(&options.MaxConnections, "max-connections", 64, "maximum concurrent SOCKS5 connections")
	flags.BoolVar(&options.Check, "check", false, "validate flags and files without connecting")
	if err := flags.Parse(args); err != nil {
		return cliOptions{}, fmt.Errorf("parse flags: %w", err)
	}
	if flags.NArg() != 0 {
		return cliOptions{}, fmt.Errorf("unexpected positional arguments: %v", flags.Args())
	}
	return options, nil
}

func runExplicitProxy(ctx context.Context, cfg proxyConfig, roots *x509.CertPool, stderr io.Writer) error {
	session, err := newEgressSession(cfg, roots)
	if err != nil {
		return err
	}
	if err := session.Start(ctx); err != nil {
		return fmt.Errorf("start egress session: %w", err)
	}
	defer stopEgressSession(session)

	snapshot := session.Snapshot()
	if snapshot.State != egress.StateRunning && snapshot.State != egress.StateDegraded {
		return fmt.Errorf("%w: state=%s: %s", errSessionUnavailable, snapshot.State, snapshot.LastError)
	}
	proxy, err := newProxy(cfg, &egressTunnel{session: session})
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen on explicit SOCKS5 address: %w", err)
	}
	defer listener.Close()
	if ip := addressIP(listener.Addr()); ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("refusing non-loopback listener bound at %s", listener.Addr())
	}

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	proxy.markReady()
	go monitorSession(runCtx, session, proxy)
	fmt.Fprintf(stderr, "egress-helper: listening on %s\n", listener.Addr())

	serveErr := proxy.serve(runCtx, listener)
	cancel()
	if failure := proxy.failureError(); failure != nil {
		return failure
	}
	if serveErr != nil && !errors.Is(serveErr, context.Canceled) {
		return serveErr
	}
	return nil
}

func stopEgressSession(session *egress.Session) {
	if session == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = session.Stop(ctx)
}
