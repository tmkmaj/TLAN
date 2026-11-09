package egressgateway

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
)

var (
	ErrUnsupported          = errors.New("egress NAT is unsupported on this platform")
	ErrNATUnavailable       = errors.New("no supported NAT backend is available")
	ErrInvalidNATConfig     = errors.New("invalid NAT configuration")
	ErrNATInterfaceNotFound = errors.New("configured egress interface does not exist")
)

const (
	defaultNATMarker       = "tmknetworklan-egress"
	defaultNFTTable        = "tmknetworklan_egress"
	defaultIPTablesChain   = "TLAN_EGRESS"
	defaultIPForwardPath   = "/proc/sys/net/ipv4/ip_forward"
	defaultEgressInterface = ""
)

var natIdentifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$`)

// CommandRunner executes one external command. Tests supply a fake recorder;
// production uses ExecCommandRunner.
type CommandRunner interface {
	Run(ctx context.Context, name string, args ...string) error
}

// ExecCommandRunner executes commands without a shell.
type ExecCommandRunner struct{}

// Run implements CommandRunner.
func (ExecCommandRunner) Run(ctx context.Context, name string, args ...string) error {
	output, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		message := strings.TrimSpace(string(output))
		if message == "" {
			return fmt.Errorf("run %s: %w", name, err)
		}
		return fmt.Errorf("run %s: %w: %s", name, err, message)
	}
	return nil
}

// NATBackend identifies the firewall backend selected for this host.
type NATBackend string

const (
	NATBackendNone     NATBackend = "none"
	NATBackendNFTables NATBackend = "nftables"
	NATBackendIPTables NATBackend = "iptables"
)

// NATCapabilities reports observed firewall support.
type NATCapabilities struct {
	PlatformSupported  bool
	NFTables           bool
	IPTables           bool
	IPForwardStateRead bool
	Backend            NATBackend
}

// NATConfig describes the single source CIDR and egress interface managed by
// this gateway. The manager never flushes a global ruleset.
type NATConfig struct {
	EgressInterface string
	SourceCIDR      string
	IPForwardPath   string
	Marker          string
	NFTTable        string
	IPTablesChain   string
}

// NatConfig is an idiomatic alias for NATConfig.
type NatConfig = NATConfig

// NatCapabilities is an idiomatic alias for NATCapabilities.
type NatCapabilities = NATCapabilities

// Normalize applies safe defaults and validates all user-controlled values.
func (c NATConfig) Normalize() (NATConfig, error) {
	c.EgressInterface = strings.TrimSpace(c.EgressInterface)
	c.SourceCIDR = strings.TrimSpace(c.SourceCIDR)
	c.IPForwardPath = strings.TrimSpace(c.IPForwardPath)
	c.Marker = strings.TrimSpace(c.Marker)
	c.NFTTable = strings.TrimSpace(c.NFTTable)
	c.IPTablesChain = strings.TrimSpace(c.IPTablesChain)
	if c.IPForwardPath == "" {
		c.IPForwardPath = defaultIPForwardPath
	}
	if c.Marker == "" {
		c.Marker = defaultNATMarker
	}
	if c.NFTTable == "" {
		c.NFTTable = defaultNFTTable
	}
	if c.IPTablesChain == "" {
		c.IPTablesChain = defaultIPTablesChain
	}
	if c.EgressInterface == defaultEgressInterface || c.EgressInterface == "" || len(c.EgressInterface) > 15 ||
		strings.ContainsAny(c.EgressInterface, " \t\r\n/\\") {
		return NATConfig{}, fmt.Errorf("%w: egress interface is required and must be a valid short interface name", ErrInvalidNATConfig)
	}
	prefix, err := netip.ParsePrefix(c.SourceCIDR)
	if err != nil || !prefix.Addr().Is4() || prefix.Bits() == 0 {
		return NATConfig{}, fmt.Errorf("%w: source CIDR must be a non-default IPv4 prefix", ErrInvalidNATConfig)
	}
	c.SourceCIDR = prefix.Masked().String()
	if strings.ContainsAny(c.Marker, "\x00\r\n") {
		return NATConfig{}, fmt.Errorf("%w: marker contains control characters", ErrInvalidNATConfig)
	}
	if !natIdentifierPattern.MatchString(c.Marker) {
		return NATConfig{}, fmt.Errorf("%w: marker must be a stable product identifier", ErrInvalidNATConfig)
	}
	if !natIdentifierPattern.MatchString(c.NFTTable) {
		return NATConfig{}, fmt.Errorf("%w: nftables table name is invalid", ErrInvalidNATConfig)
	}
	if !natIdentifierPattern.MatchString(c.IPTablesChain) || len(c.IPTablesChain) > 28 {
		return NATConfig{}, fmt.Errorf("%w: iptables chain name is invalid", ErrInvalidNATConfig)
	}
	if strings.ContainsAny(c.IPForwardPath, "\x00\r\n") {
		return NATConfig{}, fmt.Errorf("%w: ip_forward path is invalid", ErrInvalidNATConfig)
	}
	return c, nil
}

type natCommand struct {
	name          string
	args          []string
	ignoreFailure bool
}

// NatManager owns one idempotent NAT lifecycle. All state transitions are
// serialized; only the configured dedicated table/chain and marker are touched.
type NatManager struct {
	mu                sync.Mutex
	config            NATConfig
	runner            CommandRunner
	platformSupported bool
	applied           bool
	backend           NATBackend
	forwardOriginal   []byte
	forwardSaved      bool
	forwardChanged    bool
}

// NewNATManager validates config and creates a manager for the current OS.
func NewNATManager(config NATConfig, runner CommandRunner) (*NatManager, error) {
	normalized, err := config.Normalize()
	if err != nil {
		return nil, err
	}
	if !platformNATSupported() {
		return nil, ErrUnsupported
	}
	if runner == nil {
		runner = ExecCommandRunner{}
	}
	return &NatManager{config: normalized, runner: runner, platformSupported: true}, nil
}

// NewNatManager is an alias for NewNATManager.
func NewNatManager(config NatConfig, runner CommandRunner) (*NatManager, error) {
	return NewNATManager(config, runner)
}

func newNATManager(config NATConfig, runner CommandRunner, platformSupported bool) (*NatManager, error) {
	normalized, err := config.Normalize()
	if err != nil {
		return nil, err
	}
	if runner == nil {
		runner = ExecCommandRunner{}
	}
	return &NatManager{config: normalized, runner: runner, platformSupported: platformSupported}, nil
}

// DetectCapabilities prefers nftables and falls back to iptables. A missing
// backend is reported as ErrNATUnavailable instead of attempting partial rules.
func (m *NatManager) DetectCapabilities(ctx context.Context) (NATCapabilities, error) {
	if !m.platformSupported {
		return NATCapabilities{}, ErrUnsupported
	}
	caps := NATCapabilities{PlatformSupported: true}
	if err := m.runner.Run(ctx, "nft", "--version"); err == nil {
		caps.NFTables = true
	}
	if err := m.runner.Run(ctx, "iptables", "--version"); err == nil {
		caps.IPTables = true
	}
	switch {
	case caps.NFTables:
		caps.Backend = NATBackendNFTables
	case caps.IPTables:
		caps.Backend = NATBackendIPTables
	default:
		return caps, ErrNATUnavailable
	}
	if original, err := readIPForward(m.config.IPForwardPath); err == nil && validForwardValue(original) {
		caps.IPForwardStateRead = true
	}
	return caps, nil
}

// Plan returns a textual dry-run for the selected backend. It accepts an
// optional context and never changes firewall or sysctl state.
func (m *NatManager) Plan(contexts ...context.Context) (string, error) {
	ctx := context.Background()
	if len(contexts) > 1 {
		return "", fmt.Errorf("%w: at most one context is allowed", ErrInvalidNATConfig)
	}
	if len(contexts) == 1 && contexts[0] != nil {
		ctx = contexts[0]
	}
	if !m.platformSupported {
		return "", ErrUnsupported
	}
	caps, err := m.DetectCapabilities(ctx)
	if err != nil {
		return "", err
	}
	if err := m.ensureInterface(ctx); err != nil {
		return "", err
	}
	commands := m.applyCommands(caps.Backend)
	var builder strings.Builder
	fmt.Fprintf(&builder, "backend: %s\nmarker: %s\nsource_cidr: %s\negress_interface: %s\n", caps.Backend, m.config.Marker, m.config.SourceCIDR, m.config.EgressInterface)
	fmt.Fprintf(&builder, "ip_forward: %s -> 1, restore on rollback\n", m.config.IPForwardPath)
	for _, command := range commands {
		fmt.Fprintf(&builder, "%s %s\n", command.name, strings.Join(command.args, " "))
	}
	return builder.String(), nil
}

func (m *NatManager) ensureInterface(ctx context.Context) error {
	if err := m.runner.Run(ctx, "ip", "link", "show", "dev", m.config.EgressInterface); err != nil {
		return fmt.Errorf("%w: %s: %v", ErrNATInterfaceNotFound, m.config.EgressInterface, err)
	}
	return nil
}

func (m *NatManager) applyCommands(backend NATBackend) []natCommand {
	switch backend {
	case NATBackendNFTables:
		table := m.config.NFTTable
		return []natCommand{
			{name: "nft", args: []string{"delete", "table", "inet", table}, ignoreFailure: true},
			{name: "nft", args: []string{"add", "table", "inet", table}},
			{name: "nft", args: []string{"add", "chain", "inet", table, "postrouting", "{", "type", "nat", "hook", "postrouting", "priority", "srcnat", ";", "policy", "accept", ";", "}"}},
			{name: "nft", args: []string{"add", "rule", "inet", table, "postrouting", "ip", "saddr", m.config.SourceCIDR, "oifname", m.config.EgressInterface, "masquerade", "comment", m.config.Marker}},
		}
	case NATBackendIPTables:
		chain := m.config.IPTablesChain
		jump := []string{"-t", "nat", "-w", "POSTROUTING", "-m", "comment", "--comment", m.config.Marker, "-j", chain}
		deleteJump := append([]string{"-t", "nat", "-w", "-D"}, jump[3:]...)
		insertJump := append([]string{"-t", "nat", "-w", "-I", "POSTROUTING", "1"}, jump[4:]...)
		return []natCommand{
			{name: "iptables", args: deleteJump, ignoreFailure: true},
			{name: "iptables", args: []string{"-t", "nat", "-w", "-N", chain}, ignoreFailure: true},
			{name: "iptables", args: []string{"-t", "nat", "-w", "-S", chain}},
			{name: "iptables", args: []string{"-t", "nat", "-w", "-F", chain}},
			{name: "iptables", args: []string{"-t", "nat", "-w", "-A", chain, "-m", "comment", "--comment", m.config.Marker, "-s", m.config.SourceCIDR, "-o", m.config.EgressInterface, "-j", "MASQUERADE"}},
			{name: "iptables", args: insertJump},
		}
	default:
		return nil
	}
}

func (m *NatManager) rollbackCommands(backend NATBackend) []natCommand {
	switch backend {
	case NATBackendNFTables:
		return []natCommand{{name: "nft", args: []string{"delete", "table", "inet", m.config.NFTTable}}}
	case NATBackendIPTables:
		chain := m.config.IPTablesChain
		return []natCommand{
			{name: "iptables", args: []string{"-t", "nat", "-w", "-D", "POSTROUTING", "-m", "comment", "--comment", m.config.Marker, "-j", chain}},
			{name: "iptables", args: []string{"-t", "nat", "-w", "-F", chain}},
			{name: "iptables", args: []string{"-t", "nat", "-w", "-X", chain}},
		}
	default:
		return nil
	}
}

// Apply installs only this product's NAT rules and enables IPv4 forwarding.
// Repeated calls are no-ops. Failure rolls back any partial product rules.
func (m *NatManager) Apply(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.applied {
		return nil
	}
	if !m.platformSupported {
		return ErrUnsupported
	}
	caps, err := m.DetectCapabilities(ctx)
	if err != nil {
		return err
	}
	if err := m.ensureInterface(ctx); err != nil {
		return err
	}
	original, err := readIPForward(m.config.IPForwardPath)
	if err != nil || !validForwardValue(original) {
		return fmt.Errorf("%w: read %s: %v", ErrInvalidNATConfig, m.config.IPForwardPath, err)
	}

	commands := m.applyCommands(caps.Backend)
	for _, command := range commands {
		if err := m.runCommand(ctx, command); err != nil {
			_ = m.runAll(ctx, m.rollbackCommands(caps.Backend))
			return err
		}
	}

	m.forwardOriginal = append([]byte(nil), original...)
	m.forwardSaved = true
	if !forwardEnabled(original) {
		m.forwardChanged = true
		if err := os.WriteFile(m.config.IPForwardPath, []byte("1"), 0o644); err != nil {
			_ = m.runAll(ctx, m.rollbackCommands(caps.Backend))
			_ = restoreIPForward(m.config.IPForwardPath, m.forwardOriginal)
			m.forwardOriginal = nil
			m.forwardSaved = false
			m.forwardChanged = false
			return fmt.Errorf("enable ip_forward: %w", err)
		}
	}
	m.backend = caps.Backend
	m.applied = true
	return nil
}

// Rollback removes this product's rules and restores the exact previous
// ip_forward contents. It is a no-op when Apply succeeded without changes.
func (m *NatManager) Rollback(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.applied {
		return nil
	}
	var failures []error
	for _, command := range m.rollbackCommands(m.backend) {
		if err := m.runCommand(ctx, command); err != nil {
			failures = append(failures, err)
		}
	}
	if m.forwardSaved && m.forwardChanged {
		if err := restoreIPForward(m.config.IPForwardPath, m.forwardOriginal); err != nil {
			failures = append(failures, fmt.Errorf("restore ip_forward: %w", err))
		}
	}
	if len(failures) != 0 {
		return errors.Join(failures...)
	}
	m.applied = false
	m.backend = NATBackendNone
	m.forwardOriginal = nil
	m.forwardSaved = false
	m.forwardChanged = false
	return nil
}

// Close is an alias for Rollback.
func (m *NatManager) Close(ctx context.Context) error {
	return m.Rollback(ctx)
}

// Applied reports whether the manager currently owns an applied NAT lifecycle.
func (m *NatManager) Applied() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.applied
}

func (m *NatManager) runAll(ctx context.Context, commands []natCommand) error {
	var failures []error
	for _, command := range commands {
		if err := m.runCommand(ctx, command); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

func (m *NatManager) runCommand(ctx context.Context, command natCommand) error {
	err := m.runner.Run(ctx, command.name, command.args...)
	if err != nil && !command.ignoreFailure {
		return err
	}
	return nil
}

func readIPForward(path string) ([]byte, error) {
	return os.ReadFile(path)
}

func restoreIPForward(path string, original []byte) error {
	return os.WriteFile(path, original, 0o644)
}

func validForwardValue(value []byte) bool {
	switch strings.TrimSpace(string(value)) {
	case "0", "1":
		return true
	default:
		return false
	}
}

func forwardEnabled(value []byte) bool {
	return strings.TrimSpace(string(value)) == "1"
}
