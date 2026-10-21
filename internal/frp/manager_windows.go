//go:build windows

package frp

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/windows"

	"github.com/private-radminlan/lanmesh/core"
	"github.com/private-radminlan/lanmesh/internal/frpauth"
	"github.com/private-radminlan/lanmesh/internal/netpolicy"
	"github.com/private-radminlan/lanmesh/internal/targetgateway"
)

type Options struct {
	Store               *Store
	CorePath            string
	ExecutableDir       string
	DeviceID            string
	MeshCIDR            string
	NetworkID           string
	MeshInterfaceName   string
	LeaseProvider       LeaseProvider
	MeshTargetProvider  MeshTargetProvider
	NetObserver         netpolicy.Observer
	EndpointRegistry    *EndpointRegistry
	EgressCheckInterval time.Duration
	ReservationProvider func() []TargetReservation
}

const runtimeCeilingFileName = "runtime-ceiling.json"

type Manager struct {
	opMu     sync.Mutex
	mu       sync.Mutex
	runMu    sync.Mutex
	retrying atomic.Bool

	runCancel         context.CancelFunc
	runtimeCeiling    *Config
	runtimeCeilingErr error

	store              *Store
	core               Core
	deviceID           string
	meshMu             sync.RWMutex
	meshCIDRs          []netip.Prefix
	networkID          string
	leaseProvider      LeaseProvider
	meshTargets        MeshTargetProvider
	observer           netpolicy.Observer
	endpoints          *EndpointRegistry
	meshInterface      string
	egressInterval     time.Duration
	reservations       func() []TargetReservation
	observationMu      sync.Mutex
	observationGen     uint64
	observationGate    *netpolicy.ObservationDebouncer
	config             Config
	hasConfig          bool
	state              string
	instance           *managedInstance
	startingInstance   *managedInstance
	instanceGeneration uint64
	instanceSequence   uint64
	lastErr            error
	logs               logRing
	desiredRun         atomic.Bool
}

type managedInstance struct {
	dir            string
	generation     uint64
	configPath     string
	tokenPath      string
	adminPort      int
	adminUser      string
	adminPassword  string
	config         Config
	rendered       RenderedConfig
	admin          *AdminClient
	process        *launchedProcess
	done           chan struct{}
	exitCode       uint32
	stopping       atomic.Bool
	loggedIn       atomic.Bool
	leaseMonitor   atomic.Bool
	leaseMu        sync.Mutex
	lease          *Lease
	leaseCancel    context.CancelFunc
	stopMu         sync.Mutex
	stopped        bool
	stopErr        error
	gateways       []*targetgateway.Gateway
	gatewayMu      sync.RWMutex
	gatewaysByRule map[string]*targetgateway.Gateway
	gatewayCancel  context.CancelFunc
	runtimeCancel  context.CancelFunc
	egressProxy    *egressProxy
	udpEgressProxy *udpEgressProxy
	endpointScope  string
	endpointOwner  *EndpointRegistry
	reapOnce       sync.Once
	reapErr        error
	egressOnce     sync.Once
}

func NewManager(options Options) (*Manager, error) {
	store := options.Store
	if store == nil {
		var err error
		store, err = DefaultStore()
		if err != nil {
			return nil, err
		}
	}
	if err := store.Ensure(); err != nil {
		return nil, err
	}
	var core Core
	if options.CorePath != "" {
		path, err := filepath.Abs(options.CorePath)
		if err != nil {
			return nil, err
		}
		sum, err := fileSHA256(path)
		if err != nil {
			return nil, codedError(CodeCoreInvalid, "read bundled frpc: %v", err)
		}
		if !strings.EqualFold(sum, FRPCSHA256) {
			return nil, codedError(CodeCoreInvalid, "frpc SHA-256 mismatch: got %s, want %s", sum, FRPCSHA256)
		}
		core = Core{Path: path, Version: CoreVersion, SHA256: sum}
	} else {
		var err error
		core, err = ResolveCore(options.ExecutableDir)
		if err != nil {
			return nil, err
		}
	}
	if err := recoverLedger(store.RuntimeRoot()); err != nil {
		return nil, err
	}
	observer := options.NetObserver
	if observer == nil {
		observer = netpolicy.NewObserver()
	}
	meshInterface := strings.TrimSpace(options.MeshInterfaceName)
	if meshInterface == "" {
		meshInterface = defaultMeshInterfaceName
	}
	egressInterval := options.EgressCheckInterval
	if egressInterval <= 0 {
		egressInterval = 5 * time.Second
	}
	endpoints := options.EndpointRegistry
	if endpoints == nil {
		endpoints = NewEndpointRegistry()
	}
	manager := &Manager{
		store: store, core: core, deviceID: options.DeviceID, networkID: options.NetworkID,
		leaseProvider: options.LeaseProvider, meshTargets: options.MeshTargetProvider,
		observer: observer, endpoints: endpoints, meshInterface: meshInterface, egressInterval: egressInterval,
		reservations: options.ReservationProvider, observationGate: netpolicy.NewObservationDebouncer(2), state: "stopped",
	}
	if strings.TrimSpace(options.MeshCIDR) != "" {
		prefix, parseErr := netip.ParsePrefix(strings.TrimSpace(options.MeshCIDR))
		if parseErr != nil {
			return nil, fmt.Errorf("parse Mesh CIDR policy: %w", parseErr)
		}
		manager.meshCIDRs = []netip.Prefix{prefix.Masked()}
	}
	if cfg, err := store.Load(); err == nil {
		manager.config = cfg
		manager.hasConfig = true
		ceiling, ceilingErr := loadRuntimeCeiling(store)
		if ceilingErr != nil {
			return nil, ceilingErr
		}
		manager.runtimeCeiling = ceiling
	} else if !errors.Is(err, ErrNoConfig) {
		return nil, err
	}
	return manager, nil
}

func loadRuntimeCeiling(store *Store) (*Config, error) {
	if store == nil {
		return nil, nil
	}
	path := filepath.Join(store.Root(), runtimeCeilingFileName)
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read FRP runtime permission ceiling: %w", err)
	}
	defer file.Close()
	cfg, err := DecodeConfig(file)
	if err != nil {
		return nil, fmt.Errorf("decode FRP runtime permission ceiling: %w", err)
	}
	return &cfg, nil
}

// UpdateMembership refreshes the network identity and Mesh CIDR policy after a
// join or session restore. It refuses to mutate a running runtime because the
// lease provider and target grants are bound to the old identity.
func (m *Manager) UpdateMembership(networkID, deviceID, cidr string) error {
	if core.NetworkID(networkID).Validate() != nil || core.DeviceID(deviceID).Validate() != nil {
		return codedError(CodeAuthRejected, "invalid FRP membership identity")
	}
	var prefixes []netip.Prefix
	if strings.TrimSpace(cidr) != "" {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(cidr))
		if err != nil {
			return fmt.Errorf("parse Mesh CIDR policy: %w", err)
		}
		prefixes = []netip.Prefix{prefix.Masked()}
	}
	m.opMu.Lock()
	defer m.opMu.Unlock()
	m.mu.Lock()
	if m.runtimeRequiresIdentityStopLocked() {
		m.mu.Unlock()
		return codedError(CodeConfigurationInvalid, "stop the managed or Mesh-dependent FRP runtime before changing the TLAN membership identity")
	}
	m.networkID = networkID
	m.deviceID = deviceID
	m.mu.Unlock()
	m.meshMu.Lock()
	m.meshCIDRs = prefixes
	m.meshMu.Unlock()
	m.advanceObservationGeneration()
	if updater, ok := m.leaseProvider.(interface{ UpdateIdentity(string, string) }); ok {
		updater.UpdateIdentity(networkID, deviceID)
	}
	return nil
}

// UpdateMeshCIDR refreshes only the active route-policy prefix. Unlike an
// identity change, this is safe while FRP is running: the next route check
// uses the new prefix and stops the runtime if the control path conflicts.
func (m *Manager) UpdateMeshCIDR(cidr string) error {
	var prefixes []netip.Prefix
	if strings.TrimSpace(cidr) != "" {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(cidr))
		if err != nil {
			return fmt.Errorf("parse Mesh CIDR policy: %w", err)
		}
		prefixes = []netip.Prefix{prefix.Masked()}
	}
	m.meshMu.Lock()
	m.meshCIDRs = prefixes
	m.meshMu.Unlock()
	m.advanceObservationGeneration()
	return nil
}

func configRequiresTLANIdentity(cfg Config) bool {
	return strings.EqualFold(cfg.Profile.Server.Kind, "managed") || hasMeshTarget(cfg)
}

func (m *Manager) runtimeRequiresIdentityStopLocked() bool {
	cfg := m.config
	if m.instance != nil && !m.hasConfig {
		cfg = m.instance.config
	}
	if !configRequiresTLANIdentity(cfg) {
		return false
	}
	return m.instance != nil || m.desiredRun.Load() || m.state == "waiting_dependency"
}

// RequiresIdentityStop reports whether changing the Mesh identity would leave
// a managed or Mesh-dependent runtime bound to the old identity. Independent
// private-token FRP profiles do not depend on TLAN membership and may continue
// while the user joins, leaves, or switches networks.
func (m *Manager) RequiresIdentityStop() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.runtimeRequiresIdentityStopLocked()
}

func (m *Manager) nextInstanceGeneration() uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.instanceSequence++
	return m.instanceSequence
}

func (m *Manager) instanceMatchesLocked(inst *managedInstance) bool {
	return inst != nil && m.instance == inst && m.instanceGeneration == inst.generation
}

func (m *Manager) isCurrentInstance(inst *managedInstance) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.instanceMatchesLocked(inst)
}

func (m *Manager) isCurrentOrStartingInstance(inst *managedInstance) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.instanceMatchesLocked(inst) || (inst != nil && m.startingInstance == inst)
}

func (m *Manager) isStartingInstance(inst *managedInstance) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return inst != nil && m.startingInstance == inst
}

func (m *Manager) endpointRegistry() *EndpointRegistry {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.endpoints == nil {
		m.endpoints = NewEndpointRegistry()
	}
	return m.endpoints
}

func (m *Manager) Endpoints() []EndpointRecord {
	m.mu.Lock()
	registry := m.endpoints
	profileID := m.config.Profile.ID
	m.mu.Unlock()
	if registry == nil {
		return nil
	}
	return registry.SnapshotForProfile(profileID)
}

func (m *Manager) EndpointDiagnostics() []string {
	records := m.Endpoints()
	out := make([]string, 0, len(records))
	for _, record := range records {
		out = append(out, fmt.Sprintf("%s/%s %s:%d state=%s generation=%d rule=%s visitor=%s purpose=%s",
			record.Kind, record.Protocol, record.Host, record.Port, record.State,
			record.Owner.InstanceGeneration, record.Owner.RuleID, record.Owner.VisitorID, record.Owner.Purpose))
	}
	return out
}

func (m *Manager) observationDebouncerLocked() *netpolicy.ObservationDebouncer {
	if m.observationGate == nil {
		m.observationGate = netpolicy.NewObservationDebouncer(2)
	}
	return m.observationGate
}

func (m *Manager) advanceObservationGeneration() uint64 {
	m.observationMu.Lock()
	defer m.observationMu.Unlock()
	m.observationGen++
	if m.observationGen == 0 {
		m.observationGen = 1
	}
	m.observationDebouncerLocked().Advance(m.observationGen)
	return m.observationGen
}

func (m *Manager) currentObservationGeneration() uint64 {
	m.observationMu.Lock()
	defer m.observationMu.Unlock()
	if m.observationGen == 0 {
		m.observationGen = 1
	}
	m.observationDebouncerLocked().Advance(m.observationGen)
	return m.observationGen
}

func (m *Manager) observationStatus() netpolicy.ObservationStatus {
	m.observationMu.Lock()
	defer m.observationMu.Unlock()
	return m.observationDebouncerLocked().Status()
}

// ValidateMeshStart performs the reverse conflict check used before the GUI
// creates the TLAN interface. If FRP currently has run intent, its control
// endpoints must remain reachable without the planned Mesh prefix/interface.
func (m *Manager) ValidateMeshStart(ctx context.Context, cidr string) error {
	prefix, err := netip.ParsePrefix(strings.TrimSpace(cidr))
	if err != nil || !prefix.Addr().Is4() {
		return unsupported("pending TLAN network prefix must be a valid IPv4 prefix")
	}
	prefix = prefix.Masked()
	m.mu.Lock()
	active := m.instance != nil || m.desiredRun.Load()
	cfg := CloneConfig(m.config)
	hasConfig := m.hasConfig
	observer := m.observer
	meshInterface := m.meshInterface
	m.mu.Unlock()
	if !active || !hasConfig {
		return nil
	}
	planned := []netip.Prefix{prefix}
	for _, rule := range cfg.Profile.Rules {
		if !rule.Enabled || rule.Target.Kind != "lan" {
			continue
		}
		if err := targetInsidePrefixes(rule.Target, planned); err != nil {
			return err
		}
	}
	return checkFRPSEgressOnInterface(ctx, observer, cfg, planned, meshInterface)
}

// ReservedTargets reports dynamically allocated management and gateway
// listeners owned by this manager. Target validation uses this to avoid
// publishing another component's internal management surface.
func (m *Manager) ReservedTargets() []TargetReservation {
	m.mu.Lock()
	inst := m.instance
	registry := m.endpoints
	profileID := m.config.Profile.ID
	m.mu.Unlock()
	if registry != nil && profileID != "" {
		if records := registry.SnapshotForProfile(profileID); len(records) > 0 {
			return endpointReservations(records)
		}
	}
	if inst == nil {
		return nil
	}
	out := []TargetReservation{{
		Host: "127.0.0.1", Port: inst.adminPort, Purpose: "active frpc administration listener",
	}}
	if inst.egressProxy != nil {
		if addr := inst.egressProxy.Address(); addr.IsValid() {
			out = append(out, TargetReservation{
				Host: addr.Addr().String(), Port: int(addr.Port()), Purpose: "FRPC egress guard proxy listener",
			})
		}
	}
	if inst.udpEgressProxy != nil {
		if addr := inst.udpEgressProxy.Address(); addr.IsValid() {
			out = append(out, TargetReservation{
				Host: addr.Addr().String(), Port: int(addr.Port()), Purpose: "FRPC UDP egress guard relay listener",
			})
		}
	}
	out = append(out, configListenerReservations(inst.config)...)
	inst.gatewayMu.RLock()
	for ruleID, gateway := range inst.gatewaysByRule {
		if gateway == nil {
			continue
		}
		out = append(out, TargetReservation{
			Host: gateway.Addr().Addr().String(), Port: int(gateway.Addr().Port()),
			Purpose: "TargetGateway listener for rule " + ruleID,
		})
	}
	inst.gatewayMu.RUnlock()
	return out
}

func configListenerReservations(cfg Config) []TargetReservation {
	out := make([]TargetReservation, 0, len(cfg.Profile.Visitors))
	for _, visitor := range cfg.Profile.Visitors {
		if !visitor.Enabled {
			continue
		}
		out = append(out, TargetReservation{
			Host: visitor.BindAddr, Port: visitor.BindPort,
			Purpose: "visitor listener for " + visitor.Name, AllowVisitorBind: true,
			OwnerProfileID: cfg.Profile.ID, VisitorID: visitor.ID,
		})
	}
	return out
}

func endpointScopeFor(profileID string, generation uint64) string {
	return fmt.Sprintf("%s/instance-%d", profileID, generation)
}

func instanceEndpointRecords(cfg Config, generation uint64, scope string, adminPort int, guard *egressGuard, gatewaysByRule map[string]*targetgateway.Gateway) []EndpointRecord {
	owner := EndpointOwner{ProfileID: cfg.Profile.ID, InstanceScope: scope, InstanceGeneration: generation}
	records := make([]EndpointRecord, 0, 1+len(cfg.Profile.Visitors)+1+len(gatewaysByRule))
	adminOwner := owner
	adminOwner.Purpose = "active frpc administration listener"
	records = append(records, EndpointRecord{
		Host: "127.0.0.1", Port: adminPort, Protocol: EndpointProtocolTCP,
		Kind: EndpointKindAdmin, State: EndpointStateStarting, Owner: adminOwner,
	})
	for _, visitor := range cfg.Profile.Visitors {
		if !visitor.Enabled {
			continue
		}
		visitorOwner := owner
		visitorOwner.VisitorID = visitor.ID
		visitorOwner.Purpose = "visitor listener for " + visitor.Name
		protocol := EndpointProtocolTCP
		if visitor.Type == "sudp" {
			protocol = EndpointProtocolUDP
		}
		records = append(records, EndpointRecord{
			Host: visitor.BindAddr, Port: visitor.BindPort, Protocol: protocol,
			Kind: EndpointKindVisitor, State: EndpointStateStarting, Owner: visitorOwner,
		})
	}
	if guard != nil {
		proxyOwner := owner
		proxyOwner.Purpose = "FRPC egress guard proxy listener"
		switch {
		case guard.tcp != nil:
			if addr := guard.tcp.Address(); addr.IsValid() {
				records = append(records, EndpointRecord{
					Host: addr.Addr().String(), Port: int(addr.Port()), Protocol: EndpointProtocolTCP,
					Kind: EndpointKindEgressProxy, State: EndpointStateStarting, Owner: proxyOwner,
				})
			}
		case guard.udp != nil:
			if addr := guard.udp.Address(); addr.IsValid() {
				proxyOwner.Purpose = "FRPC UDP egress guard relay listener"
				records = append(records, EndpointRecord{
					Host: addr.Addr().String(), Port: int(addr.Port()), Protocol: EndpointProtocolUDP,
					Kind: EndpointKindEgressProxy, State: EndpointStateStarting, Owner: proxyOwner,
				})
			}
		}
	}
	for ruleID, gateway := range gatewaysByRule {
		if gateway == nil {
			continue
		}
		addr := gateway.Addr()
		gatewayOwner := owner
		gatewayOwner.RuleID = ruleID
		gatewayOwner.Purpose = "TargetGateway listener for rule " + ruleID
		records = append(records, EndpointRecord{
			Host: addr.Addr().String(), Port: int(addr.Port()), Protocol: EndpointProtocol(gateway.Protocol()),
			Kind: EndpointKindTargetGateway, State: EndpointStateStarting, Owner: gatewayOwner,
		})
	}
	return records
}

func gatewayTargetReservations(gateways []*targetgateway.Gateway) []TargetReservation {
	out := make([]TargetReservation, 0, len(gateways))
	for _, gateway := range gateways {
		if gateway == nil {
			continue
		}
		addr := gateway.Addr()
		out = append(out, TargetReservation{
			Host: addr.Addr().String(), Port: int(addr.Port()), Purpose: "active TargetGateway listener",
		})
	}
	return out
}

func (m *Manager) Core() Core { return m.core }

func (m *Manager) Config() (Config, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return CloneConfig(m.config), m.hasConfig
}

func (m *Manager) HasToken() bool {
	m.mu.Lock()
	ref := m.config.Profile.Server.CredentialRef
	configured := m.hasConfig
	m.mu.Unlock()
	if !configured || ref == "" {
		return false
	}
	return m.store.HasToken(ref)
}

func (m *Manager) fail(err error) error {
	if err == nil {
		return nil
	}
	m.mu.Lock()
	m.state = "failed"
	m.lastErr = err
	m.mu.Unlock()
	return err
}

var errRunCancelled = errors.New("FRP start was cancelled by Stop")

func (m *Manager) setRunCancel(cancel context.CancelFunc) {
	m.runMu.Lock()
	m.runCancel = cancel
	m.runMu.Unlock()
}

func (m *Manager) clearRunCancel() {
	m.runMu.Lock()
	m.runCancel = nil
	m.runMu.Unlock()
}

func (m *Manager) cancelRunningStart() {
	m.runMu.Lock()
	cancel := m.runCancel
	m.runMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func isRetryableStartError(err error) bool {
	switch ErrorCode(err) {
	case CodeMeshDependencyDown, CodeServerUnreachable, CodeLocalListenBusy, CodeProcessFailed:
		return true
	default:
		return false
	}
}

// finishStartFailure makes the foreground intent match the actual state. A
// retryable dependency/server failure keeps a cancellable intent; a terminal
// configuration or authorization error clears it so identity changes are not
// blocked by a runtime that will never recover by itself.
func (m *Manager) finishStartFailure(err error) {
	if err == nil {
		return
	}
	if !m.desiredRun.Load() || errors.Is(err, context.Canceled) {
		m.mu.Lock()
		if m.instance == nil {
			m.state = "stopped"
			m.lastErr = nil
		}
		m.mu.Unlock()
		return
	}
	if isRetryableStartError(err) {
		m.mu.Lock()
		if m.instance == nil {
			if ErrorCode(err) == CodeMeshDependencyDown {
				m.state = "waiting_dependency"
			} else {
				m.state = "failed"
			}
			m.lastErr = err
		}
		m.mu.Unlock()
		go m.retryDependency()
		return
	}
	m.desiredRun.Store(false)
	m.mu.Lock()
	if m.instance == nil {
		m.state = "failed"
		m.lastErr = err
	}
	m.mu.Unlock()
}

func (m *Manager) Start(ctx context.Context) error {
	m.desiredRun.Store(true)
	m.mu.Lock()
	if m.instance != nil {
		m.state = "running"
		m.mu.Unlock()
		return nil
	}
	m.state = "starting"
	m.lastErr = nil
	m.mu.Unlock()

	runCtx, cancel := context.WithCancel(ctx)
	m.setRunCancel(cancel)
	m.opMu.Lock()
	err := m.startLocked(runCtx)
	m.opMu.Unlock()
	m.clearRunCancel()
	cancel()
	if err != nil {
		m.finishStartFailure(err)
	}
	return err
}

func (m *Manager) startForRetry(ctx context.Context) error {
	runCtx, cancel := context.WithCancel(ctx)
	m.setRunCancel(cancel)
	defer func() {
		m.clearRunCancel()
		cancel()
	}()
	m.opMu.Lock()
	defer m.opMu.Unlock()
	if !m.desiredRun.Load() {
		return errRunCancelled
	}
	m.mu.Lock()
	if m.instance == nil {
		m.state = "starting"
	}
	m.mu.Unlock()
	err := m.startLocked(runCtx)
	if err != nil && !errors.Is(err, context.Canceled) && !isRetryableStartError(err) {
		m.desiredRun.Store(false)
	}
	return err
}

func (m *Manager) startLocked(ctx context.Context) error {
	m.mu.Lock()
	if m.instance != nil {
		m.mu.Unlock()
		return nil
	}
	m.mu.Unlock()

	cfg, err := m.store.Load()
	if err != nil {
		if errors.Is(err, ErrNoConfig) {
			return m.fail(codedError(CodeConfigurationInvalid, "请先配置 FRP 服务器"))
		}
		return m.fail(err)
	}
	cfg, err = m.limitToRuntimeCeiling(cfg)
	if err != nil {
		return m.fail(err)
	}
	token, err := m.store.Token(cfg.Profile.Server.CredentialRef)
	if err != nil {
		return m.fail(codedError(CodeAuthRejected, "读取 FRP 令牌失败: %v", err))
	}
	if err = ValidateRunInputs(cfg, token); err != nil {
		return m.fail(err)
	}
	if err = m.validatePolicyContext(ctx, cfg); err != nil {
		return m.fail(err)
	}
	if err = preflightTLS(ctx, cfg); err != nil {
		return m.fail(err)
	}
	secrets, err := m.resolveSecrets(cfg, nil)
	if err != nil {
		return m.fail(err)
	}
	m.logs.clear()
	logSecrets := append([]string{token}, mapValues(secrets)...)
	m.logs.setSecrets(logSecrets...)
	lease, leaseErr := m.acquireLeaseWithSecrets(ctx, cfg, secrets)
	if leaseErr != nil {
		return m.fail(leaseErr)
	}
	if lease != nil {
		logSecrets = append(logSecrets, lease.Credential)
		m.logs.setSecrets(logSecrets...)
	}
	inst, err := m.startInstance(ctx, cfg, token, secrets, lease)
	if err != nil {
		_ = m.releaseLease(ctx, lease)
	}
	if err != nil {
		return m.fail(err)
	}
	if err = m.commitInstance(inst, cfg); err != nil {
		return err
	}
	return nil
}

func (m *Manager) commitInstance(inst *managedInstance, cfg Config) error {
	m.mu.Lock()
	select {
	case <-inst.done:
		err := codedError(CodeProcessFailed, "FRP process exited before runtime state commit")
		if m.startingInstance == inst {
			m.startingInstance = nil
		}
		m.state = "failed"
		m.lastErr = err
		m.mu.Unlock()
		return err
	default:
	}
	m.startingInstance = nil
	m.config = cfg
	m.hasConfig = true
	m.instance = inst
	m.instanceGeneration = inst.generation
	m.state = "running"
	m.lastErr = nil
	m.mu.Unlock()
	if inst.endpointOwner != nil && !inst.endpointOwner.MarkScopeRunning(inst.endpointScope, inst.generation) {
		m.logs.add(fmt.Sprintf("endpoint registry could not mark instance generation %d running", inst.generation))
	}
	m.advanceObservationGeneration()
	m.startEgressMonitor(inst)
	return nil
}

// startEgressMonitor polls the actual OS route while the process is running.
// Polling is the sole change source in this R2 slice; interface switches, VPN
// changes, Mesh interface recreation, sleep/resume restoration, and DNS
// changes are observed on the next tick. Each tick carries a manager
// generation so an in-flight result cannot override a newer membership/CIDR.
func (m *Manager) startEgressMonitor(inst *managedInstance) {
	if inst == nil || m.observer == nil {
		return
	}
	inst.egressOnce.Do(func() {
		interval := m.egressInterval
		if interval <= 0 {
			interval = 10 * time.Second
		}
		go m.watchEgress(inst, interval)
	})
}

func (m *Manager) watchEgress(inst *managedInstance, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-inst.done:
			return
		case <-ticker.C:
		}
		if inst.stopping.Load() {
			return
		}
		m.mu.Lock()
		current := m.instance == inst
		m.mu.Unlock()
		if !current {
			return
		}
		generation := m.currentObservationGeneration()
		m.meshMu.RLock()
		prefixes := append([]netip.Prefix(nil), m.meshCIDRs...)
		m.meshMu.RUnlock()
		if len(prefixes) == 0 {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		err := checkFRPSEgressOnInterface(ctx, m.observer, inst.config, prefixes, m.meshInterface)
		cancel()
		if err == nil {
			for _, rule := range inst.config.Profile.Rules {
				if !rule.Enabled || rule.Target.Kind != "lan" {
					continue
				}
				if targetErr := targetInsidePrefixes(rule.Target, prefixes); targetErr != nil {
					err = targetErr
					break
				}
			}
		}
		state := netpolicy.ObservationHealthy
		if err != nil {
			state = netpolicy.ObservationConflict
			if ErrorCode(err) == CodeRouteObservationUnavailable {
				state = netpolicy.ObservationUnavailable
			}
		}
		m.observationMu.Lock()
		decision := m.observationDebouncerLocked().Observe(generation, state)
		m.observationMu.Unlock()
		if decision.Stale {
			m.logs.add(fmt.Sprintf("discarded stale route observation generation %d (current state generation %d)", generation, m.observationStatus().Generation))
			continue
		}
		if !decision.Apply || state == netpolicy.ObservationHealthy {
			if state == netpolicy.ObservationUnavailable && decision.Accepted {
				m.logs.add("FRPS route observation temporarily unavailable; debouncing before fail-closed stop")
			}
			continue
		}
		m.failEgressRuntime(inst, err, generation)
		return
	}
}

func (m *Manager) failEgressRuntime(inst *managedInstance, cause error, generation uint64) {
	m.observationMu.Lock()
	if generation != m.observationGen {
		m.observationMu.Unlock()
		m.logs.add(fmt.Sprintf("discarded stale route failure generation %d before stopping instance generation %d", generation, inst.generation))
		return
	}
	m.mu.Lock()
	if !m.instanceMatchesLocked(inst) {
		m.mu.Unlock()
		m.observationMu.Unlock()
		return
	}
	m.desiredRun.Store(false)
	m.state = "stopping"
	m.lastErr = cause
	m.mu.Unlock()
	m.observationMu.Unlock()
	m.logs.add(fmt.Sprintf("FRPS egress guard stopped FRP runtime (observation generation %d): %v", generation, cause))
	inst.stopping.Store(true)
	stopErr := m.stopInstance(context.Background(), inst)
	failure := cause
	if stopErr != nil {
		failure = codedError(CodeCleanupIncomplete, "%v；停止 FRP 失败: %v", cause, stopErr)
	}
	m.mu.Lock()
	if m.instance == nil || m.instanceMatchesLocked(inst) {
		m.instance = nil
		m.state = "failed"
		m.lastErr = failure
	}
	m.mu.Unlock()
}

// Apply validates and commits a new revision. If the runtime is active, the
// old configuration is stopped and the new one is started before persistence.
// A failed apply restarts the last-good configuration.
func (m *Manager) resolveSecrets(cfg Config, provided map[string]string) (map[string]string, error) {
	refs := requiredSecretRefs(cfg)
	delete(refs, cfg.Profile.Server.CredentialRef)
	if len(refs) == 0 {
		return map[string]string{}, nil
	}
	if m.store == nil {
		return nil, codedError(CodeConfigurationInvalid, "FRP secret store is unavailable")
	}
	resolved := make(map[string]string, len(refs))
	for ref := range refs {
		value := provided[ref]
		if value == "" {
			var err error
			value, err = m.store.Secret(ref)
			if err != nil {
				return nil, codedError(CodeConfigurationInvalid, "读取 FRP secret %q 失败: %v", ref, err)
			}
		}
		if value == "" {
			return nil, codedError(CodeConfigurationInvalid, "FRP secret %q is empty", ref)
		}
		resolved[ref] = value
	}
	return resolved, nil
}

func sameOptionalBool(a, b *bool) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

func sameRollbackServer(a, b Server) bool {
	return a.Kind == b.Kind &&
		a.Host == b.Host &&
		a.Port == b.Port &&
		a.Transport == b.Transport &&
		a.TLSServerName == b.TLSServerName &&
		a.TrustedCAPath == b.TrustedCAPath &&
		a.CredentialRef == b.CredentialRef &&
		a.ServerID == b.ServerID &&
		a.PublicHTTPPort == b.PublicHTTPPort &&
		a.PublicHTTPSPort == b.PublicHTTPSPort &&
		sameOptionalBool(a.TCPMux, b.TCPMux) &&
		sameOptionalBool(a.DisableCustomTLSFirstByte, b.DisableCustomTLSFirstByte)
}

func sameRollbackTarget(a, b Target) bool {
	return a.Kind == b.Kind &&
		a.Host == b.Host &&
		a.Port == b.Port &&
		a.NetworkID == b.NetworkID &&
		a.DeviceID == b.DeviceID &&
		a.PublicKey == b.PublicKey &&
		a.ServiceID == b.ServiceID
}

func domainsAllowed(previous, next []string) bool {
	allowed := make(map[string]struct{}, len(next))
	for _, domain := range next {
		allowed[strings.ToLower(domain)] = struct{}{}
	}
	for _, domain := range previous {
		if _, ok := allowed[strings.ToLower(domain)]; !ok {
			return false
		}
	}
	return true
}

func previousRuleAllowed(previous, next Rule) bool {
	if !next.Enabled || previous.Type != next.Type || previous.SecretRef != next.SecretRef || !sameRollbackTarget(previous.Target, next.Target) {
		return false
	}
	if previous.Exposure.RemotePort != next.Exposure.RemotePort {
		return false
	}
	if !domainsAllowed(previous.Exposure.CustomDomains, next.Exposure.CustomDomains) {
		return false
	}
	if previous.Exposure.Subdomain != next.Exposure.Subdomain ||
		!allowUsersAllowed(previous.Exposure.AllowUsers, next.Exposure.AllowUsers) ||
		previous.Exposure.HTTPUser != next.Exposure.HTTPUser ||
		previous.Exposure.HTTPPasswordRef != next.Exposure.HTTPPasswordRef ||
		previous.Exposure.HostHeaderRewrite != next.Exposure.HostHeaderRewrite ||
		previous.Exposure.RouteByHTTPUser != next.Exposure.RouteByHTTPUser ||
		previous.Exposure.Multiplexer != next.Exposure.Multiplexer ||
		!sameStringSlice(previous.Exposure.Locations, next.Exposure.Locations) ||
		!sameStringMap(previous.Exposure.RequestHeaders, next.Exposure.RequestHeaders) ||
		!sameStringMap(previous.Exposure.ResponseHeaders, next.Exposure.ResponseHeaders) {
		return false
	}
	return previous.Transport == next.Transport
}

func previousVisitorAllowed(previous, next Visitor) bool {
	return next.Enabled &&
		previous.Type == next.Type &&
		previous.ServerName == next.ServerName &&
		previous.ServerUser == next.ServerUser &&
		previous.SecretRef == next.SecretRef &&
		previous.BindAddr == next.BindAddr &&
		previous.BindPort == next.BindPort &&
		previous.Protocol == next.Protocol &&
		previous.KeepTunnelOpen == next.KeepTunnelOpen &&
		previous.MaxRetriesAnHour == next.MaxRetriesAnHour &&
		previous.MinRetryInterval == next.MinRetryInterval &&
		previous.FallbackTo == next.FallbackTo &&
		previous.FallbackTimeoutMs == next.FallbackTimeoutMs
}

func allowUsersAllowed(previous, next []string) bool {
	if len(next) == 0 {
		return len(previous) == 0
	}
	allowed := make(map[string]struct{}, len(next))
	for _, user := range next {
		allowed[user] = struct{}{}
	}
	for _, user := range previous {
		if _, ok := allowed[user]; !ok {
			return false
		}
	}
	return true
}

func sameStringSlice(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func sameStringMap(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		if right[key] != value {
			return false
		}
	}
	return true
}

func sameSecretValue(ref string, previous, next map[string]string, compareValues bool) bool {
	if ref == "" || !compareValues {
		return true
	}
	value := previous[ref]
	return value != "" && value == next[ref]
}

func withCleanupErrors(cause error, cleanup ...error) error {
	var failures []error
	for _, err := range cleanup {
		if err != nil {
			failures = append(failures, err)
		}
	}
	if len(failures) == 0 {
		return cause
	}
	cleanupErr := codedError(CodeCleanupIncomplete, "FRP 清理失败: %v", errors.Join(failures...))
	if cause == nil {
		return cleanupErr
	}
	return errors.Join(cause, cleanupErr)
}

func enabledRuntimeCount(cfg Config) int {
	count := 0
	for _, rule := range cfg.Profile.Rules {
		if rule.Enabled {
			count++
		}
	}
	for _, visitor := range cfg.Profile.Visitors {
		if visitor.Enabled {
			count++
		}
	}
	return count
}

// previousAllowedByNext returns the previous revision reduced to the exact
// published resources that the next revision still authorizes. fullyAllowed is
// false as soon as a server identity, target, port, domain, credential, rule,
// or visitor is removed, disabled, replaced, or tightened.
func previousAllowedByNext(previous, next Config, previousToken, nextToken string, previousSecrets, nextSecrets map[string]string) (Config, bool) {
	return previousAllowedByNextMode(previous, next, previousToken, nextToken, previousSecrets, nextSecrets, true)
}

// previousAllowedByCeiling compares persisted permission structure only. The
// runtime-ceiling file deliberately does not contain secret values, so it must
// not treat missing plaintext as a revoked SecretRef. Rule and visitor
// comparison still requires the exact reference and all permission fields.
func previousAllowedByCeiling(previous, next Config) (Config, bool) {
	return previousAllowedByNextMode(previous, next, "", "", nil, nil, false)
}

func previousAllowedByNextMode(previous, next Config, previousToken, nextToken string, previousSecrets, nextSecrets map[string]string, compareSecretValues bool) (Config, bool) {
	rollback := CloneConfig(previous)
	rollback.Profile.Rules = nil
	rollback.Profile.Visitors = nil
	serverAllowed := previous.Profile.ID == next.Profile.ID && sameRollbackServer(previous.Profile.Server, next.Profile.Server) &&
		(!compareSecretValues || previousToken == nextToken)
	fullyAllowed := serverAllowed

	for _, rule := range previous.Profile.Rules {
		if !rule.Enabled {
			continue
		}
		allowed := serverAllowed && sameSecretValue(rule.SecretRef, previousSecrets, nextSecrets, compareSecretValues) &&
			sameSecretValue(rule.Exposure.HTTPPasswordRef, previousSecrets, nextSecrets, compareSecretValues)
		if allowed {
			found := false
			for _, candidate := range next.Profile.Rules {
				if candidate.ID == rule.ID && previousRuleAllowed(rule, candidate) {
					found = true
					break
				}
			}
			allowed = found
		}
		if allowed {
			rollback.Profile.Rules = append(rollback.Profile.Rules, CloneConfig(Config{Profile: Profile{Rules: []Rule{rule}}}).Profile.Rules[0])
		} else {
			fullyAllowed = false
		}
	}
	for _, visitor := range previous.Profile.Visitors {
		if !visitor.Enabled {
			continue
		}
		allowed := serverAllowed && sameSecretValue(visitor.SecretRef, previousSecrets, nextSecrets, compareSecretValues)
		if allowed {
			found := false
			for _, candidate := range next.Profile.Visitors {
				if candidate.ID == visitor.ID && previousVisitorAllowed(visitor, candidate) {
					found = true
					break
				}
			}
			allowed = found
		}
		if allowed {
			rollback.Profile.Visitors = append(rollback.Profile.Visitors, visitor)
		} else {
			fullyAllowed = false
		}
	}
	return rollback, fullyAllowed
}

func (m *Manager) setRuntimeCeiling(cfg *Config) error {
	var stored *Config
	if cfg != nil {
		value := CloneConfig(*cfg)
		stored = &value
	}
	m.mu.Lock()
	m.runtimeCeiling = stored
	m.runtimeCeilingErr = nil
	m.mu.Unlock()
	if m.store == nil {
		return nil
	}
	path := filepath.Join(m.store.Root(), runtimeCeilingFileName)
	var persistErr error
	if stored == nil {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			persistErr = fmt.Errorf("remove FRP runtime permission ceiling: %w", err)
		}
	} else {
		data, err := EncodeConfig(*stored)
		if err != nil {
			persistErr = fmt.Errorf("encode FRP runtime permission ceiling: %w", err)
		} else if err = writePrivateFile(path, data); err != nil {
			persistErr = fmt.Errorf("persist FRP runtime permission ceiling: %w", err)
		}
	}
	if persistErr != nil {
		// Keep the in-memory ceiling so this process cannot reopen the
		// revoked permissions while the durable ceiling is unavailable.
		m.mu.Lock()
		m.runtimeCeilingErr = persistErr
		m.mu.Unlock()
		return persistErr
	}
	return nil
}

func (m *Manager) limitToRuntimeCeiling(cfg Config) (Config, error) {
	m.mu.Lock()
	ceiling := m.runtimeCeiling
	ceilingErr := m.runtimeCeilingErr
	m.mu.Unlock()
	if ceilingErr != nil {
		return Config{}, codedError(CodeConfigurationInvalid, "上一次收紧配置未保存成功，拒绝恢复旧发布: %v", ceilingErr)
	}
	if ceiling == nil {
		return cfg, nil
	}
	limited, fullyAllowed := previousAllowedByCeiling(cfg, *ceiling)
	if !fullyAllowed && enabledRuntimeCount(limited) == 0 && enabledRuntimeCount(cfg) > 0 {
		return limited, codedError(CodeConfigurationInvalid, "权限上限不包含任何可恢复的旧发布，已 fail-closed 停止")
	}
	return limited, nil
}

func (m *Manager) restoreAfterApplyFailure(ctx context.Context, previous, next Config, previousToken, nextToken string, previousSecrets, nextSecrets map[string]string, cause error) error {
	rollback, fullyAllowed := previousAllowedByNext(previous, next, previousToken, nextToken, previousSecrets, nextSecrets)
	previousCount := enabledRuntimeCount(previous)
	rollbackCount := enabledRuntimeCount(rollback)
	skipped := previousCount - rollbackCount
	var ceilingErr error
	if fullyAllowed {
		ceilingErr = m.setRuntimeCeiling(nil)
	} else {
		ceilingErr = m.setRuntimeCeiling(&rollback)
	}
	if ceilingErr != nil {
		// A failed revocation-intent write is itself a fail-closed condition.
		// Do not restore any old listener, even one that would otherwise be
		// within the intersection, because a restart could reopen it.
		m.desiredRun.Store(false)
		m.mu.Lock()
		inst := m.instance
		m.mu.Unlock()
		var stopErr error
		if inst != nil {
			stopErr = m.stopInstance(context.Background(), inst)
		}
		failure := fmt.Errorf("%w；撤销意图持久化失败，相关运行保持关闭: %v", cause, ceilingErr)
		failure = withCleanupErrors(failure, stopErr)
		m.mu.Lock()
		m.instance = nil
		m.state = "failed"
		m.lastErr = failure
		m.mu.Unlock()
		return failure
	}

	restoreErr := error(nil)
	restoreAttempted := rollbackCount > 0 || (previousCount == 0 && fullyAllowed)
	if restoreAttempted {
		restoreCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		lease, leaseErr := m.acquireLeaseWithSecrets(restoreCtx, rollback, previousSecrets)
		if leaseErr != nil {
			restoreErr = fmt.Errorf("恢复仍被允许的旧服务时获取授权失败: %w", leaseErr)
		} else {
			inst, startErr := m.startInstance(restoreCtx, rollback, previousToken, previousSecrets, lease)
			if startErr != nil {
				releaseErr := m.releaseLease(context.Background(), lease)
				restoreErr = withCleanupErrors(startErr, releaseErr)
			} else if commitErr := m.commitInstance(inst, rollback); commitErr != nil {
				stopErr := m.stopInstance(context.Background(), inst)
				releaseErr := m.releaseLease(context.Background(), lease)
				restoreErr = withCleanupErrors(commitErr, stopErr, releaseErr)
			}
		}
	}

	if restoreErr == nil && restoreAttempted {
		message := cause
		if skipped > 0 {
			message = fmt.Errorf("%w；已撤销并保持关闭 %d 项被新配置删除、禁用或收紧的旧发布，仅恢复 %d 项仍被新权限允许的旧服务", cause, skipped, rollbackCount)
		}
		m.mu.Lock()
		m.state = "running"
		m.lastErr = message
		m.mu.Unlock()
		return message
	}

	m.desiredRun.Store(false)
	failure := cause
	if restoreErr != nil {
		failure = fmt.Errorf("%w；旧服务恢复失败，相关运行保持关闭: %v", cause, restoreErr)
	} else if skipped > 0 {
		failure = fmt.Errorf("%w；旧配置包含 %d 项被新配置删除、禁用或收紧的发布，相关运行保持关闭", cause, skipped)
	}
	m.mu.Lock()
	m.instance = nil
	m.state = "failed"
	m.lastErr = failure
	m.mu.Unlock()
	return failure
}
func (m *Manager) Apply(ctx context.Context, cfg Config, token string) (Config, error) {
	return m.ApplyWithSecrets(ctx, cfg, token, nil)
}

func (m *Manager) ApplyWithSecrets(ctx context.Context, cfg Config, token string, providedSecrets map[string]string) (Config, error) {
	m.opMu.Lock()
	defer m.opMu.Unlock()

	cfg = NormalizeConfig(cfg)
	if err := ValidateConfig(cfg); err != nil {
		return Config{}, err
	}
	current, err := m.store.Load()
	currentRevision := uint64(0)
	if err == nil {
		currentRevision = current.Profile.Revision
	} else if !errors.Is(err, ErrNoConfig) {
		return Config{}, err
	}
	if cfg.Profile.Revision != currentRevision {
		return Config{}, fmt.Errorf("%w: expected %d, got %d", ErrRevisionConflict, currentRevision, cfg.Profile.Revision)
	}
	ref := cfg.Profile.Server.CredentialRef
	if token == "" {
		token, err = m.store.Token(ref)
		if err != nil {
			return Config{}, codedError(CodeAuthRejected, "读取 FRP 令牌失败: %v", err)
		}
	}
	if err = ValidateRunInputs(cfg, token); err != nil {
		return Config{}, err
	}
	secrets, err := m.resolveSecrets(cfg, providedSecrets)
	if err != nil {
		return Config{}, err
	}

	next := CloneConfig(cfg)
	next.Profile.Revision = currentRevision + 1

	m.mu.Lock()
	running := m.instance != nil
	m.mu.Unlock()
	if err = preflightTLS(ctx, cfg); err != nil {
		return Config{}, err
	}
	if err = m.validatePolicyContext(ctx, cfg); err != nil {
		return Config{}, err
	}
	if !running {
		lease, leaseErr := m.acquireLeaseWithSecrets(ctx, cfg, secrets)
		if leaseErr != nil {
			return Config{}, m.fail(leaseErr)
		}
		if err = m.verifyOnly(ctx, cfg, token, secrets, lease); err != nil {
			_ = m.releaseLease(ctx, lease)
			return Config{}, m.fail(err)
		}
		saved, saveErr := m.store.SaveWithSecrets(cfg, token, secrets)
		if saveErr != nil {
			_ = m.releaseLease(ctx, lease)
			return Config{}, m.fail(saveErr)
		}
		if releaseErr := m.releaseLease(ctx, lease); releaseErr != nil {
			return Config{}, m.fail(releaseErr)
		}
		if err = m.setRuntimeCeiling(nil); err != nil {
			failure := codedError(CodeConfigurationInvalid, "配置已保存，但清除运行权限上限失败: %v", err)
			m.mu.Lock()
			m.config = saved
			m.hasConfig = true
			m.state = "failed"
			m.lastErr = failure
			m.mu.Unlock()
			return saved, failure
		}
		m.mu.Lock()
		m.config = saved
		m.hasConfig = true
		m.state = "stopped"
		m.lastErr = nil
		m.mu.Unlock()
		return saved, nil
	}

	oldToken, err := m.store.Token(current.Profile.Server.CredentialRef)
	if err != nil {
		return Config{}, codedError(CodeAuthRejected, "读取上一版 FRP 令牌失败: %v", err)
	}
	oldSecrets, err := m.resolveSecrets(current, nil)
	if err != nil {
		return Config{}, err
	}
	m.logs.clear()
	logSecrets := append([]string{token}, mapValues(secrets)...)
	m.logs.setSecrets(logSecrets...)
	// A managed replacement cannot coexist with the old lease because proxy
	// names and public ports are exclusive. Stop and revoke the old grant
	// first, then acquire the replacement. Recovery only re-acquires the
	// resources still authorized by the requested revision.
	if err = m.stopCurrent(ctx); err != nil {
		return Config{}, err
	}
	newLease, leaseErr := m.acquireLeaseWithSecrets(ctx, cfg, secrets)
	if newLease != nil {
		logSecrets = append(logSecrets, newLease.Credential)
		m.logs.setSecrets(logSecrets...)
	}
	if leaseErr != nil {
		return Config{}, m.restoreAfterApplyFailure(ctx, current, next, oldToken, token, oldSecrets, secrets, leaseErr)
	}
	inst, startErr := m.startInstance(ctx, next, token, secrets, newLease)
	if startErr != nil {
		_ = m.releaseLease(context.Background(), newLease)
		return Config{}, m.restoreAfterApplyFailure(ctx, current, next, oldToken, token, oldSecrets, secrets, startErr)
	}
	saved, saveErr := m.store.SaveWithSecrets(cfg, token, secrets)
	if saveErr != nil {
		_ = m.stopInstance(context.Background(), inst)
		return Config{}, m.restoreAfterApplyFailure(ctx, current, next, oldToken, token, oldSecrets, secrets, saveErr)
	}
	if err = m.commitInstance(inst, saved); err != nil {
		stopErr := m.stopInstance(context.Background(), inst)
		return Config{}, m.restoreAfterApplyFailure(ctx, current, next, oldToken, token, oldSecrets, secrets, withCleanupErrors(err, stopErr))
	}
	if err = m.setRuntimeCeiling(nil); err != nil {
		m.desiredRun.Store(false)
		stopErr := m.stopInstance(context.Background(), inst)
		failure := codedError(CodeConfigurationInvalid, "新配置已启动，但清除运行权限上限失败，已停止相关运行: %v", err)
		failure = withCleanupErrors(failure, stopErr)
		m.mu.Lock()
		m.state = "failed"
		m.lastErr = failure
		m.mu.Unlock()
		return Config{}, failure
	}
	return saved, nil
}

func (m *Manager) restorePrevious(cfg Config, token string, secrets map[string]string, lease *Lease) error {
	inst, err := m.startInstance(context.Background(), cfg, token, secrets, lease)
	if err != nil {
		return err
	}
	return m.commitInstance(inst, cfg)
}

func (m *Manager) Stop(ctx context.Context) error {
	m.desiredRun.Store(false)
	m.advanceObservationGeneration()
	m.cancelRunningStart()
	m.opMu.Lock()
	defer m.opMu.Unlock()
	return m.stopCurrent(ctx)
}

func (m *Manager) Close(ctx context.Context) error { return m.Stop(ctx) }

func (m *Manager) stopCurrent(ctx context.Context) error {
	m.mu.Lock()
	inst := m.instance
	if inst == nil {
		m.state = "stopped"
		m.lastErr = nil
		m.mu.Unlock()
		return nil
	}
	inst.stopping.Store(true)
	m.state = "stopping"
	m.mu.Unlock()
	return m.stopInstance(ctx, inst)
}

func (m *Manager) stopInstance(ctx context.Context, inst *managedInstance) error {
	inst.stopMu.Lock()
	defer inst.stopMu.Unlock()
	if inst.stopped {
		return inst.stopErr
	}
	inst.stopped = true
	inst.stopping.Store(true)
	inst.stopErr = m.stopInstanceOnce(ctx, inst)
	return inst.stopErr
}

func (m *Manager) stopInstanceOnce(ctx context.Context, inst *managedInstance) error {
	lease := m.takeInstanceLease(inst)
	stopCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	var adminErr error
	if inst.admin != nil {
		adminErr = inst.admin.Stop(stopCtx)
	}
	cancel()
	if adminErr != nil {
		m.logs.add(fmt.Sprintf("FRP admin stop unavailable; falling back to owned job termination: %v", adminErr))
		select {
		case <-inst.done:
		case <-time.After(1200 * time.Millisecond):
		}
	}
	var terminateErr error
	select {
	case <-inst.done:
	case <-time.After(4 * time.Second):
		if inst.process != nil {
			terminateErr = windows.TerminateJobObject(inst.process.Job, 1)
		}
		select {
		case <-inst.done:
		case <-time.After(3 * time.Second):
		}
	}
	reapErr := inst.reap()
	leaseErr := m.releaseLease(ctx, lease)
	cleanupErr := errors.Join(terminateErr, reapErr, leaseErr)
	m.mu.Lock()
	if m.startingInstance == inst {
		m.startingInstance = nil
	}
	current := m.instanceMatchesLocked(inst)
	if current {
		m.instance = nil
		m.state = "stopped"
		if cleanupErr != nil {
			m.lastErr = codedError(CodeCleanupIncomplete, "FRP 已停止，但清理失败: %v", cleanupErr)
		} else {
			m.lastErr = nil
		}
	}
	m.mu.Unlock()
	if cleanupErr != nil {
		return codedError(CodeCleanupIncomplete, "FRP 已停止，但清理失败: %v", cleanupErr)
	}
	return nil
}

type egressGuard struct {
	tcp         *egressProxy
	udp         *udpEgressProxy
	proxyURL    string
	dialHost    string
	dialPort    int
	reservation TargetReservation
}

func (m *Manager) startEgressGuard(ctx context.Context, cfg Config, protected []netip.Prefix) (*egressGuard, error) {
	switch cfg.Profile.Server.Transport {
	case "kcp", "quic":
		proxy, err := startUDPEgressProxy(ctx, m.observer, cfg, protected, m.meshInterface)
		if err != nil {
			return nil, err
		}
		addr := proxy.Address()
		if !addr.IsValid() {
			return nil, withCleanupErrors(codedError(CodeLocalListenBusy, "FRPS UDP 出口代理没有有效监听地址"), proxy.Close())
		}
		return &egressGuard{
			udp: proxy, dialHost: "127.0.0.1", dialPort: int(addr.Port()),
			reservation: TargetReservation{Host: addr.Addr().String(), Port: int(addr.Port()), Purpose: "active FRPC UDP egress guard proxy listener"},
		}, nil
	default:
		proxy, err := startEgressProxy(ctx, m.observer, cfg, protected, m.meshInterface)
		if err != nil {
			return nil, err
		}
		addr := proxy.Address()
		if !addr.IsValid() {
			return nil, withCleanupErrors(codedError(CodeLocalListenBusy, "FRPS TCP 出口代理没有有效监听地址"), proxy.Close())
		}
		return &egressGuard{
			tcp: proxy, proxyURL: proxy.URL(),
			reservation: TargetReservation{Host: addr.Addr().String(), Port: int(addr.Port()), Purpose: "active FRPC egress guard proxy listener"},
		}, nil
	}
}

func (g *egressGuard) Close() error {
	if g == nil {
		return nil
	}
	var errs []error
	if g.tcp != nil {
		errs = append(errs, g.tcp.Close())
	}
	if g.udp != nil {
		errs = append(errs, g.udp.Close())
	}
	return errors.Join(errs...)
}

func (m *Manager) verifyOnly(ctx context.Context, cfg Config, token string, secrets map[string]string, lease *Lease) (retErr error) {
	adminPort, err := freeLoopbackPort()
	if err != nil {
		return codedError(CodeLocalListenBusy, "分配 FRP 校验端口失败: %v", err)
	}
	if err = m.validateTargetReservations(cfg, TargetReservation{
		Host: "127.0.0.1", Port: adminPort, Purpose: "temporary frpc administration listener",
	}); err != nil {
		return err
	}
	adminPassword, err := NewSecret(32)
	if err != nil {
		return err
	}
	instanceID, err := NewSecret(8)
	if err != nil {
		return err
	}
	dir := filepath.Join(m.store.RuntimeRoot(), "verify-"+instanceID)
	if err = os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create FRP verify directory: %w", err)
	}
	defer func() {
		retErr = withCleanupErrors(retErr, os.RemoveAll(dir))
	}()
	if err = secureDirectory(dir); err != nil {
		return err
	}
	tokenPath := filepath.Join(dir, "token.txt")
	configPath := filepath.Join(dir, "frpc.toml")
	if err = writePrivateFile(tokenPath, []byte(token)); err != nil {
		return fmt.Errorf("write FRP verify token: %w", err)
	}
	m.meshMu.RLock()
	meshPrefixes := append([]netip.Prefix(nil), m.meshCIDRs...)
	m.meshMu.RUnlock()
	guard, err := m.startEgressGuard(ctx, cfg, meshPrefixes)
	if err != nil {
		return err
	}
	defer func() {
		retErr = withCleanupErrors(retErr, guard.Close())
	}()
	proxyReservation := guard.reservation
	if err = m.validateTargetReservations(cfg, proxyReservation); err != nil {
		return err
	}
	localTargets, gateways, _, gatewayCancel, gatewayErr := m.prepareGateways(ctx, cfg, lease)
	if gatewayErr != nil {
		return gatewayErr
	}
	defer func() {
		var cleanup []error
		for _, gateway := range gateways {
			if gateway != nil {
				cleanup = append(cleanup, gateway.Close())
			}
		}
		gatewayCancel()
		retErr = withCleanupErrors(retErr, cleanup...)
	}()
	reservations := append(gatewayTargetReservations(gateways), proxyReservation)
	if err = m.validateTargetReservations(cfg, reservations...); err != nil {
		return err
	}
	rendered, err := RenderConfig(RenderInput{
		Config: cfg, DeviceID: m.deviceID, TokenPath: tokenPath, AdminPort: adminPort,
		AdminUser: DefaultAdminUser, AdminPassword: adminPassword, Secrets: secrets, Lease: lease, LocalTargets: localTargets,
		ServerProxyURL: guard.proxyURL, ServerDialHost: guard.dialHost, ServerDialPort: guard.dialPort,
	})
	if err != nil {
		return err
	}
	if err = writePrivateFile(configPath, []byte(rendered.TOML)); err != nil {
		return fmt.Errorf("write FRP verify config: %w", err)
	}
	return verifyFRPC(ctx, m.core.Path, configPath, dir, managedLeaseEnvironment(lease))
}
func (m *Manager) startInstance(ctx context.Context, cfg Config, token string, secrets map[string]string, lease *Lease) (*managedInstance, error) {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		inst, err := m.startInstanceOnce(ctx, cfg, token, secrets, lease)
		if err == nil {
			return inst, nil
		}
		lastErr = err
		if ErrorCode(err) != CodeLocalListenBusy {
			break
		}
	}
	return nil, lastErr
}

func (m *Manager) startInstanceOnce(ctx context.Context, cfg Config, token string, secrets map[string]string, lease *Lease) (result *managedInstance, retErr error) {
	generation := m.nextInstanceGeneration()
	endpointScope := endpointScopeFor(cfg.Profile.ID, generation)
	endpointRegistry := m.endpointRegistry()
	endpointRegistered := false
	defer func() {
		if endpointRegistered && result == nil {
			endpointRegistry.RemoveScope(endpointScope)
		}
	}()
	adminPort, err := freeLoopbackPort()
	if err != nil {
		return nil, codedError(CodeLocalListenBusy, "分配 FRP 管理端口失败: %v", err)
	}
	if err = m.validateTargetReservations(cfg, TargetReservation{
		Host: "127.0.0.1", Port: adminPort, Purpose: "active frpc administration listener",
	}); err != nil {
		return nil, err
	}
	adminPassword, err := NewSecret(32)
	if err != nil {
		return nil, err
	}
	logSecrets := append([]string{token, adminPassword}, mapValues(secrets)...)
	if lease != nil {
		logSecrets = append(logSecrets, lease.Credential)
	}
	m.logs.setSecrets(logSecrets...)
	instanceID, err := NewSecret(8)
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(m.store.RuntimeRoot(), "instance-"+instanceID)
	if err = os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create FRP runtime directory: %w", err)
	}
	if err = secureDirectory(dir); err != nil {
		return nil, withCleanupErrors(err, os.RemoveAll(dir))
	}
	tokenPath := filepath.Join(dir, "token.txt")
	configPath := filepath.Join(dir, "frpc.toml")
	if err = writePrivateFile(tokenPath, []byte(token)); err != nil {
		return nil, withCleanupErrors(fmt.Errorf("write FRP token file: %w", err), os.RemoveAll(dir))
	}
	if err = checkVisitorBindings(cfg); err != nil {
		return nil, withCleanupErrors(err, os.RemoveAll(dir))
	}
	runtimeCtx, runtimeCancel := context.WithCancel(context.Background())
	m.meshMu.RLock()
	meshPrefixes := append([]netip.Prefix(nil), m.meshCIDRs...)
	m.meshMu.RUnlock()
	guard, err := m.startEgressGuard(runtimeCtx, cfg, meshPrefixes)
	if err != nil {
		runtimeCancel()
		return nil, withCleanupErrors(err, os.RemoveAll(dir))
	}
	if guard.tcp != nil {
		logSecrets = append(logSecrets, guard.tcp.password)
	}
	m.logs.setSecrets(logSecrets...)

	var gateways []*targetgateway.Gateway
	var gatewayCancel context.CancelFunc
	var localTargets map[string]Target
	resourcesOwned := true
	defer func() {
		if !resourcesOwned {
			return
		}
		var cleanup []error
		for _, gateway := range gateways {
			if gateway != nil {
				cleanup = append(cleanup, gateway.Close())
			}
		}
		if gatewayCancel != nil {
			gatewayCancel()
		}
		cleanup = append(cleanup, guard.Close())
		runtimeCancel()
		retErr = withCleanupErrors(retErr, cleanup...)
	}()

	proxyReservation := guard.reservation
	if err = m.validateTargetReservations(cfg, proxyReservation); err != nil {
		return nil, withCleanupErrors(err, os.RemoveAll(dir))
	}
	var gatewaysByRule map[string]*targetgateway.Gateway
	localTargets, gateways, gatewaysByRule, gatewayCancel, err = m.prepareGateways(runtimeCtx, cfg, lease)
	if err != nil {
		return nil, withCleanupErrors(err, os.RemoveAll(dir))
	}
	reservations := append(gatewayTargetReservations(gateways), proxyReservation)
	if err = m.validateTargetReservations(cfg, reservations...); err != nil {
		return nil, withCleanupErrors(err, os.RemoveAll(dir))
	}
	if err = endpointRegistry.ReplaceScope(endpointScope, instanceEndpointRecords(cfg, generation, endpointScope, adminPort, guard, gatewaysByRule)); err != nil {
		return nil, withCleanupErrors(codedError(CodeUnsupportedFeature, "FRP listener ownership conflict: %v", err), os.RemoveAll(dir))
	}
	endpointRegistered = true
	rendered, err := RenderConfig(RenderInput{
		Config: cfg, DeviceID: m.deviceID, TokenPath: tokenPath, AdminPort: adminPort,
		AdminUser: DefaultAdminUser, AdminPassword: adminPassword, Secrets: secrets, Lease: lease, LocalTargets: localTargets,
		ServerProxyURL: guard.proxyURL, ServerDialHost: guard.dialHost, ServerDialPort: guard.dialPort,
	})
	if err != nil {
		return nil, withCleanupErrors(err, os.RemoveAll(dir))
	}
	if err = writePrivateFile(configPath, []byte(rendered.TOML)); err != nil {
		return nil, withCleanupErrors(fmt.Errorf("write FRP runtime config: %w", err), os.RemoveAll(dir))
	}
	leaseEnv := managedLeaseEnvironment(lease)
	if err = verifyFRPC(ctx, m.core.Path, configPath, dir, leaseEnv); err != nil {
		return nil, withCleanupErrors(err, os.RemoveAll(dir))
	}
	process, err := launchRestricted(m.core.Path, configPath, dir, leaseEnv)
	if err != nil {
		return nil, withCleanupErrors(err, os.RemoveAll(dir))
	}
	inst := &managedInstance{
		dir: dir, generation: generation, configPath: configPath, tokenPath: tokenPath, adminPort: adminPort,
		adminUser: DefaultAdminUser, adminPassword: adminPassword, config: cfg,
		rendered: rendered, process: process, done: make(chan struct{}), lease: lease, gateways: gateways,
		gatewaysByRule: gatewaysByRule, gatewayCancel: gatewayCancel, runtimeCancel: runtimeCancel,
		egressProxy: guard.tcp, udpEgressProxy: guard.udp,
		endpointScope: endpointScope, endpointOwner: endpointRegistry,
	}
	resourcesOwned = false
	m.mu.Lock()
	m.startingInstance = inst
	m.mu.Unlock()
	inst.admin = NewAdminClient(adminPort, DefaultAdminUser, adminPassword)
	if err = writeLedger(dir, process); err != nil {
		return nil, m.stopStartedInstance(inst, fmt.Errorf("write FRP resource ledger: %w", err))
	}
	m.startLogReaders(inst)
	go m.watchProcess(inst)
	for ruleID, gateway := range gatewaysByRule {
		go m.watchGateway(inst, ruleID, gateway)
	}
	if err = m.waitReady(ctx, inst); err != nil {
		return nil, m.stopStartedInstance(inst, err)
	}
	if err = m.verifyManagedLease(ctx, cfg, lease); err != nil {
		return nil, m.stopStartedInstance(inst, err)
	}
	m.startLeaseWatch(inst)
	return inst, nil
}

func (m *Manager) stopStartedInstance(inst *managedInstance, cause error) error {
	if inst == nil {
		return cause
	}
	inst.stopping.Store(true)
	m.mu.Lock()
	if m.startingInstance == inst {
		m.startingInstance = nil
	}
	m.mu.Unlock()
	var cleanup []error
	if inst.process != nil {
		select {
		case <-inst.done:
		default:
			if err := windows.TerminateJobObject(inst.process.Job, 1); err != nil {
				cleanup = append(cleanup, fmt.Errorf("terminate owned FRP job: %w", err))
			}
			event, waitErr := windows.WaitForSingleObject(inst.process.Process, 3000)
			if waitErr != nil {
				cleanup = append(cleanup, fmt.Errorf("wait for FRP process termination: %w", waitErr))
			} else if event != uint32(windows.WAIT_OBJECT_0) {
				cleanup = append(cleanup, fmt.Errorf("FRP process did not terminate, wait result %#x", event))
			}
		}
	}
	cleanup = append(cleanup, inst.reap())
	return withCleanupErrors(cause, cleanup...)
}
func checkVisitorBindings(cfg Config) error {
	for _, visitor := range cfg.Profile.Visitors {
		if !visitor.Enabled {
			continue
		}
		addr := net.JoinHostPort(visitor.BindAddr, fmt.Sprint(visitor.BindPort))
		if visitor.Type == "sudp" {
			conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: visitor.BindPort})
			if err != nil {
				return codedError(CodeLocalListenBusy, "visitor %q cannot bind %s: %v", visitor.Name, addr, err)
			}
			_ = conn.Close()
			continue
		}
		listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: visitor.BindPort})
		if err != nil {
			return codedError(CodeLocalListenBusy, "visitor %q cannot bind %s: %v", visitor.Name, addr, err)
		}
		_ = listener.Close()
	}
	return nil
}

func freeLoopbackPort() (int, error) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port, nil
}

func (m *Manager) startLogReaders(inst *managedInstance) {
	stdout := os.NewFile(uintptr(inst.process.Stdout), "frpc-stdout")
	stderr := os.NewFile(uintptr(inst.process.Stderr), "frpc-stderr")
	inst.process.Stdout = 0
	inst.process.Stderr = 0
	go m.readLog(inst, stdout)
	go m.readLog(inst, stderr)
}

func (m *Manager) readLog(inst *managedInstance, file *os.File) {
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 256*1024)
	for scanner.Scan() {
		line := scanner.Text()
		m.logs.add(line)
		if strings.Contains(strings.ToLower(line), "login to server success") {
			inst.loggedIn.Store(true)
		}
		if inst.leaseMonitor.Load() {
			if reason := terminalManagedLeaseLog(line); reason != "" {
				go m.failManagedLease(inst, errors.New(reason))
			}
		}
	}
}

func terminalManagedLeaseLog(line string) string {
	upper := strings.ToUpper(line)
	switch {
	case strings.Contains(upper, "FRP_LEASE_REVOKED"):
		return "FRPS rejected the managed FRP lease: lease revoked"
	case strings.Contains(upper, "FRP_LEASE_EXPIRED"):
		return "FRPS rejected the managed FRP lease: lease expired"
	default:
		return ""
	}
}

func (m *Manager) watchProcess(inst *managedInstance) {
	code, err := waitProcess(inst.process.Process)
	inst.exitCode = code
	close(inst.done)
	reapErr := inst.reap()
	if inst.stopping.Load() {
		if reapErr != nil {
			m.logs.add(fmt.Sprintf("FRP process cleanup deferred to stop path: %v", reapErr))
		}
		return
	}
	message := m.logs.text()
	if err != nil && message == "" {
		message = err.Error()
	}
	cause := classifyStartupError(message)
	leaseErr := m.releaseInstanceLease(context.Background(), inst)
	m.handleProcessExit(inst, cause, reapErr, leaseErr)
}

// handleProcessExit is the only place a process-exit callback may mutate
// global Manager state. An old instance can finish after a replacement has
// been committed, so pointer identity and generation must both match.
func (m *Manager) handleProcessExit(inst *managedInstance, cause error, reapErr, leaseErr error) {
	m.mu.Lock()
	if !m.instanceMatchesLocked(inst) {
		m.mu.Unlock()
		if reapErr != nil || leaseErr != nil {
			m.logs.add(fmt.Sprintf("stale FRP instance cleanup error (instance=%p generation=%d): cleanup=%v lease=%v", inst, inst.generation, reapErr, leaseErr))
		}
		return
	}
	shouldRetry := m.desiredRun.Load() && isRetryableStartError(cause)
	if m.desiredRun.Load() && !shouldRetry {
		m.desiredRun.Store(false)
	}
	m.instance = nil
	m.state = "failed"
	m.lastErr = cause
	if reapErr != nil {
		m.lastErr = codedError(CodeCleanupIncomplete, "%v；运行目录清理失败: %v", cause, reapErr)
	} else if leaseErr != nil {
		m.lastErr = leaseErr
	}
	m.mu.Unlock()
	if shouldRetry {
		go m.retryDependency()
	}
}
func (m *Manager) waitReady(ctx context.Context, inst *managedInstance) error {
	deadline := time.Now().Add(15 * time.Second)
	enabled := 0
	for _, rule := range inst.config.Profile.Rules {
		if rule.Enabled {
			enabled++
		}
	}
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-inst.done:
			return classifyStartupError(m.logs.text())
		case <-time.After(200 * time.Millisecond):
		}
		statusCtx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
		status, err := inst.admin.Status(statusCtx)
		cancel()
		logs := m.logs.text()
		if terminalStartupLog(logs) {
			return classifyStartupError(logs)
		}
		if err != nil {
			if ErrorCode(err) == CodeAdminUnauthorized {
				return err
			}
			continue
		}
		registered := 0
		for _, rule := range inst.config.Profile.Rules {
			if !rule.Enabled {
				continue
			}
			name := inst.rendered.ProxyNames[rule.ID]
			var proxy ProxyStatus
			found := false
			for _, list := range status {
				for _, candidate := range list {
					if candidate.Name == name {
						proxy, found = candidate, true
						break
					}
				}
				if found {
					break
				}
			}
			if !found {
				continue
			}
			if proxy.Err != "" {
				return classifyProxyError(proxy.Err)
			}
			if strings.EqualFold(proxy.Status, "running") &&
				(rule.Type == "http" || rule.Type == "https" || rule.Type == "stcp" || rule.Type == "sudp" || rule.Type == "tcpmux" || rule.Type == "xtcp" || proxy.RemoteAddr != "") {
				registered++
				inst.loggedIn.Store(true)
			}
		}
		if enabled == 0 && inst.loggedIn.Load() {
			return nil
		}
		if registered >= enabled && inst.loggedIn.Load() {
			return nil
		}
	}
	logs := m.logs.text()
	if strings.Contains(strings.ToLower(logs), "login to server failed") {
		return classifyStartupError(logs)
	}
	if inst.loggedIn.Load() {
		return codedError(CodeProcessFailed, "FRP 已登录，但代理在超时前未完成注册")
	}
	return codedError(CodeServerUnreachable, "在超时前未能连接 FRP 服务器")
}

func (inst *managedInstance) reap() error {
	inst.reapOnce.Do(func() {
		var cleanupErrors []error
		for _, gateway := range inst.gateways {
			if gateway != nil {
				cleanupErrors = append(cleanupErrors, gateway.Close())
			}
		}
		inst.gateways = nil
		inst.gatewayMu.Lock()
		inst.gatewaysByRule = nil
		inst.gatewayMu.Unlock()
		if inst.gatewayCancel != nil {
			inst.gatewayCancel()
			inst.gatewayCancel = nil
		}
		if inst.runtimeCancel != nil {
			inst.runtimeCancel()
		}
		if inst.egressProxy != nil {
			cleanupErrors = append(cleanupErrors, inst.egressProxy.Close())
			inst.egressProxy = nil
		}
		if inst.udpEgressProxy != nil {
			cleanupErrors = append(cleanupErrors, inst.udpEgressProxy.Close())
			inst.udpEgressProxy = nil
		}
		if inst.process != nil {
			cleanupErrors = append(cleanupErrors, closeHandlesErr(inst.process.Stdin, inst.process.Stdout, inst.process.Stderr, inst.process.Process, inst.process.Job))
			inst.process.Stdin = 0
			inst.process.Stdout = 0
			inst.process.Stderr = 0
			inst.process.Process = 0
			inst.process.Job = 0
		}
		if inst.endpointOwner != nil {
			inst.endpointOwner.RemoveScope(inst.endpointScope)
			inst.endpointOwner = nil
		}
		cleanupErrors = append(cleanupErrors, os.RemoveAll(inst.dir))
		inst.reapErr = errors.Join(cleanupErrors...)
	})
	return inst.reapErr
}

func (m *Manager) Snapshot(ctx context.Context) Snapshot {
	m.mu.Lock()
	cfg := CloneConfig(m.config)
	configured := m.hasConfig
	state := m.state
	inst := m.instance
	lastErr := m.lastErr
	desired := m.desiredRun.Load()
	canStop := desired || inst != nil || state == "starting" || state == "stopping" || state == "waiting_dependency" || state == "retry_backoff"
	m.mu.Unlock()

	snapshot := Snapshot{
		Configured: configured, DesiredRunning: desired, CanStop: canStop, State: state, CoreVersion: m.core.Version, CoreHash: m.core.SHA256,
		ProfileName: cfg.Profile.Name, ServerHost: cfg.Profile.Server.Host,
		ServerPort: cfg.Profile.Server.Port, Revision: cfg.Profile.Revision,
		SharedToken: configured && m.store.HasToken(cfg.Profile.Server.CredentialRef),
		Endpoints:   m.Endpoints(), Observation: m.observationStatus(), Logs: m.logs.snapshot(),
	}
	if lastErr != nil {
		snapshot.LastError = lastErr.Error()
		snapshot.LastErrorCode = ErrorCode(lastErr)
	}
	if inst != nil {
		select {
		case <-inst.done:
			snapshot.Running = false
		default:
			snapshot.Running = true
		}
		snapshot.Authenticated = inst.loggedIn.Load()
	}
	status := StatusResponse{}
	if inst != nil && snapshot.Running {
		statusCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		got, err := inst.admin.Status(statusCtx)
		cancel()
		if err == nil {
			status = got
		}
	}
	byName := make(map[string]ProxyStatus)
	for _, list := range status {
		for _, proxy := range list {
			byName[proxy.Name] = proxy
		}
	}
	var gatewaysByRule map[string]*targetgateway.Gateway
	if inst != nil {
		inst.gatewayMu.RLock()
		gatewaysByRule = make(map[string]*targetgateway.Gateway, len(inst.gatewaysByRule))
		for ruleID, gateway := range inst.gatewaysByRule {
			gatewaysByRule[ruleID] = gateway
		}
		inst.gatewayMu.RUnlock()
	}
	ruleByID := make(map[string]Rule, len(cfg.Profile.Rules))
	for _, rule := range cfg.Profile.Rules {
		ruleByID[rule.ID] = rule
	}
	diagnostics, _ := m.meshTargets.(interface{ TargetPath(Rule) string })
	for ruleID, gateway := range gatewaysByRule {
		state := "运行中"
		select {
		case <-gateway.LeaseInvalid():
			state = "依赖失效"
		case <-gateway.Done():
			state = "已停止"
		default:
		}
		path := ""
		if diagnostics != nil {
			path = diagnostics.TargetPath(ruleByID[ruleID])
		}
		snapshot.Gateways = append(snapshot.Gateways, GatewayRuntimeStatus{
			RuleID: ruleID, Protocol: string(gateway.Protocol()), Address: gateway.Addr().String(), Path: path, State: state, Stats: gateway.Stats(),
		})
	}
	for _, rule := range cfg.Profile.Rules {
		row := RuleRuntimeStatus{RuleID: rule.ID, Name: rule.Name, Type: strings.ToUpper(rule.Type), Enabled: rule.Enabled}
		if !rule.Enabled {
			row.State = "已禁用"
			row.Backend = "—"
		} else if !snapshot.Running {
			row.State = "已停止"
			row.Backend = "—"
		} else {
			row.State = "等待注册"
			proxy, ok := byName[inst.rendered.ProxyNames[rule.ID]]
			if ok {
				row.RemoteAddr = proxyRemoteAddress(rule, proxy.RemoteAddr, cfg.Profile.Server)
				if proxy.Err != "" {
					row.State = "注册失败"
					row.ErrorDetail = proxy.Err
					row.ErrorCode = ErrorCode(classifyProxyError(proxy.Err))
				} else if strings.EqualFold(proxy.Status, "running") {
					row.State = "已注册"
					snapshot.Authenticated = true
				} else if proxy.Status != "" {
					row.State = "等待注册"
				}
			}
			if gateway := gatewaysByRule[rule.ID]; gateway != nil {
				stats := gateway.Stats()
				row.GatewayStats = fmt.Sprintf("gen %d · TCP %d/%d 拒绝 %d · UDP %d/%d 丢弃 %d · ↑%d ↓%d B",
					stats.LeaseGeneration, stats.TCPActive, stats.TCPAccepted, stats.TCPRejected,
					stats.UDPActive, stats.UDPAccepted, stats.UDPDropped, stats.BytesToTarget, stats.BytesFromTarget)
				if diagnostics != nil {
					if path := diagnostics.TargetPath(rule); path != "" {
						row.GatewayStats += " · " + path
					}
				}
				row.Backend = row.GatewayStats
			} else if rule.Target.Kind == "mesh_peer" || rule.Target.Kind == "mesh_self" {
				row.Backend = "依赖未就绪"
			} else if rule.Type == "udp" || rule.Type == "sudp" {
				row.Backend = "未主动探测"
			} else if probeTCP(rule.Target.Host, rule.Target.Port) {
				row.Backend = "可用"
			} else {
				row.Backend = "不可达"
				if row.ErrorCode == "" {
					row.ErrorCode = CodeBackendUnreachable
					row.ErrorDetail = rule.Target.Host + ":" + fmt.Sprint(rule.Target.Port) + " 未接受连接"
				}
			}
		}
		snapshot.Rules = append(snapshot.Rules, row)
	}
	for _, visitor := range cfg.Profile.Visitors {
		row := VisitorRuntimeStatus{VisitorID: visitor.ID, Name: visitor.Name, Type: strings.ToUpper(visitor.Type), Enabled: visitor.Enabled, BindAddr: visitor.BindAddr, BindPort: visitor.BindPort}
		switch {
		case !visitor.Enabled:
			row.State = "已禁用"
		case !snapshot.Running:
			row.State = "已停止"
		case visitorBindObserved(visitor):
			row.State = "监听中"
		default:
			row.State = "等待绑定"
			row.ErrorDetail = "本机访问端口尚未处于监听状态"
		}
		snapshot.Visitors = append(snapshot.Visitors, row)
	}
	return snapshot
}

func visitorBindObserved(visitor Visitor) bool {
	if visitor.Type == "sudp" {
		conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: visitor.BindPort})
		if err != nil {
			return true
		}
		_ = conn.Close()
		return false
	}
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: visitor.BindPort})
	if err != nil {
		return true
	}
	_ = listener.Close()
	return false
}

func probeTCP(host string, port int) bool {
	conn, err := net.DialTimeout("tcp4", net.JoinHostPort(host, fmt.Sprint(port)), 250*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func proxyRemoteAddress(rule Rule, remote string, server Server) string {
	remote = strings.TrimSpace(remote)
	switch rule.Type {
	case "http", "https", "tcpmux":
		if remote == "" {
			return ruleAccessAddress(rule, server)
		}
		if !strings.Contains(remote, "://") {
			return rule.Type + "://" + remote
		}
		return remote
	case "tcp", "udp":
		if remote == "" && rule.Exposure.RemotePort > 0 {
			return net.JoinHostPort(server.Host, fmt.Sprint(rule.Exposure.RemotePort))
		}
		if strings.HasPrefix(remote, ":") {
			return net.JoinHostPort(server.Host, strings.TrimPrefix(remote, ":"))
		}
		return remote
	default:
		return remote
	}
}
func ruleAccessAddress(rule Rule, server Server) string {
	host := ""
	if len(rule.Exposure.CustomDomains) > 0 {
		host = rule.Exposure.CustomDomains[0]
	} else if rule.Exposure.Subdomain != "" {
		host = rule.Exposure.Subdomain
		if strings.TrimSpace(server.SubdomainHost) != "" {
			host += "." + strings.TrimSpace(server.SubdomainHost)
		}
	}
	if host == "" {
		return ""
	}
	if rule.Type == "https" {
		return fmt.Sprintf("https://%s:%d", host, server.PublicHTTPSPort)
	}
	if rule.Type == "tcpmux" {
		return fmt.Sprintf("http://%s:%d", host, server.PublicTCPMuxPort)
	}
	return fmt.Sprintf("http://%s:%d", host, server.PublicHTTPPort)
}

func (m *Manager) validatePolicy(cfg Config) error {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	return m.validatePolicyContext(ctx, cfg)
}

func (m *Manager) validatePolicyContext(ctx context.Context, cfg Config) error {
	m.meshMu.RLock()
	meshCIDRs := append([]netip.Prefix(nil), m.meshCIDRs...)
	m.meshMu.RUnlock()
	m.mu.Lock()
	networkID := m.networkID
	deviceID := m.deviceID
	observer := m.observer
	meshInterface := m.meshInterface
	m.mu.Unlock()

	for _, rule := range cfg.Profile.Rules {
		if err := targetInsidePrefixes(rule.Target, meshCIDRs); err != nil {
			return err
		}
	}
	if hasMeshTarget(cfg) {
		if len(meshCIDRs) != 1 {
			return codedError(CodeMeshDependencyDown, "active TLAN network prefix is unavailable; start or restore Mesh before applying Mesh targets")
		}
		if err := ValidateMeshTargetPolicy(cfg, networkID, deviceID, meshCIDRs[0]); err != nil {
			return err
		}
	}
	if err := checkFRPSEgressOnInterface(ctx, observer, cfg, meshCIDRs, meshInterface); err != nil {
		return err
	}
	return m.validateTargetReservations(cfg)
}

func (m *Manager) validateTargetReservations(cfg Config, extra ...TargetReservation) error {
	reservations := append([]TargetReservation(nil), m.ReservedTargets()...)
	reservations = append(reservations, configListenerReservations(cfg)...)
	m.mu.Lock()
	external := m.reservations
	registry := m.endpoints
	m.mu.Unlock()
	if registry != nil {
		reservations = append(reservations, registry.Reservations()...)
	}
	if external != nil {
		reservations = append(reservations, external()...)
	}
	reservations = append(reservations, extra...)
	if len(reservations) == 0 {
		return nil
	}
	return ValidateConfigWithReservations(cfg, reservations)
}

func (m *Manager) verifyManagedLease(ctx context.Context, cfg Config, lease *Lease) error {
	if cfg.Profile.Server.Kind != "managed" || lease == nil {
		return nil
	}
	verifier, ok := m.leaseProvider.(LeaseVerifier)
	if !ok {
		return codedError(CodeAuthRejected, "managed lease verifier is unavailable")
	}
	requireProxy := false
	for _, rule := range cfg.Profile.Rules {
		if rule.Enabled {
			requireProxy = true
			break
		}
	}
	verifyCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := verifier.VerifyActive(verifyCtx, lease.ID, requireProxy); err != nil {
		return codedError(CodeAuthRejected, "FRPS managed authorization was not observed: %v", err)
	}
	return nil
}

func managedLeaseEnvironment(lease *Lease) map[string]string {
	if lease == nil || lease.Credential == "" {
		return nil
	}
	return map[string]string{managedCapabilityEnv: lease.Credential}
}

func mapValues(values map[string]string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value != "" {
			result = append(result, value)
		}
	}
	return result
}

func hasMeshTarget(cfg Config) bool {
	for _, rule := range cfg.Profile.Rules {
		if rule.Enabled && (rule.Target.Kind == "mesh_peer" || rule.Target.Kind == "mesh_self") {
			return true
		}
	}
	return false
}

func (m *Manager) validateLeaseGrant(cfg Config, lease *Lease, providedSecrets ...map[string]string) error {
	if cfg.Profile.Server.Kind != "managed" {
		return nil
	}
	secrets := map[string]string{}
	if len(providedSecrets) > 0 && providedSecrets[0] != nil {
		secrets = providedSecrets[0]
	}
	expected, err := m.buildLeaseRules(cfg, secrets)
	if err != nil {
		return err
	}
	if lease == nil {
		return codedError(CodeAuthRejected, "managed FRP lease response is missing")
	}
	if len(lease.Rules) == 0 {
		for _, want := range expected {
			if want.TargetKind == "mesh_peer" || want.TargetKind == "mesh_self" {
				return codedError(CodeAuthRejected, "managed FRP lease response is missing Mesh target grants")
			}
		}
		return nil
	}
	byID := make(map[string]LeaseRule, len(lease.Rules))
	for _, granted := range lease.Rules {
		if _, exists := byID[granted.ID]; exists {
			return codedError(CodeAuthRejected, "managed FRP lease response contains a duplicate rule")
		}
		byID[granted.ID] = granted
	}
	for _, want := range expected {
		granted, ok := byID[want.ID]
		mesh := want.TargetKind == "mesh_peer" || want.TargetKind == "mesh_self"
		if !ok {
			return codedError(CodeAuthRejected, "managed FRP lease response is missing rule %q", want.ID)
		}
		if !sameLeaseRule(want, granted, mesh) {
			return codedError(CodeAuthRejected, "managed FRP lease response for rule %q does not match the requested authorization", want.ID)
		}
	}
	for id := range byID {
		found := false
		for _, want := range expected {
			if want.ID == id {
				found = true
				break
			}
		}
		if !found {
			return codedError(CodeAuthRejected, "managed FRP lease response contains an unexpected rule %q", id)
		}
	}
	return nil
}

func (m *Manager) acquireLease(ctx context.Context, cfg Config) (*Lease, error) {
	if cfg.Profile.Server.Kind != "managed" {
		if hasMeshTarget(cfg) {
			return nil, unsupported("Mesh target rules require server.kind = managed")
		}
		return nil, nil
	}
	secrets, err := m.resolveSecrets(cfg, nil)
	if err != nil {
		return nil, err
	}
	return m.acquireLeaseWithSecrets(ctx, cfg, secrets)
}

func (m *Manager) acquireLeaseWithSecrets(ctx context.Context, cfg Config, secrets map[string]string) (*Lease, error) {
	if cfg.Profile.Server.Kind != "managed" {
		if hasMeshTarget(cfg) {
			return nil, unsupported("Mesh target rules require server.kind = managed")
		}
		return nil, nil
	}
	if m.leaseProvider == nil {
		return nil, codedError(CodeAuthRejected, "managed FRP lease provider is not configured")
	}
	rules, err := m.buildLeaseRules(cfg, secrets)
	if err != nil {
		return nil, err
	}
	request := LeaseRequest{NetworkID: m.networkID, DeviceID: m.deviceID, ServerID: cfg.Profile.Server.ServerID, Rules: rules, TTL: 10 * time.Minute, TTLSeconds: 600}
	lease, err := m.leaseProvider.Acquire(ctx, request)
	if err != nil {
		return nil, withCode(CodeAuthRejected, err)
	}
	if lease.ID == "" || lease.Credential == "" || !lease.ExpiresAt.After(time.Now()) {
		return nil, codedError(CodeAuthRejected, "managed FRP lease response is incomplete or already expired")
	}
	if err = m.validateLeaseGrant(cfg, &lease, secrets); err != nil {
		_ = m.releaseLease(ctx, &lease)
		return nil, err
	}
	return &lease, nil
}

func (m *Manager) buildLeaseRules(cfg Config, secrets map[string]string) ([]LeaseRule, error) {
	rules := make([]LeaseRule, 0, len(cfg.Profile.Rules))
	for _, rule := range cfg.Profile.Rules {
		if !rule.Enabled {
			continue
		}
		secretHash := ""
		if rule.SecretRef != "" {
			secret, ok := secrets[rule.SecretRef]
			if !ok || secret == "" {
				return nil, codedError(CodeConfigurationInvalid, "FRP secret %q is unavailable for the managed lease", rule.SecretRef)
			}
			secretHash = frpauth.HashSecret(secret)
		}
		httpPasswordHash := ""
		if rule.Exposure.HTTPPasswordRef != "" {
			password, ok := secrets[rule.Exposure.HTTPPasswordRef]
			if !ok || password == "" {
				return nil, codedError(CodeConfigurationInvalid, "HTTP password %q is unavailable for the managed lease", rule.Exposure.HTTPPasswordRef)
			}
			httpPasswordHash = frpauth.HashSecret(password)
		}
		targetKind := ""
		targetNetworkID := ""
		targetDeviceID := ""
		targetPublicKey := ""
		targetHost := ""
		targetServiceID := ""
		if rule.Target.Kind == "mesh_peer" || rule.Target.Kind == "mesh_self" {
			targetKind = rule.Target.Kind
			targetNetworkID = rule.Target.NetworkID
			if targetNetworkID == "" {
				targetNetworkID = m.networkID
			}
			targetDeviceID = rule.Target.DeviceID
			if targetDeviceID == "" && rule.Target.Kind == "mesh_self" {
				targetDeviceID = m.deviceID
			}
			targetPublicKey = rule.Target.PublicKey
			targetHost = rule.Target.Host
			targetServiceID = rule.Target.ServiceID
			if rule.Target.Kind == "mesh_peer" && targetServiceID == "" {
				return nil, codedError(CodeConfigurationInvalid, "mesh_peer rule %q requires the approved target service ID", rule.Name)
			}
		}
		rules = append(rules, LeaseRule{
			ID: rule.ID, ProxyName: ProxyName(m.deviceID, cfg.Profile.ID, rule.ID), Type: rule.Type,
			RemotePort: rule.Exposure.RemotePort, CustomDomains: append([]string(nil), rule.Exposure.CustomDomains...),
			BindPort:  rule.Target.Port,
			SubDomain: rule.Exposure.Subdomain, Locations: append([]string(nil), rule.Exposure.Locations...),
			HTTPUser: rule.Exposure.HTTPUser, HTTPPasswordHash: httpPasswordHash,
			HostHeaderRewrite: rule.Exposure.HostHeaderRewrite, Headers: cloneStringMap(rule.Exposure.RequestHeaders),
			ResponseHeaders: cloneStringMap(rule.Exposure.ResponseHeaders), RouteByHTTPUser: rule.Exposure.RouteByHTTPUser,
			Multiplexer: rule.Exposure.Multiplexer, SecretHash: secretHash,
			AllowUsers:    append([]string(nil), rule.Exposure.AllowUsers...),
			UseEncryption: rule.Transport.UseEncryption, UseCompression: rule.Transport.UseCompression,
			TargetKind: targetKind, TargetNetworkID: targetNetworkID, TargetDeviceID: targetDeviceID,
			TargetPublicKey: targetPublicKey, TargetHost: targetHost, TargetServiceID: targetServiceID,
		})
	}
	return rules, nil
}

func sameLeaseRule(want, got LeaseRule, mesh bool) bool {
	if want.ID != got.ID {
		return false
	}
	// Older providers may return only target fields for Mesh grants. Accept
	// omitted basic fields, but reject any value that is present and differs.
	if got.ProxyName != "" && want.ProxyName != got.ProxyName {
		return false
	}
	if got.Type != "" && want.Type != got.Type {
		return false
	}
	if got.RemotePort != 0 && want.RemotePort != got.RemotePort {
		return false
	}
	if got.BindPort != 0 && want.BindPort != got.BindPort {
		return false
	}
	if want.SubDomain != got.SubDomain || want.HTTPUser != got.HTTPUser ||
		want.HTTPPasswordHash != got.HTTPPasswordHash || want.HostHeaderRewrite != got.HostHeaderRewrite ||
		want.RouteByHTTPUser != got.RouteByHTTPUser || want.Multiplexer != got.Multiplexer ||
		want.SecretHash != got.SecretHash || want.UseEncryption != got.UseEncryption ||
		want.UseCompression != got.UseCompression || !sameLeaseStringSet(want.CustomDomains, got.CustomDomains) ||
		!sameLeaseStringSet(want.Locations, got.Locations) || !sameLeaseStringSet(want.AllowUsers, got.AllowUsers) ||
		!sameStringMap(want.Headers, got.Headers) || !sameStringMap(want.ResponseHeaders, got.ResponseHeaders) {
		return false
	}
	if mesh {
		if got.GrantID == "" || want.TargetKind != got.TargetKind || want.TargetNetworkID != got.TargetNetworkID ||
			want.TargetDeviceID != got.TargetDeviceID || want.TargetHost != got.TargetHost ||
			want.TargetServiceID != got.TargetServiceID || got.TargetPublicKey == "" {
			return false
		}
		if want.TargetPublicKey != "" && !strings.EqualFold(want.TargetPublicKey, got.TargetPublicKey) {
			return false
		}
	} else if got.TargetKind != "" || got.TargetNetworkID != "" || got.TargetDeviceID != "" ||
		got.TargetPublicKey != "" || got.TargetHost != "" || got.TargetServiceID != "" || got.GrantID != "" {
		return false
	}
	return true
}

func sameLeaseStringSet(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	counts := make(map[string]int, len(left))
	for _, value := range left {
		counts[value]++
	}
	for _, value := range right {
		counts[value]--
	}
	for _, count := range counts {
		if count != 0 {
			return false
		}
	}
	return true
}

func (m *Manager) takeInstanceLease(inst *managedInstance) *Lease {
	if inst == nil {
		return nil
	}
	inst.leaseMonitor.Store(false)
	inst.leaseMu.Lock()
	lease := inst.lease
	inst.lease = nil
	cancel := inst.leaseCancel
	inst.leaseCancel = nil
	inst.leaseMu.Unlock()
	if cancel != nil {
		cancel()
	}
	return lease
}

func (m *Manager) releaseInstanceLease(ctx context.Context, inst *managedInstance) error {
	return m.releaseLease(ctx, m.takeInstanceLease(inst))
}

func leaseRenewDelay(now, expiresAt time.Time) time.Duration {
	// Renewal is also the revocation heartbeat. Keep it well below the
	// 10-second managed revocation SLA even when the server TTL is long.
	delay := expiresAt.Sub(now) / 3
	if delay > 5*time.Second {
		delay = 5 * time.Second
	}
	if delay < 250*time.Millisecond {
		delay = 250 * time.Millisecond
	}
	return delay
}

func (m *Manager) startLeaseWatch(inst *managedInstance) {
	if inst == nil || inst.config.Profile.Server.Kind != "managed" || m.leaseProvider == nil {
		return
	}
	inst.leaseMu.Lock()
	if inst.lease == nil || inst.leaseCancel != nil {
		inst.leaseMu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	inst.leaseCancel = cancel
	inst.leaseMonitor.Store(true)
	inst.leaseMu.Unlock()
	go m.watchLease(ctx, inst)
}

func (m *Manager) watchLease(ctx context.Context, inst *managedInstance) {
	retryDelay := time.Duration(0)
	for {
		inst.leaseMu.Lock()
		lease := inst.lease
		inst.leaseMu.Unlock()
		if lease == nil {
			return
		}
		delay := leaseRenewDelay(time.Now(), lease.ExpiresAt)
		if retryDelay > 0 && retryDelay < delay {
			delay = retryDelay
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-inst.done:
			timer.Stop()
			return
		case <-timer.C:
		}

		renewCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
		renewed, err := m.leaseProvider.Renew(renewCtx, lease.ID)
		cancel()
		if ctx.Err() != nil || inst.stopping.Load() {
			return
		}
		if err == nil {
			now := time.Now()
			if renewed.ID == "" || !renewed.ExpiresAt.After(now) {
				err = fmt.Errorf("invalid managed FRP lease renewal response")
			} else {
				inst.leaseMu.Lock()
				if inst.lease != nil && inst.lease.ID == lease.ID {
					if renewed.Credential == "" {
						renewed.Credential = inst.lease.Credential
					}
					if len(renewed.Rules) == 0 {
						renewed.Rules = append([]LeaseRule(nil), inst.lease.Rules...)
					}
					inst.lease.ExpiresAt = renewed.ExpiresAt
					inst.lease.Rules = append([]LeaseRule(nil), renewed.Rules...)
				}
				inst.leaseMu.Unlock()
				retryDelay = 0
				continue
			}
		}
		if errors.Is(err, ErrLeaseTerminal) {
			m.failManagedLease(inst, err)
			return
		}
		remaining := time.Until(lease.ExpiresAt)
		if remaining <= 5*time.Second {
			m.failManagedLease(inst, fmt.Errorf("managed FRP lease renewal failed before expiry: %w", err))
			return
		}
		retryDelay = 3 * time.Second
		if remaining/2 < retryDelay {
			retryDelay = remaining / 2
		}
		if retryDelay < time.Second {
			retryDelay = time.Second
		}
		m.logs.add(fmt.Sprintf("managed FRP lease renewal deferred: %v", err))
	}
}

func (m *Manager) failManagedLease(inst *managedInstance, cause error) {
	if inst == nil || inst.stopping.Load() {
		return
	}
	if !m.isCurrentInstance(inst) {
		m.logs.add(fmt.Sprintf("ignored stale managed lease failure for instance generation %d", inst.generation))
		return
	}
	m.desiredRun.Store(false)
	m.logs.add(fmt.Sprintf("managed FRP lease stopped FRP runtime: %v", cause))
	inst.stopping.Store(true)
	stopErr := m.stopInstance(context.Background(), inst)
	failure := withCode(CodeAuthRejected, cause)
	if stopErr != nil {
		failure = codedError(CodeCleanupIncomplete, "%v；停止 FRP 失败: %v", failure, stopErr)
	}
	m.mu.Lock()
	if m.instance == nil || m.instanceMatchesLocked(inst) {
		m.instance = nil
		m.state = "failed"
		m.lastErr = failure
	}
	m.mu.Unlock()
}

func (m *Manager) releaseLease(ctx context.Context, lease *Lease) error {
	if lease == nil || m.leaseProvider == nil || lease.ID == "" {
		return nil
	}
	releaseCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := m.leaseProvider.Release(releaseCtx, lease.ID); err != nil {
		return codedError(CodeCleanupIncomplete, "release managed FRP lease: %v", err)
	}
	return nil
}

func (m *Manager) prepareGateways(ctx context.Context, cfg Config, lease *Lease) (map[string]Target, []*targetgateway.Gateway, map[string]*targetgateway.Gateway, context.CancelFunc, error) {
	gatewayCtx, cancel := context.WithCancel(ctx)
	localTargets := make(map[string]Target)
	gateways := make([]*targetgateway.Gateway, 0)
	gatewaysByRule := make(map[string]*targetgateway.Gateway)
	closeAll := func() error {
		var cleanup []error
		for _, gateway := range gateways {
			if gateway != nil {
				cleanup = append(cleanup, gateway.Close())
			}
		}
		cancel()
		return errors.Join(cleanup...)
	}
	fail := func(cause error) (map[string]Target, []*targetgateway.Gateway, map[string]*targetgateway.Gateway, context.CancelFunc, error) {
		return nil, nil, nil, nil, withCleanupErrors(cause, closeAll())
	}
	for _, rule := range cfg.Profile.Rules {
		if !rule.Enabled || (rule.Target.Kind != "mesh_peer" && rule.Target.Kind != "mesh_self") {
			continue
		}
		if m.meshTargets == nil {
			return fail(codedError(CodeMeshDependencyDown, "rule %q requires a Mesh target provider", rule.Name))
		}
		effective := rule
		if lease != nil {
			for _, granted := range lease.Rules {
				if granted.ID != rule.ID {
					continue
				}
				effective.Target.Kind = granted.TargetKind
				effective.Target.NetworkID = granted.TargetNetworkID
				effective.Target.DeviceID = granted.TargetDeviceID
				effective.Target.Host = granted.TargetHost
				effective.Target.PublicKey = granted.TargetPublicKey
				effective.Target.ServiceID = granted.TargetServiceID
				break
			}
		}
		target, meshLease, dialer, err := m.meshTargets.PrepareTarget(gatewayCtx, effective)
		if err != nil {
			return fail(withCode(CodeMeshDependencyDown, err))
		}
		if meshLease == nil {
			return fail(codedError(CodeMeshDependencyDown, "Mesh target provider returned no lease validator for rule %q", rule.Name))
		}
		granted, err := meshLease.Validate(gatewayCtx, target)
		if err != nil {
			return fail(withCode(CodeMeshDependencyDown, err))
		}
		if granted.Done != nil {
			select {
			case <-granted.Done:
				return fail(codedError(CodeMeshDependencyDown, "Mesh dependency is already unavailable"))
			default:
			}
		}
		protocol := targetgateway.ProtocolTCP
		if rule.Type == "udp" || rule.Type == "sudp" {
			protocol = targetgateway.ProtocolUDP
		}
		gateway, err := targetgateway.Start(gatewayCtx, targetgateway.Config{Protocol: protocol, Target: target, Lease: meshLease, Dialer: dialer})
		if err != nil {
			return fail(withCode(CodeMeshDependencyDown, err))
		}
		gateways = append(gateways, gateway)
		gatewaysByRule[rule.ID] = gateway
		localTargets[rule.ID] = Target{Kind: "loopback", Host: "127.0.0.1", Port: int(gateway.Addr().Port())}
	}
	return localTargets, gateways, gatewaysByRule, cancel, nil
}
func (m *Manager) watchGateway(inst *managedInstance, ruleID string, gateway *targetgateway.Gateway) {
	if !m.isCurrentOrStartingInstance(inst) {
		return
	}
	var err error
	select {
	case <-gateway.LeaseInvalid():
		err = gateway.LeaseErr()
	case <-gateway.Done():
		err = gateway.Err()
	}
	if !m.isCurrentInstance(inst) {
		if m.isStartingInstance(inst) {
			inst.stopping.Store(true)
			_ = m.stopInstance(context.Background(), inst)
		}
		return
	}
	if inst.stopping.Load() {
		return
	}
	if err == nil || errors.Is(err, targetgateway.ErrClosed) {
		return
	}
	cause := withCode(CodeMeshDependencyDown, err)
	m.logs.add(fmt.Sprintf("Mesh target dependency for rule %s stopped FRP runtime: %v", ruleID, err))
	inst.stopping.Store(true)
	stopErr := m.stopInstance(context.Background(), inst)
	failure := withCleanupErrors(cause, stopErr)
	m.mu.Lock()
	if m.instance != nil {
		m.mu.Unlock()
		return
	}
	if !m.desiredRun.Load() {
		m.state = "stopped"
		m.lastErr = failure
		m.mu.Unlock()
		return
	}
	m.state = "waiting_dependency"
	m.lastErr = failure
	m.mu.Unlock()
	go m.retryDependency()
}

func (m *Manager) retryDependency() {
	if !m.retrying.CompareAndSwap(false, true) {
		return
	}
	defer m.retrying.Store(false)
	delay := 2 * time.Second
	for m.desiredRun.Load() {
		m.mu.Lock()
		if m.instance == nil {
			m.state = "retry_backoff"
		}
		m.mu.Unlock()
		time.Sleep(delay)
		if !m.desiredRun.Load() {
			return
		}
		err := m.startForRetry(context.Background())
		if err == nil {
			return
		}
		if errors.Is(err, errRunCancelled) {
			return
		}
		switch ErrorCode(err) {
		case CodeMeshDependencyDown, CodeServerUnreachable, CodeLocalListenBusy:
			m.mu.Lock()
			m.state = "waiting_dependency"
			m.lastErr = withCode(CodeMeshDependencyDown, err)
			m.mu.Unlock()
		default:
			m.desiredRun.Store(false)
			return
		}
		if delay < 30*time.Second {
			delay *= 2
		}
	}
}
