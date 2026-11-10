package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/private-radminlan/lanmesh/internal/egress"
	"github.com/private-radminlan/lanmesh/internal/egressgateway"
)

const (
	gatewayHandshakeTimeout = 10 * time.Second
	gatewayResolveTimeout   = 10 * time.Second
	gatewayDialTimeout      = 10 * time.Second
	maxResolvedAddresses    = 64
	maxAuthorizedTargets    = 1024
	leaseMonitorInterval    = 10 * time.Second
)

type networkDependencies struct {
	lookupNetIP func(context.Context, string, string) ([]netip.Addr, error)
	dialContext func(context.Context, string, string) (net.Conn, error)
}

func defaultNetworkDependencies() networkDependencies {
	dialer := &net.Dialer{Timeout: gatewayDialTimeout, KeepAlive: 30 * time.Second}
	return networkDependencies{
		lookupNetIP: net.DefaultResolver.LookupNetIP,
		dialContext: dialer.DialContext,
	}
}

func (d networkDependencies) withDefaults() networkDependencies {
	defaults := defaultNetworkDependencies()
	if d.lookupNetIP == nil {
		d.lookupNetIP = defaults.lookupNetIP
	}
	if d.dialContext == nil {
		d.dialContext = defaults.dialContext
	}
	return d
}

type gatewayService struct {
	config         gatewayConfig
	issuer         *egressgateway.LeaseIssuer
	baselinePolicy *egressgateway.SessionPolicy
	registry       *sessionRegistry
	network        networkDependencies
	logger         *log.Logger
}

func newGatewayService(config gatewayConfig, issuer *egressgateway.LeaseIssuer, network networkDependencies, logger *log.Logger) (*gatewayService, error) {
	if issuer == nil {
		return nil, errors.New("lease issuer is required")
	}
	policy, err := config.gatewayPolicy()
	if err != nil {
		return nil, err
	}
	baseline, err := egressgateway.NewSessionPolicy(policy, config.Limits.gatewayLimits())
	if err != nil {
		return nil, fmt.Errorf("compile baseline policy: %w", err)
	}
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}
	return &gatewayService{
		config:         config,
		issuer:         issuer,
		baselinePolicy: baseline,
		registry:       newSessionRegistry(config.Limits.MaxSessions),
		network:        network.withDefaults(),
		logger:         logger,
	}, nil
}

func (s *gatewayService) serveConnection(ctx context.Context, connection net.Conn) {
	if connection == nil {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	defer connection.Close()
	stopOnCancel := context.AfterFunc(ctx, func() {
		_ = connection.Close()
	})
	defer stopOnCancel()

	state := &connectionState{service: s}
	session, err := egress.NewGatewaySession(egress.GatewaySessionConfig{
		Conn:              connection,
		ValidateHandshake: state.validateHandshake,
		AuthorizeTarget:   state.authorizeTarget,
		DialTCP:           state.dialTCP,
		DialUDP:           state.dialUDP,
		HandshakeTimeout:  gatewayHandshakeTimeout,
	})
	if err != nil {
		s.logger.Printf("create egress gateway session for %s: %v", connection.RemoteAddr(), err)
		return
	}
	state.session = session
	err = session.Serve(ctx)
	state.release()
	if err != nil && ctx.Err() == nil {
		s.logger.Printf("egress gateway session from %s ended: %v", connection.RemoteAddr(), err)
	}
}

type connectionState struct {
	service *gatewayService

	mu         sync.RWMutex
	session    *egress.GatewaySession
	leaseID    string
	runtime    *leaseRuntimeState
	authorizer *targetAuthorizer
}

func (s *connectionState) validateHandshake(ctx context.Context, info egress.HandshakeInfo) (egress.SessionGrant, error) {
	if s.session == nil {
		return egress.SessionGrant{}, errors.New("gateway session is not initialized")
	}
	if strings.TrimSpace(info.Nonce) == "" {
		return egress.SessionGrant{}, errors.New("handshake nonce is required")
	}
	lease, err := s.service.issuer.Verify(info.LeaseID, info.DeviceID, info.Capability, info.PolicyVersion)
	if err != nil {
		return egress.SessionGrant{}, fmt.Errorf("lease verification failed: %w", err)
	}
	if lease.ProfileID != info.ProfileID || lease.RuleID != info.RuleID {
		return egress.SessionGrant{}, errors.New("lease profile or rule does not match the handshake")
	}
	sessionID, err := randomSessionID()
	if err != nil {
		return egress.SessionGrant{}, err
	}
	runtimeState, err := s.service.registry.add(lease, s.session, s.service.baselinePolicy, s.service.config.Limits.gatewayLimits())
	if err != nil {
		return egress.SessionGrant{}, err
	}
	authorizer := newTargetAuthorizer(runtimeState.policies, s.service.network.lookupNetIP, s.service.config.denyPortSet())

	s.mu.Lock()
	s.leaseID = lease.ID
	s.runtime = runtimeState
	s.authorizer = authorizer
	s.mu.Unlock()

	return egress.SessionGrant{
		SessionID: sessionID,
		Secret:    egress.DeriveSessionSecret(info.Capability),
	}, nil
}

func (s *connectionState) authorizeTarget(ctx context.Context, target egress.OpenTarget) error {
	authorizer := s.authorizerSnapshot()
	if authorizer == nil {
		return errors.New("egress session is not authorized")
	}
	return authorizer.authorize(ctx, target)
}

func (s *connectionState) dialTCP(ctx context.Context, target egress.OpenTarget) (net.Conn, error) {
	return s.dial(ctx, target, "tcp")
}

func (s *connectionState) dialUDP(ctx context.Context, target egress.OpenTarget) (net.Conn, error) {
	return s.dial(ctx, target, "udp")
}

func (s *connectionState) dial(ctx context.Context, target egress.OpenTarget, network string) (net.Conn, error) {
	authorizer, runtimeState, err := s.sessionSnapshot()
	if err != nil {
		return nil, err
	}
	addresses, err := authorizer.authorizedAddresses(target)
	if err != nil {
		return nil, err
	}
	protocol, err := gatewayProtocol(target.Protocol)
	if err != nil {
		return nil, err
	}
	if !policyAllowsProtocol(s.service.baselinePolicy.Policy(), protocol) {
		return nil, fmt.Errorf("gateway policy denies protocol %s", protocol)
	}
	if err := runtimeState.leasePolicy.AcquireConnection(protocol); err != nil {
		return nil, fmt.Errorf("acquire lease connection: %w", err)
	}
	release := true
	defer func() {
		if release {
			runtimeState.leasePolicy.ReleaseConnection(protocol)
		}
	}()

	if ctx == nil {
		ctx = context.Background()
	}
	dialCtx, cancel := context.WithTimeout(ctx, gatewayDialTimeout)
	defer cancel()

	var failures []error
	for _, address := range addresses {
		connection, dialErr := s.service.network.dialContext(dialCtx, network, address.String())
		if dialErr == nil && connection == nil {
			dialErr = errors.New("dialer returned a nil connection")
		}
		if dialErr == nil {
			release = false
			return &quotaConnection{
				Conn:     connection,
				policy:   runtimeState.leasePolicy,
				protocol: protocol,
			}, nil
		}
		failures = append(failures, fmt.Errorf("%s: %w", address, dialErr))
		if dialCtx.Err() != nil {
			break
		}
	}
	if len(failures) == 0 {
		return nil, errors.New("no authorized target address is available")
	}
	return nil, fmt.Errorf("dial %s target: %w", network, errors.Join(failures...))
}

func (s *connectionState) authorizerSnapshot() *targetAuthorizer {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.authorizer
}

func (s *connectionState) sessionSnapshot() (*targetAuthorizer, *leaseRuntimeState, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.authorizer == nil || s.runtime == nil {
		return nil, nil, errors.New("egress session is not authorized")
	}
	return s.authorizer, s.runtime, nil
}

func (s *connectionState) release() {
	s.mu.Lock()
	session := s.session
	leaseID := s.leaseID
	s.leaseID = ""
	s.runtime = nil
	s.authorizer = nil
	s.mu.Unlock()
	if session != nil && leaseID != "" {
		s.service.registry.remove(leaseID, session)
	}
}

func randomSessionID() (egress.SessionID, error) {
	for attempt := 0; attempt < 4; attempt++ {
		var id egress.SessionID
		if _, err := rand.Read(id[:]); err != nil {
			return egress.SessionID{}, fmt.Errorf("generate session id: %w", err)
		}
		if !id.IsZero() {
			return id, nil
		}
	}
	return egress.SessionID{}, errors.New("could not generate a non-zero session id")
}

func gatewayProtocol(protocol egress.Protocol) (egressgateway.Protocol, error) {
	switch protocol {
	case egress.ProtocolTCP:
		return egressgateway.ProtocolTCP, nil
	case egress.ProtocolUDP:
		return egressgateway.ProtocolUDP, nil
	default:
		return "", fmt.Errorf("unsupported protocol %q", protocol)
	}
}

func policyAllowsProtocol(policy egressgateway.Policy, protocol egressgateway.Protocol) bool {
	for _, allowed := range policy.AllowedProtocols {
		if egressgateway.Protocol(strings.ToLower(strings.TrimSpace(string(allowed)))) == protocol {
			return true
		}
	}
	return false
}

type leaseRuntimeState struct {
	lease       egressgateway.Lease
	policies    []*egressgateway.SessionPolicy
	leasePolicy *egressgateway.SessionPolicy
	sessions    map[*egress.GatewaySession]struct{}
}

type sessionRegistry struct {
	mu          sync.Mutex
	maxSessions int
	total       int
	states      map[string]*leaseRuntimeState
}

func newSessionRegistry(maxSessions int) *sessionRegistry {
	return &sessionRegistry{
		maxSessions: maxSessions,
		states:      make(map[string]*leaseRuntimeState),
	}
}

func (r *sessionRegistry) add(lease egressgateway.Lease, gateway *egress.GatewaySession, baseline *egressgateway.SessionPolicy, capLimits egressgateway.Limits) (*leaseRuntimeState, error) {
	if gateway == nil || baseline == nil {
		return nil, errors.New("invalid gateway session registration")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	state := r.states[lease.ID]
	if state == nil {
		limits := cappedLeaseLimits(lease.Limits, capLimits)
		leasePolicy, err := egressgateway.NewSessionPolicy(lease.Policy, limits)
		if err != nil {
			return nil, fmt.Errorf("compile lease policy: %w", err)
		}
		state = &leaseRuntimeState{
			lease:       lease.Clone(),
			policies:    []*egressgateway.SessionPolicy{baseline, leasePolicy},
			leasePolicy: leasePolicy,
			sessions:    make(map[*egress.GatewaySession]struct{}),
		}
		r.states[lease.ID] = state
	} else if state.lease.PolicyVersion != lease.PolicyVersion {
		return nil, errors.New("lease policy changed while the lease is active")
	}
	if r.total >= r.maxSessions {
		if len(state.sessions) == 0 {
			delete(r.states, lease.ID)
		}
		return nil, fmt.Errorf("gateway session limit %d reached", r.maxSessions)
	}
	state.sessions[gateway] = struct{}{}
	r.total++
	return state, nil
}

func (r *sessionRegistry) remove(leaseID string, gateway *egress.GatewaySession) {
	r.mu.Lock()
	defer r.mu.Unlock()
	state := r.states[leaseID]
	if state == nil {
		return
	}
	if _, exists := state.sessions[gateway]; !exists {
		return
	}
	delete(state.sessions, gateway)
	if r.total > 0 {
		r.total--
	}
}

func (r *sessionRegistry) closeLease(leaseID string) {
	if r == nil || leaseID == "" {
		return
	}
	r.mu.Lock()
	state := r.states[leaseID]
	delete(r.states, leaseID)
	gateways := make([]*egress.GatewaySession, 0, 1)
	if state != nil {
		for gateway := range state.sessions {
			gateways = append(gateways, gateway)
		}
		if len(gateways) <= r.total {
			r.total -= len(gateways)
		} else {
			r.total = 0
		}
	}
	r.mu.Unlock()
	for _, gateway := range gateways {
		_ = gateway.Close()
	}
}

func (r *sessionRegistry) closeAll() {
	if r == nil {
		return
	}
	r.mu.Lock()
	gateways := make([]*egress.GatewaySession, 0, r.total)
	for _, state := range r.states {
		for gateway := range state.sessions {
			gateways = append(gateways, gateway)
		}
	}
	r.states = make(map[string]*leaseRuntimeState)
	r.total = 0
	r.mu.Unlock()
	for _, gateway := range gateways {
		_ = gateway.Close()
	}
}

func (r *sessionRegistry) monitor(ctx context.Context, issuer *egressgateway.LeaseIssuer, logger *log.Logger) {
	if ctx == nil {
		ctx = context.Background()
	}
	if r == nil || issuer == nil {
		return
	}
	ticker := time.NewTicker(leaseMonitorInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.mu.Lock()
			ids := make([]string, 0, len(r.states))
			for leaseID := range r.states {
				ids = append(ids, leaseID)
			}
			r.mu.Unlock()
			for _, leaseID := range ids {
				status, err := issuer.Status(leaseID)
				if err == nil && status == egressgateway.LeaseStatusActive {
					continue
				}
				if logger != nil {
					if err != nil {
						logger.Printf("stop sessions for lease %s: status lookup failed", leaseID)
					} else {
						logger.Printf("stop sessions for lease %s: %s", leaseID, status)
					}
				}
				r.closeLease(leaseID)
			}
		}
	}
}

func cappedLeaseLimits(lease, cap egressgateway.Limits) egressgateway.Limits {
	if cap.MaxConnections > 0 && lease.MaxConnections > cap.MaxConnections {
		lease.MaxConnections = cap.MaxConnections
	}
	if cap.MaxBytes > 0 && lease.MaxBytes > cap.MaxBytes {
		lease.MaxBytes = cap.MaxBytes
	}
	if cap.MaxRateBPS > 0 && lease.MaxRateBPS > cap.MaxRateBPS {
		lease.MaxRateBPS = cap.MaxRateBPS
	}
	return lease
}

type targetAuthorizer struct {
	policies    []*egressgateway.SessionPolicy
	lookupNetIP func(context.Context, string, string) ([]netip.Addr, error)
	denyPorts   map[uint16]struct{}
	mu          sync.Mutex
	authorized  map[string][]netip.AddrPort
}

func newTargetAuthorizer(policies []*egressgateway.SessionPolicy, lookup func(context.Context, string, string) ([]netip.Addr, error), denyPorts map[uint16]struct{}) *targetAuthorizer {
	return &targetAuthorizer{
		policies:    append([]*egressgateway.SessionPolicy(nil), policies...),
		lookupNetIP: lookup,
		denyPorts:   denyPorts,
		authorized:  make(map[string][]netip.AddrPort),
	}
}

func (a *targetAuthorizer) authorize(ctx context.Context, target egress.OpenTarget) error {
	if a == nil || a.lookupNetIP == nil || len(a.policies) == 0 {
		return errors.New("target authorization is not configured")
	}
	if err := target.Validate(); err != nil {
		return fmt.Errorf("invalid target: %w", err)
	}
	protocol, err := gatewayProtocol(target.Protocol)
	if err != nil {
		return err
	}
	for _, policy := range a.policies {
		if !policyAllowsProtocol(policy.Policy(), protocol) {
			return fmt.Errorf("target protocol %s is denied by policy", protocol)
		}
	}
	if _, denied := a.denyPorts[target.Port]; denied {
		return fmt.Errorf("target port %d is denied by gateway policy", target.Port)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	resolveCtx, cancel := context.WithTimeout(ctx, gatewayResolveTimeout)
	defer cancel()
	addresses, err := a.lookupNetIP(resolveCtx, "ip", target.Host)
	if err != nil {
		return fmt.Errorf("resolve target %q: %w", target.Host, err)
	}
	if len(addresses) == 0 {
		return fmt.Errorf("target %q resolved to no addresses", target.Host)
	}
	if len(addresses) > maxResolvedAddresses {
		return fmt.Errorf("target %q resolved to too many addresses", target.Host)
	}
	authorized := make([]netip.AddrPort, 0, len(addresses))
	seen := make(map[netip.AddrPort]struct{}, len(addresses))
	for _, resolved := range addresses {
		addrPort := netip.AddrPortFrom(resolved.Unmap(), target.Port)
		if _, exists := seen[addrPort]; exists {
			continue
		}
		for index, policy := range a.policies {
			if err := policy.ValidateTarget(addrPort, egressgateway.ClassifyTarget(addrPort)); err != nil {
				label := "gateway policy"
				if index > 0 {
					label = "lease policy"
				}
				return fmt.Errorf("target %q resolved to %s: %s rejected it: %w", target.Host, addrPort, label, err)
			}
		}
		seen[addrPort] = struct{}{}
		authorized = append(authorized, addrPort)
	}
	if len(authorized) == 0 {
		return fmt.Errorf("target %q resolved to no usable addresses", target.Host)
	}

	key := target.String()
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, exists := a.authorized[key]; !exists && len(a.authorized) >= maxAuthorizedTargets {
		return errors.New("per-session authorized target limit reached")
	}
	a.authorized[key] = authorized
	return nil
}

func (a *targetAuthorizer) authorizedAddresses(target egress.OpenTarget) ([]netip.AddrPort, error) {
	if a == nil {
		return nil, errors.New("target authorization is not configured")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	addresses := a.authorized[target.String()]
	if len(addresses) == 0 {
		return nil, fmt.Errorf("target %q was not authorized before dialing", target.String())
	}
	return append([]netip.AddrPort(nil), addresses...), nil
}

type quotaConnection struct {
	net.Conn
	policy   *egressgateway.SessionPolicy
	protocol egressgateway.Protocol
	once     sync.Once
}

func (c *quotaConnection) Read(payload []byte) (int, error) {
	count, err := c.Conn.Read(payload)
	if count > 0 {
		if quotaErr := c.policy.ConsumeBytes(uint64(count)); quotaErr != nil {
			return 0, fmt.Errorf("egress byte quota: %w", quotaErr)
		}
	}
	return count, err
}

func (c *quotaConnection) Write(payload []byte) (int, error) {
	if len(payload) > 0 {
		if err := c.policy.ConsumeBytes(uint64(len(payload))); err != nil {
			return 0, fmt.Errorf("egress byte quota: %w", err)
		}
	}
	return c.Conn.Write(payload)
}

func (c *quotaConnection) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() {
		c.policy.ReleaseConnection(c.protocol)
	})
	return err
}
