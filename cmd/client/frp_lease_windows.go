//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"

	"github.com/private-radminlan/lanmesh/internal/clientapi"
	frpctl "github.com/private-radminlan/lanmesh/internal/frp"
	"github.com/private-radminlan/lanmesh/internal/frpauth"
)

type frpLeaseProvider struct {
	api       *clientapi.Client
	networkID string
	deviceID  string
	mu        sync.Mutex
	requests  map[string]frpctl.LeaseRequest
	leases    map[string]frpctl.Lease
}

func newFRPLeaseProvider(api *clientapi.Client, networkID, deviceID string) *frpLeaseProvider {
	if api == nil {
		return nil
	}
	return &frpLeaseProvider{
		api: api, networkID: networkID, deviceID: deviceID,
		requests: make(map[string]frpctl.LeaseRequest), leases: make(map[string]frpctl.Lease),
	}
}

func (p *frpLeaseProvider) UpdateIdentity(networkID, deviceID string) {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.networkID = networkID
	p.deviceID = deviceID
	p.mu.Unlock()
}

func (p *frpLeaseProvider) client(ctx context.Context) *clientapi.Client {
	copy := *p.api
	copy.Context = ctx
	return &copy
}

func (p *frpLeaseProvider) Acquire(ctx context.Context, request frpctl.LeaseRequest) (frpctl.Lease, error) {
	if p == nil {
		return frpctl.Lease{}, fmt.Errorf("FRP lease provider is unavailable")
	}
	p.mu.Lock()
	defaultNetworkID := p.networkID
	defaultDeviceID := p.deviceID
	p.mu.Unlock()
	if request.NetworkID == "" {
		request.NetworkID = defaultNetworkID
	}
	if request.DeviceID == "" {
		request.DeviceID = defaultDeviceID
	}
	rules := make([]frpauth.Rule, 0, len(request.Rules))
	for _, rule := range request.Rules {
		rules = append(rules, authRuleFromLeaseRule(rule))
	}
	response, err := p.client(ctx).CreateFRPLease(request.NetworkID, request.DeviceID, request.ServerID, rules)
	if err != nil {
		return frpctl.Lease{}, err
	}
	lease := frpctl.Lease{ID: response.LeaseID, Credential: response.Credential, ExpiresAt: response.ExpiresAt}
	for _, rule := range response.Rules {
		lease.Rules = append(lease.Rules, leaseRuleFromAuthRule(rule))
	}
	p.mu.Lock()
	p.requests[lease.ID] = request
	p.leases[lease.ID] = lease
	p.mu.Unlock()
	return lease, nil
}

func (p *frpLeaseProvider) Renew(ctx context.Context, leaseID string) (frpctl.Lease, error) {
	if p == nil {
		return frpctl.Lease{}, fmt.Errorf("FRP lease provider is unavailable")
	}
	p.mu.Lock()
	current, ok := p.leases[leaseID]
	p.mu.Unlock()
	if !ok || current.Credential == "" {
		return frpctl.Lease{}, fmt.Errorf("%w: FRP lease credential is unavailable", frpctl.ErrLeaseTerminal)
	}
	response, err := p.client(ctx).RenewFRPLease(leaseID)
	if err != nil {
		var httpErr *clientapi.HTTPError
		if errors.As(err, &httpErr) {
			switch httpErr.StatusCode {
			case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusConflict, http.StatusGone:
				return frpctl.Lease{}, fmt.Errorf("%w: %v", frpctl.ErrLeaseTerminal, err)
			}
		}
		return frpctl.Lease{}, err
	}
	current.ID = response.LeaseID
	current.ExpiresAt = response.ExpiresAt
	current.Rules = nil
	for _, rule := range response.Rules {
		current.Rules = append(current.Rules, leaseRuleFromAuthRule(rule))
	}
	p.mu.Lock()
	p.leases[leaseID] = current
	p.mu.Unlock()
	return current, nil
}

func (p *frpLeaseProvider) VerifyActive(ctx context.Context, leaseID string, requireProxy bool) error {
	if p == nil {
		return fmt.Errorf("FRP lease provider is unavailable")
	}
	status, err := p.client(ctx).FRPLeaseStatus(leaseID)
	if err != nil {
		return err
	}
	if status.Revoked || !status.LoginSeen {
		return fmt.Errorf("FRPS did not reach the managed authorization plugin")
	}
	if requireProxy && !status.ProxySeen {
		return fmt.Errorf("FRPS did not authorize any managed proxy for this lease")
	}
	return nil
}

func (p *frpLeaseProvider) Release(ctx context.Context, leaseID string) error {
	if p == nil || leaseID == "" {
		return nil
	}
	err := p.client(ctx).RevokeFRPLease(leaseID)
	p.mu.Lock()
	delete(p.requests, leaseID)
	delete(p.leases, leaseID)
	p.mu.Unlock()
	return err
}

func authRuleFromLeaseRule(rule frpctl.LeaseRule) frpauth.Rule {
	return frpauth.Rule{
		ID: rule.ID, ProxyName: rule.ProxyName, Type: rule.Type, RemotePort: rule.RemotePort,
		CustomDomains: append([]string(nil), rule.CustomDomains...), BindPort: rule.BindPort,
		SubDomain: rule.SubDomain, Locations: append([]string(nil), rule.Locations...),
		HTTPUser: rule.HTTPUser, HTTPPasswordHash: rule.HTTPPasswordHash,
		HostHeaderRewrite: rule.HostHeaderRewrite, Headers: cloneFRPLeaseMap(rule.Headers),
		ResponseHeaders: cloneFRPLeaseMap(rule.ResponseHeaders), RouteByHTTPUser: rule.RouteByHTTPUser,
		Multiplexer: rule.Multiplexer, SecretHash: rule.SecretHash,
		AllowUsers: append([]string(nil), rule.AllowUsers...), UseEncryption: rule.UseEncryption,
		UseCompression: rule.UseCompression, TargetKind: rule.TargetKind,
		TargetNetworkID: rule.TargetNetworkID, TargetDeviceID: rule.TargetDeviceID,
		TargetPublicKey: rule.TargetPublicKey, TargetHost: rule.TargetHost,
		TargetServiceID: rule.TargetServiceID, GrantID: rule.GrantID,
	}
}

func leaseRuleFromAuthRule(rule frpauth.Rule) frpctl.LeaseRule {
	return frpctl.LeaseRule{
		ID: rule.ID, ProxyName: rule.ProxyName, Type: rule.Type, RemotePort: rule.RemotePort,
		CustomDomains: append([]string(nil), rule.CustomDomains...), BindPort: rule.BindPort,
		SubDomain: rule.SubDomain, Locations: append([]string(nil), rule.Locations...),
		HTTPUser: rule.HTTPUser, HTTPPasswordHash: rule.HTTPPasswordHash,
		HostHeaderRewrite: rule.HostHeaderRewrite, Headers: cloneFRPLeaseMap(rule.Headers),
		ResponseHeaders: cloneFRPLeaseMap(rule.ResponseHeaders), RouteByHTTPUser: rule.RouteByHTTPUser,
		Multiplexer: rule.Multiplexer, SecretHash: rule.SecretHash,
		AllowUsers: append([]string(nil), rule.AllowUsers...), UseEncryption: rule.UseEncryption,
		UseCompression: rule.UseCompression, TargetKind: rule.TargetKind,
		TargetNetworkID: rule.TargetNetworkID, TargetDeviceID: rule.TargetDeviceID,
		TargetPublicKey: rule.TargetPublicKey, TargetHost: rule.TargetHost,
		TargetServiceID: rule.TargetServiceID, GrantID: rule.GrantID,
	}
}

func cloneFRPLeaseMap(source map[string]string) map[string]string {
	if source == nil {
		return nil
	}
	out := make(map[string]string, len(source))
	for key, value := range source {
		out[key] = value
	}
	return out
}
