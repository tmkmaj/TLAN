//go:build windows

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/private-radminlan/lanmesh/core"
	"github.com/private-radminlan/lanmesh/internal/clientapi"
	"github.com/private-radminlan/lanmesh/internal/clientui"
	frpctl "github.com/private-radminlan/lanmesh/internal/frp"
	"github.com/private-radminlan/lanmesh/internal/mesh"
)

const diagnosticSchemaVersion = 1

type frpDiagnosticSource struct {
	ProfileID  string
	Config     frpctl.Config
	Configured bool
	Manager    *frpctl.Manager
	Provider   *frpLeaseProvider
	Snapshot   *frpctl.Snapshot
}

type diagnosticExport struct {
	SchemaVersion int                         `json:"schema_version"`
	AppVersion    string                      `json:"app_version"`
	GeneratedAt   time.Time                   `json:"generated_at"`
	Checks        []clientapi.DiagnosticCheck `json:"checks"`
	FRP           frpDiagnosticExport         `json:"frp"`
	MeshQuality   *meshQualityDiagnostic      `json:"mesh_quality,omitempty"`
}

type meshQualityDiagnostic struct {
	SchemaVersion int                  `json:"schema_version"`
	Summary       mesh.QualitySummary  `json:"summary"`
	Samples       []mesh.QualitySample `json:"samples"`
}

type frpDiagnosticExport struct {
	SchemaVersion int                    `json:"schema_version"`
	GeneratedAt   time.Time              `json:"generated_at"`
	Profiles      []frpProfileDiagnostic `json:"profiles"`
}

type frpProfileDiagnostic struct {
	ProfileID        string                       `json:"profile_id"`
	ProfileName      string                       `json:"profile_name"`
	Configured       bool                         `json:"configured"`
	ServerKind       string                       `json:"server_kind"`
	ServerHost       string                       `json:"server_host"`
	ServerPort       int                          `json:"server_port"`
	Transport        string                       `json:"transport"`
	TLSServerName    string                       `json:"tls_server_name"`
	TrustedCAPath    string                       `json:"trusted_ca_path"`
	Snapshot         frpctl.Snapshot              `json:"snapshot"`
	ManagedLeases    []frpManagedLeaseDiagnostic  `json:"managed_leases"`
	Egress           []frpEgressDiagnostic        `json:"egress"`
	Routes           []frpRouteDiagnostic         `json:"routes"`
	TargetGateways   []frpTargetGatewayDiagnostic `json:"target_gateways"`
	TLS              frpTLSCheckDiagnostic        `json:"tls"`
	Logs             []string                     `json:"logs"`
	CollectionErrors []string                     `json:"collection_errors,omitempty"`
}

type frpManagedLeaseDiagnostic struct {
	LeaseID            string     `json:"lease_id_masked"`
	ExpiresAt          time.Time  `json:"expires_at"`
	RemainingSeconds   int64      `json:"remaining_seconds"`
	RequestedRuleCount int        `json:"requested_rule_count"`
	GrantedRuleCount   int        `json:"granted_rule_count"`
	Observed           bool       `json:"observed"`
	Revoked            *bool      `json:"revoked,omitempty"`
	LoginSeen          *bool      `json:"login_seen,omitempty"`
	ProxySeen          *bool      `json:"proxy_seen,omitempty"`
	LastSeen           *time.Time `json:"last_seen,omitempty"`
	ObservationError   string     `json:"observation_error,omitempty"`
}

type frpEgressDiagnostic struct {
	Kind      string `json:"kind"`
	Mode      string `json:"mode"`
	Address   string `json:"address"`
	Purpose   string `json:"purpose"`
	Transport string `json:"transport,omitempty"`
}

type frpRouteDiagnostic struct {
	RuleID         string `json:"rule_id"`
	RuleName       string `json:"rule_name"`
	Type           string `json:"type"`
	TargetKind     string `json:"target_kind"`
	TargetEndpoint string `json:"target_endpoint"`
	RemoteAddress  string `json:"remote_address,omitempty"`
	State          string `json:"state"`
	Path           string `json:"path"`
	GatewayAddress string `json:"gateway_address,omitempty"`
	GatewayStats   string `json:"gateway_stats,omitempty"`
	ProxyProtocol  string `json:"proxy_protocol,omitempty"`
	Error          string `json:"error,omitempty"`
}

type frpTargetGatewayDiagnostic struct {
	RuleID   string                    `json:"rule_id"`
	Protocol string                    `json:"protocol"`
	Address  string                    `json:"address"`
	Path     string                    `json:"path"`
	State    string                    `json:"state"`
	Stats    frpGatewayStatsDiagnostic `json:"stats"`
}

type frpGatewayStatsDiagnostic struct {
	LeaseGeneration     uint64 `json:"lease_generation"`
	TCPAccepted         uint64 `json:"tcp_accepted"`
	TCPActive           uint64 `json:"tcp_active"`
	TCPRejected         uint64 `json:"tcp_rejected"`
	UDPAccepted         uint64 `json:"udp_accepted"`
	UDPActive           uint64 `json:"udp_active"`
	UDPDropped          uint64 `json:"udp_dropped"`
	LeaseRejections     uint64 `json:"lease_rejections"`
	DialFailures        uint64 `json:"dial_failures"`
	BytesToTarget       uint64 `json:"bytes_to_target"`
	BytesFromTarget     uint64 `json:"bytes_from_target"`
	DatagramsToTarget   uint64 `json:"datagrams_to_target"`
	DatagramsFromTarget uint64 `json:"datagrams_from_target"`
}

type frpTLSCheckDiagnostic struct {
	Status                    string                     `json:"status"`
	CheckedAt                 time.Time                  `json:"checked_at"`
	TLSServerName             string                     `json:"tls_server_name"`
	CAFile                    string                     `json:"ca_file"`
	CAValid                   bool                       `json:"ca_valid"`
	CACertificates            []frpCertificateDiagnostic `json:"ca_certificates,omitempty"`
	PrivateKeyMaterialPresent bool                       `json:"private_key_material_present"`
	HandshakeAttempted        bool                       `json:"handshake_attempted"`
	HandshakeOK               bool                       `json:"handshake_ok"`
	Verified                  bool                       `json:"verified"`
	TLSVersion                string                     `json:"tls_version,omitempty"`
	CipherSuite               string                     `json:"cipher_suite,omitempty"`
	HandshakeDurationMS       int64                      `json:"handshake_duration_ms,omitempty"`
	ServerCertificates        []frpCertificateDiagnostic `json:"server_certificates,omitempty"`
	SkippedReason             string                     `json:"skipped_reason,omitempty"`
	Error                     string                     `json:"error,omitempty"`
}

type frpCertificateDiagnostic struct {
	Subject           string    `json:"subject"`
	Issuer            string    `json:"issuer"`
	NotBefore         time.Time `json:"not_before"`
	NotAfter          time.Time `json:"not_after"`
	IsCA              bool      `json:"is_ca"`
	DNSNames          []string  `json:"dns_names,omitempty"`
	IPAddresses       []string  `json:"ip_addresses,omitempty"`
	FingerprintSHA256 string    `json:"fingerprint_sha256"`
}

var (
	frpDiagnosticSecretField = regexp.MustCompile(`(?i)((?:token|password|secret(?:[ _-]?key)?|capability|credential|authorization|private(?:[ _-]?key))\s*[=:]\s*)([^\s&,;\"\\]+)`)
	frpDiagnosticPrivateKey  = regexp.MustCompile(`(?s)-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----`)
)

func redactFRPDiagnosticText(value string, secrets ...string) string {
	value = clientui.RedactLang(currentLang(), value, secrets...)
	value = frpDiagnosticPrivateKey.ReplaceAllString(value, tr("[已隐藏私钥]", "[redacted private key]"))
	return frpDiagnosticSecretField.ReplaceAllString(value, "${1}"+tr("[已隐藏]", "[redacted]"))
}

func (a *desktop) frpDiagnosticSources() []frpDiagnosticSource {
	if a == nil {
		return nil
	}
	type candidate struct {
		id      string
		manager *frpctl.Manager
	}
	seen := make(map[*frpctl.Manager]struct{})
	candidates := make([]candidate, 0, len(a.frpManagers)+1)
	add := func(id string, manager *frpctl.Manager) {
		if manager == nil {
			return
		}
		if _, ok := seen[manager]; ok {
			return
		}
		seen[manager] = struct{}{}
		candidates = append(candidates, candidate{id: id, manager: manager})
	}
	for id, manager := range a.frpManagers {
		add(id, manager)
	}
	add(a.frpProfileID, a.frpManager)
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].id < candidates[j].id })
	sources := make([]frpDiagnosticSource, 0, len(candidates))
	for _, item := range candidates {
		cfg, configured := item.manager.Config()
		if !configured {
			continue
		}
		sources = append(sources, frpDiagnosticSource{
			ProfileID: item.id, Config: cfg, Configured: true, Manager: item.manager,
			Provider: a.frpLeaseProviders[item.id],
		})
	}
	return sources
}

func buildFRPDiagnosticExport(ctx context.Context, sources []frpDiagnosticSource, secrets []string, now time.Time) (frpDiagnosticExport, []clientapi.DiagnosticCheck) {
	if ctx == nil {
		ctx = context.Background()
	}
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	result := frpDiagnosticExport{SchemaVersion: diagnosticSchemaVersion, GeneratedAt: now, Profiles: []frpProfileDiagnostic{}}
	var checks []clientapi.DiagnosticCheck
	for _, source := range sources {
		if source.Manager == nil && source.Snapshot == nil && !source.Configured {
			continue
		}
		var snapshot frpctl.Snapshot
		switch {
		case source.Manager != nil:
			snapshot = source.Manager.Snapshot(ctx)
		case source.Snapshot != nil:
			snapshot = *source.Snapshot
		}
		snapshot = sanitizeFRPSnapshot(snapshot, secrets...)
		cfg := source.Config
		profile := frpProfileDiagnostic{
			ProfileID: source.ProfileID, ProfileName: cfg.Profile.Name,
			Configured: source.Configured || snapshot.Configured,
			ServerKind: cfg.Profile.Server.Kind, ServerHost: cfg.Profile.Server.Host,
			ServerPort: cfg.Profile.Server.Port, Transport: cfg.Profile.Server.Transport,
			TLSServerName: cfg.Profile.Server.TLSServerName, TrustedCAPath: cfg.Profile.Server.TrustedCAPath,
			Snapshot: snapshot, Logs: append([]string{}, snapshot.Logs...),
		}
		var reservations []frpctl.TargetReservation
		if source.Manager != nil {
			reservations = source.Manager.ReservedTargets()
		}
		profile.Egress = buildFRPEgress(cfg, reservations)
		profile.Routes = buildFRPRoutes(cfg, snapshot)
		profile.TargetGateways = buildFRPTargetGateways(snapshot)
		if cfg.Profile.Server.Kind == "managed" {
			profile.ManagedLeases = collectFRPManagedLeaseDiagnostics(ctx, source.Provider, secrets, now)
		}
		profile.TLS = inspectFRPTLS(ctx, cfg, now)
		if profile.TLS.Status == "fail" && profile.TLS.Error != "" {
			profile.CollectionErrors = append(profile.CollectionErrors, profile.TLS.Error)
		}
		profile.ProfileName = redactFRPDiagnosticText(profile.ProfileName, secrets...)
		profile.ServerHost = redactFRPDiagnosticText(profile.ServerHost, secrets...)
		profile.TLSServerName = redactFRPDiagnosticText(profile.TLSServerName, secrets...)
		profile.TrustedCAPath = redactFRPDiagnosticText(profile.TrustedCAPath, secrets...)
		profile.CollectionErrors = redactFRPDiagnosticStrings(profile.CollectionErrors, secrets...)
		result.Profiles = append(result.Profiles, profile)
		checks = append(checks, buildFRPProfileChecks(profile, now)...)
	}
	return result, checks
}

func sanitizeFRPSnapshot(snapshot frpctl.Snapshot, secrets ...string) frpctl.Snapshot {
	out := snapshot
	out.ProfileName = redactFRPDiagnosticText(out.ProfileName, secrets...)
	out.ServerHost = redactFRPDiagnosticText(out.ServerHost, secrets...)
	out.LastError = redactFRPDiagnosticText(out.LastError, secrets...)
	out.Logs = redactFRPDiagnosticStrings(out.Logs, secrets...)
	out.Rules = append([]frpctl.RuleRuntimeStatus(nil), snapshot.Rules...)
	for i := range out.Rules {
		out.Rules[i].Name = redactFRPDiagnosticText(out.Rules[i].Name, secrets...)
		out.Rules[i].RemoteAddr = redactFRPDiagnosticText(out.Rules[i].RemoteAddr, secrets...)
		out.Rules[i].Backend = redactFRPDiagnosticText(out.Rules[i].Backend, secrets...)
		out.Rules[i].GatewayStats = redactFRPDiagnosticText(out.Rules[i].GatewayStats, secrets...)
		out.Rules[i].ErrorDetail = redactFRPDiagnosticText(out.Rules[i].ErrorDetail, secrets...)
	}
	out.Visitors = append([]frpctl.VisitorRuntimeStatus(nil), snapshot.Visitors...)
	for i := range out.Visitors {
		out.Visitors[i].Name = redactFRPDiagnosticText(out.Visitors[i].Name, secrets...)
		out.Visitors[i].BindAddr = redactFRPDiagnosticText(out.Visitors[i].BindAddr, secrets...)
		out.Visitors[i].ErrorDetail = redactFRPDiagnosticText(out.Visitors[i].ErrorDetail, secrets...)
	}
	out.Gateways = append([]frpctl.GatewayRuntimeStatus(nil), snapshot.Gateways...)
	for i := range out.Gateways {
		out.Gateways[i].Address = redactFRPDiagnosticText(out.Gateways[i].Address, secrets...)
		out.Gateways[i].Path = redactFRPDiagnosticText(out.Gateways[i].Path, secrets...)
		out.Gateways[i].State = redactFRPDiagnosticText(out.Gateways[i].State, secrets...)
	}
	return out
}

func redactFRPDiagnosticStrings(values []string, secrets ...string) []string {
	if values == nil {
		return nil
	}
	out := make([]string, len(values))
	for i, value := range values {
		out[i] = redactFRPDiagnosticText(value, secrets...)
	}
	return out
}

func collectFRPManagedLeaseDiagnostics(ctx context.Context, provider *frpLeaseProvider, secrets []string, now time.Time) []frpManagedLeaseDiagnostic {
	if provider == nil {
		return nil
	}
	type leaseEntry struct {
		lease     frpctl.Lease
		requested frpctl.LeaseRequest
	}
	provider.mu.Lock()
	entries := make([]leaseEntry, 0, len(provider.leases))
	for id, lease := range provider.leases {
		entries = append(entries, leaseEntry{lease: lease, requested: provider.requests[id]})
	}
	api := provider.api
	provider.mu.Unlock()
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].lease.ExpiresAt.Equal(entries[j].lease.ExpiresAt) {
			return entries[i].lease.ID < entries[j].lease.ID
		}
		return entries[i].lease.ExpiresAt.Before(entries[j].lease.ExpiresAt)
	})
	out := make([]frpManagedLeaseDiagnostic, 0, len(entries))
	for _, entry := range entries {
		item := frpManagedLeaseDiagnostic{
			LeaseID: maskFRPDiagnosticID(entry.lease.ID), ExpiresAt: entry.lease.ExpiresAt,
			RemainingSeconds:   int64(entry.lease.ExpiresAt.Sub(now).Seconds()),
			RequestedRuleCount: len(entry.requested.Rules), GrantedRuleCount: len(entry.lease.Rules),
		}
		if api == nil {
			item.ObservationError = tr("FRP 控制面客户端不可用，未执行服务端租约观察", "FRP control API client unavailable; server lease check skipped")
		} else {
			statusCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
			status, err := provider.client(statusCtx).FRPLeaseStatus(entry.lease.ID)
			cancel()
			if err != nil {
				item.ObservationError = redactFRPDiagnosticText(err.Error(), secrets...)
			} else {
				revoked, loginSeen, proxySeen := status.Revoked, status.LoginSeen, status.ProxySeen
				lastSeen := status.LastSeen
				item.Observed = true
				item.Revoked = &revoked
				item.LoginSeen = &loginSeen
				item.ProxySeen = &proxySeen
				if !lastSeen.IsZero() {
					item.LastSeen = &lastSeen
				}
			}
		}
		out = append(out, item)
	}
	return out
}

func maskFRPDiagnosticID(value string) string {
	if value == "" {
		return ""
	}
	if len(value) <= 8 {
		return "****"
	}
	return value[:4] + "…" + value[len(value)-4:]
}

func buildFRPEgress(cfg frpctl.Config, reservations []frpctl.TargetReservation) []frpEgressDiagnostic {
	server := cfg.Profile.Server
	transport := strings.ToLower(server.Transport)
	if transport == "" {
		transport = "tcp"
	}
	control := frpEgressDiagnostic{
		Kind: "control", Mode: "direct", Address: net.JoinHostPort(server.Host, fmt.Sprint(server.Port)),
		Purpose: "FRPS 控制连接", Transport: transport,
	}
	if transport == "kcp" || transport == "quic" {
		control.Mode = "direct-udp"
	}
	guard := false
	out := []frpEgressDiagnostic{control}
	for _, reservation := range reservations {
		lower := strings.ToLower(reservation.Purpose)
		kind := ""
		switch {
		case strings.Contains(lower, "egress"):
			kind = "local_egress_guard"
			guard = true
		case strings.Contains(lower, "administration"):
			kind = "frpc_admin"
		case strings.Contains(lower, "targetgateway"):
			kind = "target_gateway"
		case strings.Contains(lower, "visitor"):
			kind = "visitor"
		}
		if kind == "" {
			continue
		}
		out = append(out, frpEgressDiagnostic{
			Kind: kind, Mode: "loopback-listener", Address: net.JoinHostPort(reservation.Host, fmt.Sprint(reservation.Port)),
			Purpose: reservation.Purpose, Transport: transport,
		})
	}
	if guard {
		if transport == "kcp" || transport == "quic" {
			out[0].Mode = "local-udp-relay"
		} else {
			out[0].Mode = "local-policy-proxy"
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind == out[j].Kind {
			return out[i].Address < out[j].Address
		}
		return out[i].Kind < out[j].Kind
	})
	return out
}

func buildFRPRoutes(cfg frpctl.Config, snapshot frpctl.Snapshot) []frpRouteDiagnostic {
	statuses := make(map[string]frpctl.RuleRuntimeStatus, len(snapshot.Rules))
	for _, status := range snapshot.Rules {
		statuses[status.RuleID] = status
	}
	gateways := make(map[string]frpctl.GatewayRuntimeStatus, len(snapshot.Gateways))
	for _, gateway := range snapshot.Gateways {
		gateways[gateway.RuleID] = gateway
	}
	routes := make([]frpRouteDiagnostic, 0, len(cfg.Profile.Rules))
	for _, rule := range cfg.Profile.Rules {
		status := statuses[rule.ID]
		gateway, hasGateway := gateways[rule.ID]
		state := status.State
		if state == "" {
			switch {
			case !rule.Enabled:
				state = "已禁用"
			case snapshot.Running:
				state = "等待注册"
			default:
				state = "已停止"
			}
		}
		path := ""
		gatewayAddress := ""
		if hasGateway {
			path = gateway.Path
			gatewayAddress = gateway.Address
		}
		if path == "" {
			if rule.Target.Kind == "mesh_peer" || rule.Target.Kind == "mesh_self" {
				path = "未建立"
			} else {
				path = "本地/局域网"
			}
		}
		routes = append(routes, frpRouteDiagnostic{
			RuleID: rule.ID, RuleName: rule.Name, Type: strings.ToUpper(rule.Type),
			TargetKind: rule.Target.Kind, TargetEndpoint: net.JoinHostPort(rule.Target.Host, fmt.Sprint(rule.Target.Port)),
			RemoteAddress: status.RemoteAddr, State: state, Path: path,
			GatewayAddress: gatewayAddress, GatewayStats: status.GatewayStats,
			ProxyProtocol: rule.Transport.ProxyProtocolVersion, Error: status.ErrorDetail,
		})
	}
	return routes
}

func buildFRPTargetGateways(snapshot frpctl.Snapshot) []frpTargetGatewayDiagnostic {
	out := make([]frpTargetGatewayDiagnostic, 0, len(snapshot.Gateways))
	for _, gateway := range snapshot.Gateways {
		stats := gateway.Stats
		out = append(out, frpTargetGatewayDiagnostic{
			RuleID: gateway.RuleID, Protocol: gateway.Protocol, Address: gateway.Address,
			Path: gateway.Path, State: gateway.State,
			Stats: frpGatewayStatsDiagnostic{
				LeaseGeneration: stats.LeaseGeneration, TCPAccepted: stats.TCPAccepted,
				TCPActive: stats.TCPActive, TCPRejected: stats.TCPRejected,
				UDPAccepted: stats.UDPAccepted, UDPActive: stats.UDPActive,
				UDPDropped: stats.UDPDropped, LeaseRejections: stats.LeaseRejections,
				DialFailures: stats.DialFailures, BytesToTarget: stats.BytesToTarget,
				BytesFromTarget: stats.BytesFromTarget, DatagramsToTarget: stats.DatagramsToTarget,
				DatagramsFromTarget: stats.DatagramsFromTarget,
			},
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RuleID < out[j].RuleID })
	return out
}

func inspectFRPTLS(ctx context.Context, cfg frpctl.Config, now time.Time) frpTLSCheckDiagnostic {
	if ctx == nil {
		ctx = context.Background()
	}
	check := frpTLSCheckDiagnostic{
		Status: "fail", CheckedAt: now.UTC(), TLSServerName: cfg.Profile.Server.TLSServerName,
		CAFile: cfg.Profile.Server.TrustedCAPath,
	}
	if cfg.Profile.Server.TrustedCAPath == "" {
		check.Error = tr("未配置可信 CA 文件", "Trusted CA file not configured")
		return check
	}
	certs, privateKey, err := readFRPCertificates(cfg.Profile.Server.TrustedCAPath)
	if err != nil {
		check.Error = redactFRPDiagnosticText(err.Error())
		return check
	}
	check.CAValid = true
	check.PrivateKeyMaterialPresent = privateKey
	check.CACertificates = make([]frpCertificateDiagnostic, 0, len(certs))
	status := "pass"
	for _, cert := range certs {
		check.CACertificates = append(check.CACertificates, describeFRPCertificate(cert))
		if now.Before(cert.NotBefore) {
			status = "fail"
			check.CAValid = false
			check.Error = tr("可信 CA 证书尚未生效", "Trusted CA certificate is not valid yet")
		} else if !now.Before(cert.NotAfter) {
			status = "fail"
			check.CAValid = false
			check.Error = tr("可信 CA 证书已过期", "Trusted CA certificate has expired")
		} else if cert.NotAfter.Sub(now) < 30*24*time.Hour && status != "fail" {
			status = "warn"
			check.Error = tr("可信 CA 证书将在 30 天内过期", "Trusted CA certificate expires within 30 days")
		}
	}
	if privateKey {
		if status == "pass" {
			status = "warn"
		}
		if check.Error == "" {
			check.Error = tr("可信 CA 文件中包含私钥材料；导出不会包含私钥内容", "Trusted CA file contains private key material; exports omit private keys")
		}
	}
	check.Status = status
	transport := strings.ToLower(cfg.Profile.Server.Transport)
	if transport == "kcp" || transport == "quic" {
		check.SkippedReason = tr("KCP/QUIC 的 TLS 握手由固定 frpc 在 UDP 传输内完成，本次只检查 CA 文件", "KCP/QUIC TLS handshake is handled by frpc over UDP; checked CA file only")
		return check
	}
	if cfg.Profile.Server.Host == "" || cfg.Profile.Server.Port < 1 || cfg.Profile.Server.TLSServerName == "" {
		check.Status = "fail"
		check.Error = tr("FRPS 地址或 TLS serverName 不完整", "FRPS host or TLS serverName is incomplete")
		return check
	}
	check.HandshakeAttempted = true
	start := time.Now()
	raw, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(cfg.Profile.Server.Host, fmt.Sprint(cfg.Profile.Server.Port)))
	if err != nil {
		check.Status = "warn"
		check.Error = redactFRPDiagnosticText("连接 FRPS TLS 端点: " + err.Error())
		return check
	}
	defer raw.Close()
	pool := x509.NewCertPool()
	for _, cert := range certs {
		pool.AddCert(cert)
	}
	tlsConn := tls.Client(raw, &tls.Config{
		ServerName: cfg.Profile.Server.TLSServerName, RootCAs: pool, MinVersion: tls.VersionTLS12,
	})
	handshakeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	err = tlsConn.HandshakeContext(handshakeCtx)
	check.HandshakeDurationMS = time.Since(start).Milliseconds()
	if err != nil {
		lower := strings.ToLower(err.Error())
		if strings.Contains(lower, "certificate") || strings.Contains(lower, "x509") || strings.Contains(lower, "unknown authority") || strings.Contains(lower, "server name") {
			check.Status = "fail"
		} else if check.Status != "fail" {
			check.Status = "warn"
		}
		check.Error = redactFRPDiagnosticText("TLS 握手: " + err.Error())
		return check
	}
	state := tlsConn.ConnectionState()
	check.HandshakeOK = true
	check.Verified = len(state.VerifiedChains) > 0
	check.TLSVersion = tlsVersionName(state.Version)
	check.CipherSuite = tls.CipherSuiteName(state.CipherSuite)
	for _, cert := range state.PeerCertificates {
		check.ServerCertificates = append(check.ServerCertificates, describeFRPCertificate(cert))
	}
	if check.Status == "pass" && !check.Verified {
		check.Status = "warn"
		check.Error = "TLS 握手完成，但没有可验证的证书链"
	}
	return check
}

func readFRPCertificates(path string) ([]*x509.Certificate, bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, false, fmt.Errorf("读取可信 CA: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, false, errors.New("可信 CA 不是普通文件")
	}
	if info.Size() <= 0 || info.Size() > frpctl.MaxCABytes {
		return nil, false, fmt.Errorf("可信 CA 文件大小无效（%d 字节）", info.Size())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false, fmt.Errorf("读取可信 CA: %w", err)
	}
	var certs []*x509.Certificate
	privateKey := false
	for len(data) > 0 {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		data = rest
		if strings.Contains(strings.ToUpper(block.Type), "PRIVATE KEY") {
			privateKey = true
			continue
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, parseErr := x509.ParseCertificate(block.Bytes)
		if parseErr != nil {
			return nil, privateKey, fmt.Errorf("解析可信 CA 证书: %w", parseErr)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, privateKey, errors.New("可信 CA 文件不包含 PEM 证书")
	}
	return certs, privateKey, nil
}

func describeFRPCertificate(cert *x509.Certificate) frpCertificateDiagnostic {
	sum := sha256.Sum256(cert.Raw)
	out := frpCertificateDiagnostic{
		Subject: cert.Subject.String(), Issuer: cert.Issuer.String(),
		NotBefore: cert.NotBefore.UTC(), NotAfter: cert.NotAfter.UTC(), IsCA: cert.IsCA,
		FingerprintSHA256: strings.ToUpper(hex.EncodeToString(sum[:])),
	}
	for _, name := range cert.DNSNames {
		out.DNSNames = append(out.DNSNames, name)
	}
	for _, ip := range cert.IPAddresses {
		out.IPAddresses = append(out.IPAddresses, ip.String())
	}
	return out
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS10:
		return "TLS 1.0"
	default:
		return fmt.Sprintf("0x%04x", version)
	}
}

func buildFRPProfileChecks(profile frpProfileDiagnostic, now time.Time) []clientapi.DiagnosticCheck {
	checked := now.UTC()
	status := "warn"
	if profile.Snapshot.Running && profile.Snapshot.Authenticated {
		status = "pass"
	}
	profileDetail := fmt.Sprintf("profile=%s server=%s:%d transport=%s state=%s running=%t authenticated=%t rules=%d visitors=%d",
		profile.ProfileID, profile.ServerHost, profile.ServerPort, profile.Transport, profile.Snapshot.State,
		profile.Snapshot.Running, profile.Snapshot.Authenticated, len(profile.Snapshot.Rules), len(profile.Snapshot.Visitors))
	if profile.Snapshot.LastError != "" {
		profileDetail += "; last_error=" + profile.Snapshot.LastError
	}
	checks := []clientapi.DiagnosticCheck{{
		Name: frpDiagnosticCheckName("frp_profile_", profile.ProfileID), Status: status,
		Detail: frpDiagnosticDetail(profileDetail), Checked: checked,
	}}
	if len(profile.Snapshot.Endpoints) > 0 {
		endpointStatus := "pass"
		endpointDetail := fmt.Sprintf("endpoints=%d", len(profile.Snapshot.Endpoints))
		for _, endpoint := range profile.Snapshot.Endpoints {
			if endpoint.State != frpctl.EndpointStateRunning {
				endpointStatus = "warn"
			}
			endpointDetail += fmt.Sprintf("; %s/%s %s:%d=%s generation=%d", endpoint.Kind, endpoint.Protocol, endpoint.Host, endpoint.Port, endpoint.State, endpoint.Owner.InstanceGeneration)
		}
		checks = append(checks, clientapi.DiagnosticCheck{
			Name: frpDiagnosticCheckName("frp_endpoints_", profile.ProfileID), Status: endpointStatus,
			Detail: frpDiagnosticDetail(endpointDetail), Checked: checked,
		})
	}
	observation := profile.Snapshot.Observation
	if observation.Generation != 0 || observation.StableState != "" || observation.CandidateState != "" {
		observationStatus := "pass"
		if observation.StableState != "healthy" {
			observationStatus = "warn"
		}
		observationDetail := fmt.Sprintf("generation=%d stable=%s candidate=%s candidate_count=%d stale_dropped=%d",
			observation.Generation, observation.StableState, observation.CandidateState, observation.CandidateCount, observation.StaleDropped)
		checks = append(checks, clientapi.DiagnosticCheck{
			Name: frpDiagnosticCheckName("frp_observation_", profile.ProfileID), Status: observationStatus,
			Detail: frpDiagnosticDetail(observationDetail), Checked: checked,
		})
	}
	if profile.ServerKind == "managed" {
		leaseStatus := "warn"
		leaseDetail := "未发现本地 managed lease"
		if len(profile.ManagedLeases) > 0 {
			leaseStatus = "pass"
			leaseDetail = fmt.Sprintf("leases=%d", len(profile.ManagedLeases))
			for _, lease := range profile.ManagedLeases {
				leaseDetail += fmt.Sprintf("; id=%s expires=%s rules=%d/%d observed=%t", lease.LeaseID, lease.ExpiresAt.UTC().Format(time.RFC3339), lease.GrantedRuleCount, lease.RequestedRuleCount, lease.Observed)
				if lease.Revoked != nil && *lease.Revoked {
					leaseStatus = "warn"
				}
				if lease.LoginSeen == nil || !*lease.LoginSeen {
					leaseStatus = "warn"
				}
				if profile.Snapshot.Running && (lease.ProxySeen == nil || !*lease.ProxySeen) {
					leaseStatus = "warn"
				}
				if lease.ObservationError != "" {
					leaseStatus = "warn"
					leaseDetail += "; error=" + lease.ObservationError
				}
			}
		}
		checks = append(checks, clientapi.DiagnosticCheck{
			Name: frpDiagnosticCheckName("frp_lease_", profile.ProfileID), Status: leaseStatus,
			Detail: frpDiagnosticDetail(leaseDetail), Checked: checked,
		})
	}
	if profile.Snapshot.Running || profile.Snapshot.DesiredRunning {
		routeStatus := "pass"
		routeDetail := fmt.Sprintf("egress=%d routes=%d", len(profile.Egress), len(profile.Routes))
		for _, route := range profile.Routes {
			if route.Path == "未建立" || route.State == "注册失败" {
				routeStatus = "warn"
			}
			routeDetail += fmt.Sprintf("; %s=%s/%s", route.RuleID, route.State, route.Path)
		}
		checks = append(checks, clientapi.DiagnosticCheck{
			Name: frpDiagnosticCheckName("frp_route_", profile.ProfileID), Status: routeStatus,
			Detail: frpDiagnosticDetail(routeDetail), Checked: checked,
		})
	}
	if len(profile.TargetGateways) > 0 {
		gatewayStatus := "pass"
		gatewayDetail := fmt.Sprintf("gateways=%d", len(profile.TargetGateways))
		for _, gateway := range profile.TargetGateways {
			if gateway.State != "运行中" {
				gatewayStatus = "warn"
			}
			gatewayDetail += fmt.Sprintf("; %s=%s gen=%d tcp=%d/%d udp=%d/%d", gateway.RuleID, gateway.State, gateway.Stats.LeaseGeneration, gateway.Stats.TCPActive, gateway.Stats.TCPAccepted, gateway.Stats.UDPActive, gateway.Stats.UDPAccepted)
		}
		checks = append(checks, clientapi.DiagnosticCheck{
			Name: frpDiagnosticCheckName("frp_gateway_", profile.ProfileID), Status: gatewayStatus,
			Detail: frpDiagnosticDetail(gatewayDetail), Checked: checked,
		})
	}
	tlsStatus := profile.TLS.Status
	if tlsStatus == "" {
		tlsStatus = "warn"
	}
	tlsDetail := fmt.Sprintf("ca_valid=%t handshake_attempted=%t handshake_ok=%t verified=%t version=%s skipped=%s",
		profile.TLS.CAValid, profile.TLS.HandshakeAttempted, profile.TLS.HandshakeOK,
		profile.TLS.Verified, profile.TLS.TLSVersion, profile.TLS.SkippedReason)
	if profile.TLS.Error != "" {
		tlsDetail += "; error=" + profile.TLS.Error
	}
	checks = append(checks, clientapi.DiagnosticCheck{
		Name: frpDiagnosticCheckName("frp_tls_", profile.ProfileID), Status: tlsStatus,
		Detail: frpDiagnosticDetail(tlsDetail), Checked: checked,
	})
	return checks
}

func frpDiagnosticCheckName(prefix, id string) string {
	value := prefix + id
	if len(value) <= 128 {
		return value
	}
	return value[:128]
}

func frpDiagnosticDetail(value string) string {
	const limit = 2048
	if len(value) <= limit {
		return value
	}
	end := limit
	for end > 0 && (value[end]&0xc0) == 0x80 {
		end--
	}
	return value[:end]
}

func (e diagnosticExport) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s 诊断报告\r\n", appName, e.AppVersion)
	fmt.Fprintf(&b, "生成时间: %s\r\n", e.GeneratedAt.UTC().Format(time.RFC3339))
	b.WriteString("检查项:\r\n")
	for _, check := range e.Checks {
		fmt.Fprintf(&b, "[%s] %s: %s\r\n", check.Status, check.Name, check.Detail)
	}
	if e.MeshQuality != nil {
		fmt.Fprintf(&b, "\r\n== 网络质量（最近 5 分钟）==\r\n")
		fmt.Fprintf(&b, "样本: %d, 平均 RTT: %d ms, 最大 RTT: %d ms, 丢包增量: %d, 直连样本: %d, 中继样本: %d\r\n",
			e.MeshQuality.Summary.Samples, e.MeshQuality.Summary.AverageRTTMillis, e.MeshQuality.Summary.MaxRTTMillis,
			e.MeshQuality.Summary.DroppedDelta, e.MeshQuality.Summary.DirectSamples, e.MeshQuality.Summary.RelaySamples)
		for _, sample := range e.MeshQuality.Samples {
			fmt.Fprintf(&b, "%s path=%s rtt_ms=%d reachable=%d/%d sent=%d received=%d dropped=%d relay_queue=%d/%d relay_drops=%d relay_backpressure=%d\r\n",
				sample.At.UTC().Format(time.RFC3339), sample.Path, sample.RTTMillis, sample.ReachablePeers, sample.TotalPeers,
				sample.Sent, sample.Received, sample.Dropped, sample.RelayQueueDepth, sample.RelayQueueCapacity,
				sample.RelayDrops, sample.RelayBackpressure)
		}
	}
	for _, profile := range e.FRP.Profiles {
		fmt.Fprintf(&b, "\r\n== FRP 配置: %s (%s) ==\r\n", profile.ProfileName, profile.ProfileID)
		fmt.Fprintf(&b, "服务器: %s %s:%d, transport=%s, tls_server_name=%s\r\n", profile.ServerKind, profile.ServerHost, profile.ServerPort, profile.Transport, profile.TLSServerName)
		fmt.Fprintf(&b, "状态: %s, running=%t, authenticated=%t, rules=%d, visitors=%d\r\n", profile.Snapshot.State, profile.Snapshot.Running, profile.Snapshot.Authenticated, len(profile.Snapshot.Rules), len(profile.Snapshot.Visitors))
		if profile.Snapshot.LastError != "" {
			fmt.Fprintf(&b, "最近错误: %s (%s)\r\n", profile.Snapshot.LastError, profile.Snapshot.LastErrorCode)
		}
		if len(profile.Snapshot.Endpoints) > 0 {
			b.WriteString("EndpointRegistry:\r\n")
			for _, endpoint := range profile.Snapshot.Endpoints {
				fmt.Fprintf(&b, "  kind=%s protocol=%s address=%s state=%s profile=%s generation=%d rule=%s visitor=%s purpose=%s\r\n",
					endpoint.Kind, endpoint.Protocol, net.JoinHostPort(endpoint.Host, fmt.Sprint(endpoint.Port)), endpoint.State,
					endpoint.Owner.ProfileID, endpoint.Owner.InstanceGeneration, endpoint.Owner.RuleID, endpoint.Owner.VisitorID, endpoint.Owner.Purpose)
			}
		}
		observation := profile.Snapshot.Observation
		fmt.Fprintf(&b, "RouteObservation: generation=%d stable=%s candidate=%s candidate_count=%d stale_dropped=%d\r\n",
			observation.Generation, observation.StableState, observation.CandidateState, observation.CandidateCount, observation.StaleDropped)
		for _, lease := range profile.ManagedLeases {
			fmt.Fprintf(&b, "managed lease: %s expires=%s remaining=%ds rules=%d/%d observed=%t revoked=%s login_seen=%s proxy_seen=%s\r\n",
				lease.LeaseID, lease.ExpiresAt.UTC().Format(time.RFC3339), lease.RemainingSeconds,
				lease.GrantedRuleCount, lease.RequestedRuleCount, lease.Observed,
				boolPointerText(lease.Revoked), boolPointerText(lease.LoginSeen), boolPointerText(lease.ProxySeen))
			if lease.ObservationError != "" {
				fmt.Fprintf(&b, "  lease observation error: %s\r\n", lease.ObservationError)
			}
		}
		for _, egress := range profile.Egress {
			fmt.Fprintf(&b, "出口: kind=%s mode=%s address=%s purpose=%s\r\n", egress.Kind, egress.Mode, egress.Address, egress.Purpose)
		}
		for _, route := range profile.Routes {
			fmt.Fprintf(&b, "路由: rule=%s type=%s target=%s state=%s path=%s remote=%s\r\n", route.RuleID, route.Type, route.TargetEndpoint, route.State, route.Path, route.RemoteAddress)
			if route.Error != "" {
				fmt.Fprintf(&b, "  错误: %s\r\n", route.Error)
			}
		}
		for _, gateway := range profile.TargetGateways {
			fmt.Fprintf(&b, "TargetGateway: rule=%s protocol=%s address=%s state=%s path=%s gen=%d tcp=%d/%d/%d udp=%d/%d/%d dial_failures=%d\r\n",
				gateway.RuleID, gateway.Protocol, gateway.Address, gateway.State, gateway.Path, gateway.Stats.LeaseGeneration,
				gateway.Stats.TCPActive, gateway.Stats.TCPAccepted, gateway.Stats.TCPRejected,
				gateway.Stats.UDPActive, gateway.Stats.UDPAccepted, gateway.Stats.UDPDropped, gateway.Stats.DialFailures)
		}
		fmt.Fprintf(&b, "TLS: status=%s ca_valid=%t private_key_material=%t handshake_attempted=%t handshake_ok=%t verified=%t version=%s cipher=%s skipped=%s\r\n",
			profile.TLS.Status, profile.TLS.CAValid, profile.TLS.PrivateKeyMaterialPresent, profile.TLS.HandshakeAttempted,
			profile.TLS.HandshakeOK, profile.TLS.Verified, profile.TLS.TLSVersion, profile.TLS.CipherSuite, profile.TLS.SkippedReason)
		if profile.TLS.Error != "" {
			fmt.Fprintf(&b, "TLS 错误: %s\r\n", profile.TLS.Error)
		}
		if len(profile.Logs) > 0 {
			b.WriteString("FRP 日志:\r\n")
			for _, line := range profile.Logs {
				fmt.Fprintf(&b, "  %s\r\n", line)
			}
		}
		for _, item := range profile.CollectionErrors {
			fmt.Fprintf(&b, "采集错误: %s\r\n", item)
		}
	}
	return b.String()
}

func boolPointerText(value *bool) string {
	if value == nil {
		return "unknown"
	}
	if *value {
		return "true"
	}
	return "false"
}

func writeDiagnosticExport(dir string, export diagnosticExport, secrets []string) (string, string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", "", fmt.Errorf("创建诊断目录: %w", err)
	}
	jsonData, err := encodeRedactedFRPDiagnosticJSON(export, secrets, true)
	if err != nil {
		return "", "", err
	}
	jsonPath := filepath.Join(dir, "diagnostics.json")
	textPath := filepath.Join(dir, "diagnostics.txt")
	textData := []byte(redactFRPDiagnosticText(export.Text(), secrets...))
	jsonErr := os.WriteFile(jsonPath, append(jsonData, '\n'), 0o600)
	textErr := os.WriteFile(textPath, append(textData, '\r', '\n'), 0o600)
	if err := errors.Join(jsonErr, textErr); err != nil {
		return jsonPath, textPath, err
	}
	return jsonPath, textPath, nil
}
func encodeRedactedFRPDiagnosticJSON(value any, secrets []string, indent bool) ([]byte, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("编码诊断 JSON: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var document any
	if err = decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("准备诊断 JSON: %w", err)
	}
	document = redactFRPDiagnosticJSONValue(document, secrets...)
	if indent {
		data, err = json.MarshalIndent(document, "", "  ")
	} else {
		data, err = json.Marshal(document)
	}
	if err != nil {
		return nil, fmt.Errorf("编码诊断 JSON: %w", err)
	}
	return data, nil
}

func frpDiagnosticSecretValues(sources []frpDiagnosticSource, base []string) []string {
	seen := make(map[string]struct{}, len(base)+len(sources))
	out := make([]string, 0, len(base)+len(sources))
	add := func(value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		if _, ok := seen[value]; ok {
			return
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	for _, value := range base {
		add(value)
	}
	for _, source := range sources {
		if source.Provider == nil {
			continue
		}
		source.Provider.mu.Lock()
		for _, lease := range source.Provider.leases {
			add(lease.Credential)
		}
		source.Provider.mu.Unlock()
	}
	return out
}

func uploadFRPDiagnosticReport(api *clientapi.Client, networkID core.NetworkID, deviceID core.DeviceID, checks []clientapi.DiagnosticCheck, report frpDiagnosticExport, secrets []string) error {
	if api == nil {
		return errors.New("FRP 诊断上传客户端不可用")
	}
	reportJSON, err := encodeRedactedFRPDiagnosticJSON(report, secrets, false)
	if err != nil {
		return err
	}
	return api.UploadDiagnosticsWithFRP(networkID, deviceID, checks, reportJSON)
}

func redactFRPDiagnosticJSONValue(value any, secrets ...string) any {
	switch item := value.(type) {
	case string:
		return redactFRPDiagnosticText(item, secrets...)
	case []any:
		for i := range item {
			item[i] = redactFRPDiagnosticJSONValue(item[i], secrets...)
		}
		return item
	case map[string]any:
		for key, child := range item {
			item[key] = redactFRPDiagnosticJSONValue(child, secrets...)
		}
		return item
	default:
		return value
	}
}
