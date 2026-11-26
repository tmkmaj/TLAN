package control

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/private-radminlan/lanmesh/core"
	"github.com/private-radminlan/lanmesh/internal/frpauth"
	"github.com/private-radminlan/lanmesh/internal/metrics"
	"github.com/private-radminlan/lanmesh/internal/storage"
)

type adminOverview struct {
	Service        string                 `json:"service"`
	Version        string                 `json:"version"`
	Stage          string                 `json:"stage"`
	UptimeSeconds  int64                  `json:"uptime_seconds"`
	ControlListen  string                 `json:"control_listen"`
	ControlTLS     bool                   `json:"control_tls"`
	AdminListen    string                 `json:"admin_listen"`
	AdminTLS       bool                   `json:"admin_tls"`
	DataDirSummary string                 `json:"data_dir_summary"`
	Network        storage.NetworkSummary `json:"network"`
	MemberCount    int                    `json:"member_count"`
	OnlineCount    int                    `json:"online_count"`
	BlockedCount   int                    `json:"blocked_count"`
	RelayStatus    string                 `json:"relay_status"`
	RelaySessions  int                    `json:"relay_sessions"`
	FRPStatus      string                      `json:"frp_status"`
	FRPLeaseCount  int                         `json:"frp_lease_count"`
	FRPPortStart   int                         `json:"frp_port_start"`
	FRPPortEnd     int                         `json:"frp_port_end"`
	ServerDisplay  storage.ServerDisplayConfig `json:"server_display"`
}

type adminMember struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	VirtualIP  string    `json:"virtual_ip"`
	Online     bool      `json:"online"`
	Blocked    bool      `json:"blocked"`
	Forwarding *bool     `json:"forwarding,omitempty"`
	JoinedAt   time.Time `json:"joined_at"`
	LastSeen   time.Time `json:"last_seen"`
	RelayCount int       `json:"relay_count"`
	FRPLeases  int       `json:"frp_leases"`
	// ClientVersion is the release version the device last reported so an
	// operator can see who a minimum-version gate would cut off.
	ClientVersion string `json:"client_version,omitempty"`
}

type adminConsole struct {
	server        *Server
	auth          *adminAuth
	listenAddress string
	apiToken      string
}

type adminAPIError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type adminAPIResponse struct {
	OK        bool           `json:"ok"`
	Data      any            `json:"data,omitempty"`
	Error     *adminAPIError `json:"error,omitempty"`
	RequestID string         `json:"request_id"`
}

func (s *Server) AdminHandler(adminToken string, secure bool) http.Handler {
	return s.AdminHandlerForListen(adminToken, secure, "")
}

func (s *Server) AdminHandlerForListen(adminToken string, secure bool, listenAddress string) http.Handler {
	console := &adminConsole{server: s, auth: newAdminAuth(adminToken, secure), listenAddress: strings.TrimSpace(listenAddress)}
	console.apiToken = adminToken
	return http.HandlerFunc(console.serveHTTP)
}

func (c *adminConsole) serveHTTP(w http.ResponseWriter, r *http.Request) {
	requestID := adminRequestID()
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Request-ID", requestID)
	w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
	if !c.allowedHost(r) {
		writeAdminFailure(w, http.StatusNotFound, requestID, "NOT_FOUND", "接口不存在")
		return
	}
	if !c.allowedOrigin(r) {
		writeAdminFailure(w, http.StatusForbidden, requestID, "FORBIDDEN", "请求来源不被允许")
		return
	}
	switch {
	case r.URL.Path == "/admin" || r.URL.Path == "/admin/":
		_, csrf, ok := c.auth.authorize(r)
		if !ok {
			writeAdminPage(w, false, "", !c.auth.secure)
			return
		}
		writeAdminPage(w, true, csrf, !c.auth.secure)
	case r.URL.Path == "/admin/login":
		c.auth.login(w, r)
	case r.URL.Path == "/admin/logout":
		c.auth.logout(w, r)
	case r.URL.Path == "/metrics":
		token := r.Header.Get("X-Admin-Token")
		if token == "" {
			token = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		}
		if !adminTokenMatches(token, c.apiToken) {
			if _, _, ok := c.auth.authorize(r); !ok {
				writeAdminFailure(w, http.StatusUnauthorized, requestID, "UNAUTHORIZED", "认证失败")
				return
			}
		}
		c.metrics(w)
	case strings.HasPrefix(r.URL.Path, "/admin/api/"):
		if _, _, ok := c.auth.authorize(r); !ok {
			writeAdminFailure(w, http.StatusUnauthorized, requestID, "UNAUTHORIZED", "认证失败")
			return
		}
		c.serveAPI(w, r, requestID)
	default:
		writeAdminFailure(w, http.StatusNotFound, requestID, "NOT_FOUND", "接口不存在")
	}
}

func (c *adminConsole) allowedHost(r *http.Request) bool {
	if c.listenAddress == "" {
		return true
	}
	listenHost, listenPort, err := net.SplitHostPort(c.listenAddress)
	if err != nil {
		return false
	}
	host, port, err := net.SplitHostPort(r.Host)
	if err != nil {
		host = r.Host
		port = ""
	}
	if listenPort != "" && port != listenPort {
		return false
	}
	host = normalizeAdminHost(host)
	listenHost = normalizeAdminHost(listenHost)
	if strings.EqualFold(host, listenHost) {
		return true
	}
	if isLoopbackAdminHost(listenHost) && isLoopbackAdminHost(host) {
		return true
	}
	if listenHost == "" || listenHost == "0.0.0.0" || listenHost == "::" {
		if strings.EqualFold(host, "localhost") {
			return true
		}
		return net.ParseIP(host) != nil
	}
	return false
}

func normalizeAdminHost(host string) string {
	return strings.TrimSuffix(strings.Trim(strings.TrimSpace(host), "[]"), ".")
}

func isLoopbackAdminHost(host string) bool {
	host = normalizeAdminHost(host)
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (c *adminConsole) allowedOrigin(r *http.Request) bool {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return true
	}
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Host == "" || parsed.User != nil {
		return false
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return false
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return false
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if !strings.EqualFold(parsed.Scheme, scheme) {
		return false
	}
	return strings.EqualFold(normalizeAdminHost(parsed.Host), normalizeAdminHost(r.Host))
}

func (c *adminConsole) serveAPI(w http.ResponseWriter, r *http.Request, requestID string) {
	switch {
	case r.URL.Path == "/admin/api/overview" && r.Method == http.MethodGet:
		c.overview(w, requestID)
	case r.URL.Path == "/admin/api/members" && r.Method == http.MethodGet:
		c.members(w, requestID)
	case r.URL.Path == "/admin/api/relay-sessions" && r.Method == http.MethodGet:
		c.relaySessions(w, requestID)
	case r.URL.Path == "/admin/api/session" && r.Method == http.MethodGet:
		c.session(w, r, requestID)
	case r.URL.Path == "/admin/api/frp-port-range" && r.Method == http.MethodPost:
		c.setFRPPortRange(w, r, requestID)
	case r.URL.Path == "/admin/api/server-display" && r.Method == http.MethodPost:
		c.setServerDisplay(w, r, requestID)
	case r.URL.Path == "/admin/api/network-name" && r.Method == http.MethodPost:
		c.setNetworkName(w, r, requestID)
	case strings.HasPrefix(r.URL.Path, "/admin/api/members/") && r.Method == http.MethodPost:
		c.memberAction(w, r, requestID)
	case r.URL.Path == "/admin/api/overview" || r.URL.Path == "/admin/api/members" || r.URL.Path == "/admin/api/relay-sessions" || r.URL.Path == "/admin/api/session" || r.URL.Path == "/admin/api/frp-port-range" || r.URL.Path == "/admin/api/server-display" || r.URL.Path == "/admin/api/network-name" || strings.HasPrefix(r.URL.Path, "/admin/api/members/"):
		writeAdminFailure(w, http.StatusMethodNotAllowed, requestID, "METHOD_NOT_ALLOWED", "请求方法不允许")
	default:
		writeAdminFailure(w, http.StatusNotFound, requestID, "NOT_FOUND", "接口不存在")
	}
}

func (c *adminConsole) metrics(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	registry := metrics.NewRegistry()
	relaySessions := 0
	if c.server.Relay != nil {
		relaySessions = len(c.server.Relay.Snapshot())
	}
	relayQueueDropped, relayBackpressure, relayWriteErrors := int64(0), int64(0), int64(0)
	if c.server.Relay != nil {
		stats := c.server.Relay.Stats()
		relayQueueDropped = stats.DroppedQueueFull
		relayBackpressure = stats.BackpressureEvents
		relayWriteErrors = stats.WriteErrors
	}
	network, networkErr := c.server.Store.PrivateNetwork()
	activeMembers := 0
	versionCounts := make(map[string]int)
	if networkErr == nil {
		devices, err := c.server.Store.ListDevicesWithBlocked(network.ID, true)
		if err == nil {
			for _, device := range devices {
				if device.Online {
					activeMembers++
				}
				version, _ := c.server.Store.ClientVersion(core.DeviceID(device.ID))
				if version == "" {
					version = "unknown"
				}
				versionCounts[version]++
			}
		}
	}
	gauges := []struct {
		name, help string
		value      float64
	}{
		{"tlan_active_members", "Currently online private-network members.", float64(activeMembers)},
		{"tlan_relay_sessions", "Current relay sessions.", float64(relaySessions)},
	}
	for _, metric := range gauges {
		gauge, err := registry.NewGauge(metric.name, metric.help)
		if err == nil {
			gauge.Set(metric.value)
		}
	}
	counters := []struct {
		name, help string
		value      float64
	}{
		{"tlan_relay_queue_dropped_total", "Relay queue drops caused by full recipient queues.", float64(relayQueueDropped)},
		{"tlan_relay_backpressure_total", "Relay queue congestion events.", float64(relayBackpressure)},
		{"tlan_relay_write_errors_total", "Relay stream asynchronous write failures.", float64(relayWriteErrors)},
	}
	for _, metric := range counters {
		counter, err := registry.NewCounter(metric.name, metric.help)
		if err == nil {
			counter.Set(metric.value)
		}
	}
	if versions, err := registry.NewGaugeVec("tlan_client_version", "Registered members by reported client version.", []string{"version"}); err == nil {
		for version, count := range versionCounts {
			if gauge, lookupErr := versions.WithLabelValues(version); lookupErr == nil {
				gauge.Set(float64(count))
			}
		}
	}
	_ = registry.WritePrometheus(w)
}

func (c *adminConsole) session(w http.ResponseWriter, r *http.Request, requestID string) {
	csrf, expiresAt, ok := c.auth.sessionInfo(r)
	if !ok {
		writeAdminFailure(w, http.StatusUnauthorized, requestID, "UNAUTHORIZED", "认证失败")
		return
	}
	writeAdminData(w, http.StatusOK, requestID, map[string]any{
		"csrf_token": csrf,
		"expires_at": expiresAt,
		"started_at": c.server.StartedAt,
	})
}

func (c *adminConsole) overview(w http.ResponseWriter, requestID string) {
	network, err := c.server.Store.PrivateNetwork()
	if err != nil {
		writeAdminFailure(w, http.StatusNotFound, requestID, "NETWORK_NOT_CONFIGURED", "私人网络未配置")
		return
	}
	devices, err := c.server.Store.ListDevicesWithBlocked(network.ID, true)
	if err != nil {
		slog.Error("admin overview failed", "request_id", requestID, "network", network.ID, "error", err)
		writeAdminFailure(w, http.StatusInternalServerError, requestID, "INTERNAL_ERROR", "服务器内部错误")
		return
	}
	online, blocked := 0, 0
	for _, device := range devices {
		if device.Online {
			online++
		}
		if device.Blocked {
			blocked++
		}
	}
	relayStatus, relayCount := "disabled", 0
	if c.server.Relay != nil {
		relayStatus = "enabled"
		relayCount = len(c.server.Relay.Snapshot())
	}
	frpStatus, frpLeases := "disabled", 0
	if c.server.FRP != nil {
		frpStatus = "enabled"
		frpLeases = c.server.FRP.ActiveLeaseCount(network.ID, "")
	}
	uptime := int64(0)
	if !c.server.StartedAt.IsZero() {
		uptime = int64(time.Since(c.server.StartedAt).Seconds())
	}
	portRange := c.server.effectiveFRPPortRange()
	serverDisplay := storage.DefaultServerDisplay
	if c.server.Store != nil {
		serverDisplay = c.server.Store.ServerDisplay()
	}
	writeAdminData(w, http.StatusOK, requestID, adminOverview{
		Service: "tlan-control", Version: "1.0.0", Stage: "encrypted-ipv4-mesh",
		UptimeSeconds: uptime, ControlListen: c.server.ControlListen, ControlTLS: c.server.ControlTLS,
		AdminListen: c.server.AdminListen, AdminTLS: c.server.AdminTLS, DataDirSummary: c.server.DataDirSummary,
		Network: network, MemberCount: len(devices), OnlineCount: online, BlockedCount: blocked,
		RelayStatus: relayStatus, RelaySessions: relayCount, FRPStatus: frpStatus, FRPLeaseCount: frpLeases,
		FRPPortStart: portRange.Start, FRPPortEnd: portRange.End,
		ServerDisplay: serverDisplay,
	})
}

func (c *adminConsole) setServerDisplay(w http.ResponseWriter, r *http.Request, requestID string) {
	var req struct {
		Mode  string `json:"mode"`
		Alias string `json:"alias"`
	}
	if err := decodeAdminJSON(r, &req); err != nil {
		logAdminAction(r, requestID, "server_display", "", "", "invalid_request", err)
		writeAdminFailure(w, http.StatusBadRequest, requestID, "INVALID_REQUEST", "请求格式无效")
		return
	}
	if _, err := storage.ValidateServerDisplay(req.Mode, req.Alias); err != nil {
		writeAdminFailure(w, http.StatusBadRequest, requestID, "INVALID_SERVER_DISPLAY", "连接服务器显示配置无效："+err.Error())
		return
	}
	saved, err := c.server.Store.SetServerDisplay(req.Mode, req.Alias)
	if err != nil {
		logAdminAction(r, requestID, "server_display", "", "", "error", err)
		writeAdminFailure(w, http.StatusInternalServerError, requestID, "INTERNAL_ERROR", "保存服务器显示配置失败")
		return
	}
	logAdminAction(r, requestID, "server_display", "", saved.Mode, "ok", nil)
	writeAdminData(w, http.StatusOK, requestID, saved)
}

func (c *adminConsole) setNetworkName(w http.ResponseWriter, r *http.Request, requestID string) {
	var req struct {
		Name string `json:"name"`
	}
	if err := decodeAdminJSON(r, &req); err != nil {
		logAdminAction(r, requestID, "network_name", "", "", "invalid_request", err)
		writeAdminFailure(w, http.StatusBadRequest, requestID, "INVALID_REQUEST", "请求格式无效")
		return
	}
	valid, err := storage.ValidateNetworkName(req.Name)
	if err != nil {
		writeAdminFailure(w, http.StatusBadRequest, requestID, "INVALID_NETWORK_NAME", "网络名称无效：请填写 1-64 个非控制字符")
		return
	}
	saved, err := c.server.Store.RenameNetwork("", valid)
	if err != nil {
		logAdminAction(r, requestID, "network_name", "", "", "error", err)
		writeAdminFailure(w, http.StatusInternalServerError, requestID, "INTERNAL_ERROR", "保存网络名称失败")
		return
	}
	logAdminAction(r, requestID, "network_name", saved.ID, saved.Name, "ok", nil)
	writeAdminData(w, http.StatusOK, requestID, saved)
}

func (c *adminConsole) setFRPPortRange(w http.ResponseWriter, r *http.Request, requestID string) {
	var req struct {
		Start int `json:"start"`
		End   int `json:"end"`
	}
	if err := decodeAdminJSON(r, &req); err != nil {
		logAdminAction(r, requestID, "frp_port_range", "", "", "invalid_request", err)
		writeAdminFailure(w, http.StatusBadRequest, requestID, "INVALID_REQUEST", "请求格式无效")
		return
	}
	if err := storage.ValidatePortRange(req.Start, req.End); err != nil {
		writeAdminFailure(w, http.StatusBadRequest, requestID, "INVALID_PORT_RANGE", "端口范围无效，请填写 1-65535 且起始端口不大于结束端口")
		return
	}
	saved, err := c.server.Store.SetFRPPortRange(req.Start, req.End)
	if err != nil {
		logAdminAction(r, requestID, "frp_port_range", "", "", "error", err)
		writeAdminFailure(w, http.StatusInternalServerError, requestID, "INTERNAL_ERROR", "保存端口范围失败")
		return
	}
	if c.server.FRP != nil {
		if err := c.server.FRP.SetAllowedPorts([]frpauth.PortRange{{Start: saved.Start, End: saved.End}}); err != nil {
			logAdminAction(r, requestID, "frp_port_range", "", "", "error", err)
			writeAdminFailure(w, http.StatusInternalServerError, requestID, "INTERNAL_ERROR", "更新 FRP 端口限制失败")
			return
		}
	}
	logAdminAction(r, requestID, "frp_port_range", "", fmt.Sprintf("%d-%d", saved.Start, saved.End), "ok", nil)
	writeAdminData(w, http.StatusOK, requestID, saved)
}

func (c *adminConsole) members(w http.ResponseWriter, requestID string) {
	network, err := c.server.Store.PrivateNetwork()
	if err != nil {
		writeAdminFailure(w, http.StatusNotFound, requestID, "NETWORK_NOT_CONFIGURED", "私人网络未配置")
		return
	}
	devices, err := c.server.Store.ListDevicesWithBlocked(network.ID, true)
	if err != nil {
		slog.Error("admin members failed", "request_id", requestID, "network", network.ID, "error", err)
		writeAdminFailure(w, http.StatusInternalServerError, requestID, "INTERNAL_ERROR", "服务器内部错误")
		return
	}
	counts := c.relayCounts()
	members := make([]adminMember, 0, len(devices))
	for _, device := range devices {
		frpLeases := 0
		if c.server.FRP != nil {
			frpLeases = c.server.FRP.ActiveLeaseCount(network.ID, device.ID)
		}
		clientVersion, _ := c.server.Store.ClientVersion(core.DeviceID(device.ID))
		members = append(members, adminMember{
			ID: device.ID, Name: device.Name, VirtualIP: device.VirtualIP, Online: device.Online,
			Blocked: device.Blocked, Forwarding: device.Forwarding, JoinedAt: device.JoinedAt,
			LastSeen: device.LastSeen, RelayCount: counts[device.ID], FRPLeases: frpLeases,
			ClientVersion: clientVersion,
		})
	}
	writeAdminData(w, http.StatusOK, requestID, map[string]any{"network": network, "members": members})
}
func (c *adminConsole) relaySessions(w http.ResponseWriter, requestID string) {
	if c.server.Relay == nil {
		writeAdminData(w, http.StatusOK, requestID, map[string]any{"sessions": []any{}})
		return
	}
	writeAdminData(w, http.StatusOK, requestID, map[string]any{"sessions": c.server.Relay.Snapshot()})
}

func (c *adminConsole) relayCounts() map[string]int {
	counts := make(map[string]int)
	if c.server.Relay == nil {
		return counts
	}
	for _, session := range c.server.Relay.Snapshot() {
		counts[session.Source.String()]++
		counts[session.Target.String()]++
	}
	return counts
}

func (c *adminConsole) memberAction(w http.ResponseWriter, r *http.Request, requestID string) {
	c.memberActionForPrefix(w, r, requestID, "/admin/api/members/")
}

func (c *adminConsole) memberActionForPrefix(w http.ResponseWriter, r *http.Request, requestID, prefix string) {
	path := strings.TrimPrefix(r.URL.Path, prefix)
	parts := strings.Split(path, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		writeAdminFailure(w, http.StatusNotFound, requestID, "NOT_FOUND", "接口不存在")
		return
	}
	action := parts[1]
	deviceID, err := core.NewDeviceID(parts[0])
	if err != nil {
		writeAdminFailure(w, http.StatusBadRequest, requestID, "INVALID_DEVICE_ID", "成员 ID 无效")
		return
	}
	network, err := c.server.Store.PrivateNetwork()
	if err != nil {
		writeAdminFailure(w, http.StatusNotFound, requestID, "NETWORK_NOT_CONFIGURED", "私人网络未配置")
		return
	}
	switch action {
	case "rename":
		var req struct {
			Name string `json:"name"`
		}
		if err := decodeAdminJSON(r, &req); err != nil {
			logAdminAction(r, requestID, action, network.ID, deviceID.String(), "invalid_request", err)
			writeAdminFailure(w, http.StatusBadRequest, requestID, "INVALID_REQUEST", "请求格式无效")
			return
		}
		member, err := c.server.Store.RenameDevice(network.ID, deviceID.String(), req.Name)
		if err != nil {
			writeAdminStorageError(w, r, requestID, action, network.ID, deviceID.String(), err)
			return
		}
		logAdminAction(r, requestID, action, network.ID, deviceID.String(), "ok", nil)
		writeAdminData(w, http.StatusOK, requestID, member)
	case "disconnect":
		if err := c.cleanupRuntime(network.ID, deviceID, true); err != nil {
			logAdminAction(r, requestID, action, network.ID, deviceID.String(), "partial_failure", err)
			writeAdminFailure(w, http.StatusInternalServerError, requestID, "PARTIAL_FAILURE", "运行时清理未完成，请刷新后重试")
			return
		}
		logAdminAction(r, requestID, action, network.ID, deviceID.String(), "ok", nil)
		writeAdminData(w, http.StatusOK, requestID, map[string]string{"status": "disconnected"})
	case "kick":
		if err := c.server.Store.RevokeMemberCredentials(network.ID, deviceID.String()); err != nil {
			writeAdminStorageError(w, r, requestID, action, network.ID, deviceID.String(), err)
			return
		}
		if err := c.cleanupRuntime(network.ID, deviceID, true); err != nil {
			logAdminAction(r, requestID, action, network.ID, deviceID.String(), "partial_failure", err)
			writeAdminFailure(w, http.StatusInternalServerError, requestID, "PARTIAL_FAILURE", "凭据已撤销，但运行时清理未完成，请刷新后重试")
			return
		}
		logAdminAction(r, requestID, action, network.ID, deviceID.String(), "ok", nil)
		writeAdminData(w, http.StatusOK, requestID, map[string]string{"status": "kicked"})
	case "ban":
		if _, err := c.server.Store.SetDeviceBlocked(network.ID, deviceID.String(), true); err != nil {
			writeAdminStorageError(w, r, requestID, action, network.ID, deviceID.String(), err)
			return
		}
		if err := c.cleanupRuntime(network.ID, deviceID, true); err != nil {
			logAdminAction(r, requestID, action, network.ID, deviceID.String(), "partial_failure", err)
			writeAdminFailure(w, http.StatusInternalServerError, requestID, "PARTIAL_FAILURE", "封禁已保存，但运行时清理未完成，请刷新后重试")
			return
		}
		logAdminAction(r, requestID, action, network.ID, deviceID.String(), "ok", nil)
		writeAdminData(w, http.StatusOK, requestID, map[string]string{"status": "banned"})
	case "unban":
		member, err := c.server.Store.SetDeviceBlocked(network.ID, deviceID.String(), false)
		if err != nil {
			writeAdminStorageError(w, r, requestID, action, network.ID, deviceID.String(), err)
			return
		}
		logAdminAction(r, requestID, action, network.ID, deviceID.String(), "ok", nil)
		writeAdminData(w, http.StatusOK, requestID, member)
	default:
		writeAdminFailure(w, http.StatusNotFound, requestID, "NOT_FOUND", "接口不存在")
	}
}

func (c *adminConsole) cleanupRuntime(networkID string, deviceID core.DeviceID, revokeFRP bool) error {
	var failures []error
	if c.server.Relay != nil {
		c.server.Relay.DisconnectDevice(deviceID)
	}
	if revokeFRP {
		if err := c.revokeFRP(networkID, deviceID.String()); err != nil {
			failures = append(failures, err)
		}
	}
	if _, err := c.server.Store.SetForwarding(networkID, deviceID.String(), false); err != nil {
		failures = append(failures, err)
	}
	return errors.Join(failures...)
}

func (c *adminConsole) revokeFRP(networkID, deviceID string) error {
	if c.server.FRP == nil {
		return nil
	}
	return c.server.FRP.RevokeDevice(networkID, deviceID)
}

func writeAdminData(w http.ResponseWriter, status int, requestID string, data any) {
	writeJSON(w, status, adminAPIResponse{OK: true, Data: data, RequestID: requestID})
}

func writeAdminFailure(w http.ResponseWriter, status int, requestID, code, message string) {
	writeJSON(w, status, adminAPIResponse{OK: false, Error: &adminAPIError{Code: code, Message: message}, RequestID: requestID})
}

func writeAdminStorageError(w http.ResponseWriter, r *http.Request, requestID, action, networkID, deviceID string, err error) {
	status, code, message := http.StatusInternalServerError, "INTERNAL_ERROR", "服务器内部错误"
	switch {
	case errors.Is(err, storage.ErrNotFound):
		status, code, message = http.StatusNotFound, "MEMBER_NOT_FOUND", "成员不存在"
	case errors.Is(err, storage.ErrBlocked):
		status, code, message = http.StatusConflict, "MEMBER_BLOCKED", "成员已被拉黑"
	case errors.Is(err, storage.ErrConflict):
		status, code, message = http.StatusConflict, "CONFLICT", "操作冲突"
	}
	logAdminAction(r, requestID, action, networkID, deviceID, "error", err)
	writeAdminFailure(w, status, requestID, code, message)
}

func logAdminAction(r *http.Request, requestID, action, networkID, deviceID, result string, err error) {
	args := []any{
		"request_id", requestID,
		"action", action,
		"network", networkID,
		"device", deviceID,
		"result", result,
		"client_ip", adminClientIP(r),
	}
	if err != nil {
		args = append(args, "error", err)
		slog.Error("admin action", args...)
		return
	}
	slog.Info("admin action", args...)
}

func adminRequestID() string {
	id, err := randomAdminToken(12)
	if err != nil {
		return fmt.Sprintf("req-%d", time.Now().UnixNano())
	}
	return id
}

func decodeAdminJSON(r *http.Request, target any) error {
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, 4097))
	if err != nil {
		return err
	}
	if len(body) > 4096 {
		return errors.New("request body is too large")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return err
	}
	return nil
}
