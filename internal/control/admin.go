package control

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/private-radminlan/lanmesh/core"
	"github.com/private-radminlan/lanmesh/internal/storage"
)

type adminOverview struct {
	Service       string                 `json:"service"`
	Version       string                 `json:"version"`
	Stage         string                 `json:"stage"`
	UptimeSeconds int64                  `json:"uptime_seconds"`
	Network       storage.NetworkSummary `json:"network"`
	MemberCount   int                    `json:"member_count"`
	OnlineCount   int                    `json:"online_count"`
	BlockedCount  int                    `json:"blocked_count"`
	RelayStatus   string                 `json:"relay_status"`
	RelaySessions int                    `json:"relay_sessions"`
	FRPStatus     string                 `json:"frp_status"`
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
}

type adminConsole struct {
	server *Server
	auth   *adminAuth
}

func (s *Server) AdminHandler(adminToken string, secure bool) http.Handler {
	console := &adminConsole{server: s, auth: newAdminAuth(adminToken, secure)}
	return http.HandlerFunc(console.serveHTTP)
}

func (c *adminConsole) serveHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
	switch {
	case r.URL.Path == "/admin" || r.URL.Path == "/admin/":
		_, csrf, ok := c.auth.authorize(r)
		if !ok {
			writeAdminPage(w, false, "")
			return
		}
		writeAdminPage(w, true, csrf)
	case r.URL.Path == "/admin/login":
		c.auth.login(w, r)
	case r.URL.Path == "/admin/logout":
		c.auth.logout(w, r)
	case strings.HasPrefix(r.URL.Path, "/admin/api/"):
		if _, _, ok := c.auth.authorize(r); !ok {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		c.serveAPI(w, r)
	default:
		writeError(w, http.StatusNotFound, "endpoint not found")
	}
}

func (c *adminConsole) serveAPI(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/admin/api/overview" && r.Method == http.MethodGet:
		c.overview(w)
	case r.URL.Path == "/admin/api/members" && r.Method == http.MethodGet:
		c.members(w)
	case r.URL.Path == "/admin/api/relay-sessions" && r.Method == http.MethodGet:
		c.relaySessions(w)
	case strings.HasPrefix(r.URL.Path, "/admin/api/members/") && r.Method == http.MethodPost:
		c.memberAction(w, r)
	case r.URL.Path == "/admin/api/overview" || r.URL.Path == "/admin/api/members" || r.URL.Path == "/admin/api/relay-sessions" || strings.HasPrefix(r.URL.Path, "/admin/api/members/"):
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	default:
		writeError(w, http.StatusNotFound, "endpoint not found")
	}
}

func (c *adminConsole) overview(w http.ResponseWriter) {
	network, err := c.server.Store.PrivateNetwork()
	if err != nil {
		writeError(w, http.StatusNotFound, "private network is not configured")
		return
	}
	devices, err := c.server.Store.ListDevicesWithBlocked(network.ID, true)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
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
	frpStatus := "disabled"
	if c.server.FRP != nil {
		frpStatus = "enabled"
	}
	uptime := int64(0)
	if !c.server.StartedAt.IsZero() {
		uptime = int64(time.Since(c.server.StartedAt).Seconds())
	}
	writeJSON(w, http.StatusOK, adminOverview{Service: "tmknetworklan-control", Version: "0.2.0", Stage: "encrypted-ipv4-mesh", UptimeSeconds: uptime, Network: network, MemberCount: len(devices), OnlineCount: online, BlockedCount: blocked, RelayStatus: relayStatus, RelaySessions: relayCount, FRPStatus: frpStatus})
}

func (c *adminConsole) members(w http.ResponseWriter) {
	network, err := c.server.Store.PrivateNetwork()
	if err != nil {
		writeError(w, http.StatusNotFound, "private network is not configured")
		return
	}
	devices, err := c.server.Store.ListDevicesWithBlocked(network.ID, true)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	counts := c.relayCounts()
	members := make([]adminMember, 0, len(devices))
	for _, device := range devices {
		members = append(members, adminMember{ID: device.ID, Name: device.Name, VirtualIP: device.VirtualIP, Online: device.Online, Blocked: device.Blocked, Forwarding: device.Forwarding, JoinedAt: device.JoinedAt, LastSeen: device.LastSeen, RelayCount: counts[device.ID]})
	}
	writeJSON(w, http.StatusOK, map[string]any{"network": network, "members": members})
}

func (c *adminConsole) relaySessions(w http.ResponseWriter) {
	if c.server.Relay == nil {
		writeJSON(w, http.StatusOK, map[string]any{"sessions": []any{}})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": c.server.Relay.Snapshot()})
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

func (c *adminConsole) memberAction(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/admin/api/members/")
	parts := strings.Split(path, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		writeError(w, http.StatusNotFound, "endpoint not found")
		return
	}
	deviceID, err := core.NewDeviceID(parts[0])
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	network, err := c.server.Store.PrivateNetwork()
	if err != nil {
		writeError(w, http.StatusNotFound, "private network is not configured")
		return
	}
	switch parts[1] {
	case "rename":
		var req struct {
			Name string `json:"name"`
		}
		if !decodeStrictJSONLimit(w, r, &req, 4096) {
			return
		}
		member, err := c.server.Store.RenameDevice(network.ID, deviceID.String(), req.Name)
		if err != nil {
			writeStorageError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, member)
	case "disconnect":
		if err := c.disconnect(network.ID, deviceID); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "disconnected"})
	case "kick":
		if err := c.server.Store.RevokeMemberCredentials(network.ID, deviceID.String()); err != nil {
			writeStorageError(w, err)
			return
		}
		revokeErr := c.revokeFRP(network.ID, deviceID.String())
		disconnectErr := c.disconnect(network.ID, deviceID)
		if revokeErr != nil || disconnectErr != nil {
			writeError(w, http.StatusInternalServerError, actionPartialFailure("kicked", revokeErr, disconnectErr))
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "kicked"})
	case "ban":
		if _, err := c.server.Store.SetDeviceBlocked(network.ID, deviceID.String(), true); err != nil {
			writeStorageError(w, err)
			return
		}
		revokeErr := c.revokeFRP(network.ID, deviceID.String())
		disconnectErr := c.disconnect(network.ID, deviceID)
		if revokeErr != nil || disconnectErr != nil {
			writeError(w, http.StatusInternalServerError, actionPartialFailure("banned", revokeErr, disconnectErr))
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "banned"})
	case "unban":
		member, err := c.server.Store.SetDeviceBlocked(network.ID, deviceID.String(), false)
		if err != nil {
			writeStorageError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, member)
	default:
		writeError(w, http.StatusNotFound, "endpoint not found")
	}
}

func actionPartialFailure(action string, failures ...error) string {
	message := action + " persisted, but runtime cleanup failed:"
	for _, failure := range failures {
		if failure != nil {
			message += " " + failure.Error()
		}
	}
	return message
}

func (c *adminConsole) disconnect(networkID string, deviceID core.DeviceID) error {
	if c.server.Relay != nil {
		c.server.Relay.DisconnectDevice(deviceID)
	}
	if _, err := c.server.Store.SetForwarding(networkID, deviceID.String(), false); err != nil {
		return err
	}
	return nil
}

func (c *adminConsole) revokeFRP(networkID, deviceID string) error {
	if c.server.FRP == nil {
		return nil
	}
	return c.server.FRP.RevokeDevice(networkID, deviceID)
}

func writeStorageError(w http.ResponseWriter, err error) {
	status := http.StatusBadRequest
	if errors.Is(err, storage.ErrNotFound) {
		status = http.StatusNotFound
	}
	writeError(w, status, err.Error())
}
