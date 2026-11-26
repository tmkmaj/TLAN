package clientapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/private-radminlan/lanmesh/core"
)

type AdminClient struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
	Context context.Context
}

type AdminOverview struct {
	Service        string  `json:"service"`
	Version        string  `json:"version"`
	Stage          string  `json:"stage"`
	UptimeSeconds  int64   `json:"uptime_seconds"`
	ControlListen  string  `json:"control_listen"`
	ControlTLS     bool    `json:"control_tls"`
	AdminListen    string  `json:"admin_listen"`
	AdminTLS       bool    `json:"admin_tls"`
	DataDirSummary string  `json:"data_dir_summary"`
	Network        Network `json:"network"`
	MemberCount    int     `json:"member_count"`
	OnlineCount    int     `json:"online_count"`
	BlockedCount   int     `json:"blocked_count"`
	RelayStatus    string  `json:"relay_status"`
	RelaySessions  int     `json:"relay_sessions"`
	FRPStatus      string              `json:"frp_status"`
	FRPLeaseCount  int                 `json:"frp_lease_count"`
	FRPPortStart   int                 `json:"frp_port_start"`
	FRPPortEnd     int                 `json:"frp_port_end"`
	ServerDisplay  ServerDisplayConfig `json:"server_display"`
}

type AdminMember struct {
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
}

type AdminMembers struct {
	Network Network       `json:"network"`
	Members []AdminMember `json:"members"`
}

type AdminRelaySession struct {
	SessionID     string        `json:"session_id"`
	Source        core.DeviceID `json:"source"`
	Target        core.DeviceID `json:"target"`
	CreatedAt     time.Time     `json:"created_at"`
	LastActivity  time.Time     `json:"last_activity"`
	AttachedPeers int           `json:"attached_peers"`
}

func NewAdmin(baseURL, token string) *AdminClient {
	return &AdminClient{BaseURL: strings.TrimRight(strings.TrimSpace(baseURL), "/"), Token: token, HTTP: newControlHTTPClient()}
}

func (c *AdminClient) Overview() (AdminOverview, error) {
	var response AdminOverview
	err := c.request(http.MethodGet, "/api/v1/admin/overview", nil, &response)
	return response, err
}

func (c *AdminClient) Members() (AdminMembers, error) {
	var response AdminMembers
	err := c.request(http.MethodGet, "/api/v1/admin/members", nil, &response)
	return response, err
}

func (c *AdminClient) RelaySessions() ([]AdminRelaySession, error) {
	var response struct {
		Sessions []AdminRelaySession `json:"sessions"`
	}
	if err := c.request(http.MethodGet, "/api/v1/admin/relay-sessions", nil, &response); err != nil {
		return nil, err
	}
	return response.Sessions, nil
}

func (c *AdminClient) RenameMember(deviceID, name string) (AdminMember, error) {
	var response AdminMember
	err := c.request(http.MethodPost, "/api/v1/admin/members/"+url.PathEscape(deviceID)+"/rename", map[string]string{"name": name}, &response)
	return response, err
}

func (c *AdminClient) DisconnectMember(deviceID string) error {
	return c.request(http.MethodPost, "/api/v1/admin/members/"+url.PathEscape(deviceID)+"/disconnect", nil, nil)
}

func (c *AdminClient) KickMember(deviceID string) error {
	return c.request(http.MethodPost, "/api/v1/admin/members/"+url.PathEscape(deviceID)+"/kick", nil, nil)
}

func (c *AdminClient) BanMember(deviceID string) error {
	return c.request(http.MethodPost, "/api/v1/admin/members/"+url.PathEscape(deviceID)+"/ban", nil, nil)
}

func (c *AdminClient) UnbanMember(deviceID string) (AdminMember, error) {
	var response AdminMember
	err := c.request(http.MethodPost, "/api/v1/admin/members/"+url.PathEscape(deviceID)+"/unban", nil, &response)
	return response, err
}

func (c *AdminClient) SetFRPPortRange(start, end int) (PortRange, error) {
	var response PortRange
	err := c.request(http.MethodPost, "/api/v1/admin/frp-port-range", PortRange{Start: start, End: end}, &response)
	return response, err
}

func (c *AdminClient) SetServerDisplay(mode, alias string) (ServerDisplayConfig, error) {
	var response ServerDisplayConfig
	err := c.request(http.MethodPost, "/api/v1/admin/server-display", ServerDisplayConfig{Mode: mode, Alias: alias}, &response)
	return response, err
}

func (c *AdminClient) RenameNetwork(name string) (Network, error) {
	var response Network
	err := c.request(http.MethodPost, "/api/v1/admin/network-name", map[string]string{"name": name}, &response)
	return response, err
}

func (c *AdminClient) request(method, path string, body any, target any) error {
	if c == nil || c.Token == "" {
		return &AdminAPIError{Code: "UNAUTHORIZED", Message: "admin token is required"}
	}
	if c.BaseURL == "" {
		return fmt.Errorf("server URL is required")
	}
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(encoded)
	}
	ctx := c.Context
	if ctx == nil {
		ctx = context.Background()
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("X-Admin-Token", c.Token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	httpClient := c.HTTP
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("control service unavailable: %w", err)
	}
	defer resp.Body.Close()
	var envelope struct {
		OK        bool            `json:"ok"`
		Data      json.RawMessage `json:"data"`
		Error     json.RawMessage `json:"error"`
		RequestID string          `json:"request_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return &AdminAPIError{StatusCode: resp.StatusCode, Code: "INVALID_RESPONSE", Message: "服务器返回了无效的管理响应"}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 || !envelope.OK {
		result := &AdminAPIError{StatusCode: resp.StatusCode, Code: "INTERNAL_ERROR", Message: resp.Status, RequestID: envelope.RequestID}
		if len(envelope.Error) > 0 {
			var detail struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			}
			if err := json.Unmarshal(envelope.Error, &detail); err == nil {
				if detail.Code != "" {
					result.Code = detail.Code
				}
				if detail.Message != "" {
					result.Message = detail.Message
				}
			} else if message := strings.Trim(string(envelope.Error), "\""); message != "" {
				result.Message = message
			}
		}
		if result.Message == "" {
			result.Message = "管理员请求失败"
		}
		return result
	}
	if target == nil || len(envelope.Data) == 0 {
		return nil
	}
	if err := json.Unmarshal(envelope.Data, target); err != nil {
		return fmt.Errorf("decode admin server response: %w", err)
	}
	return nil
}
