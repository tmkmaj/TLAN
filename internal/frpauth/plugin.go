package frpauth

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const (
	PluginPath         = "/api/v1/frp/plugin"
	PluginAPIVersion   = "0.1.0"
	metadataLease      = "tlan_lease"
	metadataCapability = "tlan_capability"
	metadataServer     = "tlan_server"
)

type pluginRequest struct {
	Version string          `json:"version"`
	Op      string          `json:"op"`
	Content json.RawMessage `json:"content"`
}

type pluginResponse struct {
	Reject       bool   `json:"reject"`
	RejectReason string `json:"reject_reason,omitempty"`
	Unchange     bool   `json:"unchange"`
	Content      any    `json:"content,omitempty"`
}

// loginContent mirrors the fields FRP v0.71.1 sends to a server HTTP plugin
// for the Login operation. It intentionally does not import FRP packages.
type loginContent struct {
	Version       string            `json:"version"`
	Hostname      string            `json:"hostname"`
	OS            string            `json:"os"`
	Arch          string            `json:"arch"`
	User          string            `json:"user"`
	PrivilegeKey  string            `json:"privilege_key"`
	Timestamp     int64             `json:"timestamp"`
	RunID         string            `json:"run_id"`
	ClientID      string            `json:"client_id"`
	Metas         map[string]string `json:"metas"`
	ClientSpec    json.RawMessage   `json:"client_spec"`
	PoolCount     int               `json:"pool_count"`
	ClientAddress string            `json:"client_address"`
}

type userInfo struct {
	User  string            `json:"user"`
	Metas map[string]string `json:"metas"`
	RunID string            `json:"run_id"`
}

// newProxyContent mirrors msg.NewProxy plus the UserInfo wrapper that FRP's
// server plugin manager adds before calling the HTTP endpoint.
type newProxyContent struct {
	User userInfo `json:"user"`

	ProxyName          string            `json:"proxy_name"`
	ProxyType          string            `json:"proxy_type"`
	UseEncryption      bool              `json:"use_encryption"`
	UseCompression     bool              `json:"use_compression"`
	BandwidthLimit     string            `json:"bandwidth_limit"`
	BandwidthLimitMode string            `json:"bandwidth_limit_mode"`
	Group              string            `json:"group"`
	GroupKey           string            `json:"group_key"`
	Metas              map[string]string `json:"metas"`
	Annotations        map[string]string `json:"annotations"`

	RemotePort int `json:"remote_port"`

	CustomDomains     []string          `json:"custom_domains"`
	SubDomain         string            `json:"subdomain"`
	Locations         []string          `json:"locations"`
	HTTPUser          string            `json:"http_user"`
	HTTPPwd           string            `json:"http_pwd"`
	HostHeaderRewrite string            `json:"host_header_rewrite"`
	Headers           map[string]string `json:"headers"`
	ResponseHeaders   map[string]string `json:"response_headers"`
	RouteByHTTPUser   string            `json:"route_by_http_user"`

	Sk          string   `json:"sk"`
	AllowUsers  []string `json:"allow_users"`
	Multiplexer string   `json:"multiplexer"`
}

type pingContent struct {
	User         userInfo `json:"user"`
	PrivilegeKey string   `json:"privilege_key"`
	Timestamp    int64    `json:"timestamp"`
}

type newUserConnContent struct {
	User       userInfo `json:"user"`
	ProxyName  string   `json:"proxy_name"`
	ProxyType  string   `json:"proxy_type"`
	RemoteAddr string   `json:"remote_addr"`
}

// NewPluginHandler returns the fail-closed HTTP adapter used by FRPS's
// httpPlugins configuration. It should be bound to a loopback listener only.
func NewPluginHandler(store *Store) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != PluginPath {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			writePluginReject(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if store == nil {
			writePluginReject(w, http.StatusOK, "FRP_AUTH_REJECTED: managed authorization is unavailable")
			return
		}
		if r.URL.Query().Get("version") != PluginAPIVersion {
			writePluginReject(w, http.StatusOK, "FRP_AUTH_REJECTED: unsupported plugin protocol version")
			return
		}
		op := r.URL.Query().Get("op")
		if op == "" {
			writePluginReject(w, http.StatusOK, "FRP_AUTH_REJECTED: plugin operation is missing")
			return
		}
		var request pluginRequest
		if err := decodePluginJSON(w, r, &request); err != nil {
			writePluginReject(w, http.StatusOK, "FRP_AUTH_REJECTED: malformed plugin request")
			return
		}
		if request.Version != PluginAPIVersion || request.Op != op {
			writePluginReject(w, http.StatusOK, "FRP_AUTH_REJECTED: plugin protocol mismatch")
			return
		}
		switch op {
		case "Login":
			var content loginContent
			if err := decodePluginContent(request.Content, &content); err != nil {
				writePluginReject(w, http.StatusOK, "FRP_AUTH_REJECTED: malformed Login content")
				return
			}
			leaseID, capability, serverID, err := metadataCredentials(content.Metas)
			if err != nil {
				writePluginReject(w, http.StatusOK, pluginReason(err))
				return
			}
			if content.Version != store.coreVersion {
				writePluginReject(w, http.StatusOK, "FRP_AUTH_REJECTED: unsupported FRP core version")
				return
			}
			err = store.AuthorizeLogin(LoginRequest{
				LeaseID:    leaseID,
				Capability: capability,
				ServerID:   serverID,
				User:       content.User,
				RunID:      content.RunID,
			})
			if err != nil {
				writePluginReject(w, http.StatusOK, pluginReason(err))
				return
			}
		case "Ping":
			var content pingContent
			if err := decodePluginContent(request.Content, &content); err != nil {
				writePluginReject(w, http.StatusOK, "FRP_AUTH_REJECTED: malformed Ping content")
				return
			}
			leaseID, capability, serverID, err := metadataCredentials(content.User.Metas)
			if err != nil {
				writePluginReject(w, http.StatusOK, pluginReason(err))
				return
			}
			if err := store.AuthorizePing(SessionRequest{
				LeaseID: leaseID, Capability: capability, ServerID: serverID,
				User: content.User.User, RunID: content.User.RunID,
			}); err != nil {
				writePluginReject(w, http.StatusOK, pluginReason(err))
				return
			}
		case "NewUserConn":
			var content newUserConnContent
			if err := decodePluginContent(request.Content, &content); err != nil {
				writePluginReject(w, http.StatusOK, "FRP_AUTH_REJECTED: malformed NewUserConn content")
				return
			}
			leaseID, capability, serverID, err := metadataCredentials(content.User.Metas)
			if err != nil {
				writePluginReject(w, http.StatusOK, pluginReason(err))
				return
			}
			if err := store.AuthorizeUserConn(UserConnRequest{
				LeaseID: leaseID, Capability: capability, ServerID: serverID,
				User: content.User.User, RunID: content.User.RunID,
				ProxyName: content.ProxyName, ProxyType: content.ProxyType, RemoteAddr: content.RemoteAddr,
			}); err != nil {
				writePluginReject(w, http.StatusOK, pluginReason(err))
				return
			}
		case "NewProxy":
			var content newProxyContent
			if err := decodePluginContent(request.Content, &content); err != nil {
				writePluginReject(w, http.StatusOK, "FRP_AUTH_REJECTED: malformed NewProxy content")
				return
			}
			leaseID, capability, serverID, err := metadataCredentials(content.User.Metas)
			if err != nil {
				writePluginReject(w, http.StatusOK, pluginReason(err))
				return
			}
			err = store.AuthorizeNewProxy(NewProxyRequest{
				LeaseID:            leaseID,
				Capability:         capability,
				ServerID:           serverID,
				User:               content.User.User,
				RunID:              content.User.RunID,
				ProxyName:          content.ProxyName,
				ProxyType:          content.ProxyType,
				RemotePort:         content.RemotePort,
				CustomDomains:      content.CustomDomains,
				SubDomain:          content.SubDomain,
				Locations:          content.Locations,
				HTTPUser:           content.HTTPUser,
				HTTPPwd:            content.HTTPPwd,
				HostHeaderRewrite:  content.HostHeaderRewrite,
				Headers:            content.Headers,
				ResponseHeaders:    content.ResponseHeaders,
				RouteByHTTPUser:    content.RouteByHTTPUser,
				Group:              content.Group,
				GroupKey:           content.GroupKey,
				Sk:                 content.Sk,
				AllowUsers:         content.AllowUsers,
				Multiplexer:        content.Multiplexer,
				UseEncryption:      content.UseEncryption,
				UseCompression:     content.UseCompression,
				BandwidthLimit:     content.BandwidthLimit,
				BandwidthLimitMode: content.BandwidthLimitMode,
				Metas:              content.Metas,
				Annotations:        content.Annotations,
			})
			if err != nil {
				writePluginReject(w, http.StatusOK, pluginReason(err))
				return
			}
		default:
			writePluginReject(w, http.StatusOK, "FRP_AUTH_REJECTED: unsupported plugin operation")
			return
		}
		writePluginJSON(w, http.StatusOK, pluginResponse{Reject: false, Unchange: true})
	})
}

func decodePluginJSON(w http.ResponseWriter, r *http.Request, target any) error {
	defer r.Body.Close()
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256*1024))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing JSON data")
		}
		return err
	}
	return nil
}

func decodePluginContent(raw json.RawMessage, target any) error {
	if len(bytes.TrimSpace(raw)) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return errors.New("content is required")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing content JSON data")
		}
		return err
	}
	return nil
}

func metadataCredentials(metas map[string]string) (leaseID, capability, serverID string, err error) {
	if len(metas) == 0 {
		return "", "", "", ErrUnauthorized
	}
	for key := range metas {
		if !strings.HasPrefix(key, "tlan_") {
			continue
		}
		switch key {
		case metadataLease, metadataCapability, metadataServer:
		default:
			return "", "", "", fmt.Errorf("%w: unsupported tlan metadata", ErrUnauthorized)
		}
	}
	leaseID = strings.TrimSpace(metas[metadataLease])
	capability = strings.TrimSpace(metas[metadataCapability])
	serverID = strings.TrimSpace(metas[metadataServer])
	if leaseID == "" || capability == "" || serverID == "" {
		return "", "", "", ErrUnauthorized
	}
	return leaseID, capability, serverID, nil
}

func pluginReason(err error) string {
	switch {
	case errors.Is(err, ErrExpired):
		return "FRP_LEASE_EXPIRED: managed lease is expired"
	case errors.Is(err, ErrRevoked):
		return "FRP_LEASE_REVOKED: managed lease is revoked"
	case errors.Is(err, ErrPortDenied):
		return "FRP_REMOTE_PORT_DENIED: remote port is not granted"
	case errors.Is(err, ErrDomainDenied):
		return "FRP_DOMAIN_DENIED: custom domain is not granted"
	default:
		return "FRP_AUTH_REJECTED: managed lease validation failed"
	}
}

func writePluginReject(w http.ResponseWriter, status int, reason string) {
	writePluginJSON(w, status, pluginResponse{Reject: true, RejectReason: reason, Unchange: true})
}

func writePluginJSON(w http.ResponseWriter, status int, value pluginResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
