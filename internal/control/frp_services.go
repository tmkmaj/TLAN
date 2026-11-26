package control

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/private-radminlan/lanmesh/core"
	"github.com/private-radminlan/lanmesh/internal/frpauth"
	"github.com/private-radminlan/lanmesh/internal/storage"
)

type frpServiceRequest struct {
	NetworkID   string `json:"network_id"`
	DeviceID    string `json:"device_id"`
	ServiceID   string `json:"service_id,omitempty"`
	Protocol    string `json:"protocol"`
	Port        int    `json:"port"`
	Description string `json:"description,omitempty"`
	TTLSeconds  int    `json:"ttl_seconds,omitempty"`
}

type frpServiceRequestCreate struct {
	TargetDeviceID string `json:"target_device_id"`
	ServiceID      string `json:"service_id,omitempty"`
	Protocol       string `json:"protocol"`
	Port           int    `json:"port"`
	Description    string `json:"description,omitempty"`
	TTLSeconds     int    `json:"ttl_seconds,omitempty"`
}

func (s *Server) frpCapabilities(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.FRP == nil {
		writeError(w, http.StatusServiceUnavailable, "managed FRP is disabled")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, s.FRP.Capabilities())
}

func (s *Server) effectiveFRPPortRange() storage.PortRange {
	if s.Store != nil && s.Store.HasFRPPortRange() {
		return s.Store.FRPPortRange()
	}
	if s.FRP != nil {
		if ports := s.FRP.AllowedPorts(); len(ports) > 0 {
			return storage.PortRange{Start: ports[0].Start, End: ports[0].End}
		}
	}
	if s.Store != nil {
		return s.Store.FRPPortRange()
	}
	return storage.DefaultFRPPortRange
}

type FRPBootstrapConfig struct {
	Enabled       bool   `json:"enabled"`
	Mode          string `json:"mode,omitempty"`
	Host          string `json:"host,omitempty"`
	Port          int    `json:"port,omitempty"`
	Transport     string `json:"transport,omitempty"`
	TLSServerName string `json:"tls_server_name,omitempty"`
	ServerID      string `json:"server_id,omitempty"`
	Token         string `json:"token,omitempty"`
	CAPEM         string `json:"ca_pem,omitempty"`
}

func (s *Server) frpBootstrap(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if s.FRPBootstrap == nil {
		writeJSON(w, http.StatusOK, FRPBootstrapConfig{Enabled: false})
		return
	}
	cfg, err := s.FRPBootstrap()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to load FRP bootstrap config")
		return
	}
	writeJSON(w, http.StatusOK, cfg)
}

func (s *Server) frpPortRange(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, s.effectiveFRPPortRange())
}
func (s *Server) frpServices(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if s.FRP == nil {
		writeError(w, http.StatusServiceUnavailable, "managed FRP is disabled")
		return
	}
	switch r.Method {
	case http.MethodGet:
		networkID := strings.TrimSpace(r.URL.Query().Get("network_id"))
		deviceID := strings.TrimSpace(r.URL.Query().Get("device_id"))
		if _, err := core.NewNetworkID(networkID); err != nil {
			writeError(w, http.StatusBadRequest, "network_id is invalid")
			return
		}
		if _, err := core.NewDeviceID(deviceID); err != nil {
			writeError(w, http.StatusBadRequest, "device_id is invalid")
			return
		}
		if credential, member := memberIdentity(r); member && (credential.NetworkID != networkID || credential.DeviceID != deviceID) {
			writeError(w, http.StatusForbidden, "member permission denied")
			return
		}
		services, err := s.FRP.ListServices(networkID, deviceID)
		if err != nil {
			writeFRPError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"services": services})
	case http.MethodPost:
		var request frpServiceRequest
		if !decodeStrictJSON(w, r, &request) {
			return
		}
		if _, err := core.NewNetworkID(request.NetworkID); err != nil {
			writeError(w, http.StatusBadRequest, "network_id is invalid")
			return
		}
		if _, err := core.NewDeviceID(request.DeviceID); err != nil {
			writeError(w, http.StatusBadRequest, "device_id is invalid")
			return
		}
		devices, err := s.Store.ListDevices(request.NetworkID)
		if err != nil {
			writeError(w, http.StatusNotFound, "network or device not found")
			return
		}
		found := false
		for _, device := range devices {
			if device.ID == request.DeviceID {
				found = true
				break
			}
		}
		if !found {
			writeError(w, http.StatusNotFound, "network or device not found")
			return
		}
		if request.TTLSeconds < 0 || request.TTLSeconds > 30*24*60*60 {
			writeError(w, http.StatusBadRequest, "ttl_seconds is invalid")
			return
		}
		ttl := time.Duration(request.TTLSeconds) * time.Second
		service, err := s.FRP.IssueService(request.NetworkID, request.DeviceID, request.ServiceID, request.Protocol, request.Port, request.Description, ttl)
		if err != nil {
			writeFRPError(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, service)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) frpServiceRequests(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.FRP == nil {
		writeError(w, http.StatusServiceUnavailable, "managed FRP is disabled")
		return
	}
	credential, ok := memberIdentity(r)
	if !ok {
		writeError(w, http.StatusForbidden, "member token required")
		return
	}
	var request frpServiceRequestCreate
	if !decodeStrictJSON(w, r, &request) {
		return
	}
	if _, err := core.NewDeviceID(request.TargetDeviceID); err != nil {
		writeError(w, http.StatusBadRequest, "target_device_id is invalid")
		return
	}
	if request.TargetDeviceID == credential.DeviceID {
		writeError(w, http.StatusBadRequest, "target_device_id must differ from the requester")
		return
	}
	devices, err := s.Store.ListDevices(credential.NetworkID)
	if err != nil {
		writeError(w, http.StatusNotFound, "network or target device not found")
		return
	}
	found := false
	for _, device := range devices {
		if device.ID == request.TargetDeviceID {
			found = true
			break
		}
	}
	if !found {
		writeError(w, http.StatusNotFound, "network or target device not found")
		return
	}
	if request.TTLSeconds < 0 || request.TTLSeconds > 30*24*60*60 {
		writeError(w, http.StatusBadRequest, "ttl_seconds is invalid")
		return
	}
	ttl := time.Duration(request.TTLSeconds) * time.Second
	service, err := s.FRP.RequestService(
		credential.NetworkID, request.TargetDeviceID, credential.DeviceID, request.ServiceID,
		request.Protocol, request.Port, request.Description, ttl,
	)
	if err != nil {
		writeFRPError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, service)
}

func (s *Server) frpPendingServices(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.FRP == nil {
		writeError(w, http.StatusServiceUnavailable, "managed FRP is disabled")
		return
	}
	credential, ok := memberIdentity(r)
	if !ok {
		writeError(w, http.StatusForbidden, "member token required")
		return
	}
	services, err := s.FRP.ListPendingServices(credential.NetworkID, credential.DeviceID)
	if err != nil {
		writeFRPError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"services": services})
}

func (s *Server) frpRequestedServices(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.FRP == nil {
		writeError(w, http.StatusServiceUnavailable, "managed FRP is disabled")
		return
	}
	credential, ok := memberIdentity(r)
	if !ok {
		writeError(w, http.StatusForbidden, "member token required")
		return
	}
	services, err := s.FRP.ListRequestedServices(credential.NetworkID, credential.DeviceID)
	if err != nil {
		writeFRPError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"services": services})
}

func (s *Server) frpServiceDecision(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/frp/services/")
	action := ""
	serviceID := ""
	switch {
	case strings.HasSuffix(path, "/approve"):
		action = "approve"
		serviceID = strings.TrimSuffix(path, "/approve")
	case strings.HasSuffix(path, "/deny"):
		action = "deny"
		serviceID = strings.TrimSuffix(path, "/deny")
	case strings.HasSuffix(path, "/revoke"):
		action = "revoke"
		serviceID = strings.TrimSuffix(path, "/revoke")
	default:
		writeError(w, http.StatusNotFound, "service not found")
		return
	}
	if serviceID == "" || strings.Contains(serviceID, "/") {
		writeError(w, http.StatusNotFound, "service not found")
		return
	}
	credential, ok := memberIdentity(r)
	if !ok {
		writeError(w, http.StatusForbidden, "member token required")
		return
	}
	var (
		service frpauth.ServiceResponse
		err     error
	)
	switch action {
	case "approve":
		service, err = s.FRP.ApproveService(serviceID, credential.NetworkID, credential.DeviceID)
	case "deny":
		service, err = s.FRP.DenyService(serviceID, credential.NetworkID, credential.DeviceID)
	case "revoke":
		err = s.FRP.RevokeServiceByTarget(serviceID, credential.NetworkID, credential.DeviceID)
	}
	if err != nil {
		writeFRPError(w, err)
		return
	}
	if action == "revoke" {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	writeJSON(w, http.StatusOK, service)
}

func (s *Server) frpService(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if s.FRP == nil {
		writeError(w, http.StatusServiceUnavailable, "managed FRP is disabled")
		return
	}
	if strings.HasSuffix(r.URL.Path, "/approve") || strings.HasSuffix(r.URL.Path, "/deny") || strings.HasSuffix(r.URL.Path, "/revoke") {
		s.frpServiceDecision(w, r)
		return
	}
	if r.Method != http.MethodDelete {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	serviceID := strings.TrimPrefix(r.URL.Path, "/api/v1/frp/services/")
	if serviceID == "" || strings.Contains(serviceID, "/") {
		writeError(w, http.StatusNotFound, "service not found")
		return
	}
	if err := s.FRP.RevokeService(serviceID); err != nil {
		if errors.Is(err, frpauth.ErrNotFound) {
			writeError(w, http.StatusNotFound, "service not found")
			return
		}
		writeFRPError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
