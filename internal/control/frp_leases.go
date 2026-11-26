package control

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/private-radminlan/lanmesh/core"
	"github.com/private-radminlan/lanmesh/internal/frpauth"
)

type createFRPLeaseRequest struct {
	NetworkID string         `json:"network_id"`
	DeviceID  string         `json:"device_id"`
	ServerID  string         `json:"server_id"`
	Rules     []frpauth.Rule `json:"rules"`
}

// frpRouteAllowed is deliberately separate from memberRouteAllowed. FRP
// lease routes are member-scoped and must not accidentally inherit a generic
// network/device route allowance.
func frpRouteAllowed(r *http.Request) bool {
	switch {
	case r.URL.Path == "/api/v1/frp/capabilities":
		return r.Method == http.MethodGet
	case r.URL.Path == "/api/v1/frp/port-range":
		return r.Method == http.MethodGet
	case r.URL.Path == "/api/v1/frp/bootstrap":
		return r.Method == http.MethodGet
	case r.URL.Path == "/api/v1/frp/leases":
		return r.Method == http.MethodPost
	case r.URL.Path == "/api/v1/frp/services":
		return r.Method == http.MethodGet
	case r.URL.Path == "/api/v1/frp/services/requests":
		return r.Method == http.MethodPost
	case r.URL.Path == "/api/v1/frp/services/pending":
		return r.Method == http.MethodGet
	case r.URL.Path == "/api/v1/frp/services/requested":
		return r.Method == http.MethodGet
	case strings.HasPrefix(r.URL.Path, "/api/v1/frp/services/"):
		servicePath := strings.TrimPrefix(r.URL.Path, "/api/v1/frp/services/")
		if r.Method != http.MethodPost {
			return false
		}
		for _, action := range []string{"/approve", "/deny", "/revoke"} {
			if strings.HasSuffix(servicePath, action) {
				serviceID := strings.TrimSuffix(servicePath, action)
				return serviceID != "" && !strings.Contains(serviceID, "/")
			}
		}
		return false
	case strings.HasPrefix(r.URL.Path, "/api/v1/frp/leases/"):
		leasePath := strings.TrimPrefix(r.URL.Path, "/api/v1/frp/leases/")
		if r.Method == http.MethodGet && strings.HasSuffix(leasePath, "/status") {
			leaseID := strings.TrimSuffix(leasePath, "/status")
			return leaseID != "" && !strings.Contains(leaseID, "/")
		}
		if r.Method == http.MethodPost && strings.HasSuffix(leasePath, "/renew") {
			leaseID := strings.TrimSuffix(leasePath, "/renew")
			return leaseID != "" && !strings.Contains(leaseID, "/")
		}
		return r.Method == http.MethodDelete && leasePath != "" && !strings.Contains(leasePath, "/")
	default:
		return false
	}
}

func (s *Server) frpLeases(w http.ResponseWriter, r *http.Request) {
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
	var request createFRPLeaseRequest
	if !decodeStrictJSON(w, r, &request) {
		return
	}
	networkID, err := core.NewNetworkID(request.NetworkID)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	deviceID, err := core.NewDeviceID(request.DeviceID)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if networkID.String() != credential.NetworkID || deviceID.String() != credential.DeviceID {
		writeError(w, http.StatusForbidden, "member permission denied")
		return
	}
	rules, err := s.validateFRPTargetGrants(networkID.String(), deviceID.String(), request.Rules)
	if err != nil {
		writeFRPError(w, err)
		return
	}
	response, err := s.FRP.Issue(networkID.String(), deviceID.String(), request.ServerID, rules)
	if err != nil {
		writeFRPError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, response)
}

func (s *Server) frpLease(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodDelete && r.Method != http.MethodPost && r.Method != http.MethodGet {
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
	leasePath := strings.TrimPrefix(r.URL.Path, "/api/v1/frp/leases/")
	if r.Method == http.MethodGet {
		if !strings.HasSuffix(leasePath, "/status") {
			writeError(w, http.StatusNotFound, "lease not found")
			return
		}
		leaseID := strings.TrimSuffix(leasePath, "/status")
		if leaseID == "" || strings.Contains(leaseID, "/") {
			writeError(w, http.StatusNotFound, "lease not found")
			return
		}
		status, err := s.FRP.Status(leaseID, credential.NetworkID, credential.DeviceID)
		if err != nil {
			writeFRPError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, status)
		return
	}
	if r.Method == http.MethodPost {
		if !strings.HasSuffix(leasePath, "/renew") {
			writeError(w, http.StatusNotFound, "lease not found")
			return
		}
		leaseID := strings.TrimSuffix(leasePath, "/renew")
		if leaseID == "" || strings.Contains(leaseID, "/") {
			writeError(w, http.StatusNotFound, "lease not found")
			return
		}
		response, err := s.FRP.Renew(leaseID, credential.NetworkID, credential.DeviceID)
		if err != nil {
			writeFRPError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, response)
		return
	}
	leaseID := leasePath
	if leaseID == "" || strings.Contains(leaseID, "/") {
		writeError(w, http.StatusNotFound, "lease not found")
		return
	}
	if err := s.FRP.Revoke(leaseID, credential.NetworkID, credential.DeviceID); err != nil {
		if errors.Is(err, frpauth.ErrNotFound) {
			writeError(w, http.StatusNotFound, "lease not found")
			return
		}
		writeFRPError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// validateFRPTargetGrants turns the server-side membership directory into an
// exact target grant. A client cannot self-assert a peer identity, virtual IP,
// or public key; mesh_self is bound to the authenticated publisher itself.
func (s *Server) validateFRPTargetGrants(networkID, deviceID string, rules []frpauth.Rule) ([]frpauth.Rule, error) {
	out := append([]frpauth.Rule(nil), rules...)
	needsDirectory := false
	for i := range out {
		out[i].CustomDomains = append([]string(nil), out[i].CustomDomains...)
		if out[i].TargetKind != "" {
			needsDirectory = true
		}
	}
	if !needsDirectory {
		return out, nil
	}
	if s.Store == nil {
		return nil, frpauth.ErrUnauthorized
	}
	devices, err := s.Store.ListDevices(networkID)
	if err != nil {
		return nil, frpauth.ErrUnauthorized
	}
	byID := make(map[string]struct {
		publicKey string
		virtualIP string
	}, len(devices))
	for _, device := range devices {
		byID[device.ID] = struct {
			publicKey string
			virtualIP string
		}{publicKey: device.PublicKey, virtualIP: device.VirtualIP}
	}
	for i := range out {
		rule := &out[i]
		if rule.TargetKind == "" {
			continue
		}
		if rule.TargetKind != "mesh_peer" && rule.TargetKind != "mesh_self" {
			return nil, frpauth.ErrInvalid
		}
		if rule.TargetNetworkID != networkID {
			return nil, frpauth.ErrUnauthorized
		}
		target, ok := byID[rule.TargetDeviceID]
		if !ok || target.publicKey == "" {
			return nil, frpauth.ErrUnauthorized
		}
		if rule.TargetKind == "mesh_self" {
			if rule.TargetDeviceID != deviceID {
				return nil, frpauth.ErrUnauthorized
			}
		} else if rule.TargetDeviceID == deviceID {
			return nil, frpauth.ErrUnauthorized
		}
		if rule.TargetPublicKey == "" {
			rule.TargetPublicKey = target.publicKey
		}
		if !strings.EqualFold(rule.TargetPublicKey, target.publicKey) || rule.TargetHost != target.virtualIP {
			return nil, frpauth.ErrUnauthorized
		}
	}
	return out, nil
}

func decodeStrictJSON(w http.ResponseWriter, r *http.Request, target any) bool {
	defer r.Body.Close()
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256*1024))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return false
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			writeError(w, http.StatusBadRequest, "invalid JSON: trailing data")
		} else {
			writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		}
		return false
	}
	return true
}

func writeFRPError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, frpauth.ErrDisabled):
		writeError(w, http.StatusServiceUnavailable, err.Error())
	case errors.Is(err, frpauth.ErrInvalid):
		writeError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, frpauth.ErrQuota):
		w.Header().Set("Retry-After", "30")
		writeError(w, http.StatusTooManyRequests, err.Error())
	case errors.Is(err, frpauth.ErrConflict):
		writeError(w, http.StatusConflict, err.Error())
	case errors.Is(err, frpauth.ErrNotFound):
		writeError(w, http.StatusNotFound, "lease not found")
	case errors.Is(err, frpauth.ErrRevoked), errors.Is(err, frpauth.ErrExpired):
		writeError(w, http.StatusGone, err.Error())
	case errors.Is(err, frpauth.ErrUnauthorized), errors.Is(err, frpauth.ErrPortDenied), errors.Is(err, frpauth.ErrDomainDenied):
		writeError(w, http.StatusForbidden, err.Error())
	default:
		writeError(w, http.StatusInternalServerError, "managed FRP authorization failed")
	}
}
