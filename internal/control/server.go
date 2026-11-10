package control

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/private-radminlan/lanmesh/core"
	"github.com/private-radminlan/lanmesh/internal/diagreport"
	"github.com/private-radminlan/lanmesh/internal/frpauth"
	"github.com/private-radminlan/lanmesh/internal/network"
	"github.com/private-radminlan/lanmesh/internal/storage"
)

type Server struct {
	DisableEnrollment bool
	joinMu            sync.Mutex
	joinAttempts      map[string]joinWindow
	joinSlots         chan struct{}
	joinSlotsOnce     sync.Once
	Store             *storage.Store
	AdminToken        string
	StartedAt         time.Time
	Relay             *network.RelayBroker
	FRP               *frpauth.Store
	relayMu           sync.Mutex
	relaySlotsOnce    sync.Once
	relaySlots        chan struct{}
	relayPairs        map[string]network.RelayTicket
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", s.health)
	mux.HandleFunc("/api/v1/enroll", s.enroll)
	mux.HandleFunc("/api/v1/session", s.memberSession)
	mux.HandleFunc("/api/v1/status", s.status)
	mux.HandleFunc("/api/v1/networks", s.networks)
	mux.HandleFunc("/api/v1/networks/", s.network)
	mux.HandleFunc("/api/v1/devices/register", s.registerDevice)
	mux.HandleFunc("/api/v1/devices/", s.device)
	mux.HandleFunc("/api/v1/frp/leases", s.frpLeases)
	mux.HandleFunc("/api/v1/frp/leases/", s.frpLease)
	mux.HandleFunc("/api/v1/frp/capabilities", s.frpCapabilities)
	mux.HandleFunc("/api/v1/frp/services", s.frpServices)
	mux.HandleFunc("/api/v1/frp/services/requests", s.frpServiceRequests)
	mux.HandleFunc("/api/v1/frp/services/pending", s.frpPendingServices)
	mux.HandleFunc("/api/v1/frp/services/requested", s.frpRequestedServices)
	mux.HandleFunc("/api/v1/frp/services/", s.frpService)
	mux.HandleFunc("/api/v1/relay/sessions", s.relaySessions)
	mux.HandleFunc("/api/v1/relay/stream", s.relayStream)
	return logging(s.auth(mux))
}
func (s *Server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" || r.URL.Path == "/api/v1/enroll" {
			next.ServeHTTP(w, r)
			return
		}
		token := r.Header.Get("X-Admin-Token")
		if token == "" {
			token = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		}
		if s.AdminToken != "" && token == s.AdminToken {
			next.ServeHTTP(w, r)
			return
		}
		if credential, ok := s.Store.AuthenticateMember(token); ok && (frpRouteAllowed(r) || memberRouteAllowed(r, credential)) {
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), memberKey{}, credential)))
			return
		}
		writeError(w, http.StatusUnauthorized, "unauthorized")
	})
}
func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
func (s *Server) status(w http.ResponseWriter, _ *http.Request) {
	relay := "disabled"
	if s.Relay != nil {
		relay = "enabled"
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"service":    "tmknetworklan-control",
		"version":    "0.2.0",
		"stage":      "encrypted-ipv4-mesh",
		"networks":   len(s.Store.ListNetworks()),
		"data_plane": "wireguard-go + Wintun/Linux TUN; IPv4 encapsulation",
		"relay":      relay,
		"dark_hours": "diagnostics-only",
	})
}

func (s *Server) relaySessions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.Relay == nil {
		writeError(w, http.StatusServiceUnavailable, "relay listener is disabled")
		return
	}
	var req struct {
		NetworkID      string `json:"network_id"`
		SourceDeviceID string `json:"source_device_id"`
		TargetDeviceID string `json:"target_device_id"`
		TTLSeconds     int    `json:"ttl_seconds,omitempty"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	networkID, err := core.NewNetworkID(req.NetworkID)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	source, err := core.NewDeviceID(req.SourceDeviceID)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	target, err := core.NewDeviceID(req.TargetDeviceID)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if credential, ok := memberIdentity(r); ok && (credential.NetworkID != networkID.String() || credential.DeviceID != source.String()) {
		writeError(w, http.StatusForbidden, "member permission denied")
		return
	}
	if !s.Store.RegisteredDeviceExists(source) || !s.Store.RegisteredDeviceExists(target) ||
		!s.Store.NetworkMembershipExists(networkID, source) || !s.Store.NetworkMembershipExists(networkID, target) {
		writeError(w, http.StatusNotFound, "both relay devices must be registered members of the network")
		return
	}
	if req.TTLSeconds < 0 || req.TTLSeconds > 3600 {
		writeError(w, http.StatusBadRequest, "ttl_seconds must be 0-3600")
		return
	}
	ttl := 5 * time.Minute
	if req.TTLSeconds > 0 {
		ttl = time.Duration(req.TTLSeconds) * time.Second
	}
	s.relayMu.Lock()
	defer s.relayMu.Unlock()
	if s.relayPairs == nil {
		s.relayPairs = make(map[string]network.RelayTicket)
	}
	left, right := source.String(), target.String()
	if left > right {
		left, right = right, left
	}
	pairKey := networkID.String() + "/" + left + "/" + right
	for key, ticket := range s.relayPairs {
		if !s.Relay.SessionActive(ticket) {
			delete(s.relayPairs, key)
		}
	}
	if ticket, ok := s.relayPairs[pairKey]; ok {
		writeJSON(w, http.StatusCreated, ticket)
		return
	}
	ticket, err := s.Relay.CreateSession(source, target, ttl)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, network.ErrRelayCapacity) {
			status = http.StatusServiceUnavailable
		}
		writeError(w, status, err.Error())
		return
	}
	s.relayPairs[pairKey] = ticket
	writeJSON(w, http.StatusCreated, ticket)
}

func (s *Server) networks(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{"networks": s.Store.ListNetworks()})
	case http.MethodPost:
		var req struct {
			Name     string `json:"name"`
			Password string `json:"password"`
			CIDR     string `json:"cidr"`
		}
		if !decodeJSON(w, r, &req) {
			return
		}
		network, err := s.Store.CreateNetwork(req.Name, req.Password, req.CIDR)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, network)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) network(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/networks/"), "/"), "/")
	if len(parts) != 2 && len(parts) != 4 {
		writeError(w, http.StatusNotFound, "endpoint not found")
		return
	}
	id := parts[0]
	if len(parts) == 4 && parts[1] == "devices" {
		s.networkDevice(w, r, id, parts[2], parts[3])
		return
	}
	if len(parts) != 2 {
		writeError(w, http.StatusNotFound, "endpoint not found")
		return
	}
	switch parts[1] {
	case "join":
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		var req struct {
			Name      string `json:"name"`
			PublicKey string `json:"public_key"`
			Password  string `json:"password"`
			DeviceID  string `json:"device_id,omitempty"`
		}
		if !decodeJSON(w, r, &req) {
			return
		}
		var device storage.Device
		var err error
		if strings.TrimSpace(req.DeviceID) != "" {
			registeredID, idErr := core.NewDeviceID(req.DeviceID)
			if idErr != nil {
				writeError(w, http.StatusBadRequest, idErr.Error())
				return
			}
			device, err = s.Store.JoinRegisteredNetwork(core.NetworkID(id), req.Name, req.Password, registeredID)
		} else {
			device, err = s.Store.JoinNetwork(id, req.Name, req.PublicKey, req.Password)
		}
		if err != nil {
			status := http.StatusBadRequest
			if errors.Is(err, storage.ErrNotFound) {
				status = http.StatusNotFound
			}
			if errors.Is(err, storage.ErrConflict) {
				status = http.StatusConflict
			}
			writeError(w, status, err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, device)
	case "devices":
		s.devices(w, r, id)
	default:
		writeError(w, http.StatusNotFound, "endpoint not found")
	}
}

func (s *Server) registerDevice(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req core.RegisterDeviceRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	device, created, err := s.Store.RegisterDevice(req)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, storage.ErrConflict) {
			status = http.StatusConflict
		}
		writeError(w, status, err.Error())
		return
	}
	if created {
		writeJSON(w, http.StatusCreated, device)
	} else {
		writeJSON(w, http.StatusOK, device)
	}
}

func (s *Server) device(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/devices/"), "/"), "/")
	if len(parts) != 2 || parts[1] != "heartbeat" {
		writeError(w, http.StatusNotFound, "endpoint not found")
		return
	}
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	id, err := core.NewDeviceID(parts[0])
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	device, err := s.Store.Heartbeat(id)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, storage.ErrNotFound) {
			status = http.StatusNotFound
		}
		writeError(w, status, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, device)
}

func (s *Server) networkDevice(w http.ResponseWriter, r *http.Request, networkID, deviceID, action string) {
	nid, err := core.NewNetworkID(networkID)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	did, err := core.NewDeviceID(deviceID)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	switch action {
	case "forwarding":
		if r.Method != http.MethodPost {
			writeError(w, 405, "method not allowed")
			return
		}
		var req struct {
			Enabled bool `json:"enabled"`
		}
		if !decodeJSON(w, r, &req) {
			return
		}
		member, err := s.Store.SetForwarding(networkID, deviceID, req.Enabled)
		if err != nil {
			writeError(w, 404, err.Error())
			return
		}
		writeJSON(w, 200, member)
	case "candidates":
		switch r.Method {
		case http.MethodGet:
			record, err := s.Store.GetCandidates(nid, did)
			if err != nil {
				status := http.StatusBadRequest
				if errors.Is(err, storage.ErrNotFound) {
					status = http.StatusNotFound
				}
				writeError(w, status, err.Error())
				return
			}
			writeJSON(w, http.StatusOK, record)
		case http.MethodPost:
			var req struct {
				Candidates []core.Candidate `json:"candidates"`
			}
			if !decodeJSON(w, r, &req) {
				return
			}
			record, err := s.Store.SetCandidates(nid, did, req.Candidates)
			if err != nil {
				status := http.StatusBadRequest
				if errors.Is(err, storage.ErrNotFound) {
					status = http.StatusNotFound
				}
				writeError(w, status, err.Error())
				return
			}
			writeJSON(w, http.StatusOK, record)
		default:
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
	case "diagnostics":
		w.Header().Set("Cache-Control", "no-store")
		switch r.Method {
		case http.MethodGet:
			reports, err := s.Store.ListDiagnostics(nid, did)
			if err != nil {
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"reports": reports})
		case http.MethodPost:
			var req struct {
				Checks    []storage.DiagnosticCheck `json:"checks"`
				FRPReport json.RawMessage           `json:"frp_report,omitempty"`
			}
			if !decodeStrictJSONLimit(w, r, &req, diagreport.MaxRequestBytes) {
				return
			}
			report, err := s.Store.SaveDiagnostics(storage.DiagnosticReport{DeviceID: did, NetworkID: nid, Checks: req.Checks, FRPReport: req.FRPReport})
			if err != nil {
				status := http.StatusBadRequest
				if errors.Is(err, storage.ErrNotFound) {
					status = http.StatusNotFound
				}
				writeError(w, status, err.Error())
				return
			}
			writeJSON(w, http.StatusCreated, report)
		default:
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
	default:
		writeError(w, http.StatusNotFound, "endpoint not found")
	}
}

func (s *Server) devices(w http.ResponseWriter, r *http.Request, id string) {
	switch r.Method {
	case http.MethodGet:
		devices, err := s.Store.ListDevices(id)
		if err != nil {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"devices": devices})
	case http.MethodDelete:
		deviceID := r.URL.Query().Get("id")
		if deviceID == "" {
			writeError(w, http.StatusBadRequest, "id is required")
			return
		}
		if s.FRP != nil {
			if err := s.FRP.RevokeDevice(id, deviceID); err != nil {
				writeFRPError(w, err)
				return
			}
		}
		if err := s.Store.RemoveDevice(id, deviceID); err != nil {
			status := http.StatusBadRequest
			if errors.Is(err, storage.ErrNotFound) {
				status = http.StatusNotFound
			}
			writeError(w, status, err.Error())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}
func decodeStrictJSONLimit(w http.ResponseWriter, r *http.Request, target any, limit int) bool {
	defer r.Body.Close()
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, int64(limit)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		writeDecodeError(w, err)
		return false
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			err = errors.New("trailing JSON value")
		}
		writeDecodeError(w, err)
		return false
	}
	return true
}

func writeDecodeError(w http.ResponseWriter, err error) {
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		writeError(w, http.StatusRequestEntityTooLarge, "diagnostic request is too large")
		return
	}
	writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
}

func decodeJSON(w http.ResponseWriter, r *http.Request, target any) bool {
	defer r.Body.Close()
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	if err := decoder.Decode(target); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return false
	}
	return true
}
func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
func logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
	})
}
