package control

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/private-radminlan/lanmesh/core"
	"github.com/private-radminlan/lanmesh/internal/enrollment"
	"github.com/private-radminlan/lanmesh/internal/storage"
)

type memberKey struct{}

func memberIdentity(r *http.Request) (storage.MemberCredential, bool) {
	v, ok := r.Context().Value(memberKey{}).(storage.MemberCredential)
	return v, ok
}
func memberRouteAllowed(r *http.Request, c storage.MemberCredential) bool {
	p := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if r.URL.Path == "/api/v1/session" {
		return r.Method == http.MethodGet
	}
	if r.URL.Path == "/api/v1/relay/sessions" {
		return r.Method == http.MethodPost
	}
	if r.URL.Path == "/api/v1/relay/stream" {
		return r.Method == http.MethodGet
	}
	if len(p) == 5 && p[0] == "api" && p[1] == "v1" && p[2] == "devices" && p[3] == c.DeviceID && p[4] == "heartbeat" {
		return r.Method == http.MethodPost
	}
	if len(p) < 5 || p[0] != "api" || p[1] != "v1" || p[2] != "networks" || p[3] != c.NetworkID || p[4] != "devices" {
		return false
	}
	if len(p) == 5 {
		return r.Method == http.MethodGet || (r.Method == http.MethodDelete && r.URL.Query().Get("id") == c.DeviceID)
	}
	if len(p) != 7 {
		return false
	}
	if r.Method == http.MethodGet && p[6] == "candidates" {
		return true
	}
	return p[5] == c.DeviceID && ((p[6] == "candidates" || p[6] == "diagnostics" || p[6] == "forwarding") && r.Method == http.MethodPost || p[6] == "diagnostics" && r.Method == http.MethodGet)
}

type joinWindow struct {
	Start time.Time
	Count int
}

func (s *Server) allowEnrollment(r *http.Request) bool {
	// Deliberately ignore untrusted forwarded headers. A reverse proxy's clients
	// share the budget; this endpoint is intended for a small private group.
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
	}
	now := time.Now()
	s.joinMu.Lock()
	defer s.joinMu.Unlock()
	if s.joinAttempts == nil {
		s.joinAttempts = make(map[string]joinWindow)
	}
	for key, window := range s.joinAttempts {
		if now.Sub(window.Start) > time.Minute {
			delete(s.joinAttempts, key)
		}
	}
	if len(s.joinAttempts) >= 2048 {
		return false
	}
	w := s.joinAttempts[ip]
	if w.Start.IsZero() {
		w.Start = now
	}
	w.Count++
	s.joinAttempts[ip] = w
	return w.Count <= 12
}
func (s *Server) enroll(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if s.DisableEnrollment {
		writeError(w, 503, "private enrollment is disabled")
		return
	}
	if r.Method != http.MethodPost {
		writeError(w, 405, "method not allowed")
		return
	}
	if !s.allowEnrollment(r) {
		w.Header().Set("Retry-After", "60")
		writeError(w, 429, "too many join attempts")
		return
	}
	s.joinSlotsOnce.Do(func() { s.joinSlots = make(chan struct{}, 2) })
	select {
	case s.joinSlots <- struct{}{}:
		defer func() { <-s.joinSlots }()
	default:
		writeError(w, 429, "too many join attempts")
		return
	}
	var req struct {
		Code   string                     `json:"code"`
		Device core.RegisterDeviceRequest `json:"device"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := req.Device.Validate(); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	if _, err := enrollment.Seal(req.Device.WireGuardPublicKey, nil); err != nil {
		writeError(w, 400, "invalid device key")
		return
	}
	n, member, token, err := s.Store.EnrollPrivate(req.Device, req.Code)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, storage.ErrInvalidPassword) {
			status = http.StatusUnauthorized
		}
		if errors.Is(err, storage.ErrConflict) {
			status = http.StatusConflict
		}
		writeError(w, status, err.Error())
		return
	}
	plain, _ := json.Marshal(struct {
		Network storage.NetworkSummary `json:"network"`
		Member  storage.Device         `json:"member"`
		Token   string                 `json:"token"`
	}{n, member, token})
	sealed, err := enrollment.Seal(req.Device.WireGuardPublicKey, plain)
	if err != nil {
		writeError(w, 400, "invalid device key")
		return
	}
	writeJSON(w, http.StatusCreated, sealed)
}
func (s *Server) memberSession(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	c, ok := memberIdentity(r)
	if !ok {
		writeError(w, 403, "member token required")
		return
	}
	n, err := s.Store.NetworkSummary(c.NetworkID)
	if err != nil {
		writeError(w, 404, "membership not found")
		return
	}
	devices, err := s.Store.ListDevices(c.NetworkID)
	if err != nil {
		writeError(w, 404, "membership not found")
		return
	}
	for _, m := range devices {
		if m.ID == c.DeviceID {
			writeJSON(w, 200, map[string]any{"network": n, "member": m})
			return
		}
	}
	writeError(w, 404, "membership not found")
}
