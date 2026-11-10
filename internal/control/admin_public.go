package control

import (
	"net/http"
	"strings"
	"time"
)

func (s *Server) allowPublicAdminAttempt(ip string) bool {
	now := time.Now()
	s.publicAdminMu.Lock()
	defer s.publicAdminMu.Unlock()
	if s.publicAdminAttempts == nil {
		s.publicAdminAttempts = make(map[string]adminWindow)
	}
	for key, window := range s.publicAdminAttempts {
		if now.Sub(window.start) >= adminLoginWindow {
			delete(s.publicAdminAttempts, key)
		}
	}
	window := s.publicAdminAttempts[ip]
	if window.start.IsZero() || now.Sub(window.start) >= adminLoginWindow {
		window = adminWindow{start: now}
	}
	if window.count >= adminLoginLimit {
		s.publicAdminAttempts[ip] = window
		return false
	}
	s.publicAdminAttempts[ip] = window
	return true
}

func (s *Server) notePublicAdminFailure(ip string) {
	now := time.Now()
	s.publicAdminMu.Lock()
	defer s.publicAdminMu.Unlock()
	window := s.publicAdminAttempts[ip]
	if window.start.IsZero() || now.Sub(window.start) >= adminLoginWindow {
		window = adminWindow{start: now}
	}
	window.count++
	s.publicAdminAttempts[ip] = window
}

func (s *Server) resetPublicAdminFailures(ip string) {
	s.publicAdminMu.Lock()
	delete(s.publicAdminAttempts, ip)
	s.publicAdminMu.Unlock()
}

func (s *Server) adminAPI(w http.ResponseWriter, r *http.Request) {
	if !adminIdentity(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	requestID := adminRequestID()
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Request-ID", requestID)
	console := &adminConsole{server: s}
	switch {
	case r.URL.Path == "/api/v1/admin/overview" && r.Method == http.MethodGet:
		console.overview(w, requestID)
	case r.URL.Path == "/api/v1/admin/members" && r.Method == http.MethodGet:
		console.members(w, requestID)
	case r.URL.Path == "/api/v1/admin/relay-sessions" && r.Method == http.MethodGet:
		console.relaySessions(w, requestID)
	case strings.HasPrefix(r.URL.Path, "/api/v1/admin/members/") && r.Method == http.MethodPost:
		console.memberActionForPrefix(w, r, requestID, "/api/v1/admin/members/")
	case r.URL.Path == "/api/v1/admin/overview" || r.URL.Path == "/api/v1/admin/members" || r.URL.Path == "/api/v1/admin/relay-sessions" || strings.HasPrefix(r.URL.Path, "/api/v1/admin/members/"):
		writeAdminFailure(w, http.StatusMethodNotAllowed, requestID, "METHOD_NOT_ALLOWED", "请求方法不允许")
	default:
		writeAdminFailure(w, http.StatusNotFound, requestID, "NOT_FOUND", "接口不存在")
	}
}
