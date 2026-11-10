package control

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	adminSessionCookie = "tlan_admin"
	adminCSRFHeader    = "X-CSRF-Token"
	adminSessionTTL    = 30 * time.Minute
	adminSessionMax    = 8
	adminLoginWindow   = 15 * time.Minute
	adminLoginLimit    = 5
)

type adminSession struct {
	csrf      string
	expiresAt time.Time
	lastSeen  time.Time
}

type adminWindow struct {
	start time.Time
	count int
}

type adminAuth struct {
	tokenHash [32]byte
	secure    bool
	mu        sync.Mutex
	sessions  map[string]adminSession
	attempts  map[string]adminWindow
	now       func() time.Time
}

func newAdminAuth(token string, secure bool) *adminAuth {
	return &adminAuth{
		tokenHash: sha256.Sum256([]byte(token)),
		secure:    secure,
		sessions:  make(map[string]adminSession),
		attempts:  make(map[string]adminWindow),
		now:       time.Now,
	}
}

func randomAdminToken(bytes int) (string, error) {
	buf := make([]byte, bytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func adminClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && host != "" {
		return host
	}
	return strings.TrimSpace(r.RemoteAddr)
}

func (a *adminAuth) allowLogin(r *http.Request) bool {
	ip := adminClientIP(r)
	now := a.now()
	a.mu.Lock()
	defer a.mu.Unlock()
	for key, window := range a.attempts {
		if now.Sub(window.start) >= adminLoginWindow {
			delete(a.attempts, key)
		}
	}
	window := a.attempts[ip]
	if window.start.IsZero() || now.Sub(window.start) >= adminLoginWindow {
		window = adminWindow{start: now}
	}
	if window.count >= adminLoginLimit {
		a.attempts[ip] = window
		return false
	}
	a.attempts[ip] = window
	return true
}

func (a *adminAuth) noteLoginFailure(r *http.Request) {
	ip := adminClientIP(r)
	now := a.now()
	a.mu.Lock()
	defer a.mu.Unlock()
	window := a.attempts[ip]
	if window.start.IsZero() || now.Sub(window.start) >= adminLoginWindow {
		window = adminWindow{start: now}
	}
	window.count++
	a.attempts[ip] = window
}

func (a *adminAuth) resetLoginFailures(r *http.Request) {
	a.mu.Lock()
	delete(a.attempts, adminClientIP(r))
	a.mu.Unlock()
}

func (a *adminAuth) login(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !a.allowLogin(r) {
		http.Error(w, "too many login attempts", http.StatusTooManyRequests)
		return
	}
	var req struct {
		Token string `json:"token"`
	}
	if !decodeStrictJSONLimit(w, r, &req, 4096) {
		return
	}
	got := sha256.Sum256([]byte(req.Token))
	if subtle.ConstantTimeCompare(a.tokenHash[:], got[:]) != 1 {
		a.noteLoginFailure(r)
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	sessionID, err := randomAdminToken(32)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "session unavailable")
		return
	}
	csrf, err := randomAdminToken(32)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "session unavailable")
		return
	}
	now := a.now()
	a.mu.Lock()
	for id, session := range a.sessions {
		if !now.Before(session.expiresAt) {
			delete(a.sessions, id)
		}
	}
	for len(a.sessions) >= adminSessionMax {
		var oldestID string
		var oldest time.Time
		for id, session := range a.sessions {
			if oldestID == "" || session.lastSeen.Before(oldest) {
				oldestID, oldest = id, session.lastSeen
			}
		}
		if oldestID == "" {
			break
		}
		delete(a.sessions, oldestID)
	}
	a.sessions[sessionID] = adminSession{csrf: csrf, expiresAt: now.Add(adminSessionTTL), lastSeen: now}
	a.mu.Unlock()
	a.resetLoginFailures(r)
	http.SetCookie(w, &http.Cookie{
		Name: adminSessionCookie, Value: sessionID, Path: "/admin", MaxAge: int(adminSessionTTL.Seconds()),
		HttpOnly: true, Secure: a.secure, SameSite: http.SameSiteStrictMode,
	})
	writeJSON(w, http.StatusOK, map[string]string{"csrf_token": csrf})
}

func (a *adminAuth) logout(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if cookie, err := r.Cookie(adminSessionCookie); err == nil {
		a.mu.Lock()
		delete(a.sessions, cookie.Value)
		a.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: adminSessionCookie, Value: "", Path: "/admin", MaxAge: -1, HttpOnly: true, Secure: a.secure, SameSite: http.SameSiteStrictMode})
	w.WriteHeader(http.StatusNoContent)
}

func (a *adminAuth) authorize(r *http.Request) (string, string, bool) {
	cookie, err := r.Cookie(adminSessionCookie)
	if err != nil || cookie.Value == "" {
		return "", "", false
	}
	now := a.now()
	a.mu.Lock()
	session, ok := a.sessions[cookie.Value]
	if ok && !now.Before(session.expiresAt) {
		delete(a.sessions, cookie.Value)
		ok = false
	}
	if ok {
		session.lastSeen = now
		session.expiresAt = now.Add(adminSessionTTL)
		a.sessions[cookie.Value] = session
	}
	a.mu.Unlock()
	if !ok {
		return "", "", false
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions {
		provided := r.Header.Get(adminCSRFHeader)
		if subtle.ConstantTimeCompare([]byte(provided), []byte(session.csrf)) != 1 {
			return "", "", false
		}
	}
	return cookie.Value, session.csrf, true
}
