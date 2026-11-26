package control

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func adminLoginRequest(body string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/admin/login", bytes.NewBufferString(body))
	req.RemoteAddr = "192.0.2.10:12345"
	req.Header.Set("Content-Type", "application/json")
	return req
}

func TestAdminAuthLoginSessionAndCSRF(t *testing.T) {
	auth := newAdminAuth("test-admin-token", false)
	login := httptest.NewRecorder()
	auth.login(login, adminLoginRequest(`{"token":"test-admin-token"}`))
	if login.Code != http.StatusOK {
		t.Fatalf("login status = %d body=%s", login.Code, login.Body.String())
	}
	cookies := login.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != adminSessionCookie || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatalf("login cookie = %#v", cookies)
	}
	auth.mu.Lock()
	if _, ok := auth.sessions[cookies[0].Value]; ok {
		auth.mu.Unlock()
		t.Fatal("raw session id was stored in server memory")
	}
	if _, ok := auth.sessions[adminSessionKey(cookies[0].Value)]; !ok {
		auth.mu.Unlock()
		t.Fatal("hashed session key was not stored")
	}
	auth.mu.Unlock()
	var loginPayload struct {
		CsrfToken string `json:"csrf_token"`
	}
	if err := json.Unmarshal(login.Body.Bytes(), &loginPayload); err != nil || loginPayload.CsrfToken == "" {
		t.Fatalf("csrf token missing from %s: %v", login.Body.String(), err)
	}
	csrf := loginPayload.CsrfToken
	req := httptest.NewRequest(http.MethodPost, "/admin/api/members/device-a/rename", nil)
	req.AddCookie(cookies[0])
	if _, _, ok := auth.authorize(req); ok {
		t.Fatal("mutating request without CSRF was authorized")
	}
	req.Header.Set(adminCSRFHeader, csrf)
	if _, gotCSRF, ok := auth.authorize(req); !ok || gotCSRF != csrf {
		t.Fatal("valid CSRF request was rejected")
	}
	req = httptest.NewRequest(http.MethodGet, "/admin/api/overview", nil)
	req.AddCookie(cookies[0])
	if _, _, ok := auth.authorize(req); !ok {
		t.Fatal("authenticated GET was rejected")
	}
}

func TestAdminAuthWrongTokenAndRateLimit(t *testing.T) {
	auth := newAdminAuth("test-admin-token", false)
	for i := 0; i < adminLoginLimit; i++ {
		rec := httptest.NewRecorder()
		auth.login(rec, adminLoginRequest(`{"token":"wrong"}`))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d status = %d", i+1, rec.Code)
		}
	}
	rec := httptest.NewRecorder()
	auth.login(rec, adminLoginRequest(`{"token":"wrong"}`))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("rate limited status = %d, body=%s", rec.Code, rec.Body.String())
	}
}

func TestAdminAuthLogoutAndExpiry(t *testing.T) {
	auth := newAdminAuth("test-admin-token", true)
	now := time.Unix(1000, 0)
	auth.now = func() time.Time { return now }
	rec := httptest.NewRecorder()
	auth.login(rec, adminLoginRequest(`{"token":"test-admin-token"}`))
	cookie := rec.Result().Cookies()[0]
	if !cookie.Secure {
		t.Fatal("secure mode did not set Secure cookie")
	}
	req := httptest.NewRequest(http.MethodGet, "/admin/api/overview", nil)
	req.AddCookie(cookie)
	if _, _, ok := auth.authorize(req); !ok {
		t.Fatal("initial session was rejected")
	}
	now = now.Add(adminSessionTTL + time.Second)
	if _, _, ok := auth.authorize(req); ok {
		t.Fatal("expired session was authorized")
	}
	rec = httptest.NewRecorder()
	auth.login(rec, adminLoginRequest(`{"token":"test-admin-token"}`))
	cookie = rec.Result().Cookies()[0]
	req = httptest.NewRequest(http.MethodPost, "/admin/logout", nil)
	req.AddCookie(cookie)
	rec = httptest.NewRecorder()
	auth.logout(rec, req)
	req = httptest.NewRequest(http.MethodGet, "/admin/api/overview", nil)
	req.AddCookie(cookie)
	if _, _, ok := auth.authorize(req); ok {
		t.Fatal("logout did not invalidate session")
	}
}
func TestAdminAuthSessionInfo(t *testing.T) {
	auth := newAdminAuth("test-admin-token", false)
	rec := httptest.NewRecorder()
	auth.login(rec, adminLoginRequest(`{"token":"test-admin-token"}`))
	cookie := rec.Result().Cookies()[0]
	req := httptest.NewRequest(http.MethodGet, "/admin/api/session", nil)
	req.AddCookie(cookie)
	csrf, expiresAt, ok := auth.sessionInfo(req)
	if !ok || csrf == "" || expiresAt.IsZero() {
		t.Fatalf("session info = %q/%v/%v", csrf, expiresAt, ok)
	}
}
func TestAdminClientIPIgnoresForwardedFor(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/admin/login", nil)
	req.RemoteAddr = "192.0.2.10:12345"
	req.Header.Set("X-Forwarded-For", "203.0.113.9")
	if got := adminClientIP(req); got != "192.0.2.10" {
		t.Fatalf("client IP = %q, want TCP peer", got)
	}
}
