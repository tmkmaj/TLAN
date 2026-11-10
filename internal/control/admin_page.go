package control

import (
	_ "embed"
	"html"
	"io"
	"net/http"
	"strings"
)

const adminCSRFPlaceholder = "__CSRF_TOKEN__"

//go:embed admin_login.html
var adminLoginPage string

//go:embed admin_console.html
var adminConsolePage string

func writeAdminPage(w http.ResponseWriter, authenticated bool, csrf string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
	if !authenticated {
		_, _ = io.WriteString(w, adminLoginPage)
		return
	}
	_, _ = io.WriteString(w, strings.Replace(adminConsolePage, adminCSRFPlaceholder, html.EscapeString(csrf), 1))
}
