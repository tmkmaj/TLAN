package control

import (
	_ "embed"
	"html"
	"io"
	"net/http"
	"strings"
)

const adminCSRFPlaceholder = "__CSRF_TOKEN__"
const adminInsecurePlaceholder = "__INSECURE_BANNER__"

const adminInsecureBanner = `<div class="insecure-banner" role="alert"><strong>明文 HTTP 风险</strong><span>当前管理页未使用 TLS。请仅通过 SSH 隧道或受限内网访问，并在防火墙限制端口；不要暴露到公网。</span></div>`

//go:embed admin_login.html
var adminLoginPage string

//go:embed admin_console.html
var adminConsolePage string

func writeAdminPage(w http.ResponseWriter, authenticated bool, csrf string, insecure bool) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
	banner := ""
	if insecure {
		banner = adminInsecureBanner
	}
	if !authenticated {
		_, _ = io.WriteString(w, strings.Replace(adminLoginPage, adminInsecurePlaceholder, banner, 1))
		return
	}
	page := strings.Replace(adminConsolePage, adminInsecurePlaceholder, banner, 1)
	page = strings.Replace(page, adminCSRFPlaceholder, html.EscapeString(csrf), 1)
	_, _ = io.WriteString(w, page)
}
