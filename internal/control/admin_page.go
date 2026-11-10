package control

import (
	"io"
	"net/http"
)

func writeAdminPage(w http.ResponseWriter, authenticated bool) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if authenticated {
		_, _ = io.WriteString(w, `<!doctype html><html lang="zh-CN"><body><h1>TLAN 管理控制台</h1></body></html>`)
		return
	}
	_, _ = io.WriteString(w, `<!doctype html><html lang="zh-CN"><body><form method="post" action="/admin/login">管理控制台</form></body></html>`)
}
