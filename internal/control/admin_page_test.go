package control

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAdminPageContainsRequiredUIAndNoSecrets(t *testing.T) {
	server, _, _, _, _, _ := adminAPIFixture(t)
	defer server.Close()
	resp, err := http.Get(server.URL + "/admin")
	if err != nil {
		t.Fatal(err)
	}
	loginBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login page status = %d", resp.StatusCode)
	}
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("login page cache-control = %q", resp.Header.Get("Cache-Control"))
	}
	if !strings.Contains(resp.Header.Get("Content-Security-Policy"), "default-src 'self'") {
		t.Fatalf("login page CSP = %q", resp.Header.Get("Content-Security-Policy"))
	}
	loginPage := string(loginBody)
	for _, want := range []string{"管理令牌", "/admin/login", "tlan_admin"} {
		if !strings.Contains(loginPage, want) {
			t.Fatalf("login page missing %q", want)
		}
	}
	if strings.Contains(loginPage, "Tmkmaj233") {
		t.Fatal("login page leaked admin token")
	}
	if strings.Contains(loginPage, "https://") || strings.Contains(loginPage, "http://") {
		t.Fatal("login page contains an external URL")
	}
	if !strings.Contains(loginPage, "明文 HTTP 风险") {
		t.Fatal("plaintext admin page did not show the high-risk warning")
	}

	client, _ := adminLoginClient(t, server.URL)
	pageResp, err := client.Get(server.URL + "/admin")
	if err != nil {
		t.Fatal(err)
	}
	pageBody, _ := io.ReadAll(pageResp.Body)
	pageResp.Body.Close()
	page := string(pageBody)
	for _, want := range []string{"概览", "成员", "连接", "/admin/api/overview", "/admin/api/members", "/admin/api/session", "加入时间", "Forwarding", "Managed FRP", "重命名", "踢出", "拉黑", "解封", "设置", "控制台版本", "亮暗风格", `data-theme-option="dark"`, "settings-version"} {
		if !strings.Contains(page, want) {
			t.Fatalf("authenticated page missing %q", want)
		}
	}
	if strings.Contains(page, "Tmkmaj233") {
		t.Fatal("authenticated page leaked admin token")
	}
	if strings.Contains(page, "https://") || strings.Contains(page, "http://") {
		t.Fatal("authenticated page contains an external URL")
	}
}
func TestAdminPageSecureModeOmitsInsecureWarning(t *testing.T) {
	rec := httptest.NewRecorder()
	writeAdminPage(rec, false, "", false)
	if strings.Contains(rec.Body.String(), "明文 HTTP 风险") {
		t.Fatal("secure admin page showed the plaintext warning")
	}
}
