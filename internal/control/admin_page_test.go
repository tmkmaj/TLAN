package control

import (
	"io"
	"net/http"
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

	client, _ := adminLoginClient(t, server.URL)
	pageResp, err := client.Get(server.URL + "/admin")
	if err != nil {
		t.Fatal(err)
	}
	pageBody, _ := io.ReadAll(pageResp.Body)
	pageResp.Body.Close()
	page := string(pageBody)
	for _, want := range []string{"概览", "成员", "连接", "/admin/api/overview", "/admin/api/members", "重命名", "踢出", "拉黑", "解封"} {
		if !strings.Contains(page, want) {
			t.Fatalf("authenticated page missing %q", want)
		}
	}
	if strings.Contains(page, "Tmkmaj233") {
		t.Fatal("authenticated page leaked admin token")
	}
}
