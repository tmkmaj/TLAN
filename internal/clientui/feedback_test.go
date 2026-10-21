package clientui

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
)

func TestExplainActionableErrors(t *testing.T) {
	cases := []struct {
		err   error
		title string
	}{
		{fmt.Errorf("server error: invalid network password"), "网络密码不正确"},
		{fmt.Errorf("server error: unauthorized"), "访问令牌未通过验证"},
		{fmt.Errorf("control service unavailable: %w", &net.DNSError{Err: "no such host", Name: "example.invalid"}), "找不到服务器地址"},
		{fmt.Errorf("request: %w", context.DeadlineExceeded), "服务器响应超时"},
		{fmt.Errorf("virtual range overlaps existing interface WLAN"), "虚拟网段与现有网络冲突"},
		{fmt.Errorf("create Wintun: missing DLL"), "无法创建虚拟网卡"},
		{fmt.Errorf("x509: certificate has expired"), "无法验证服务器证书"},
		{fmt.Errorf("FRP_TLS_UNTRUSTED: certificate signed by unknown authority"), "穿透服务器证书无法验证"},
		{fmt.Errorf("FRP_AUTH_REJECTED: invalid token"), "穿透凭据无效或已过期"},
		{fmt.Errorf("FRP_REMOTE_PORT_BUSY: port already used"), "公网端口已被占用"},
		{fmt.Errorf("FRP_BACKEND_UNREACHABLE: dial tcp 127.0.0.1"), "本地服务不可达"},
		{fmt.Errorf("UNSUPPORTED_FRP_FEATURE: virtual_net plugin"), "当前版本不支持此穿透配置"},
	}
	for _, c := range cases {
		f := Explain("连接", c.err)
		if f.Title != c.title || f.Message == "" || f.Detail == "" {
			t.Fatalf("%v: %+v", c.err, f)
		}
	}
}

func TestDetailsDoNotExposeCredentials(t *testing.T) {
	s := Redact("GET https://alice:hunter2@example.test/path?token=abc&password=secret; authorization=Bearer-abc actual-token", "actual-token")
	for _, secret := range []string{"alice", "hunter2", "abc", "secret", "actual-token"} {
		if strings.Contains(s, secret) {
			t.Fatal("credentials remain in details")
		}
	}
}

func TestAuthorizationHeaderRedaction(t *testing.T) {
	s := Redact("request failed\nAuthorization: Bearer my-sensitive-credential\nstatus=403")
	if strings.Contains(s, "my-sensitive-credential") || !strings.Contains(s, "status=403") {
		t.Fatal("authorization header redaction failed")
	}
}
