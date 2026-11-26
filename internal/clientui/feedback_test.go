package clientui

import (
	"errors"
	"strings"
	"testing"
)

func TestExplainLangEnglishAndRedaction(t *testing.T) {
	f := ExplainLang("en", "Join network", errors.New("401 unauthorized token=supersecret123"))
	if !strings.Contains(f.Title, "Authentication failed") {
		t.Fatalf("unexpected EN title: %q", f.Title)
	}
	if strings.Contains(f.Detail, "supersecret123") {
		t.Fatalf("secret leaked in Detail: %q", f.Detail)
	}
	if !strings.Contains(f.Detail, "[redacted]") {
		t.Fatalf("expected redaction marker in Detail: %q", f.Detail)
	}

	zh := ExplainLang("zh", "加入私有网络", errors.New("dial tcp 127.0.0.1:8443: connection refused"))
	if !strings.Contains(zh.Title, "暂时无法连接服务器") {
		t.Fatalf("unexpected ZH title: %q", zh.Title)
	}
}
