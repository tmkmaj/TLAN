package frp

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestAnalyzeConfigImportReportsRuleAndServerDiff(t *testing.T) {
	current := testConfig(t)
	current.Profile.Rules = append(current.Profile.Rules, Rule{
		ID: "rule-old", Name: "旧规则", Type: "tcp", Enabled: true,
		Target:   Target{Kind: "loopback", Host: "127.0.0.1", Port: 8081},
		Exposure: Exposure{RemotePort: 30002},
	})
	imported := testConfig(t)
	imported.Profile.Server.Port = 7001
	imported.Profile.Rules = []Rule{
		{ID: "rule-game", Name: "游戏服务", Type: "tcp", Enabled: true, Target: Target{Kind: "loopback", Host: "127.0.0.1", Port: 7777}, Exposure: Exposure{RemotePort: 30001}},
		{ID: "rule-new", Name: "新规则", Type: "tcp", Enabled: true, Target: Target{Kind: "loopback", Host: "127.0.0.1", Port: 8082}, Exposure: Exposure{RemotePort: 30003}},
	}
	data, err := EncodeConfig(imported)
	if err != nil {
		t.Fatal(err)
	}
	analysis, err := AnalyzeConfigImport(data, &current)
	if err != nil {
		t.Fatal(err)
	}
	if !analysis.Supported {
		t.Fatalf("valid import rejected: %s", analysis.RejectText())
	}
	if analysis.Rules.Added != 1 || analysis.Rules.Removed != 1 || analysis.Rules.Modified != 1 {
		t.Fatalf("rule diff = %+v", analysis.Rules)
	}
	if got := strings.Join(analysis.Rules.AddedIDs, ","); got != "rule-new" {
		t.Fatalf("added IDs = %q", got)
	}
	if got := strings.Join(analysis.Rules.RemovedIDs, ","); got != "rule-old" {
		t.Fatalf("removed IDs = %q", got)
	}
	if got := strings.Join(analysis.Rules.ModifiedIDs, ","); got != "rule-game" {
		t.Fatalf("modified IDs = %q", got)
	}
	if !analysis.Server.Changed || !containsString(analysis.Server.Fields, "端口") {
		t.Fatalf("server diff = %+v", analysis.Server)
	}
	if !strings.Contains(analysis.PreviewText(), "新增 1，删除 1，修改 1") {
		t.Fatalf("preview = %q", analysis.PreviewText())
	}
}

func TestAnalyzeConfigImportRejectsDangerousAndUnknownFields(t *testing.T) {
	cfg := testConfig(t)
	data, err := EncodeConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err = json.Unmarshal(data, &root); err != nil {
		t.Fatal(err)
	}
	profile := root["profile"].(map[string]any)
	rules := profile["rules"].([]any)
	rule := rules[0].(map[string]any)
	rule["plugin"] = "virtual_net"
	root["auth"] = map[string]any{"token": "do-not-import"}
	data, err = json.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	analysis, err := AnalyzeConfigImport(data, nil)
	if err != nil {
		t.Fatal(err)
	}
	if analysis.Supported {
		t.Fatal("dangerous import was accepted")
	}
	if len(analysis.Issues) < 2 {
		t.Fatalf("issues = %+v", analysis.Issues)
	}
	var foundAuth, foundPlugin bool
	for _, issue := range analysis.Issues {
		if issue.Path == "auth" && issue.Dangerous {
			foundAuth = true
		}
		if issue.Path == "profile.rules[0].plugin" && issue.Dangerous {
			foundPlugin = true
		}
	}
	if !foundAuth || !foundPlugin {
		t.Fatalf("missing dangerous field reports: %+v", analysis.Issues)
	}
	if !strings.Contains(analysis.RejectText(), "危险字段") {
		t.Fatalf("reject text = %q", analysis.RejectText())
	}
}

func TestAnalyzeConfigImportRejectsTOML(t *testing.T) {
	_, err := AnalyzeConfigImport([]byte("serverAddr = \"127.0.0.1\"\n"), nil)
	if err == nil {
		t.Fatal("TOML import was accepted")
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
