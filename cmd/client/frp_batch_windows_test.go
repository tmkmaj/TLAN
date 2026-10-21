//go:build windows

package main

import (
	"path/filepath"
	"strconv"
	"testing"

	frpctl "github.com/private-radminlan/lanmesh/internal/frp"
)

func batchTestConfig(t *testing.T) frpctl.Config {
	t.Helper()
	cfg := frpctl.NewDefaultConfig()
	cfg.Profile.Server.Host = "127.0.0.1"
	cfg.Profile.Server.Port = 7000
	cfg.Profile.Server.TLSServerName = "localhost"
	cfg.Profile.Server.TrustedCAPath = filepath.Join(t.TempDir(), "ca.pem")
	return cfg
}

func TestAddBatchRulesGeneratesTCPAndUDP(t *testing.T) {
	cfg, err := addBatchRules(batchTestConfig(t), "loopback", "127.0.0.1", []string{"tcp", "udp"}, 25565, 30000, 2, "Game")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Profile.Rules) != 4 {
		t.Fatalf("rules = %d, want 4", len(cfg.Profile.Rules))
	}
	want := map[string]bool{"tcp:25565:30000": true, "udp:25565:30000": true, "tcp:25566:30001": true, "udp:25566:30001": true}
	for _, rule := range cfg.Profile.Rules {
		key := rule.Type + ":" + strconv.Itoa(rule.Target.Port) + ":" + strconv.Itoa(rule.Exposure.RemotePort)
		if !want[key] {
			t.Fatalf("unexpected generated rule %+v", rule)
		}
	}
}

func TestAddBatchRulesRejectsRangeAndLimit(t *testing.T) {
	if _, err := addBatchRules(batchTestConfig(t), "loopback", "127.0.0.1", []string{"tcp"}, 25565, 65535, 2, "overflow"); err == nil {
		t.Fatal("overflowing port range was accepted")
	}
	base := batchTestConfig(t)
	for i := 0; i < frpctl.MaxRules-1; i++ {
		base.Profile.Rules = append(base.Profile.Rules, frpctl.Rule{
			ID: "rule-" + strconv.Itoa(i), Name: "existing-" + strconv.Itoa(i), Type: "tcp", Enabled: false,
			Target: frpctl.Target{Kind: "loopback", Host: "127.0.0.1", Port: 20000 + i}, Exposure: frpctl.Exposure{RemotePort: 20000 + i},
		})
	}
	if _, err := addBatchRules(base, "loopback", "127.0.0.1", []string{"tcp", "udp"}, 25565, 30000, 1, "limit"); err == nil {
		t.Fatal("rule limit was not enforced")
	}
}
