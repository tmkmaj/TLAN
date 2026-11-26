//go:build windows

package main

import (
	"strings"
	"testing"
	"time"

	"github.com/private-radminlan/lanmesh/internal/clientapi"
	frpctl "github.com/private-radminlan/lanmesh/internal/frp"
)

func TestBuildDiagnosticSummaryTranslatesChecks(t *testing.T) {
	export := diagnosticExport{
		SchemaVersion: 1,
		AppVersion:    "v1.0.0",
		GeneratedAt:   time.Now().UTC(),
		Checks: []clientapi.DiagnosticCheck{
			{Name: "control_health", Status: "pass", Detail: "控制服务可访问，耗时 18 ms"},
			{Name: "virtual_adapter", Status: "pass", Detail: "10.240.0.1/24"},
			{Name: "peer Friend-PC", Status: "pass", Detail: "10.240.0.3 direct UDP"},
			{Name: "network_quality", Status: "warn", Detail: "samples=12 avg_rtt_ms=14 max_rtt_ms=28 dropped_delta=0 direct=12 relay=0"},
			{Name: "frp_tls_default", Status: "pass", Detail: "ca_valid=true handshake_attempted=true handshake_ok=true verified=true version=TLS 1.3 skipped="},
		},
		FRP: frpDiagnosticExport{
			Profiles: []frpProfileDiagnostic{{
				Snapshot: frpctl.Snapshot{
					Rules: []frpctl.RuleRuntimeStatus{{
						Name: "mcserver_25565", Type: "TCP", Enabled: true, State: "已发布", RemoteAddr: "203.0.113.10:60001", Backend: "可用",
					}},
				},
			}},
		},
	}
	probe := serverProbeStats{LatestRTTMillis: 16, AvgRTTMillis: 15, LossPercent: 0, Mode: "STUN UDP", Count: 5}
	setActiveLanguage(langZH)
	summary := buildDiagnosticSummary(export, probe, "https://203.0.113.10:8443", "203.0.113.10:3478")

	if summary.PassCount != 5 || summary.WarnCount != 1 || summary.FailCount != 0 {
		t.Fatalf("counts = pass:%d warn:%d fail:%d", summary.PassCount, summary.WarnCount, summary.FailCount)
	}
	if summary.OverallLevel != "warn" {
		t.Fatalf("OverallLevel = %q, want warn", summary.OverallLevel)
	}
	if summary.Rows[1].Item != "虚拟网卡" || !strings.Contains(summary.Rows[1].Detail, "10.240.0.1/24") {
		t.Fatalf("virtual adapter row = %+v", summary.Rows[1])
	}
	if summary.Rows[2].Item != "成员连接 · Friend-PC" || !strings.Contains(summary.Rows[2].Detail, "P2P 直连") {
		t.Fatalf("peer row = %+v", summary.Rows[2])
	}
	if summary.Rows[4].Item != "端口映射 TLS 证书" || !strings.Contains(summary.Rows[4].Detail, "TLS 1.3") {
		t.Fatalf("tls row = %+v", summary.Rows[4])
	}
}
