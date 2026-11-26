//go:build windows

package main

import (
	"fmt"
	"strings"

	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
	"github.com/private-radminlan/lanmesh/internal/clientapi"
	"github.com/private-radminlan/lanmesh/internal/clientui"
)

type diagnosticRow struct {
	Item       string
	StatusText string
	Level      string // "pass", "warn", "fail"
	Detail     string
}

type diagnosticSummary struct {
	OverallTitle string
	OverallLevel string // "pass", "warn", "fail"
	PassCount    int
	WarnCount    int
	FailCount    int
	ServerLine   string
	QualityLine  string
	Rows         []diagnosticRow
}

func normalizeDiagLevel(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "pass", "ok", "healthy":
		return "pass"
	case "fail", "error":
		return "fail"
	default:
		return "warn"
	}
}

func diagStatusLabel(level string) string {
	switch level {
	case "pass":
		return tr("正常", "OK")
	case "fail":
		return tr("异常", "Fail")
	default:
		return tr("告警", "Warn")
	}
}

func formatDiagnosticKV(detail string) map[string]string {
	out := make(map[string]string)
	var lastKey string
	fields := strings.Fields(strings.ReplaceAll(detail, ";", " "))
	for _, field := range fields {
		if k, v, ok := strings.Cut(field, "="); ok {
			lastKey = strings.ToLower(strings.TrimSpace(k))
			out[lastKey] = strings.TrimSpace(v)
		} else if lastKey != "" && out[lastKey] != "" {
			out[lastKey] += " " + field
		}
	}
	return out
}

func translateDiagnosticCheck(check clientapi.DiagnosticCheck) diagnosticRow {
	level := normalizeDiagLevel(check.Status)
	name := strings.TrimSpace(check.Name)
	detail := strings.TrimSpace(check.Detail)
	kv := formatDiagnosticKV(detail)

	row := diagnosticRow{
		Item:       name,
		StatusText: diagStatusLabel(level),
		Level:      level,
		Detail:     detail,
	}

	switch {
	case name == "control_health":
		row.Item = tr("控制服务端连接", "Control Service")
		if row.Detail == "" {
			row.Detail = tr("服务器接口响应正常", "Server API responded normally")
		}
	case name == "stun_probe":
		row.Item = tr("STUN 穿透探测", "STUN Probe")
		if row.Detail == "" {
			row.Detail = tr("UDP 打洞探测完成", "UDP NAT probe completed")
		}
	case name == "server_link":
		row.Item = tr("服务器实时链路", "Server Link")
	case name == "virtual_adapter":
		row.Item = tr("虚拟网卡", "Virtual Adapter")
		if detail != "" {
			row.Detail = tr("已就绪 · ", "Ready · ") + detail
		}
	case strings.HasPrefix(name, "peer "):
		peerName := strings.TrimSpace(strings.TrimPrefix(name, "peer "))
		row.Item = tr("成员连接 · ", "Peer · ") + peerName
		row.Detail = translatePeerDiagnosticDetail(detail)
	case name == "network_quality":
		row.Item = tr("组网传输质量", "Mesh Quality")
		row.Detail = translateNetworkQualityDetail(kv, detail)
	case name == "resource_recovery":
		row.Item = tr("虚拟资源恢复", "Resource Recovery")
		if recovered, ok := kv["recovered"]; ok {
			row.Detail = trf("恢复 %s 项，失败 %s 项，未知归属 %s 项", "Recovered %s, failed %s, unproven %s", recovered, kv["failed"], kv["unproven"])
		}
	case name == "last_error":
		row.Item = tr("最近错误信息", "Last Error")
	case strings.HasPrefix(name, "frp_endpoints_"):
		row.Item = tr("端口映射监听", "FRP Listeners")
		if state := kv["state"]; state != "" {
			row.Detail = tr("监听端点 ", "Endpoints ") + kv["endpoints"] + tr(" · 状态 ", " · State ") + state
		}
	case strings.HasPrefix(name, "frp_observation_"):
		row.Item = tr("端口映射路由检测", "FRP Egress Route")
		if kv["stable"] == "healthy" {
			row.Detail = tr("出口路由正常，未与虚拟网卡网段冲突", "Egress route healthy; no virtual subnet overlap")
		} else if kv["stable"] != "" {
			row.Detail = tr("出口路由状态：", "Egress route state: ") + kv["stable"]
		}
	case strings.HasPrefix(name, "frp_lease_"):
		row.Item = tr("端口映射授权", "FRP Lease")
		if leases, ok := kv["leases"]; ok {
			row.Detail = trf("已获取服务器授权 (%s 条)", "Active server leases (%s)", leases)
			if errMsg := kv["error"]; errMsg != "" {
				row.Detail += " · " + errMsg
			}
		}
	case strings.HasPrefix(name, "frp_route_"):
		row.Item = tr("端口映射规则状态", "FRP Routes")
		if routes, ok := kv["routes"]; ok {
			row.Detail = trf("共 %s 条活动规则", "%s active rules", routes)
		}
	case strings.HasPrefix(name, "frp_gateway_"):
		row.Item = tr("映射转发网关", "Target Gateways")
		if gws, ok := kv["gateways"]; ok {
			row.Detail = trf("活动转发网关 %s 个", "%s active gateways", gws)
		}
	case strings.HasPrefix(name, "frp_tls_"):
		row.Item = tr("端口映射 TLS 证书", "FRP TLS Certificate")
		if kv["handshake_ok"] == "true" && kv["verified"] == "true" {
			ver := kv["version"]
			if ver == "" {
				ver = "TLS"
			}
			row.Detail = tr("CA 证书校验通过 · 已建立 ", "CA verified · ") + ver + tr(" 加密通道", " encrypted")
		} else if kv["ca_valid"] == "false" {
			row.Detail = tr("可信 CA 证书无效或尚未配置", "Trusted CA invalid or missing")
		} else if errIdx := strings.Index(detail, "error="); errIdx >= 0 {
			row.Detail = tr("TLS 握手失败：", "TLS handshake failed: ") + strings.TrimSpace(detail[errIdx+len("error="):])
		}
	}

	if row.Detail == "" {
		row.Detail = "—"
	}
	return row
}

func translatePeerDiagnosticDetail(detail string) string {
	if strings.Contains(detail, "=") {
		kv := formatDiagnosticKV(detail)
		path := kv["path"]
		label := path
		switch {
		case strings.Contains(path, "direct UDP"):
			label = tr("P2P 直连", "P2P Direct")
		case strings.Contains(path, "relay TCP/TLS"):
			label = tr("服务器中继", "Server Relay")
		case strings.Contains(path, "checking"):
			label = tr("正在探测直连", "Probing")
		}
		var parts []string
		if ip := kv["ip"]; ip != "" {
			parts = append(parts, ip)
		}
		if label != "" {
			parts = append(parts, label)
		}
		if rtt := kv["rtt"]; rtt != "" && rtt != "0s" && rtt != "0" {
			parts = append(parts, rtt)
		}
		if len(parts) > 0 {
			return strings.Join(parts, " · ")
		}
	}
	switch {
	case strings.Contains(detail, "direct UDP"):
		ip := strings.TrimSpace(strings.ReplaceAll(detail, "direct UDP", ""))
		return strings.Trim(ip+" · "+tr("P2P 直连", "P2P Direct"), " ·")
	case strings.Contains(detail, "relay TCP/TLS"):
		ip := strings.TrimSpace(strings.ReplaceAll(detail, "relay TCP/TLS", ""))
		return strings.Trim(ip+" · "+tr("服务器中继", "Server Relay"), " ·")
	case strings.Contains(detail, "checking"):
		ip := strings.TrimSpace(strings.ReplaceAll(detail, "checking", ""))
		return strings.Trim(ip+" · "+tr("正在探测直连", "Probing"), " ·")
	default:
		return detail
	}
}

func translateNetworkQualityDetail(kv map[string]string, fallback string) string {
	avg, ok := kv["avg_rtt_ms"]
	if !ok {
		return fallback
	}
	return trf("平均延迟 %s ms · 峰值 %s ms · 直连样本 %s / 中继样本 %s",
		"Avg %s ms · Peak %s ms · Direct %s / Relay %s",
		avg, kv["max_rtt_ms"], kv["direct"], kv["relay"])
}

func buildDiagnosticSummary(export diagnosticExport, probe serverProbeStats, serverURL, stunAddr string) diagnosticSummary {
	summary := diagnosticSummary{
		OverallTitle: tr("连接正常", "Healthy"),
		OverallLevel: "pass",
		ServerLine:   tr("服务器：", "Server: ") + formatEndpointSummary(serverURL, stunAddr),
	}
	if probe.Count > 0 {
		summary.QualityLine = trf("当前延迟 %s · 平均 %.0f ms · 丢包 %.1f%% (%s)",
			"RTT %s · Avg %.0f ms · Loss %.1f%% (%s)",
			formatLatencyText(probe.LatestRTTMillis), probe.AvgRTTMillis, probe.LossPercent, probe.Mode)
	} else {
		summary.QualityLine = tr("延迟与丢包：暂未采集到样本", "Latency & loss: no samples yet")
	}

	rows := make([]diagnosticRow, 0, len(export.Checks)+len(export.FRP.Profiles)*2)
	for _, check := range export.Checks {
		row := translateDiagnosticCheck(check)
		rows = append(rows, row)
	}
	for _, profile := range export.FRP.Profiles {
		for _, rule := range profile.Snapshot.Rules {
			if !rule.Enabled {
				continue
			}
			level := "pass"
			if rule.State == "注册失败" || rule.ErrorDetail != "" {
				level = "warn"
			} else if rule.State == "已停止" || rule.State == "等待注册" {
				level = "warn"
			}
			detail := rule.RemoteAddr
			if rule.ErrorDetail != "" {
				detail = rule.RemoteAddr + " · " + rule.ErrorDetail
			} else if rule.Backend != "" && rule.Backend != "—" {
				detail = rule.RemoteAddr + tr(" · 本地服务", " · Local ") + rule.Backend
			}
			rows = append(rows, diagnosticRow{
				Item:       trf("映射规则 · %s (%s)", "Rule · %s (%s)", rule.Name, rule.Type),
				StatusText: diagStatusLabel(level),
				Level:      level,
				Detail:     strings.Trim(detail, " ·"),
			})
		}
	}

	for _, row := range rows {
		switch row.Level {
		case "fail":
			summary.FailCount++
		case "warn":
			summary.WarnCount++
		default:
			summary.PassCount++
		}
	}
	switch {
	case summary.FailCount > 0:
		summary.OverallTitle = trf("发现 %d 项连接异常", "%d check(s) failed", summary.FailCount)
		summary.OverallLevel = "fail"
	case summary.WarnCount > 0:
		summary.OverallTitle = trf("共 %d 项正常，%d 项需要关注", "%d OK, %d warning(s)", summary.PassCount, summary.WarnCount)
		summary.OverallLevel = "warn"
	case summary.PassCount > 0:
		summary.OverallTitle = trf("全部 %d 项检查正常", "All %d check(s) passed", summary.PassCount)
		summary.OverallLevel = "pass"
	default:
		summary.OverallTitle = tr("暂无可显示检查项", "No checks available")
		summary.OverallLevel = "warn"
	}
	summary.Rows = rows
	return summary
}

func (s diagnosticSummary) plainText(syncMessage string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s\r\n", appName, tr("连接诊断", "Diagnostics"))
	fmt.Fprintf(&b, "%s: %s\r\n", tr("结果", "Result"), s.OverallTitle)
	fmt.Fprintf(&b, "%s\r\n%s\r\n", s.ServerLine, s.QualityLine)
	if syncMessage != "" {
		fmt.Fprintf(&b, "%s: %s\r\n", tr("报告同步", "Sync"), syncMessage)
	}
	b.WriteString("\r\n")
	for _, r := range s.Rows {
		fmt.Fprintf(&b, "[%s] %s: %s\r\n", r.StatusText, r.Item, r.Detail)
	}
	return b.String()
}

func (a *desktop) showDiagnosticsDialog(summary diagnosticSummary, syncMessage, rawDetail string) {
	if a.window == nil || a.window.IsDisposed() {
		return
	}
	var dlg *walk.Dialog
	var table *walk.TableView
	var closeButton *walk.PushButton
	model := &frpRuleTableModel{}
	rows := make([][]string, 0, len(summary.Rows))
	for _, r := range summary.Rows {
		rows = append(rows, []string{r.Item, r.StatusText, r.Detail})
	}
	model.setRows(rows)

	overallColor := uiSuccess
	switch summary.OverallLevel {
	case "fail":
		overallColor = uiDanger
	case "warn":
		overallColor = uiWarning
	}

	banner := roundView{Composite: Composite{Background: SolidColorBrush{Color: uiTableAlt}, Layout: VBox{Margins: Margins{Left: 14, Top: 12, Right: 14, Bottom: 12}, Spacing: 4}, Children: []Widget{
		Composite{Background: SolidColorBrush{Color: uiTableAlt}, Layout: HBox{MarginsZero: true, Spacing: 8}, Children: []Widget{
			Label{Text: "● " + summary.OverallTitle, TextColor: overallColor, Font: uiFont(11, true), NoPrefix: true},
			HSpacer{},
			Label{Text: trf("正常 %d / 告警 %d / 异常 %d", "OK %d / Warn %d / Fail %d", summary.PassCount, summary.WarnCount, summary.FailCount), TextColor: uiMuted, Font: uiFont(9, false), NoPrefix: true},
		}},
		Label{Text: summary.ServerLine, TextColor: uiInk, Font: uiMonoFont(8, false), NoPrefix: true, EllipsisMode: EllipsisEnd},
		Label{Text: summary.QualityLine, TextColor: uiInk, Font: uiMonoFont(8, false), NoPrefix: true, EllipsisMode: EllipsisEnd},
		Label{Text: syncMessage, TextColor: uiMuted, Font: uiFont(8, false), NoPrefix: true, EllipsisMode: EllipsisEnd},
	}}, fill: uiTableAlt, radius: 10, border: borderColor(uiBorder), hud: false}

	err := (Dialog{
		AssignTo:      &dlg,
		Title:         tr("连接诊断", "Diagnostics"),
		Icon:          a.appIcon,
		Size:          Size{Width: 720, Height: 510},
		MinSize:       Size{Width: 620, Height: 410},
		Font:          uiFont(10, false),
		Background:    SolidColorBrush{Color: uiWhite},
		Layout:        VBox{Margins: Margins{Left: 22, Top: 18, Right: 22, Bottom: 18}, Spacing: 12},
		CancelButton:  &closeButton,
		DefaultButton: &closeButton,
		Children: []Widget{
			heading(tr("连接诊断", "Diagnostics")),
			banner,
			TableView{
				AssignTo:                    &table,
				Model:                       model,
				Background:                  SolidColorBrush{Color: uiWhite},
				Font:                        uiFont(9, false),
				StretchFactor:               1,
				CustomRowHeight:             32,
				CustomHeaderHeight:          28,
				LastColumnStretched:         true,
				SelectionHiddenWithoutFocus: true,
				AlternatingRowBG:            true,
				Columns: []TableViewColumn{
					{Title: tr("检查项目", "Check"), Width: 170},
					{Title: tr("状态", "Status"), Width: 68},
					{Title: tr("结果说明", "Detail"), Width: 360},
				},
				StyleCell: func(s *walk.CellStyle) {
					if s.Row() < 0 {
						titles := []string{tr("检查项目", "Check"), tr("状态", "Status"), tr("结果说明", "Detail")}
						if s.Col() >= 0 && s.Col() < len(titles) {
							styleTableHeader(s, titles[s.Col()], false)
						}
						return
					}
					s.TextColor = uiInk
					if s.Row()%2 == 1 {
						s.BackgroundColor = uiTableAlt
					} else {
						s.BackgroundColor = uiWhite
					}
					if s.Row() < len(summary.Rows) && s.Col() == 1 {
						switch summary.Rows[s.Row()].Level {
						case "pass":
							s.TextColor = uiSuccess
						case "fail":
							s.TextColor = uiDanger
						default:
							s.TextColor = uiWarning
						}
					}
				},
			},
			Composite{Background: SolidColorBrush{Color: uiWhite}, Layout: HBox{MarginsZero: true, Spacing: 8}, Children: []Widget{
				compactButton(nil, tr("复制报告", "Copy Report"), btnSecondary, 96, func() {
					_ = walk.Clipboard().SetText(summary.plainText(syncMessage))
				}),
				compactButton(nil, tr("查看原始日志", "Raw Log"), btnSecondary, 110, func() {
					a.showTextDialog(tr("诊断原始日志", "Raw Diagnostic Log"), syncMessage, clientui.RedactLang(currentLang(), rawDetail, a.api.Token, a.adminToken))
				}),
				HSpacer{},
				actionButton(&closeButton, tr("关闭", "Close"), true, 88, func() { dlg.Accept() }),
			}},
		},
	}).Create(a.window)
	if err != nil {
		a.showTextDialog(tr("连接诊断", "Diagnostics"), syncMessage, clientui.RedactLang(currentLang(), rawDetail, a.api.Token, a.adminToken))
		return
	}
	styleFramelessTable(table)
	defer dlg.Dispose()
	runThemedDialog(dlg)
}
