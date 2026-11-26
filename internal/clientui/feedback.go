// Package clientui formats desktop feedback without changing connection behavior.
package clientui

import (
	"context"
	"errors"
	"net"
	"regexp"
	"strings"
)

type Feedback struct {
	Title, Message, Detail string
}

// Explain keeps technical errors available while giving users an actionable summary.
func Explain(action string, err error, secrets ...string) Feedback {
	return ExplainLang("zh", action, err, secrets...)
}

// ExplainLang formats user-facing error summaries in Chinese ("zh") or English ("en").
func ExplainLang(lang, action string, err error, secrets ...string) Feedback {
	if strings.EqualFold(strings.TrimSpace(lang), "en") {
		return explainEN(action, err, secrets...)
	}
	return explainZH(action, err, secrets...)
}

func explainZH(action string, err error, secrets ...string) Feedback {
	f := Feedback{Title: action + "失败", Message: "请重试。若问题持续，可打开技术详情定位原因。"}
	if err == nil {
		return f
	}
	f.Detail = RedactLang("zh", err.Error(), secrets...)
	s := strings.ToLower(err.Error())
	var dns *net.DNSError
	var timeout net.Error
	switch {
	case errors.Is(err, context.Canceled):
		f.Title, f.Message = "操作已取消", "需要时可以重新发起连接。"
	case strings.Contains(s, "frp profile revision conflict"):
		f.Title, f.Message = "穿透配置已更新", "配置在另一处发生了变化，请关闭当前设置窗口并重新打开后再保存。"
	case strings.Contains(s, "route_conflict"):
		f.Title, f.Message = "穿透路径与组网网段冲突", "FRPS 控制连接或 LAN 目标会被 TLAN 虚拟路由捕获。请改用独立的服务器/物理地址，或调整组网网段后再启动。"
	case strings.Contains(s, "route_observation_unavailable"):
		f.Title, f.Message = "无法确认穿透出口路径", "程序无法解析 FRPS 地址或读取当前有效路由，因此已按安全策略停止。请检查 DNS、网络适配器和 FRP 服务器域名后重试。"
	case strings.Contains(s, "mesh_dependency_down"):
		f.Title, f.Message = "组网依赖不可用", "该规则依赖 TLAN 成员；请确认 Mesh 已启动、目标成员仍在线且地址/公钥未变化。恢复后程序会自动重试。"
	case strings.Contains(s, "frp_server_unreachable"):
		f.Title, f.Message = "无法连接穿透服务器", "请检查 FRP 域名、端口、当前网络和服务器防火墙。"
	case strings.Contains(s, "frp_tls_untrusted"):
		f.Title, f.Message = "穿透服务器证书无法验证", "请选择正确的可信 CA，并确认 TLS serverName 与证书域名一致。程序不会跳过证书校验。"
	case strings.Contains(s, "frp_lease_revoked") || strings.Contains(s, "frp_lease_expired"):
		f.Title, f.Message = "穿透发布授权已失效", "托管授权已被撤销或过期，穿透已自动停止。请重新申请授权后再启动。"
	case strings.Contains(s, "frp_auth_rejected"):
		f.Title, f.Message = "穿透凭据无效或已过期", "请重新填写服务器提供的独立 FRP 令牌，或重新申请托管发布授权。"
	case strings.Contains(s, "frp_remote_port_denied") || strings.Contains(s, "port not allowed"):
		f.Title, f.Message = "服务器端口不在允许范围内", "该端口超出管理员允许的映射范围，请更换允许范围内的端口。"
	case strings.Contains(s, "frp_remote_port_busy") || strings.Contains(s, "remote_port is already leased") ||
		strings.Contains(s, "port already used") || strings.Contains(s, "port unavailable"):
		f.Title, f.Message = "服务器端口已被占用", "该服务器端口已被其他服务或成员占用，请更换其他端口后重试。"
	case strings.Contains(s, "frp_local_listen_busy"):
		f.Title, f.Message = "本机管理入口被占用", "请稍后重试；程序会自动重新分配受管管理端口。"
	case strings.Contains(s, "frp_backend_unreachable"):
		f.Title, f.Message = "本地服务不可达", "请先启动本机应用，并确认它监听 127.0.0.1 的对应端口。"
	case strings.Contains(s, "frp_core_invalid"):
		f.Title, f.Message = "内置穿透组件不可用", "请完整解压客户端，并确认 runtime/frp 目录中的 frpc.exe 未被替换。"
	case strings.Contains(s, "frp_admin_unauthorized"):
		f.Title, f.Message = "穿透管理接口认证失败", "请停止后重新启动穿透，程序会生成新的本机随机管理凭据。"
	case strings.Contains(s, "frp_process_failed"):
		f.Title, f.Message = "穿透服务异常退出", "请打开运行日志查看最近原因，然后重新启动穿透。"
	case strings.Contains(s, "frp_configuration_invalid"):
		f.Title, f.Message = "穿透配置不正确", "请检查服务器地址、端口、TLS serverName、CA 和规则端口。"
	case strings.Contains(s, "unsupported_frp_feature"):
		f.Title, f.Message = "当前版本不支持此穿透配置", "请检查目标类型、服务器模式和规则组合；Mesh 发布需要托管授权，且不能与独立 FRP 规则混在同一配置档。"
	case strings.Contains(s, "cleanup_incomplete"):
		f.Title, f.Message = "部分资源清理失败", "穿透已停止，但本机运行目录可能仍有残留。请重新启动客户端后重试。"
	case strings.Contains(s, "invalid network password"):
		f.Title, f.Message = "网络密码不正确", "请向网络创建者确认密码后重新加入；它与服务器访问令牌不同。"
	case strings.Contains(s, "private enrollment is disabled"):
		f.Title, f.Message = "服务器尚未启用口令加入", "请联系管理员在服务器配置入网密钥并重启服务端。"
	case strings.Contains(s, "too many join attempts"):
		f.Title, f.Message = "口令尝试过于频繁", "请稍等一分钟，再确认口令并重新加入。"
	case strings.Contains(s, "unauthorized") || strings.Contains(s, "403 forbidden"):
		f.Title, f.Message = "访问令牌未通过验证", "请确认入网密钥是否正确，或联系管理员。"
	case strings.Contains(s, "overlaps existing interface"):
		f.Title, f.Message = "虚拟网段与现有网络冲突", "请选择其他虚拟网段，或先断开使用相同网段的 VPN 后重试。"
	case strings.Contains(s, "interface") && strings.Contains(s, "already exists"):
		f.Title, f.Message = "虚拟网卡已被占用", "请先关闭另一 TLAN 实例或断开已有隧道，再重新连接。"
	case strings.Contains(s, "wintun"):
		f.Title, f.Message = "无法创建虚拟网卡", "请完整解压客户端，保留同目录的 wintun.dll，并以管理员权限运行。"
	case strings.Contains(s, "access is denied") || strings.Contains(s, "permission denied") || strings.Contains(s, "拒绝访问"):
		f.Title, f.Message = "没有足够的操作权限", "请以管理员权限运行客户端，并检查相关文件是否被占用或禁止写入。"
	case strings.Contains(s, "x509") || strings.Contains(s, "certificate") || strings.Contains(s, "tls:"):
		f.Title, f.Message = "无法验证服务器证书", "请核对证书是否包含服务器 IP 或域名，并检查证书有效期和电脑时间。"
	case errors.As(err, &dns) || strings.Contains(s, "no such host") || strings.Contains(s, "name resolution"):
		f.Title, f.Message = "找不到服务器地址", "请检查域名拼写和当前网络，确认服务器域名能够正常解析。"
	case errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &timeout) && timeout.Timeout()) || strings.Contains(s, "timed out") || strings.Contains(s, "timeout"):
		f.Title, f.Message = "服务器响应超时", "请检查网络和服务器是否在线，确认所用端口已放行后重试。"
	case strings.Contains(s, "connection refused") || strings.Contains(s, "actively refused") || strings.Contains(s, "connectex") || strings.Contains(s, "unreachable"):
		f.Title, f.Message = "暂时无法连接服务器", "请核对服务器地址和端口，确认服务正在运行且防火墙允许连接。"
	case strings.Contains(s, "no longer a member"):
		f.Title, f.Message = "本机已退出该网络", "请刷新网络列表，选择网络并重新加入。"
	case strings.Contains(s, "pool is full") || strings.Contains(s, "128 device"):
		f.Title, f.Message = "网络成员已满", "请清理不再使用的成员，或创建容量合适的新网络。"
	case strings.Contains(s, "password must be at least"):
		f.Title, f.Message = "网络密码太短", "请设置至少 8 位的网络密码。"
	case strings.Contains(s, "name and password are required"):
		f.Title, f.Message = "请补全网络信息", "网络名称和网络密码均不能为空。"
	case strings.Contains(s, "cidr") || strings.Contains(s, "ipv4 private pool"):
		f.Title, f.Message = "虚拟网段格式不正确", "请使用 10.0.0.0/8 或 100.64.0.0/10 内的 IPv4 网段，例如 10.240.0.0/24。"
	case strings.Contains(s, "404") || strings.Contains(s, "endpoint not found") || strings.Contains(s, "decode server response"):
		f.Title, f.Message = "服务器地址或响应不正确", "请确认填写的是 TLAN 服务根地址，并检查反向代理是否正确转发。"
	case strings.Contains(s, "control service unavailable"):
		f.Title, f.Message = "与服务器的连接中断", "请检查网络及服务器地址，然后重新连接。"
	case strings.Contains(s, "cryptunprotect") || strings.Contains(s, "dpapi"):
		f.Title, f.Message = "无法读取本机加密配置", "请使用保存配置时的 Windows 用户运行客户端，或重新填写服务器和令牌。"
	case strings.Contains(s, "ttm_addtool"):
		f.Title, f.Message = "窗口组件初始化失败", "请完整解压新版客户端后重新运行，确认 EXE 及其同目录文件未被替换。"
	}
	return f
}

func explainEN(action string, err error, secrets ...string) Feedback {
	f := Feedback{Title: action + " failed", Message: "Please try again. Open details if the issue persists."}
	if err == nil {
		return f
	}
	f.Detail = RedactLang("en", err.Error(), secrets...)
	s := strings.ToLower(err.Error())
	var dns *net.DNSError
	var timeout net.Error
	switch {
	case errors.Is(err, context.Canceled):
		f.Title, f.Message = "Operation canceled", "You can retry the connection whenever ready."
	case strings.Contains(s, "frp profile revision conflict"):
		f.Title, f.Message = "Port mapping config changed", "Settings were modified elsewhere. Reopen the dialog and save again."
	case strings.Contains(s, "route_conflict"):
		f.Title, f.Message = "Route conflict with virtual LAN", "The FRPS control route overlaps the TLAN virtual subnet. Use a separate address or adjust the subnet."
	case strings.Contains(s, "route_observation_unavailable"):
		f.Title, f.Message = "Unable to verify egress route", "Could not resolve FRPS host or inspect system routes. Check DNS and network adapters."
	case strings.Contains(s, "mesh_dependency_down"):
		f.Title, f.Message = "Mesh dependency unavailable", "This rule depends on a TLAN peer; ensure Mesh is running and the peer is online."
	case strings.Contains(s, "frp_server_unreachable"):
		f.Title, f.Message = "Cannot reach FRP server", "Check the FRP host, port, network connection, and firewall."
	case strings.Contains(s, "frp_tls_untrusted"):
		f.Title, f.Message = "Untrusted FRP server certificate", "Select the matching trusted CA certificate and verify TLS serverName."
	case strings.Contains(s, "frp_lease_revoked") || strings.Contains(s, "frp_lease_expired"):
		f.Title, f.Message = "FRP lease revoked or expired", "Managed authorization was revoked or expired. Restart port mapping to re-acquire."
	case strings.Contains(s, "frp_auth_rejected"):
		f.Title, f.Message = "FRP credentials rejected", "Check the server FRP token or request a fresh managed lease."
	case strings.Contains(s, "frp_remote_port_denied") || strings.Contains(s, "port not allowed"):
		f.Title, f.Message = "Server port not allowed", "This port is outside the administrator-allowed range."
	case strings.Contains(s, "frp_remote_port_busy") || strings.Contains(s, "remote_port is already leased") ||
		strings.Contains(s, "port already used") || strings.Contains(s, "port unavailable"):
		f.Title, f.Message = "Server port already in use", "Choose another port on the server and try again."
	case strings.Contains(s, "frp_local_listen_busy"):
		f.Title, f.Message = "Local admin port busy", "Please retry in a moment; a free loopback port will be selected."
	case strings.Contains(s, "frp_backend_unreachable"):
		f.Title, f.Message = "Local service unreachable", "Start the local application first and confirm it is listening on 127.0.0.1."
	case strings.Contains(s, "frp_core_invalid"):
		f.Title, f.Message = "Built-in FRP binary unavailable", "Extract the full archive and ensure runtime/frp/frpc.exe is intact."
	case strings.Contains(s, "frp_admin_unauthorized"):
		f.Title, f.Message = "FRP admin auth failed", "Stop and restart port mapping to regenerate local admin credentials."
	case strings.Contains(s, "frp_process_failed"):
		f.Title, f.Message = "FRP process exited unexpectedly", "Check the runtime logs for details and restart port mapping."
	case strings.Contains(s, "frp_configuration_invalid"):
		f.Title, f.Message = "Invalid FRP configuration", "Verify server address, port, TLS serverName, CA, and rule ports."
	case strings.Contains(s, "unsupported_frp_feature"):
		f.Title, f.Message = "Unsupported FRP configuration", "Check target kind, server mode, and rule combination."
	case strings.Contains(s, "cleanup_incomplete"):
		f.Title, f.Message = "Incomplete cleanup", "Port mapping stopped, but some runtime files remain. Restart the client to retry."
	case strings.Contains(s, "invalid network password"):
		f.Title, f.Message = "Invalid join code", "Please verify the join code and try again."
	case strings.Contains(s, "private enrollment is disabled"):
		f.Title, f.Message = "Enrollment is disabled", "Ask the server administrator to configure network.join_code."
	case strings.Contains(s, "too many join attempts"):
		f.Title, f.Message = "Too many join attempts", "Wait a minute before trying again."
	case strings.Contains(s, "unauthorized") || strings.Contains(s, "403 forbidden"):
		f.Title, f.Message = "Authentication failed", "Check your join key or contact the administrator."
	case strings.Contains(s, "overlaps existing interface"):
		f.Title, f.Message = "Subnet conflict", "Virtual subnet overlaps an active interface. Disconnect conflicting VPNs."
	case strings.Contains(s, "interface") && strings.Contains(s, "already exists"):
		f.Title, f.Message = "Virtual adapter already in use", "Close any other running TLAN instance first."
	case strings.Contains(s, "wintun"):
		f.Title, f.Message = "Failed to create virtual adapter", "Keep wintun.dll next to the executable and run as Administrator."
	case strings.Contains(s, "access is denied") || strings.Contains(s, "permission denied") || strings.Contains(s, "拒绝访问"):
		f.Title, f.Message = "Permission denied", "Run the client as Administrator and check file permissions."
	case strings.Contains(s, "x509") || strings.Contains(s, "certificate") || strings.Contains(s, "tls:"):
		f.Title, f.Message = "TLS certificate verification failed", "Ensure the certificate matches the server IP/domain and your system clock is accurate."
	case errors.As(err, &dns) || strings.Contains(s, "no such host") || strings.Contains(s, "name resolution"):
		f.Title, f.Message = "Server host not found", "Check the hostname spelling and your DNS/network connection."
	case errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &timeout) && timeout.Timeout()) || strings.Contains(s, "timed out") || strings.Contains(s, "timeout"):
		f.Title, f.Message = "Connection timed out", "Verify the server is online and firewall ports are open."
	case strings.Contains(s, "connection refused") || strings.Contains(s, "actively refused") || strings.Contains(s, "connectex") || strings.Contains(s, "unreachable"):
		f.Title, f.Message = "Unable to reach server", "Verify the server address and port, and check firewall rules."
	case strings.Contains(s, "no longer a member"):
		f.Title, f.Message = "Device removed from network", "Please re-join the network with a valid key."
	case strings.Contains(s, "pool is full") || strings.Contains(s, "128 device"):
		f.Title, f.Message = "Network is full", "Remove unused devices or ask an admin to manage members."
	case strings.Contains(s, "password must be at least"):
		f.Title, f.Message = "Join key too short", "Use a join key of at least 8 bytes."
	case strings.Contains(s, "name and password are required"):
		f.Title, f.Message = "Missing network fields", "Both network name and join key are required."
	case strings.Contains(s, "cidr") || strings.Contains(s, "ipv4 private pool"):
		f.Title, f.Message = "Invalid virtual CIDR", "Use an IPv4 prefix inside 10.0.0.0/8 or 100.64.0.0/10."
	case strings.Contains(s, "404") || strings.Contains(s, "endpoint not found") || strings.Contains(s, "decode server response"):
		f.Title, f.Message = "Invalid server response", "Verify the TLAN server root URL and reverse proxy settings."
	case strings.Contains(s, "control service unavailable"):
		f.Title, f.Message = "Lost connection to server", "Check your network connection and server address."
	case strings.Contains(s, "cryptunprotect") || strings.Contains(s, "dpapi"):
		f.Title, f.Message = "Cannot decrypt local settings", "Run under the same Windows user or re-enter your server and key."
	case strings.Contains(s, "ttm_addtool"):
		f.Title, f.Message = "Window initialization failed", "Extract all files from the release archive and try again."
	}
	return f
}

var credentialField = regexp.MustCompile(`(?i)((?:token|password|secret|private_key|authorization)\s*[=:]\s*)([^\s&,;\"\\]+)`)
var authorizationField = regexp.MustCompile(`(?i)(authorization\s*[=:]\s*)([^\r\n,;\"\\]+)`)
var urlCredentials = regexp.MustCompile(`(https?://)[^\s/@]+:[^\s/@]+@`)

func Redact(detail string, secrets ...string) string {
	return RedactLang("zh", detail, secrets...)
}

func RedactLang(lang, detail string, secrets ...string) string {
	mask := "[已隐藏]"
	if strings.EqualFold(strings.TrimSpace(lang), "en") {
		mask = "[redacted]"
	}
	for _, secret := range secrets {
		if secret != "" {
			detail = strings.ReplaceAll(detail, secret, mask)
		}
	}
	detail = authorizationField.ReplaceAllString(detail, "${1}"+mask)
	detail = credentialField.ReplaceAllString(detail, "${1}"+mask)
	return urlCredentials.ReplaceAllString(detail, "${1}"+mask+"@")
}
