# 应用流量转发（Egress）验证记录

日期：2026-11-10。对应计划：`docs/superpowers/plans/2026-11-09-app-egress-forwarding.md`。

结论：**显式 SOCKS5 代理模式（explicit proxy）已端到端打通，可交付试用**；**透明按进程转发尚未实现**，需要签名 WFP 组件。因此不满足计划的“完全转发”完成判定。

## 已交付组件

| 组件 | 位置 | 说明 |
| --- | --- | --- |
| 客户端核心 | `internal/egress` | 模型/校验/独立存储/DPAPI、TLNE v1 协议（ChaCha20-Poly1305 + 方向独立 HKDF）、两步握手、目标前导、TCP/UDP 会话、协议不匹配拒绝 |
| 网关核心 | `internal/egressgateway` | 租约一次性 capability、目标策略、连接/字节配额、Lease API、nftables/iptables NAT 生命周期 |
| 网关二进制 | `cmd/egress-gateway` | 独立 Linux 服务：严格 YAML、`-check`/`-print-plan`、TLS 数据面、租约 API、NAT 启动/回滚 |
| 显式代理 helper | `cmd/egress-helper` | 回环 SOCKS5（CONNECT/UDP ASSOCIATE），TLS + CA 固定，fail-closed；明确标注显式代理模式 |
| GUI 第三页 | `cmd/client/egress_page_windows.go` | 状态/服务器/代理地址、规则表、服务器设置、应用规则增删改、启动/停止、复制代理地址；顶部横幅注明透明模式未启用 |
| 侧栏 refinement | `cmd/client/ui_windows.go`、`controls_windows.go`、`drawing_windows.go` | 72px 侧栏、44px 导航目标、选中/悬停/按下态、MSAA/UIA selected 状态、DPI 焦点环、可访问描述 |
| 部署骨架 | `deploy/egress/` | `egress-gateway.yaml.example`、systemd unit、CAP_NET_ADMIN 与显式代理限制说明 |
| 打包 | `build-windows-client.ps1` | 客户端 ZIP 内置 `runtime/egress/egress-helper.exe` 与 Egress 文档 |

## 2026-11-10 本轮修复

- 修复 TCP/UDP 协议绕过：TCP 流目标前导必须是 `tcp`，UDP 数据报目标前导必须是 `udp`；拨号前拒绝不匹配并新增两条交叉测试。
- 严格 YAML 示例改为 `deploy/egress/egress-gateway.yaml.example`；默认路径与 systemd `ExecStart` 统一为 YAML。
- 新增示例配置加载测试，UnknownFields、多文档、硬拒绝和 IPv6 策略均有回归覆盖。
- `deny_private`/`deny_metadata` 配置为 false 现在会直接拒绝；网关 CLI 只接受 `ipv6_policy: "block"`。
- Egress 页改为顶部对齐；空状态和规则表不再悬在窗口中部。
- 侧栏保留白蓝视觉世界，补齐当前页 accessibility selected 状态、准确的更多操作/版本信息描述、DPI 焦点环、高对比度系统配色和独立按下反馈。
- 修复窄窗口/最小尺寸下 Egress 内容布局；实际截图覆盖 Power、FRP、Egress 三条主页面。

## 验证结果（真实执行）

```text
gofmt -l cmd/client cmd/egress-gateway cmd/egress-helper internal/egress internal/egressgateway
→ 无输出

go vet -mod=vendor ./cmd/egress-gateway ./cmd/egress-helper ./cmd/client ./internal/egress ./internal/egressgateway
→ exit 0

go test -mod=vendor ./cmd/egress-gateway ./cmd/egress-helper ./cmd/client ./internal/egress ./internal/egressgateway -count=1
→ 全部 ok

go test -mod=vendor ./... -count=1 -timeout 900s
→ exit 0，全部包通过

go test -mod=vendor ./cmd/egress-gateway -run TestExampleConfigLoads -count=1 -v
→ PASS

go test -mod=vendor ./internal/egress -run 'TestGatewaySessionRejects' -count=1 -v
→ PASS（含 TCP/UDP 协议不匹配拒绝）

GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -mod=vendor -trimpath -o .tmp-build/linux/ ./cmd/egress-gateway ./cmd/egress-helper
→ exit 0

go test -mod=vendor ./cmd/client -count=1
→ ok

& .\build-windows-client.ps1
→ 成功，生成 dist/TmkNetworkLAN-client-windows-amd64.zip

发布窗口 EXE --ui-smoke-test
→ PASS（三页导航、显式代理横幅、规则表、托盘/关闭策略/绘制初始化；不创建网卡、不访问服务器）

实际窗口截图
→ docs/screenshots/sidebar-refinement-2026-11-10.png
→ docs/screenshots/egress-explicit-proxy-2026-11-10.png
→ docs/screenshots/sidebar-focus-2026-11-10.png
```

环境说明：本机 `C:\Windows\Temp` 的 ACL 会让 `internal/frp` 与 `internal/winproc` 的受限令牌测试报 `Access is denied`；把 `TEMP`/`TMP` 指向工作区内目录后，全量测试全绿。未运行 `-race`（当前环境无可用 gcc/clang）。

## 明确未完成（不满足计划完成判定）

| 计划要求 | 状态 |
| --- | --- |
| 目标 exe 的 TCP/UDP **透明**从后端公网 IP 出口 | ❌ 需要签名 WFP callout 驱动；当前只有显式 SOCKS5 代理 |
| 非目标 exe 不受影响（按进程） | ❌ 同上；显式模式下由应用是否配置代理决定 |
| DNS/IPv6 无静默泄漏 | ⚠️ 网关 CLI 的 IPv6 只允许 block；`dns_servers` 当前是 DNS 目标白名单，目标 hostname 仍使用系统 resolver；透明数据面未接入 |
| 断线/撤销不回退直连 | ✅ helper 在会话不可用时拒绝代理连接；透明模式未接入 |
| Linux NAT 真实主机验证 | ❌ 仅 fake-runner 命令测试与 Linux 交叉编译 |
| 三模块同时工作 | ⚠️ GUI 已并列展示；显式代理与 Mesh/FRP 并行未做真机联合验收 |
| 崩溃/重启/卸载/升级清理 | ⚠️ 设计已定；helper 清理与安装器回滚未验证 |
| 跨公网真实双机验收 | ❌ 未执行 |

## 关键限制

1. **透明转发必须依赖签名内核组件。** 未有可用且签名的 WFP 实现前，不得宣称透明转发完成。GUI 与文档均明确标注“显式代理模式”。
2. **独立租约 API 默认绑定 loopback。** 显式配置 HTTPS hostname 监听属于操作员选择；系统未自动把它限制为 loopback。部署者必须限制网络访问并保护 bearer secret。
3. **`max_rate_bps` 尚未实际限速。** 连接数和累计字节配额已强制执行；速率只记录在租约中。
4. **自定义 DNS resolver 尚未实现。** `dns_servers` 是允许的 DNS 目标地址集合；目标 hostname 解析使用网关主机系统 resolver。
5. **真实 Linux/NAT 与公网验收**需要真实主机与客户端。本机 Windows 结果不能替代。

## 下一步

①获取签名的 WFP/驱动组件并实现透明捕获；②真实 Linux 主机部署 `cmd/egress-gateway` 并验证 NAT 回滚；③跨公网双机验收（目标/非目标应用对比、UDP、断线、撤销）；④可选：把租约 API 接入既有控制面；⑤实现自定义 DNS resolver 与实际 `max_rate_bps` 限速。