# 应用流量转发（Egress）验证记录

日期：2026-11-09。对应计划：`docs/superpowers/plans/2026-11-09-app-egress-forwarding.md`。

结论：**显式代理模式（explicit proxy）已端到端打通，可交付试用**；**透明按进程转发尚未实现**，需要签名的 WFP 组件。因此不满足计划的"完全转发"完成判定。

## 已交付组件

| 组件 | 位置 | 说明 |
| --- | --- | --- |
| 客户端核心 | `internal/egress` | 模型/校验/独立存储/DPAPI 秘密、`TLNE` v1 协议（ChaCha20-Poly1305 + 方向独立 HKDF）、两步握手（固定握手密钥 → capability 派生会话密钥）、目标前导、TCP/UDP 会话、网关侧会话 |
| 网关核心 | `internal/egressgateway` | 租约签发/续租/撤销/校验（一次性 capability 只存 SHA-256）、目标策略（私网/回环/链路本地/元数据/管理端口拒绝）、连接与字节配额、Lease HTTP API、nftables/iptables NAT 生命周期（产品标记、精确回滚、恢复 `ip_forward`） |
| 网关二进制 | `cmd/egress-gateway` | 独立 Linux 服务：严格 YAML 配置、`-check`/`-print-plan`、TLS 数据面、租约 API、NAT 启动/回滚 |
| 显式代理 helper | `cmd/egress-helper` | 回环 SOCKS5（CONNECT/UDP ASSOCIATE），TLS + CA 固定、fail-closed；**明确标注为显式代理模式** |
| GUI 第三页 | `cmd/client/egress_page_windows.go` + 导航接线 | "应用流量转发"页：状态/服务器/代理地址、规则表、服务器设置、应用规则增删改、启动/停止、复制代理地址；顶部横幅注明透明模式未启用 |
| 打包 | `build-windows-client.ps1` | 客户端 ZIP 内置 `runtime/egress/egress-helper.exe` 与 Egress 文档 |
| 部署骨架 | `deploy/egress/` | systemd unit、配置示例（CAP_NET_ADMIN、仅回环 lease API、产品标记规则） |

## 验证结果（真实执行）

```text
gofmt -l cmd/egress-gateway cmd/egress-helper cmd/client internal/egress internal/egressgateway → 无输出
go vet -mod=vendor ./cmd/egress-gateway ./cmd/egress-helper ./cmd/client ./internal/egress ./internal/egressgateway → 0
go test -mod=vendor ./cmd/egress-gateway -count=1   → ok
go test -mod=vendor ./cmd/egress-helper  -count=1   → ok
go test -mod=vendor ./internal/egress    -count=1   → ok（含 net.Pipe 客户端↔网关 TCP 端到端，以及握手拒绝/目标阻断）
go test -mod=vendor ./internal/egressgateway -count=1 → ok
go test -mod=vendor ./... -count=1 -timeout 900s    → 全部 ok
GOOS=linux GOARCH=amd64 go build ./cmd/egress-gateway ./cmd/egress-helper → 0
build-windows-client.ps1                            → 成功，ZIP 含 runtime/egress/egress-helper.exe（6,474,752 字节）
发布 EXE --ui-smoke-test                            → PASS（断言第三页、显式代理横幅、规则表）
```

环境说明：本机 `C:\Windows\Temp` 的 ACL 会让 `internal/frp` 与 `internal/winproc` 的受限令牌测试报 `Access is denied`（既有问题）。把 `TEMP`/`TMP` 指向工作区内目录后，全量测试全绿。未运行 `-race`（无 gcc）。

## 明确未完成（不满足计划完成判定）

| 计划要求 | 状态 |
| --- | --- |
| 目标 exe 的 TCP/UDP **透明**从后端公网 IP 出口 | ❌ 需要签名 WFP callout 驱动；当前只有显式 SOCKS5 代理 |
| 非目标 exe 不受影响（按进程） | ❌ 同上；显式模式下由应用是否配置代理决定 |
| DNS/IPv6 无静默泄漏 | ⚠️ 策略层已 fail-closed；透明数据面未接入 |
| 断线/撤销不回退直连 | ✅ helper 在会话不可用时拒绝代理连接；透明模式未接入 |
| Linux NAT 真实主机验证 | ❌ 仅 fake-runner 命令测试与 Linux 交叉编译 |
| 三模块同时工作 | ⚠️ GUI 已并列展示；显式代理与 Mesh/FRP 并行未做真机联合验收 |
| 崩溃/重启/卸载/升级清理 | ⚠️ 设计已定；helper 清理与安装器回滚未验证 |
| 跨公网真实双机验收 | ❌ 未执行 |

## 关键限制

1. **透明转发必须依赖签名内核组件。** 计划明确：未有可用且签名的 WFP 实现前，不得宣称透明转发完成。当前 GUI 与文档均显式标注"显式代理模式"。
2. **租约 API 目前由独立网关提供**，尚未接入既有控制面（经批准的方案，避免改动既有服务端行为）。
3. **真实 Linux/NAT 与公网验收**需要真实主机。

## 下一步

①获取签名的 WFP/驱动组件并实现 helper 的透明捕获；②真实 Linux 主机部署 `cmd/egress-gateway` 并验证 NAT 回滚；③跨公网双机验收（目标/非目标应用对比、UDP、断线、撤销）；④可选：把租约 API 接入既有控制面。
