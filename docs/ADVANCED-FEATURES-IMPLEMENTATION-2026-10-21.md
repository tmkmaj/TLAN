# 高级功能实现与验证报告

日期：2026-10-21（Asia/Shanghai）  
工作目录：`D:/RadminLanPrivate`

本报告记录在 R1/R2 修复之后完成的高级能力批次。状态严格区分：

- **代码已实现**
- **本机测试/真实本机 FRP 联调通过**
- **真实公网/双机/生产发布验收未完成**

## 1. 本轮新增能力

### 1.1 FRP 高级协议与 HTTP 配置

已接入固定 FRP v0.71.1：

- 服务器传输：TCP、WebSocket、WSS、KCP、QUIC。
- 代理类型：TCP、UDP、HTTP、HTTPS、STCP、SUDP、TCPMUX、XTCP。
- visitor：STCP、SUDP、XTCP。
- HTTP/HTTPS：customDomains、subdomain、locations、Basic Auth、Host Header rewrite、routeByHTTPUser、请求/响应 Header。
- 规则 transport：useEncryption、useCompression、proxyProtocolVersion。`proxyProtocolVersion` 只写入本地 frpc TOML，FRP v0.71.1 的 FRPS 插件无法观察，因此不纳入 managed 精确授权声明。
- 受管 FRP 日志持久化到每个 profile 的 `logs/frp.log`，默认 2 MiB/5 文件/8 MiB 上限，轮转并继续脱敏；完整 FRP 诊断可上传到控制面，服务端再次校验和脱敏。
- XTCP visitor：protocol、keepTunnelOpen、重试参数、fallback。
- KCP/QUIC 使用本机回环 UDP 出口中继，仍执行实际路由观察和接口绑定。

WSS 的上游限制：固定 FRPS 没有直接 TLS→WebSocket 监听路径，必须部署外部 TLS→WebSocket 反向代理。2026-10-21 已通过公网 Caddy 8444 的真实 managed WSS 端到端回显验证，并完成 WSS TCP、HTTP subdomain、HTTPS vhost 和 TCPMUX 组合验证；主 FRPS 7000 保持 TLS-only，独立 127.0.0.1:7001 FRPS 负责 WSS 回源，详见 `docs/FINAL-PUBLIC-DEPLOYMENT-VERIFICATION-2026-10-21.md`。

XTCP 已通过配置、启动和 FRPS 插件授权验证；完整双端 P2P 打洞需要 STUN 和两个真实网络端点，仍属外部验收。

### 1.2 Managed FRPS 高级授权

managed lease 现在精确授权：

- TCPMUX、XTCP；
- subdomain、locations；
- HTTP Basic Auth 用户与密码哈希；
- Host Header rewrite、routeByHTTPUser；
- request/response headers；
- multiplexer、allow_users；
- useEncryption、useCompression；
- XTCP/STCP/SUDP secret 哈希。

密码和 proxy secret 仍保存在本地 DPAPI secret store；lease 请求和持久化状态只包含 SHA-256 哈希。FRPS 插件在内存中计算哈希并做常量时间比较，不把明文写入磁盘或日志。

### 1.3 目标成员授权

新增完整流程：

1. 发布者选择目标成员，提交服务发布申请。
2. 目标成员在“目标授权”窗口查看待确认项。
3. 目标成员同意、拒绝或撤销。
4. 只有目标成员确认且 requester 匹配时，才允许创建 managed mesh_peer lease。
5. 拒绝/撤销会联动撤销引用该服务的 lease。
6. 发布者可查看自己发起申请的状态并复制服务 ID。

相关 API：

```text
POST /api/v1/frp/services/requests
GET  /api/v1/frp/services/pending
GET  /api/v1/frp/services/requested
POST /api/v1/frp/services/{id}/approve
POST /api/v1/frp/services/{id}/deny
POST /api/v1/frp/services/{id}/revoke
```

### 1.4 客户端常驻体验

- 原生 Walk 托盘图标与菜单。
- 托盘可显示窗口、启停 Mesh、启停当前 FRP 配置、打开设置、退出。
- 默认关闭窗口仍直接退出；可显式开启“关闭时最小化到托盘”。
- 托盘不可用时安全回退到直接退出，避免窗口隐藏后无法恢复。
- 登录自启动使用当前用户 `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`。
- 只写本程序值 `TLAN`，关闭时只删除该值。
- `--startup` 隐藏窗口并驻留托盘。
- 不创建 SYSTEM 服务，不跨用户，不修改其他启动项。

### 1.5 低权限 FRPC

受管 frpc 不再继承管理员令牌启动。Windows 启动器会：

- 优先使用当前用户 UAC linked token；
- 其次使用 SAFER normal-user 令牌；
- 最后使用 `CreateRestrictedToken`；
- 将完整性限制为 Medium 或更低；
- 验证用户 SID、Session、Logon Session、完整性、Administrators deny-only 状态和启用特权；
- 验证失败时终止挂起进程并 fail-closed，绝不回退管理员令牌。

本机证据：

```text
parent: High, Administrators enabled
child:  Medium, Administrators disabled/deny-only,
        privileges=[SeChangeNotifyPrivilege]
```

`TokenElevationFlag` 在当前内置 Administrator 的 SAFER 回退路径仍为 true，但实际管理员组和特权已受限。若要求该布尔值也必须为 false，需要在标准用户/UAC linked-token 环境验证。

### 1.6 Mesh 资源账本

新增持久化 `mesh-resources.json`，记录：

- 实例 ID、所有者、Wintun GUID；
- 地址、MTU、metric、广播/组播路由；
- 防火墙规则 InstanceID；
- WireGuard/plain transport；
- 清理状态、错误和更新时间。

启动时只清理能够通过实例、所有者、精确名称/前缀和系统 GUID/InstanceID 证明属于本程序的资源。无法证明的记录只报告，不猜测删除。清理失败保留账本供下次幂等重试，并在 GUI 和诊断中提示。

### 1.7 配置与批量操作

- 安全导入/导出 TLAN 受限 JSON 配置；文件不包含 token、CA 私钥、HTTP 密码或私有 secret。
- 批量添加 TCP/UDP 连续端口规则，仍执行完整配置校验和服务器授权。
- 不开放未校验原始 TOML 透传。

### 1.8 受控核心更新基础设施

新增 `internal/coreupdate` 和 `cmd/corepack`：

- Ed25519 签名清单；
- SHA-256、大小、版本、平台、时间校验；
- HTTPS 同主机重定向限制；
- 原子安装、安装后复验和失败回滚；
- 维护端签名/验证工具。

**尚未接入客户端自动更新入口**，且没有生产签名密钥、生产公钥、更新源或发布清单。因此当前程序不会自动更新 FRPC。

## 2. 本机验证

已通过：

```text
go test -mod=vendor ./... -count=1 -timeout 360s
go vet -mod=vendor ./...
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go vet -mod=vendor ./...
go test -mod=vendor -tags frp_audit_regression ./... -count=1
```

真实本机 FRP v0.71.1 联调通过：

- TCP、UDP、WebSocket、KCP、QUIC；
- 公网 Caddy 8444 的 managed WSS；
- HTTP/HTTPS 高级字段；
- TCPMUX HTTP CONNECT；
- managed HTTP advanced、TCPMUX、XTCP 授权；
- 既有 managed lease、撤销、回滚、依赖停止；
- 低权限 frpc 启动。

明确跳过：

- XTCP 完整双端打洞，因为需要 STUN 和两个真实网络端点。

未运行 `-race`，当前环境没有 CGO/gcc。

### 2.1 当前构建产物

- Windows 客户端：v0.6.0
- EXE：`dist/windows/TLAN.exe`
- EXE SHA-256：以 `dist/SHA256SUMS.txt` 为准
- 四个发布归档的最新摘要以 `dist/SHA256SUMS.txt` 为准。
- 客户端包内 `frpc.exe` 固定摘要仍为 `509F4FA082BF9B85F9AD27B45D37A89A8ACCB011F3B724CFF352DFAC90A94FEB`。

## 3. 仍然不能宣称完成的事项

- 两台独立 Windows、真实 Debian。
- 真实 Wintun/物理 LAN 抓包、接口切换、休眠恢复、第三方 VPN。
- XTCP 双端打洞。
- 24–72 小时稳定性、资源泄漏和 race。
- Windows SYSTEM 服务、无人登录后台运行。
- 生产自动更新签名密钥、HTTPS 更新源、客户端更新入口和回滚演练。
- 代码签名、自动发布、密钥轮换和撤回流程。
- 任意插件、VirtualNet、未校验原始 TOML、自定义核心仍按安全边界禁止。

## 4. 结论

本轮已经把此前列出的主要客户端功能实现到可运行、可回归的代码路径：

- 高级协议/HTTP 配置；
- managed 高级授权；
- 目标成员审批；
- 托盘/自启动；
- 低权限 frpc；
- Mesh 资源账本；
- 安全配置导入导出和批量端口；
- 更新基础设施。

但“生产自动更新”“SYSTEM 服务”“真实公网/双机/长稳验收”仍未完成，不能把本报告当作完整生产发布验收。