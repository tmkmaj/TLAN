# 应用流量转发模块实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在现有 `TLAN.exe` 中增加与“虚拟网卡组网”和“FRPC 端口映射”并列的“应用流量转发”模块，使指定 Windows 应用的网络流量经过指定 Linux 后端服务器出网。

**Architecture:** GUI 继续集成在现有 EXE 中；按进程捕获、连接状态和隧道数据面由独立的 `egress-helper.exe` 或 Windows 服务承担。客户端连接独立的 Linux Egress Gateway，服务端负责认证、解封装、IP 转发和 SNAT。Mesh、FRPC、Egress 使用独立的 profile、runtime、租约、状态机和停止清理流程。

**Tech Stack:** Go、现有 Walk/Win32 GUI、Windows Filtering Platform（正式透明转发）、现有加密传输基础、Linux amd64、systemd、nftables/iptables、vendor 依赖。

**Spec:** 本计划即实施规格；背景参考 `FEATURE-AUDIT.md`、`README.md`、`docs/FRPC-INTEGRATION-PLAN.md` 和 `VALIDATION.md`。

## Global Constraints

- 模块名称为“应用流量转发”，代码包使用 `egress`，不要把它实现成 FRPC 的特殊模式。
- Mesh、FRPC、Egress 必须独立启动、停止、失败和恢复；一个模块停止不得级联停止另两个模块。
- Egress 使用独立 profile、runtime、日志、秘密和租约；停止时清理自己的 helper、WFP 规则、接口、路由和临时文件。
- 正式目标是 TCP/UDP 按应用透明转发；DNS、IPv6、QUIC 必须有明确策略，禁止静默绕过。
- Egress 断线、租约撤销或 helper 异常时默认 fail-closed，匹配应用不得自动回退本地直连。
- 服务端必须限制目标网段、云元数据地址、管理端口、连接数和带宽，禁止变成开放代理。
- 不使用普通默认路由冒充按应用转发；按进程选择必须使用 WFP 或受支持的网络重定向机制。
- 所有 Go 命令使用 `-mod=vendor`；每个阶段先写测试，再实现，再运行最小测试和全量回归。

## 可实现性结论

功能可实现，但它是新的网络数据面，不是 FRPC 页面增加一个开关。当前项目可以复用设备身份、控制面、加密隧道经验、诊断、Windows 网络事件和 Linux 部署框架；当前缺少按进程捕获、Egress Gateway、Linux NAT、DNS/IPv6 策略和绕过防护。正式路线采用 WFP + 用户态 helper + Linux Egress Gateway。SOCKS5/HTTP 代理可用于早期联调，但不能作为“完整应用流量转发”的完成标准。

## 产品边界

目标：

- 左侧导航增加“应用流量转发”，不要求先启动 Mesh。
- 支持按 exe 路径添加、编辑、删除、启动和停止规则，并可选择是否包含子进程。
- 指定应用的 TCP/UDP 流量通过后端公网出口；显示出口服务器、隧道状态、流量和错误。
- 支持租约撤销、断线阻断、网络变化、崩溃恢复和完整清理。

首版不做：

- Radmin 私有协议兼容；
- 把 FRPS 改成通用代理；
- 无限制访问服务器内网、云元数据或管理端口；
- IPv6 静默直连；若首版不支持 IPv6，必须阻断并在 UI 明示；
- 多服务器负载均衡、计费和复杂策略语言。

## 模块与文件边界

客户端核心：

- 新建 `internal/egress/model.go`：`EgressProfile`、`AppRule`、`EgressPolicy`、`EgressState`、`EgressSnapshot`。
- 新建 `internal/egress/validate.go`：`ValidateProfile`、`ValidateRule`；拒绝相对路径、重复规则、非法地址和不明确 IPv6 策略。
- 新建 `internal/egress/store.go`：独立持久化，原子写入，秘密沿用现有安全存储但不复用 FRP 明文文件。
- 新建 `internal/egress/protocol.go`：版本化帧、握手、keepalive、关闭原因和最大帧长度。
- 新建 `internal/egress/session.go`：`Start(ctx, Profile, Policy) error`、`Stop(ctx) error`、`Snapshot() EgressSnapshot`；Start/Stop 幂等。
- 新建 `internal/egress/manager_windows.go`：desired/observed reconcile、helper、WFP、租约、诊断和网络事件。
- 新建 `internal/egress/helper_windows.go`、`wfp_windows.go`、`cleanup_windows.go`；提供非 Windows stub 和单元测试。
- 新建 `cmd/client/egress_page_windows.go`、`egress_route_windows.go`；GUI 只负责页面和 manager 调用，不实现数据面。
- 修改现有导航、设置和 UI smoke：增加第三个页面，状态必须来自 snapshot，编辑需要停止规则的字段在运行中禁用。

服务端：

- 新建 `internal/egressgateway/model.go`、`auth.go`、`policy.go`、`session.go`、`nat_linux.go`、`nat_other.go`。
- 新建或修改 `internal/control/egress.go`、`internal/control/server.go`：独立 egress lease 的创建、续租、查询和撤销。
- 修改 `cmd/server/main.go`、systemd 和安装脚本：能力检测、转发/NAT、回滚和 `--check`。
- 新建 `deploy/egress/README.md`：内核转发、出口接口、云安全组、日志、限制和卸载。

文档和发布：

- 新建 `docs/EGRESS-DESIGN.md`、`docs/EGRESS-VALIDATION.md`、`docs/EGRESS-SECURITY-REVIEW.md`。
- 修改 `README.md`、`VALIDATION.md`、Windows/Linux 构建脚本和发布清单，只有真实验证后才能写入通过结论。

## 关键接口

```go
type Manager interface {
    Start(ctx context.Context, ruleID string) error
    Stop(ctx context.Context, ruleID string) error
    UpsertRule(ctx context.Context, rule AppRule) error
    DeleteRule(ctx context.Context, ruleID string) error
    Snapshot(ruleID string) EgressSnapshot
}

type WFPController interface {
    Apply(ctx context.Context, rule AppRule, endpoint netip.AddrPort) error
    Remove(ctx context.Context, ruleID string) error
    Snapshot(ctx context.Context, ruleID string) (WFPState, error)
}
```

协议帧必须先校验 magic、版本和长度，再分配内存；数据帧必须绑定已认证 session，拒绝未知类型、错误 session、重放和伪造源 IP。建议格式为 `magic(4)|version(1)|type(1)|flags(2)|sessionID(16)|streamID(8)|payloadLen(4)|payload|tag`。

Lease API 建议为：

- `POST /api/v1/egress/leases`
- `POST /api/v1/egress/leases/{id}/renew`
- `POST /api/v1/egress/leases/{id}/revoke`
- `GET /api/v1/egress/leases/{id}`

Lease 必须绑定 device、profile/rule、策略版本、有效期、目标策略、连接/字节额度和 gateway endpoint。过期或撤销后续租必须失败，数据会话必须在规定 SLA 内停止。

## 实施任务

### Task 1：冻结模型、验证和状态机

**Files:** `internal/egress/model.go`、`validate.go`、对应测试、`docs/EGRESS-DESIGN.md`。

- [ ] 定义 `stopped/starting/running/degraded/stopping/error/blocked` 状态。
- [ ] 定义规范化 exe 路径、规则唯一性、子进程策略、IPv4/IPv6/DNS/KillSwitch 策略。
- [ ] 测试相对路径、空路径、重复规则、非法地址、模糊 IPv6 和非法状态转换。
- [ ] 运行 `go test -mod=vendor ./internal/egress -count=1`。

### Task 2：独立配置和秘密存储

**Files:** `internal/egress/store.go`、对应测试、现有配置路径代码。

- [ ] profile/rule 与 Mesh、FRP 分目录保存，原子写入，限制权限。
- [ ] 缺失配置加载为空状态，不能隐式启动；覆盖损坏 JSON、并发写、重启恢复和秘密脱敏。
- [ ] 运行 egress 和现有 settings 测试。

### Task 3：服务端租约、认证和策略

**Files:** `internal/control/egress.go`、`internal/egressgateway/{model,auth,policy}.go`、对应测试。

- [ ] 实现创建、续租、查询、撤销；绑定设备和 rule/profile。
- [ ] 拒绝错误设备、过期/撤销 lease、伪造源地址、私网/回环/链路本地/元数据目标和超额连接。
- [ ] 运行 `go test -mod=vendor ./internal/control ./internal/egressgateway -count=1`。

### Task 4：版本化协议和 TCP/UDP session

**Files:** 客户端 `protocol.go/session.go`，服务端 `egressgateway/session.go`，对应测试。

- [ ] 实现有界帧解析、认证握手、TCP stream open/data/close、UDP datagram、返回流量、keepalive 和重连。
- [ ] 测试恶意长度、错误版本、并发 Close、半关闭、重连和传输中撤销 lease。
- [ ] 先通过协议/session 测试，再接 Windows 网络层。

### Task 5：Linux Gateway 和 NAT 生命周期

**Files:** `nat_linux.go`、`nat_other.go`、`cmd/server/main.go`、systemd/installer、`deploy/egress/README.md`。

- [ ] 增加能力检测、启动/停止和恢复原有 forwarding 状态。
- [ ] 安装带产品标记的 nftables/iptables 规则，绝不 flush 无关规则；验证安全接口和地址。
- [ ] 测试 dry-run、缺少工具、重复启停、异常回滚和保留无关防火墙规则。
- [ ] 在真实 Linux 主机通过前，不更新文档为已部署。

### Task 6：Windows helper 和 WFP

**Files:** `helper_windows.go`、`wfp_windows.go`、`cleanup_windows.go`、非 Windows stub、构建脚本。

- [ ] 定义并版本化 helper IPC；复用 Job containment、受限环境和崩溃检测。
- [ ] 按规范化 exe 路径匹配，明确子进程规则；为控制面、gateway、localhost 和清理流量建立 bypass。
- [ ] 实现 IPv4/IPv6 行为与策略一致；helper 注册失败时不得放行匹配应用直连。
- [ ] 测试 helper 崩溃、注册失败、旧规则、Stop 竞态、接口变化和强制终止后的清理。
- [ ] 未有可用且签名的 WFP 实现前，不得宣称透明转发完成。

### Task 7：Windows Egress Manager

**Files:** `manager_windows.go`、对应测试、客户端启动/关闭 wiring。

- [ ] 实现每条 rule 独立 instance、lease、helper、runtime 和 watcher。
- [ ] 处理 Start/Stop 与 lease revoke、helper exit、网络变化、依赖重试并发。
- [ ] 旧 watcher 不得覆盖新实例；Stop 必须和发布 child/helper 使用同一锁。
- [ ] 测试启动失败清理、停止竞态、重启、多规则和断线 fail-closed。

### Task 8：第三个 GUI 页面

**Files:** `cmd/client/egress_page_windows.go`、`egress_route_windows.go`、导航/设置/UI smoke。

- [ ] 增加“应用流量转发”入口、空状态、添加/编辑规则、启动/停止、删除和错误详情。
- [ ] 显示实际 snapshot 状态、出口服务器、DNS/IPv6/KillSwitch 策略；运行中禁用需要停止的编辑项。
- [ ] UI smoke 覆盖导航、规则编辑、停止/运行/错误状态，且不访问服务器、不创建真实网卡。

### Task 9：真实端到端验证

**Files:** egress integration tests、`deploy/tests/egress-gateway-test.sh`、验证文档。

- [ ] 使用真实 Linux gateway 和 Windows client 验证目标应用公网 IP 为 gateway 出口 IP。
- [ ] 同时运行目标和非目标应用，证明只有目标应用改变出口。
- [ ] 验证 TCP、UDP、长连接、重连、DNS、IPv6 策略、lease revoke 和 gateway 断线不回退直连。
- [ ] 验证 Mesh、FRPC、Egress 并行运行不会互相停止、改路由或破坏清理。
- [ ] 记录命令、环境、哈希、时间和未覆盖项。

### Task 10：安全、打包和发布门槛

**Files:** 构建/安装器、`README.md`、`THIRD-PARTY-NOTICES.md`、安全审查文档。

- [ ] helper/driver 只使用固定版本和哈希校验的发布物；验证签名、安装回滚和卸载。
- [ ] 日志脱敏 token、lease secret、私钥和 payload；服务端阻断内网/元数据访问。
- [ ] 验证客户端被杀、服务重启、卸载和升级回滚后的资源清理。
- [ ] 运行全量测试、Windows/Linux vet/build、安装器测试、UI smoke、真实 Windows/Linux Egress 验证后，才更新完成状态。

## Review Focus

- helper 或 gateway 失败时，目标应用必须被阻断，不能本地回退。
- 非目标应用必须继续走正常网络；用两个进程同时验证。
- DNS 和 IPv6 必须遵循策略，不能出现静默泄漏。
- exe 路径、重启、改名和子进程匹配必须稳定。
- Stop、重连、lease revoke、网络变化和强制终止下必须无旧 watcher 覆盖和残留规则。

## 完成判定

只有同时满足以下条件才算完成：EXE 显示三个独立模块；Egress 可不启动 Mesh 独立运行；目标 exe 的 TCP/UDP 经验证从后端公网 IP 出口；非目标 exe 不受影响；DNS/IPv6 无静默泄漏；断线和撤销不回退直连；服务器 NAT 和防火墙变更可回滚；三个模块可同时工作；崩溃、重启、卸载和升级后资源可清理；全量测试、构建、UI smoke、真实 Windows 和真实 Linux 证据齐全。

## 风险与实现决策

- WFP/驱动与签名是 Windows 端最大风险；不得用全局默认路由替代按应用捕获。
- 建议 Egress 使用独立虚拟接口或独立逻辑隧道，不能修改 Mesh 的默认路由；需要单独验证 MTU 和接口切换。
- SOCKS5/HTTP 只能作为原型或联调工具，正式 UI 必须标记能力边界。
- 后端变成网络出口后，必须加入限速、目标过滤、审计和运行监控。
- IPv6 方案必须在实现前确定；只转 IPv4 而放任 IPv6 直连不符合“完全转发”。
