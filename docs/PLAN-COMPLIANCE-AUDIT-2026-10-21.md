# FRPC 方案符合性审计报告（2026-10-21）

> 本报告主体是 2026-10-21 14:11 的审计快照，保留用于追踪当时发现的问题。
> 后续修复、最终部署和公网协议矩阵以第 9 节和 `docs/FINAL-PUBLIC-DEPLOYMENT-VERIFICATION-2026-10-21.md` 为准。

## 0. 审计边界与结论摘要

- 工作区：`<REPO_ROOT>`。
- 审计方式：只读代码检查、文档交叉核对、当前工作区编译/非 live 测试、只读哈希与发布物比对。
- 本轮没有使用 `D:/SSH.txt`，没有 SSH 登录、部署、重启服务或修改服务器。
- 除本报告外，没有修改源码、配置、构建脚本或 `dist`。
- 结论：**不能宣称 R0-R5 或“参考项目全部功能”已经完成。**

当前事实应分三层表述：

1. **代码存在且主要生产入口已接通**：FRP Manager、真实 FRPC 子进程、TLS/CA、托管 lease、FRPS 插件、TargetGateway、目标成员审批、托盘/自启动、受限令牌启动、Mesh 资源账本等都有实际入口，不是单纯 UI。
2. **本机测试覆盖较广，但仍有 fake/模型/schema 层**：当前 Windows 非 live 全量测试、Windows/Linux vet、审计回归均通过；真实本机 FRP 和公网记录存在，但没有在本次审计中重新执行 live/公网测试。
3. **发布物和服务器与当前源码并未完全对齐**：最新公网报告明确记录了一个 `internal/frpauth` 修复尚未部署到服务器；`dist` 中的 Caddyfile、FRPS 示例和安装器载荷早于 8444/WSS 变更；部分文档仍与代码相反。

因此，下面所有“已实现”均不自动等于“已真实环境验收”。

## 1. 证据优先级

本次以以下材料为主：

- `docs/FRPC-DEVELOPMENT-ROADMAP-2026-10-21.md`
- `docs/FRPC-INTEGRATION-PLAN.md`
- `docs/ADVANCED-FEATURES-IMPLEMENTATION-2026-10-21.md`
- `docs/CURRENT-CODE-VERIFICATION-2026-10-21.md`
- `docs/SERVER-DEPLOYMENT-VERIFICATION-2026-10-21.md`
- `docs/PUBLIC-MANAGED-FRP-VERIFICATION-2026-10-21.md`
- 当前源码、当前 `dist`、`.tmp-runtime/public-frp-e2e/` 证据和测试文件

后两份服务器报告时间较新，且 `PUBLIC-MANAGED-FRP-VERIFICATION` 明确记录了修复未部署；若旧报告与其冲突，以较新报告和源码实际状态为准。历史报告中的“只剩外部验收”不能作为当前结论。

## 2. R0-R5 四态矩阵

四态定义：

- **已实现代码**：有生产入口，能从 GUI/Manager/服务端 API 走到实际逻辑。
- **已本机测试**：本机测试、审计回归或真实本机 FRP 联调有记录；不等同于公网。
- **真实环境已验证**：有独立服务器、真实公网、真实设备或真实系统资源证据。
- **未实现/外部验收**：代码缺口、未接通、证据不足或只能在外部环境完成。

| 阶段 | 已实现代码 | 已本机测试 | 真实环境已验证 | 未实现 / 外部验收 |
| --- | --- | --- | --- | --- |
| R0 基线 | 固定 FRPC/FRPS/Wintun 哈希检查、Windows/Linux CI 文件、测试拆分、审计回归标签、安装器自检 | 当前 `go test ./...`、Windows/Linux vet、审计回归通过；历史记录有基线脚本通过 | 没有实际 GitHub Actions 运行证据；没有 Linux 原生测试运行证据 | Git 仍无 tracked 文件/首个提交；没有可复现的 commit 基线；发布包未包含全部新审计文档 |
| R1 逻辑缺陷 | F-01/F-02/F-04/F-05/F-06/F-07 主要修复；权限交集回滚、运行意图、动态保留端口、TLAN 双地址池、visitor 隔离、平台测试拆分 | 当前审计回归 F-01/F-02/F-04/F-05/F-06 通过；F-01/F-02 有真实本机 FRPC/FRPS 回归记录 | 只有本机回环/临时 FRPS；没有真实公网权限收紧、真实管理员撤销、真实多用户组合 | 权限上限持久化失败和 secret 比较仍有缺陷；旧进程回调可覆盖新状态；独立 FRP 被过度视为身份依赖；清理错误有遗漏 |
| R2 协调层 | `netpolicy` 观察器/Planner、TCP/UDP 出口代理、Mesh 启动双向预检、运行中 5 秒复检、TargetGateway、Mesh ResourceLedger | 模型/接口/fake observer/本机 FRP live/fake Mesh 测试存在；当前审计回归只覆盖字面地址和计划前缀 | 没有真实 Wintun、真实接口切换、物理 LAN 抓包、第三方 VPN、休眠恢复证据 | 没有事件通知、代次和去抖；没有独立 EndpointRegistry；LAN backend 仍主要做 CIDR 包含检查；没有硬性 worker/socket 全路径证明 |
| R3 真实场景稳定版 | Windows GUI、服务端、FRPS 包、managed 控制面、目标审批、TCP/UDP/HTTP/WSS 部署材料 | 本机安装器自检、UI smoke、非 live 全量测试；历史记录有本机真实 FRP live | 服务器记录有 CentOS 7、公网 TCP 30001、UDP 30002、HTTP vhost、WSS 8444、健康检查、lease 撤销和清理 | 没有两台独立 Windows、真实 Wintun/物理 LAN、真实 Debian、接口切换、24-72 小时长稳；当前服务器未部署最新 frpauth 修复 |
| R4 常用功能体验 | 受限 JSON 导入/导出、批量 TCP/UDP 端口、HTTP locations/Basic Auth/subdomain/Header、目标成员审批窗口、部分诊断 | 批量端口单测、HTTP schema/渲染/真实本机测试、目标审批 store/API 测试、UI smoke | 公网 HTTP vhost 已有记录；没有真实多用户目标审批、没有导入/导出 UI 级验收 | 导入没有差异预览/逐项不支持报告；诊断只覆盖 Mesh，不覆盖 FRP；`allow_users` 未接通客户端模型；发布可用性反馈不完整 |
| R5 长期演进 | 托盘、关闭到托盘、HKCU 自启动、受限令牌 frpc 启动、coreupdate 基础设施、WSS/TCPMUX/XTCP/KCP/QUIC schema 和部分 live | UI smoke、fake 注册表单测、受限令牌证据、本机真实 FRP、coreupdate 单测；历史 WSS 8444 公网验证 | WSS 8444 有公网记录；TCP/UDP/HTTP 公网有记录 | XTCP 双端 P2P、真实登录重启/托盘点击、卸载器、生产更新密钥/更新源/客户端入口、SYSTEM 服务、代码签名和 24-72 小时长稳未完成；`verifyFRPC` 仍是管理员令牌路径 |

## 3. 重点功能逐项核对

### 3.1 高级协议与 HTTP

**代码路径存在：**

- `internal/frp/model.go` 支持 TCP/WebSocket/WSS/KCP/QUIC、TCP/UDP/HTTP/HTTPS/STCP/SUDP/TCPMUX/XTCP、HTTP locations/Basic Auth/subdomain/Header、XTCP visitor 参数。
- `internal/frp/render.go` 实际生成对应 FRP v0.71.1 TOML；KCP/QUIC 通过 UDP 回环中继，TCP 系列通过受限 CONNECT 代理。
- `cmd/client/frp_ui_windows.go` 有服务器传输、规则高级字段和 visitor 编辑入口。

**本机测试：**

- schema、渲染、`frpc verify` 测试存在。
- 历史记录有本机真实 TCP/UDP/WebSocket/KCP/QUIC、HTTP 高级字段、TCPMUX 和 XTCP 授权验证。
- WSS 的旧高级报告曾标记“运行时跳过”；较新的公网记录已记录 8444 WSS managed 回显通过。

**真实环境：**

- 公网记录覆盖 WSS 8444、UDP 30002、HTTP 18080。
- XTCP 只做到配置、启动和授权，没有完整双端 P2P 打洞证据。

**缺口：**

- `allow_users` 存在于 `frpauth.Rule` 和 `frp.LeaseRule`，但 `internal/frp` 的 `Rule`/`Exposure` 没有对应字段，渲染器也不写 `allowUsers`；客户端无法通过正常 GUI 配置它。
- `proxyProtocolVersion` 会渲染到 frpc，但 FRP v0.71.1 的 `NewProxy` 消息没有该字段，FRPS 插件无法在服务端精确观察/授权该值；不能把“managed 精确授权”扩大到这一字段。
- WSS 的服务器安装器和发布包尚未同步 8444 路由与防火墙规则。

### 3.2 managed 精确授权

**代码路径存在：**

- `internal/frpauth` 支持 lease、capability hash、端口/域名配额、撤销、续租、目标服务审批和 FRPS 插件四个操作。
- `internal/control/frp_leases.go` 用服务端成员目录解析目标设备、虚拟 IP、公钥，并拒绝客户端自报目标。
- `internal/frp/manager_windows.go` 会把 `TargetServiceID`、grant ID 和高级字段带入 lease 请求，并校验返回 grant。

**本机测试：**

- `internal/frpauth` 和 `internal/control` 的 in-process 测试覆盖高级 HTTP、TCPMUX、XTCP、目标服务审批和撤销。
- 本机真实 FRPS 测试覆盖 managed HTTP/TCPMUX/XTCP 授权和撤销。
- 公网记录覆盖 managed TCP/UDP/HTTP/WSS，但只有一台 Windows。

**缺口：**

- `cmd/client/frp_mesh_windows.go` 的 `TargetRequest`/`targetgateway.Target` 使用 `rule.ID` 作为 `ServiceID`，没有传播已审批的 `rule.Target.ServiceID`。服务端 lease grant 仍会校验审批 ID，但本机 TargetGateway 的 target identity 不是完整服务授权 ID，诊断和本地绑定语义不完整。
- `internal/frpauth/store.go` 的持久化 lease 结构校验不强制 `mesh_peer.TargetServiceID`；`validateLeaseServicesLocked` 遇到空值直接 `continue`。新 lease 的 `Issue` 会拒绝空值，但旧/伪造持久化 lease 可能绕过目标服务审批。
- `allow_users` 和 `proxyProtocolVersion` 的端到端授权边界如上，不能宣称完整。

### 3.3 目标成员审批

**代码路径存在：**

- `cmd/client/frp_approval_windows.go` 有发布申请、待确认、同意/拒绝/撤销、复制服务 ID。
- `internal/control/frp_services.go` 和 `internal/frpauth/store.go` 有 target/requester 绑定和审批状态。
- 只有目标成员本人能同意/拒绝/撤销；批准前不能签发 `mesh_peer` lease。

**本机测试：**

- `TestTargetMemberApprovalLifecycle`、`TestFRPServiceTargetMemberApprovalAPI` 等 in-process 测试存在。
- 当前全量非 live 测试通过。

**真实环境：**

- 没有两台真实 Windows 的多用户审批记录。

**缺口：**

- `README.md:75` 和 `deploy/frps/README.md:106` 仍说“没有目标成员 B 的逐次弹窗确认”，与当前代码和高级功能报告相反。`dist/frps-package/opt/tlan-frp/README.md` 也沿用了旧文本。
- 没有 UI 自动化测试真正打开并操作审批窗口；现有 UI smoke 只检查按钮存在。

### 3.4 托盘与自启动

**代码路径存在：**

- `cmd/client/tray_windows.go` 创建 `walk.NotifyIcon`、菜单、关闭到托盘和显式退出。
- `cmd/client/startup_windows.go` 只写 HKCU 的 `TLAN` 值，关闭时只删除该值。
- `cmd/client/desktop_windows.go` 有 `--startup` 隐藏启动和 `CloseToTray`/`LaunchAtLogin` 设置。

**本机测试：**

- `tray_windows_test.go` 和 `startup_windows_test.go` 使用 fake store；UI smoke 验证托盘图标、菜单和关闭策略。
- 注册表测试没有污染真实用户启动项。

**真实环境：**

- 没有实际重启 Windows 验证登录启动。
- 没有自动化鼠标点击托盘菜单。
- 没有卸载器集成。

**结论：** 代码入口和本机 smoke 成立；真实登录、Explorer 重启、卸载清理仍属外部验收。

### 3.5 低权限 frpc

**代码路径存在：**

- `internal/winproc` 创建受限令牌，校验用户 SID、Session、Logon Session、完整性、Administrators 组和启用特权。
- `internal/frp/supervisor_windows.go` 的正式 frpc 通过 `winproc.LaunchRestricted` 启动，失败不回退管理员令牌。
- 本机证据记录 child 为 Medium、Administrators deny-only、仅 `SeChangeNotifyPrivilege`。

**关键缺口：**

- `internal/frp/verify_windows.go:21` 的 `verifyFRPC` 使用 `exec.CommandContext`，没有走 `winproc.LaunchRestricted`。也就是说正式进程是受限的，但 `frpc verify` 仍在当前管理员令牌下运行；不能把“所有 frpc 调用都不继承管理员”作为已完成结论。
- 当前机器是内置 Administrator，SAFER 路径的 `TokenElevationFlag=true`；标准用户/UAC linked token 环境没有验证。
- 没有 `-race` 证据。

### 3.6 Mesh 资源账本

**代码路径存在：**

- `internal/platform/resources.go` 持久化实例、所有者、GUID、地址、路由、防火墙、清理状态。
- `internal/mesh/engine.go` 在启动前恢复旧实例，启动/关闭登记和清理 transport 资源。
- `internal/platform/cleanup_windows.go` 按精确名称、GUID、InstanceID、接口、前缀清理。

**本机测试：**

- `resources_test.go`、`cleanup_windows_test.go`、`mesh/resources_test.go` 使用 fake runner/ledger/native NIC 覆盖恢复和失败保留。
- 当前全量非 live 测试通过。

**真实环境：**

- 没有真实 Wintun 管理员权限下的创建/重启恢复/接口删除/防火墙清理证据。
- 没有两台 Windows 的物理 LAN 抓包。

**缺口：**

- `internal/frp/ledger_windows.go:90` 忽略 `terminateOwnedProcess` 的错误，然后删除运行目录；进程仍存活时可能留下孤儿。
- `internal/frp/manager_windows.go` 的启动失败分支多处 `_ = inst.reap()`、`_ = guard.Close()`，清理失败不会进入最终错误。
- `cmd/client/desktop_windows.go:212`、`:216` 的退出路径忽略 `engine.Close()`；`cmd/client/frp_ui_windows.go:1657`、`:1674` 忽略 `Manager.Close()`。正常停止路径有提示，最终退出路径没有完整残留证据。

### 3.7 安全导入导出与批量端口

**已实现：**

- `cmd/client/frp_transfer_windows.go` 使用受限 JSON、文件大小/普通文件检查、`ValidateConfig`，不导入 token/CA 私钥/私有 secret。
- `cmd/client/frp_batch_windows.go` 生成连续 TCP/UDP 规则，并重新走 `ValidateConfig`；有批量端口单测。

**缺口：**

- 导入只在确认框中说明替换，没有按 R4 要求做配置差异预览，也没有逐项报告不支持字段。
- 没有专门针对导入/导出 UI 流程的自动化测试；文件对话框和真实导入路径未被 UI smoke 覆盖。

### 3.8 受控核心更新基础设施

**已实现：**

- `internal/coreupdate` 支持签名清单、SHA-256、大小、版本/平台、HTTPS、原子安装和回滚。
- `cmd/corepack` 提供签名/校验开发工具。

**未实现：**

- 没有生产 Ed25519 公钥、私钥、更新源、发布清单或客户端自动更新入口。
- `cmd/client` 没有导入 `internal/coreupdate`；当前程序不会自动更新 FRPC。
- `build-windows-client.ps1` 仍只打包固定 `frpc.exe`，不包含更新客户端流程。

## 4. 当前确认的代码/发布缺陷（按优先级）

### P0-01 当前服务器二进制没有包含最新 frpauth 修复

证据：

- `docs/PUBLIC-MANAGED-FRP-VERIFICATION-2026-10-21.md:130` 明确写道：源码修复已加入，但**尚未部署到当前公网服务器二进制**。
- 该报告同时记录了一个真实启动故障：撤销测试 lease 后，缩小 `allowed_domains` 会让控制面在加载历史 lease 时启动失败。
- 当前 `dist/linux/TLAN-server` SHA-256 为 `0CC56851A648088D61D9447852AD28D6B96F6E6D599D713FF6F7FF2168B2C922`，而 `.tmp-runtime/public-frp-e2e/TLAN-server-fixed` 为 `ABF2DBAD56F0228070E448CF2E9420A7AC820E109AB72333FD7FA84AD3C21423`。后者是修复构建，不是当前发布包。
- `docs/SERVER-DEPLOYMENT-VERIFICATION-2026-10-21.md` 的 5.7.7 也明确要求重新构建发布物。

影响：当前公网验证证明“旧版本可用”，不能证明“当前源码已部署”。在缩小域名/端口白名单后，旧服务器存在启动失败风险。

### P0-02 dist 发布物与当前 WSS 部署不一致

证据：

- `deploy/Caddyfile` 已包含 8444 WSS 路由；`dist/linux/Caddyfile` 仍是旧版，不含 8444。
- `deploy/Caddyfile` SHA-256 为 `83ED0816BCF6BEC64FAA887FF8895EF3EDA381D587B9F338463B4C056D84655F`；`dist/linux/Caddyfile` 为 `120059FEA802AA4CC28129D6E67839B636210B7D0FBE013C4AEA5564C8ED9576`。
- `deploy/frps/frps.toml.example` 已改为 `transport.tls.force = false`；`dist/frps-package/opt/tlan-frp/frps.toml.example` 仍是 `true`。
- `deploy/install-server.sh:211` 和 `:217` 的防火墙端口仍只有 `80/tcp 8443/tcp 3478/udp`，没有 8444。
- `.tmp-build/server-installer-payload/Caddyfile` 仍是旧文件；`dist/TLAN-server-linux-amd64.run` 和 `dist/TLAN-server-debian-amd64.zip` 构建于该旧载荷。
- `dist/SHA256SUMS.txt` 与旧包自洽，但不能证明它们对应当前源码。

影响：新用户按当前发布包安装不会自动获得 WSS 8444 路由；FRPS 示例会与服务器实际 WSS 设置冲突；安装器不会自动放行 8444。这是发布阻断项，不是“外部验收”。

### P0 发布模板一致性修复（后续状态，2026-10-21）

状态：**代码、模板、安装脚本和本地发布包已修复；未部署，真实公网组合未验证。**

- 主 FRPS 模板新增 `kcpBindPort = 7002`、`quicBindPort = 7003`、
  `tcpmuxHTTPConnectPort = 18081`、`subDomainHost = "frp.example.com"`。
- WSS 回环实例新增 `vhostHTTPPort = 18082`、`vhostHTTPSPort = 18444`、
  `tcpmuxHTTPConnectPort = 18083` 和同一 subdomain 根；仍只监听 `127.0.0.1:7001`
  且 `transport.tls.force = false`。
- 主 FRPS 保持 `transport.tls.force = true`，主/WSS vhost 与 TCPMUX 端口不冲突。
- 独立 FRPS 安装器会校验实际配置并默认更新 firewalld/UFW，保留已有 `/etc` 配置；
  旧配置不匹配固定端口矩阵时，`--start` 会拒绝启动而不是覆盖配置。
- `scripts/verify-frps-templates.ps1` 执行固定字段、TCP/UDP 监听冲突、防火墙列表和发布包复制范围检查；
  存在可运行固定版本二进制时执行真实 `frps verify`。
- `build-debian-server.ps1` 已纳入校验，并把 `docs/FRPS-DEPLOY.md` 打入 FRPS 发布包。

仍待：将新包部署到真实服务器，验证 7002/7003、18081/18083、18082/18444 的公网组合、
云安全组和 WSS + HTTP/HTTPS/TCPMUX 的真实端到端行为。
### P1-01 权限上限的 secret 比较和持久化失败处理不闭合

证据：

- `internal/frp/manager_windows.go:943` 的 `limitToRuntimeCeiling` 调用 `previousAllowedByNext(cfg, *ceiling, "", "", nil, nil)`。
- `previousAllowedByNext` 对带 `SecretRef` 的规则/visitor 调用 `sameSecretValue`；传入 nil secret map 时值比较失败。
- 因此，带私有 secret 的规则可能在权限上限重载时被错误丢弃，或整个 Start 被误判为无可用运行项。
- `restoreAfterApplyFailure` 在 `ceilingErr != nil` 时仍可能恢复 `rollback` 并返回运行中的状态；这违反“撤销意图持久化失败时停止相关运行”的 fail-closed 要求。
- `ApplyWithSecrets` 成功路径调用 `m.setRuntimeCeiling(nil)` 时忽略返回值（`:1093`、`:1137`），删除失败会留下旧权限上限。

影响：在磁盘错误、ACL 错误或带 secret 的规则上，可能出现错误的启动/停止行为，或旧权限上限残留。

### P1-02 旧 frpc 进程回调可能覆盖新实例状态

证据：

- `internal/frp/manager_windows.go:1605` 的 `watchProcess` 在进程退出后只条件性清除 `m.instance`，随后无条件执行 `m.state = "failed"` 和写 `lastErr`。
- 如果旧实例退出回调晚于新实例 commit，它可以把新实例的全局状态改成 failed，并可能触发额外重试路径。

影响：Start/Apply/Stop 快速交错时，GUI 状态和重试行为可能不一致；这正是 R1 要求“旧回调不得覆盖新修订/新实例”的场景。

### P1-03 独立 FRP 被错误当作 Mesh 身份依赖

证据：

- `internal/frp/manager_windows.go:257` 的 `RequiresIdentityStop` 对任何 `instance`、`desiredRun` 或 `waiting_dependency` 都返回 true。
- `cmd/client/desktop_windows.go` 的 join/leave/identity 检查使用该结果。
- 对 `private_token` 的独立回环/LAN 配置，代码没有区分它是否真的绑定 TLAN 网络。

影响：独立 FRP 运行时可能阻止加入/切换/退出网络，与 R1 的“身份切换只阻止真正依赖旧身份的运行”不一致。`UpdateMembership` 也在 `instance != nil` 时无条件拒绝。

### P1-04 TargetGateway 未完整传播已审批服务 ID，旧 lease 可能绕过审批

证据：

- `cmd/client/frp_mesh_windows.go:75`、`:83`、`:88` 使用 `rule.ID` 作为 `ServiceID`，没有使用 `rule.Target.ServiceID`。
- `internal/frpauth/store.go:335` 的 `validateLoadedRecord` 用 `validateRules(..., false)`；`internal/frpauth/model.go:877` 的 `normalizeTargetGrant` 不要求 `mesh_peer.TargetServiceID`。
- `internal/frpauth/store.go:1153` 的 `validateLeaseServicesLocked` 在 `TargetServiceID == ""` 时直接继续。

影响：新 lease 由 `Issue` 拒绝空服务 ID，但旧持久化 lease 或伪造/损坏状态可能不经过目标成员审批；本机 TargetGateway 也不携带已审批服务 ID。服务端 grant 检查仍是主要防线，但本地身份绑定和诊断语义不完整。

### P1-05 启动失败和最终退出路径的清理错误未汇总

证据：

- `internal/frp/manager_windows.go:1502`、`:1517`、`:1527` 对 `inst.reap()` 使用 `_ =`。
- `internal/frp/manager_windows.go:1432`、`:1439`、`:1450`、`:1462` 忽略 guard 关闭错误。
- `cmd/client/desktop_windows.go:212`、`:216` 忽略 Mesh engine 关闭错误；`cmd/client/frp_ui_windows.go:1657`、`:1674` 忽略 FRP Manager 关闭错误。
- `internal/frp/ledger_windows.go:90` 忽略进程终止错误后删除运行目录。

影响：正常 Stop 路径的提示较好，但启动失败、异常退出和最终关闭可能留下未报告的进程/文件/资源，违反 R2 的清理错误可诊断要求。

### P1-06 配置事务回滚本身可能失败但被忽略

证据：

- `internal/frp/store.go:190` 的 rollback 调用 `restoreFile`，后者在 `:227` 忽略 `writePrivateFile` 的返回错误。
- CA、secrets、profile 是分步替换，不是单次原子事务。

影响：磁盘满、ACL 变化、文件被占用时，可能出现 CA/secret/profile 版本不一致，而调用方只看到原始保存错误。应增加回滚失败聚合和明确的 `CLEANUP_INCOMPLETE`/事务失败状态。

### P2-01 R2 仍是轮询和字面目标检查，不是完整协调层

证据：

- `internal/frp/manager_windows.go:600` 启动 ticker，`:613` 的 `watchEgress` 每 5 秒检查一次；没有 Windows 接口/路由变更通知、去抖或 observer generation。
- `internal/netpolicy/observer_windows.go` 只在每次调用时解析并 `GetBestInterfaceEx`；没有事件订阅。
- 没有独立 EndpointRegistry；只有 `Manager.ReservedTargets()` 和 `desktop.frpReservations()` 的临时汇总。
- LAN backend 主要用 `targetInsidePrefixes` 做 CIDR 包含判断，没有为每个 LAN target 记录实际 route/source interface。
- 固定核心仍通过回环 CONNECT/UDP relay 约束出口；没有 worker 级别的所有拨号点证明。

影响：R2 只能称为“有轮询复检和局部 socket 约束”，不能称为完整的 NetworkObserver/ConflictPlanner/EndpointRegistry 协调层。

### P2-02 文档仍有与代码相反的陈述

证据：

- `README.md:75` 说没有目标成员逐次确认 UI；但 `cmd/client/frp_approval_windows.go` 和 `internal/frpauth` 已实现。
- `deploy/frps/README.md:106` 同样说没有逐次确认；`dist/frps-package/.../README.md` 沿用了旧文本。
- `VALIDATION.md:168` 仍说 F-03 失败；同文件顶部和当前审计回归已通过 F-03 字面/计划路径检查。
- `VALIDATION.md` 较早的“P4 XTCP/KCP/QUIC/WSS 未实现”与当前高级功能报告冲突；该段没有清楚标记为历史段落。
- `docs/ADVANCED-FEATURES-IMPLEMENTATION-2026-10-21.md:26` 说 WSS 运行时跳过；较新的公网报告已记录 8444 WSS 通过。
- `cmd/server` 的 status 仍硬编码 `version: "0.2.0"`（`internal/control/server.go:88`），而客户端/文档使用 v0.6.0；这不是功能缺陷，但会让版本审计混乱。

影响：审计人员和用户无法从文档判断哪条是当前状态；必须把历史段落标记为历史，并同步最新结论。

### P2-03 R4 诊断和导入体验未达到方案描述

证据：

- `cmd/client/desktop_windows.go:709` 的 `diagnose` 只调用 `a.engine.Diagnostics()`，要求 Mesh engine 存在；没有 FRP snapshot、lease、路由、出口、日志和 TargetGateway 汇总。
- `cmd/client/frp_transfer_windows.go:125` 只有“将替换当前配置”的确认，没有差异预览或逐项不支持字段报告。
- 目标审批窗口没有 UI 自动化测试；批量端口有单测但没有完整授权链路 UI 测试。

影响：R4 的“诊断导出”和“受限导入预览”仍只能算部分实现。

### P2-04 服务器验证记录是可信的“记录”，但不是本次独立复核

已记录的真实公网结果包括：

- CentOS 7 上部署控制面和 FRPS 0.71.1；
- managed TCP 30001、UDP 30002、HTTP vhost 18080、WSS 8444 回显；
- TLS、health、STUN、lease status、撤销和临时成员清理。

但：

- `PUBLIC-MANAGED-FRP-VERIFICATION` 明确只有一台 Windows，未完成两台 Windows Mesh 联调；
- 没有物理 LAN 抓包、接口切换、真实 Debian 主机、24-72 小时长稳；
- 没有本次重新执行 SSH 验证；
- 报告没有提供完整原始命令流，部分结论只能作为记录接受；
- 最新 frpauth 修复没有部署，因此服务器记录不能代表当前源码。

### P2-05 缺少 race 和部分真实资源证据

- 当前环境没有 CGO/gcc，未执行 `go test -race`。
- Mesh 资源账本测试使用 fake native/runner/ledger，不能替代真实 Wintun、路由、防火墙和管理员权限验证。
- TargetGateway 测试覆盖 fake Mesh provider；真实虚拟接口绑定仍需外部证据。

## 5. 下一批最优先开发项（按可独立交付和文件范围分组）

### 批次 A：发布完整性（最优先，先做）

范围：

- `deploy/Caddyfile`
- `deploy/frps/frps.toml.example`
- `deploy/frps/README.md`
- `deploy/install-server.sh`
- `build-debian-server.ps1`
- `build-server-installer.ps1`
- `build-windows-client.ps1`
- `README.md`、`VALIDATION.md`、`docs/FRPC-DESKTOP-COVERAGE.md`
- `dist`（只在代码冻结后重建）

工作：

1. 把 8444 加入 Linux 安装器防火墙列表和安装说明。
2. 用当前 `deploy/Caddyfile`、`deploy/frps/frps.toml.example`、README 重建 ZIP/tar.gz/.run。
3. 把 `SERVER-DEPLOYMENT-VERIFICATION`、`PUBLIC-MANAGED-FRP-VERIFICATION`、`CURRENT-CODE-VERIFICATION`、`FRPC-DEVELOPMENT-ROADMAP`、`FRPC-INTEGRATION-PLAN` 按交付策略加入发布文档或明确排除。
4. 重建后重新生成 `dist/SHA256SUMS.txt`，记录源码快照/构建时间和二进制哈希。
5. 把历史文档中的旧结论标为“历史/已被新报告取代”。

验收：

```powershell
./build-debian-server.ps1
./build-server-installer.ps1 -Offline
./test-server-installer.ps1
# 比对 deploy/Caddyfile 与 dist/linux/Caddyfile、dist 载荷 Caddyfile 哈希
# 比对 deploy/frps/frps.toml.example 与 dist/frps-package 示例哈希
# 检查安装器包含 8444/tcp
```

### 批次 B：R1 运行状态和权限上限（源码正确性）

范围：

- `internal/frp/manager_windows.go`
- `internal/frp/store.go`
- `internal/frp/ledger_windows.go`
- `internal/frp/verify_windows.go`
- `internal/frp/supervisor_windows.go`
- 对应 `*_test.go`、`audit_manager_windows_test.go`

工作：

1. `limitToRuntimeCeiling` 解析/传入旧、新 secret；增加带 secret 的权限上限回归。
2. `restoreAfterApplyFailure` 在权限上限持久化失败时停止相关运行；不要以“running + error”收尾。
3. `setRuntimeCeiling(nil)` 的返回值必须处理；失败时保留/停止并提示。
4. `watchProcess` 只在 `m.instance == inst` 时更新全局 state/lastErr，避免旧回调覆盖新实例。
5. `RequiresIdentityStop`/`UpdateMembership` 区分 `private_token` 独立配置与 Mesh/managed 依赖。
6. `verifyFRPC` 使用同一受限令牌路径，或明确记录“验证进程仍为管理员”的产品限制。
7. 汇总启动失败、最终退出和 recoverLedger 的清理错误。

验收：

```powershell
go test -mod=vendor ./internal/frp -count=1
go test -mod=vendor -tags frp_audit_regression ./internal/frp -run TestAuditRegression -count=1 -v -timeout 180s
go test -mod=vendor ./... -count=1 -timeout 240s
go vet -mod=vendor ./...
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go vet -mod=vendor ./...
```

### 批次 C：R2 协调层

范围：

- `internal/netpolicy/`
- `internal/frp/manager_windows.go`
- `internal/frp/egress*.go`
- `cmd/client/desktop_windows.go`
- `internal/targetgateway/` 相关测试

工作：

1. 增加接口/路由变更通知或明确的轮询边界文档；为 observer 增加 generation、去抖和旧事件丢弃。
2. 为每个 LAN target 记录实际 route/source interface，而不是只做 CIDR 包含检查。
3. 增加 EndpointRegistry，登记 admin、visitor、TargetGateway、代理监听和归属。
4. 处理 Mesh 启动失败/停止后的 CIDR 状态回滚或明确保留策略。
5. 用真实 Windows 测试 `IP_UNICAST_IF`、接口重建、VPN、Wi-Fi/有线切换。

验收：

```powershell
go test -mod=vendor ./internal/netpolicy ./internal/frp ./internal/targetgateway -count=1
go test -mod=vendor -tags frp_audit_regression ./internal/frp -run TestAuditRegression -count=1 -v
# 外部：真实 Wintun、接口切换、物理 LAN 抓包、两台 Windows
```

### 批次 D：R4 体验与高级授权

范围：

- `internal/frp/model.go`、`render.go`、`validate.go`
- `internal/frpauth/model.go`、`store.go`
- `cmd/client/frp_transfer_windows.go`
- `cmd/client/frp_ui_windows.go`
- `cmd/client/frp_approval_windows.go`
- `cmd/client/desktop_windows.go`

工作：

1. 为导入实现 diff 预览和逐项不支持字段报告；增加 UI 级导入/导出测试。
2. 增加 FRP 诊断导出，覆盖 FRP snapshot、lease、FRP route、TargetGateway、日志和证书结果。
3. 决定是否正式开放 `allow_users`；若开放，补模型、渲染、UI、lease、插件和真实测试。
4. 对 `proxyProtocolVersion` 明确标注“客户端本地字段，FRPS 插件不可观察”，不要纳入 managed 精确授权声明。
5. 修正 README/FRPS README/部署包中的目标成员审批旧文本。

验收：

```powershell
go test -mod=vendor ./internal/frp ./internal/frpauth ./cmd/client -count=1
go run -mod=vendor ./cmd/client --ui-smoke-test .tmp-runtime/audit-ui-smoke.txt
# 外部：真实目标成员审批、公网 vhost、WSS/XTCP 专项
```

### 批次 E：R3/R5 真实环境验收

这些不能由本机命令替代：

1. 两台独立 Windows，经真实公网 FRPS 测试 Mesh 直连/中继 × FRP TCP/UDP/HTTP/HTTPS/STCP/SUDP。
2. 真实 Wintun、物理 LAN 抓包、同地址冲突、接口禁用/重建、Wi-Fi/有线切换、休眠恢复、第三方 VPN。
3. 真实 Debian/systemd 安装、升级、回滚和证书续期。
4. 真实 XTCP 双端 P2P 和 WSS 外部代理（WSS 已有公网记录，但需发布包复验）。
5. 24-72 小时混合负载、句柄/内存/进程/路由/防火墙残留趋势。
6. Windows 登录自启动、托盘鼠标操作、卸载器清理。
7. 生产 Ed25519 密钥、更新源、客户端更新入口、签名安装包和回滚演练。
8. 在具备 gcc/CGO 的环境补 `go test -race`。

## 6. 建议的发布门槛

在下列条件全部满足前，不应把项目标记为“R0-R5 完成”或“全部功能已搬入”：

- `dist` 与源码哈希、Caddyfile、FRPS 示例、安装器 8444 规则一致。
- 当前服务器部署包含最新 frpauth 修复，并有可复核的二进制哈希。
- F-01/F-02 的权限上限 secret/持久化失败回归通过。
- 独立 FRP 不阻塞身份切换，旧进程回调不覆盖新实例。
- 低权限声明与 `verifyFRPC` 实际令牌路径一致。
- 至少两台独立 Windows、真实 Debian、真实 Wintun/物理 LAN 和 24-72 小时记录完成。
- 生产自动更新、代码签名、卸载器和 SYSTEM/无人登录服务未完成时，文档明确标注。

## 7. 本次实际执行的检查

本轮在当前 Windows 工作区执行了：

```text
go test -mod=vendor ./... -count=1 -timeout 240s             PASS
go vet -mod=vendor ./...                                    PASS
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go vet -mod=vendor ./... PASS
go test -mod=vendor -tags frp_audit_regression ./internal/frp -run TestAuditRegression -count=1 -v -timeout 180s PASS
```

未执行：

- 真实本机 FRP live 测试（本轮没有重跑；历史记录有证据）
- 公网/SSH 复验（按要求不部署、不重启）
- `go test -race`（当前环境没有可用 CGO/gcc）
- 真实 Wintun/物理 LAN/双 Windows/24-72 小时长稳

因此，本报告的“本机测试通过”仅指上述当前命令；“真实环境已验证”只引用服务器报告和 `.tmp-runtime` 证据，不扩大为本次独立复核。

## 8. 最终判断

历史快照的结论是（已被第 9 节取代）：

> **主要 FRPC 客户端/服务端功能代码已实现，当前工作区非 live 测试和静态检查通过，公网 managed FRP 的 TCP/UDP/HTTP/WSS 有记录；但 R1 仍有运行状态/权限上限/清理缺口，R2 仍不是完整协调层，R3 缺少双机和长稳，R4 的导入预览与 FRP 诊断不完整，R5 的生产更新/服务化/卸载/XTCP 打洞未完成；同时当前服务器和 dist 发布物没有包含最新源码修复。**

这比“只剩外部环境验收”更准确，也符合最新 `PUBLIC-MANAGED-FRP-VERIFICATION` 的明确记录。

## 9. 2026-10-21 15:35 当前状态更新

本节覆盖前文已经过时的结论。

### 9.1 已完成的代码与发布修复

- P2-01 的独立 EndpointRegistry 已实现：登记 admin、visitor、TargetGateway、TCP/UDP egress 监听，包含 profile/实例代次/规则或 visitor 归属，并在 Manager 启动、停止和失败路径接入。
- P2-01 的 generation/去抖已实现：`netpolicy.ObservationDebouncer` 提供单调代次、两次稳定确认、旧 generation 丢弃和诊断状态。当前仍以轮询为唯一变更来源，没有接入 Windows 接口/路由事件通知；这一边界已写入代码注释和验证文档。
- P2-03/R4 的 FRP 诊断已实现：`cmd/client/frp_diagnostics_windows.go` 统一导出 snapshot、EndpointRegistry、route observation、managed lease、egress、TargetGateway、日志、CA/TLS 结果，输出 JSON 和文本并做凭据/私钥脱敏。
- 受限导入差异预览、逐项不支持字段报告和 `allow_users` 模型/渲染/UI/lease/插件路径已接通。
- `proxyProtocolVersion` 已明确标注为客户端本地 TOML 字段，FRPS 插件不可观察，不纳入 managed 精确授权声明。
- 未入网时 managed lease provider 会先创建，入网后按“先更新 Manager、成功后再更新 provider”的顺序绑定身份；修复首次使用和失败回滚时的身份错配。
- frpauth 续租现在保证到期时间严格前进，避免时钟粒度导致的偶发续租回归。
- 目标成员逐次同意/拒绝/撤销 UI 已存在；README、FRPS 部署文档中的旧“没有逐次确认”文本已修正。

### 9.2 发布模板与公网部署

- 主 FRPS 已增加 UDP 7002/7003（KCP/QUIC）、TCP 18081（TCPMUX）和 `subDomainHost`。
- WSS FRPS 已增加 TCP 18082/18444（HTTP/HTTPS vhost）、TCP 18083（TCPMUX）和 `subDomainHost`。
- 主 FRPS 仍 TLS-only；WSS FRPS 仍只监听 `127.0.0.1:7001`。
- 最新服务端二进制已部署到 `<SERVER_IP>`，SHA-256 为 `0eab75c8924b0a650cae23744785d000a4ced78404551fc7163b76b37e62a0bd`。
- 2026-10-21 已建立首个 Git 提交基线；发布产物和临时验证目录保持忽略。
- 2026-10-22 已完成 R2 Windows 网络变更通知、R4 完整诊断服务端上传和 FRP 持久化日志轮转；真实 `--adapter-smoke-test` 发现并修复 CLIXML 输出污染、非 GUID 防火墙身份和适配器不存在退出码三个生产缺陷，修复后 Wintun 创建/地址/路由/防火墙/清理全部通过。
- 2026-10-22 仍只有单物理上游，真实双 Windows、独立 NAT、XTCP 打洞和 24–72 小时长稳仍未验证。
- 真实公网 managed 回归已通过：TCP、WebSocket、KCP、QUIC、主/WSS TCP、HTTP、HTTPS、TCPMUX；停止后的端口/路由清理、lease 撤销、临时成员删除和配置 SHA 恢复均通过。

### 9.3 仍不能宣称完成

- 真实两台独立 Windows、真实 Wintun、物理 LAN 抓包、Wi-Fi/有线切换、第三方 VPN、休眠恢复。
- XTCP 双端真实打洞。
- 24–72 小时长稳和资源泄漏趋势。
- Windows SYSTEM/无人登录服务、生产自动更新签名、HTTPS 更新源、代码签名和卸载器。
- `go test -race`（当前环境无可用 CGO/gcc）。
- 自定义域名 HTTPS 的生产证书 SAN/浏览器信任仍需按实际域名配置；当前公网 FRPS 证书只有 IP SAN，HTTPS 组合测试验证的是端口、SNI 路由和 TLS 透传链路。

### 9.4 当前结论

> **P1/P2/P3 主要功能和本轮 P0 发布一致性修复已进入生产路径，当前源码全量测试、审计回归、真实本机 FRP live 测试和真实公网协议矩阵通过；但 R3/R5 的双机、真实网卡/长稳、XTCP 打洞、SYSTEM 服务和生产自动更新仍未完成，不能标记为 R0–R5 全部完成或“参考项目全部功能已搬入”。**