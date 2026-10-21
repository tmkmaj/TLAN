# FRPC 功能覆盖与一致性报告

- 生成日期：2026-10-21（Asia/Shanghai）
- 对照对象：`luckjiawei/frpc-desktop`、`fatedier/frp v0.71.1`、`docs/FRPC-INTEGRATION-PLAN.md`
- 当前 TLAN：Windows 原生 GUI + 固定版独立 `frpc.exe` 子进程 + TLAN 控制面托管授权 + P3 TargetGateway

## 0. 结论

TLAN 已把方案要求的 P1、P2、P3 主体真正接入代码和运行链路，而不是只增加 UI：

- P2 有设备级发布租约、端口/域名配额、FRPS 插件校验、续租、撤销和成员删除联动。
- P3 有 `mesh_peer`/`mesh_self` 目标授权、TargetGateway TCP/UDP 数据面、generation/lease 失效检查、Windows 虚拟接口绑定和依赖暂停/恢复。
- 固定版 FRP 的真实本机联调已覆盖 TCP/UDP、HTTP/HTTPS、STCP/SUDP、visitor、托管 lease 和 TargetGateway。

TLAN 已完成主要协议、高级 HTTP、TCPMUX/XTCP、目标成员审批、托盘/自启动、低权限 frpc 和 Mesh 资源账本；仍不是 `frpc-desktop` 的逐项全量复制，任意插件、VirtualNet、原始 TOML、自定义核心、SYSTEM 服务和生产自动更新仍未开放。

## 1. frpc-desktop 已有、TLAN 尚无（按阶段）

### P1 范围

| frpc-desktop 能力 | TLAN 当前状态 | 说明 |
| --- | --- | --- |
| TCP/UDP/HTTP/HTTPS/STCP/SUDP 规则 | 已实现 | 与固定版 v0.71.1 字段一致 |
| visitor、serverName/serverUser/secretKey/bindPort | 已实现 | visitor 只绑定回环地址 |
| 服务器地址/端口、token、TLS、日志、运行状态 | 已实现 | token 文件、强制 CA、管理 API、日志脱敏 |
| 多服务器配置 | 已实现 | 每配置独立 store、token、CA、规则和 frpc 进程 |
| 规则表格、启停、错误提示 | 已实现 | 原生 GUI，风格与现有 TLAN 页面一致 |
| 原始 TOML 导入/导出 | 有意不支持 | 已实现受限 TLAN JSON 导入/导出；任意 TOML 透传仍禁止 |
| frpc 版本下载/切换 | 基础设施已实现 | `internal/coreupdate` + `cmd/corepack` 支持签名清单和原子安装；客户端入口、生产公钥/更新源未接入 |
| 开机启动/后台常驻 | 已实现当前用户级 | 托盘、关闭到托盘、HKCU 登录自启动；SYSTEM 服务和无人登录运行未实现 |

### P2 范围

| frpc-desktop 能力 | TLAN 当前状态 | 说明 |
| --- | --- | --- |
| 物理 LAN IPv4 目标 | 已实现 | 显式地址策略校验，不做公网/LAN 自动回退 |
| HTTP/HTTPS 自定义域名 | 已实现 | 使用 `customDomains` 和 vhost 端口 |
| STCP/SUDP visitor | 已实现 | 访问器只绑定 `127.0.0.1` |
| HTTP locations、basic auth、subdomain、header rewrite | 已实现 | 受严格 schema 和 managed 精确授权约束 |
| 批量端口规则 | 已实现 | 连续端口生成独立规则，仍逐条校验和授权 |
| 插件（static_file、socks5、https2http 等） | 有意不支持 | 明确拒绝，避免插件绕过目标网关 |
| 托管设备授权/配额/撤销 | 已实现 | lease + capability + FRPS Login/NewProxy/Ping/NewUserConn 插件 |
| 多用户/metadata 配置 | 部分 | 有稳定的 client user/metadata，但不提供 frpc-desktop 的任意用户配置编辑 |

### P3 范围

| 能力 | TLAN 当前状态 | 说明 |
| --- | --- | --- |
| 发布 TLAN 成员服务 | 已实现 | `mesh_peer` + TargetGateway；跨成员需管理员登记目标服务 ID |
| 发布本机虚拟地址服务 | 已实现 | `mesh_self`，校验本机设备、虚拟 IP 和 generation |
| 目标身份/公钥绑定 | 已实现 | 服务端目录校验网络、设备、公钥、虚拟 IP；lease 保存 grant |
| 目标成员逐次人工确认 | 已实现 | 发布者申请、目标成员同意/拒绝/撤销，批准前不能签发 lease |
| 真实双机/Wintun/物理 LAN 抓包 | 未验证 | 本机 fake-provider 和单元测试通过，真实硬件验收仍待完成 |

### P4/高级范围

当前状态：

- XTCP、TCPMUX、QUIC、KCP、WebSocket 已实现；WSS 已通过公网 Caddy 8444 的 managed 端到端回显，并完成 WSS TCP/HTTP/HTTPS/TCPMUX 组合验证；XTCP 双端打洞仍待真实网络验收。
- HTTP locations、Basic Auth、subdomain、Header rewrite 已实现。
- 托盘常驻、关闭到托盘、当前用户登录自启动已实现。
- 受管 frpc 已使用 Medium 完整性、Administrators deny-only 的受限令牌启动。
- Mesh 资源账本、异常恢复和诊断提示已实现。
- 安全 JSON 配置导入/导出和批量端口规则已实现。
- 受控核心更新基础设施已实现，但生产签名密钥、更新源和客户端更新入口未接入。

仍有意不支持或未完成：

- 任意 FRP 插件、VirtualNet、virtual_net visitor；
- 未校验原始 TOML、自定义/任意替换核心；
- SYSTEM 服务、无人登录后台运行；
- 生产自动更新、代码签名、密钥轮换和发布回滚；
- 双机、XTCP 打洞和 24–72 小时长稳。

## 2. TLAN 有意不支持项

- 不在 GUI 中导入 FRP Go 包，不把 TLAN 配置直接当 frpc TOML 使用。
- 不允许跳过 TLS 证书校验或使用明文回退。
- 不按进程名结束 `frpc.exe`，避免误杀用户自行运行的进程。
- 不开放 VirtualNet 和任意插件；这些能力会绕过 TLAN 的目标/路由约束。
- 不把共享 token 当作设备级授权；`private_token` 与 `managed` 明确区分。
- 不承诺 frpc-desktop 的全部功能等价；P4 能力需要单独设计、授权和验收。

## 3. 当前与 FRP v0.71.1 的字段一致性

已核对并用于真实联调：

- 服务器：`serverAddr`、`serverPort`、`user`、`loginFailExit`；
- token：`auth.method = "token"`、`auth.tokenSource.type = "file"`、`auth.tokenSource.file.path`；
- TLS：`transport.tls.enable`、`serverName`、`trustedCaFile`；
- 管理 API：`webServer.addr/port/user/password/pprofEnable`；
- 规则：`name/type/localIP/localPort/remotePort/customDomains/secretKey`；
- visitor：`name/type/serverName/serverUser/secretKey/bindAddr/bindPort`；
- 托管元数据：`metadatas.tlan_lease`、`metadatas.tlan_capability`、`metadatas.tlan_server`。

托管 capability 不再作为 TOML 明文值写入，而是通过受限环境变量模板注入；日志会脱敏 capability。 `transport.proxyURL` 由受管认证出口代理动态注入，只接受精确 FRPS 主机/端口并钉住非 TLAN 接口。

外部 FRPS 可通过 GUI 配置 `transport.tcpMux` 和 `transport.tls.disableCustomTLSFirstByte`，默认开启；它们必须与 FRPS 实际配置一致。

## 4. 当前声称已实现但需保留边界的事项

1. **外部 FRPS 插件能力**：TLAN 会读取控制面 lease status，确认 FRPS 已观察到 Login 和 proxy；这仍依赖控制面与 FRPS 的部署一致性，部署必须核对四个插件操作和 FRPS 日志。
2. **真实 P3 路由**：代码已使用虚拟接口索引绑定和本机源地址校验；仍需两台独立 Windows + Wintun 抓包证明同地址物理 LAN 不会回退。
3. **撤销 SLA**：本机真实联调已证明 5 秒续租下 10 秒内停止；公网高延迟/断网场景仍需单独测量。
4. **目标成员审批**：发布者申请、目标成员同意/拒绝/撤销和 requester 绑定均已实现；真实多用户网络仍需外部验收。
5. **权限隔离**：GUI 仍要求管理员权限，但受管 frpc 已使用 Medium 完整性、Administrators deny-only 的受限令牌启动；SYSTEM 服务未实现。

## 5. 需要真实联调才能证明的项目

- 公网 FRPS、真实域名、DNS、云安全组和主机防火墙；
- Debian 实机 systemd 部署、重启、升级和回滚；
- 两台独立 Windows 的 Mesh 直连/强制中继 × FRP TCP/UDP/HTTP/HTTPS/STCP/SUDP；
- 物理 LAN 同地址冲突、网卡禁用/重建、Wi-Fi/有线切换、休眠唤醒；
- 成员删除、IP 变化、公钥变化、授权撤销的真实端到端 SLA；
- 24–72 小时混合负载、句柄/内存/孤儿进程/路由残留；
- 外部 FRPS 插件启用的独立验证。

## 6. 最终一致性结论（2026-10-21）

- TLAN 的 P1/P2/P3 主体不是“只有 UI”：托管 lease、FRPS 插件校验、续租/撤销、成员删除联动、TargetGateway、`mesh_peer`/`mesh_self`、虚拟接口绑定和依赖暂停/恢复均已接入真实代码路径。
- 与固定版 FRP v0.71.1 的配置字段一致；真实本机联调已通过 TCP/UDP、HTTP/HTTPS、STCP/SUDP、visitor、托管 lease、运行中 Apply、撤销 SLA、TargetGateway 和未观察到插件时拒绝启动。
- 托管客户端通过控制面 lease status 确认 FRPS 已观察到 Login 和 proxy；这不是对 FRPS 二进制的独立度量，部署仍需核对 `httpPlugins` 四个操作和 FRPS 日志。
- 与 `frpc-desktop` 的主要剩余差异：XTCP 双端打洞尚未真实验收；任意插件、VirtualNet、原始 TOML、自定义核心、SYSTEM 服务、生产自动更新和代码签名仍未开放。
- 仍不能宣称完成的验收：真实 Debian 主机、两台独立 Windows、物理 LAN 抓包、Mesh/FRP 四组合、24–72 小时长稳。
- 最终 Windows 客户端为 v0.6.0；原生 UI smoke PASS。最终运行时代码快照上，全量 `go test -mod=vendor ./... -count=1`、`go vet -mod=vendor ./...` 和全部固定版 FRP live tests 均通过；发布包已重建并生成 `dist/SHA256SUMS.txt`。

## 7. 代码位置

- `internal/frp/`：受限配置模型、渲染、管理 API、进程监督、租约 watchdog、TargetGateway 接入、受限出口代理；
- `internal/netpolicy/`：实际路由观察、冲突规划和接口钉住拨号；
- `internal/frpauth/`：设备级 lease、配额、capability hash、FRPS 插件；
- `internal/targetgateway/`：TCP/UDP 回环目标网关、会话隔离、统计；
- `internal/mesh/target.go`、`target_route_windows.go`：Mesh 目标身份、generation 和接口绑定；
- `cmd/client/frp_ui_windows.go`：P2/P3 GUI；
- `cmd/client/frp_lease_windows.go`、`frp_mesh_windows.go`：客户端授权/Mesh 适配；
- `cmd/server/main.go`、`internal/control/frp_leases.go`：服务端托管授权 API 和插件 listener。
