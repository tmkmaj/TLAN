# FRP P2/P3 只读审计报告

- 审计日期：2026-10-21（Asia/Shanghai）
- 审计目录：`D:/RadminLanPrivate`
- 审计方式：只读检查源码、固定 FRP v0.71.1 源码/示例、`stilleshan/frpc`、`luckjiawei/frpc-desktop`，并运行本机测试。
- 审计边界：本报告不修改源码；唯一新增文件为本文。没有公网、Debian 实机、两台独立 Windows、物理 LAN 抓包或长期稳定性验证。

## 0.1 后续修复复核（2026-10-21）

本报告第 2、3 节保留首次审计快照；其中以下问题已在后续代码中修复，并由全量测试/真实 FRP 联调复核：

- P2-01：托管运行中 Apply 先停止旧实例、撤销旧 lease，再申请新 lease；失败路径会重新申请旧 lease 并恢复旧配置。
- P2-02：客户端已实现真实 `/renew`、5 秒续租 watchdog、终止错误识别和停止联动。
- P2-03：FRPS 插件增加 `Ping`/`NewUserConn`，撤销会关闭现有连接；成员删除会批量撤销该成员全部 lease。
- P2-04：capability 不再写入运行 TOML，通过受限环境变量注入，并加入日志脱敏。
- P2-05/P2-06：以 frpc 管理 API 的 `status=="running"` 作为注册条件；visitor 做本机端口预检和运行态绑定观察。
- P2-07/P2-12/P2-13：Apply 每次都执行目标策略校验；GUI 入网后刷新 FRP 身份/CIDR；FRP 秘密严格使用 DPAPI；显式固定 tcpMux/TLS 首字节兼容值。
- P2-08：客户端启动后读取 lease status，要求 FRPS 已观察到 Login 和 proxy；未观察到插件时拒绝运行。
- P3-01/P3-02：TargetGateway 使用 Manager 生命周期 context；Mesh 拨号通过 Windows `IP_UNICAST_IF` 绑定虚拟接口并校验源地址，未绑定接口直接失败。
- P3-03/P3-04：控制面按成员目录签发精确目标 grant，绑定网络、设备、虚拟 IP、公钥、service ID 和端口；已支持 `mesh_self`。
- P3-05/P3-06：Snapshot 不再直接探测 Mesh 目标；generation 变化会触发依赖失效信号。
- P3-07：Mesh 规则必须使用独立配置档，依赖失效进入 `waiting_dependency` 并自动重试，独立规则不会被同一进程连带停止。

仍未完成的是外部环境验收，而不是本轮代码路径：真实公网 FRPS、真实 Debian、两台独立 Windows、物理 LAN 抓包、真实 Mesh 接口切换和 24–72 小时长稳。不能把本地 fake-provider 联调替代这些验收。
## 0. 结论摘要

当前实现已经把方案要求的 P1/P2/P3 主体接入真实代码路径，而不是只增加 UI：

| 范围 | 当前结论 |
| --- | --- |
| P2 基础数据面 | 已有实质实现，本机真实 FRPS/FRPC 联调通过 TCP、UDP、HTTP、HTTPS、STCP、SUDP、visitor、TLS、tokenSource、Job 清理等路径 |
| P2 管理边界 | 设备级 lease、配额、续租、撤销、成员删除联动、lease status、四个 FRPS 插件操作和未观察插件拒绝启动均已实现并本机验证 |
| P3 数据面 | `mesh_peer`/`mesh_self`、管理员目标服务授权、TargetGateway TCP/UDP、generation/lease 失效、虚拟接口绑定和依赖暂停/恢复已接入 |
| P3 发布验收 | 仍需真实两台 Windows、Wintun/物理 LAN 抓包、真实公网/Debian 和 24–72 小时长稳；不能把本机 fake-provider 联调替代这些验收 |
| P4/上游高级能力 | 未实现：XTCP、tcpmux、QUIC/KCP/WSS、任意插件、HTTP locations/basic auth、原始 TOML、后台服务化、低权限 worker 等 |

一句话判断：**P1/P2/P3 的方案主体已真实接入并完成本机代码/真实 FRP 联调；生产发布仍受真实外部环境和目标成员 B 逐次确认 UI 的限制。**
## 1. 基线与已验证项

### 1.1 固定核心

已核对：

- FRP v0.71.1 tag object：`72d643d661dcb686087e342142a70f8f4698e29f`
- commit：`d8cf1800dc1abd7fda1828cab105d7a6b5a50eb1`
- Windows `frpc.exe` SHA-256：`509F4FA082BF9B85F9AD27B45D37A89A8ACCB011F3B724CFF352DFAC90A94FEB`
- Linux `frps` SHA-256：`2FB8DA8392CF2B332BFCC540F075E928A82D1A106DF0B8FCFCF13497149F8C48`
- `frpc verify -c`、管理 API、TLS CA 校验和 Job 回收已在本机测试中使用。

### 1.2 与 FRP v0.71.1 配置字段的核对

以下字段名、类型或位置与 v0.71.1 一致：

| 功能 | 生成字段 | 结论 |
| --- | --- | --- |
| 服务器 | `serverAddr`、`serverPort`、`user`、`loginFailExit` | 正确 |
| 文件令牌 | `auth.method="token"`、`auth.tokenSource.type="file"`、`auth.tokenSource.file.path` | 正确；令牌不在 TOML 中 |
| TLS | `transport.protocol="tcp"`、`transport.tls.enable=true`、`serverName`、`trustedCaFile` | 正确；强制 TLS |
| 管理 API | `webServer.addr="127.0.0.1"`、随机 `port`、`user`、`password`、`pprofEnable=false` | 正确 |
| TCP/UDP | `name`、`type`、`localIP`、`localPort`、`remotePort` | 正确 |
| HTTP/HTTPS | `customDomains`，不使用 `remotePort` | 正确 |
| STCP/SUDP | `secretKey`，不使用 `remotePort`/`customDomains` | 正确 |
| visitor | `name`、`type`、`serverName`、`serverUser`、`secretKey`、`bindAddr`、`bindPort` | 字段正确；语义和状态有缺口，见下文 |
| 管理 API 响应 | `name`、`type`、`status`、`err`、`local_addr`、`plugin`、`remote_addr`、`source` | 反序列化字段正确 |

FRP 的 `user` 会在 wire name 上添加 `"{user}."` 前缀；当前 `ProxyName` 保留内部 raw name，管理 API 的 `name` 也是 raw name。`frpauth` 已兼容 `user+"."+proxyName`，这点与真实 v0.71.1 行为一致。

### 1.3 已通过的本机测试

执行并通过：

```text
go test -mod=vendor ./... -count=1
go vet -mod=vendor ./...
```

全量测试约 32.5 秒完成，所有包通过。

真实 FRP 联调通过：

```text
TLAN_FRP_INTEGRATION=1 go test -mod=vendor ./internal/frp -run TestLive -count=1 -v
```

通过项：

- `TestLiveFRPTCPUDP`：真实临时 FRPS/FRPC，TCP、UDP、HTTP vhost、HTTPS vhost、STCP visitor、SUDP visitor；错误 CA 返回 `FRP_TLS_UNTRUSTED`；错误 token 返回 `FRP_AUTH_REJECTED`；停止后进程终止、运行目录为空。
- `TestLiveManagedFRPLease`：真实 FRPS/FRPC + HTTP plugin + lease capability，托管 TCP 映射通过。
- `TestLiveTargetGatewayPublishAndDependencyStop`：真实 FRPS/FRPC + TargetGateway + fake Mesh provider，发布、转发和依赖停止通过。

真实 plugin 联调通过：

```text
TLAN_FRP_LIVE=1 go test -mod=vendor ./internal/frpauth -run TestLive -count=1 -v
```

`TestLiveFRPSPluginTCPAndHTTPProxy` 覆盖 TCP、HTTP、UDP，并验证撤销后新 FRPC 登录失败。

已通过的原生 UI smoke（使用现有 `dist/windows/TLAN.exe`，不是当前 P3 源码重新构建的二进制）：

```text
PASS: integrated Mesh workspace, FRP page, version control, power-off transition,
member/rule tables and antialiased drawing calls; no network or adapter created
```

该 EXE 的 SHA-256 为 `142D63003B7C6C4998E899E7F8D8B488F40419E193F0C97F3AE99C18A6FDE823`，时间早于当前 P3 源码；因此不能把这次 smoke 当成当前 P3 UI 的视觉验收。

### 1.4 进程、凭据和文件保护

源码核对确认已接入：

- `frpc.exe` 固定 SHA-256 校验；
- `CREATE_SUSPENDED | CREATE_NO_WINDOW`；
- 受限继承句柄列表；
- 先加入 Job Object 再 `ResumeThread`；
- `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`；
- 停止时优先 `/api/stop`，超时后只终止自己拥有的 Job；
- 不按进程名杀用户自己的 `frpc.exe`；
- token 使用当前用户 DPAPI；
- FRP 配置、token、secrets、CA、运行目录使用 Windows DACL；
- 最小环境变量，未继承 `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY` 等大小写变体；
- `recoverLedger` 清理本用户遗留运行目录并校验 PID + creation time。

DACL 和 DPAPI 是代码级核对；本轮没有独立 ACL 断言的自动化测试，也没有以另一个 Windows 用户实际验证 DPAPI 失败路径。

### 1.5 P3 单元/局部联调

`internal/targetgateway` 的 TCP/UDP 单元测试通过，包括：

- TCP 半关闭、并发连接、租约撤销、generation 变化、dial 失败；
- UDP 多客户端隔离、租约撤销、generation 变化、超长报文、会话上限、空闲回收；
- 实际 FRPS/FRPC + TargetGateway + fake Mesh provider 的依赖停止测试通过。

这些结果证明 TargetGateway 自身的局部逻辑可工作，但**不证明真实 TUN/WireGuard 路由、真实成员变化或物理 LAN 回退已被阻断**。

## 2. P2 发现的不一致与可复现风险

### P2-01（高）托管配置在运行中更新会与旧 lease 冲突

`internal/frp/manager_windows.go` 的 `ApplyWithSecrets` 在停止旧实例之前先调用 `acquireLease(ctx, cfg)`（约 338 行），随后才 `stopCurrent`（约 345 行）。

`internal/frpauth/store.go` 的 `checkQuotaAndConflictsLocked` 会把当前 active lease 的 `proxy_name`、同协议 `remote_port` 和 `custom_domain` 计入全局冲突；新 lease 请求只要包含原有规则，就会返回 `ErrConflict`。

影响：托管模式运行中修改任何包含既有规则的配置，通常无法保存/应用。当前 `TestLiveManagedFRPLease` 只验证首次 `Start`，没有覆盖运行中 `Apply`。

最小修复：托管更新应先建立可替换的 lease/事务，或先停止旧实例并撤销旧 lease，再申请新 lease；回滚时重新申请旧 lease，且要保证失败路径不会释放仍在使用的新 lease。

### P2-02（高）租约续期链路不完整，且客户端实现会再次创建 lease

服务端 `internal/frpauth/store.go` 已有 `Store.Renew`（约 419 行），`internal/control/frp_leases.go` 也新增了 `/renew` 路由。

但客户端 `cmd/client/frp_lease_windows.go` 的 `Renew`（约 64-74 行）仍然调用 `Acquire`，而 `Acquire` 调用 `CreateFRPLease`；`internal/clientapi/client.go` 目前没有 `RenewFRPLease` 方法。结果：

- 续期请求会走新建 lease，而不是服务端续期；
- 对已有规则会触发 `ErrConflict`；
- `internal/frp/manager_windows.go` 没有续期循环，租约到期后没有自动延长。

影响：托管映射的 lease TTL 到期后，不能保证后续注册/续期正常；客户端重启或长时间运行后的行为没有完整闭环。

### P2-03（高）撤销只阻止新 Login/NewProxy，不关闭已有连接

`internal/frpauth/plugin.go` 的 plugin switch 只处理 `Login` 和 `NewProxy`；`internal/frpauth/store.go` 的 `Revoke` 只写入 `RevokedAt` 并持久化 tombstone。

当前真实 plugin 测试的注释也明确写明：

```text
Existing connections are intentionally not killed by this adapter;
that requires a separate FRPS/worker revocation mechanism.
```

影响：

- 已经建立的 TCP 连接、UDP 会话、HTTP/HTTPS vhost 流量不会因撤销立即断开；
- 撤销 SLA 不成立；
- 服务端只保证后续登录/注册被拒绝，不能保证当前数据面停止。

此外，`internal/control/server.go` 的 `RemoveDevice` 只调用 `storage.RemoveDevice`，没有调用 `frpauth.Store` 的撤销接口；当前也没有按设备批量撤销 lease 的方法。删除成员后，旧 lease 在 TTL 内仍可能继续使用。

最小修复：增加 `CloseProxy`/`NewUserConn` 或独立 FRPS worker 管理能力；成员删除、凭据撤销、lease 过期都必须同时切断当前连接/会话，不能只做 tombstone。

### P2-04（高/中）托管 capability 被写入运行 TOML，且日志脱敏列表没有它

`internal/frp/render.go` 在 managed profile 中写入：

```toml
metadatas.tlan_lease = ...
metadatas.tlan_capability = ...
metadatas.tlan_server = ...
```

`metadatas.tlan_capability` 是短期的发布凭据，但当前作为明文 TOML 值存在。`internal/frp/manager_windows.go` 的日志脱敏初始化只加入 token、admin password 和 STCP/SUDP secret，没有加入 `lease.Credential`。

影响：

- 运行 TOML 虽然有 DACL，但 capability 仍是明文文件内容；
- 如果 frpc 日志、诊断或异常输出包含 metadata，当前 `logRing` 不会按 capability 精确脱敏；
- 与“令牌/凭据不进入明文配置、日志无秘密”的安全目标存在偏差。

最小修复：尽量通过受限文件/一次性环境或 FRP 支持的间接 source 传递；至少把 lease capability 加入日志秘密集合，并检查所有错误详情。

### P2-05（高）管理 API 的 `status` phase 和实际 `remote_addr` 没有正确使用

`ProxyStatus` 已包含 `Status` 字段，但 `Manager.waitReady`（约 672-735 行）和 `Snapshot`（约 771-850 行）只检查：

- `proxy.Err` 是否为空；
- 对于 HTTP/HTTPS/STCP/SUDP，proxy 是否存在；
- 对于 TCP/UDP，`proxy.RemoteAddr` 是否非空。

FRP v0.71.1 的 `status` 可能是 `new`、`wait start`、`start error`、`running`、`check failed`、`closed`。当前逻辑可能把 `wait start`/`new` 的 HTTP、STCP、SUDP proxy 直接显示为“已注册”。

另外：

- TCP/UDP 的 API `remote_addr` 是 `:port` 形式，当前 UI 直接显示该值，而不是 `serverHost:actualPort`；
- HTTP/HTTPS 的 API `remote_addr` 是实际 vhost 地址，但 `Snapshot` 用 `ruleAccessAddress` 根据配置的 `PublicHTTPPort`/`PublicHTTPSPort` 重新拼接，配置端口错误时会显示错误地址；
- `Snapshot` 没有把 `ProxyStatus.Status` 暴露给 UI。

最小修复：把 `status == "running"` 作为注册成功条件；保留 API 原始 `remote_addr`，仅做 scheme 展示；对 TCP/UDP 明确显示 server host + actual remote port；不要用未确认的配置端口宣称在线。

### P2-06（高）visitor 没有真实状态和错误分类

`Snapshot` 对 visitor 只做：

```text
已禁用 / 已停止 / 已配置
```

只要 FRP 进程运行，enabled visitor 就是“已配置”；`ErrorDetail` 从未设置。`waitReady` 只统计 proxy rules，不检查 visitor 是否成功绑定端口、serverName 是否存在、secretKey 是否匹配。

影响：

- visitor bindPort 被占用时，界面仍可能显示“已配置”；
- serverName 拼错、serverUser 错误、secretKey 错误可能只出现在日志里；
- 仅含 visitor 的 profile 可以在未验证 visitor 的情况下被判定启动成功。

最小修复：对 visitor 做本地 bind 预检；从 frpc 日志/管理扩展中提取 visitor 错误；至少把 bind 失败、serverName 不存在、认证失败映射为明确状态。

### P2-07（高）运行中 Apply 绕过 LAN 目标策略，且 MeshCIDR 不会在入网后刷新

`Manager.Start` 会调用 `validatePolicy`（约 183 行），但 `ApplyWithSecrets` 的运行中路径只调用 `preflightTLS`（约 299-302 行），没有再次调用 `validatePolicy`。因此：

- 运行中把 LAN 目标改成当前 Mesh CIDR 内的地址，可以经过 Apply 重启并开始使用；
- 只有下次显式 Start 才会被拒绝。

`cmd/client/frp_ui_windows.go` 的 `initializeFRP` 在启动时把 `a.membership.Network.CIDR` 传给 Manager（约 96-103 行），但 `join()` 之后没有重建 FRP manager。没有保存 token、先打开 FRP、再加入网络的用户，默认 manager 的 `MeshCIDR` 为空，LAN 目标可能绕过策略；同一 manager 也不会感知网络 CIDR 变化。

最小修复：每次 Apply/Start 都执行策略校验；Manager 保存动态 Mesh 策略接口，入网/换网后刷新，或重建 manager；不要只依赖构造时字符串。

### P2-08（高/中）managed 模式没有证明外部 FRPS 真的启用了插件

客户端只根据配置中的 `Server.Kind="managed"` 使用 lease provider 并写入 metadata。若用户指向一个没有 `httpPlugins` 的外部 FRPS，外层 token 仍可让 proxy 注册；客户端没有对 FRPS 能力做证明或握手。

因此“外部 FRPS 不能假装支持托管授权”这一 P2 条件目前没有服务端/客户端能力协商保证。最小修复：增加 managed FRPS 能力探测/证明，或者把外部 FRPS 明确限定为 private-token 模式并禁止 managed 选择。

### P2-09（中）UI 把 STCP/SUDP 改为 TCP/UDP 时没有清除 `SecretRef`

`cmd/client/frp_ui_windows.go` 约 874-900 行：

- HTTP/HTTPS 分支会清空 `updated.SecretRef`；
- STCP/SUDP 分支会保留/生成 secret；
- TCP/UDP 分支没有清空 `updated.SecretRef`。

因此把一个已存在的 STCP/SUDP 规则改为 TCP 或 UDP 后，`ValidateConfig` 会以“TCP/UDP 不使用私有密钥”拒绝保存。这是可直接复现的编辑路径问题。

### P2-10（中）visitor 的 `serverName` 仍需手工填写，UI 没有提供稳定代理名

FRP v0.71.1 的 visitor `serverName` 是发布端 raw proxy name；`user`/`serverUser` 前缀由 FRP 在 wire 层添加。当前 UI 只给出“发布端 FRP 代理名”输入框，没有显示或复制本机/远端的 `ProxyName`，也没有提示用户不要输入 `user.` 前缀。

影响：用户很容易输入 wire name，最终被 FRP 再次加前缀，visitor 找不到目标。当前没有远端名称解析或可用性预检。

### P2-11（中）错误分类没有覆盖 managed/Mesh 的新错误码

`internal/frp/classify.go` 识别 `FRP_SERVER_UNREACHABLE`、TLS、auth、port、busy、backend 等常见字符串，但没有识别：

- `FRP_AUTH_REJECTED` 的插件拒绝字符串；
- `FRP_LEASE_EXPIRED`；
- `FRP_LEASE_REVOKED`；
- `FRP_DOMAIN_DENIED`；
- `MESH_DEPENDENCY_DOWN`。

`internal/clientui/feedback.go` 也没有 `mesh_dependency_down` 分支，`unsupported_frp_feature` 的提示仍写着“P1 仅支持 TCP/UDP 到 127.0.0.1”。用户可能看到泛化的 `FRP_PROCESS_FAILED` 或通用提示，而不是准确的端口/域名/租约/依赖错误。

### P2-12（中）DPAPI 读取接受非 DPAPI 明文

`internal/clientidentity/secret_windows.go` 的 `UnprotectSecret` 对不以 `dpapi:` 开头的值直接返回原值。FRP Store 依赖该函数读取 secrets。虽然目录 DACL 限制了访问，但严格意义上没有强制 secrets 文件必须由 DPAPI 保护；被篡改的 secrets 文件可能降级为明文读取。

### P2-13（低/中）外部 FRPS 的默认值依赖没有显式固定

当前生成配置没有显式写：

- `transport.tls.disableCustomTLSFirstByte = true`
- `transport.tcpMux = true`

v0.71.1 的默认值分别是 true/true，因此固定版本本机测试通过；但外部 FRPS 若配置 `tcpMux=false`，当前客户端没有兼容档位，也没有预检提示。这是 P2“外部 FRPS 兼容档位”的未完成项。

## 3. P3 发现的不一致与可复现风险

### P3-01（严重）UI 启动后 35 秒 context 被取消，TargetGateway 会被立即关闭

`cmd/client/frp_ui_windows.go` 的 `runFRPOperation` 在约 467-469 行创建 35 秒 context，调用 `operation(ctx)` 后立即 `cancel()`。

`internal/frp/manager_windows.go` 的 `prepareGateways` 在约 960 行使用 `context.WithCancel(ctx)` 创建 gateway context。因此 UI 路径中 `Manager.Start` 返回后，gateway context 被取消，TargetGateway listener 关闭；FRP 仍可能保持已注册 proxy，但 backend 是已关闭的 loopback 端口。

现有 `TestLiveTargetGatewayPublishAndDependencyStop` 使用长生命周期的测试 context，不能捕获这个 UI 生命周期差异。这是当前 P3 最关键的实际集成风险。

最小修复：gateway 使用 Manager 自己的生命周期 context，而不是一次 UI 操作 context；Stop/Close 显式取消 Manager context。

### P3-02（严重）Mesh Dialer 没有真正绑定 Mesh 接口/路由

`internal/mesh/target.go` 的 `DialTargetTCP`/`DialTargetUDP` 只设置 `net.Dialer.LocalAddr` 为本地虚拟 IP（约 91-110 行），没有：

- `GetBestRoute2` 查询实际路由；
- `IP_UNICAST_IF` 绑定接口；
- 连接后的路由/接口复核；
- 物理 LAN 回退阻断。

源地址绑定不等于接口绑定。若系统存在与 Mesh 目标同地址的物理路由、第三方 VPN 或接口切换，仍可能选择错误路径。P3 方案要求“抓包确认没有转发到同地址物理 LAN”，当前无法满足。

### P3-03（严重）没有发布授权 grant

`frp.Target` 目前只有 `Kind/Host/Port/NetworkID/DeviceID/PublicKey`；没有 grant/authorization ID。`internal/mesh/target.go` 的 `LeaseTarget` 只验证目标仍是当前 `e.peers` 成员、IP/公钥匹配，不验证 B 设备或管理员是否授权 A 发布该服务。

当前 UI 可以直接选择“TLAN 成员”并填入成员 IP/设备 ID；只要 Mesh 运行且成员存在，就可能建立发布。方案 P3 要求的 A/B/网络/协议/端口/FRPS/入口/有效期/撤销版本授权没有实现。

### P3-04（高）`mesh_self`、serviceID 和强制公钥绑定缺失

- `internal/frp/validate.go` 只支持 `loopback`、`lan`、`mesh_peer`，没有 `mesh_self`。
- `internal/mesh/target.go` 的 `LeaseTarget` 明确拒绝 `target.DeviceID == self`（约 68-70 行），因此无法发布本机虚拟 IP 服务。
- `TargetRequest` 没有 `serviceID`；方案要求服务身份绑定，当前只有 device + IPv4 + port。
- `Target.PublicKey` 是可选字段；为空时不检查当前成员公钥变化，公钥轮换/冒用检测不完整。

### P3-05（高）Snapshot 直接探测 Mesh 目标，绕过 TargetGateway

`internal/frp/manager_windows.go` 的 `Snapshot` 约 843 行对 `rule.Target.Host` 直接调用 `probeTCP`。对 `mesh_peer` 规则，这会绕过 TargetGateway，直接向 Mesh 目标（或错误路由）发起 TCP 连接。

影响：

- 状态可能显示“可用”，但实际 FRP→Gateway 路径未验证；
- 可能产生与“不得绕过受管网关”冲突的探测流量；
- 无法通过 gateway stats 判断 lease/route 状态。

最小修复：mesh_peer 的健康检查只能通过 TargetGateway 或使用 gateway 暴露的 stats；不要直接 probe 原始目标。

### P3-06（高）generation 变化没有触发 FRP proxy 的停止/重协调

`internal/targetgateway/gateway.go` 的 `watchLease` 已能检查 `lease.Done`（当前版本约 186-210 行），但只关注错误/Done，不比较 `Lease.Generation`。每个连接的 `leaseGuard` 会检测 generation，现有连接会关闭；但 Manager 不会因此停止/重启已注册的 FRP proxy，UI 也不会显示 generation 变化。

P3 的“网络切换、身份变化、授权收紧时停止/恢复”没有完整状态机；当前最多是连接层拒绝/关闭。

### P3-07（高）没有显式 dependency pause/resume 状态

当前 `stopPower`/`setPoweredOff` 不直接通知 FRP manager 进入 `WaitingDependency`，也没有在 Mesh 恢复后自动恢复依赖规则。Mesh 停止时 TargetGateway 的 lease Done 可以间接触发 gateway invalid，随后 Manager 可能停止整个 FRP 实例；但这不是方案要求的“暂停依赖组、保留独立组、恢复时按授权重建”。

多个 mesh_peer 规则共享一个 frpc 进程，一个 dependency 失效会停止该 profile 的所有规则，包括独立 loopback/LAN 规则。P3 方案要求按 serverProfile + dependencyDomain 分组，独立规则不能受影响。

### P3-08（高）没有真实 Mesh/物理 LAN 验收

`TestLiveTargetGatewayPublishAndDependencyStop` 使用的是 `gatewayTestProvider`/`gatewayTestDialer`，不是实际 `mesh.Engine`；`internal/mesh/target_test.go` 只测试 `LeaseTarget` 的身份/generation，不测试 `DialTargetTCP/UDP` 的实际路由。

因此当前没有证据证明：

- 停 Mesh、删成员、换 IP、换公钥时真实数据面立即阻断；
- 同地址物理 LAN 没有被转发；
- 网络切换/双中继诊断；
- TargetGateway 与真实 TUN 接口的配合。

### P3-09（中）UI 没有依赖状态和网关诊断

当前 FRP 页可以编辑 `mesh_peer` 目标，但没有展示：

- Mesh dependency 是否在线；
- gateway lease/generation；
- 规则是否 WaitingDependency；
- 实际 direct/relay 路径；
- gateway TCP/UDP 会话数、拒绝数、字节数；
- `MESH_DEPENDENCY_DOWN` 的用户可读解释。

`internal/clientui/feedback.go` 没有对应分支；`Snapshot` 也没有 gateway stats 字段。

## 4. 与两个参考项目的范围差异

### 4.1 `stilleshan/frpc`

该项目主要是 Linux/群晖/Docker 的一键安装脚本和示例 `frpc.toml`，不是完整 GUI 客户端。其示例使用共享 token、TCP/HTTP/HTTPS 和 systemd；没有实现 STCP/SUDP visitor、租约或 GUI 状态机。当前 TLAN 的独立 `frps` 部署包与其部署目标相近，但 TLAN 不应复制其明文 token、按进程名清理或旧 `.ini` service 写法。

### 4.2 `luckjiawei/frpc-desktop`

该项目提供更广的可视化配置能力，包括（以当前 checkout 为准）：

- TCP/UDP/HTTP/HTTPS/STCP/XTCP/SUDP；
- visitor、serverName/serverUser/secretKey/bindPort；
- HTTP locations、basic auth、subdomain、header rewrite；
- 插件、批量端口、导入导出 TOML、版本下载、开机启动、日志；
- 多用户/metadata 配置。

当前 TLAN 只按方案 P2/P3 取了受限子集，以下未搬入：

- XTCP、tcpmux；
- HTTP locations、basic auth、subdomain、header rewrite；
- 插件、批量端口、原始 TOML 导入导出；
- 版本下载/升级、开机启动/后台服务；
- KCP/QUIC/WSS/XTCP；
- frpc-desktop 的明文 token 和 `taskkill /F /T` 行为（TLAN 明确不采用）。

因此不能声称“完全移植 frpc-desktop 的全部功能”。这些属于 P4/后续能力，除非方案另行扩展 P2/P3。

## 5. 可复现验证与未验证项

### 5.1 已执行

| 命令 | 结果 | 说明 |
| --- | --- | --- |
| `go test -mod=vendor ./... -count=1` | PASS | 所有包通过，约 32.5s |
| `go vet -mod=vendor ./...` | PASS | 无输出 |
| `TLAN_FRP_INTEGRATION=1 go test -mod=vendor ./internal/frp -run TestLive -count=1 -v` | PASS | 3 个真实/局部联调测试 |
| `TLAN_FRP_LIVE=1 go test -mod=vendor ./internal/frpauth -run TestLive -count=1 -v` | PASS | 真实 plugin TCP/HTTP/UDP |
| 现有 `dist/windows/TLAN.exe --ui-smoke-test` | PASS | 旧 P2 二进制，不是当前 P3 源码构建 |
| `go test -race ...` | 未执行成功 | 环境无 gcc，`CGO_ENABLED=1` 仍报 `C compiler "gcc" not found` |

### 5.2 未验证

- 真实公网 FRPS/域名/DNS/防火墙；
- Debian/Ubuntu/CentOS 实机部署和 systemd；
- 两台独立 Windows 的 Mesh/FRP 组合；
- 物理 LAN 抓包，证明没有 Mesh/物理 LAN 回退；
- 真实 Mesh 目标下的 TargetGateway；
- 成员删除、IP 变化、公钥变化、授权撤销的真实端到端 SLA；
- 24–72 小时混合负载/长稳；
- 当前 P3 源码重新构建的 UI 视觉验收；
- 低权限 worker（当前 GUI manifest 要求管理员，frpc 继承管理员权限）。

## 6. 建议的最小修复顺序

1. **先修 P2 事务和撤销**：托管运行中 Apply 不再先申请冲突 lease；实现客户端 `RenewFRPLease` 与续期循环；撤销/成员删除/过期必须关闭当前 proxy 和连接；把 capability 加入日志脱敏并避免明文 TOML。
2. **修 P2 状态语义**：`status=="running"` 才算注册；使用 API 实际 `remote_addr`；visitor 做 bind/认证/状态检查；补齐 managed/Mesh 错误码和 `clientui` 映射。
3. **修 P2 策略和 UI**：Apply 每次执行 `validatePolicy`；入网/换网后刷新或重建 manager；修复 STCP→TCP/UDP 的 `SecretRef`；补充 visitor serverName 辅助/校验。
4. **修 P3 生命周期**：TargetGateway 使用 Manager 生命周期 context；确保 gateway 归 Manager 所有；依赖失效只暂停依赖组，独立规则继续运行；停止/恢复要有显式状态。
5. **修 P3 安全边界**：增加 grant/authorization、`mesh_self`、serviceID、强制公钥/身份校验；使用 `GetBestRoute2`/`IP_UNICAST_IF` 绑定 Mesh 接口；用真实 Mesh + 抓包验证无物理回退。
6. **再补 P3 诊断和发布**：gateway stats、dependency 状态、direct/relay 诊断、真实 Mesh 集成测试、P3 UI 截图和长稳测试。
7. **P4/上游能力**：XTCP、tcpmux、插件、HTTP locations/basic auth、KCP/QUIC/WSS、原始 TOML 导入导出、后台服务和低权限 worker。

## 7. 审计结论

- 本机 P2 数据面主体：**已验证可运行**。
- P2 完成条件：**未完成**，尤其是托管更新、续期、撤销、成员删除、状态语义、外部 FRPS 能力证明。
- P3 局部数据面：**TargetGateway/fake-provider 测试通过**。
- P3 完成条件：**未完成**，尤其是真实 Mesh 路由绑定、发布授权、`mesh_self`、生命周期、依赖状态和物理 LAN 抓包。
- 上游完整功能：**未完整搬入**；`frpc-desktop` 的许多高级能力属于 P4/后续范围。
- 当前管理员权限限制：Windows GUI 仍要求管理员，受管 frpc 继承该权限；未实现低权限 worker。

本报告只记录当前快照和实际运行结果，不把本机测试、fake provider 或旧 P2 UI smoke 当成公网、Debian、真实 Mesh 或长期稳定性验证。

## 8. 后续修复状态（2026-10-21）

本报告第 0–7 节保留为修复前的只读审计快照。后续实现已处理以下项目：

- 托管运行中 Apply 改为先停止并撤销旧 lease，再申请替换 lease；失败时恢复旧配置和旧授权。
- 客户端已调用 `/renew` 而非重新创建 lease；续租周期固定为 5 秒，撤销/成员删除按 10 秒 SLA 停止受管 frpc 和 TargetGateway。
- 服务端成员删除会批量撤销该成员 lease；FRPS 插件要求 `Login`、`NewProxy`、`Ping`、`NewUserConn`。
- capability 通过受限环境变量模板注入 frpc，不再作为 TOML 明文值；日志脱敏包含 capability。
- 管理 API 使用 `status == running` 判定注册，HTTP/HTTPS 使用实际 remote_addr 并补全 scheme；visitor 增加本地绑定预检和“监听中”状态。
- Apply 每次执行 Mesh/LAN 路由策略校验，入网/恢复会话后刷新 FRP manager 的网络身份和 Mesh CIDR。
- P3 增加服务端目录绑定的精确目标授权、`mesh_self`、公钥/虚拟 IP/generation 校验、Windows 虚拟接口绑定、依赖暂停与自动重试、独立规则必须使用独立配置、网关统计和错误分类。
- 托管客户端通过 lease status 观察 FRPS 是否实际到达 Login/NewProxy 插件；未观察到插件时拒绝启动。
- 目标 service grant 过期后 `/renew` 也失败；管理员撤销服务授权会联动撤销活动 lease。Mesh generation done channel、gateway watcher 回收、frpc 崩溃重试和 Stop/旧 watcher 状态门控已补齐。

仍需真实环境证明：公网 FRPS、真实 Debian 主机、两台独立 Windows、物理 LAN 抓包、Mesh/FRP 四组合、24–72 小时长稳，以及外部 FRPS 插件启用的独立能力证明。P4 功能仍未实现。
## 9. 最终复核（2026-10-21，最新快照）

本节以 **2026-10-21 08:12（Asia/Shanghai）** 可编译快照为准，覆盖前文第 0–8 节的旧结论；前文已经修复的 P2-01—P3-09 不再重复列为缺口。审计只读，未修改业务代码。

- 快照树 SHA-256（`internal/frp`、`internal/frpauth`、`internal/control`、`internal/mesh`、`internal/targetgateway`、`cmd/client` 下 88 个 Go 文件按路径和内容计算）：`9925fdef3877c521a4e690948affd77a7da50981535b79ceb5dca98c99cceba9`
- 审计期间有并发写盘，最终测试是在源码稳定后重新执行的；曾出现的 `targetgateway.leaseWG` 中间态构建失败已不再存在。

### 9.1 已验证项（本轮不重复报告为缺口）

以下项目已由源码和当前本机测试确认：

- FRP v0.71.1 的 `transport.tcpMux`、TLS、`auth.tokenSource.type=file`、`serverName`、`trustedCaFile`、代理/visitor 字段名和类型与固定版本源码一致；真实 TCP、UDP、HTTP vhost、HTTPS vhost、STCP、SUDP visitor 联调通过。
- 托管 `/renew`、5 秒 watchdog、撤销/过期/成员删除、`Login`/`NewProxy`/`Ping`/`NewUserConn` 插件路径，以及“未观察到插件则拒绝启动”路径通过；`TestLiveManagedRejectsUnobservedPlugin` PASS。
- TargetGateway TCP/UDP、依赖失效、generation/lease 检查、接口绑定失败关闭、Mesh 独立规则隔离通过本机单元/局部联调；真实 Mesh 和物理网卡仍未验证。
- `/api/v1/frp/services` 的 POST/DELETE 没有被普通成员路由放行：`frpRouteAllowed` 只放行 capabilities 和 leases，`memberRouteAllowed` 不包含 services；因此目标服务登记/撤销仍由管理员令牌控制。此项不再列为授权缺口。
- 生产 GUI 使用的 `newFRPLeaseProvider` 实现了 `LeaseVerifier`，当前正常 GUI 路径不会走下面的“无 verifier”回退；本机真实插件拒绝测试也覆盖了生产路径。

### 9.2 仍可在代码或本机测试中完成的缺口

#### P2-R1（中，发布前必须明确）外部 FRPS 兼容档位没有真正实现

**证据**

- `internal/frp/render.go:67-72` 固定生成 `transport.protocol = "tcp"`、`transport.tcpMux = true`、`transport.tls.disableCustomTLSFirstByte = true`。
- `internal/frp/model.go:58-69` 没有 `tcpMux`、兼容档位或相应的能力字段；UI 也没有此选项。
- 固定版 FRP v0.71.1 的 `server/proxy/tcp.go:86` 和 `server/proxy/udp.go:90` 明确返回 `:port`；其 TCP/UDP 服务端配置若使用 `transport.tcpMux=false`，当前客户端仍强制使用 mux，无法建立兼容连接。当前 live fixture 只覆盖 `tcpMux=true`。
- 方案 P2 工作项明确列有“外部 FRPS 兼容档位”；当前仅有单一固定档位，不能称为完成。

**影响**

- 用户连接自行部署、关闭 TCP mux 的 FRPS 时，可能在 TLS 后握手/工作连接阶段失败，而 UI 只给出泛化连接或进程失败，无法区分“服务器兼容档位不匹配”。

**最小修复**

1. 在 Server/Profile 增加明确的兼容档位（至少 `tcpMux=true/false`，如需兼容旧 TLS 首字节再加独立开关）；不提供任意 TOML 覆盖。
2. 渲染器按档位写入字段，严格校验组合；启动前给出不支持组合的 `UNSUPPORTED_FRP_FEATURE` 或配置错误。
3. 增加 local FRPS `tcpMux=false` fixture，验证真实握手和 TCP/UDP 数据面。

**回归测试**

```powershell
$env:TLAN_FRP_INTEGRATION='1'
go test -mod=vendor ./internal/frp -run 'TestLiveFRPTCPUDP|TestLiveExternalFRPSCompatibility' -count=1 -v
```

`TestLiveExternalFRPSCompatibility` 目前尚不存在，应先补测试；只有该测试 PASS 才能宣称外部兼容档位完成。

#### P2-R2（低/中，接口层 fail-open）缺少 `LeaseVerifier` 时托管校验跳过

**证据**

- `internal/frp/manager_windows.go:1155-1174`：managed lease 的 provider 若不实现 `LeaseVerifier`，`verifyManagedLease` 直接 `return nil`。
- `internal/frp/lease.go:57-61` 只把 verifier 定义为可选接口；没有在 `NewManager`/`Start` 的 managed 分支强制断言。
- 生产 `cmd/client/frp_lease_windows.go` 的 provider 已实现该接口，所以当前 GUI 正常路径不受影响；这是接口契约和未来 provider 替换时的 fail-open 风险。

**影响**

- 若以后新增的 provider、测试替身或重构忘记实现 verifier，`Server.Kind=managed` 可能在未证明 FRPS 到达插件的情况下被视为成功，破坏 P2“外部 FRPS 不能假装支持托管授权”的边界。

**最小修复**

- managed 模式启动前 `provider, ok := leaseProvider.(LeaseVerifier); if !ok { return CodeAuthRejected }`；仅 private-token 模式允许无 verifier。
- 增加 `TestManagedRequiresLeaseVerifier`，并明确 `LeaseProvider` 与 verifier 的组合契约。

**回归测试**

```powershell
go test -mod=vendor ./internal/frp -run 'TestManagedRequiresLeaseVerifier|TestLiveManagedRejectsUnobservedPlugin' -count=1 -v
```

#### P2-R3（低）TCP/UDP 访问地址不完整，且访问地址没有复制入口

**证据**

- `internal/frp/manager_windows.go:1029` 直接把管理 API 的 `proxy.RemoteAddr` 写入 `row.RemoteAddr`；固定 FRP v0.71.1 对 TCP/UDP 返回 `:port`（例如 `:30000`），不是 `serverHost:30000`。
- 只有 HTTP/HTTPS 分支在 `1036-1041` 补 scheme；TCP/UDP 没有补服务器地址。
- `cmd/client/frp_ui_windows.go` 的规则表和按钮中没有剪贴板/复制地址操作；方案 12.1 要求“访问者地址用复制地址按钮”，并明确 UDP 不应伪装成 HTTP URL。

**影响**

- 用户看到的 TCP/UDP 地址只有端口，不能直接复制为可访问 endpoint；这不是数据面转发失败，但属于 P2 诊断/可用性完成项。

**最小修复**

- 从服务器配置的 Host 和实际返回端口组合显示；若 API 返回空地址则明确显示“端口已获分配，地址待服务器确认”，不要凭空拼接未经确认的端口。
- 增加只复制地址的按钮和单元测试；UDP 只显示 `host:port` 和 UDP 标识，不生成 URL。

**回归测试**

```powershell
go test -mod=vendor ./internal/frp -run 'TestSnapshotTCPUDPServerAddress|TestAccessAddressCopyFormat' -count=1
```

#### P3-R1（高，网络切换）运行中的 FRP 会阻止身份刷新，但界面仍允许换网

**证据**

- `cmd/client/frp_ui_windows.go:114-125` 的 `refreshFRPIdentity` 对每个 manager 调用 `UpdateMembership`。
- `internal/frp/manager_windows.go:145-163` 在 `m.instance != nil` 时明确返回“stop FRP before changing the TLAN membership identity”，不会更新 provider identity/Mesh CIDR。
- `cmd/client/desktop_windows.go:263-270` 的 `join()` 只检查 `a.engine != nil`；`changeCode()`（324-331）和 `leaveNetwork()`（561-565）也只检查 Mesh engine，不检查独立 FRP manager。
- 成功登录后错误仅写入 `frpManagerErrors`，不会立即阻止换网或改变运行中 FRP 的目标身份。

**可复现路径**

1. 启动一个 managed FRP 配置（或包含 Mesh 目标的配置）；
2. 保持 Mesh 电源关闭，打开“更换入网令牌”并加入另一个网络；
3. `UpdateMembership` 返回配置错误，但 FRP 进程仍持有旧 network/device/grant 继续运行；新网络身份与 FRP 状态不一致。

**影响**

- P3 完成条件要求网络切换后相关流量立即切断；当前换网路径没有保证旧 grant 的本地停止，也可能让用户误以为新网络下的发布已经生效。

**最小修复**

- 在 `changeCode`、`join`、`leaveNetwork` 前检查所有 `frpManagers` 是否 Running；若在运行，要求先停止或自动执行受控停止（并处理失败回滚）。
- 身份变更成功后再次刷新所有 manager，校验 network/device/CIDR 与 lease provider 一致；失败时禁止继续并显示明确错误。
- 增加 `TestChangeNetworkStopsRunningFRP` 和 `TestLeaveNetworkRevokesManagedFRP`。

**回归测试**

```powershell
go test -mod=vendor ./cmd/client -run 'TestChangeNetworkStopsRunningFRP|TestLeaveNetworkRevokesManagedFRP' -count=1 -v
```

#### P3-R2（中，功能组合不一致）`mesh_peer` + STCP/SUDP 在 UI 可选但无法取得服务授权

**证据**

- `cmd/client/frp_ui_windows.go:872` 对任何目标类型都提供 `TCP/UDP/HTTP/HTTPS/STCP/SUDP`；`909-932` 只要求 `mesh_peer` 填 service ID，没有限制它与 STCP/SUDP 的组合。
- `internal/frpauth/store.go:526-529` 的 `IssueService` 只接受 `tcp/udp/http/https`。
- `internal/frpauth/store.go:400-402` 和 `900-902` 要求目标服务 `service.Protocol == rule.Type`；因此管理员无法登记 `stcp`/`sudp` 服务，`mesh_peer` 申请会返回未授权。
- TargetGateway 自身在 `internal/frp/manager_windows.go:1509-1512` 已把 STCP 当作 TCP、SUDP 当作 UDP，这说明数据面具备承载能力，缺的是授权模型/配置约束。

**影响**

- 用户按 UI 提示配置了一个表面支持的组合，保存或启动后才失败；P3 目标类型与 P2 私有协议组合没有单一真源。

**最小修复（二选一，必须写入产品规则）**

- 若不支持：在 `ValidateConfig` 和 UI 中将 `mesh_peer` 限制为 `tcp/udp/http/https`（或明确只允许 TCP/UDP），用 `UNSUPPORTED_FRP_FEATURE` 拒绝，并补文档；或
- 若支持：服务授权记录保存底层目标传输（tcp/udp），lease 校验把 `stcp→tcp`、`sudp→udp` 做显式规范化，同时保持 FRP proxy type 不变，并补完整租约/负向测试。

**回归测试**

```powershell
go test -mod=vendor ./internal/frp ./internal/frpauth -run 'TestMeshTargetProtocolMatrix|TestIssueServiceRejectsUnsupportedMeshProtocol' -count=1
```

#### P3-R3（低/中，诊断完成度）TargetGateway 字节统计没有进入 UI 诊断

**证据**

- `internal/targetgateway/types.go` 的 `Stats` 包含 `BytesToTarget`、`BytesFromTarget`、`DatagramsToTarget`、`DatagramsFromTarget`。
- `internal/frp/manager_windows.go:1048-1058` 的 `GatewayStats` 只显示 generation、TCP/UDP 连接/拒绝计数，没有显示上述字节/报文统计。
- `cmd/client/frp_ui_windows.go:417-420` 只把该字符串放进规则行；方案 6.3 要求分别显示 FRP 应用字节、Mesh 加密/内部流量和服务器流量，不能简单相加。
- `meshTargetProvider.TargetPath` 已能标记 `direct UDP`/`relay TCP/TLS`，所以路径诊断有基础；流量分层统计仍未完成。

**最小修复**

- 在规则/网关诊断中显示至少 `BytesToTarget`、`BytesFromTarget` 和 datagram 计数，并明确这是 TargetGateway 观测值；FRP 侧与 Mesh 侧指标分开命名。
- 为 `Snapshot.Gateways` 和 UI 行增加格式化测试。

**回归测试**

```powershell
go test -mod=vendor ./internal/frp -run 'TestSnapshotIncludesGatewayBytes|TestGatewayStatsFormat' -count=1
```

#### P2-R4（低，残余可观测性）visitor“监听中”仍是端口占用启发式

**证据**

- `internal/frp/manager_windows.go:1088-1105` 的 `visitorBindObserved` 通过尝试绑定端口失败来推断 visitor 已监听；不能证明占用者是当前 frpc，也不能证明 `serverName`/`secretKey` 与服务端匹配。
- 本机 `TestLiveFRPTCPUDP` 已用正确 serverName/secretKey 验证 STCP/SUDP 正常流量，因此这不是当前数据面失败；但错误 serverName 或认证失败仍可能只显示等待绑定/日志错误，缺少稳定的运行态证明。
- visitor 名称和 `serverUser` 仍需用户手工填写 raw proxy name；UI 提示已要求不要加 `user.` 前缀，但没有从本机规则复制稳定代理名的辅助。

**影响**

- 用户配置错误时可复现地得到模糊的“等待绑定”或日志诊断，而不是准确的 visitor 认证/目标错误。

**最小修复**

- 优先使用 frpc 管理 API/日志中的 visitor 状态；若上游没有稳定字段，至少把 frpc 日志中的 visitor bind/auth 错误分类映射到 `VisitorRuntimeStatus.ErrorCode/ErrorDetail`，并避免仅凭任意进程占用端口判定成功。
- 增加“复制发布端代理名”的只读辅助，不自动猜测其他服务器的 raw name。

**回归测试**

```powershell
go test -mod=vendor ./internal/frp -run 'TestVisitorStatus|TestVisitorErrorClassify' -count=1 -v
```

### 9.3 本机构建/发布物一致性缺口

- `dist/windows/TLAN.exe` 的时间为 `2026-10-21 03:10:42`，而当前 `internal/frp/manager_windows.go`、`internal/control`、`internal/mesh`、`internal/frpauth`、`cmd/client/frp_mesh_windows.go` 等多个源文件时间为 `07:59–08:07`；当前发布 EXE/ZIP 不是本节快照的构建产物。
- 因此 `VALIDATION.md` 中“最终包已重建”的表述不能覆盖本节最新源码；当前源码的临时 `--ui-smoke-test` 已 PASS，但该结果不能替代重新打包和发布包校验。
- 这是本地可完成的发布工程缺口，不是数据面缺口。源码冻结后应重新运行构建脚本、重新生成 `dist/SHA256SUMS.txt`，并对新 EXE 重跑 UI smoke 和包内 frpc hash 校验。

建议命令（会写 `dist`，本次只读审计未执行）：

```powershell
.\build-windows-client.ps1
.\build-debian-server.ps1
.\build-server-installer.ps1 -Offline
Get-FileHash -Algorithm SHA256 .\dist\windows\TLAN.exe
```

### 9.4 当前测试结果与可继续完成的验证

本轮当前快照实际执行并通过：

```text
go test -mod=vendor ./... -count=1                         PASS（约 32.8s）
go vet -mod=vendor ./...                                  PASS
TLAN_FRP_INTEGRATION=1
go test -mod=vendor ./internal/frp -run TestLive -count=1 -v
  PASS: TestLiveTargetGatewayPublishAndDependencyStop
  PASS: TestLiveFRPTCPUDP
  PASS: TestLiveManagedFRPLease
  PASS: TestLiveManagedRejectsUnobservedPlugin
TLAN_FRP_LIVE=1
go test -mod=vendor ./internal/frpauth -run TestLive -count=1 -v
  PASS: TestLiveFRPSPluginTCPAndHTTPProxy
```

当前源码另以临时目录构建 Windows GUI，并执行：

```text
TLAN.exe --ui-smoke-test <临时报告>
PASS: integrated Mesh workspace, FRP page, version control, power-off transition,
member/rule tables and antialiased drawing calls; no network or adapter created
```

该 smoke 不创建网卡、不连接网络，也不能替代视觉验收或真实数据面验收。

`go test -race` 未能完成，原因是当前环境没有可用 C 编译器：

```text
$env:CGO_ENABLED='1'
go test -mod=vendor -race ./internal/frp ./internal/targetgateway -run '^$' -count=1
# cgo: C compiler "gcc" not found
```

这不是已发现的竞态，只是 race detector 未执行；应在具备 gcc/MSVC cgo 工具链的构建机补跑。

### 9.5 必须外部硬件/公网才能验收的项

以下项目不能由当前本机测试、fake provider 或日志断言替代，不能声称已通过：

- 真实公网 FRPS、DNS、云安全组/防火墙、NAT/CGNAT 和真实外部访问。
- 真实 Debian/Ubuntu/CentOS 主机、systemd、生产证书、FRPS 插件同机/受保护网络部署。
- 两台独立 Windows 的真实 Wintun/WireGuard Mesh；真实成员在线、直连和中继路径。
- 真实 `IP_UNICAST_IF`、`GetBestRoute2`/路由快照、同地址物理 LAN、接口切换、VPN/第三方网卡竞争，以及抓包证明没有物理 LAN 回退。
- 停 Mesh、删成员、换 IP、换公钥、撤销 service grant 后的真实端到端 SLA；尤其撤销瞬间高吞吐下的零在途流量。
- Mesh/FRP 四种启停组合、进程异常退出/重启、系统重启后的残留清理。
- 24–72 小时混合负载、吞吐/RTT/丢包、句柄/内存/进程数与长期稳定性。
- 外部 FRPS 的多版本、不同 `tcpMux`/TLS 首字节和真实部署矩阵。

### 9.6 最小修复顺序

1. **P3-R1 先修**：换网/退网前停止或受控迁移所有运行中的 FRP manager；这是 P3 网络切换和旧 grant 切断的明确代码缺口。
2. **P3-R2**：确定 `mesh_peer` 与 STCP/SUDP 的产品规则；要么显式拒绝，要么把服务底层协议与 FRP 暴露协议分离并补租约测试。
3. **P2-R1**：增加外部 FRPS 兼容档位和 local `tcpMux=false` fixture；完成后再宣称外部 FRPS 兼容。
4. **P2-R2**：把 managed 模式的 `LeaseVerifier` 断言改为 fail-closed，并补接口测试。
5. **P2-R3/P3-R3/P2-R4**：补齐可复制访问地址、分层流量统计和 visitor 错误状态；这些不阻塞当前本机转发，但阻塞 P2/P3 的完整诊断/UI 验收。
6. **发布工程**：源码冻结后重建四个发布物、更新 SHA-256，并对新 EXE 重新运行 smoke；在有 gcc 的机器补跑 `-race`。
7. **最后才做外部验收**：真实公网、Debian、双 Windows、抓包和长稳；未完成前继续保持 README 的“仍需外部环境证明”表述。

### 9.7 结论

- P2 数据面主体和托管授权主体：**本机真实 FRP 联调通过**。
- P2 完成条件：**仍未完全完成**，剩余明确代码项是外部 FRPS 兼容档位、verifier fail-closed、访问地址/诊断完整性和 visitor 可观测性。
- P3 数据面主体：**本机单元/真实 FRP + fake Mesh 联调通过**；服务授权和 `mesh_self` 路径已具备。
- P3 完成条件：**仍未完全完成**，剩余明确代码项是运行中换网/退网身份切换、`mesh_peer` 私有协议组合约束、分层流量诊断；真实双 Windows/物理 LAN/撤销 SLA 仍需外部验收。
- 本节不声称公网、Debian 实机、真实 Mesh 路由或长期稳定性已验证。
## 9.8 最终收尾复核（2026-10-21）

在 9.1–9.7 之后又完成以下代码项：

- 运行中的任意受管 FRP 配置会阻止加入新网络、更换令牌和退出网络；用户必须先停止穿透，避免旧 identity/grant 继续运行。
- `mesh_peer` 与 STCP/SUDP 组合已支持：服务授权协议 `tcp` 可匹配 `stcp`，`udp` 可匹配 `sudp`，并有租约回归测试。
- 外部 FRPS 兼容档位已加入 `tcpMux` 和 `disableCustomTLSFirstByte`，GUI 与服务端设置可切换。
- managed 模式下缺失 `LeaseVerifier` 改为 fail-closed；生产 provider 和 live 测试 provider 已实现。
- TCP/UDP 访问地址补全服务器主机；TargetGateway 规则诊断显示 lease generation、连接/拒绝计数、双向字节和 Mesh direct/relay 路径。
- 最终发布物已重新构建并更新 `dist/SHA256SUMS.txt`；客户端包 frpc 哈希、UI smoke 和安装器自检通过。

仍然保留的已知限制是 visitor 运行态仍依赖端口占用启发式（上游 frpc 管理 API 没有稳定 visitor 字段）、目标成员 B 的逐次弹窗确认 UI 未实现，以及真实公网/双机/抓包/长稳和 race detector 未完成的外部验收项。