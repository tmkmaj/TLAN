# R1/R2 实现与验证报告

日期：2026-10-21（Asia/Shanghai）

工作目录：`D:/RadminLanPrivate`。依据：

- `docs/CURRENT-CODE-VERIFICATION-2026-10-21.md`
- `docs/FRPC-DEVELOPMENT-ROADMAP-2026-10-21.md`
- `docs/FRPC-INTEGRATION-PLAN.md`
- docs/ADVANCED-FEATURES-IMPLEMENTATION-2026-10-21.md（后续高级能力批次）

本文区分三种状态：**代码存在**、**本机测试通过**、**真实环境已验收**。除非明确写出“真实环境已验收”，否则不能把测试结论扩大为公网、双机、真实 Wintun 或长期稳定性结论。

## 1. 总结

最新审查报告中的 F-01 至 F-07 均已修复对应代码路径并加入回归：

- F-01、F-02：配置权限交集回滚、撤销上限持久化、可取消运行意图和 GUI 停止契约。
- F-03：实际路由观察、FRPS 控制连接受限出口代理、Mesh 启动双向预检、运行中路由复检。
- F-04、F-05、F-06：保留目标/动态管理端口、TLAN 两个地址池、visitor 依赖隔离。
- F-07：Windows 管理器测试拆分，Linux 全量 vet 恢复通过。

本机固定 FRP v0.71.1 联调通过，并验证真实受管 `frpc.exe` 的 TCP 控制连接确实经过受限出口代理。两台 Windows、真实 Wintun 接口切换、公网 FRPS、真实 Debian 和 24–72 小时长稳仍未验收。

## 2. F-01 至 F-07 状态

| 编号 | 实现状态 | 本机验证 | 真实环境状态 |
| --- | --- | --- | --- |
| F-01 失败回滚重开旧映射 | 已修复 | 真实 FRPC/FRPS 删除/收紧规则失败回归通过 | 公网服务端和管理员撤销组合待验收 |
| F-02 失败/等待状态不可停止 | 已修复 | Manager 状态契约、真实依赖中断停止及 GUI smoke 通过 | 自动化鼠标级操作和真实网卡重建待验收 |
| F-03 FRPS 出口/运行时路由 | 已修复当前 TCP+TLS 代码路径 | 路由模型、接口钉住代理、真实 FRPC 代理使用、Mesh 双向预检、运行中变化回归通过 | 真实 Wintun、物理 LAN 抓包、Wi‑Fi/有线切换待验收 |
| F-04 保留目标/管理面 | 已修复主要入口 | 元数据、固定管理端口、动态 admin/TargetGateway/代理端口、visitor 监听端口和合法回环业务测试通过 | 多 Profile 长时间竞争和真实端口占用待验收 |
| F-05 100.64.0.0/10 Mesh 目标 | 已修复 | `10/8`、`100.64/10`、错误网络/设备/前缀测试通过 | 真实 100.64 网段双机待验收 |
| F-06 Mesh 与独立 visitor 混用 | 已修复 | 非法组合拒绝、纯 visitor/纯 Mesh 保持有效 | 真实外部 visitor 网络待验收 |
| F-07 Linux 全量 vet | 已修复 | Linux/amd64 全量 vet 和测试源码交叉编译通过 | Linux 原生 CI 尚未在远端实际执行 |

## 3. R1：配置事务与运行意图

### 3.1 权限交集和撤销上限

`internal/frp/manager_windows.go` 在 Apply 失败时会比较旧配置和新配置，只恢复仍被新配置允许的旧资源。服务器身份、token/凭据、规则类型、目标、公网端口、域名、visitor 监听范围和秘密值都参与比较。

被删除、禁用或收紧的旧发布不会因为新配置注册失败而重新开放。若没有安全可恢复项，运行保持关闭并报告原因。收紧后的权限上限写入 `runtime-ceiling.json`，Manager 重建后不能通过旧磁盘配置重新扩大发布范围。

### 3.2 Stop 与运行意图

Snapshot 暴露 `DesiredRunning` 和 `CanStop`。启动中、等待依赖、重试退避以及失败但仍保留恢复意图时，GUI 提供“取消穿透”。Stop 先清除运行意图，再取消当前启动并回收实例；用户停止后，依赖恢复不能自行重开。

Terminal 启动失败会清除运行意图；可重试错误可以保留意图，但必须可通过 Stop 取消。`RequiresIdentityStop` 只阻止确实依赖旧身份的实例或运行意图。

## 4. R2：虚拟组网与 FRP 协调

### 4.1 NetworkObserver

新增 `internal/netpolicy`：

- 使用 Windows `GetBestInterfaceEx` 对 IPv4 目的地址查询 OS 选择的接口。
- 记录目的地址、接口索引、接口名称和接口网段。
- 每次拨号重新解析，不跨接口重建缓存旧索引。
- 区分回环、TLAN、其他 VPN 和普通接口；不强制选择物理网卡。

### 4.2 ConflictPlanner

`internal/netpolicy/planner.go` 对 FRPS 控制端点和计划 Mesh 启动做保守检查：

- FRPS 字面地址或任一解析结果落入 TLAN 前缀时拒绝。
- OS 选择 TLAN 接口或带 TLAN 前缀的接口时拒绝。
- 合法第三方 VPN 路径允许，不添加绕过 VPN 的默认路由。
- DNS/路由证据不足时 fail-closed，不宣称路径安全。

### 4.3 FRPC 受限出口代理

固定核心仍为官方 FRP v0.71.1。`RenderConfig` 在 TCP 控制传输上写入 `transport.proxyURL`，指向仅在 `127.0.0.1` 监听、随机凭据认证的进程内 CONNECT 代理。

代理只接受配置中的精确 FRPS 主机和端口；每次 CONNECT 都：

1. 重新解析地址并查询有效路由。
2. 拒绝 TLAN 地址/接口。
3. 使用 Windows `IP_UNICAST_IF` 将 socket 钉在本次观察到的接口。
4. 再建立到 FRPS 的 TCP 连接。

这把“检查后 FRPC 再解析或系统改路由”的竞态从无约束拨号收窄为“观察后 socket 固定接口”。真实 `TestLiveFRPTCPUDP` 会断言受管 FRPC 通过该代理建立了连接，而不只是检查代理类存在。

当前边界：项目只开放 TCP+TLS 控制传输；`proxyURL` 覆盖该控制连接，FRP 数据流复用该连接/mux。未来开放 QUIC/KCP/WSS 等传输时，必须重新验证每个拨号入口，不能沿用本结论。

### 4.4 Mesh 启动前反向检查

开始 Mesh 前，GUI 对每个有运行意图的 FRP Manager 调用 `ValidateMeshStart`；Mesh 建立后先把最新网络 CIDR 刷新到所有 Manager，再基于真实接口复核：

- FRPS 解析地址不能落入计划 Mesh CIDR。
- 已有 FRP LAN 后端不能落入计划 Mesh CIDR。
- Mesh 启动后再检查一次实际接口/路由。

冲突时阻止本次 Mesh 启动，不静默改变正在运行的 FRP 出口；如果接口创建后的复核失败，关闭刚创建的 Mesh 并显示原因。

### 4.5 运行时复检

运行中的受管实例每 5 秒重新检查 FRPS 出口和 LAN 后端冲突。DNS、Wi‑Fi/有线切换、VPN、Mesh 网卡重建或路由变化导致冲突时：

- 立即清除自动运行意图。
- 停止 FRPC 和所属 TargetGateway/代理资源。
- 进入 failed 状态并显示稳定错误码。
- 不自动在错误路径上反复重启。

事件处理绑定具体 `managedInstance`；旧实例的迟到事件不能停止新实例。

### 4.6 资源清理

- `platform.IPTunnel.Close` 使用 `errors.Join` 返回 cleanup 和 device close 错误。
- `mesh.Engine.Close` 返回 native、WireGuard/plain transport 清理错误。
- FRP `managedInstance.reap` 返回网关、受限代理和运行目录的联合清理错误。
- GUI 在 Mesh 停止或启动失败时显示清理不完整提示，不再无条件声称“网卡和路由已释放”。

## 5. 目标策略、地址池和依赖隔离

- 禁止云/平台元数据地址、固定 TLAN/FRP 管理端口、本机 FRPS 管理/vhost 端口以及运行时动态管理端口。
- `TargetReservation` 统一接入 Save/Start/Apply/Render 和运行时动态分配检查，包括 admin、出口代理、TargetGateway 与 visitor 监听端口。
- TLAN Mesh 目标明确支持 `10.0.0.0/8` 与 `100.64.0.0/10`，并按当前网络 ID、设备 ID、实际前缀和成员授权校验。
- Mesh 规则与独立 STCP/SUDP visitor 混用会拒绝，并引导拆分独立配置。
- 本机回环 FRPS 下，若规则把本地目标端口直接指向同一个公网发布端口，按已知自引用入口拒绝。

## 6. 本轮实际执行结果

以下均在本机执行：

```text
go test -mod=vendor ./... -count=1 -timeout 240s             PASS
go vet -mod=vendor ./...                                    PASS
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go vet ./...          PASS
go test -tags frp_audit_regression ./internal/frp            PASS
TLAN_FRP_INTEGRATION=1 go test ./internal/frp TestLive...   PASS
TLAN_FRP_LIVE=1 go test ./internal/frpauth TestLive...      PASS
go run ./cmd/client --ui-smoke-test ...                      PASS
```

真实 FRP 本机联调覆盖：TCP/UDP、HTTP/HTTPS、STCP/SUDP、visitor、托管 lease/续租/撤销、运行中 Apply、FRPC 崩溃恢复、TargetGateway fake-Mesh、受限出口代理实际使用和错误 CA/token。TargetGateway 的 Mesh provider 是 fake，不能替代真实虚拟接口验收。

### 6.1 当前构建产物

本轮代码冻结后已重建客户端 v0.5.1、Debian 服务端归档、独立 FRPS 归档和 Linux 单文件安装器：

- `dist/windows/TmkNetworkLAN.exe` SHA-256：`BC72EB2190CF894C30AEAF3B2BFED0CE5DC65F0A18ACE9A0A453210FA9A9862D`
- 新构建 EXE 的 `--ui-smoke-test`：PASS。
- 客户端 ZIP、服务端 ZIP、FRPS tar.gz、单文件安装器的最新摘要以 `dist/SHA256SUMS.txt` 为准。
- 客户端包内 `frpc.exe` SHA-256：`509F4FA082BF9B85F9AD27B45D37A89A8ACCB011F3B724CFF352DFAC90A94FEB`，与固定值一致。
- `test-server-installer.ps1`：PASS。
- 检查时未发现残留 `TmkNetworkLAN.exe`、`frpc.exe` 或 `frps.exe` 进程。

## 7. 尚未完成或不能宣称完成的内容

- 两台独立 Windows 经公网 FRPS 的双向业务和抓包。
- 真实 Wintun 接口重建、Wi‑Fi/有线切换、休眠恢复、第三方 VPN 和静态路由冲突。
- 真实 Debian/systemd/云防火墙部署和证书链。
- 真实游戏发现、广播/组播和 LAN 同地址冲突。
- 24–72 小时混合负载、句柄/内存趋势和竞态检测。
- `-race` 尚未运行；当前环境没有 CGO/gcc。
- QUIC/KCP/WSS/XTCP、插件透传、原始 TOML、自定义核心、后台服务和低权限 worker 属于后续能力，不应声称已经搬入。
- 未建立 Git tracked 基线；发布包必须在最终代码冻结后重新构建并更新 SHA-256。

## 8. 发布前门槛

1. 代码冻结后重新执行 R0 基线脚本。
2. 重建 Windows 客户端、Debian 服务端、独立 FRPS 包和安装器。
3. 从新 EXE 运行 UI smoke，并核对内置 frpc 哈希。
4. 在真实环境完成 R3 的双机、Linux、接口切换和长稳证据。
5. 只有完成上述步骤后，才把“本机测试通过”升级为“发布版本已验收”。