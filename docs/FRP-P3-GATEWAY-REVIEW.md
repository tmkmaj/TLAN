# FRP P3 TargetGateway 只读审计报告

- 审计日期：2026-10-21（Asia/Shanghai）
- 审计目录：`<REPO_ROOT>`
- 审计范围：`internal/targetgateway/**`、`internal/mesh/target.go`、`internal/mesh/target_route_windows.go`、`cmd/client/frp_mesh_windows.go`、`internal/frp/manager_windows.go`，对照 `docs/FRPC-INTEGRATION-PLAN.md` 的 P3、6.2、15.4。
- 说明：本报告是只读审计结果，没有修改实现代码；审计期间工作区被并发修改，行号以最终快照为准。

## 后续修复说明

首次审计后已完成以下修复：

- 增加管理员登记的目标服务授权（`/api/v1/frp/services`）；`mesh_peer` 租约必须引用目标成员已登记且协议/端口匹配的服务 ID，撤销服务会同时撤销引用它的活动租约。因此 P0 中“任何成员关系即可公开服务”的缺口已收敛为管理员管理授权；目标成员 B 的逐次弹窗确认仍未实现。
- TCP 空闲检测改为整条连接级活动时间，单向持续流量不会再被反向读超时切断。
- 依赖重试改为在 `opMu` 内重新检查 `desiredRun`，用户 Stop 后不会再次启动。
- UDP 首次 dispatch 的 `WaitGroup.Add` 已移到 `g.mu` 临界区内，消除 Close 先 Wait 后 Add 的竞态。
- 撤销瞬间仍有一个已通过检查但尚未写出的在途 chunk/datagram 窗口；代码已尽量缩短，但“撤销后允许流量严格为零”仍需高吞吐抓包验证。
## 结论

P3 数据面主体已经可运行，并且当前快照已修复此前最明显的 GUI 操作 context 生命周期问题：`internal/frp/manager_windows.go:638-640` 使用独立 runtime context，`internal/frp/live_gateway_windows_test.go:144-152` 已覆盖 Start 返回后取消操作 context 的路径。当前快照还具备初始 lease 校验、`mesh_self`、ServiceID、服务端精确 target 字段、`IP_UNICAST_IF` 和依赖等待/重试。

但 P3 仍不能宣称完全完成。最高风险 5 条如下，其中没有一条被现有自动化测试完整覆盖。

## P3 最高风险 5 条

### 1. P0：成员目录被当作发布授权，缺少逐服务授权/B 端确认

**证据**

- `internal/control/frp_leases.go:139-198`：服务端只根据当前网络成员目录校验目标 DeviceID、虚拟 IP 和公钥，然后签发租约。
- `internal/frpauth/model.go:66-82`：租约规则没有独立 GrantID、B 端确认、授权版本或撤销版本。
- `internal/frp/manager_windows.go:1171-1213`：客户端只核对返回租约中的 target 字段，不验证 B 的逐服务授权。
- 方案要求见 `docs/FRPC-INTEGRATION-PLAN.md:236-242` 和 `:419`：必须绑定 A、B、网络、协议、端口、FRPS/入口、有效期、授权版本和撤销状态，不能把成员关系当作公开其他成员服务的授权。

**可复现证据**

A、B 加入同一网络；B 启动任意本机服务；A 配置 B 的 DeviceID、虚拟 IP、公钥和端口并启动。服务端只要确认 B 是当前成员就会签发租约，B 不需要确认，A 即可通过 FRPS 公网入口访问 B 的服务。

**测试覆盖**

**未被覆盖。** 现有 `live_gateway` 测试使用 `gatewayTestProvider`/`gatewayTestLease`，没有 B 端确认、授权版本或逐服务授权测试。

### 2. P1：TCP 空闲超时按方向计算，会切断持续单向传输

**证据**

- `internal/targetgateway/tcp.go:119-159`：每个方向的 `copyStream` 单独设置 `src.SetReadDeadline(now + IdleTimeout)`。
- `internal/targetgateway/tcp.go:102-109`：任一方向返回错误就关闭整条 `tcpPair`。
- `internal/targetgateway/types.go:21`：默认空闲时间为 5 分钟。

**可复现证据**

backend 持续向 client 推送数据、client 不发送数据；超过 5 分钟后 client -> backend 方向读超时，即使 backend -> client 一直在传输，整条连接仍被关闭。下载、日志推送和远程桌面等长单向流会受影响。

**测试覆盖**

**未被覆盖。** `internal/targetgateway/tcp_test.go` 覆盖半关闭、并发、撤销和 generation，但没有“单向持续流量超过 IdleTimeout 不应断开”的测试。

### 3. P1：依赖重试与用户 Stop 存在竞态，可能重新拉起已停止的 FRP

**证据**

- `internal/frp/manager_windows.go:205-208`：`Start` 在获取 `opMu` 前无条件执行 `desiredRun.Store(true)`。
- `internal/frp/manager_windows.go:463-467`：`Stop` 先设置 `desiredRun=false`。
- `internal/frp/manager_windows.go:1517-1525`：`retryDependency` 检查 desiredRun 后直接调用 `m.Start(context.Background())`。

**可复现证据**

Mesh gateway 失效后进入 `waiting_dependency`；用户点击 Stop；重试 goroutine 已读取 desiredRun=true，随后调用 Start，Start 又把 desiredRun 置 true。若 Stop 先获得 `opMu` 并完成停止，重试 Start 仍可能在其后启动新实例。

**测试覆盖**

**未被覆盖。** 当前没有 desiredRun/retryDependency 与 Stop 并发测试。

### 4. P2：UDP dispatch 与 Close 的 WaitGroup/生命周期竞态

**证据**

- `internal/targetgateway/udp.go:98-140`：`dispatchUDP` 在解锁后才执行 `g.wg.Add(1)` 并启动 `session.run`。
- `internal/targetgateway/gateway.go:128-159`：`Close` 关闭 listener/session 后执行 `g.wg.Wait()`。

**可复现证据**

在首个 UDP 数据报到达、session 尚未 Add 时并发调用 Close。Close 可能先完成 Wait 并关闭 Done，之后 dispatch 才 Add/启动 session；严重时触发 WaitGroup Add/Wait 误用，至少会破坏“Done 在全部 goroutine 退出后关闭”的契约。

**测试覆盖**

**未被覆盖。** `TestUDPContextCancellationClosesSessions` 是先建立 session 再取消，未覆盖首次 dispatch 与 Close 的竞态。

### 5. P2：撤销瞬间仍存在在途数据窗口

**证据**

- `internal/targetgateway/tcp.go:128-145`：先 `guard.check`，再执行 `dst.Write`；撤销可发生在检查和写入之间。
- `internal/targetgateway/udp.go:271-283`：先 `guard.check`，再执行 `g.udp.WriteToUDPAddrPort`。
- `internal/targetgateway/lease.go:90-108`：撤销通过 250ms 轮询检测。

**可复现证据**

高吞吐连接上撤销 lease，抓包/计数器可能观察到一个 32KB TCP chunk 或一个 UDP datagram 在撤销检查之后仍被写出。方案 `docs/FRPC-INTEGRATION-PLAN.md:421-427` 要求撤销后失去授权的允许流量在实测中为零。

**测试覆盖**

**部分覆盖，不充分。** 现有测试验证撤销后不建立新连接、不再调用 dialer；但没有验证撤销后的在途字节为零，也没有真实高吞吐抓包。

## 其他重要残余问题

- **P2 接口索引缓存：** `internal/mesh/engine.go:113` 只缓存一次 `interfaceIndex`，`internal/mesh/target.go:209/232` 后续复用；`internal/mesh/target_route_windows.go:28-50` 虽已设置 `IP_UNICAST_IF`，但没有每次连接 `GetBestRoute2` 路线快照，也没有接口重建后的索引刷新。真实 Wintun/物理 LAN 抓包仍未完成。
- **P2 provider 快照竞态：** `cmd/client/frp_mesh_windows.go:17-35` 通过闭包读取 `a.engine` 并缓存 networkID；`cmd/client/desktop_windows.go:406/447` 在 UI 线程修改 engine。`UpdateMembership` 未同步更新 provider 的 networkID。
- **P2 公钥提示矛盾：** `cmd/client/frp_ui_windows.go:864` 提示公钥可留空，但 `internal/frp/validate.go:197-198` 要求 `mesh_peer` 公钥非空。
- **P2 Lease Done 语义：** `internal/mesh/target.go:87/100/143` 返回 `e.ctx.Done()`，generation 在 `internal/mesh/engine.go:97` 初始化后没有看到递增；成员删除/IP/公钥变化主要依赖 Validate 轮询，不是目标级 Done 事件。
- **P3 UI 重复分支：** `cmd/client/frp_ui_windows.go:366-373` 出现两个相同的 `case s.State == "waiting_dependency"`，第二个分支不可达。

## 已通过验证

当前快照执行并通过：

```text
go test -mod=vendor ./... -count=1
go vet -mod=vendor ./...
```

真实本机 FRPS/FRPC 联调通过：

```text
$env:TLAN_FRP_INTEGRATION='1'
$env:TLAN_FRPS_BINARY=(Resolve-Path '.tmp-runtime\frps-v0.71.1.exe').Path
go test -mod=vendor ./internal/frp -run TestLiveTargetGatewayPublishAndDependencyStop -count=1 -v
```

结果：`PASS`。该测试使用真实 frpc/frps 和 TargetGateway，但 Mesh provider/dialer 是测试实现，不是实际 Wintun Mesh。

## 验证限制

- 当前 `CGO_ENABLED=0` 且没有 gcc，无法执行 `go test -race`；P2 竞态结论来自代码时序和静态审查。
- 未完成真实两台 Windows、Wintun/WireGuard、物理 LAN 同地址抓包、真实公网 FRPS、真实 Debian 和 24–72 小时长稳验收。
- 因此本报告不能作为“P3 全部功能已安全完成”的发布结论。

## 最终判定

当前 P3 已达到本机 fake-provider + 真实 FRPS/FRPC 可运行程度；首次审计列出的 P0 已通过管理员登记目标服务授权收敛，P1 的单向 TCP 空闲超时和 Stop/重试竞态、P2 的 UDP dispatch/Close 竞态均已修复并有回归测试。剩余发布门槛是真实双机/Wintun/物理 LAN 抓包、撤销瞬间高吞吐零流量验证，以及目标成员 B 的逐次确认 UI。

## 最终复核（2026-10-21 08:0x，当前最新快照）

本次复核不重复此前已修复的 P0/P1/P2：管理员服务授权、TCP 单向空闲、UDP dispatch/Close、Stop/retry 已按当前代码重新核对。当前快照的全量 `go test`、`go vet` 均通过；本机真实 FRPS/FRPC + fake Mesh provider 联调仍通过。以下只列当前仍存在或有明确验收缺口的问题。

### 当前最高风险 5 条

1. **P1：服务授权过期后，`Renew` 仍可继续延长租约**
   - 证据：`internal/frpauth/store.go:692-716` 的 `Renew` 只检查 lease 自身 revoked/expired，没有调用 `authenticateLocked`，也没有检查 `rule.TargetServiceID` 对应 service 的 `ExpiresAt`。
   - 对比：`internal/frpauth/store.go:863-880` 的 `authenticateLocked` 才检查 service revoked/expired。
   - 可复现：创建短 TTL 的 service grant，获取 lease，推进时钟超过 service `ExpiresAt`，调用 `Renew`；当前会成功并延长 lease。客户端 watchdog 因此可能继续认为租约健康，直到 FRPS Ping/日志路径间接停止。
   - 覆盖：**未被覆盖**。现有 `internal/frpauth/store_test.go` 测试续租和 service 撤销，但没有“service 过期后 Renew 必须失败”的测试。

2. **P2：`watchGateway` 会在 Stop 或旧实例 watcher 返回后覆盖当前状态**
   - 证据：`internal/frp/manager_windows.go:1521-1544` 在停止实例后无条件设置 `m.state = "waiting_dependency"`；没有检查 `desiredRun`，也没有检查 `m.instance == inst`。
   - 可复现：Mesh gateway 失效的同时用户点击 Stop；如果 watcher 在 `inst.stopping` 检查之后、Stop 完成之前继续执行，最终管理器状态可能显示“等待依赖”，但用户实际已停止且不会重试。旧实例 watcher 也可能覆盖新实例状态。
   - 覆盖：**未被覆盖**。现有测试只验证 `startForRetry` 在 desiredRun=false 时返回，没有覆盖 Stop 与 gateway watcher 的竞态。

3. **P2：frpc 进程异常退出后不会进入依赖重试，desiredRun 仍为 true**
   - 证据：`internal/frp/manager_windows.go:808-830` 的 `watchProcess` 在非 stopping 退出时直接设置 `state = "failed"`，没有调用 `retryDependency`；而 gateway 失效路径才触发重试。
   - 可复现：运行一个 Mesh profile 后强制结束 `frpc.exe`；进程 watcher 会释放 lease、进入 failed，但 `desiredRun` 仍为 true，管理器不会自动重新启动。
   - 覆盖：**未被覆盖**。当前没有 frpc crash + 自动恢复测试。

4. **P2：Mesh Lease 的 Done 仍绑定整个 Engine context，generation 实际为常量**
   - 证据：`internal/mesh/target.go:87/100/143` 返回 `e.ctx.Done()`；`internal/mesh/engine.go:97` 初始化 `generation: 1`，搜索代码没有 peer/接口/路线变化时的 generation 递增。
   - 方案要求：`internal/targetgateway/types.go:114-130` 明确 Done 应在成员删除、IP/公钥变化、授权撤销和 generation 变化时关闭。
   - 现状：成员/IP/公钥变化主要靠 `Validate` 250ms 轮询（`internal/targetgateway/lease.go:90-108`），不是目标级 Done 事件；gateway 的 generation watcher 虽然能比较值，但 adapter 从不产生新的 generation。
   - 覆盖：**部分覆盖**。`internal/mesh/target_test.go` 只验证 Engine context 关闭，没有验证成员删除/IP/公钥变化时 Done 立即关闭。

5. **P2：`Gateway.Close` 不等待 `watchLease` 和 guard watcher**
   - 证据：`internal/targetgateway/gateway.go:118-122` 启动 context closer 和 `go g.watchLease()`，但两者不在 `g.wg`；`internal/targetgateway/gateway.go:128-159` 的 `Close` 只 `g.wg.Wait()`。`internal/targetgateway/tcp.go:50` 和 `internal/targetgateway/udp.go:148` 的 `guard.watch` 同样未纳入等待。
   - 可复现：使用一个在 `Validate` 中阻塞且忽略 ctx 的测试 validator；建立连接后调用 `Close`，`Done` 可先关闭而 watcher 仍在运行。正常 adapter 应遵守 ctx，但该 Close 契约和异常资源回收不成立。
   - 覆盖：**未被覆盖**。现有 context cancellation 测试没有检查 watcher goroutine 或阻塞 validator。

### 其他当前未覆盖的 P3 完成条件

- **P2：撤销瞬间的在途数据窗口仍未消除。** `internal/targetgateway/tcp.go:145-171` 和 `internal/targetgateway/udp.go:271-283` 都是先 `guard.check` 再 `Write`；撤销可发生在两者之间。现有测试只验证撤销后不建立新连接，没有验证高吞吐下撤销后的在途字节为零，也没有真实抓包。
- **P2：真实物理 LAN 隔离仍只有代码约束，没有抓包证据。** 当前每次拨号会重新解析接口索引并设置 `IP_UNICAST_IF`，但 `internal/mesh/target.go:208-258` 没有 `GetBestRoute2` 目标路线快照；方案要求的 Wintun/物理 LAN 同地址、接口重建和第三方 VPN 场景没有真实双机测试。
- **P3：UI 公钥提示与校验仍矛盾。** `cmd/client/frp_ui_windows.go:864` 提示“可留空”，但 `internal/frp/validate.go:203-205` 要求 `mesh_peer` 公钥非空。用户留空保存会失败；当前没有 UI 测试覆盖。
- **P3：UI 状态文案仍需做单分支测试。** `cmd/client/frp_ui_windows.go:366-373` 当前有一个 `waiting_dependency` 分支；建议用 Snapshot 状态测试确认“等待组网/自动重试”文案与实际状态一致。

### 结论

当前 P3 的主要数据面修复已经生效，测试也覆盖了先前的 TCP 单向空闲和 UDP 首次 dispatch/Close 场景。仍不能宣称 P3 完全完成，剩余最高优先级是 **服务授权过期后 `Renew` 未失效**；其次是 Stop/旧实例 watcher 状态覆盖、frpc 崩溃不重试、目标级 Done/generation 语义和 gateway watcher 生命周期。
## 后续补充复核（2026-10-21）

在“最终复核”之后又完成以下代码修复：

- `frpauth.Store.Renew` 现在复用 lease 服务授权校验；目标 service grant 过期后续租返回 `ErrExpired`，新增回归测试。
- `watchGateway` 在停止后重新检查 `desiredRun` 和当前 instance；用户 Stop 或旧实例 watcher 不再覆盖新状态。
- frpc 非预期退出后，如果 `desiredRun=true` 会自动进入受控重试。
- Mesh 增加 generation done channel；peer 新增、删除、虚拟 IP 或公钥变化时关闭旧 done 并递增 generation。
- TargetGateway 的 lease watcher 和连接级 guard watcher 纳入等待，`Close` 不再早于 watcher 退出关闭 Done。
- `mesh_peer` 配置允许公钥留空，由控制面目录填充；修复 UI 提示与客户端校验矛盾。
- 管理员服务授权增加 ServerID 绑定；服务授权过期/撤销会联动租约。

仍未完成的发布门槛：目标成员 B 的逐次弹窗确认 UI、撤销瞬间高吞吐“零在途流量”抓包、真实双机 Wintun/物理 LAN 同地址与接口切换、公网 FRPS/Debian 和 24–72 小时长稳。