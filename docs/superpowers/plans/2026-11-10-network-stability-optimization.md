# TLAN 网络连接协议与稳定性优化计划

## Goal

在不改变现有 enrollment、成员凭据和 Relay 协议兼容性的前提下，降低瞬时网络故障导致的控制面失败、网络切换后的候选地址陈旧、以及 Relay 建链抖动。

## P0

### P0-1 控制面幂等请求重试与退避

**问题**：`internal/clientapi/client.go` 的 `request` 单次执行；DNS/TLS/连接重置或 502/503/504 会直接向上返回，Mesh 控制循环只能等下一次 5 秒 ticker。

**改动**：
- 在 `internal/clientapi/client.go` 增加可重试分类：
  - `GET`/`HEAD` 默认可重试。
  - 幂等写请求白名单：`/heartbeat`、`/candidates`、`/forwarding`。
  - `Enroll`、`CreateRelaySession`、`FRP lease create` 等有副作用的请求不得自动重试。
- 每次请求重新构造 body reader；最多 3 次尝试，使用指数退避 `250ms → 750ms` 加 ±20% jitter。
- 仅重试网络错误、`502`、`503`、`504`；`401/403/404/409/429` 不重试。
- 尊重 `Context` 取消；最后一次错误保留 `HTTPError` 状态码。
- 测试：`internal/clientapi/client_retry_test.go` 或扩展现有测试，覆盖 GET 重试、heartbeat POST 重试、Enroll 不重试、取消不重试、503 状态保留。

### P0-2 网络切换后的候选地址快速刷新

**问题**：`internal/mesh/control.go` 只在 `time.Since(lastGather) > time.Minute` 时重新采集 candidates；切换 Wi-Fi/热点后最多一分钟仍上报旧地址。

**改动**：
- 在 `internal/mesh/control.go` 增加轻量候选环境指纹：接口名、UP 状态、IPv4 地址、STUN 可用性变化。
- 每次控制循环比较指纹；变化时立即执行 `gatherCandidates()` 并 `SetCandidates`。
- 保持 5 秒心跳；STUN 探测继续有 3 秒超时，但刷新失败不能停止控制循环。
- 单元测试：为指纹函数增加纯函数测试，验证地址/接口变化会产生不同结果，相同集合稳定。
- 集成测试：`internal/mesh/engine_test.go` 增加“候选变化后同步次数增加”的测试，使用可注入接口快照或测试 helper。

### P0-3 Relay 建链退避与过期余量

**问题**：`internal/mesh/peers.go:ensureRelay` 每次 `syncPeers` 都可能立即重试失败建链；Relay ticket 快过期时没有主动续建保护。

**改动**：
- 为每个 peer 保存 `relayNextAttempt` 与连续失败次数；失败后退避 `1s → 2s → 4s`，上限 30s。
- 稳定成功或 peer 移除时清空退避状态。
- `meshBind.hasRelay` 增加最小剩余有效期判断（例如少于 30 秒视为需要重建）。
- 测试：`internal/mesh/peers_test.go` 验证失败退避、成功后清零、临近过期会重建、peer 删除会清理状态。
- 保持现有 Relay ticket 和服务端会话协议不变。

## P1

### P1-1 STUN 采集异步化

`gatherCandidates` 当前最多阻塞控制循环 3 秒。把 STUN 探测移到独立 goroutine，通过 generation 丢弃旧结果；心跳不受影响。

### P1-2 Windows 网络变更通知

复用 Windows IP Helper 地址/路由变更思路，在 `internal/platform` 暴露跨平台 `NetworkChange()` channel；Mesh control loop 收到通知后触发 P0-2 的刷新。非 Windows 实现为 no-op。

### P1-3 可观测性

为控制面重试、候选刷新、Relay 建链失败记录结构化计数，并在 `internal/mesh/status.go` 中暴露最近错误和重试次数，便于诊断“为什么没有直连/为什么还在中继”。

## Compatibility / Rollback

- 不修改服务端接口和 Relay frame 格式。
- 重试仅限幂等请求；客户端版本可单独回滚。
- 新增状态均为内存态，不影响成员凭据、IP 分配和持久化资源账本。
- 出现异常时可关闭重试策略或恢复 `controlLoop` 固定 60 秒候选刷新。

## Acceptance

- `gofmt -l` 无输出。
- `go vet -mod=vendor ./...` 通过。
- `go test -mod=vendor ./... -count=1 -timeout 900s` 全部通过。
- Windows 客户端 `--ui-smoke-test` PASS。
- 新增测试覆盖重试边界、候选指纹变化、Relay 退避。
- 不改变已有 enrollment、Session、Relay、FRP 行为。

## Decision Needed

- 是否允许对 `SetCandidates`、`Heartbeat`、`SetForwarding` 这三个幂等 POST 自动重试。
- 是否把 P1-2 的 Windows 网络变更通知纳入本轮；它改动平台层但收益最直接。

## Implementation Status (2026-11-10)

- P0-1 已完成：`internal/clientapi` 幂等重试、退避和测试。
- P0-2 已完成：候选环境指纹刷新与 5 秒级网络变化感知。
- P0-3 已完成：Relay 失败退避、成功清零、临近过期重建和测试。
- P1-1 已完成：候选/STUN 刷新异步化，不阻塞心跳控制循环。
- P1-2 未单独接入系统通知；P0-2 已通过每 5 秒指纹比较获得同类收益，仍可作为后续优化。
- P1-3 仅保留现有 `LastError`/诊断通道，结构化重试计数未新增。
