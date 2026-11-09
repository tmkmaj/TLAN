# 应用流量转发（Egress）设计

日期：2026-11-09。状态：**设计定稿，核心包开发中；透明转发数据面尚未实现**。本文对应 `docs/superpowers/plans/2026-11-09-app-egress-forwarding.md`，是该计划的架构说明与决策记录。

## 1. 目标与边界

在现有客户端增加与「虚拟网卡组网」「内网穿透」并列的第三个独立模块：把**指定 Windows 应用**的 TCP/UDP 流量经一台自有 Linux Egress Gateway 出网。

不做：

- 不与 Radmin 私有协议互通，不复用 FRPC 的 data plane；
- 不把 FRPS / 现有中继改造成通用代理；
- 不做多服务器负载均衡、计费或策略语言；
- 不提供「无限制访问服务器内网 / 云元数据 / 管理端口」的能力。

三个模块必须相互独立：启动、停止、失败与恢复互不级联；Egress 不要求先启动 Mesh。

## 2. 组件

| 组件 | 位置 | 职责 |
| --- | --- | --- |
| GUI 页面 | `cmd/client/egress_page_windows.go`（待建） | 规则增删改、启停、状态与错误展示；只调用 manager，不实现数据面 |
| Egress Manager | `internal/egress/manager_windows.go`（待建） | desired/observed 协调、每条规则的 instance/lease/helper/watcher |
| 核心模型 | `internal/egress/{model,validate,store,protocol,session}.go` | 规则模型、校验、独立存储、版本化协议、会话 |
| Helper | `cmd/egress-helper`（待建） | 提权、进程级捕获、WFP 规则、随客户端退出清理 |
| Gateway | `internal/egressgateway`、`cmd/egress-gateway` | 认证、解封装、目标策略、NAT/SNAT、配额 |
| 租约 API | `internal/egressgateway/lease_api.go` | 创建/续租/查询/撤销，绑定设备与规则 |

## 3. 数据流

```text
目标应用 → (WFP 按进程重定向) → egress-helper → ChaCha20-Poly1305 隧道
        → Linux Egress Gateway → 策略校验 → NAT/SNAT → 公网
返回流量沿原路返回；非目标应用不受影响。
```

控制面（租约）与数据面（隧道）分离：租约失效、gateway 断线或 helper 异常时，**匹配应用必须被阻断**，不得回退本地直连。

## 4. 协议

帧格式（与计划一致）：

```text
magic(4)="TLNE" | version(1)=1 | type(1) | flags(2) |
sessionID(16) | streamID(8) | payloadLen(4, BE) | payload | tag(16)
```

- 解析时先校验 magic / version / length，**校验通过后才分配内存**；payload 上限 64 KiB。
- AEAD：ChaCha20-Poly1305；密钥由 32 字节租约秘密经 HKDF-SHA256 派生；AAD 覆盖头部字段。
- 帧类型：handshake / handshakeAck / open / data / close / udp / keepalive / error / revoke。
- 数据帧必须绑定已认证 session；拒绝未知类型、错误 session、重放与非单调序号。
- `revoke` 由 gateway 主动下发；客户端收到后立即 fail-closed。

## 5. 策略

| 策略 | 取值 | 行为 |
| --- | --- | --- |
| IPv6 | `block` / `proxy` | 首版 `block`：匹配应用的 IPv6 流量直接阻断并在 UI 明示；不允许静默直连 |
| DNS | `remote` / `local` / `block` | `remote` 使用 gateway 指定解析器；`block` 阻断；未知取值拒绝启动 |
| KillSwitch | 显式布尔 | 为 true 时 tunnel 失效即阻断匹配应用；不得默认关闭 |
| 目标 | CIDR 白名单 + 类别拒绝 | 拒绝回环、私网、链路本地、组播、未指定、元数据地址、管理端口 |
| 配额 | 连接数 / 字节 / 速率 | 由 gateway 强制，超限拒绝新连接并计数 |

## 6. 状态机

`stopped → starting → running → stopping → stopped`，异常时为 `error`，策略或租约拒绝时为 `blocked`，部分规则可用时为 `degraded`。状态必须来自真实 snapshot，而非 UI 缓存；运行中禁止编辑需要重启才生效的字段。

## 7. 资源与清理

每条规则的 runtime 目录独立；helper 以挂起方式创建并先挂入 Job（复用 FRP 的 `CREATE_SUSPENDED` + `KILL_ON_JOB_CLOSE` 模式），确保崩溃后进程树随宿主退出。运行目录在写入任何凭据前设置受保护 DACL（当前用户 + SYSTEM），并带归属标记；仅在原 PID 不存在时清理异常残留，历史无标记目录保留。

WFP 过滤器、路由、接口与防火墙规则必须带产品标记；停止时只删除本产品创建的资源，绝不 flush 无关规则。Linux 侧启用 `ip_forward` 前记录原值，回滚时恢复。

## 8. 安全模型

- 租约绑定 device / profile / rule / policyVersion，带有效期与随机 nonce；raw secret 只在签发时返回一次，服务端只存 SHA-256。
- 每条数据帧绑定 session 并做重放检查；未知 session、错误 tag、伪造源地址一律丢弃。
- Gateway 是**出口**而不是开放代理：必须拒绝私网/元数据/管理端口，限制连接数与带宽。
- 日志与诊断脱敏 token、lease secret、私钥与 payload。

## 9. 关键限制（必须如实告知）

1. **按进程透明重定向需要签名内核组件。** 仅靠用户态无法把任意进程的 TCP/UDP 透明改道；正式路线是 WFP callout 驱动（或等价签名组件）。在获得可用且签名的实现之前，本模块只能提供：模型、存储、协议、网关、策略与 helper 骨架，**不得宣称透明转发完成**。
2. **真实端到端验收需要真实 Linux 主机**（转发/NAT）与外部网络；本机无法替代。
3. 首版若不支持 IPv6，必须阻断而不是放行直连；这与「完全转发」的完成判定绑定。

## 10. 分阶段

1. 模型 / 校验 / 独立存储（本阶段）
2. 版本化协议与 TCP/UDP 会话
3. 租约 API、认证、策略、配额
4. Linux gateway 与 NAT 生命周期
5. helper IPC 与 WFP（依赖签名组件）
6. GUI 第三页与桌面接线
7. 真实 Windows + Linux 验收、打包与安全审查
