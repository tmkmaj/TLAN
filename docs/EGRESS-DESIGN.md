# 应用流量转发（Egress）设计

更新日期：2026-11-10。状态：**显式 SOCKS5 代理模式已实现并通过本机端到端验证；透明按进程转发尚未实现**。本文对应 `docs/superpowers/plans/2026-11-09-app-egress-forwarding.md`。

## 1. 目标与边界

在现有客户端增加与「虚拟网卡组网」「内网穿透」并列的第三个独立模块。当前可交付的是显式代理：目标应用必须手动把 SOCKS5 代理指向 helper 的本地监听地址；helper 不修改进程路由，也不声称按进程隔离。

不做：

- 不与 Radmin 私有协议互通，不复用 FRPC 的 data plane；
- 不把 FRPS / 现有中继改造成通用代理；
- 不做多服务器负载均衡、计费或复杂策略语言；
- 不提供访问服务器内网、云元数据或管理端口的能力。

## 2. 组件

| 组件 | 位置 | 当前职责 |
| --- | --- | --- |
| GUI 页面 | `cmd/client/egress_page_windows.go` | 规则增删改、启停、状态/错误、显式代理横幅；启动 helper 进程 |
| 客户端核心 | `internal/egress` | 模型/校验/独立存储/DPAPI、TLNE v1、握手、TCP/UDP 会话 |
| Helper | `cmd/egress-helper` | 回环 SOCKS5（TCP CONNECT、UDP ASSOCIATE）；TLS + CA 固定，失败时拒绝连接 |
| Gateway | `cmd/egress-gateway`、`internal/egressgateway` | TLS 数据面、租约、目标策略、连接/字节配额、nftables/iptables NAT |
| 租约 API | `cmd/egress-gateway/lease_api.go` | 独立网关的租约签发、续租、查询、撤销；默认绑定 loopback |
| 部署资产 | `deploy/egress/` | 严格 YAML 示例、systemd unit、显式代理限制说明 |

## 3. 当前数据流

```text
目标应用（手动配置 SOCKS5） → egress-helper
    → TLS + TLNE v1 → Linux Egress Gateway
    → 目标策略校验 → NAT/SNAT → 公网
```

返回流量沿原路返回。helper 在租约/会话不可用时拒绝代理连接，不会回退为本地直连。

计划中的 WFP 数据流是：

```text
目标应用 → (WFP 按进程重定向) → egress-helper → 隧道 → Gateway → 公网
```

该路径需要签名 WFP callout 组件，当前仓库不包含，也不得对外宣称完成。

## 4. 协议与安全约束

- TLNE v1 帧：固定握手密钥完成 capability 认证，之后使用 `DeriveSessionSecret(capability)` 派生的方向独立会话密钥。
- AEAD：ChaCha20-Poly1305；AAD 覆盖帧头；长度在分配内存前校验，payload 上限 64 KiB。
- 客户端↔网关 TCP 帧只能携带 `tcp` 目标；UDP 帧只能携带 `udp` 目标。协议不匹配会在拨号前被拒绝，并有交叉测试。
- 目标策略拒绝回环、私网、链路本地、组播、未指定、云元数据和配置的管理端口。`deny_private`/`deny_metadata` 是强制硬拒绝，配置为 `false` 会被拒绝启动。
- 租约能力只存 SHA-256；撤销会关闭关联会话。
- 目标 hostname 解析后，对每个结果地址重新执行策略；混合安全/受限地址会整体拒绝。

## 5. 策略

| 策略 | Gateway CLI 当前取值 | 行为与限制 |
| --- | --- | --- |
| IPv6 | `block` | 首版部署只允许阻断；`allow_public`/`proxy` 不在网关 CLI 中开放。核心策略包保留 `allow_public` 以便未来扩展 |
| DNS | `remote` / `block` | `local` 被拒绝。`dns_servers` 当前是允许的 DNS 目标地址白名单；目标 hostname 的实际解析仍使用网关主机的系统 resolver |
| KillSwitch | 客户端策略字段 | 显式代理模式下 helper 失败即拒绝连接；按进程透明模式的 KillSwitch 尚未接入 |
| 目标 | CIDR 白名单 + 类别拒绝 | 私网/元数据/管理端口不可关闭 |
| 配额 | 连接数 / 字节 | 已强制执行；`max_rate_bps` 当前只记录，尚未实际限速 |

## 6. 状态与 UI

`stopped → starting → running → stopping → stopped`，异常为 `error`，策略拒绝为 `blocked`。GUI 展示真实 helper 状态；运行中禁止编辑配置。

2026-11-10 侧边栏 refinement：

- 72px 白色侧栏、44px 导航触控目标、46px 品牌容器；
- 选中页使用浅蓝填充与 deeper blue 图标，悬停/按下态保持可见；
- 键盘焦点使用按 DPI 缩放的双层焦点环；高对比度使用系统高亮/窗口颜色，侧栏和版本文字响应系统主题变更；
- 当前页向 MSAA/UIA 暴露 `selected` 状态；“更多操作/版本信息”使用准确的角色和描述；
- 侧栏底部加入 1px 分隔线、版本按钮与更清晰的版本号；
- Egress 页改为顶部对齐，空状态和规则表都不再悬在窗口中部。

实际截图见 `docs/screenshots/sidebar-refinement-2026-11-10.png` 与 `docs/screenshots/egress-explicit-proxy-2026-11-10.png`；焦点态见 `docs/screenshots/sidebar-focus-2026-11-10.png`。

## 7. 部署与回滚

- 严格 YAML；未知字段和多文档会被拒绝。示例为 `deploy/egress/egress-gateway.yaml.example`。
- Linux NAT 启用前记录 `ip_forward` 原值；规则带产品标记，回滚只删除本产品规则并恢复原值。
- 独立租约 API 默认绑定 loopback；显式配置的 HTTPS hostname 监听属于操作员选择，部署者必须自行限制网络访问和证书。
- 部署资产尚未并入主服务安装器，不能宣称已完成生产安装/升级清理验证。

## 8. 明确未完成

1. 签名 WFP/等价内核组件，以及透明按进程重定向。
2. 真实 Linux 主机上的 NAT、systemd、卸载/升级回滚验收。
3. 跨公网双机、目标/非目标应用对比、UDP 长连、撤销 SLA、长稳负载。
4. 租约 API 接入既有控制面（当前由独立网关提供）。
5. 自定义 DNS resolver、`max_rate_bps` 实际限速、透明模式 KillSwitch。
6. Mesh、FRP、Egress 三模块真机并行验收。

## 9. 完成判定

只有 `UDP/TCP 显式代理`、真实 Linux NAT、跨公网、撤销/断线 fail-closed、三模块并行、清理回滚、全量测试、UI smoke 和真实双机证据全部齐全，才能把“应用流量转发”标记为完全完成。当前只能声称：**显式代理链路已交付试用，透明按进程转发未完成**。