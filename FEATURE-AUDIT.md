# 目标功能核对（2026-10-17）

核对对象为当前源代码、README、验证记录，以及最初“自建服务器、Radmin VPN 风格组网、Dark Hours 联机改善”的开发方案。这里的 RadminLan 按此前约定指 Radmin VPN。

结论：总体架构接近，核心 IPv4 组网数据通道已实现，但尚未达到 Radmin VPN 全功能等价，也没有完成最初开发方案中的全部模块。“核心开发完成”不能等同于“全部目标完成”。

最新变更：当前熟人版客户端已改为内置服务器、只输口令加入、圆形电源启停；新增独立成员凭据及设备/网络范围权限、转发在线状态和加密通道往返延迟。2026-10-21 又接入 FRP 托管授权与 P3 TargetGateway。下表涉及共用管理令牌、仅有直连 RTT 的描述以此更新为准；完整多管理员、永久封禁、后台 Agent、L2 与游戏专用模块仍未完成。

## 公开产品能力与实现差异

Radmin VPN 官方帮助确认了网络名称与密码加入、虚拟网卡、Ping 和直连失败后的 Relay/TCP；官方主页列出自动更新；安全说明列出端到端 AES-256 和公共 Gaming Networks 的内置防火墙。TmkNetworkLAN 采用 WireGuard、Wintun 和自有控制协议，架构目标相近，协议不相同，也不与官方 Radmin 网络互通。

来源：

- [官方帮助](https://www.radmin-vpn.com/help/)
- [官方主页](https://www.radmin-vpn.com/)
- [官方安全说明](https://www.radmin-vpn.com/security/)

远程桌面、远程文件传输等 Radmin 集成功能需要另装 Radmin Server，不能将其全部视为 VPN 自带的数据通道功能。聊天等未能从本次官方页面确认的能力不纳入确定性差异清单。

## 当前实现与原定目标

| 能力 | 状态 | 代码所支持的范围 |
| --- | --- | --- |
| 自有 Debian 服务端 | 已实现，待实机部署验收 | Linux amd64 独立二进制；信令、STUN、中继可在一台服务器运行 |
| Windows 原生 GUI EXE | 已实现 | 白蓝界面；运行时需同目录 Wintun DLL 和管理员权限 |
| 内网穿透（FRP P2/P3 受控发布） | 已实现本机回环、物理 LAN、TLAN 成员/本机 Mesh 地址、TCP/UDP/HTTP/HTTPS/STCP/SUDP、visitor、多配置、托管租约和 TargetGateway | 固定 FRP v0.71.1、强制 TLS、独立 Job；FRPS Login/NewProxy/Ping/NewUserConn 插件、端口/域名配额、按设备撤销、mesh_peer/mesh_self 授权、管理员目标服务授权、虚拟接口绑定和依赖暂停/恢复已接入；真实公网/双机/抓包/长稳和低权限 worker 仍未验收 |
| 应用流量转发（显式代理） | 已迁移 | 功能、Windows helper、Linux gateway、GUI 和部署文件已移至 `D:\TmkTrafficSandbox`；TmkNetworkLAN 主客户端不再提供该页面或打包 helper；透明按进程转发需签名 WFP 组件，尚未实现 |
| 创建、加入、退出网络 | 已实现 | 网络密码、持久化成员、稳定身份与虚拟 IPv4 |
| 端到端加密 | 已实现 | wireguard-go；服务端转发加密载荷 |
| UDP 直连、STUN、中继回退 | 已实现基础路径 | UDP 直连与 HTTP/HTTPS Upgrade 中继；本地真实加密实例已测 |
| 所有原定传输模式 | 部分 | 尚无 Direct TCP、UDP Relay、QUIC 路径 |
| 成员、路径、流量与诊断 | 部分 | 路径、握手、直连 RTT、流量；缺少主动虚拟 IP Ping、完整丢包率和游戏故障分类 |
| 多网络 | 部分 | 服务端保存多个网络，客户端同一时刻只启动一个网络 |
| GUI 与后台 Agent 分离 | 未实现 | 关闭窗口即取消会话并释放网卡；无客户端常驻系统服务、托盘保持在线和启动恢复 |
| IPv4 LAN 发现 | 部分 | 转发限制广播、子网广播和组播；每秒 100 包、每包最多 64 个对端 |
| 完整 L2/TAP 网络 | 未接入运行链路 | 有 Ethernet/ARP/桥接单元，但当前 Windows 数据面为 Wintun L3；不传任意以太网帧，无 IPv6 |
| 成员 ACL 与网络防火墙 | 未接入运行链路 | ACL 规则求值库存在，但 mesh 收发路径未调用；Windows 仅配置虚拟接口防火墙例外 |
| 用户与管理员权限分离 | 基础已实现 | 普通客户端独立成员凭据、仅允许本机/本网络操作；管理员可在客户端入网令牌框输入管理令牌，仅管理客户端解锁管理面板；无完整多管理员与网络所有者角色 |
| 踢人、永久吊销、密钥轮换 | 部分 | API 可移除成员，客户端约 5 秒同步；GUI 只有本机退出；无永久封禁，持有令牌及网络密码的设备可重新加入，无身份密钥轮换流程 |
| 邀请与网络管理 | 不完整 | 无一次性邀请、网络改名/删除/改密、设备改名的完整管理流程 |
| 自动更新、发布签名 | 未实现 | 手动 ZIP 发布；Wintun DLL 的官方签名不等于客户端 EXE 已签名 |
| Dark Hours 专用兼容模块 | 未实现完整模块 | 当前只有通用网络、路由与诊断；无游戏版本/分支检查、Steam/EOS 进程检查、游戏日志采集和专用可回滚策略 |
| 生产化与性能等价 | 尚不能确认 | 无真实 Debian 启动、两台独立 Windows 跨公网验收；不能据本地测试推断兼容率、速度和长期稳定性相同 |

单网络最多 128 个成员；广播最多复制给 64 个对端。以上是当前程序限制，不是对 Radmin VPN 上限的推测。

## 关键代码证据

- [实际数据面](internal/mesh/engine.go)：`Start` 使用 `platform.OpenTunnel`；`Diagnostics` 仅检查虚拟地址、握手、路径和最近错误；成员轮询间隔为 5 秒。
- [广播转发](internal/mesh/tunnel.go)：IPv4 封装、速率与扇出限制。
- [客户端生命周期](cmd/client/desktop_windows.go)：关闭窗口取消会话；加入时只持有一个 `engine`；GUI 退出网络使用本机设备 ID。
- [控制面权限](internal/control/server.go)：管理 API 使用 `AdminToken`，成员 API 使用设备/网络范围的成员凭据；FRP lease 路由只允许认证成员访问自己的租约。
- [成员存储](internal/storage/store.go)：有移除和重新加入，没有永久吊销状态或网络所有者字段。
- [L2 桥接](internal/l2/bridge.go) 与 [ACL](internal/network/acl.go)：构造与求值目前只在其单元测试中调用，不能当作已经接通的产品功能。
- [现有验证范围](VALIDATION.md)：本地加密传输与 Wintun 实测通过；未进行 Dark Hours 测试。

## 达到原目标的后续优先级

1. 完成设备凭据、网络所有者与成员权限、GUI 成员管理、永久吊销及密钥管理。
2. 分离客户端 Agent 与 GUI，增加后台保持、启动恢复和故障重连；完成多网络同时在线。
3. 把 ACL 和可配置广播策略接入数据面，补齐虚拟 IP Ping、虚拟链路质量检测与其他需要的传输模式。
4. 根据原定兼容范围完成 Windows TAP/L2 接入及完整帧转发，避免将已有 L2 算法库误算为已交付能力。
5. 开发 Dark Hours 专用诊断与可回滚配置；按用户当前要求继续不运行游戏兼容性测试。
6. 完成真实 Debian 与跨公网双 Windows 验收、长期运行验证，再完成签名、更新和发布流程。

这些条目区分了开发缺项与验证缺项；不以文件存在、编译通过或界面状态作为实际组网成功的证明。



