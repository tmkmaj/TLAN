# TLAN 独立 FRPS 部署包

此包与 `tlan-server`、`tlan-config.yml`、成员数据库和 Caddy 完全独立。
它只提供 FRP 控制连接和用户明确创建的公网端口映射，不代替现有 Mesh 中继。

## 安装

```bash
tar -xzf TLAN-frps-linux-amd64.tar.gz -C /tmp/tlan-frps
sudo bash /tmp/tlan-frps/opt/tlan-frp/install-frps.sh
```

需要同时校验证书并启动服务时：

```bash
sudo bash /tmp/tlan-frps/opt/tlan-frp/install-frps.sh --start
```

安装脚本创建独立账户 `tlan-frp`、目录 `/opt/tlan-frp/0.71.1`、
`/etc/tlan-frp`、`/var/lib/tlan-frp`、`tlan-frps.service` 和
`tlan-frps-wss.service`。已有 `/etc/tlan-frp/frps.toml`、`frps-wss.toml`
和 token 永远不会被覆盖。

安装器会对实际生效的配置执行 `frps verify`，并检查固定端口矩阵。升级时若保留的旧配置缺少
KCP/QUIC、TCPMUX、subdomain 或 WSS vhost 字段，安装器会明确报告不匹配；带 `--start`
时拒绝启动，要求管理员手工合并新模板字段。这样不会静默覆盖生产配置，也不会把不完整配置标记为可用。

## TLS 与传输

FRPS 不会自动生成生产证书。把包含实际 FRP 域名/IP SAN 的证书放到：

```text
/etc/tlan-frp/server.crt
/etc/tlan-frp/server.key
```

客户端必须配置可信 CA 和正确的 TLS `serverName`。程序没有跳过证书校验的开关。
客户端的 `tcpMux` 和 `disableCustomTLSFirstByte` 必须与 FRPS 实际配置一致；默认均为开启，可在 GUI 服务器设置中切换兼容档位。
私钥只应允许 root 和 `tlan-frp` 读取。

WSS 使用独立的回环 FRPS 实例，主 FRPS 始终保持 TLS-only：

- `frps.toml`：`0.0.0.0:7000`，`transport.tls.force = true`。
- `frps-wss.toml`：仅 `127.0.0.1:7001`，`transport.tls.force = false`，只允许 Caddy 回源。
- Caddy 在公网 `8444/TCP` 终止客户端 TLS，再把 WebSocket 转发到 `127.0.0.1:7001`。
- 客户端仍使用 `protocol = "wss"`、8444、正确 `serverName` 和可信 CA。

主实例和 WSS 实例使用不同 vhost/TCPMUX 端口，避免同一主机上的监听冲突。
两个实例的 subdomain 根均为 `frp.example.com`。

## 端口矩阵

| 协议/端口 | 实例 | 用途 | 公网 |
| --- | --- | --- | --- |
| TCP 7000 | 主 FRPS | 控制与工作连接，TLS-only | 是 |
| UDP 7002 | 主 FRPS | KCP | 是 |
| UDP 7003 | 主 FRPS | QUIC | 是 |
| TCP 18080 | 主 FRPS | HTTP vhost | 是 |
| TCP 18443 | 主 FRPS | HTTPS vhost | 是 |
| TCP 18081 | 主 FRPS | TCPMUX HTTP CONNECT | 是 |
| TCP 7001 | WSS FRPS | Caddy 回源控制连接 | 否，仅回环 |
| TCP 18082 | WSS FRPS | HTTP vhost | 是 |
| TCP 18444 | WSS FRPS | HTTPS vhost | 是 |
| TCP 18083 | WSS FRPS | TCPMUX HTTP CONNECT | 是 |
| TCP 8444 | Caddy | 公网 WSS 入口 | 是，由主服务安装器放行 |
| TCP/UDP 30000-30999 | 两个 FRPS 实例 | 示例业务端口范围，与 `allowPorts` 一致 | 是 |

`frp.example.com` 用于 subdomain 访问；例如规则子域为 `demo` 时，
HTTP 访问形式为 `http://demo.frp.example.com:18080`。使用泛域名或 `nip.io` 解析通配子域时，无需额外逐条配置 DNS 记录。

## 防火墙

`install-frps.sh` 默认向当前活动的 firewalld 区域或已启用 UFW 添加上述 FRPS 公网端口；
不会关闭防火墙、刷新整个规则集或暴露回环端口 7001。使用 `--skip-firewall` 可跳过主机防火墙变更。
自定义 iptables/nftables 和云安全组仍需管理员自行放行：

- TCP 7000、18080-18083、18443-18444
- UDP 7002-7003
- TCP/UDP 30000-30999
- 若同时部署 TLAN 主服务，另有 TCP 80、8443、8444 和 UDP 3478

TCP 和 UDP 同号端口是独立协议；云安全组和主机防火墙需要分别按实际规则放行。
不要把 FRPS dashboard 暴露到公网；本包默认不启用 dashboard。

## 两种认证模式

- `private_token`：兼容独立共享 token。所有使用同一 token 的客户端共享认证，不具备设备级授权、端口租约或按用户撤销能力；不要把这种模式称为托管隔离。
- `managed`：TLAN 控制面签发设备级发布租约，FRPS 通过回环 HTTP 插件校验。外层 FRP token 仍是第一道门槛，但真正的 proxy 名称、类型、公网端口、域名和会话身份由 lease capability 约束。


## TLAN 托管授权模式

若要启用 P2 托管授权，在 `tlan-config.yml` 中设置：

```yaml
frp:
  mode: managed
  core_version: "0.71.1"
  server_id: "frps-managed-1"
  plugin_listen: "127.0.0.1:9093"
  lease_state_file: "/var/lib/tlan/frp-leases.json"
  allowed_ports:
    - start: 30000
      end: 30999
  allowed_domains:
    - "frp.example.com"
```

控制面提供 `GET /api/v1/frp/capabilities`（认证成员或管理员）用于读取 mode、核心版本、server ID、lease TTL、四个插件操作和支持特性；它不返回任何 capability 或 token。

TLAN 服务端会启动仅回环可达的 FRPS HTTP 插件；`frps.toml` 中的
`httpPlugins` 已配置为 `127.0.0.1:9093/api/v1/frp/plugin`，操作必须同时包含
`Login`、`NewProxy`、`Ping` 和 `NewUserConn`。缺少 `Ping` 时无法持续校验撤销，缺少
`NewUserConn` 时新连接无法逐次校验。FRPS 的共享 token 只作为外层门槛，真正的设备和端口授权由
TLAN lease capability 校验；插件不可达时 FRPS 必须拒绝登录，不能回退到仅共享 token。

托管模式需要 FRPS 与 TLAN 控制服务运行在同一台主机，或通过受保护的本地管理网络
把插件端口提供给 FRPS。不要把这个插件端口暴露到公网。
## 目标服务授权（P3）

跨成员发布 `mesh_peer` 时，不能只凭“对方是网络成员”就公开其服务。第一版采用管理员登记服务授权：

```bash
curl -fsS -X POST https://你的控制服务/api/v1/frp/services \
  -H "X-Admin-Token: $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"network_id":"net-xxx","device_id":"dev-b","service_id":"svc-game","protocol":"tcp","port":7777,"description":"B 的游戏服务","ttl_seconds":86400}'
```

响应中的 `id` 就是客户端规则里的“服务授权 ID”。删除授权会同时撤销引用该服务的活动租约：

```bash
curl -fsS -X DELETE https://你的控制服务/api/v1/frp/services/svc-game \
  -H "X-Admin-Token: $ADMIN_TOKEN"
```

`mesh_self` 是发布本机虚拟地址，不要求跨成员服务授权；`mesh_peer` 必须提供目标成员已登记的服务 ID、协议和端口。目标成员通过客户端“目标授权”窗口逐次同意、拒绝或撤销；管理员登记不再是唯一授权边界。
## 撤销与状态核对

- 托管客户端每 5 秒调用续租端点；FRPS 通过 `Ping` 和 `NewUserConn` 校验撤销。撤销、过期或成员删除后，官方 frpc 会在下一次心跳关闭控制连接，FRPS 在 8 秒 heartbeatTimeout 内清理；客户端同时停止受管 frpc 和 TargetGateway。
- 服务端删除成员时会批量撤销该成员的租约；已存在连接由客户端停止进程时一并断开。
- FRPS 必须和 TLAN 控制服务同时可用；插件不可达时必须 fail-closed，不得回退到仅共享 token。
- 客户端会读取控制面 lease status，确认 FRPS 已观察到 Login 和 proxy；这仍依赖控制面与 FRPS 的部署一致性，部署后应检查 FRPS 日志并确认四个操作均已配置。
