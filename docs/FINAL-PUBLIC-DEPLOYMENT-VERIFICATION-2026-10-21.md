# 最终公网部署与协议组合验证（2026-10-21）

本记录是本轮最终证据汇总。验证通过 SSH 读取 `D:/SSH.txt` 作为凭据数据；报告不包含密码、join code、FRP token、lease capability 或私钥。

## 1. 最终部署

- 服务器：`8.163.21.82`，CentOS 7。
- 控制面服务端二进制 SHA-256：`0eab75c8924b0a650cae23744785d000a4ced78404551fc7163b76b37e62a0bd`，与本地 `dist/linux/tmknetworklan-server` 一致。
- 安装器、客户端 ZIP、服务端 ZIP、FRPS 包最终摘要以 `dist/SHA256SUMS.txt` 为准。
- `tmknetworklan.service`、`tmknetworklan-https.service`、`tlan-frps.service`、`tlan-frps-wss.service`、`tlan-sync-frps-cert.timer` 均为 `active`。
- 主 FRPS：TCP 7000（TLS-only）、UDP 7002（KCP）、UDP 7003（QUIC）、TCP 18080/18443（HTTP/HTTPS vhost）、TCP 18081（TCPMUX）。
- WSS FRPS：仅回环控制 `127.0.0.1:7001`；TCP 18082/18444（WSS vhost）、TCP 18083（WSS TCPMUX）。
- Caddy 8444 将公网 TLS/WebSocket 回源到 `127.0.0.1:7001`；公网 7000 的明文探测被重置。
- `subDomainHost = "frp.8-163-21-82.nip.io"`，DNS 已实测解析到 `8.163.21.82`。

## 2. 最终公网 managed 回归矩阵

以下均使用固定 `frpc v0.71.1`、临时成员、真实 managed lease、临时公网端口和真实 Windows 数据客户端。

| 用例 | 入口 | 结果 |
| --- | --- | --- |
| TCP | 7000 → 30990 | PASS |
| WebSocket | 7000 → 30996 | PASS |
| KCP | UDP 7002 → 30991 | PASS |
| QUIC | UDP 7003 → 30992 | PASS |
| HTTP subdomain | 18080 → `p0main.frp.8-163-21-82.nip.io` | PASS |
| HTTPS vhost | 18443 → TLS backend | PASS（见边界） |
| 主 FRPS TCPMUX | 18081 → `p0mux.8-163-21-82.nip.io` | PASS |
| WSS TCP | 8444 → 30995 | PASS |
| WSS HTTP subdomain | 18082 → `p0wss.frp.8-163-21-82.nip.io` | PASS |
| WSS HTTPS vhost | 18444 → TLS backend | PASS（见边界） |
| WSS TCPMUX | 18083 → `p0wssmux.8-163-21-82.nip.io` | PASS |

每个用例都验证了：

- managed lease 被 FRPS 观察到 Login 和 Proxy；
- 真实公网数据路径成功；
- Manager 停止后 TCP 端口关闭或 HTTP/HTTPS/TCPMUX 路由移除；
- lease 撤销、临时成员删除、成员 token 失效；
- 控制面配置 SHA-256 恢复为 `b8f17e74b6be87d8ce828bba026432c7f7808c3935a339247851334b2145091f`；
- 临时 join code、outer token 和远端临时目录清理完成。

## 3. 部署后基础回归

部署最新服务端二进制后再次执行 managed UDP/HTTP 完整回归：

```text
PASS temporary_member_enrolled
PASS local_backends_started
PASS managed_lease_login_and_proxy_observed
PASS public_udp_echo
PASS public_http_custom_domain_host_and_headers
PASS managed_frp_stopped
PASS public_udp_port_closed
PASS http_vhost_route_removed
PASS managed_lease_revoked
PASS temporary_member_deleted
PUBLIC_MANAGED_FRP_E2E_PASS
VERIFY_OK
```

结果文件：`.tmp-runtime/public-frp-e2e/run/result-20261021-153131.json`。

协议组合结果文件位于：

```text
D:\RadminLanPrivate\.tmp-runtime\p0-e2e\run\
```

## 4. 修复与一致性

本轮同时完成：

- 客户端补齐 `subdomainHost`、`publicTcpMuxPort` 和 WSS vhost 端口默认值，subdomain 访问地址现在包含完整后缀。
- 未入网时先创建 managed lease provider，入网后按“先更新 Manager、成功后再更新 provider”的顺序绑定身份。
- R2 新增独立 EndpointRegistry 和 ObservationDebouncer；R4 新增完整 FRP 诊断 JSON/文本导出。
- frpauth 续租保证到期时间严格前进，修复时钟粒度导致的偶发续租回归。
- FRPS 模板、安装器防火墙、发布包复制范围和真实 `frps verify --strict-config=true` 一致。

## 5. HTTPS 验证边界

服务器当前 FRPS 证书只有 `IP Address:8.163.21.82` SAN。HTTPS vhost 数据面测试使用本地 TLS backend，并在测试客户端跳过主机名校验、使用域名 SNI，以验证 FRPS 端口、SNI 路由和 TLS 透传链路；这不等于任意自定义域名已经具备浏览器可信证书。

生产使用自定义域名 HTTPS 时，必须为该域名配置包含正确 SAN 的证书，并让客户端使用对应可信 CA；不能把本测试扩展为“公网浏览器证书已验证”。

## 6. 仍未覆盖

- 两台独立 Windows 的真实 Mesh 组合；
- 真实 Wintun、物理 LAN 抓包、接口切换、VPN、休眠恢复；
- XTCP 双端真实打洞；
- 24–72 小时长稳和资源泄漏趋势；
- Windows SYSTEM/无人登录服务、生产自动更新签名和安装包代码签名；
- `go test -race`（当前环境无可用 CGO/gcc）。