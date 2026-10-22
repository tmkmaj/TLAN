# 服务器部署与公网验证记录

> 本记录保留了首次部署时的状态；2026-10-21 15:31 已完成最终更新部署。
> UDP 7002/7003、TCP 18081、WSS vhost 18082/18444 和 WSS TCPMUX 18083
> 均已上线并通过真实公网 managed 组合验证，详见 `docs/FINAL-PUBLIC-DEPLOYMENT-VERIFICATION-2026-10-21.md`。

日期：2026-10-21（Asia/Shanghai）  
目标：`8.163.21.82`  
访问方式：SSH（凭据来自用户提供的 `D:/SSH.txt`，本记录不包含任何密码、token 或私钥）

## 1. 部署前环境

| 项目 | 实际值 |
| --- | --- |
| 系统 | CentOS Linux 7 (Core) |
| 内核 | `3.10.0-1160.119.1.el7.x86_64` |
| 架构 | x86_64 |
| systemd | 219 |
| 磁盘 | 40G，部署前已用 3.1G |
| 内存 | 1.7G |
| 现有服务 | `tmknetworklan.service`、`tmknetworklan-https.service` |
| 现有入口 | TCP 80、TCP 8443、UDP 3478 |
| 现有数据 | `/var/lib/lanmesh/data/state.json`，2594 bytes |

SSH 主机密钥首次连接指纹：

```text
SHA256:avo554+RKSb99NgeioOZ1M5ke8xeMX+HAI/xwAwnBEA
```

## 2. 部署前保护

额外备份：

```text
/var/backups/tmknetworklan/pre-deploy-20261021-133033.tar.gz
SHA-256 f18ade3eb428ddc755794804958f974ad16109d68e1c17d0df9138abca1273d6
```

备份包含旧服务文件、systemd unit、配置和成员状态；文件权限 0600。安装器另外创建了事务备份：

```text
/var/backups/tmknetworklan/install-ybfnospI
```

## 3. 安装包

上传到服务器：

```text
/var/tmp/TmkNetworkLAN-server-linux-amd64.run
```

部署时安装包 SHA-256：

```text
526f80f5bf4b40b8c0b926d56e246d5826ca7e831f774fae2404a76480657886
```

随后更新文档和 FRPS unit 后重新构建；当前 `dist/TmkNetworkLAN-server-linux-amd64.run` 的 SHA-256 为：

```text
688924250a150e9eaa7333403ec4ee8f72a3daba972e27c7ee19a3745332afa1
```

先执行 `--check`，预检通过后执行安装。安装器返回 `INSTALL_EXIT=0`。

## 4. 部署后核验

### 服务

```text
tmknetworklan.service          active (running), enabled
tmknetworklan-https.service    active (running), enabled
```

新主进程：

```text
tmknetworklan-server PID 5290
caddy PID 5317
```

### 二进制摘要

```text
/opt/tmknetworklan/tmknetworklan-server
0cc56851a648088d61d9447852ad28d6b96f6e6d599d713ff6f7ff2168b2c922

本地 dist/linux/tmknetworklan-server
0cc56851a648088d61d9447852ad28d6b96f6e6d599d713ff6f7ff2168b2c922
```

服务端二进制摘要完全一致。

### 端口

```text
TCP 80    Caddy
TCP 8443  Caddy
UDP 3478  tmknetworklan-server
TCP 8080  127.0.0.1 only
```

### 本机健康检查

```text
GET https://8.163.21.82:8443/health
{"status":"ok"}
```

### 当前 Windows 公网检查

```text
GET https://8.163.21.82:8443/health -> {"status":"ok"}
GET http://8.163.21.82/ -> HTTP 308 to https://8.163.21.82:8443/
STUN Binding UDP 3478 -> PASS
mapped=58.249.112.32:5527
```

### 鉴权检查

```text
GET /api/v1/session              -> HTTP 401 without token
GET /api/v1/frp/capabilities     -> HTTP 401 without token
GET /api/v1/networks with admin  -> HTTP 200
```

### 数据和服务兼容

- `/var/lib/lanmesh/tnlan-config.yml` 权限仍为 0600、`lanmesh:lanmesh`。
- `/var/lib/lanmesh/data/state.json` 权限仍为 0600、大小仍为 2594 bytes。
- 新进程日志出现 `private code enrollment enabled for network 我的私人网络`，说明旧网络状态已加载。
- 部署后观察到真实客户端 `GET /api/v1/session` 和 `GET /api/v1/frp/capabilities`，说明现有客户端能重新连接新服务端。
- 5 分钟错误日志为空。

## 5. FRPS 与 managed FRP

### 5.1 已部署

独立 FRPS 已安装并运行：

```text
版本       0.71.1
服务       tlan-frps.service active (running), enabled
控制端口   TCP 7000
vhost      TCP 18080 / 18443
业务端口   TCP/UDP 30000-30999
插件       127.0.0.1:9093
```

部署时使用的 FRPS 安装包 SHA-256：

```text
fa212e185ac6f90f7299f25cb6e2fd65514b1d580dbdb77b010424453595a1bd
```

随后修复 CentOS 7 unit 兼容警告并重新打包；当前 `dist/TmkNetworkLAN-frps-debian-amd64.tar.gz` 的 SHA-256 为：

```text
9f7c4c4572e9c38cc2545ce6505e28c319dea7b38db1ca594bfe47e84ee78379
```

FRPS 使用 Caddy 已签发的 `8.163.21.82` IP 证书；主 FRPS 7000 保持 TLS-only。WSS 8444 通过 Caddy 终止 TLS 后回源到独立的 127.0.0.1:7001 WSS FRPS 实例；详见 5.7。

控制面已切换为：

```yaml
frp:
  mode: managed
  core_version: "0.71.1"
  server_id: "frps-managed-1"
  plugin_listen: "127.0.0.1:9093"
  lease_state_file: "/var/lib/lanmesh/frp-leases.json"
  lease_ttl_seconds: 900
  allowed_ports:
    - start: 30000
      end: 30999
```

认证后的 capabilities：

```json
{"mode":"managed","core_version":"0.71.1","server_id":"frps-managed-1","lease_ttl_seconds":900,"plugin_ops":["Login","NewProxy","Ping","NewUserConn"],"features":["managed-leases","lease-renewal","lease-revocation","mesh-target-grants","target-service-authorization","target-member-approval"]}
```

### 5.2 公网端到端验证

使用临时成员和临时 managed lease 执行：

```text
临时成员 enroll                PASS
控制面签发 managed lease       PASS
FRPC TLS 连接 7000             PASS
FRPS 注册 TCP proxy 30001      PASS
Windows -> 8.163.21.82:30001   PASS
本地回显内容校验               PASS
停止 FRPC 后 30001 关闭        PASS
lease 撤销                     PASS
临时成员删除                   PASS
```

FRPS 日志确认了 Login、NewProxy、用户连接、proxy 关闭和 client exit。临时成员已从网络成员列表中删除，测试后 30001 不再监听。

### 5.3 端口和 TLS

从当前 Windows 验证：

```text
TCP 7000   可连接
TCP 18080  可连接
TCP 18443  可连接
UDP 3478   STUN Binding PASS
TCP 8443   HTTPS health PASS
```

FRPS TLS 证书使用与 Caddy 相同的公网 IP 证书，客户端使用系统根 CA 验证成功。

### 5.4 CentOS 7 unit 兼容

首次部署时 FRPS unit 使用了 systemd 219 不支持的 `ReadWritePaths`、`LockPersonality` 和 `ProtectSystem=strict`，日志出现警告。已改为：

```text
ProtectSystem=full
```

并移除两个旧版本不支持的指令；重启后无解析警告，FRPS 正常运行。
## 5.5 客户端配置

在 Windows 客户端“服务器设置”中使用：

```text
服务器地址       8.163.21.82
端口             7000
TLS serverName   8.163.21.82
模式             managed
server_id        frps-managed-1
可信 CA          从服务器复制 /etc/tlan-frp/server.crt 到 Windows 后选择
外层 FRP token   从服务器 /etc/tlan-frp/token 安全读取
```

不要把 `/etc/tlan-frp/token` 或客户端 token 发到聊天或提交到仓库。当前 `allowed_domains` 为空，因此已配置的 TCP/UDP 发布可用；HTTP/HTTPS 自定义域名发布需要先在控制面配置允许域名和 DNS。

### 5.6 证书续期同步

Caddy 的 IP 证书是短周期证书。已增加：

```text
/usr/local/sbin/tlan-sync-frps-cert
/etc/systemd/system/tlan-sync-frps-cert.service
/etc/systemd/system/tlan-sync-frps-cert.timer
```

timer 每 5 分钟检查 Caddy 证书文件；只有证书或私钥变化时才复制到 `/etc/tlan-frp` 并重启 FRPS。首次手动运行和 timer 状态均已验证为成功。

## 5.7 WSS 8444 端到端部署验证

### 5.7.1 部署前保护

- 本地 Caddyfile 备份：`.tmp-runtime/Caddyfile.pre-8444-20261021-135131`
- 服务器 Caddyfile 备份：`/opt/tmknetworklan/backups/wss-8444-20261021-135138/Caddyfile`
- 原 Caddyfile SHA-256：`120059fea802aa4cc28129d6e67839b636210b7d0fbe013c4aea5564c8ed9576`
- FRPS 配置备份：`/etc/tlan-frp/frps.toml.wss-backup-20261021-135519`
- 备份同时记录了 `tmknetworklan-https.service` 的 active/enabled 状态、unit、监听端口和 firewalld 规则。

### 5.7.2 Caddy 配置

`deploy/Caddyfile` 与服务器 `/opt/tmknetworklan/Caddyfile` 已同步，保留原有 8443 -> 8080，并新增：

```caddyfile
https://8.163.21.82:8444 {
	log
	tls {
		issuer acme {
			dir https://acme-v02.api.letsencrypt.org/directory
			profile shortlived
			disable_tlsalpn_challenge
		}
	}
	reverse_proxy 127.0.0.1:7000 {
		flush_interval -1
	}
}
```

- Caddy 版本：2.11.7
- Caddyfile SHA-256：`83ed0816bcf6bec64faa887ff8895ef3eda381d587b9f338463b4c056d84655f`
- `caddy validate`：`Valid configuration`
- `tmknetworklan-https.service`：`active`，已执行正式 restart
- 重启后 PID：9176
- 8443 与 8444 均监听 TCP；8443 仍返回原有的未认证 401，证明旧控制入口未被替换

### 5.7.3 防火墙

已通过 firewalld 同时添加运行时和永久规则：

```text
8444/tcp -> open
8443/tcp -> open
```

云安全组仍需由用户在云控制台确认 8444/tcp 放行；本次公网 WSS 实际连通，说明当前路径已可达。

### 5.7.4 FRPS WSS 双实例安全设置

主 FRPS 保持 TLS-only：

```toml
bindAddr = "0.0.0.0"
bindPort = 7000
transport.tls.force = true
```

独立 WSS FRPS 只监听 loopback：

```toml
bindAddr = "127.0.0.1"
bindPort = 7001
transport.tls.force = false
```

Caddy 8444 终止客户端 TLS，再转发到 `127.0.0.1:7001`。客户端仍使用
`serverPort=8444`、`protocol=wss`、`serverName=8.163.21.82`、可信 CA 和
`transport.tls.enable=true`。公网 7000 不再接受明文，7001 不暴露到公网。

双实例服务：

```text
tlan-frps.service      0.0.0.0:7000 TLS-only
tlan-frps-wss.service  127.0.0.1:7001 WSS loopback
```

WSS 验证完成后，主 TCP/TLS 7000 也重新通过了一次真实 managed 回显。
### 5.7.5 真实 WSS 回显

使用固定 `frpc 0.71.1`（SHA-256 `509F4FA082BF9B85F9AD27B45D37A89A8ACCB011F3B724CFF352DFAC90A94FEB`），
通过临时 managed 成员和短期 lease：

```text
临时成员 enroll                         PASS
控制面签发 managed lease                PASS
Windows frpc -> 8.163.21.82:8444 WSS    PASS
Caddy WebSocket upgrade                 status=101
FRPS Login 插件观察                     login_seen=true
FRPS NewProxy 插件观察                  proxy_seen=true
FRPS TCP proxy 30997                    PASS
Windows -> 8.163.21.82:30997 回显        PASS
回显内容逐字节一致                       PASS
Caddy restart 后重复 managed WSS         PASS
```

Caddy 访问日志记录 `uri=/~!frp`、HTTP/1.1 Upgrade 和 `status=101`；FRPS 日志记录
`client login info`、`tcp proxy listen port [30997]`、`new proxy ... type [tcp] success` 和
真实 `get a user connection`。测试未打印 token、lease capability、私钥或密码。

### 5.7.6 清理

两次测试的临时 lease 和成员均已撤销/删除，清理后 lease 查询返回 401；30997 不再监听；
本机无残留 `frpc`/`TmkNetworkLAN` 进程；远端临时 join code、server-id、CA 临时文件已删除。
服务器上的 Caddy 和 FRPS 服务保持 active，8444 保持监听。

### 5.7.7 发布工程同步完成

2026-10-21 15:31（Asia/Shanghai）已完成最终发布工程同步：

1. 使用最新源码重建客户端、服务端、FRPS 包和 Linux 安装器，并更新 `dist/SHA256SUMS.txt`；
2. 服务端二进制已部署，远端 SHA-256 为 `0eab75c8924b0a650cae23744785d000a4ced78404551fc7163b76b37e62a0bd`；
3. 主 FRPS 已启用 KCP/QUIC、TCPMUX 和 subdomain；WSS 实例已启用独立 HTTP/HTTPS vhost 和 TCPMUX；
4. 主机防火墙已放行 7000/tcp、7002-7003/udp、18080-18083/tcp、18443-18444/tcp、30000-30999/tcp+udp；云安全组仍需按实际环境确认；
5. KCP、QUIC、WebSocket、主/WSS TCP、HTTP、HTTPS、TCPMUX 的 managed 公网组合已重新验证，详见 `docs/FINAL-PUBLIC-DEPLOYMENT-VERIFICATION-2026-10-21.md`。

剩余外部验收仍是两台独立 Windows、真实 Wintun/物理 LAN、接口切换、XTCP 双端打洞和 24–72 小时长稳。

## 6. 回滚方式

若需回滚：

```bash
systemctl stop tlan-frps.service tmknetworklan.service tmknetworklan-https.service
tar -xzf /var/backups/tmknetworklan/pre-deploy-20261021-133033.tar.gz -C /
# 如需回滚控制面 frp 配置，同时恢复 /var/backups/tmknetworklan/tnlan-config-pre-frp-20261021-133727.yml。
systemctl daemon-reload
systemctl start tmknetworklan.service tmknetworklan-https.service
# 确认 FRPS 配置和证书后再启动 tlan-frps.service。
```

执行前应确认备份文件仍存在且摘要一致。

## 8. 公网 UDP / HTTP vhost 后续验证

2026-10-21 又完成了真实公网 managed FRP 的 UDP 与 HTTP vhost 验证：

- UDP `8.163.21.82:30002` 回显通过；
- `8-163-21-82.nip.io:18080` HTTP 200，Host rewrite 和请求/响应 Header 通过；
- 停止后 UDP 端口关闭、vhost 路由移除、lease 撤销、临时成员删除；
- 控制面配置摘要恢复到原值，临时 secret 清理完成。

完整结果见 `docs/PUBLIC-MANAGED-FRP-VERIFICATION-2026-10-21.md`。该验证同时发现并修复了历史 lease 在域名白名单缩小后导致控制面启动失败的源码缺陷；修复已通过本机回归并已部署到当前服务器二进制；部署后再次执行 UDP/HTTP 回归通过。
## 7. 安全提醒

- 用户提供的 `D:/SSH.txt` 仍是明文凭据文件，部署完成后应立即删除或移动到受控密码库。
- 本次使用 root SSH 密码登录；建议部署后改为临时 sudo 用户 + SSH 密钥，并轮换密码。
- 本次没有输出、保存或写入任何服务器 token、密码或私钥到报告。