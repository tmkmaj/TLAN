# IP 直连升级：8.163.21.82:8443

客户端入口为 `https://8.163.21.82:8443`，STUN 为 `8.163.21.82:3478`。入网、控制和 HTTPS Upgrade 中继均使用 IP，业务请求不依赖旧域名。服务端用 Caddy 终止 TLS，后端仍监听本机 HTTP 8080。

## 1. 准备 Caddy 和端口

本配置已用官方 Caddy **2.11.7** 解析验证。旧版本可能不支持生产环境 IP 证书或 ACME profile，请升级到该版本或兼容的新版本。通过 [Caddy 官方 Debian 安装说明](https://caddyserver.com/docs/install#debian-ubuntu-raspbian)安装或升级后，执行 `caddy version` 确认版本。保留现有 Caddy 数据目录，以便保存证书、ACME 账户和续期状态。

在云安全组和服务器防火墙开放：

| 端口 | 用途 |
| --- | --- |
| TCP 8443 | 客户端 HTTPS 控制和中继 |
| TCP 80 | IP 证书 HTTP-01 验证及自动续期，必须持续可达 |
| UDP 3478 | STUN |

不需要把后端 8080 暴露到公网。该配置禁用 TLS-ALPN 验证，不依赖 TCP 443。服务器需要能够出站访问 Let's Encrypt ACME 服务。

## 2. 替换应用二进制，保留原数据

以下假定使用仓库自带的 systemd unit，应用在 `/opt/tmknetworklan/`，工作目录在 `/var/lib/lanmesh/`。在解压的新服务端包目录中执行：

```sh
sudo systemctl stop tmknetworklan
sudo cp -a /opt/tmknetworklan/tmknetworklan-server /opt/tmknetworklan/tmknetworklan-server.before-ip
sudo install -m 0755 ./tmknetworklan-server /opt/tmknetworklan/tmknetworklan-server
sudo cp -a /var/lib/lanmesh/tnlan-config.yml /var/lib/lanmesh/tnlan-config.yml.before-ip
sudoedit /var/lib/lanmesh/tnlan-config.yml
```

只确认或调整 `server` 下这三个值，保留其他字段，尤其是 `storage.data_dir`、管理员令牌、入网令牌和原 `state.json`：

```yaml
server:
  listen: 127.0.0.1:8080
  tls_cert: ""
  tls_key: ""
```

上面是字段片段，不是完整配置文件。不要删除 `stun_listen` 等已有配置，也不要重新生成网络或成员数据。若此前 Go 程序直接监听 8443，必须先移到本机 8080，才能把 8443 交给 Caddy。

管理控制台字段与 Caddy 无关：保留 `server.admin_listen`、`admin_tls_cert/key` 和 `admin_allow_insecure_http`。默认管理页只供本机/SSH 隧道使用，不要把管理端口映射到公网。

```sh
sudo systemctl start tmknetworklan
curl --noproxy '*' -fsS --max-time 10 http://127.0.0.1:8080/health
```

应返回 `{"status":"ok"}`。全新部署请先按 README 创建服务用户、安装 systemd unit；首次运行只生成 YAML，需要检查后再启动一次。

## 3. 更新 HTTPS 入口

如果此 Caddy 实例只用于 TmkNetworkLAN，在新服务端包目录执行：

```sh
sudo caddy validate --config ./Caddyfile --adapter caddyfile
sudo cp -a /etc/caddy/Caddyfile /etc/caddy/Caddyfile.before-ip
sudo install -m 0644 ./Caddyfile /etc/caddy/Caddyfile
sudo systemctl reload caddy
sudo journalctl -u caddy -n 100 --no-pager
```

若 Caddy 尚未启动，则使用 `sudo systemctl start caddy`。如果它还承载其他网站，请合并新 IP 站点和全局 `default_sni 8.163.21.82`，避免覆盖其他站点；全局块只能有一个。

该 Caddyfile 显式使用 Let's Encrypt 的 `shortlived` profile 获取 IP 证书，并自动续期。证书有效期约六天，依赖自动续期；不能使用仅包含旧域名的证书。`default_sni` 用于选择无 SNI 连接的证书，不会让客户端重新发送旧域名。

等待日志确认 IP 证书签发成功，再执行：

```sh
curl --noproxy '*' --http1.1 -v --max-time 15 \
  --resolve 8.163.21.82:8443:127.0.0.1 \
  https://8.163.21.82:8443/health
```

此命令在本机连接但仍校验公网 IP 身份。应返回 HTTP 200，不使用 `-k`。

## 4. 换新版客户端验收

完整解压新版 Windows ZIP 后启动。旧版使用 `https://relay.tmknetwork.online` 或 `https://relay.tmknetwork.online:8443` 保存的成员令牌会用于固定的新 IP 入口，成功恢复成员后保存新地址。自定义服务器不会触发这项迁移；设备私钥和虚拟 IP 保留，无需删除本地配置。

先在客户端电脑检查：

```powershell
curl.exe --noproxy "*" --http1.1 -v --max-time 15 https://8.163.21.82:8443/health
```

应返回 HTTP 200 和 `{"status":"ok"}`，然后在 GUI 加入或恢复网络。服务端 IP 证书尚未部署好时，客户端仍会拒绝连接。

## 失败时检查

- 无 SNI 握手失败：检查 Caddy 是否加载新配置、IP 证书是否签发完成、`default_sni` 是否存在。
- IP 证书申请失败：检查 Caddy 版本、TCP 80 的监听及公网可达性、ACME 日志和服务器时间。
- 返回 502：检查后端 8080 和 YAML 的 TLS 字段是否清空。
- 本机 HTTPS 成功但公网失败：检查云安全组、主机防火墙和云平台接入策略；改用 IP 不等于已确认公网策略放行。

本次交付修改本地源码、部署配置和发布包，不会自动修改云服务器。公网证书签发只能在拥有该 IP 的服务器部署后验证。

参考：[Let's Encrypt IP 证书公告](https://letsencrypt.org/2026/01/15/6day-and-ip-general-availability)、[Caddy ACME 配置](https://caddyserver.com/docs/caddyfile/directives/tls)、[default_sni 配置](https://caddyserver.com/docs/caddyfile/options#default-sni)。
