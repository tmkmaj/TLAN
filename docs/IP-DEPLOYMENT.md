# IP 直连部署说明（`<YOUR_SERVER_IP>:8443`）

客户端入口形式为 `https://<YOUR_SERVER_IP>:8443`，STUN 为 `<YOUR_SERVER_IP>:3478`。入网、控制和 HTTPS Upgrade 中继均可直接使用公网 IP，无需强制绑定域名。服务端用 Caddy 终止 TLS，后端仍监听本机 HTTP `127.0.0.1:8080`。

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

以下假定使用仓库自带的 systemd unit，应用在 `/opt/tlan/`，工作目录在 `/var/lib/tlan/`。在解压的新服务端包目录中执行：

```sh
sudo systemctl stop tlan
sudo cp -a /opt/tlan/tlan-server /opt/tlan/tlan-server.before-ip
sudo install -m 0755 ./tlan-server /opt/tlan/tlan-server
sudo cp -a /var/lib/tlan/tlan-config.yml /var/lib/tlan/tlan-config.yml.before-ip
sudoedit /var/lib/tlan/tlan-config.yml
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
sudo systemctl start tlan
curl --noproxy '*' -fsS --max-time 10 http://127.0.0.1:8080/health
```

应返回 `{"status":"ok"}`。全新部署请直接使用根目录的 `sudo bash install.sh` 完成初始化和 systemd 配置。

## 3. 更新 HTTPS 入口

如果此 Caddy 实例只用于 TLAN，在新服务端包目录执行：

```sh
sudo caddy validate --config ./Caddyfile --adapter caddyfile
sudo cp -a /etc/caddy/Caddyfile /etc/caddy/Caddyfile.before-ip
sudo install -m 0644 ./Caddyfile /etc/caddy/Caddyfile
sudo systemctl reload caddy
sudo journalctl -u caddy -n 100 --no-pager
```

若 Caddy 尚未启动，则使用 `sudo systemctl start caddy`。如果它还承载其他网站，请合并新 IP 站点和全局配置，避免覆盖其他站点；全局块只能有一个。

当使用内置 CA（`tls internal`）签发 IP 证书时，请将 Caddy 根证书导出并安装到客户端的受信任根证书存储；如配置了公网 ACME `shortlived` IP 证书，则在签发完成后可直接通过标准 HTTPS 验证：

```sh
curl --noproxy '*' --http1.1 -v --max-time 15 \
  --resolve <YOUR_SERVER_IP>:8443:127.0.0.1 \
  https://<YOUR_SERVER_IP>:8443/health
```

## 4. 客户端验证

启动编译好的 `TLAN.exe`，在加入页填入 `https://<YOUR_SERVER_IP>:8443` 和你的 `join_code`。也可以先在客户端电脑检查：

```powershell
curl.exe --noproxy "*" --http1.1 -v --max-time 15 https://<YOUR_SERVER_IP>:8443/health
```

应返回 HTTP 200 和 `{"status":"ok"}`，然后在 GUI 加入或恢复网络。服务端 IP 证书尚未部署好时，客户端仍会拒绝连接。

## 失败时检查

- 无 SNI 握手失败：检查 Caddy 是否加载新配置、IP 证书是否签发完成、`default_sni` 是否存在。
- IP 证书申请失败：检查 Caddy 版本、TCP 80 的监听及公网可达性、ACME 日志和服务器时间。
- 返回 502：检查后端 8080 和 YAML 的 TLS 字段是否清空。
- 本机 HTTPS 成功但公网失败：检查云安全组、主机防火墙和云平台接入策略；改用 IP 不等于已确认公网策略放行。

本次交付修改本地源码、部署配置和发布包，不会自动修改云服务器。公网证书签发只能在拥有该 IP 的服务器部署后验证。

参考：[Let's Encrypt IP 证书公告](https://letsencrypt.org/2026/01/15/6day-and-ip-general-availability)、[Caddy ACME 配置](https://caddyserver.com/docs/caddyfile/directives/tls)、[default_sni 配置](https://caddyserver.com/docs/caddyfile/options#default-sni)。
