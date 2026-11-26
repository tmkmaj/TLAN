# Linux 服务端安装指南（TLAN）

你可以使用仓库根目录的一键脚本 `install.sh`（支持源码编译或 `--binary` 安装，自动安装 Go/Caddy/系统依赖、交互设置管理员密钥并配置 `systemctl`），或者使用自解压安装包 `TLAN-server-linux-amd64.run`。默认服务地址形式为 `https://<你的服务器地址>:8443`，STUN 为 `<你的服务器地址>:3478`。

支持范围：使用 systemd 的 x86_64/amd64（及 `install.sh` 支持的 arm64）Debian、Ubuntu、CentOS、RHEL、Rocky Linux、AlmaLinux、Fedora。不适用于无 systemd 的容器。

## 1. 放行云安全组 / 防火墙端口

在服务器对应安全组放行入方向：

| 协议/端口 | 用途 |
| --- | --- |
| TCP 80 | Let's Encrypt 证书验证及自动续期（使用域名证书时须保持公网可达） |
| TCP 8443 | 客户端 HTTPS 控制接口及加密中继 |
| TCP 8444 | Web 管理控制台 HTTPS 入口 / 公网 WSS 入口 |
| UDP 3478 | STUN，帮助客户端直连与延迟探测 |

保留原有 SSH 规则；无需将 TCP 8080、Caddy 管理端口 2019 或 WSS FRPS 回环端口 7001 暴露公网。服务器还需要正常的 DNS、出方向 HTTPS 和准确的系统时间。安装包内置程序，但证书签发需要联网。公网 IP 在云服务器上经 NAT 映射也可以，不要求公网 IP 出现在网卡上。

如果同时部署独立 FRPS 包，还需要放行以下端口。独立包的 `install-frps.sh` 会默认更新活动 firewalld/UFW 的主机规则；云安全组仍需手工放行。带 `--skip-firewall` 可跳过主机规则变更。

| 协议/端口 | 用途 |
| --- | --- |
| TCP 7000 | 主 FRPS 控制与工作连接，TLS-only |
| UDP 7002 / 7003 | 主 FRPS KCP / QUIC |
| TCP 18080 / 18443 | 主 FRPS HTTP / HTTPS vhost |
| TCP 18081 | 主 FRPS TCPMUX HTTP CONNECT |
| TCP 18082 / 18444 | WSS FRPS HTTP / HTTPS vhost |
| TCP 18083 | WSS FRPS TCPMUX HTTP CONNECT |
| TCP/UDP 30000-30999 | FRP 业务端口范围，与 `allowPorts` 一致 |

主实例和 WSS 实例使用不同的 vhost/TCPMUX 端口；WSS FRPS 的 7001 只监听 `127.0.0.1`，不要放行到公网。示例 subdomain 根为 `frp.example.com`。

## 2. 上传并安装

如果直接使用仓库一键脚本：

```bash
sudo bash install.sh
```

如果使用自解压 `.run` 安装包，将文件上传到服务器（例如 `/root`）后执行：

```bash
cd /root
sha256sum -c TLAN-server-linux-amd64.run.sha256
sudo bash ./TLAN-server-linux-amd64.run
```

已登录 root 时可以省略 `sudo`。通过 `bash` 执行无需 chmod，勿用 `sh`。只上传 `.run` 也能安装，其内部自带载荷校验。

可选：先执行只检查模式；它仅在临时目录解包与验证，不停止服务、不安装、不修改原配置。运行中的服务可能占用端口，正式安装会在停止本项目服务后再次检测。

```bash
sudo bash ./TLAN-server-linux-amd64.run --check
```

如果旧部署正在运行 `caddy.service`，默认拒绝接管。**确认旧 Caddy 仅用于本项目、没有承载其他网站后**，可在同一安装命令加参数：

```bash
sudo bash ./TLAN-server-linux-amd64.run --replace-caddy
```

该参数停止并禁用旧 `caddy.service`，保留其配置及证书目录，改由独立的 `tlan-https.service` 提供服务。若旧 Caddy 承载其他网站，请使用手工部署方案，勿使用该参数。

安装器会向当前活动的 firewalld 区域或已启用 UFW 添加上述四个主服务端口，不会关闭防火墙、SELinux 或刷新整个规则集。自定义 iptables/nftables、云安全组仍需自行配置。使用 `--skip-firewall` 可跳过主机防火墙变更。

## 3. 查看结果并连接客户端

- `READY` / 退出码 0：本机后端和经过正常证书验证的 IP HTTPS 健康检查通过；外部连通性仍需从客户端确认。
- `INSTALLED; HTTPS is not ready yet` / 退出码 2：程序已安装，HTTPS 尚未就绪。通常需检查 TCP 80、安全组、DNS、系统时间、CA 证书或 ACME 日志。Caddy 会自动重试，不必反复重装。
- 退出码 3：程序已安装，但主机防火墙添加规则失败，需要手动处理。
- 退出码 1：检查或安装失败。部署事务开始后的失败会恢复已备份的程序、配置、服务文件及服务启用/运行状态；保留成员数据与新建的服务账号、目录。进入“已安装”阶段后的证书或防火墙问题不会回滚已工作的后端。

在客户端连接页填写你部署好的服务器地址和入网密钥：

```text
服务器：https://<你的服务器地址>:8443
STUN：<你的服务器地址>:3478
入网码：服务器配置中的 network.join_code
```

在服务器本机用编辑器查看 `/var/lib/tlan/tlan-config.yml`，只把 `network.join_code` 分享给成员。不要公开整个配置文件，尤其是 `security.admin_token`。

管理控制台默认只监听 `127.0.0.1:8081`（启用 Caddy 时亦可通过 HTTPS 入口的 `8444` 访问）。在服务器本机或通过 SSH 隧道访问 `http://127.0.0.1:8081/admin`，使用你在安装时设置的 `security.admin_token` 登录。不要把 `8081` 加入公网安全组；如需局域网设备直接访问，把 `server.admin_listen` 改为服务器内网 IP，并在未配置 TLS 时显式设置 `server.admin_allow_insecure_http: true`，同时只在内网防火墙放行。

## 安装位置与升级行为

| 内容 | 位置 |
| --- | --- |
| 服务端、Caddy、Caddyfile | `/opt/tlan/` |
| 服务端配置 | `/var/lib/tlan/tlan-config.yml` |
| 默认成员数据 | `/var/lib/tlan/data/state.json` |
| 证书与 Caddy 状态 | `/var/lib/tlan-caddy/` |
| 每次安装的私有备份 | `/var/backups/tlan/install-*/` |
| 后端服务 | `tlan.service` |
| 优雅切换脚本 | `/opt/tlan/tlan-graceful-restart.sh` |
| HTTPS 服务 | `tlan-https.service` |

再次运行同一安装命令可以更新程序；已安装的 `/opt/tlan/tlan-graceful-restart.sh` 可在替换二进制后执行零窗口监听切换，旧进程最多排空 30 秒 Relay 会话。保留入网码、管理员令牌、网段、成员数据、STUN 和可选 TCP 中继配置；控制接口调整为 `127.0.0.1:8080`，后端的 `tls_cert/tls_key` 清空，由 Caddy 统一提供 HTTPS。YAML 会重新排版，原文件（含注释）保存在备份中。

为避免错误接管，安装器会拒绝管理路径中的符号链接、现有本项目 systemd drop-in，以及 `/var/lib/tlan` 以外的自定义存储路径。这些部署应先人工确认，参考 [IP 手工部署说明](IP-DEPLOYMENT.md)。不会停止其他占用端口的服务。已有自定义 STUN/TCP 中继端口会保留，但其额外防火墙规则需自行管理。

备份目录的 `paths.txt` 按行列出原路径，对应从零开始的 `file-0`、`file-1` 等备份；原来不存在的文件没有对应备份。`services.txt` 记录原服务状态，`state.json` 是停服后的数据快照（如存在）。**自动回滚不会用快照覆盖当前成员数据**。备份包含凭据，目录仅 root 可读；手工恢复前先停止两个本项目服务，并保留当前数据。

## 常用排查命令

```bash
systemctl status tlan tlan-https --no-pager -l
journalctl -u tlan -n 100 --no-pager
journalctl -u tlan-https -n 100 --no-pager
ss -lntup
curl --fail http://127.0.0.1:8080/health
curl --fail https://<你的服务器地址>:8443/health
timedatectl status
```

Prometheus 指标只在管理 listener 暴露，并要求管理令牌：

```bash
TOKEN=$(awk '$1=="admin_token:" {print $2}' /var/lib/tlan/tlan-config.yml | tr -d '"')
curl -H "X-Admin-Token: $TOKEN" http://127.0.0.1:8081/metrics
unset TOKEN
```

请从另一台电脑也运行 HTTPS 健康检查；不要使用 `curl -k` 判断是否修好。出现 `x509` 错误检查证书、系统 CA 与时间；证书签发失败重点看 Caddy 日志和公网 TCP 80；本机正常但远端失败重点检查安全组、主机规则及线路。

CentOS 缺少命令时需要的常见包：`util-linux tar gzip coreutils shadow-utils ca-certificates`；Debian/Ubuntu：`util-linux tar gzip coreutils passwd ca-certificates`。安装器会列出缺少的命令，不会在 CentOS 7 上盲目执行已经失效的软件源命令。端口绑定能力由内置工具配置，无需另装 libcap/setcap。`/var/tmp` 必须允许执行临时安装工具，安装目录所在文件系统需支持 Linux file capabilities；否则安装会报错。

## 构建与验证范围

Windows 开发机运行 `./build-server-installer.ps1` 生成 `.run`、SHA-256 文件和本说明。首次构建下载官方 Caddy 并校验固定 SHA-512；已有缓存可用 `-Offline`。发行包内含第三方许可证。

已在开发机进行全项目 Go 测试、Windows/Linux 静态检查、配置迁移/保留测试、静态 ELF 检查、Bash 语法检查、自解包载荷校验及模拟服务的失败恢复测试。FRPS 模板可通过 `powershell -ExecutionPolicy Bypass -File ./scripts/verify-frps-templates.ps1` 执行固定字段、TCP/UDP 监听冲突和真实 `frps verify` 检查；存在可运行的固定 0.71.1 二进制时优先执行真实校验。使用 `./test-server-installer.ps1 -Bash <bash路径>` 可复查安装包与恢复逻辑。已在真实 CentOS 7 服务器完成安装、服务启动、IP HTTPS 证书签发和公网 FRP 验证；Debian/Ubuntu 实机、SELinux 专项和 24–72 小时长稳仍未验证。兼容性以目标版本的内核、systemd 和 Bash 能力为设计依据。

参考：[Go 最低系统要求](https://go.dev/wiki/MinimumRequirements)、[Caddy 服务运行说明](https://caddyserver.com/docs/running)、[Let's Encrypt IP 证书说明](https://letsencrypt.org/2026/01/15/6day-and-ip-general-availability)。
