# 公网 managed FRP UDP / HTTP vhost 验证报告

日期：2026-10-21（Asia/Shanghai）  
目标服务器：`<SERVER_IP>`（CentOS 7）  
Windows 客户端：当前工作区 `<REPO_ROOT>`  
验证方式：SSH 仅通过 `D:/SSH.txt` 作为凭据数据读取；本报告不包含密码、join code、FRP token、lease capability 或私钥。

## 1. 验证范围

本次使用真实公网控制面、managed FRPS `0.71.1` 和 Windows 端生产 `internal/frp` Manager 路径验证：

- 临时成员入网；
- 临时 managed lease；
- UDP 公网回显；
- HTTP vhost 自定义域名；
- Host Header 重写；
- 请求/响应 Header；
- 停止后 UDP 端口关闭、HTTP vhost 路由移除；
- lease 撤销、临时成员删除；
- 服务器配置备份、恢复和 SHA-256 核验；
- 测试 secret 清理。

测试域名：`example.com`，DNS 实测解析到 `<SERVER_IP>`。  
测试 UDP 端口：`30002`。测试前确认 `30000-30999` 无监听，lease 状态中也没有 `30002`。  
HTTP vhost 入口：`http://example.com:18080`。

## 2. 最终结果

| 检查项 | 结果 | 实际证据 |
| --- | --- | --- |
| 临时成员 enroll | PASS | 使用 join code 入网，生成临时设备身份 |
| managed lease 创建 | PASS | 控制面返回 lease，未输出 capability |
| FRPS Login/NewProxy 观察 | PASS | lease status 中 `LoginSeen=true`、`ProxySeen=true` |
| UDP 公网回显 | PASS | Windows 向 `<SERVER_IP>:30002` 发送 payload，收到完全一致的 echo |
| HTTP custom domain | PASS | 经 `example.com:18080` 返回 HTTP 200 |
| Host rewrite | PASS | backend 收到 `Host: backend.tlan-verify.invalid` |
| 请求 Header | PASS | backend 收到 `X-TLAN-Request: public-e2e` 和 `X-Client: windows-public-e2e` |
| 响应 Header | PASS | 客户端收到 `X-TLAN-Response: verified` |
| 停止 FRPC | PASS | Manager 正常停止 |
| UDP 端口关闭 | PASS | Windows 侧不再收到 echo；服务器 `ss` 无 `:30002` 监听 |
| HTTP vhost 路由移除 | PASS | 原域名请求不再返回测试 backend |
| lease 撤销 | PASS | lease 记录进入 revoked 状态；测试记录随后定向清理 |
| 临时成员删除 | PASS | 成员列表不再包含测试设备，原 token 失效 |
| 配置恢复 | PASS | 配置 SHA-256 恢复为 `c36a10a67218e4d210f9901d1a78701767509c19c6c31e97c39d96378b419363` |
| 服务状态 | PASS | `TLAN.service`、`tlan-frps.service` 均为 `active` |
| secret 清理 | PASS | 本地和远端临时 join code / token 文件已删除，远端临时目录不存在 |

最终服务器核验输出：

```text
member_absent=true
lease_revoked=true
test_lease_record_purged=true
udp_port_closed=true
restore_config_sha_match=true
services_active=true
remaining_member_count=1
member_cleanup=already_absent
secret_cleanup=true
VERIFY_OK
```

Windows harness 输出：

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
```

## 3. 执行摘要

1. 对 `/var/lib/lanmesh/tlan-config.yml` 做 `0600` 备份，记录原 SHA-256。
2. 临时加入 `allowed_domains: example.com`，重启控制面并等待 `/health` 成功。
3. 从服务器临时目录读取 join code 和 FRPS outer token，只下载到本地受保护临时文件；未打印值。
4. Windows harness 使用固定 `frpc v0.71.1` 和真实 managed lease，启动本地 UDP/HTTP backend。
5. 从 Windows 经公网 `30002` 和 `18080` 发起真实数据请求并校验内容。
6. 停止 Manager，验证公网端口/路由、lease 和成员清理。
7. 服务器侧再次核验成员、lease、端口、配置摘要和服务状态。
8. 删除本地与远端临时 secret，确认临时目录和测试 lease 记录不存在。

可重复脚本和说明：

```text
<REPO_ROOT>\.tmp-runtime\public-frp-e2e\README.md
<REPO_ROOT>\.tmp-runtime\public-frp-e2e\run_public_frp_e2e.ps1
<REPO_ROOT>\.tmp-runtime\public-frp-e2e\main.go
<REPO_ROOT>\.tmp-runtime\public-frp-e2e\prepare_remote.py
<REPO_ROOT>\.tmp-runtime\public-frp-e2e\verify_remote_and_restore.py
```

一键编排脚本已实际执行并通过：`HARNESS_EXIT=0`、`VERIFY_EXIT=0`、`LOCAL_SECRETS_PRESENT=False`。

sanitized 结果文件：

```text
<REPO_ROOT>\.tmp-runtime\public-frp-e2e\run\result-20261021-140301.json
```

## 4. 验证中发现并修复的缺陷

第一次清理时发现一个真实启动缺陷：

- 测试 HTTP lease 已撤销，但撤销记录仍保存在 `/var/lib/lanmesh/frp-leases.json`；
- 配置恢复为空 `allowed_domains` 后，控制面启动时重新用当前域名白名单校验历史 lease；
- 该校验失败导致 `TLAN.service` 进入反复启动失败；
- 配置文件本身已经正确恢复，摘要匹配备份。

处置：

- 立即只删除该测试 lease 的精确 ID，保留其他 lease 记录；
- 恢复服务并通过 health；
- 未删除任何真实成员；
- 未输出 capability hash 或 token。

源码修复已加入 `internal/frpauth`：

- 持久化 lease 加载时只做结构校验，不把当前端口/域名/配额策略当作历史记录的结构合法性条件；
- 加载后对仍 active 但不符合当前策略的 lease 做 fail-closed 撤销并持久化；
- 增加“撤销 lease 在域名白名单缩小后仍可启动”“active lease 在白名单缩小后被撤销”和“策略协调不丢失 service 授权”的回归测试。

该修复已通过本机测试，并已在 2026-10-21 15:31 的受控服务端发布中部署；部署后重新执行 UDP/HTTP 回归通过。最终部署哈希和扩展协议矩阵见 `docs/FINAL-PUBLIC-DEPLOYMENT-VERIFICATION-2026-10-21.md`。

## 5. 本机验证

```text
go test -mod=vendor ./... -count=1 -timeout 300s
go vet -mod=vendor ./...
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go vet -mod=vendor ./...
go test -mod=vendor -tags frp_audit_regression ./internal/frp -count=1 -timeout 180s
go test -mod=vendor ./internal/frpauth -count=1
```

结果：全部通过。  
未执行 `go test -race`：当前环境没有可用的 CGO/gcc 组合，不能声称 race 已验证。

## 6. 未覆盖边界

- 只有一台 Windows 客户端，未完成两台 Windows 的真实 Mesh 联调；
- 未做物理 LAN 抓包和接口切换；
- 未做 XTCP 双端公网 P2P 打洞；
- WSS 已通过外部 Caddy 8444 的 managed 端到端回显验证，并在双 FRPS 改造后完成 TCP/HTTP/HTTPS/TCPMUX 组合验证；
- 未做 24-72 小时长稳；
- 该历史轮次未修改 `dist`；后续发布物已重新构建，最终摘要以 `dist/SHA256SUMS.txt` 为准。