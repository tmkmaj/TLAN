# R2/R4 诊断、日志与 Windows 资源验证（2026-10-22）

本记录覆盖 2026-10-22 继续开发的内容。代码工作区为 `<REPO_ROOT>`。

## 1. 完成内容

### FRP 持久化日志

- 每个 profile 的日志写入 `Store.Root()\logs\frp.log`，不放入会被实例生命周期清理的 `runtime/`。
- 默认单文件 2 MiB、最多 5 个文件（含当前文件）、总大小 8 MiB。
- 支持 `frp.log.1` 至 `frp.log.4` 轮转和超限清理。
- 写入前继续执行 secrets 和常见凭据字段脱敏；内存环形缓存和磁盘日志共享脱敏结果。
- Windows 日志目录/文件使用受保护 DACL（当前用户和 SYSTEM）；Unix 使用 `0700`/`0600`。
- 新增 `Manager.LogStorage()` 和 `Snapshot.LogStorage`，诊断可查看路径、文件摘要、保留限制和最近错误。
- `Stop` 保留日志句柄，`Close` 刷新并关闭。

### 完整诊断上传

- 新增 `internal/diagreport`，对完整 FRP JSON 诊断做严格 schema、重复 key、深度、节点数、数组大小和大小限制校验。
- 新增 `UploadDiagnosticsWithFRP` / `SubmitDiagnosticsWithFRP`；完整 FRP 报告只附加到第一批 64 个 checks，旧 checks-only 协议保持兼容。
- 控制面诊断 API 支持可选 `frp_report`，保存前再次校验和脱敏；响应设置 `Cache-Control: no-store`。
- 客户端本地 JSON/文本导出行为不变，`diagnose()` 会同时上传 checks 和完整 FRP 报告。
- FRP 报告最大 2 MiB，单次请求最大 2.5 MiB，最多 32 个 profile，诊断历史仍按服务端 20 条滚动保留。

### Windows 网络变更通知

- 新增 `netpolicy.ChangeNotifier`，订阅 IP 接口、地址和路由变化。
- 事件通道合并突发通知，Manager 收到事件后执行 300 ms 去抖并触发 route recheck；保留 5 秒 ticker 作为兜底。
- 通知注册失败时记录诊断并继续轮询，不阻断 FRP 启动。

### Windows 资源缺陷修复

真实 `--adapter-smoke-test` 发现并修复：

- PowerShell CLIXML 进度输出污染查询：`SystemRunner` 改为分离 stdout/stderr，只返回命令数据；真实错误才附带清理后的 stderr。
- 防火墙 `InstanceID` 在目标 Windows 上可能是稳定字符串而不是 GUID：清理现在同时接受 GUID 和受限稳定标识，仍要求精确匹配。
- `Get-NetAdapter` 无结果时退出码为 1：查询脚本显式把“不存在”转换为空结果成功，不再把正常清理路径误判为失败。

修复后真实入口结果：

```text
PASS: created, configured and released LANMesh-Test
```

测试后确认：

```text
LANMesh-Test adapter = 0
LANMesh-Test IPv4 = 0
LANMesh-Test route = 0
LANMesh-Test firewall = 0
LANMesh PnP residue = 0
test process residue = 0
```

## 2. 本机验证

```text
go test -mod=vendor ./... -count=1 -timeout 480s
go vet -mod=vendor ./...
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go vet ./...
go test -mod=vendor -tags frp_audit_regression ./... -count=1 -timeout 480s
```

新增覆盖：

- 日志轮转、保留上限、脱敏、并发写入、UTF-8 截断、DACL/Unix 权限、路径逃逸拒绝。
- Manager Stop/Close 日志生命周期和 Snapshot 摘要。
- checks-only、129 checks 分批、FRP-only、完整报告、服务端重启后读取。
- 客户端/服务端双重脱敏，重复 key、未知字段、错误 schema、超大报告拒绝。
- Windows 变更通知注册/关闭、事件合并、Manager 事件唤醒。
- PowerShell CLIXML 清理、非 GUID 防火墙身份、适配器不存在查询。

## 3. 证据文件

```text
<REPO_ROOT>\.tmp-runtime\adapter-validation-20261022-171921\SUMMARY.md
<REPO_ROOT>\.tmp-runtime\adapter-test\report.txt
<REPO_ROOT>\internal\frp\persistent_logs.go
<REPO_ROOT>\internal\diagreport\report.go
<REPO_ROOT>\internal\netpolicy\change_windows.go
```

## 4. 真实公网诊断上传验证

2026-10-22 17:42（Asia/Shanghai）在已部署控制面 `<SERVER_IP>` 上执行临时成员诊断上传：

```text
DIAGNOSTIC_UPLOAD_E2E_PASS
uploaded=true
read_back=true
redacted=true
removed=true
```

测试报告包含 `profile-e2e` 以及故意放入的 `token=secret-e2e`、`Authorization: Bearer bearer-e2e`；服务端读取后仍保留 profile 结构，但敏感测试值均被脱敏。临时成员已删除，远端临时 join-code 文件已清理。服务端二进制 SHA-256 为 `0eab75c8924b0a650cae23744785d000a4ced78404551fc7163b76b37e62a0bd`。
## 4. 仍未完成

- 真实两台独立 Windows、真实物理 LAN 抓包、Wi-Fi/有线切换、VPN 和休眠恢复。
- XTCP 双端真实打洞；本机只有单物理上游，不具备两个独立 NAT 端点。
- 24–72 小时日志轮转、磁盘写满、掉电恢复和资源趋势。
- Windows SYSTEM/无人登录服务、生产更新签名和客户端自动更新入口。
- `go test -race` 当前环境没有可用 CGO/gcc。
- 真实控制面长时间并发诊断上传和 20 条报告滚动保留压力测试。