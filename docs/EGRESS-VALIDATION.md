# 应用流量转发（Egress）验证记录

日期：2026-11-09。范围：`docs/superpowers/plans/2026-11-09-app-egress-forwarding.md` 的 Task 1–5 中**不触碰既有功能**的部分。

结论：**核心包已完成并通过测试；透明转发数据面、helper、网关二进制、GUI 接入与真实端到端验收尚未完成。** 因此本模块**不能**按计划的完成判定宣称完成。

## 已完成并验证

### 客户端核心 `internal/egress`

| 能力 | 验证 |
| --- | --- |
| 7 个状态与合法状态转换 | 状态迁移表测试 |
| 严格 JSON、绝对 exe 路径规范化、重复规则拒绝 | `model_validate_test.go` |
| 独立 `<configDir>/egress` 存储、原子写入、0600/0700、私有 ACL | `store_test.go` |
| `secrets.dat` 使用 DPAPI（`clientidentity.ProtectSecret`） | 明文不出现在磁盘的测试 |
| `TLNE` v1 帧：magic/version/长度先校验再分配 | 超长声明长度不读 payload 的测试 |
| ChaCha20-Poly1305 + 方向独立 HKDF 密钥 + AAD 覆盖头部 | 篡改 tag / 错误 session / 重放测试 |
| 每流单调序号、帧率限制 | `TestFrameAuthenticationAndReplay`、`TestFrameRateGuard` |
| 基于 `net.Pipe` 的握手、TCP stream、UDP datagram、半关闭、keepalive、重连、fail-closed | `session_test.go` |
| Start/Stop 幂等与并发安全 | `TestSessionConcurrentStopDuringStart` |

### 服务端核心 `internal/egressgateway`

| 能力 | 验证 |
| --- | --- |
| 租约签发/续租/撤销/查询，设备与 rule/policy 绑定 | `auth_test.go` |
| 一次性 capability，服务端只存 SHA-256，常量时间比较 | 同上；Get 不返回 raw secret |
| 过期/撤销后验证失败 | `TestLeaseIssuerRevocationAndBinding` 等 |
| TCP/UDP 连接数与字节额度 | `TestQuotaConnectionAndByteBudgets` |
| 目标分类：拒绝回环/私网/链路本地/组播/未指定/元数据/管理端口 | `TestClassifyTarget`、`TestSessionPolicyRejectsUnsafeTargets` |
| DNS/IPv6 策略 fail-closed | `TestSessionPolicyDNS`、`TestPolicyValidationFailsClosed` |
| Lease API 四个路由、严格 JSON、请求体上限、状态码 | `lease_api_test.go`（httptest） |
| NAT：nftables 优先、iptables 回退、产品标记、精确回滚、恢复 `ip_forward`、部分失败回滚 | `nat_test.go`（fake runner） |

## 执行的命令与结果

```text
gofmt -l internal/egress internal/egressgateway        → 无输出
go vet -mod=vendor ./internal/egress ./internal/egressgateway → 0
go test -mod=vendor ./internal/egress -count=1          → ok（36 个顶层 PASS）
go test -mod=vendor ./internal/egressgateway -count=1   → ok
go test -mod=vendor ./... -count=1 -timeout 900s        → 全部 ok（TEMP 指向工作区目录时）
GOOS=linux GOARCH=amd64 go build ./internal/egress ./internal/egressgateway → 0
GOOS=linux GOARCH=amd64 go test -c ./internal/egressgateway → 0
```

环境说明：本机 `C:\Windows\Temp` 的 ACL 会让 `internal/frp` 与 `internal/winproc` 的受限令牌测试返回 `Access is denied`（既有问题，与本次新增包无关）。把 `TEMP`/`TMP` 指向工作区内目录后，全量测试全绿。

未运行 `-race`：本机缺少 CGO/gcc。

## 未完成（对照计划完成判定）

| 计划要求 | 状态 |
| --- | --- |
| EXE 显示三个独立模块 | ❌ 需要修改 `cmd/client/ui_windows.go` 等既有 UI |
| Egress 可不启动 Mesh 独立运行 | ❌ 需要 manager + 桌面接线 |
| 目标 exe 的 TCP/UDP 从后端公网 IP 出口 | ❌ 需要签名 WFP/驱动 + 真实 Linux gateway |
| 非目标 exe 不受影响 | ❌ 同上 |
| DNS/IPv6 无静默泄漏 | ✅ 策略层已 fail-closed；⚠️ 数据面未接入 |
| 断线/撤销不回退直连 | ✅ 会话层 fail-closed；⚠️ 数据面未接入 |
| 服务器 NAT 可回滚 | ✅ 命令层已实现并测；⚠️ 未在真实 Linux 验证 |
| 三模块同时工作 | ❌ 未接线 |
| 崩溃/重启/卸载/升级清理 | ⚠️ 仅设计（helper/Job/DACL），未实现 |
| 全量测试、构建、UI smoke、真实 Windows/Linux 证据 | ⚠️ 全量测试通过；UI smoke 与真实端到端未做 |

## 关键阻塞

1. **Windows 按进程透明重定向需要签名内核组件（WFP callout 驱动或等价物）。** 当前仓库没有，也不能在本机生成可分发签名。计划明确：未有可用且签名的 WFP 实现前，不得宣称透明转发完成。
2. **真实 Linux Egress Gateway 主机**用于 NAT/转发的真实验收。
3. **既有功能改动需要批准**（见交付说明中的清单）。

## 下一步

获得批准后：①接入 GUI 第三页与桌面接线；②新增 `cmd/egress-helper` 与 gateway 二进制；③接入控制面租约路由；④打包；⑤在真实 Windows + Linux 上完成验收。
