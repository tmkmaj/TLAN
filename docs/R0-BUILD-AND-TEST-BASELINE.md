# R0 构建与测试基线

日期：2026-10-21（Asia/Shanghai）

范围：`D:/RadminLanPrivate`。本文落实 `docs/FRPC-DEVELOPMENT-ROADMAP-2026-10-21.md` 的 R0，以及 `docs/CURRENT-CODE-VERIFICATION-2026-10-21.md` 的 F-07。本文只记录测试/build/CI 基线；除明确注明通过的探针外，不把审查项自动视为已验收。

## 1. 当前结论

- Windows 管理器测试已与可移植模型、序列化、配置和 TOML 渲染测试分开。
- `GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go vet -mod=vendor ./...` 已通过。
- 默认测试基线不包含真实网络/真实 FRP 探针；F-01 至 F-07 的审计回归已整理为显式 `frp_audit_regression` 套件，本机运行全部通过。
- 固定 FRP、Wintun、Go 工具链和构建参数已记录；构建脚本继续强制校验固定摘要。
- 2026-10-21 已建立首个 Git 提交基线；`dist/`、`.tmp-*`、运行配置、日志和凭据目录仍被忽略。

## 2. 工具链与构建参数

| 项目 | 基线 |
| --- | --- |
| Go 最低版本 | `1.23.1`（来自 `go.mod`） |
| 本轮验证工具链 | `go1.27.2 windows/amd64` |
| 依赖模式 | `-mod=vendor`，不访问模块代理 |
| CGO | Windows/Linux 构建均为 `CGO_ENABLED=0` |
| Windows 目标 | `GOOS=windows GOARCH=amd64` |
| Linux 目标 | `GOOS=linux GOARCH=amd64` |
| Windows 资源工具 | `go-winres v0.3.3`（仅重新生成图标/manifest 时需要） |
| 可重复性参数 | `-trimpath` |
| Windows 客户端链接参数 | `-H=windowsgui -s -w`，并注入内置控制服务和 STUN 地址 |
| Linux 服务端链接参数 | `-s -w` |

Windows 客户端构建入口：

```powershell
.\build-windows-client.ps1
```

等效核心命令：

```powershell
$env:GOOS='windows'
$env:GOARCH='amd64'
$env:CGO_ENABLED='0'
go build -mod=vendor -trimpath `
  -ldflags '-H=windowsgui -s -w -X main.bundledServerURL=https://example.invalid -X main.bundledSTUNAddress=example.invalid:3478' `
  -o .tmp-build\TmkNetworkLAN.exe .\cmd\client
```

Linux 服务端构建入口：

```powershell
.\build-debian-server.ps1
```

等效核心命令：

```powershell
$env:GOOS='linux'
$env:GOARCH='amd64'
$env:CGO_ENABLED='0'
go build -mod=vendor -trimpath -ldflags '-s -w' -o .tmp-build\tmknetworklan-server .\cmd\server
```

构建脚本不接受 `latest` 核心、用户替换的任意 FRP 二进制或可选 CGO。固定摘要不匹配时脚本必须失败。

## 3. 固定第三方二进制

| 组件 | 来源与版本 | 平台 | SHA-256 |
| --- | --- | --- | --- |
| `frpc.exe` | [fatedier/frp](https://github.com/fatedier/frp) `v0.71.1`，tag object `72d643d661dcb686087e342142a70f8f4698e29f`，commit `d8cf1800dc1abd7fda1828cab105d7a6b5a50eb1` | windows-amd64 | `509F4FA082BF9B85F9AD27B45D37A89A8ACCB011F3B724CFF352DFAC90A94FEB` |
| `frps` | 同上，build tags `frps,noweb` | linux-amd64 | `2FB8DA8392CF2B332BFCC540F075E928A82D1A106DF0B8FCFCF13497149F8C48` |
| `wintun.dll` | 项目固定虚拟机网卡运行库 | windows-amd64 | `E5DA8447DC2C320EDC0FC52FA01885C103DE8C118481F683643CACC3220DAFCE` |

FRP 使用 Apache-2.0，许可证位于 `assets/frp/licenses/FRP-LICENSE.txt`；来源详情同时保存在 `assets/frp/*/manifest.json` 和 `THIRD-PARTY-NOTICES.md`。构建不自动下载或选择最新 FRP。

## 4. 测试分层

| 层级 | 位置/命令 | 默认基线 | 说明 |
| --- | --- | --- | --- |
| 可移植单元测试 | `go test -mod=vendor ./... -count=1` | 是 | Windows 和 Linux 原生运行；覆盖模型、序列化、配置、校验、渲染等 |
| Windows 管理器测试 | `internal/frp/*_windows_test.go` | 是（Windows） | 依赖 Windows `Manager`、Job、DPAPI、进程或 socket 绑定 |
| Linux 静态检查 | `GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go vet -mod=vendor ./...` | 是 | 同时编译 Linux 目标的非 Windows 测试文件 |
| Linux 原生测试 | Linux CI：`go test -mod=vendor ./...` | CI | 不能由 Windows 交叉编译运行替代 |
| 真实 FRP 本机联调 | `TLAN_FRP_INTEGRATION=1` 等环境变量 | 否 | 需要固定 FRPS 二进制；不代表公网/双机验收 |
| 审计回归探针 | `go test -tags frp_audit_regression` | 否 | F-01 至 F-07 的显式回归门禁；本机全部通过 |
| 外部环境探针 | 双 Windows、Debian、公网防火墙、Wireshark | 否 | 无法在单机 CI 中替代 |

推荐的总体验证入口：

```powershell
.\scripts\verify-build-baseline.ps1
```

该脚本检查固定摘要、Windows 测试、Windows/Linux vet、Linux 测试编译，以及 Linux 服务端和安装辅助程序构建。它不会修改 `dist/`、不会创建真实网卡，也不会提交 Git。

## 5. F-07 拆分结果

F-07 的根因是 `internal/frp/p2_test.go` 引用了只在 `manager_windows.go` 中定义的类型。本轮处理：

- 保留 `p2_test.go` 为跨平台测试，覆盖配置校验、JSON schema 迁移、TOML 渲染、STCP/SUDP visitor、托管 metadata 和 Mesh 目标准备。
- 将 `Manager`、`managedInstance`、租约申请/续租 watchdog、运行意图和 Mesh grant 测试移入 `internal/frp/p2_windows_test.go`。
- 不改变业务实现，不以给整个文件加 Windows 标签的方式牺牲跨平台覆盖。

## 6. 审计探针整理

审计探针按可移植性拆分，并使用独立构建标签，避免已知失败项阻断默认基线：

| 问题 | 回归测试 | 平台 | 当前状态 |
| --- | --- | --- | --- |
| F-01 回滚重新开放已删除规则 | `TestAuditRegressionRollbackMustNotRepublishRemovedRule` | Windows + 固定 FRPS | 当前通过 |
| F-02 失败/等待状态不能取消 | `TestAuditRegressionFailedStartMustNotLockIdentity` | Windows | 当前通过 |
| F-03 FRPS 出口冲突漏检 | `TestAuditRegressionFRPSInsideMeshMustBeRejected`；`internal/netpolicy` 路由/接口测试；`TestLiveFRPTCPUDP` 验证代理实际被使用 | Windows | 已修复代码路径，真实接口切换仍待外部验收 |
| F-04 云元数据等保留目标 | `TestAuditRegressionMetadataTargetMustBeRejected`；默认 `TestReservedTargetPolicyRejectsMetadataAndManagementEndpoints` | 跨平台 | 当前通过 |
| F-05 `100.64.0.0/10` Mesh 目标 | `TestAuditRegressionCGNATMeshTargetMustBeSupported`；默认 `TestMeshTargetsSupportBothTLANPools` | 跨平台 | 当前通过 |
| F-06 Mesh Profile 独立 visitor 隔离 | `TestAuditRegressionMeshProfileWithIndependentVisitorMustBeRejected`；默认 `TestMeshProfileRejectsIndependentVisitor` | 跨平台 | 当前通过 |
| F-07 Linux test/vet 编译失败 | Windows 测试拆分 + Linux CI vet | 两平台 | 已修复 |

显式运行失败门禁：

```powershell
go test -mod=vendor -tags frp_audit_regression ./internal/frp -run TestAuditRegression -count=1 -v -timeout 120s
```

截至 2026-10-21 R2 复核，该命令全部通过。F-03 已增加实际路由观察、FRPS 受限出口代理、Mesh 启动双向预检和运行中路由复检；本机回环联调证明 FRPC 确实使用了该代理，但真实 Wintun/物理网卡切换仍必须按 R3 在目标 Windows 环境抓包验收。

无法自动化的外部探针：

- 两台独立 Windows 经公网 FRPS 的 TCP/UDP/HTTP/HTTPS/STCP/SUDP；
- 真实 Wintun 接口切换、物理 LAN 同地址冲突和抓包证明；
- 真实 Debian/systemd/云防火墙/域名证书部署；
- 24–72 小时混合负载、断网恢复和资源泄漏观察。

## 7. FRPC 能力表

完整逐项对照见 `docs/FRPC-DESKTOP-COVERAGE.md`。R1/R2 的代码、测试与残余边界见 `docs/R1-R2-IMPLEMENTATION-REPORT-2026-10-21.md`。稳定边界摘要：

| 能力组 | 状态 | 基线说明 |
| --- | --- | --- |
| TCP/UDP/HTTP/HTTPS/STCP/SUDP 与 visitor | 已实现，本机联调通过 | 固定 FRP `v0.71.1` 独立进程 |
| 回环、显式 LAN、`mesh_peer`、`mesh_self` | 已实现主体 | Mesh 目标经 TargetGateway；真实双机待验收 |
| 多服务器配置与凭据隔离 | 已实现 | Token/CA/规则/运行目录按 Profile 隔离 |
| 托管 lease、配额、续租、撤销 | 已实现主体 | 需要控制面与 FRPS 插件部署一致 |
| HTTP locations/basic auth/subdomain/header rewrite | 已实现 | 受严格 schema 和 managed 精确授权约束 |
| 任意插件、VirtualNet、原始 TOML、自定义二进制 | 有意不支持 | 与目标网关和授权边界冲突；安全 JSON 导入导出已提供 |
| XTCP/tcpmux/QUIC/KCP/WSS | 已实现代码路径 | WSS 已通过公网 Caddy 8444 managed 验证；XTCP 双端打洞待外部验收 |
| 核心更新基础设施、托盘/自启动、低权限 frpc | 已实现主体 | 生产更新密钥/源和自动入口未部署；SYSTEM 服务未实现 |
| stilleshan/frpc 的 Docker/NAS/Linux 客户端部署 | 未移植 | 本项目使用独立 FRPS 包，不等于覆盖该仓库全部部署方式 |

## 8. Git 基线与发布纪律

截至本文日期：

```text
git ls-files -> 0
git status --short -> 项目文件全部为 untracked
```

因此本轮已在完成代码审查、默认测试、两平台 vet、真实 FRP live 测试和发布构建后建立首个经过验证的提交基线。构建产物 `dist/`、临时二进制、运行数据、日志和配置凭据继续排除在版本控制之外；后续变更可从该提交形成可审查 diff。