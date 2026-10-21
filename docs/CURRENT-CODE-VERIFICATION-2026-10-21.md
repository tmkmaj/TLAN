# 当前代码有效性与 FRPC 方案符合性复核

日期：2026-10-21（Asia/Shanghai）

审查目录：`D:/RadminLanPrivate`。方案基线：本目录的 `docs/FRPC-INTEGRATION-PLAN.md`。此前 `docs/FRP-P2-P3-AUDIT.md` 与 `VALIDATION.md` 作为历史记录参考，结论以本次源码及实测为准。

本轮只验证和审查，不修改生产源码，不覆盖 dist，不部署服务器，不创建真实网卡，不运行游戏。新增本报告；临时构建与审计探针在 `.tmp-build/audit-20261021/`。探针通过 Go overlay 注入测试编译，未在 internal/ 下添加测试文件。

## 1. 结论

**当前代码可以在 Windows 构建并运行现有本机测试，真实 FRPC/FRPS 核心链路也能工作；整体架构遵循独立进程、独立 Mesh/FRP 功能和受控目标网关的方向。但没有完全符合预定方案，也不能据现有测试判定可以无冲突发布。**

本轮发现 7 项确定的代码/构建问题：6 项通过额外审计探针复现，1 项通过 Linux 目标静态检查复现。其中删除规则后失败回滚重新开放旧映射、不能取消等待/失败状态、路由与后端安全策略缺项，应在发布前优先修复。

此前报告中“剩余只是外部环境验收，不是代码路径”的描述过于乐观。应改为“主体功能已接通，仍有本报告指出的逻辑缺陷和方案缺项，外部环境验收另行完成”。

## 2. 本次实际执行结果

环境：Go `go1.27.2 windows/amd64`，CGO_ENABLED=0。未检测到可用 gcc/clang，未运行 race 检测。Go 依赖使用本地 vendor；核心固定 FRP v0.71.1。

| 检查 | 本次结果 | 实际证明范围 |
| --- | --- | --- |
| `go test -mod=vendor ./... -count=1 -timeout 120s` | 通过 | 当前 Windows 目标全部现有包测试；Mesh 测试约 32.46 秒 |
| `go vet -mod=vendor ./...`（Windows） | 通过 | Windows 目标静态检查 |
| 开启 TLAN_FRP_INTEGRATION/TLAN_FRP_LIVE 后运行两个包的 TestLive | 5 项通过 | 真实本机 FRPC/FRPS、代理、托管授权、撤销、网关 fake-Mesh 集成 |
| 当前源码重新构建 Windows GUI | 通过 | 新二进制在审计目录，不使用旧 dist EXE 代替 |
| 新构建 EXE `--ui-smoke-test` | PASS | 实际原生控件创建、Mesh/FRP 页面与绘制；隐藏窗口，不创建网卡或访问业务服务器 |
| Linux/amd64 `go build ./cmd/server` | 通过 | 服务端交叉编译成功，不代表真实 Linux 运行 |
| Linux/amd64 `go build ./cmd/install-helper` | 通过 | 安装辅助程序交叉编译成功 |
| Linux/amd64 `go vet -mod=vendor ./...` | **失败** | `internal/frp/p2_test.go:153:14: undefined: Manager` |
| `test-server-installer.ps1` | 通过 | 现有 .run 头部、全包/载荷校验和、解包文件与暂存构建输出一致，以及已列出的 systemd 指令兼容检查；未传 Bash 参数 |
| 6 项新增审计断言 | **全部复现预期应禁止/支持而实际不符的行为** | 见第 3 节；这些 FAIL 是发现缺陷的证据，不是“6 项新测试通过” |

真实联调命令：

```powershell
$env:TLAN_FRP_INTEGRATION = '1'
$env:TLAN_FRP_LIVE = '1'
go test -mod=vendor ./internal/frp ./internal/frpauth -p 1 -run TestLive -count=1 -v -timeout 180s
```

通过的测试为 TestLiveTargetGatewayPublishAndDependencyStop、TestLiveFRPTCPUDP、TestLiveManagedFRPLease、TestLiveManagedRejectsUnobservedPlugin、TestLiveFRPSPluginTCPAndHTTPProxy。覆盖 TCP/UDP/HTTP/HTTPS/STCP/SUDP、错误 CA/token、托管运行中 Apply、FRPC 崩溃重启、缺少授权插件拒绝、现有 TCP 连接撤销等。TargetGateway 联调使用 fake Mesh provider，不能替代真实虚拟接口路径验证。

新构建 GUI SHA-256：`0DC2992151DF791A2FC352AF98CF604173A5EBE639FD675CD204C3A192D042F9`。

内置 frpc SHA-256：`509F4FA082BF9B85F9AD27B45D37A89A8ACCB011F3B724CFF352DFAC90A94FEB`，与源码固定值一致。

报告及探针证据：

- `.tmp-build/audit-20261021/ui-smoke.txt`
- `.tmp-build/audit-20261021/linux-vet.txt`
- `.tmp-build/audit-20261021/audit_probe_windows_test.go`
- `.tmp-build/audit-20261021/overlay.json`
- `.tmp-build/audit-20261021/probe-results.txt`

复现审计断言：

```powershell
go test -mod=vendor -overlay .tmp-build/audit-20261021/overlay.json ./internal/frp -run TestAudit -count=1 -v -timeout 90s
```

overlay.json 使用本机绝对路径；移动目录后需调整映射。探针只使用临时文件和回环测试服务，不会连接示例云元数据地址或创建实际 Mesh 网络。

## 3. 当前问题，按修复优先级排列

### F-01 / P1：失败回滚会重新开放新配置已删除的服务

位置：`internal/frp/manager_windows.go:442–453`；同类回滚分支还在 426–436、458–470 行。方案第 10.3 节明确规定：权限收紧和撤销失败不能恢复到更宽的旧配置。

复现：先用真实 FRPC/FRPS 发布旧 TCP 回显服务；新配置删除旧规则并加入一个服务器不允许的新公网端口。新规则注册失败，Apply 调用 restorePrevious，原已删除的服务被重新注册。探针随后连接原公网测试端口，收到实际回显，证明不是单纯的 UI 状态残留。

证据：`TestAuditRollbackMustNotRepublishRemovedRule`，错误为 `removed public service was reopened and still forwards after failed replacement`。

影响：用户在替换/收紧发布配置时遇到错误，旧公开入口仍然继续提供服务。当前会报告 Apply 失败，但没有按方案要求在撤销路径保持关闭。托管和私人模式都经过相同的无条件恢复逻辑。

建议：配置 diff 区分权限扩大、普通参数修改、删除/禁用/缩小范围。撤销与收紧先形成不可逆的本次运行目标，失败后保持相应规则关闭；只恢复仍在新授权集合中的旧规则，或将整个组保持停止并提示失败。增加删除规则+另一条注册失败、禁用规则+保存失败等回归测试。

### F-02 / P1：失败/等待依赖状态没有可用的“停止”入口

位置：`cmd/client/frp_ui_windows.go:388–392, 505–518`；`internal/frp/manager_windows.go:178–181, 215–219`。

Start 一进入就将 desiredRun 置 true；某些失败路径只设置 state=failed，没有清除运行意图。依赖中断也会保留 desiredRun 并进入 waiting_dependency。GUI 仅以 Snapshot.Running 决定按钮是 Start 还是 Stop，因此进程已不在时只提供“启动穿透”，无法取消后台恢复意图。

同时 RequiresIdentityStop 检查 desiredRun 和 waiting_dependency，入网/退出流程据此阻止身份变更。结果是“提示先停止穿透，但页面上没有停止按钮”。依赖恢复后还可能在用户无法取消的情况下自动重新发布。

探针以合法配置中的 LAN 地址与当前 Mesh 前缀冲突触发 Start 失败，无须连网络；得到 state=failed、Running=false、RequiresIdentityStop=true。证据：`TestAuditFailedStartMustNotLockIdentity`。

建议：Snapshot 暴露 DesiredRunning/CanStop；按钮和操作按期望状态而不只是进程状态判断。等待、退避和失败但仍有运行意图时允许 Stop。不可重试启动失败应清除运行意图，或显式保留并给出取消入口。覆盖“组网关闭→等待→用户停止→组网恢复不再自动发布”。

### F-03 / P1：路由冲突检查未覆盖 FRPS 出口及运行时变化

位置：`internal/frp/manager_windows.go:1157–1175`；`internal/frp/tlscheck.go:30–32`；`cmd/client/desktop_windows.go:357` 附近的 Mesh 启动流程。

validatePolicy 目前只检查 kind=lan 的 backend 是否落在缓存 Mesh CIDR 中。它不检查 FRPS 地址是否属于该网段，不查询实际路由，不解析/钉住服务器域名对应的接口，也没有接口/路由变化通知和统一依赖图。Mesh 启动路径同样没有调用跨组件冲突规划器。

证据：`TestAuditFRPSInsideMeshMustBeRejected` 将 FRPS 设为 10.240.0.20，Mesh CIDR 为 10.240.0.0/24，检查通过。真实连接层使用普通 net.Dialer，FRPC 使用生成的普通 TCP 配置；在真实 Mesh 中该地址可达时，控制通道就可以依赖组网，违背默认独立出口约束。此次只复现策略漏检，没有实施真实误路由抓包。

影响：FRP 对 Mesh 形成隐藏依赖、关网卡导致“独立穿透”掉线、FRPS 域名地址变化后进入虚拟网络，以及第三方 VPN/静态路由造成实际路径与配置分类不一致。

建议：实现方案第 5.3 节的 NetworkObserver/ConflictPlanner：按目的地址查询有效路由，拒绝 FRPS 的 TLAN 出口；启动 Mesh 与启动 FRP 双向检查，接口变化后重新协调。socket 约束与 DNS 解析一致，不能只检查一次字符串前缀。不要自动添加绕过用户 VPN 的默认路由。

### F-04 / P1：方案要求禁止的后端目标仍被接受

位置：`internal/frp/validate.go:209–220`，以及 loopback 分支 178 行附近。方案第 9.5 节要求禁止云元数据地址、TLAN/FRP 管理入口、其他内部目标网关等保留地址。

证据：`TestAuditMetadataTargetMustBeRejected` 中，kind=lan、169.254.169.254:80 被 ValidateConfig 接受，因为代码允许任意 link-local unicast 地址。这里只调用校验器，未请求该地址。

同样，loopback 仅校验地址为 127.0.0.1，没有与各配置管理端口/网关监听端口作资源归属检查。跨配置发布另一个 frpc 的管理端口也没有集中禁止机制。管理密码可提供另一层认证，但不能代替“不公开管理面”的产品规则。

影响：运行于有相应服务的环境时，可以通过普通服务映射公开本不应暴露的接口。不是断言本机现在存在云元数据服务，而是确定的配置策略缺口。

建议：中央维护保留目标和资源注册表，在保存、启动和更新时统一检查；明确禁止云元数据地址和本产品管理/内部端口。普通业务回环端口仍允许，不能一概禁用 localhost。

### F-05 / P2：原有 100.64.0.0/10 虚拟网络无法使用 Mesh 发布

位置：`internal/frp/validate.go:200–202`。现有 `internal/storage/store.go` 和 `internal/config/config.go` 允许 10.0.0.0/8 与 100.64.0.0/10 两类虚拟地址池。

validateTarget 对 mesh_peer/mesh_self 使用 netip.Addr.IsPrivate()，该判断不包含 100.64.0.0/10。探针的 100.64.0.2 在正确的 managed/network/device/service 配置下仍得到 UNSUPPORTED_FRP_FEATURE。

证据：`TestAuditCGNATMeshTargetMustBeSupported`。

建议：共享 TLAN 地址池校验逻辑，并核对实际授权网络前缀和成员身份；不能以 RFC1918 判断替代 TLAN 自己支持的地址池。增加两个支持地址池和非法池的边界用例。

### F-06 / P2：Mesh 依赖隔离漏掉独立 visitor

位置：`internal/frp/validate.go:128–134`；`internal/frp/manager_windows.go:1548` 附近。

规则校验只禁止 Mesh backend 与独立 backend 混在同一 Profile，没有禁止独立 STCP/SUDP visitor 加到 Mesh Profile。visitor 默认绑定回环、连接另一个远端私有服务，不必依赖该 Mesh；然而 Mesh gateway 失效时 watchGateway 会停止整组 frpc，于是 visitor 一起掉线。

证据：`TestAuditMeshProfileWithIndependentVisitorMustBeRejected` 构造 Mesh 规则加独立 visitor，ValidateConfig 返回 nil。数据面连带停止的结论来自实际 stopInstance 调用链，本轮没有额外构造此组合的远端 visitor 网络。

建议：按 dependencyDomain 分组时将 visitors 一并纳入；当前一组一个进程的实现可先拒绝此组合，要求另建独立配置。继续保留同配置内合理的规则组合能力。

### F-07 / P2：当前 Linux 全量静态检查不能通过

位置：`internal/frp/p2_test.go:153`（及同文件其他 Manager 测试）；Manager 定义文件 `manager_windows.go` 有 Windows 构建约束，p2_test.go 没有。

复现：设置 GOOS=linux、GOARCH=amd64、CGO_ENABLED=0，运行 `go vet -mod=vendor ./...`，返回 undefined: Manager。Windows 测试通过并不能暴露这个问题。

建议：把依赖 Manager 的测试移到 `_windows_test.go`；可移植的模型、序列化、配置校验测试继续保留跨平台执行。不建议简单给整个 p2_test.go 加 Windows tag 而丢掉本可跨平台的覆盖。

范围说明：Linux 服务端和 install-helper 的 build 通过，此缺陷阻断的是全量静态检查/测试编译，不能夸大成“Linux 服务端无法编译”。

## 4. 与预定方案的符合程度

| 方案项 | 当前状态 | 本轮判断 |
| --- | --- | --- |
| 内置固定 FRPC，独立进程，GUI 管理 | 已实现 | 哈希检查、Job、配置/状态/启停主链路存在且本机联调通过 |
| 统一原生 GUI 风格 | 主体一致 | 新页复用原色值、卡片和按钮构造，当前源码 UI smoke 通过；本轮未进行截图逐帧视觉验收 |
| 多服务器配置/凭据隔离 | 已实现主体 | 各 Profile 独立 Store/Manager/进程 |
| TLS、CA 和 serverName 验证 | 已实现 | 错误 CA、错误 token 的真实联调通过 |
| VirtualNet、未知字段/任意插件禁止 | 已实现受限入口 | 自有严格 schema 与生成器不开放这些功能；属于有意边界 |
| FRP 与 Mesh 开关隔离 | 部分符合 | 普通独立 Profile 分开；取消语义与 visitor 依赖隔离有 F-02/F-06 |
| 托管租约、续租、注册授权、撤销 | 已实现主体 | 真实本机测试通过；不能据此扩大到所有断网/服务端故障场景 |
| Mesh peer/self TargetGateway | 已实现主体 | 真实 Windows 绑定接口代码存在；fake provider 测试通过；100.64 地址池兼容仍有问题 |
| 双向网络冲突规划/运行时路由观察 | 未完整实现 | F-03；当前没有方案描述的完整 NetworkObserver/ConflictPlanner |
| 保留地址/管理面禁止发布 | 未完整实现 | F-04 |
| 配置事务与收紧权限时保持关闭 | 部分实现且有缺陷 | F-01 |
| Mesh 全资源账本与清理错误报告 | 尚有缺项 | `IPTunnel.Close` 仍忽略 cleanup 错误；FRP 进程账本不能替代 Mesh 路由/防火墙账本 |
| P4 低权限 worker、服务化、签名更新等 | 未实现 | 文档已注明，不能当作本轮已交付 |
| 公网双 Windows、真实 Debian、物理 LAN 抓包、长稳 | 未完成 | 本机测试与交叉编译不能替代 |

架构目录没有完全按提案逐个命名不必单独视为缺陷：GUI 持有多个 FRP Manager 可以承担部分协调职责。但不能因此认为计划中的跨组件状态机、全局端口注册和冲突图已存在。

## 5. 两个参考项目的功能覆盖

本轮重新读取 stilleshan/frpc 的 Dockerfile、frpc.service、Linux 安装脚本；它主要包装上游 FRP 二进制及部署方式，不是一个需要再移植的独立穿透协议实现。[Dockerfile](https://github.com/stilleshan/frpc/blob/master/Dockerfile)、[安装脚本](https://github.com/stilleshan/frpc/blob/master/frpc_linux_install.sh)。TLAN 使用官方 FRPC 核心符合方案，但不能宣称同时获得其 Docker/NAS/Linux 客户端部署全覆盖。

对 frpc-desktop，本轮检查本地参考 checkout `99366a976ffabe448d165bf0ad6052f76ae8c9a5` 中的 config_gen、commands、lib/process 等相关入口，并重新打开官方仓库确认项目。该参考代码包含 XTCP、插件生成、HTTP locations、TOML 导入导出、核心下载/版本选择、自定义核心、托盘与自启动入口。TLAN 当前主要实现受限 TCP/UDP/HTTP/HTTPS/STCP/SUDP、visitor、多配置及运行管理，没有搬入全部功能。[参考仓库](https://github.com/luckjiawei/frpc-desktop)。这里以所读 checkout 为代码基线，不宣称已经审遍整个远端最新仓库所有文件。

某些未迁移项是按方案故意禁止的，比如任意插件、原始配置透传、自定义二进制。**“严格遵守安全边界”和“不加限制地完整搬入所有上游功能”不能同时作为当前验收标准。** 合理表述应为：已集成方案允许的主要 FRPC 功能，上游高级能力按能力表逐项验证后开放。

## 6. 后续处理顺序

1. 修 F-01/F-02：撤销后不恢复已撤下的发布，等待/失败状态可停止；加真实 FRPC 回归。
2. 修 F-03/F-04：统一双向冲突检查、有效路由观察、保留目标/管理端口防护；先用可模拟接口测试，再做真实网卡与抓包。
3. 修 F-05/F-06/F-07：两个地址池兼容、visitor 隔离、Linux 测试构建约束。
4. 补 Mesh cleanup 错误返回和资源归属记录，明确更新失败/残留清理状态。
5. 重跑当前 Windows 单测、两平台静态检查与构建、真实 FRP 联调、当前源码 GUI smoke。
6. 再完成双 Windows 公网、实际 Linux 部署、接口切换和 24–72 小时混合负载验收。

工程管理补充：本次 `git ls-files` 为 0，仓库项目文件全部处于未跟踪状态；目前没有可用于可靠差异审查和版本回滚的提交基线。本轮未替用户提交或清理文件，建议完成修复后建立首个经过验证的版本基线。
