# 验证记录（2026-10-18，最后更新 2026-10-21）

## P2/P3 受控发布验证（2026-10-21，R1/R2 复核）

- FRPS 发布模板 P0 一致性已修复并完成公网部署：主实例补齐 KCP/QUIC/TCPMUX/subdomain，WSS 回环实例补齐独立 vhost/TCPMUX/subdomain；主实例仍 TLS-only，WSS 回环仍仅 127.0.0.1:7001。2026-10-21 15:31（Asia/Shanghai）已在 8.163.21.82 部署最新安装器和 frpauth 续租修复；KCP、QUIC、WebSocket、主/WSS TCP、HTTP、HTTPS、TCPMUX 的真实公网 managed 回归均通过。详见 `docs/FINAL-PUBLIC-DEPLOYMENT-VERIFICATION-2026-10-21.md`。

- 最新审查报告 F-01～F-07 的代码路径已修复，显式 `frp_audit_regression` 回归全部通过；详细证据与残余边界见 [R1/R2 实现与验证报告](docs/R1-R2-IMPLEMENTATION-REPORT-2026-10-21.md)。
- R2 协调层新增独立 EndpointRegistry（admin/visitor/TargetGateway/egress 监听归属、跨 profile 冲突检测）和 ObservationDebouncer（generation、两次稳定去抖、旧结果丢弃）；R4 诊断入口新增完整 FRP JSON/文本导出，覆盖 snapshot、lease、route、TargetGateway、日志和 TLS/CA 结果。
- 高级能力批次已完成：TCP/WebSocket/WSS/KCP/QUIC 传输、TCPMUX/XTCP、HTTP locations/Basic Auth/subdomain/Header rewrite、managed 精确高级授权、目标成员审批、批量端口和安全 JSON 配置导入导出。本机真实 FRP 联调通过 TCP/UDP/WebSocket/KCP/QUIC、HTTP 高级字段、TCPMUX、managed HTTP/TCPMUX/XTCP 授权；WSS 已通过公网 Caddy 8444 managed 端到端回显；XTCP 双端打洞仍待真实环境。
- 客户端已支持托盘、关闭到托盘、当前用户登录自启动；受管 frpc 使用 Medium 完整性、Administrators deny-only 的受限令牌启动，并保留 fail-closed 无管理员回退。Mesh 资源账本、精确恢复和 GUI 残留提示已接入。
- 受控核心更新基础设施 `internal/coreupdate` + `cmd/corepack` 已实现签名清单、哈希、原子安装和回滚测试；生产签名密钥、更新源和客户端自动更新入口尚未部署。
- 2026-10-21 已通过 SSH 将 v0.6.0 控制服务和 FRPS 0.71.1 部署到 8.163.21.82（CentOS 7）。服务、HTTPS、STUN、managed capabilities、FRPS TLS、临时成员 enroll/lease、公网 TCP 30001 映射与回显、停止后端口关闭、lease 撤销和临时成员删除均通过；详细记录见 [服务器部署与公网验证记录](docs/SERVER-DEPLOYMENT-VERIFICATION-2026-10-21.md)。
- F-01/F-02 已加入权限交集回滚、持久化撤销上限、`DesiredRunning`/`CanStop` 和启动代次门控；删除或禁用服务后失败恢复不会再重开旧入口。
- F-03 已接入实际路由观察与认证回环出口代理。受管 FRPC 的 TCP 控制连接每次拨号重新解析路由并使用 Windows 接口约束；真实联调断言 FRPC 确实经过代理。Mesh 启动前检查 FRPS/LAN 后端，运行中每 5 秒复检，证据不足时 fail-closed。
- F-04～F-06 已统一保留目标、动态管理端口、`10/8`/`100.64/10` 地址池和 visitor 依赖隔离；F-07 的 Windows 测试拆分使 Linux 全量 vet 通过。
- `go test -mod=vendor ./... -count=1` 与 `go vet -mod=vendor ./...` 通过。
- 固定版 FRP v0.71.1 本机真实联调通过：`TestLiveFRPTCPUDP`、`TestLiveManagedFRPLease`、`TestLiveTargetGatewayPublishAndDependencyStop`、`TestLiveManagedRejectsUnobservedPlugin`；覆盖 TCP/UDP、HTTP/HTTPS vhost、STCP/SUDP visitor、TLS、tokenSource、托管 lease、运行中 Apply、frpc 强制崩溃后的自动恢复、撤销、TargetGateway 和“未观察到插件则拒绝启动”。
- 托管续租已改为真实 `/renew` 端点，不再重复申请 lease；客户端 watchdog 每 5 秒续租，撤销/过期/成员删除后停止受管 frpc 与 TargetGateway。服务端插件联调确认 `Login`、`NewProxy`、`Ping`、`NewUserConn` 四个操作；现有 TCP 连接在撤销后 10 秒内断开，新 TCP/UDP 流量被拒绝。
- 成员删除会批量撤销该成员租约；lease status API 只允许成员查询自己的 lease。客户端启动后会读取 status，要求 FRPS 实际观察到 Login 和 proxy；`TestLiveManagedRejectsUnobservedPlugin` 验证未启用插件时不会误报运行成功。
- Mesh 目标授权绑定网络、设备、虚拟 IPv4、WireGuard 公钥、管理员登记的目标 service ID、grant ID 和端口；`mesh_self`、generation 失效、依赖暂停/自动恢复和网关诊断均有测试。管理员撤销服务授权会联动撤销引用它的活动 lease。Mesh 拨号通过 Windows `IP_UNICAST_IF` 绑定 TLAN 接口并校验源地址；未绑定接口时直接失败，不做物理 LAN 回退。
- 外部 FRPS 兼容档位 `tcpMux` / `disableCustomTLSFirstByte` 已接入模型、渲染和服务器设置 GUI；managed verifier 缺失时 fail-closed，并有回归测试。
- 身份切换、退出网络和更换令牌前会检查所有受管 FRP 配置是否仍在运行；运行中要求先停止穿透。`mesh_peer` 的 STCP/SUDP 服务授权按 TCP/UDP 后端匹配；托管 verifier 缺失时 fail-closed。TCP/UDP 访问地址补全服务器主机，网关字节统计和 Mesh 路径进入规则诊断。
- 最终客户端/服务端/FRPS/安装器包已重建；`dist/SHA256SUMS.txt` 记录四个发布文件哈希，客户端包内 frpc SHA-256 与固定值一致。原生 UI smoke PASS，服务端安装器自检 PASS。
- 目标服务授权过期后 lease 续租失败；服务授权撤销联动 lease。Mesh peer 变化会关闭 generation done；TargetGateway watcher 纳入 Close 等待；frpc 异常退出在 desiredRun 仍为 true 时进入受控重试，Stop 与旧 gateway watcher 有状态门控。
- 受管 capability 不再写入运行 TOML，而是通过受限环境变量注入；token、管理密码、capability 和私有密钥均进入日志脱敏集合。TCP 空闲检测改为连接级活动时间，新增单向持续流量测试；UDP 首次 dispatch/Close 竞态和 Stop/依赖重试竞态均有回归测试。
- 尚未验证：真实 Debian 主机、两台独立 Windows、物理 LAN 抓包、Mesh/FRP 四组合、24–72 小时长稳。真实 Mesh 接口路由切换仍需在目标 Windows 环境抓包确认；本地测试只能证明代码路径和失败关闭逻辑。
- XTCP、KCP/QUIC/WSS schema、高级 HTTP/TCPMUX 和 managed 精确授权已接入；WSS 已通过公网 Caddy 8444 + 独立 loopback FRPS 端到端回显。XTCP 双端打洞、任意插件、原始 TOML、生产签名自动更新和 SYSTEM 后台服务仍需真实环境或发布工程验收。
- 最终 Windows 客户端为 v0.6.0；当前源码重建后的原生 `-ui-smoke-test` PASS（未创建网卡/未连接网络）。当前 EXE 摘要以 `dist/SHA256SUMS.txt` 为准。
- 四个发布文件已按本轮代码重建，以 `dist/SHA256SUMS.txt` 为准；安装器自检 PASS，客户端包内 `frpc.exe` 摘要与固定值一致。
## 淡亮蓝色图标同步

- 使用内置 imagegen 对原刷痕 T 进行颜色编辑，改为约 `#70C9FF` 的淡亮蓝色，保留笔触、轮廓与透明背景；原图与提示说明见 `assets/branding/`。
- 重新生成 Windows 图标资源、客户端 EXE 和 ZIP；加入页、侧栏及版本页的 PNG 与原图 SHA-256 一致。
- 从最终 EXE 提取 `APP` 图标资源，确认 16、32、48、64、256 px 均为新亮蓝色；PNG 透明角像素 alpha 为 0。
- 新客户端原生 UI smoke 检查为 PASS，未连接网络或创建网卡。
- 构建脚本现在要求图标资源工具可用并重新生成资源，避免缺少工具时静默沿用旧 `.syso`。
- 已获用户授权关闭旧客户端后更新文件；原图与旧客户端已备份至 `.tmp-runtime/icon-before-lightblue-20261018-131336/`。

## FRP P2 数据面验证（2026-10-19）

- 固定 FRP `v0.71.1`（tag object `72d643d661dcb686087e342142a70f8f4698e29f`，commit `d8cf1800dc1abd7fda1828cab105d7a6b5a50eb1`）。Windows `frpc.exe` SHA-256 为 `509f4fa082bf9b85f9ad27b45d37a89a8accb011f3b724cff352dfac90a94feb`；Linux `frps` SHA-256 为 `2fb8da8392cf2b332bfcc540f075e928a82d1a106df0b8fcfcf13497149f8c48`。
- 配置模型已扩展并通过测试：多服务器 catalog 与独立 token/CA、本机回环和私有/链路本地 IPv4 目标、TCP/UDP/HTTP/HTTPS/STCP/SUDP、HTTP/HTTPS 域名、STCP/SUDP visitor 仅绑定 `127.0.0.1`、私有密钥 DPAPI 分离存储、未知字段/VirtualNet/插件拒绝、TCP/UDP 同号端口和域名/规则冲突。
- `go test ./internal/frp ./internal/clientui ./cmd/client -count=1`、`go test -mod=vendor ./...` 和 `go vet -mod=vendor ./...` 通过。
- 真实本机 FRPS/FRPC 联调通过：临时 CA/服务器证书、TCP 回显、UDP 回显、HTTP/HTTPS vhost、STCP 访问器、SUDP 访问器、管理 API 实际注册状态、错误 CA 返回 `FRP_TLS_UNTRUSTED`、错误 token 返回 `FRP_AUTH_REJECTED`；停止后受管子进程进入终止状态且运行目录为空。
- 使用独立 Job Object 启动受管 `frpc.exe`，`CREATE_SUSPENDED | CREATE_NO_WINDOW`、受限句柄列表、最小环境变量和随机回环管理密码均已接入；没有按进程名结束用户自行运行的 FRP。
- `dist/windows/TmkNetworkLAN.exe -ui-smoke-test` 为 PASS；`--ui-preview frp` 实际窗口截图检查了多配置选择、规则/访问器表格、服务器卡和日志区。
- `build-windows-client.ps1` 生成包含 `runtime/frp/0.71.1/windows-amd64/frpc.exe`、manifest、FRP 许可证和哈希校验的客户端 ZIP；`build-debian-server.ps1` 生成独立 FRPS tar.gz，检查内容包含 ELF `frps`、systemd unit、安装脚本、示例配置和许可证。
- 该历史段落的 P2 托管授权/P3 TargetGateway“未实现”结论已由本页顶部 2026-10-21 验证记录更新；P4 和真实公网/双机/长稳验收仍未完成。当前 GUI 要求管理员权限，受管 FRPC 继承该权限。
## IP HTTPS 入口迁移

- 默认控制/入网/中继入口改为 `https://8.163.21.82:8443`，STUN 改为 `8.163.21.82:3478`。
- 对旧部署的两个已知 HTTPS 地址提供定向成员身份迁移，保留令牌、虚拟 IP、网络记录及转发设置；自定义服务器不会继承其他地址的令牌。只在成功恢复成员后保存迁移结果。
- 新增 IP HTTPS 测试确认不发送域名 SNI；不受信任证书和错误 IP SAN 被拒绝。原有 HTTPS WireGuard 端到端测试也加入无域名 SNI 断言。
- Caddyfile 经官方 Caddy 2.11.7 的 `adapt` 和 `validate` 验证：公网 IP 的 `shortlived` ACME 策略、无 SNI 默认选证书、8443 入口及 8080 后端均正确。验证工具下载包与官方 SHA512 校验值一致。
- 禁用缓存的全量 Go 测试、Windows/Linux 静态检查、Windows 客户端与 Debian 服务端发布构建全部通过。新版发布 EXE 的 `--ui-smoke-test` 为 PASS；两个 ZIP 均已更新并包含 IP 部署说明，服务端 ZIP 包含新的 IP Caddyfile。
- IP 证书申请与自动续期通过 TCP 80 HTTP-01 验证完成；本地配置校验不等同于已在公网签发证书或部署成功。云服务器升级步骤见 [IP 部署说明](docs/IP-DEPLOYMENT.md)。

## 代码审查与兼容性重构

- 完成引擎、存储和中继编解码的职责拆分；具体问题、修复及验证边界见 [REVIEW.md](REVIEW.md)。
- 成员移除后的引擎退出、握手取消、存储数据副本隔离均先用新增测试复现，再修复并通过回归。
- 诊断分批上传覆盖 129 项检查、批次失败停止与中文长字段边界。
- 禁用结果缓存的全量 Go 测试、Windows/Linux 静态检查、两平台构建与新客户端原生 UI smoke 均通过。
- 本次构建位于 `.tmp-build/review/`，未覆盖 `dist/`，未重新配置真实网卡或进行公网双机验收。

## 虚拟网卡组网命名与界面动效

- 当前核心功能在加入页、主页面标题、左侧导航和版本窗口中统一命名为“虚拟网卡组网”。
- 令牌输入框通过自绘面板和 16ms 帧计时器实现约 180ms 的淡蓝色聚焦光晕过渡；失焦后平滑淡出。光晕改为多层低透明度圆角填充，去除厚重双边框，过渡帧截图已复核。
- 令牌默认使用逐字符遮罩；输入时最后一位明文短暂显示 1 秒，随后恢复遮罩。右侧自绘眼睛按钮可切换全明文/遮罩，闭眼与睁眼图标、辅助名称同步变化。
- 编辑区实际高度固定为 20px，并按视觉中心向下微调 3px；实际截图复核文字、光标与右侧眼睛按钮处于同一水平视觉中心。遮罩输入追加、退格、全选替换、粘贴和中段编辑均有单元测试。
- 修复遮罩字符完全相同时无法通过文本差异判断中间删除位置的问题。Backspace/Delete 现在在按键前记录光标或选区，并直接更新真实令牌；实际窗口验证 `abcdefg` 在中间删除 `d` 后完整显示为 `abcefg`，被删字符不会残留。
- 启动成功时成员区域以缓出曲线从下方滑入，关闭时向下滑出后恢复布局；实际截取 620/680/750/900ms 帧确认连续平移位置。
- 左侧导航选中背景使用逐帧展开/消退动画；实际帧检查确认版本按钮切换时，高亮从启动按钮平滑过渡到版本按钮，关闭版本窗口后返回。
- 动画仍保留原生键盘操作和辅助文字；`--ui-smoke-test` 在禁用动画的隐藏窗口中验证集成布局和状态切换，不访问服务器或创建网卡。

## 启动与成员整合、版本入口

- “启动”和“成员”合并为单一工作区。未启动时保留居中的大号电源按钮；启动后上方保留电源与状态区域，本机信息、成员表格和流量信息在同一页下方展开。
- 左侧工具栏继续保留多个入口：启动/网络、版本信息、更多操作；后续页面可继续加入该栏。
- 新增版本信息按钮和无网络依赖的版本窗口，显示应用名称、`v0.2.0`、Windows 平台信息及应用图标。
- `--ui-smoke-test` 更新为检查两页切换、启动后成员区展开、关闭后成员区收起、版本按钮及绘制初始化，检查结果 PASS。
- `--ui-preview` 实际截图检查关闭态、启动后整合态和版本窗口，确认启动按钮位置、成员列表完整显示及左侧导航状态。

## frpc-desktop 风格蓝白 UI 重制

- 参照 `luckjiawei/frpc-desktop` 的页面骨架，客户端加入 68px 白色左侧导航、浅蓝灰主画布、带图标页面标题、右侧工具栏、白色卡片和蓝色主操作按钮。
- 启动区改为大号蓝色描边电源圆环与右侧状态、网络名和操作区；成员区域使用本机信息卡、紧凑成员表格，在线/离线与延迟并列显示。
- 蓝色主题调整为 `#2563EB` 主色、浅蓝选中态和白色内容面板；保留原生键盘操作与辅助功能文字。
- 使用独立 `--ui-preview` 模式生成无敏感数据的夹具窗口，在 1020×720 实际截图检查首次加入、启动和成员区域，截图保存在 `docs/screenshots/`；修复了电源控件被压缩、成员表格横向滚动及离线成员不可见的问题。
- 左侧导航栏显式使用近端对齐；实测客户区坐标 `ClientX=0`、宽度 68px，不再有 12px 内缩缝隙。
- “查看详细”错误对话框绑定与应用窗口相同的内嵌刷痕 T 图标；实际弹窗截图确认标题栏图标同步。
- `--ui-smoke-test` 验证新导航控件、工作区切换、启动与成员区域展开收起及新绘制组件初始化；检查不访问服务器或创建网卡。

## 服务端 YAML 配置

- 服务端只从当前目录读取 `tnlan-config.yml`；文件不存在时生成随机管理员令牌、随机入网令牌和全部默认配置，文件权限为 `0600`，随后以退出码 0 结束。
- 实际冷启动验证：第一次运行退出码为 0，只生成 YAML；第二次运行读取同一文件，成功创建数据目录并开始监听控制端口与 STUN。
- YAML 加载启用未知字段和多文档拒绝；管理员令牌、入网令牌、私人 CIDR、监听地址、TLS 配对和数据目录均在监听端口前校验。
- 已有旧版 `state.json` 时，首次生成的 `data_dir` 自动设为 `.`，避免升级后创建空网络或重新分配成员 IP。
- 配置生成、重复启动不覆盖、非法配置不覆盖、字段校验、令牌随机性及旧状态目录继承测试通过。

## TmkNetworkLAN 品牌更新

- 客户端名称改为 `TmkNetworkLAN`，Windows GUI EXE 与 Debian 服务端分别使用该名称发布。
- Windows PE 资源包含产品名、Common Controls v6 高 DPI manifest 和用户提供的深蓝刷痕 T 图标；GUI 窗口标题栏也使用该图标。
- 原图保存于 `assets/branding/tmknetworklan-icon.png` 并保留透明通道。
- 旧版 `%APPDATA%/LANMesh/` 身份和设置文件继续沿用，避免改名后生成新设备身份。Debian systemd 服务继续使用 `/var/lib/lanmesh`，配置和成员数据保留在该目录。

## 当前口令与电源版本

- 发布客户端内置 `https://relay.tmknetwork.online`，界面只要求入网口令。
- 新增成员凭据加密响应、权限隔离、服务端口令加入限流的测试。
- 实际 wireguard-go 双端测试覆盖普通成员凭据通过 HTTPS 中继进行加密传输，以及直连和中继下的端到端延迟。
- 两次启停循环验证引擎关闭、网卡句柄释放、服务端在线/离线状态和固定虚拟 IP。
- Windows/Linux 静态检查及构建通过；原生控件初始化通过专用 UI smoke 模式检查，该模式不创建网卡。
- 本机尝试访问公网 `/health` 时 HTTPS 连接未能建立，因此未确认已在该域名部署新版服务端。此项与本机测试通过分开记录。

下文记录前期开发验证；当前仍未进行 Dark Hours 测试或跨公网双 Windows 实机验收。

本次交付为 Windows amd64 原生 GUI 客户端与 Debian/Linux amd64 独立服务端。

## 已通过

- `go test -mod=vendor ./... -timeout 90s`：全部包通过；Windows DPAPI 测试在实际用户环境运行。
- Windows 与 Linux 目标的 `go vet -mod=vendor ./...`。
- `build-windows-client.ps1` 与 `build-debian-server.ps1`，依赖从 vendor 构建。
- 两个真实 wireguard-go 实例在本机完成握手与传输：UDP 直连、TLS HTTP Upgrade 中继、双方中继设置不同、直连失效后回退。
- IPv4 单播、限制广播、子网广播、组播，以及源地址伪造拦截、成员移除、STUN 与隧道复用 UDP 端口、持久化失败回滚。
- TLS 信任检查：受信任证书能够连接；不受信任证书被拒绝。
- Windows 管理员环境实际初始化 GUI 控件，创建并配置兼容旧安装的 `LANMesh-Test` Wintun 网卡、路由及防火墙规则，随后关闭清理；报告为 PASS。
- 发布文件检查：客户端为 PE GUI 子系统，服务端为 Linux AMD64 ELF，ZIP 包含对应运行文件、配置及许可证，不含 Windows 服务端。

最后的客户端会话生命周期调整已重新格式化、编译、打包并通过静态检查；没有重复运行与该调整无关的网络测试。

## 早期 UI 重制记录

仅修改客户端展示层与报错信息格式，保留控制 API、隧道、直连和中继行为。服务器设置、网络列表、连接概览重新分区；表格替代拼接文本；创建及加入网络使用统一弹窗；错误提示提供处理建议、独立详情和凭据隐藏。

错误分类与凭据隐藏的自动化测试通过。新客户端已完成原生窗口启动检查。电脑操作工具的窗口查看请求因未获准访问 `lanmesh-client` 被自动审批拒绝，因此本次不宣称完成截图视觉验收。上文的 Wintun 实测属于前一轮传输功能验证，本轮不重复配置网卡。

## 验证范围

尚未在实际 Debian 主机启动服务端，未进行跨公网、两台独立 Windows 电脑的实机验收；这些环境结果不能由本地测试替代。按要求未启动或测试 Dark Hours。

当前数据通道覆盖 IPv4 三层网络及其广播/组播转发，不是完整 Ethernet 二层桥，不提供 IPv6，也未复制 Radmin 私有协议。当前管理令牌适用于互相信任的私人设备。使用方法和具体限制见 README.md。

## Linux 单文件安装包验证（2026-10-18，历史记录）

- `build-server-installer.ps1 -Offline` 生成内置服务端、Caddy 2.11.7、安装工具与许可证的 `.run` 文件，官方 Caddy 压缩包已验证固定 SHA-512。
- 配置准备测试覆盖保留凭据及网段、控制 TLS 迁移、旧 state.json 布局、不改动源配置、拒绝错误配置和外部共享存储目录。
- 三个 Linux 可执行文件均为 amd64 ELF，未包含 PT_INTERP 动态加载器依赖。
- `go test -mod=vendor ./...`、Windows 和 Linux 目标 `go vet -mod=vendor ./...` 通过。
- `test-server-installer.ps1` 验证头部、完整文件及载荷 SHA-256、实际解包后文件与构建产物一致，以及服务配置不含已知 systemd 219 不支持的指令。
- Git Bash 完成脚本语法与安装包 `--help` 冒烟检查；真实 rollback 函数在临时目录和模拟 systemctl 下验证旧文件恢复、新文件移除、原服务状态恢复。
- **历史记录中的外部环境缺口已部分关闭**：后续已在真实 CentOS 7 服务器完成部署、服务启动、TLS/健康检查和公网 managed FRP 验证；真实 Debian/Ubuntu、SELinux 专项和长时间稳定性仍未验证。最终状态见 `docs/FINAL-PUBLIC-DEPLOYMENT-VERIFICATION-2026-10-21.md`。








## R0 构建与测试基线（2026-10-21）

- F-07 已修复：`internal/frp/p2_test.go` 只保留跨平台模型、序列化、配置和渲染测试；依赖 Windows `Manager` 的租约、watchdog、运行意图和 Mesh grant 测试已移至 `internal/frp/p2_windows_test.go`。
- `GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go vet -mod=vendor ./...` 通过；Windows 目标 `go test -mod=vendor ./... -count=1 -timeout 180s` 和 `go vet -mod=vendor ./...` 通过。
- Linux 测试源码已通过交叉编译检查，`cmd/server` 与 `cmd/install-helper` 的 Linux/amd64 构建通过；当前主机为 Windows，未在本机原生执行 Linux 测试二进制。
- `scripts/verify-build-baseline.ps1` 已在 `go1.27.2 windows/amd64` 实际运行通过，并验证固定 FRPC/FRPS/Wintun SHA-256。
- F-01 至 F-06 已整理为 `frp_audit_regression` 可选回归套件。截至本轮复核，F-01、F-02、F-04、F-05、F-06 已通过，F-03 仍失败且不能被默认绿灯掩盖；F-03 属于 R2 的路由/出口约束工作。命令和平台分类见 `docs/R0-BUILD-AND-TEST-BASELINE.md`。
- CI 新增 Windows 与 Linux 双平台任务。2026-10-21 已建立首个 Git 提交基线；`dist/`、`.tmp-*`、运行配置、日志和凭据目录保持忽略，后续变更可通过 Git diff 审查。
