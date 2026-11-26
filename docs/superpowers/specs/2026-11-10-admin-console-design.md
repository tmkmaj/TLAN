# 管理令牌与内网管理控制台设计

日期：2026-11-10。状态：设计优化稿，待用户批准后进入实施计划。

本方案只覆盖 Linux 控制服务端的浏览器管理控制台和成员管理能力。它不把管理页接入 Windows 客户端，也不把管理员令牌转换成普通成员凭据。

## 1. 目标与背景

现有控制服务已经有两类身份：

- `network.join_code`：普通成员入网令牌，客户端用 `/api/v1/enroll` 换取绑定设备、网络和虚拟 IP 的 `member_...` 凭据。
- `security.admin_token`：管理令牌，当前只用于管理 API，没有浏览器管理页面。

本次升级要求：

- 普通用户令牌固定为 `TLAN`。
- 管理令牌固定为 `<ADMIN_TOKEN>`。
- 管理员使用管理令牌，通过服务器的内网地址访问管理页面。
- 管理页面展示服务器信息、成员连接情况和成员管理操作：断开、踢出、拉黑/解封、重命名等。

成功标准是：管理员可以在受限的内网入口完成上述操作；普通成员无法发现或调用管理 API；每个操作的存储状态、当前 Relay 连接、Managed FRP lease 和后续心跳行为一致；服务重启后封禁状态仍然有效；旧配置和已有成员身份不被破坏。

本方案的非目标包括：细粒度 RBAC、多人管理员、完整 WireGuard 数据包遥测、在线修改网络 CIDR、删除成员历史记录、远程修改管理员令牌，以及把管理页面暴露到公网控制入口。

`<ADMIN_TOKEN>` 只有 9 个字符，低于当前 24 字符校验。用户已明确要求保留原字符串；设计必须把这个选择视为已接受的部署约束，并通过独立内网监听、固定窗口登录限速、常量时间比较、HttpOnly 会话 Cookie、CSRF 校验和日志脱敏降低风险。

## 2. 选定接入方式

采用方案 A：**独立内网管理监听器**。

新增配置：

```yaml
server:
  admin_listen: "127.0.0.1:8081"
  admin_tls_cert: ""
  admin_tls_key: ""
```

规则：

- `admin_listen` 为空时禁用管理页面，不改变现有控制 API。
- 默认绑定 `127.0.0.1:8081`，适合 SSH 隧道；也可显式改为服务器内网 IP，例如 `10.10.0.20:8081`。
- 管理监听器只注册 `/admin`、`/admin/login`、`/admin/logout`、`/admin/api/*` 和静态页面资源，不暴露普通控制 API。原始 `X-Admin-Token`/Bearer 只保留在既有公网控制 API；管理监听器只接受服务端会话 + CSRF。
- 管理监听器与公网 `8443` 的 Caddy 入口分离，默认不把 `/admin` 反向代理到公网。
- 非回环且未配置 TLS 时，启动日志必须明确警告“管理页为明文 HTTP，请限制内网和防火墙访问”。
- 为避免短令牌在误配置时直接变成公网登录入口，非回环 `admin_listen` 且未配置 TLS 时默认拒绝启动；如果确实要使用明文内网管理，增加显式配置 `admin_allow_insecure_http: true`，启动日志和页面都显示高风险提示。
- 如果配置 `admin_tls_cert`/`admin_tls_key`，管理页使用 TLS，cookie 强制 `Secure`。
- 管理监听器必须使用独立 `http.ServeMux` 和独立 `http.Server`。不能把 `/admin` 挂到公网控制服务的 mux 上，再依靠路径或来源 IP 过滤。
- `Host` 必须匹配配置的管理监听地址、明确配置的管理主机名或回环地址。不能信任任意 `Host`、`X-Forwarded-Host` 或 `X-Forwarded-For`。
- 本版本不支持反向代理管理页。以后如果需要代理，必须单独增加可信代理 CIDR、转发头解析和代理层 TLS 终止契约。

## 3. 令牌与配置

新生成配置的默认值：

```yaml
network:
  join_code: "TLAN"
security:
  admin_token: "<ADMIN_TOKEN>"
```

校验调整：

- `network.join_code` 保持 8–256 字节，`TLAN` 合法。
- `security.admin_token` 由 24 字符下限调整为 8–256 字节；低于 24 字符时启用启动警告，而不是拒绝启动。
- 已有 `tlan-config.yml` 不会被程序静默覆盖；部署文档明确提示管理员手工替换两个令牌。
- 管理令牌不会进入客户端包、不会出现在 URL、不会写日志、不会出现在错误响应中。

实现上不要直接保存或逐字比较管理员令牌。加载配置后计算 `SHA-256(admin_token)`，登录时对提交值计算相同摘要，再用 `subtle.ConstantTimeCompare` 比较固定长度摘要。日志、诊断、panic、HTTP 错误和模板渲染都必须经过统一脱敏器。由于 `<ADMIN_TOKEN>` 是固定且较短的部署口令，生产部署文档应明确要求通过 SSH/内网、防火墙和 TLS 限制入口；代码只能降低暴露面，不能把该令牌变成高熵凭据。

管理 API 的认证继续支持 `X-Admin-Token`/`Authorization: Bearer`，浏览器管理页使用短期会话，不直接把令牌塞进每个前端请求。

## 4. 管理页认证

### 登录

`POST /admin/login` 接收管理令牌，服务端：

1. 按 TCP 对端 IP 做固定窗口限速；默认 5 次/15 分钟，超限返回 `429`。不读取未经验证的 `X-Forwarded-For`。该固定窗口同时作为本版本的失败锁定策略，不再增加独立账户锁定状态。
2. 使用固定长度比较函数验证令牌。
3. 成功后创建服务端会话，生成至少 32 字节随机会话 ID；服务端存储会话 ID 的摘要，而不是原值。
4. 只把随机会话 ID 写入 Cookie，不把管理令牌写入 Cookie。Cookie 名称使用产品专用前缀，避免与其他服务冲突。
5. 会话默认 30 分钟滑动过期、最大 8 个活跃会话，服务重启后失效。

Cookie：

- `HttpOnly`
- `SameSite=Strict`
- `Path=/admin`
- TLS 管理监听器时 `Secure`

### CSRF 与页面

- 登录成功后下发随机会话绑定的 CSRF token。
- 所有会改变状态的 `/admin/api/*` 请求必须带 `X-CSRF-Token`。
- 登录页、管理页和错误页禁止缓存。
- 不提供跨域 CORS；管理页只接受同源请求。
- 失败响应不区分“令牌错误”和“会话过期”，统一返回认证失败。
- 登录、登出和所有状态变更响应设置 `Cache-Control: no-store`；登录失败不能回显提交令牌、成员是否存在或内部错误详情。
- 服务端检查 `Origin`；有 Origin 时必须是当前管理 URL 的同源值。没有 Origin 的状态变更请求仍必须通过 CSRF token，不因为缺少 Origin 而放行。
- 会话需要绑定管理监听器实例和服务启动代次。服务重启后所有旧会话无效；管理员登出只撤销当前会话。

## 5. 管理页信息

### 概览

- 服务名称、版本、运行时间。
- 控制监听地址和是否启用 TLS。
- 管理监听地址。
- 网络名称、CIDR、成员总数、在线成员数、封禁成员数。
- Relay 状态、活跃 relay session 数量。
- FRP 当前模式（disabled/external/managed）。
- 数据目录摘要，不返回令牌、密钥、密码哈希或完整文件路径。

### 成员列表

“在线”采用与现有 `ListDevices` 一致的语义：最近心跳在 30 秒内且 Forwarding 未关闭；“活跃 Relay”单独展示。二者不一致时页面同时显示，不把 Relay session 数等同于 WireGuard 在线数。\n\n每个成员显示：

- 成员 ID、显示名称、虚拟 IP。
- 在线状态和最后心跳时间。
- 加入时间、Forwarding 状态。
- 拉黑状态。
- 当前是否有 relay session。

支持按名称、IP、ID 搜索；默认按在线优先、最后心跳倒序排列。

### 连接情况

- 展示每个成员的在线/离线状态和最后心跳。
- 展示 RelayBroker 当前活跃 session、source/target、建立时间、最近活动时间。
- 不展示 WireGuard 私钥、成员凭据、Relay secret 或管理令牌。
- 页面明确标注：当前可见的是控制面和 relay 观察结果，不代表内核 WireGuard 数据面的完整流量遥测。

## 6. 成员操作语义

### 重命名

`POST /admin/api/members/{id}/rename`

- 更新网络成员名称和控制面 `RegisteredDevice.DisplayName`。
- 保留成员 ID、公钥、虚拟 IP 和凭据。
- 名称 1–128 字符，去除首尾空白，不允许控制字符。
- 操作记录到服务端日志，但不记录令牌。

### 断开当前连接

`POST /admin/api/members/{id}/disconnect`

- 关闭该成员当前 RelayBroker session，并撤销该设备的活动 Managed FRP lease。
- 不删除成员、不撤销凭据。
- 成员下次心跳或 relay 请求可以重新建立连接。
- 用于临时排除问题，不用于永久移除。

### 踢出

`POST /admin/api/members/{id}/kick`

- 关闭该成员当前 Relay session，并撤销该设备的活动 Managed FRP lease。
- 撤销该成员所有 `member_...` 凭据。
- 保留成员记录，设置为离线；成员可用 `TLAN` 重新入网。
- 结果在管理页显示清晰提示：“已踢出，仍可重新加入”。
- 踢出必须先写入“凭据撤销”持久化状态，再执行 Relay/FRP 清理；清理失败不能恢复已撤销凭据，页面显示部分成功和后续重试信息。

### 拉黑

`POST /admin/api/members/{id}/ban`

- 关闭当前 Relay session，并撤销该设备的活动 Managed FRP lease。
- 撤销全部成员凭据。
- 在成员记录上设置持久化 `blocked=true`。
- `AuthenticateMember`、入网和心跳都拒绝被封禁设备。
- 成员列表和候选列表过滤被封禁设备，避免其他成员继续获取其连接信息。
- 管理页保留封禁成员记录，供解封。
- 拉黑必须是一个存储事务：设置 `blocked=true`、撤销全部成员凭据、增加身份版本号并记录操作者和原因，然后再执行连接清理。重复拉黑应幂等；解封不能自动签发旧凭据。
- **限制必须写在 UI 和文档中**：这里封禁的是已知的 Device ID、公钥和控制面记录；客户端删除本地身份后生成新身份，仍可能用 `TLAN` 重新入网。要阻止重装重入，需要另做服务器批准/邀请名单，这是本方案的后续扩展。

### 解封

`POST /admin/api/members/{id}/unban`

- 清除 `blocked` 状态。
- 保留成员记录和虚拟 IP。
- 由于凭据已在拉黑时撤销，用户仍需重新使用 `TLAN` 入网。
- 解封只恢复“允许重新申请”的状态，不恢复旧凭据、不自动恢复 Relay、不自动恢复 FRP lease。

### 删除

本轮不提供“彻底删除成员”按钮；避免管理员误操作丢失 IP 分配和封禁记录。需要彻底删除时由现有管理 API 的删除接口处理。本版本只记录结构化服务日志，不建立不可变操作历史；如果以后要求审计报表，再单独设计审计存储。

## 7. 存储模型变更

`storage.Device` 与 `storage.RegisteredDevice` 增加向后兼容字段：

```go
Blocked bool `json:"blocked,omitempty"`
```

新增存储方法：

- `RenameDevice(networkID, deviceID, name string) (Device, error)`
- `SetDeviceBlocked(networkID, deviceID string, blocked bool) (Device, error)`
- `RevokeMemberCredentials(networkID, deviceID string) error`
- `DisconnectDevice` 由控制层协调 RelayBroker 和存储层完成。

建议增加：

- `RevokeMemberCredentials` 返回实际撤销数量，并使用成员身份版本或凭据 epoch，避免并发入网请求在撤销之后又写入旧凭据。
- `GetDeviceAdminView` 返回管理页所需的脱敏快照，禁止直接把内部 `storage.Device` 序列化给浏览器。
- `AppendAdminEvent` 写入有限长度、脱敏的结构化操作日志；至少记录时间、来源 IP、动作、网络 ID、成员 ID、结果和错误码，不记录令牌、凭据、私钥或完整请求体。

`AuthenticateMember`、`EnrollPrivate`、`Heartbeat` 必须检查 `Blocked`。封禁设备不能重新加入或伪造心跳。已有客户端本地的 WireGuard peer 配置可能不会立即消失；服务端成员/候选过滤会让客户端后续刷新时移除，完整即时撤销需要后续数据面 ACL 协同。

## 8. Relay 断开与连接快照

`RelayBroker` 增加只读快照和按设备关闭能力：

- `Snapshot() []RelaySessionSummary`
- `DisconnectDevice(deviceID core.DeviceID) int`

快照只包含 session ID、source、target、建立时间、最近活动和 peer 是否已附加，不包含 secret。

## 9. 管理 API（仅 admin listener）

```text
GET  /admin                         登录页已登录时返回管理页
POST /admin/login                   管理令牌登录
POST /admin/logout                  注销当前会话
GET  /admin/api/overview            服务器、网络、Relay、FRP 摘要
GET  /admin/api/members             成员列表
POST /admin/api/members/{id}/rename
POST /admin/api/members/{id}/disconnect
POST /admin/api/members/{id}/kick
POST /admin/api/members/{id}/ban
POST /admin/api/members/{id}/unban
GET  /admin/api/relay-sessions      活跃 relay session
```

普通控制 API 的 `security.admin_token` 兼容路径保留，但管理监听器只使用会话认证 + CSRF。管理控制台只管理 `PrivateNetworkID` 对应的配置私人网络；管理操作必须校验网络 ID/成员 ID 的合法格式。

所有 `/admin/api/*` 响应使用统一 JSON 外壳：

```json
{"ok":true,"data":{},"request_id":"..."}
```

失败时使用：

```json
{"ok":false,"error":{"code":"MEMBER_NOT_FOUND","message":"成员不存在"},"request_id":"..."}
```

`message` 面向管理员，不能包含 token、文件内容或底层系统错误详情。服务端日志中的 `request_id` 用于关联一次管理操作。所有写操作支持幂等语义；危险操作需要请求体中的 `confirm` 或专用 endpoint，不能仅靠前端按钮防止误触。

建议补充两个接口：

- `GET /admin/api/session`：返回当前会话过期时间、服务启动代次和 CSRF token，不返回会话 ID。
- `GET /admin/api/events?before=...&limit=...`：读取脱敏的最近管理事件；如果本版本不提供该接口，至少保留服务端结构化日志。

## 10. 前端形态

- 单个内嵌 HTML/CSS/JS 管理页，不依赖外部 CDN 或网络资源。
- 中文界面，白蓝视觉与客户端侧栏一致。
- 顶部显示服务状态和当前管理员会话到期时间。
- 概览、成员、连接三个区域。
- 危险操作二次确认；拉黑和踢出使用不同颜色和说明。
- 操作成功后局部刷新并显示结果；失败显示可读错误，不泄漏 token。
- 桌面和手机宽度都可使用，表格在窄屏切为卡片。
- 前端不保存管理员令牌；刷新页面只依赖 HttpOnly Cookie，再通过 `/admin/api/session` 获取当前状态。
- 所有危险操作使用明确的目标名称、成员 ID 后四位、动作后果和当前状态确认；失败后保留服务端返回的 request ID。
- 前端展示“控制面在线”“Relay 会话存在”“Managed FRP lease 存在”三个独立状态，不能把一个状态推断成另两个状态。

## 11. 安全验收

必须覆盖：

- 错误令牌、正确令牌、限速、会话过期、注销、CSRF 缺失和跨源请求。
- `<ADMIN_TOKEN>` 原样生效且不出现在日志、Cookie、HTML、URL 或 JSON 响应。
- 普通成员凭据不能访问 `/admin`。
- 管理监听器不暴露 `/api/v1/*` 普通控制路由。
- 管理监听器只注册预期的 `/admin` 路由；随机路径、双重编码路径、`..` 路径和静态文件路径穿越都返回统一 404。
- 任意 `Host`、`X-Forwarded-Host`、`X-Forwarded-For` 和跨源 `Origin` 不能绕过入口限制。
- 会话 ID 不出现在日志、HTML、URL、诊断和错误正文；服务重启后旧 Cookie 失效。
- 断开、踢出、拉黑、解封、重命名的状态转换和持久化。
- 拉黑成员不能重新 enroll、heartbeat 或使用旧凭据。
- RelayBroker 断开只影响目标设备，不影响其他 session。
- 配置缺失、非回环 HTTP、TLS 配对错误和监听失败的行为。
- 全量 Go 测试、Linux 交叉构建、服务端启动 smoke 和管理页真实浏览器截图。

开发时还必须覆盖：

- 旧 YAML 没有 `admin_*` 字段时行为不变；未知字段仍按现有严格 YAML 规则处理；生成配置不静默写入用户指定令牌。
- 端口占用、证书缺失、证书与私钥不匹配、非回环明文未显式允许时，服务明确拒绝或禁用管理页。
- 两个浏览器会话同时踢出/拉黑同一成员时结果幂等，不能一个请求恢复另一个请求撤销的状态。
- Relay 关闭失败、FRP lease 撤销失败、成员凭据撤销成功时，页面显示部分成功和后续重试信息。
- 管理页面无缓存；静态资源无外部 CDN；CSP 至少限制 `default-src 'self'`，禁止任意 frame 嵌入。

## 12. Approaches 记录

- **A（选定）独立内网监听器**：安全隔离最好；需要配置内网地址/端口和防火墙。
- **B 复用公网 HTTPS + CIDR 白名单**：部署简单，但依赖反向代理来源可信性，误配置会把管理页暴露到公网。
- **C 仅 loopback + SSH 隧道**：最安全，但不符合从局域网设备直接浏览器的目标。

## 13. 明确非目标

- 不实现细粒度管理员角色或多人管理员。
- 不实现完整 WireGuard 数据包/流量统计。
- 不把管理页放进 Windows 客户端。
- 不静默修改已有部署配置中的令牌。
- 不把管理页默认暴露到公网 `8443`。

## 14. 已决定的实现取舍

- 默认管理监听器为 `127.0.0.1:8081`；用户可在 YAML 改为服务器内网 IP。
- 保留短管理令牌的用户要求，但只能用于独立管理监听器。
- 拉黑是持久状态；踢出只撤销凭据并保留成员记录。
- 管理页使用服务端会话 Cookie，不使用 URL token。
- 管理控制台只管理配置的单个私人网络。
- 固定窗口限速即本版本的失败锁定策略。
- 拉黑按已知设备身份生效；不承诺阻止删除本地身份后的重新入网。
- 操作日志使用结构化服务日志，不建立独立审计历史。

本次优化后的实现取舍：

- 低熵 `<ADMIN_TOKEN>` 仅作为部署兼容口令；非回环管理入口默认必须 TLS，不通过放宽公网认证来适配该口令。
- 管理监听器与普通控制 API 使用不同 mux、不同认证中间件和不同路由表；可以共享业务服务和存储，但不共享 HTTP 入口。
- 高影响操作采用“持久化撤销优先、运行时清理随后”的顺序；清理失败不得恢复已撤销凭据。
- 至少保留结构化管理事件日志；是否提供浏览器事件查询可以作为后续 UI 工作，但服务端不能完全没有操作证据。
- 管理页读取专用 DTO 和快照接口，禁止直接暴露内部存储结构，以便后续增加管理员角色和字段脱敏。

## 15. 推荐实现顺序

1. **配置与监听器**：新增 admin 配置字段、迁移/校验、独立 mux、TLS/明文启动门槛和服务启动 smoke。
2. **会话中间件**：实现令牌摘要校验、IP 限速、会话 Cookie、CSRF、Origin/Host 检查、统一错误和 request ID。
3. **存储事务**：增加 `Blocked`、凭据 epoch、重命名、封禁/解封、凭据撤销和结构化管理事件；先完成并发与重启测试。
4. **控制面协调**：实现成员快照、RelayBroker 快照/断开、Managed FRP lease 撤销和部分失败结果。
5. **只读页面**：先完成概览、成员列表、Relay 连接快照和状态分层，再加入写操作。
6. **成员操作**：按“重命名 → 断开 → 踢出 → 拉黑/解封”顺序接入，每个动作独立测试并验证幂等。
7. **安全与浏览器验收**：CSP、缓存、CSRF、跨源、Host、Cookie、路径穿越、真实浏览器截图和服务重启测试。

第一阶段不应同时引入 RBAC、成员彻底删除、网络配置编辑、远程更新和公网反向代理；这些内容会扩大权限边界，应等单管理员控制台的状态和撤销语义稳定后再单独设计。
