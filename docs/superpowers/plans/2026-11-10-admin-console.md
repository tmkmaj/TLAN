# 内网管理控制台实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 实现固定普通令牌 `TLAN`、固定管理令牌 `<ADMIN_TOKEN>` 和独立内网管理控制台。

**Architecture:** 保留现有公网控制 API，新增可配置独立 admin listener；管理页使用服务端会话 Cookie 和 CSRF，管理操作委托 storage、RelayBroker 和 Managed FRP 存储。

**Tech Stack:** Go 1.23+、net/http、现有 control/storage/network/frpauth、内嵌 HTML/CSS/JavaScript。

**Spec:** `<REPO_ROOT>\docs\superpowers\specs\2026-11-10-admin-console-design.md`

## Global Constraints

- 普通入网令牌固定为 `TLAN`；管理令牌固定为 `<ADMIN_TOKEN>`。
- 新配置默认 `server.admin_listen: "127.0.0.1:8081"`，管理页默认不暴露到公网 `8443`。
- 管理 listener 只接受会话 Cookie + CSRF；原始 Bearer 仅保留在既有公网控制 API。
- 管理页只管理 `PrivateNetworkID` 对应的私人网络。
- 拉黑只对已知 Device ID/公钥生效，UI 必须说明清除本地身份后可能重新入网。
- 断开/踢出/拉黑必须尽力撤销 Relay session 和 Managed FRP 设备 lease。
- 所有 Go 命令使用 `-mod=vendor`。

## Review Focus

- 封禁成员是否从成员/候选列表过滤，避免其他成员继续获取连接信息。
- 短管理令牌的登录限速、常量时间比较、Cookie/CSRF、日志脱敏。
- 断开、踢出、拉黑、解封、重命名的持久化状态和错误语义。
- 管理 listener 的路径隔离、TLS 配对错误和非回环明文警告。
- storage/RelayBroker 的锁顺序和数据一致性。

### Task 1: 配置和固定令牌

**Files:** `internal/config/config.go`, `internal/config/config_test.go`, `README.md`

**Interfaces:** `ServerConfig.AdminListen/AdminTLSCert/AdminTLSKey`; new default tokens; admin token length 8–256; admin TLS cert/key paired.

- [ ] Write failing config tests for defaults, short admin token, admin listener, mismatched TLS.
- [ ] Run `go test -mod=vendor ./internal/config -run 'Token|Admin' -count=1`; expect failure.
- [ ] Implement config fields/defaults/validation.
- [ ] Run `go test -mod=vendor ./internal/config -count=1`; expect PASS.
- [ ] Update README and commit Task 1.

### Task 2: 成员状态和操作

**Files:** `internal/storage/store.go`, `internal/storage/enrollment.go`, relevant storage tests.

**Interfaces:** `Device.Blocked`, `RegisteredDevice.Blocked`, `RenameDevice`, `SetDeviceBlocked`, `RevokeMemberCredentials`, `PrivateNetwork`; blocked checks in auth/enroll/heartbeat/list/candidates.

- [ ] Write failing rename, block/unblock, revoke, blocked enrollment/heartbeat/filter tests.
- [ ] Run `go test -mod=vendor ./internal/storage -run 'Rename|Blocked|Revoke|PrivateNetwork' -count=1`; expect failure.
- [ ] Implement backward-compatible storage changes.
- [ ] Run `go test -mod=vendor ./internal/storage -count=1`; expect PASS.
- [ ] Commit Task 2.
### Task 3: Relay 快照和按设备断开

**Files:** `internal/network/relay.go`, `internal/network/relay_snapshot_test.go`.

**Interfaces:** `RelaySessionSummary`, `(*RelayBroker).Snapshot`, `(*RelayBroker).DisconnectDevice`.

- [ ] Write failing snapshot/disconnect tests asserting secrets are omitted and only target sessions close.
- [ ] Run `go test -mod=vendor ./internal/network -run 'Snapshot|Disconnect' -count=1`; expect failure.
- [ ] Add session creation time, snapshot cloning and device-specific close.
- [ ] Run `go test -mod=vendor ./internal/network -count=1`; expect PASS.
- [ ] Commit Task 3.

### Task 4: 管理会话和登录限速

**Files:** `internal/control/admin_auth.go`, `internal/control/admin_auth_test.go`.

**Interfaces:** `newAdminAuth(token string, secure bool) *adminAuth`; login/logout/authorize; cookie `tlan_admin`; CSRF header `X-CSRF-Token`.

- [ ] Write failing tests for correct/wrong token, 5/15-minute limit, session expiry, logout, HttpOnly/SameSite and CSRF.
- [ ] Run `go test -mod=vendor ./internal/control -run 'AdminAuth' -count=1`; expect failure.
- [ ] Implement constant-time compare, server-side sessions and fixed-window limiter.
- [ ] Run focused tests; expect PASS.
- [ ] Commit Task 4.

### Task 5: 管理 API 和成员操作

**Files:** `internal/control/admin.go`, `internal/control/admin_test.go`, small dependency access changes in `internal/control/server.go`.

**Interfaces:** `(*Server).AdminHandler(adminToken string, secure bool) http.Handler`; routes `/admin`, `/admin/login`, `/admin/logout`, `/admin/api/overview`, `/admin/api/members`, `/admin/api/members/{id}/{action}`, `/admin/api/relay-sessions`; actions rename/disconnect/kick/ban/unban; kick/ban call FRP revoke when available.

- [ ] Write failing handler tests for login/CSRF, overview, member list, rename, disconnect, kick, ban/unban, blocked filtering and invalid IDs.
- [ ] Run `go test -mod=vendor ./internal/control -run 'Admin' -count=1`; expect failure.
- [ ] Implement strict JSON APIs and action orchestration with no token leakage.
- [ ] Run `go test -mod=vendor ./internal/control -count=1`; expect PASS.
- [ ] Commit Task 5.
### Task 6: 内嵌管理页面

**Files:** `internal/control/admin_page.go`, `internal/control/admin_test.go`.

**Interfaces:** embedded HTML/CSS/JS at `/admin`; panels 概览/成员/连接; login form; CSRF placeholder; no external URLs or admin token.

- [ ] Write failing page tests for required labels/action paths, no token, no external URL, CSRF placeholder.
- [ ] Run focused page tests; expect failure.
- [ ] Implement embedded page and fetch/action JavaScript.
- [ ] Run focused page tests; expect PASS.
- [ ] Commit Task 6.

### Task 7: 服务端 listener 接线

**Files:** `cmd/server/main.go`, optional isolated helper test.

**Interfaces:** admin listener helper uses `server.admin_listen` and optional `admin_tls_cert/key`; empty disables; non-loopback plaintext logs warning; shutdown is isolated.

- [ ] Write failing tests for disabled behavior and TLS pairing/address helper.
- [ ] Run focused server tests; expect failure.
- [ ] Start admin listener/server in `cmd/server/main.go` and include in shutdown.
- [ ] Run `go test -mod=vendor ./cmd/server ./internal/control ./internal/config -count=1`; expect PASS.
- [ ] Commit Task 7.

### Task 8: 文档、验收和发布验证

**Files:** `README.md`, `VALIDATION.md`, deployment docs/config examples, management screenshots.

- [ ] Add a config/example test that verifies the documented admin block can be loaded.
- [ ] Document exact config, default loopback address, LAN bind example, TLS warning and ban limitation.
- [ ] Run `gofmt -l`, `go vet -mod=vendor ./...`, `go test -mod=vendor ./... -count=1 -timeout 900s`.
- [ ] Build Linux server, run startup smoke, capture admin page screenshots at login and authenticated overview.
- [ ] Commit Task 8.

## Self-Review

- Spec coverage: fixed tokens, admin listener, session auth, CSRF, overview, members, connections, rename, disconnect, kick, ban/unban, FRP revocation, docs and tests all have tasks.
- Interface consistency: storage methods, `AdminHandler`, admin routes and Relay snapshot types are named once and reused.
- Security gates: wrong token/limit/cookie/CSRF, listener isolation, TLS pairing, blocked filtering, token redaction and reinstall-ban limitation each have owning tests/docs.
- Deferred scope: full reinstall-proof ban and persistent audit history are explicitly out of scope in the spec and UI.