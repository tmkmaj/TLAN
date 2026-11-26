# 开源自部署客户端与双色界面 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** 为 Windows 原生客户端增加可持久化的自部署服务器入口、按服务器隔离的凭据恢复、精致入网页以及跟随系统/浅色/深色的即时主题切换。

**Architecture:** 地址规范化、STUN 推导和启动选择保持为可单测的纯函数；桌面会话通过事务式配置对象切换 API，成功后保存。视觉层使用集中语义色与控件树重绘，保留 Walk 原生控件和现有网络会话。

**Tech Stack:** Go、Walk、Windows GDI+、现有 `clientidentity.Settings` JSON/DPAPI 持久化。

**Spec:** `docs/superpowers/specs/2026-11-20-open-source-client-ui-design.md`

## Global Constraints

- 保留当前工作树已有未提交改动，不重置或覆盖无关文件。
- 不改变入网协议、FRP/Mesh 数据面或现有默认服务器。
- 不向不匹配的新服务器发送旧成员或管理员凭据。
- 不引入 Electron、WebView 或新的 UI 依赖。
- 新增行为先写可失败测试，再实现。

## Review Focus

- 自定义域名、IPv4/IPv6、端口和末尾斜杠必须生成正确 STUN 地址。
- 显式 `-server` 与保存服务器冲突时不能恢复旧服务器凭据。
- 入网失败不能覆盖之前的服务器、STUN 或成员配置。
- 深色模式必须覆盖输入框、表格、导航、提示条和对话框，而非只换窗口背景。
- 主题切换不能中断 Mesh/FRP，也不能破坏现有控件指针与可访问名称。

---

### Task 1: 服务器地址和 STUN 配置模型

**Files:** `cmd/client/endpoints.go`, `cmd/client/endpoints_test.go`, `internal/clientidentity/settings.go`, `internal/clientidentity/settings_test.go`

- [x] 为 URL 规范化、STUN 推导、启动端点选择和外观序列化编写失败测试。
- [x] 运行 `go test ./cmd/client ./internal/clientidentity`，确认新增测试按预期失败。
- [x] 实现绝对 HTTP(S) URL 校验/规范化、空值默认值、域名/IPv4/IPv6 STUN 推导和显式覆盖。
- [x] 增加外观设置字段并保持旧配置兼容。
- [x] 运行相关测试和 `go vet`。

### Task 2: 启动恢复与事务式入网

**Files:** `cmd/client/desktop_windows.go`, `cmd/client/endpoints.go`, `cmd/client/endpoints_test.go`, `cmd/client/desktop_windows_test.go`（如需要）

- [x] 为保存服务器恢复、显式 flag 优先、服务器不匹配凭据隔离和失败不覆盖配置编写失败测试。
- [x] 将入网改为先构造候选 API 与配置，验证成功后一次性提交。
- [x] 启动时选择有效保存服务器，只有 URL 匹配时恢复成员/管理员凭据。
- [x] 运行目标测试与完整客户端测试。

### Task 3: 入网页和设置界面

**Files:** `cmd/client/ui_windows.go`, `cmd/client/controls_windows.go`, `cmd/client/client_settings_windows.go`, `cmd/client/ui_check_windows.go`

- [x] 增加服务器地址、默认收起的 STUN 高级设置、清晰标签/示例、安全说明和连接状态。
- [x] 设置页增加跟随系统/浅色/深色选择，显示当前服务器，保留现有 MTU/游戏/托盘配置。
- [x] 连接中冻结输入，保留令牌显示、Enter/Escape 与可访问名称。
- [x] 更新 UI smoke 断言并构建客户端。

### Task 4: 浅色/深色即时主题系统

**Files:** `cmd/client/theme_windows.go`, `cmd/client/theme_test.go`, `cmd/client/ui_windows.go`, `cmd/client/controls_windows.go`, `cmd/client/client_settings_windows.go` 及使用语义色的现有客户端文件

- [x] 为主题规范化、系统判断和颜色映射编写测试。
- [x] 集中浅色/深色调色板，替换静态颜色依赖并提供即时控件树重绘。
- [x] 覆盖自定义按钮、圆角面板、输入框、导航、表格、FRP/管理页和后续对话框；高对比模式继续使用系统色。
- [x] 验证主题保存、系统默认和主题切换不影响会话状态。

### Task 5: 截图、文档和发布验收

**Files:** `README.md`, `docs/INSTALL-LINUX.md`（必要时）, `cmd/client/ui_check_windows.go`, `docs/screenshots/*`

- [x] 用本地 preview 验证浅色/深色入网页和主页面，检查裁切、对比、焦点与最小窗口。
- [x] 更新自部署客户端配置说明及旧配置兼容说明。
- [x] 运行 `go test ./...`、`go vet ./...`、Windows 构建、Linux 交叉构建和安装包脚本的相关检查。
- [x] 对照设计稿逐项审计，确认没有遗漏或借用旧 EXE 验证的问题。
