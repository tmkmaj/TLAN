# 受控 FRPC 核心更新基础设施

日期：2026-10-21  
范围：`internal/coreupdate`、`cmd/corepack` 及其测试

## 状态声明

本轮只实现**更新基础设施**，没有完成发布工程，也没有把更新器接入现有客户端：

- **未生成生产 Ed25519 私钥。**
- **未部署生产更新源或 HTTPS 文件服务。**
- **未生成、签名或发布生产核心清单。**
- **未修改现有 Manager、`cmd/client`、`internal/frp`、`dist` 或构建脚本。**
- **未实现客户端自动检查更新、停止正在运行的 FRPC、替换后重启服务等集成动作。**
- **未做真实公网下载、真实发布密钥轮换或 24–72 小时长稳验收。**

因此，本基础设施可以被后续集成方调用，但当前程序不会因为本功能而自动升级。

## 设计边界

### 清单

清单是严格 JSON，只接受一个 schema：

```json
{
  "schemaVersion": 1,
  "version": "0.71.1",
  "platform": "windows-amd64",
  "url": "https://updates.example.invalid/frpc/0.71.1/frpc.exe",
  "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "size": 12345678,
  "publishedAt": "2026-10-21T12:00:00Z",
  "minimumClientVersion": "1.0.0",
  "expiresAt": "2026-11-21T12:00:00Z",
  "signature": "BASE64_ED25519_SIGNATURE"
}
```

必需字段为 `schemaVersion`、`version`、`platform`、`url`、`sha256`、`size`、`publishedAt`、`minimumClientVersion`；`expiresAt` 可选；签名时增加 `signature`。

解析器会拒绝未知字段、重复键、尾随 JSON、错误 schema、非法语义版本、非 HTTPS URL、非法 SHA-256、非正大小、错误时间格式和非法平台字符串。

### 签名与公钥

- 算法：Ed25519。
- 签名对象：除 `signature` 外的字段按固定结构序列化后的 canonical JSON。
- 公钥由调用方注入；源码中没有生产公钥，也没有测试私钥。
- 未配置公钥时，验证和安装均 fail-closed。
- `corepack` 只从调用方提供的私钥文件读取密钥，不打印密钥内容，不把密钥写入清单或状态文件。
- 私钥文件应由发布工程在受控机器上生成并保管，不应提交到仓库。

### 安装策略

调用方必须提供：

- `CoreRoot`
- 生产公钥
- 当前客户端版本
- 目标平台
- 版本白名单
- 平台白名单

安装器还会执行：

- 清单大小上限和核心包大小上限。
- 清单 URL 仅允许 `https`。
- 重定向必须保持同一主机和端口，并继续使用 HTTPS。
- 下载响应的 `Content-Length`、实际读取字节数、SHA-256 必须与清单一致。
- 临时文件写入后 `fsync`，再使用平台原子替换。
- 目标名必须是 `CoreRoot` 下的单个文件名；拒绝路径穿越、保留内部文件名和符号链接。
- 目标文件没有本工具状态文件时拒绝覆盖。
- 安装完成后重新验签、重新计算安装文件哈希。
- 状态提交或安装后校验失败时，使用备份回滚旧版本。
- 启动安装事务时清理未完成的下载/状态临时文件。
- Unix 目录权限为 `0700`，文件权限按用途收紧。
- Windows 使用当前用户 SID 的保护 DACL，并通过 `MoveFileExW(..., MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)` 做替换。

## 使用方式

### 签名

```powershell
go run -mod=vendor ./cmd/corepack sign `
  -manifest .\unsigned-manifest.json `
  -key C:\secure\frpc-release-private.key `
  -out .\signed-manifest.json
```

私钥文件支持 32 字节 seed、64 字节 Ed25519 私钥、hex/base64 编码，或 PKCS#8 PEM。生产流程建议使用受控的 PKCS#8 PEM 或 32 字节 seed 文件，并限制文件 ACL。

### 验证

```powershell
go run -mod=vendor ./cmd/corepack verify `
  -manifest .\signed-manifest.json `
  -public-key C:\secure\frpc-release-public.key `
  -client-version 1.0.0 `
  -platform windows-amd64 `
  -allowed-versions 0.71.1 `
  -allowed-platforms windows-amd64
```

`corepack verify` 用于发布前检查；真正的客户端安装必须由调用方注入公钥、版本白名单和平台白名单，不能只依赖命令行参数。

## 测试覆盖

已有回归测试覆盖：

- 清单/签名篡改
- 版本白名单、平台白名单和最低客户端版本
- 过期清单和未来发布时间
- 缺失公钥 fail-closed
- 非 HTTPS URL
- 跨主机重定向
- 下载中断
- 下载字节数/Content-Length 与清单不一致
- 下载大小上限
- SHA-256 不匹配
- 未托管目标覆盖拒绝
- 路径穿越、符号链接和保留目标名
- 临时文件清理
- 原子替换失败
- 状态提交失败后的旧版本回滚
- 安装后哈希校验失败后的回滚
- `corepack sign/verify` 和私钥不泄漏

本地验证命令：

```powershell
gofmt -l .\internal\coreupdate .\cmd\corepack
go test -mod=vendor .\internal\coreupdate .\cmd\corepack -count=1
go vet -mod=vendor .\internal\coreupdate .\cmd\corepack
$env:GOOS='linux'; $env:GOARCH='amd64'; $env:CGO_ENABLED='0'
go vet -mod=vendor .\internal\coreupdate .\cmd\corepack
```

## 发布工程仍需完成

以下事项不属于本轮代码实现：

1. 在离线/受控环境生成生产 Ed25519 密钥对，建立密钥保管、备份和轮换流程。
2. 将生产公钥通过受审核的客户端配置或未来集成点注入；不得把私钥或测试密钥写入源码。
3. 部署 HTTPS 更新源，配置证书、访问控制、缓存策略和可用性监控。
4. 在 CI 中构建核心包，计算 SHA-256，生成并签名清单，保存签名审计记录。
5. 将 `coreupdate.Installer` 接入未来客户端更新入口，明确何时检查、何时停止 FRPC、何时回滚和何时重启。
6. 做真实 Windows/Linux 下载、磁盘满、权限失败、断网、进程占用、接口切换和回滚演练。
7. 定义密钥撤销、清单过期、版本撤回和紧急回滚流程。
8. 做真实双平台、公网 HTTPS、长时间稳定性和发布回滚验收。

在这些事项完成前，本功能的状态是：**代码基础设施已实现并有本机测试，生产发布链路尚未部署。**

## 本机验证结果（2026-10-21）

已通过：

- `gofmt -l internal\coreupdate cmd\corepack`：无输出。
- `go test ./internal/coreupdate ./cmd/corepack -count=1`：通过。
- `go vet ./internal/coreupdate ./cmd/corepack`：Windows 通过。
- `GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go vet ./internal/coreupdate ./cmd/corepack`：通过。
- `GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go test -c ./internal/coreupdate`：通过。
- `GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go test -c ./cmd/corepack`：通过。
- `go test ./... -count=1 -timeout 300s`：全仓通过。
- `go vet ./...`：Windows 全仓通过。
- `GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go vet ./...`：Linux 全仓通过。
- Windows 下 `go build ./cmd/corepack`：通过。

未执行或未完成：

- 未运行 `go test -race`；当前环境没有可用的 CGO/gcc 组合。
- 未执行真实公网 HTTPS 下载、真实生产签名密钥、真实发布清单、真实客户端集成、断网/磁盘满/权限失败演练和长时间稳定性验收。