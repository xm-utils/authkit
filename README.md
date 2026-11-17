# authkit · 三方登录 / 扫码登录通用组件

轻量、无侵入、平台可扩展、**存储完全插拔**的 Go 认证组件。把「第三方平台登录」与「扫码登录」的通用逻辑收敛为可复用库。

> 核心边界：**只负责认证流程编排、安全校验与标准化结果输出**，不负责数据存储、不负责用户体系、不负责会话管理。所有需要落地的数据（授权临时态、平台配置、用户绑定关系、扫码会话）全部通过接口交给使用方实现。

| 项目 | 说明 |
| --- | --- |
| 组件名称 | authkit |
| 实现语言 | Go 1.21+（模块要求 go 1.24） |
| 框架依赖 | 核心层不绑定 Web 框架 / ORM / 缓存客户端 |
| 存储依赖 | 无，全部由使用方通过 SPI 注入 |

## 目录

- [核心特性](#核心特性)
- [安装](#安装)
- [快速开始](#快速开始)
- [对外 API](#对外-api)
- [存储 SPI 接口](#存储-spi-接口)
- [内置平台适配器](#内置平台适配器)
- [第二因子认证（TOTP / 谷歌验证码）](#第二因子认证totp--谷歌验证码)
- [扩展钩子](#扩展钩子)
- [核心流程](#核心流程)
- [安全设计](#安全设计)
- [错误码](#错误码)
- [HTTP 底层依赖](#http-底层依赖)
- [运行示例](#运行示例)
- [测试](#测试)
- [项目结构](#项目结构)
- [边界约定与最佳实践](#边界约定与最佳实践)

## 核心特性

- **多平台适配**：内置微信开放平台、企业微信、钉钉、GitHub，新增平台不改核心代码。
- **存储零绑定**：4 个 SPI 接口由使用方实现，对接自有 MySQL / Redis / MongoDB / 配置中心。
- **无状态可集群**：组件实例不持有任何会话状态，天然支持水平扩展。
- **安全内置**：CSRF 防护、防重放、PKCE、回调白名单、参数校验、日志脱敏。
- **第二因子可选**：TOTP（谷歌验证器同款 RFC 6238）作为一等能力内建，与 OAuth/扫码流程正交，未装配时行为与旧版完全一致。
- **职责单一**：不干预用户注册、账号绑定决策、令牌签发。

## 安装

```bash
go get github.com/xm-utils/authkit
```

## 快速开始

接入成本被压缩为三件事：**实现 4 个存储接口 → 注册平台适配器 → 按需注册扩展钩子**。

```go
import (
    "time"
    "github.com/xm-utils/authkit"
    "github.com/xm-utils/authkit/adapter/github"
    "github.com/xm-utils/authkit/adapter/wechat"
)

component, err := authkit.New(
    authkit.WithConfig(authkit.Config{
        StateTTL:   300 * time.Second,
        QrTTL:      300 * time.Second,
        EnablePKCE: false,
    }),
    authkit.WithStateStorage(myStateStore),        // 必须实现
    authkit.WithConfigStorage(myConfigStore),      // 必须实现
    authkit.WithUserMappingStorage(myMappingStore),// 必须实现
    authkit.WithQrSessionStorage(myQrStore),       // 必须实现
    authkit.WithAdapter(wechat.NewAdapter()),
    authkit.WithAdapter(github.NewAdapter()),
    authkit.WithCallbackWhitelist("login.example.com"),
    authkit.WithLogger(authkit.NewSlogLogger(slog.Default())),
    authkit.WithLoginSuccessHandler(jwtHandler{}),
)
```

`New` 会在构建阶段校验：4 个必需存储未注入直接返回 `ErrStorageNotConfigured`，不留到运行时。

### 三方登录：生成授权地址 + 处理回调

```go
// 1) 生成授权跳转地址（内部落一笔 state）
url, err := component.BuildAuthURL(ctx, authkit.AuthURLRequest{
    Platform:    "github",
    TenantID:    "",
    RedirectURI: "https://login.example.com/auth/callback",
    ClientIP:    clientIP,
})

// 2) 处理平台回调
result, err := component.HandleCallback(ctx, authkit.CallbackRequest{
    Platform: "github",
    Code:     r.URL.Query().Get("code"),
    State:    r.URL.Query().Get("state"),
    ClientIP: clientIP,
})
if result.Bound {
    // 已绑定：result.LocalUserID 与 result.Ext（钩子写入的业务令牌等）
} else {
    // 未绑定：用 result.ThirdUser 引导注册/绑定，随后调用 BindUser
}
```

### 扫码登录：状态机全流程

```go
sess, _ := component.CreateQrSession(ctx, authkit.QrSessionRequest{TTL: 120 * time.Second, Device: dev})
// 移动端扫码 → 展示发起端设备供核对
device, _ := component.HandleQrScanned(ctx, sess.QrUUID)
// 移动端确认
_ = component.ConfirmQrLogin(ctx, sess.QrUUID, localUserID, tenantID)
// 发起端轮询获取结果
got, _ := component.GetQrSession(ctx, sess.QrUUID)
```

## 对外 API

`Component` 接口（13 个方法）：

| 方法 | 说明 |
| --- | --- |
| `BuildAuthURL` | 生成三方授权跳转地址，同时落一笔 state |
| `HandleCallback` | 处理三方回调，返回统一 `LoginResult` |
| `BindUser` / `UnbindUser` | 建立 / 解除本地用户与三方账号绑定 |
| `CreateQrSession` | 创建扫码会话，返回 qrUUID 与过期时间 |
| `HandleQrScanned` | 处理移动端扫码，状态置为已扫描，返回设备信息 |
| `ConfirmQrLogin` | 处理移动端确认，状态置为已确认 |
| `CancelQrLogin` | 处理移动端取消 |
| `GetQrSession` | 供发起端查询会话状态（轮询 / 推送落地） |
| `EnrollTOTP` | 为用户生成 TOTP 密钥与 `otpauth://` 扫码地址（第二因子绑定） |
| `VerifyTOTP` | 校验动态口令，通过后签发会话（触发登录成功钩子） |
| `DisableTOTP` | 关闭用户的第二因子并删除密钥 |
| `RequireSecondFactor` | 查询某用户当前登录是否需要第二因子 |

## 存储 SPI 接口

组件全部持久化行为仅依赖以下 6 个接口，方法均以 `context.Context` 为首参。前 4 个必需，后 2 个仅在启用第二因子时必需。

| 接口 | 方法数 | 关键约束 |
| --- | --- | --- |
| `StateStorage` | 2 | `GetAndDeleteState` 必须原子（Redis `GETDEL`/Lua），不存在返回 `ErrStateNotFound` |
| `ConfigStorage` | 1 | 支持热更新，每次实时读取；缺失返回 `ErrPlatformNotConfigured`；`ClientSecret` 建议存储侧加密 |
| `UserMappingStorage` | 3 | `(tenant_id, platform, open_id)` 唯一；未绑定 `found=false` 而非报错 |
| `QrSessionStorage` | 4 | `UpdateQrStatus` 建议 CAS，防止「已确认」被并发覆盖回「已扫描」 |
| `TOTPSecretStorage` | 3 | 存取/删除用户 TOTP 共享密钥；`GetSecret` 未绑定返回 `found=false` 而非报错 |
| `OTPConsumeStorage` | 1 | `MarkUsed(subject, code, ttl)` 须为 SETNX + TTL 语义（首次 `firstUse=true`），用于口令防重放 |

## 内置平台适配器

| 平台标识 | 平台 | 配置要点 |
| --- | --- | --- |
| `wechat` | 微信开放平台 | 网站应用扫码登录，依赖 UnionID 打通多应用 |
| `work_wechat` | 企业微信 | `Extra.agentId` 必填，ClientID=corpid、ClientSecret=corpsecret |
| `dingtalk` | 钉钉 | OAuth2 v1.0，`Extra.corpId`，ClientID=AppKey |
| `github` | GitHub | 邮箱可能为空，自动经 `/user/emails` 补取主邮箱 |
| `alipay` | 支付宝 | 第三方网站登录（scope 默认 `auth_user`）；`Extra.PrivateKey` 必填（RSA2，PKCS1/PKCS8），可选 `Extra.AlipayPublicKey` 开启响应验签；支持 `TokenRefresher` |
| `douyin` | 抖音开放平台 | 网站应用登录，ClientID=ClientKey，scope 默认 `user_info`，自动解包 `data` 并按 `error_code` 判错 |

接入任意 OAuth2 平台 / 企业自建 SSO / CAS：实现 `PlatformAdapter` 接口后通过 `WithAdapter` **显式注册**（不做反射或依赖扫描自动装配）。可选实现 `TokenRefresher` 提供刷新能力。

## 第二因子认证（TOTP / 谷歌验证码）

第二因子与 `PlatformAdapter` **正交**：适配器负责建立身份，`TOTPProvider` 只校验已登录用户是否持有共享密钥，不产生用户身份。

### 能力组成

| 组成 | 说明 |
| --- | --- |
| `TOTPProvider` | 口令校验提供方契约（`Name` / `GenerateSecret` / `ProvisioningURI` / `Verify`）。内置 `NewTOTPProvider(TOTPConfig{...})` 为纯标准库 RFC 6238 实现（默认 6 位 / 30s / ±1 窗口 / SHA1）；接入企业自建 2FA 服务时实现该接口即可 |
| `TOTPSecretStorage` / `OTPConsumeStorage` | 密钥存取与口令防重放两个 SPI，与其余存储一样由使用方实现 |
| `SecondFactorPolicy` | 可选策略：决定某次登录是否需要二因子。默认策略为「用户已绑定密钥即要求」（opt-in per user） |
| `EnrollTOTP` / `VerifyTOTP` / `DisableTOTP` / `RequireSecondFactor` | `Component` 方法组，覆盖绑定、校验、关闭、查询 |

### 装配（三件套必须同时注入）

```go
component, err := authkit.New(
    /* ...4 个必需存储与适配器... */
    authkit.WithTOTPProvider(authkit.NewTOTPProvider(authkit.TOTPConfig{Issuer: "MyApp"})),
    authkit.WithTOTPSecretStorage(myTOTPSecretStore),
    authkit.WithOTPConsumeStorage(myOTPConsumeStore),
    authkit.WithSecondFactorPolicy(myPolicy), // 可选，缺省「已绑定即要求」
    authkit.WithConfig(authkit.Config{SFReplayWindow: 90 * time.Second}), // 防重放窗口，默认 90s
)
```

只注入其中一部分时 `New` 直接返回 `ErrStorageNotConfigured`，不留到运行时；完全不注入则组件行为与旧版一致（纯加法扩展）。

### 与 OAuth / 扫码流程的衔接

会话签发统一收敛在内部闸门 `finalizeLogin`（`HandleCallback` 已绑定分支与 `ConfirmQrLogin` 均走此处）：

1. 需要二因子 → `LoginResult.RequireSecondFactor=true` 直接返回，**不触发** `LoginSuccessHandler`（该钩子是旁路设计，不能当安全闸门），会话签发被延后。
2. 业务侧引导用户进入验证码输入页，调用 `VerifyTOTP`：口令正确且在防重放窗口内首次使用 → 此时才触发登录成功钩子、签发会话。
3. 口令错误返回 `ErrOTPInvalid`；同一用户同一口令重放返回 `ErrOTPReused`（subject = `{providerName}|{userID}|{tenantID}`）。
4. 策略查询自身报错时按 **fail-closed** 处理：中止本次登录，不放行。

```go
res, _ := component.HandleCallback(ctx, req)
if res.RequireSecondFactor {
    // 前端跳转验证码页 → 校验完成后：
    final, err := component.VerifyTOTP(ctx, authkit.TOTPVerifyRequest{
        LocalUserID: res.LocalUserID, Code: "123456",
    })
}
```

### 绑定 / 关闭

```go
enroll, _ := component.EnrollTOTP(ctx, authkit.TOTPEnrollRequest{LocalUserID: uid, AccountName: "alice@example.com"})
// 把 enroll.ProvisioningURI 生成二维码交给验证器扫码；重复绑定需 Overwrite=true
_ = component.DisableTOTP(ctx, uid, tenantID) // 关闭二因子并删除密钥
```

## 扩展钩子

| 扩展点 | 用途 |
| --- | --- |
| `LoginSuccessHandler` | 签发 JWT、写登录日志、发通知；返回值写入 `LoginResult.Ext` |
| `UserInfoConverter` | 把 `ThirdPartyUser` 映射为业务自有用户模型 |
| `ExceptionHandler` | 把组件错误统一转为业务错误码与提示文案 |
| `QrCodeGenerator` | 自定义二维码样式（组件默认只返回 qrUUID） |
| `Logger` | 桥接任意日志库（内置 `NewSlogLogger` 适配 `log/slog`） |

> 钩子执行异常不阻断主流程：旁路逻辑（日志、通知）失败仅记录日志，避免用户无法登录。强一致业务逻辑（如落库绑定）应走业务侧事务。

## 核心流程

### 三方授权登录

1. `BuildAuthURL` 生成 32 字节加密随机 state，绑定平台/租户/IP/回调地址落存储（TTL 默认 300s），开启 PKCE 时派生 `code_challenge`。
2. 用户授权后回调，`HandleCallback` 取出并**立即删除** state，校验存在性/平台/租户/IP。
3. 适配器换取令牌、拉取用户信息、归一化，查询绑定关系。
4. 已绑定 → 触发 `LoginSuccessHandler` 返回结论；未绑定 → 返回三方用户信息引导注册/绑定。
5. 组件**不持久化任何令牌**，`TokenResult` 仅随返回值传递。

### 扫码登录状态机

```
CreateQrSession        HandleQrScanned
[新建] ───────> Pending ─────────────> Scanned
                  │                      │
             TTL 到期                ConfirmQrLogin
                  ▼                      ▼
              Expired <── TTL ── Confirmed   Canceled(用户取消)
```

- 状态**只允许单向流转**，反向 / 跨级跳转返回 `ErrQrStatusConflict`。
- `Expired` / `Canceled` 为终态；`Confirmed` 后不可回到 `Scanned`。
- 状态推送通道（WebSocket / SSE / 长轮询）由业务侧实现，组件只提供查询能力。

## 安全设计

CSRF（state 一次性、读取即删）、防重放（原子 get-and-delete + 回调 IP 比对）、PKCE、开放重定向防护（回调白名单，支持 `.` 前缀后缀匹配）、参数校验、敏感数据不落盘、防钓鱼（确认前强制展示发起端设备并校验状态为 `Scanned`）、第二因子口令防重放（SETNX+TTL）与 fail-closed 策略、日志脱敏工具（`MaskSecret` / `MaskMobile` / `MaskEmail`）。

## 错误码

使用 `errors.Is` / `errors.As` 分支处理：

`ErrStateNotFound`、`ErrStateInvalid`、`ErrPlatformNotConfigured`、`ErrAdapterNotRegistered`、`ErrCallbackNotAllowed`、`ErrCodeExchangeFailed`、`ErrFetchUserFailed`、`ErrQrSessionNotFound`、`ErrQrStatusConflict`、`ErrQrExpired`、`ErrNotBound`、`ErrInvalidParam`、`ErrStorageNotConfigured`。

第二因子相关：`ErrSecondFactorUnsupported`（未装配二因子能力却调用相关方法）、`ErrSecondFactorNotEnrolled`（未绑定密钥即校验）、`ErrSecondFactorAlreadyEnrolled`（重复绑定且未 `Overwrite`）、`ErrOTPInvalid`（口令错误）、`ErrOTPReused`（口令重放）。

## HTTP 底层依赖

适配器的对外 HTTP 调用统一走 `github.com/xm-utils/tools/httpclient` 弹性客户端（内置**重试 + 熔断 + 请求日志**），经内部 `internal/httpclient` 适配封装。

- 该库为 `sync.Once` 全局单例：使用方可在进程启动时调用 `httpclient.Init(cfg, logKeeper)` 自定义超时 / 重试 / 熔断与日志落库；未显式初始化时，首次请求会以默认配置惰性初始化。
- 已知限制：底层库不透传 `context`，请求级超时由全局 `Config.Timeout` 控制。

> 注：引入该库后组件不再「仅依赖标准库」，如需可切换回纯标准库实现，请在接入前评估依赖树与「轻量、无侵入」原则的取舍。

## 运行示例

```bash
go run ./example
```

示例覆盖：组件初始化、三方授权登录（未绑定 → 绑定 → 已绑定并签发业务令牌）、防重放验证、扫码登录状态机全流程，**真实适配器（支付宝 / 抖音 / GitHub）的装配演示**：通过 `NewAdapter(WithEndpoints(...))` 把端点注入到本地 httptest mock 服务（含支付宝 RSA2 请求签名与响应验签、抖音 `data` 解包、GitHub 邮箱补取），以及 **TOTP 第二因子与 GitHub OAuth / 扫码共存的两段式登录**：三件套注入 → `EnrollTOTP` 拿 `otpauth://` 地址 → `HandleCallback`/`ConfirmQrLogin` 返回 `RequireSecondFactor` 后调 `VerifyTOTP` 才签发会话（含口令重放拒绝；未绑定验证器的用户行为与旧版一致）。内置一个不发起任何网络请求的 `DemoAdapter` 与模拟手机验证器的 `mock_authenticator.go`，全部离线运行。

## 测试

```bash
# 适配器 httptest 单测（无需网络）
go test ./adapter/...

# 核心流程单测 + memory SPI 实现（依赖 test 构建标签）
go test -tags test ./...
```

## 项目结构

```
authkit/
├── types.go / storage.go / adapter.go / hooks.go  核心类型与接口契约
├── component.go          Component 接口与全流程编排实现
├── totp.go               TOTPProvider 契约 + 内置 RFC 6238 实现 + SecondFactorPolicy
├── config.go             Config 与 With* Option
├── errors.go             可判别错误码
├── security.go           state/PKCE 生成、回调白名单、脱敏
├── id.go                 二维码标识生成（禁自增）
├── internal/httpclient/  弹性 HTTP 适配层
├── adapter/{wechat,workwechat,dingtalk,github,alipay,douyin}/  内置适配器（含 httptest 单测）
├── memory/               SPI 内存实现（//go:build test）
└── example/              可运行接入示例
```

## 边界约定与最佳实践

1. 生产环境禁止使用 `memory` 包（仅 `//go:build test`），集群部署必须注入分布式实现。
2. 平台密钥不硬编码，经配置中心加密存储，`ConfigStorage` 实现内部解密并支持热更新。
3. 回调地址严格白名单，杜绝开放重定向。
4. 绑定关系建唯一索引，有 UnionID 的平台优先用 UnionID 打通多应用。
5. 组件不做会话管理，JWT / Session 的签发、续期、失效由业务侧实现。
6. 单实例通过 `tenantID` 区分租户共用，无需按租户重复初始化。
