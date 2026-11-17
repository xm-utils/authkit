package authkit

import "errors"

// 组件对外暴露的可判别错误，使用方通过 errors.Is / errors.As 分支处理。
var (
	// ErrStateNotFound state 不存在或已过期。建议：提示重新发起授权。
	ErrStateNotFound = errors.New("authkit: state not found or expired")

	// ErrStateInvalid state 校验失败（IP 不匹配、平台/租户不符）。建议：拒绝并记录安全日志。
	ErrStateInvalid = errors.New("authkit: state validation failed")

	// ErrPlatformNotConfigured 平台未配置。建议：视为接入配置问题并告警。
	ErrPlatformNotConfigured = errors.New("authkit: platform not configured")

	// ErrAdapterNotRegistered 平台未注册适配器。建议：检查 WithAdapter 注册。
	ErrAdapterNotRegistered = errors.New("authkit: platform adapter not registered")

	// ErrCallbackNotAllowed 回调地址未命中白名单。建议：拒绝请求。
	ErrCallbackNotAllowed = errors.New("authkit: callback uri not allowed")

	// ErrCodeExchangeFailed 换取令牌失败。建议：提示重试，记录平台返回。
	ErrCodeExchangeFailed = errors.New("authkit: code exchange failed")

	// ErrFetchUserFailed 获取用户信息失败。建议：提示重试。
	ErrFetchUserFailed = errors.New("authkit: fetch user info failed")

	// ErrQrSessionNotFound 扫码会话不存在或已过期。建议：前端刷新二维码。
	ErrQrSessionNotFound = errors.New("authkit: qr session not found")

	// ErrQrStatusConflict 状态流转非法（跳变或重复确认）。建议：拒绝并忽略。
	ErrQrStatusConflict = errors.New("authkit: qr status conflict")

	// ErrQrExpired 二维码已过期。建议：前端刷新二维码。
	ErrQrExpired = errors.New("authkit: qr session expired")

	// ErrNotBound 三方账号未绑定本地账号。建议：走注册 / 绑定流程。
	ErrNotBound = errors.New("authkit: third-party account not bound")

	// ErrInvalidParam 参数非法（空 code、非法 qrUUID、TTL 越界等）。
	ErrInvalidParam = errors.New("authkit: invalid parameter")

	// ErrStorageNotConfigured 构造阶段缺少必需存储实现。
	ErrStorageNotConfigured = errors.New("authkit: required storage not injected")

	// ---- 第二因子（如 TOTP / 谷歌验证码）相关 ----

	// ErrSecondFactorUnsupported 未注入第二因子 Provider 或相关存储。建议：按需装配后重试。
	ErrSecondFactorUnsupported = errors.New("authkit: second factor not configured")

	// ErrSecondFactorNotEnrolled 用户尚未登记第二因子密钥。建议：引导用户先绑定验证器。
	ErrSecondFactorNotEnrolled = errors.New("authkit: second factor not enrolled")

	// ErrSecondFactorAlreadyEnrolled 用户已存在密钥且未允许覆盖。建议：走重新绑定（Overwrite）或先 Disable。
	ErrSecondFactorAlreadyEnrolled = errors.New("authkit: second factor already enrolled")

	// ErrOTPInvalid 一次性验证码不正确。建议：提示重新输入，并触发限流 / 锁定策略。
	ErrOTPInvalid = errors.New("authkit: invalid one-time code")

	// ErrOTPReused 一次性验证码在本时间窗口内已被使用（重放）。建议：拒绝并等待下一个窗口。
	ErrOTPReused = errors.New("authkit: one-time code already used")
)
