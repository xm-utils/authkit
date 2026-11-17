package authkit

import "time"

// Config 组件行为配置，通过 WithConfig 显式注入。
type Config struct {
	StateTTL   time.Duration // 授权 state 有效期，<=0 时取默认 300s
	QrTTL      time.Duration // 扫码会话默认 TTL，<=0 时取默认 300s
	EnablePKCE bool          // 是否开启 PKCE
	MinQrTTL   time.Duration // 允许的扫码会话最小 TTL，<=0 时不限制下限
	MaxQrTTL   time.Duration // 允许的扫码会话最大 TTL，<=0 时不限制上限

	// SFReplayWindow 第二因子防重放窗口：同一主体内同一口令在此时长内不可重复使用。
	// <=0 时取默认 90s（约 3 个 TOTP 时间步，覆盖 ±1 窗口偏移）。
	SFReplayWindow time.Duration
}

const defaultTTL = 300 * time.Second

const defaultSFReplayWindow = 90 * time.Second

func (c *Config) normalize() {
	if c.StateTTL <= 0 {
		c.StateTTL = defaultTTL
	}
	if c.QrTTL <= 0 {
		c.QrTTL = defaultTTL
	}
	if c.SFReplayWindow <= 0 {
		c.SFReplayWindow = defaultSFReplayWindow
	}
}

// options 收集所有 With* 注入项，供 New 校验与装配。
type options struct {
	cfg       Config
	state     StateStorage
	config    ConfigStorage
	mapping   UserMappingStorage
	qr        QrSessionStorage
	adapters  []PlatformAdapter
	whitelist []string
	logger    Logger
	success   LoginSuccessHandler
	converter UserInfoConverter
	exception ExceptionHandler
	qrGen     QrCodeGenerator

	// 第二因子相关（均为可选，三者需同时注入或同时不注入）。
	totpProvider TOTPProvider
	totpSecret   TOTPSecretStorage
	otpConsume   OTPConsumeStorage
	sfPolicy     SecondFactorPolicy
}

// Option 组件装配选项。
type Option func(*options)

// WithConfig 注入行为配置。
func WithConfig(cfg Config) Option { return func(o *options) { o.cfg = cfg } }

// WithStateStorage 注入授权临时态存储。
func WithStateStorage(s StateStorage) Option { return func(o *options) { o.state = s } }

// WithConfigStorage 注入平台配置存储。
func WithConfigStorage(s ConfigStorage) Option { return func(o *options) { o.config = s } }

// WithUserMappingStorage 注入用户绑定关系存储。
func WithUserMappingStorage(s UserMappingStorage) Option {
	return func(o *options) { o.mapping = s }
}

// WithQrSessionStorage 注入扫码会话存储。
func WithQrSessionStorage(s QrSessionStorage) Option {
	return func(o *options) { o.qr = s }
}

// WithAdapter 注册一个平台适配器，可多次调用注册多个平台。
func WithAdapter(a PlatformAdapter) Option {
	return func(o *options) { o.adapters = append(o.adapters, a) }
}

// WithCallbackWhitelist 注册回调地址白名单主机名。
// 条目以 "." 开头表示后缀匹配，否则要求主机名完全相等。
func WithCallbackWhitelist(hosts ...string) Option {
	return func(o *options) { o.whitelist = append(o.whitelist, hosts...) }
}

// WithLogger 注入日志实现，未注入时使用丢弃日志。
func WithLogger(l Logger) Option { return func(o *options) { o.logger = l } }

// WithLoginSuccessHandler 注入登录成功钩子。
func WithLoginSuccessHandler(h LoginSuccessHandler) Option {
	return func(o *options) { o.success = h }
}

// WithUserInfoConverter 注入用户信息转换器。
func WithUserInfoConverter(c UserInfoConverter) Option {
	return func(o *options) { o.converter = c }
}

// WithExceptionHandler 注入异常处理器。
func WithExceptionHandler(h ExceptionHandler) Option {
	return func(o *options) { o.exception = h }
}

// WithQrCodeGenerator 注入二维码生成器。
func WithQrCodeGenerator(g QrCodeGenerator) Option { return func(o *options) { o.qrGen = g } }

// WithTOTPProvider 注入第二因子验证提供方（如内置 NewTOTPProvider 或自建 2FA 服务适配）。
// 与 WithTOTPSecretStorage、WithOTPConsumeStorage 需同时注入，否则构造报错。
func WithTOTPProvider(p TOTPProvider) Option { return func(o *options) { o.totpProvider = p } }

// WithTOTPSecretStorage 注入第二因子密钥存储。
func WithTOTPSecretStorage(s TOTPSecretStorage) Option { return func(o *options) { o.totpSecret = s } }

// WithOTPConsumeStorage 注入一次性码防重放存储。
func WithOTPConsumeStorage(s OTPConsumeStorage) Option { return func(o *options) { o.otpConsume = s } }

// WithSecondFactorPolicy 注入二次验证触发策略；未注入时默认「已绑定即要求」。
func WithSecondFactorPolicy(p SecondFactorPolicy) Option { return func(o *options) { o.sfPolicy = p } }
