package authkit

import "time"

// PlatformConfig 描述一个三方平台在某个租户下的接入配置。
// 由使用方通过 ConfigStorage 提供，组件只读不写。
type PlatformConfig struct {
	Platform     string            `json:"platform"`      // 平台标识，如 wechat、dingtalk
	TenantID     string            `json:"tenant_id"`     // 多租户隔离标识，单租户场景可留空
	ClientID     string            `json:"client_id"`     // 对应平台 appId / clientId
	ClientSecret string            `json:"client_secret"` // 对应平台 appSecret / clientSecret
	RedirectURI  string            `json:"redirect_uri"`  // 授权回调地址，必须命中白名单
	Scopes       []string          `json:"scopes"`        // 申请的权限范围
	Extra        map[string]string `json:"extra"`         // 平台特有参数，如企业微信的 agentId
}

// GetExtra 安全读取 Extra 中的键，不存在或为空时返回默认值。
func (c *PlatformConfig) GetExtra(key, def string) string {
	if c.Extra == nil {
		return def
	}
	if v, ok := c.Extra[key]; ok && v != "" {
		return v
	}
	return def
}

// StateMeta 与一次授权请求绑定的临时上下文，防 CSRF 与防重放的核心数据。
type StateMeta struct {
	State        string            `json:"state"`         // 32 字节加密随机串
	Platform     string            `json:"platform"`      // 发起授权的平台
	TenantID     string            `json:"tenant_id"`     // 租户标识
	ClientIP     string            `json:"client_ip"`     // 发起端 IP，回调时比对
	RedirectURI  string            `json:"redirect_uri"`  // 本次授权使用的回调地址
	CodeVerifier string            `json:"code_verifier"` // 开启 PKCE 时保存的 verifier
	CreatedAt    time.Time         `json:"created_at"`
	Ext          map[string]string `json:"ext"` // 透传的业务自定义参数
}

// ThirdPartyUser 各平台用户信息归一化后的统一模型。
type ThirdPartyUser struct {
	Platform  string         `json:"platform"`   // 平台标识
	OpenID    string         `json:"open_id"`    // 平台内用户唯一标识
	UnionID   string         `json:"union_id"`   // 跨应用统一标识，可能为空
	Nickname  string         `json:"nickname"`   // 昵称
	AvatarURL string         `json:"avatar_url"` // 头像地址
	Mobile    string         `json:"mobile"`     // 可能为空，需注意脱敏
	Email     string         `json:"email"`      // 可能为空
	Raw       map[string]any `json:"raw"`        // 平台原始返回，供业务扩展
}

// BindKey 返回用于查询绑定关系的唯一键：优先 UnionID，回落 OpenID。
func (u *ThirdPartyUser) BindKey() string {
	if u.UnionID != "" {
		return u.UnionID
	}
	return u.OpenID
}

// TokenResult 换取到的令牌信息。组件不持久化该结构，随结果返回给使用方。
type TokenResult struct {
	AccessToken  string         `json:"access_token"`
	RefreshToken string         `json:"refresh_token"`
	TokenType    string         `json:"token_type"`
	ExpiresIn    int64          `json:"expires_in"` // 秒
	Scope        string         `json:"scope"`
	Raw          map[string]any `json:"raw"`
}

// QrStatus 扫码二维码状态机取值，只允许按常量顺序流转，禁止跳变。
type QrStatus int

const (
	QrStatusPending   QrStatus = iota // 待扫描
	QrStatusScanned                   // 已扫描未确认
	QrStatusConfirmed                 // 已确认登录
	QrStatusCanceled                  // 用户取消
	QrStatusExpired                   // 已过期
)

// String 返回状态可读名称，便于日志输出。
func (s QrStatus) String() string {
	switch s {
	case QrStatusPending:
		return "pending"
	case QrStatusScanned:
		return "scanned"
	case QrStatusConfirmed:
		return "confirmed"
	case QrStatusCanceled:
		return "canceled"
	case QrStatusExpired:
		return "expired"
	default:
		return "unknown"
	}
}

// QrSession 一次扫码登录的会话数据。
type QrSession struct {
	QrUUID      string            `json:"qr_uuid"`       // 全局唯一二维码标识
	Status      QrStatus          `json:"status"`        // 当前状态
	LocalUserID string            `json:"local_user_id"` // 确认登录后绑定的本地用户
	Device      DeviceInfo        `json:"device"`        // 发起端设备信息，用于扫码后核对
	TenantID    string            `json:"tenant_id"`
	CreatedAt   time.Time         `json:"created_at"`
	ExpiresAt   time.Time         `json:"expires_at"`
	Ext         map[string]string `json:"ext"`
}

// DeviceInfo 发起扫码的设备信息，移动端确认登录前必须展示给用户核对。
type DeviceInfo struct {
	DeviceID  string `json:"device_id"`
	Model     string `json:"model"`
	IP        string `json:"ip"`
	Location  string `json:"location"`
	UserAgent string `json:"user_agent"`
}

// LoginResult 三方登录回调或扫码登录确认后的统一返回。
type LoginResult struct {
	Bound       bool            `json:"bound"`         // 是否已绑定本地账号
	LocalUserID string          `json:"local_user_id"` // 已绑定时返回
	ThirdUser   *ThirdPartyUser `json:"third_user"`    // 三方用户信息
	Token       *TokenResult    `json:"token"`         // 仅三方登录回调返回
	Ext         map[string]any  `json:"ext"`           // 钩子写入的扩展数据

	// RequireSecondFactor 为 true 表示身份已确认但需补充第二因子（如 TOTP）后才能签发会话。
	// 此时组件不会触发 LoginSuccessHandler；业务侧引导输入验证码后调用 VerifyTOTP 完成登录。
	RequireSecondFactor bool `json:"require_second_factor"`
}

// TOTPEnrollRequest 为用户绑定第二因子验证器的请求。
type TOTPEnrollRequest struct {
	LocalUserID string // 必填，本地用户唯一标识
	TenantID    string // 多租户隔离，单租户留空
	AccountName string // 展示在验证器中的账号名，留空取 LocalUserID
	Overwrite   bool   // 已存在密钥时是否覆盖（重新绑定）
}

// TOTPEnrollResult 绑定结果，Secret 仅此一次返回，供展示二维码。
type TOTPEnrollResult struct {
	Secret          string `json:"secret"`           // 共享密钥（如 base32），不透明
	ProvisioningURI string `json:"provisioning_uri"` // otpauth:// 地址，由业务侧渲染为二维码
}

// TOTPVerifyRequest 提交第二因子验证码的请求。
type TOTPVerifyRequest struct {
	LocalUserID string
	TenantID    string
	Code        string // 用户输入的动态验证码
}

// setExt 向 Ext 写入扩展数据，惰性初始化 map。
func (r *LoginResult) setExt(key string, val any) {
	if r.Ext == nil {
		r.Ext = map[string]any{}
	}
	r.Ext[key] = val
}

// AuthURLRequest 生成三方授权地址的请求参数。
type AuthURLRequest struct {
	Platform    string
	TenantID    string
	RedirectURI string // 必须命中白名单，留空时取平台配置中的 RedirectURI
	ClientIP    string
	Ext         map[string]string // 透传参数
}

// CallbackRequest 三方平台回调的请求参数。
type CallbackRequest struct {
	Platform string
	TenantID string
	Code     string
	State    string
	ClientIP string
}

// QrSessionRequest 创建扫码会话的请求参数。
type QrSessionRequest struct {
	TenantID string
	TTL      time.Duration // 留空取 Config.QrTTL
	Device   DeviceInfo
	Ext      map[string]string
}
