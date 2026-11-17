package authkit

import "context"

// PlatformAdapter 平台适配器契约。所有三方平台通过实现该接口接入，核心层不感知平台差异。
type PlatformAdapter interface {
	// PlatformName 返回平台唯一标识，需与 PlatformConfig.Platform 一致。
	PlatformName() string

	// BuildAuthorizationURL 拼接授权跳转地址，state 由核心层生成后传入。
	// ext 携带业务透传参数，开启 PKCE 时包含 code_challenge / code_challenge_method。
	BuildAuthorizationURL(state string, cfg *PlatformConfig, ext map[string]string) (string, error)

	// ExchangeToken 用授权 code 换取令牌。开启 PKCE 时，code_verifier 通过 cfg.Extra 传入。
	ExchangeToken(ctx context.Context, code string, cfg *PlatformConfig) (*TokenResult, error)

	// FetchUserInfo 用令牌拉取用户信息并归一化为 ThirdPartyUser。
	FetchUserInfo(ctx context.Context, token *TokenResult, cfg *PlatformConfig) (*ThirdPartyUser, error)
}

// TokenRefresher 可选的令牌刷新能力，仅当平台支持时实现。
// 核心层通过类型断言探测，不实现不会导致编译或运行错误。
type TokenRefresher interface {
	RefreshToken(ctx context.Context, refreshToken string, cfg *PlatformConfig) (*TokenResult, error)
}

// 适配器与核心层之间的约定键：PKCE 相关参数通过这些键在 ext / Extra 中传递。
const (
	// ExtraKeyCodeVerifier 是核心层向适配器透传 code_verifier 的约定键。
	ExtraKeyCodeVerifier = "code_verifier"
	// ExtraKeyCodeChallenge 是授权 URL 拼接时使用的 code_challenge 约定键。
	ExtraKeyCodeChallenge = "code_challenge"
	// ExtraKeyCodeChallengeMethod 是 code_challenge_method 约定键。
	ExtraKeyCodeChallengeMethod = "code_challenge_method"
)
