// Package github 提供 GitHub OAuth 2.0 登录适配器。
// ClientID=Client ID，ClientSecret=Client secret。邮箱为空时通过 /user/emails 补取。
package github

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/xm-utils/authkit"
)

// 平台默认接口地址，可通过 NewAdapter 的 WithEndpoints 选项覆盖（指向 httptest 服务等）。
const (
	defaultAuthEP       = "https://github.com/login/oauth/authorize"
	defaultTokenEP      = "https://github.com/login/oauth/access_token"
	defaultUserEP       = "https://api.github.com/user"
	defaultUserEmailsEP = "https://api.github.com/user/emails"
)

// Adapter GitHub 适配器。HTTP 出口统一走弹性客户端单例。
type Adapter struct {
	authURL       string
	tokenURL      string
	userURL       string
	userEmailsURL string
}

// Option 适配器构建选项。
type Option func(*Adapter)

// WithEndpoints 覆盖平台接口地址，空字符串保留默认值。
// 依次为：授权页、令牌接口、用户信息接口、邮箱列表接口；仅测试/代理场景使用。
func WithEndpoints(authURL, tokenURL, userURL, userEmailsURL string) Option {
	return func(a *Adapter) {
		if authURL != "" {
			a.authURL = authURL
		}
		if tokenURL != "" {
			a.tokenURL = tokenURL
		}
		if userURL != "" {
			a.userURL = userURL
		}
		if userEmailsURL != "" {
			a.userEmailsURL = userEmailsURL
		}
	}
}

// NewAdapter 构建适配器，端点默认指向 GitHub 官方地址，可用 WithEndpoints 覆盖。
func NewAdapter(opts ...Option) *Adapter {
	a := &Adapter{
		authURL:       defaultAuthEP,
		tokenURL:      defaultTokenEP,
		userURL:       defaultUserEP,
		userEmailsURL: defaultUserEmailsEP,
	}
	for _, opt := range opts {
		opt(a)
	}
	return a
}

// tokenForm 对应 GitHub 令牌接口的 application/x-www-form-urlencoded 请求体，
// 依赖 go-querystring 的 url tag 由底层库完成表单序列化。
type tokenForm struct {
	ClientID     string `url:"client_id"`
	ClientSecret string `url:"client_secret"`
	Code         string `url:"code"`
	RedirectURI  string `url:"redirect_uri"`
	CodeVerifier string `url:"code_verifier,omitempty"`
}

// PlatformName 返回平台标识。
func (a *Adapter) PlatformName() string { return "github" }

// BuildAuthorizationURL 拼接 GitHub 授权地址。
func (a *Adapter) BuildAuthorizationURL(state string, cfg *authkit.PlatformConfig, ext map[string]string) (string, error) {
	scope := strings.Join(cfg.Scopes, ",")
	if scope == "" {
		scope = "user:email"
	}
	q := url.Values{}
	q.Set("client_id", cfg.ClientID)
	q.Set("redirect_uri", cfg.RedirectURI)
	q.Set("scope", scope)
	q.Set("state", state)
	// GitHub 支持 PKCE，透传 challenge。
	if ch := ext[authkit.ExtraKeyCodeChallenge]; ch != "" {
		q.Set("code_challenge", ch)
		q.Set("code_challenge_method", ext[authkit.ExtraKeyCodeChallengeMethod])
	}
	return a.authURL + "?" + q.Encode(), nil
}

// ExchangeToken 用 code 换取访问令牌。
func (a *Adapter) ExchangeToken(ctx context.Context, code string, cfg *authkit.PlatformConfig) (*authkit.TokenResult, error) {
	form := tokenForm{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Code:         code,
		RedirectURI:  cfg.RedirectURI,
		CodeVerifier: cfg.GetExtra(authkit.ExtraKeyCodeVerifier, ""),
	}

	resp, err := authkit.DoJSON(ctx, a.PlatformName(), http.MethodPost, a.tokenURL,
		map[string]string{"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"}, form)
	if err != nil {
		return nil, err
	}
	if e := authkit.PlatformError(resp); e != "" {
		return nil, fmt.Errorf("github exchange token: %s", e)
	}
	accessToken := authkit.Str(resp, "access_token")
	if accessToken == "" {
		return nil, fmt.Errorf("github exchange token: empty access_token")
	}
	return &authkit.TokenResult{
		AccessToken:  accessToken,
		RefreshToken: authkit.Str(resp, "refresh_token"),
		TokenType:    authkit.Str(resp, "token_type"),
		ExpiresIn:    authkit.Num(resp, "expires_in"),
		Scope:        authkit.Str(resp, "scope"),
		Raw:          resp,
	}, nil
}

// FetchUserInfo 拉取用户信息，邮箱缺失时通过 /user/emails 补取主邮箱。
func (a *Adapter) FetchUserInfo(ctx context.Context, token *authkit.TokenResult, _ *authkit.PlatformConfig) (*authkit.ThirdPartyUser, error) {
	header := map[string]string{"Authorization": "Bearer " + token.AccessToken}
	resp, err := authkit.DoJSON(ctx, a.PlatformName(), http.MethodGet, a.userURL, header, nil)
	if err != nil {
		return nil, err
	}
	if e := authkit.PlatformError(resp); e != "" {
		return nil, fmt.Errorf("github fetch user: %s", e)
	}

	openID := fmt.Sprintf("%v", resp["id"])
	if openID == "<nil>" || openID == "" {
		return nil, fmt.Errorf("github fetch user: missing id")
	}
	user := &authkit.ThirdPartyUser{
		Platform:  a.PlatformName(),
		OpenID:    openID,
		Nickname:  firstNonEmpty(authkit.Str(resp, "name"), authkit.Str(resp, "login")),
		AvatarURL: authkit.Str(resp, "avatar_url"),
		Email:     authkit.Str(resp, "email"),
		Raw:       resp,
	}

	// 隐私账号 email 为空时，补取已验证主邮箱。
	if user.Email == "" {
		if email, ok := a.fetchPrimaryEmail(ctx, token); ok {
			user.Email = email
		}
	}
	return user, nil
}

// fetchPrimaryEmail 从 /user/emails 取已验证的主邮箱。
func (a *Adapter) fetchPrimaryEmail(ctx context.Context, token *authkit.TokenResult) (string, bool) {
	header := map[string]string{"Authorization": "Bearer " + token.AccessToken}
	emails, err := authkit.DoJSONArray(ctx, a.PlatformName(), http.MethodGet, a.userEmailsURL, header, nil)
	if err != nil {
		return "", false
	}
	for _, m := range emails {
		if boolTrue(m, "primary") && boolTrue(m, "verified") {
			if email := authkit.Str(m, "email"); email != "" {
				return email, true
			}
		}
	}
	// 没有主邮箱时退而取第一个已验证邮箱。
	for _, m := range emails {
		if boolTrue(m, "verified") {
			if email := authkit.Str(m, "email"); email != "" {
				return email, true
			}
		}
	}
	return "", false
}

func boolTrue(m map[string]any, key string) bool {
	if m == nil {
		return false
	}
	v, _ := m[key].(bool)
	return v
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
