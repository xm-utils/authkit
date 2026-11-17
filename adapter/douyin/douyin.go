// Package douyin 提供抖音开放平台（网站应用）登录适配器。
// ClientID=ClientKey，ClientSecret=ClientSecret；接口响应统一包裹 {"data":{...},"error_code":0}。
package douyin

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
	defaultAuthEndpoint = "https://open.douyin.com/platform/oauth/connect"
	defaultTokenEP      = "https://open.douyin.com/oauth/access_token"
	defaultUserEP       = "https://open.douyin.com/oauth/userinfo"
)

// Option 适配器构建选项。
type Option func(*Adapter)

// WithEndpoints 覆盖平台接口地址（授权页、令牌、用户信息），空字符串保留默认值。
// 单元测试与离线示例可指向 httptest 服务，生产环境无需使用。
func WithEndpoints(authURL, tokenURL, userURL string) Option {
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
	}
}

// Adapter 抖音适配器。HTTP 出口统一走弹性客户端单例。
type Adapter struct {
	authURL  string
	tokenURL string
	userURL  string
}

// NewAdapter 构建适配器，端点默认指向抖音官方地址，可用 WithEndpoints 覆盖。
func NewAdapter(opts ...Option) *Adapter {
	a := &Adapter{authURL: defaultAuthEndpoint, tokenURL: defaultTokenEP, userURL: defaultUserEP}
	for _, opt := range opts {
		opt(a)
	}
	return a
}

// PlatformName 返回平台标识。
func (a *Adapter) PlatformName() string { return "douyin" }

// BuildAuthorizationURL 拼接抖音授权地址。scope 默认 user_info。
func (a *Adapter) BuildAuthorizationURL(state string, cfg *authkit.PlatformConfig, _ map[string]string) (string, error) {
	scope := strings.Join(cfg.Scopes, ",")
	if scope == "" {
		scope = "user_info"
	}
	q := url.Values{}
	q.Set("client_key", cfg.ClientID)
	q.Set("response_type", "code")
	q.Set("scope", scope)
	q.Set("redirect_uri", cfg.RedirectURI)
	q.Set("state", state)
	return a.authURL + "?" + q.Encode(), nil
}

// ExchangeToken 用授权 code 换取 access_token。
func (a *Adapter) ExchangeToken(ctx context.Context, code string, cfg *authkit.PlatformConfig) (*authkit.TokenResult, error) {
	q := url.Values{}
	q.Set("client_key", cfg.ClientID)
	q.Set("client_secret", cfg.ClientSecret)
	q.Set("code", code)
	q.Set("grant_type", "authorization_code")

	resp, err := a.do(ctx, http.MethodGet, a.tokenURL+"?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	return &authkit.TokenResult{
		AccessToken:  authkit.Str(resp, "access_token"),
		RefreshToken: authkit.Str(resp, "refresh_token"),
		ExpiresIn:    authkit.Num(resp, "expires_in"),
		Scope:        authkit.Str(resp, "scope"),
		Raw:          resp,
	}, nil
}

// FetchUserInfo 拉取抖音用户信息（返回字段为 data 包裹内的 open_id/nickname/avatar）。
func (a *Adapter) FetchUserInfo(ctx context.Context, token *authkit.TokenResult, _ *authkit.PlatformConfig) (*authkit.ThirdPartyUser, error) {
	q := url.Values{}
	q.Set("access_token", token.AccessToken)
	q.Set("open_id", authkit.Str(token.Raw, "open_id"))

	resp, err := a.do(ctx, http.MethodGet, a.userURL+"?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	return &authkit.ThirdPartyUser{
		Platform:  a.PlatformName(),
		OpenID:    authkit.Str(resp, "open_id"),
		Nickname:  authkit.Str(resp, "nickname"),
		AvatarURL: authkit.Str(resp, "avatar"),
		Raw:       resp,
	}, nil
}

// do 发起请求并解开抖音统一的 {"data":{...},"error_code":...,"description":...} 包裹。
// error_code 非 0 视为业务错误；无 data 节点时回退返回顶层 map。
func (a *Adapter) do(ctx context.Context, method, endpoint string, body any) (map[string]any, error) {
	resp, err := authkit.DoJSON(ctx, a.PlatformName(), method, endpoint, nil, body)
	if err != nil {
		return nil, err
	}
	if e := errorCode(resp); e != "" {
		return nil, fmt.Errorf("douyin %s: %s", method, e)
	}
	if data, ok := resp["data"].(map[string]any); ok {
		return data, nil
	}
	return resp, nil
}

// errorCode 读取 error_code/error_description，非 0 时返回可读错误。
func errorCode(m map[string]any) string {
	code := authkit.Str(m, "error_code")
	if code == "" {
		if n := authkit.Num(m, "error_code"); n != 0 {
			code = fmt.Sprintf("%d", n)
		}
	}
	if code == "" || code == "0" {
		return ""
	}
	return fmt.Sprintf("error_code=%s description=%s", code, authkit.Str(m, "description"))
}
