// Package wechat 提供微信开放平台（网站应用扫码登录）适配器。
// 依赖 UnionID 打通多应用，ClientID=AppID，ClientSecret=AppSecret。
package wechat

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/xm-utils/authkit"
)

// 平台默认接口地址，测试可通过覆盖 Adapter 端点字段指向 httptest 服务。
const (
	defaultAuthEndpoint  = "https://open.weixin.qq.com/connect/qrconnect"
	defaultTokenEndpoint = "https://api.weixin.qq.com/sns/oauth2/access_token"
	defaultUserEndpoint  = "https://api.weixin.qq.com/sns/userinfo"
)

// Adapter 微信开放平台适配器。HTTP 出口统一走弹性客户端单例。
type Adapter struct {
	authURL  string
	tokenURL string
	userURL  string
}

// NewAdapter 构建适配器，端点默认指向微信官方地址。
func NewAdapter() *Adapter {
	return &Adapter{authURL: defaultAuthEndpoint, tokenURL: defaultTokenEndpoint, userURL: defaultUserEndpoint}
}

// PlatformName 返回平台标识。
func (a *Adapter) PlatformName() string { return "wechat" }

// BuildAuthorizationURL 拼接微信扫码授权地址。
func (a *Adapter) BuildAuthorizationURL(state string, cfg *authkit.PlatformConfig, _ map[string]string) (string, error) {
	scope := strings.Join(cfg.Scopes, ",")
	if scope == "" {
		scope = "snsapi_login"
	}
	q := url.Values{}
	q.Set("appid", cfg.ClientID)
	q.Set("redirect_uri", cfg.RedirectURI)
	q.Set("response_type", "code")
	q.Set("scope", scope)
	q.Set("state", state)
	return a.authURL + "?" + q.Encode() + "#wechat_redirect", nil
}

// ExchangeToken 用 code 换取网页授权 access_token。
func (a *Adapter) ExchangeToken(ctx context.Context, code string, cfg *authkit.PlatformConfig) (*authkit.TokenResult, error) {
	q := url.Values{}
	q.Set("appid", cfg.ClientID)
	q.Set("secret", cfg.ClientSecret)
	q.Set("code", code)
	q.Set("grant_type", "authorization_code")

	resp, err := authkit.DoJSON(ctx, a.PlatformName(), http.MethodGet, a.tokenURL+"?"+q.Encode(), nil, nil)
	if err != nil {
		return nil, err
	}
	if e := authkit.PlatformError(resp); e != "" {
		return nil, fmt.Errorf("wechat exchange token: %s", e)
	}
	return &authkit.TokenResult{
		AccessToken:  authkit.Str(resp, "access_token"),
		RefreshToken: authkit.Str(resp, "refresh_token"),
		ExpiresIn:    authkit.Num(resp, "expires_in"),
		Scope:        authkit.Str(resp, "scope"),
		Raw:          resp,
	}, nil
}

// FetchUserInfo 拉取用户信息并归一化。
func (a *Adapter) FetchUserInfo(ctx context.Context, token *authkit.TokenResult, _ *authkit.PlatformConfig) (*authkit.ThirdPartyUser, error) {
	openID := authkit.Str(token.Raw, "openid")
	q := url.Values{}
	q.Set("access_token", token.AccessToken)
	q.Set("openid", openID)
	q.Set("lang", "zh_CN")

	resp, err := authkit.DoJSON(ctx, a.PlatformName(), http.MethodGet, a.userURL+"?"+q.Encode(), nil, nil)
	if err != nil {
		return nil, err
	}
	if e := authkit.PlatformError(resp); e != "" {
		return nil, fmt.Errorf("wechat fetch user: %s", e)
	}
	unionID := firstNonEmpty(authkit.Str(resp, "unionid"), authkit.Str(token.Raw, "unionid"))
	return &authkit.ThirdPartyUser{
		Platform:  a.PlatformName(),
		OpenID:    firstNonEmpty(authkit.Str(resp, "openid"), openID),
		UnionID:   unionID,
		Nickname:  authkit.Str(resp, "nickname"),
		AvatarURL: authkit.Str(resp, "headimgurl"),
		Raw:       resp,
	}, nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
