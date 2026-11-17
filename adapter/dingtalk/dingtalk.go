// Package dingtalk 提供钉钉扫码登录适配器（OAuth 2.0 v1.0 接口）。
// ClientID=AppKey，ClientSecret=AppSecret；需在 Extra 配置 corpId。
package dingtalk

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
	defaultAuthEndpoint = "https://login.dingtalk.com/oauth2/auth"
	defaultTokenEP      = "https://api.dingtalk.com/v1.0/oauth2/userAccessToken"
	defaultUserEP       = "https://api.dingtalk.com/v1.0/contact/users/me"
)

// Adapter 钉钉适配器。HTTP 出口统一走弹性客户端单例。
type Adapter struct {
	authURL  string
	tokenURL string
	userURL  string
}

// NewAdapter 构建适配器，端点默认指向钉钉官方地址。
func NewAdapter() *Adapter {
	return &Adapter{authURL: defaultAuthEndpoint, tokenURL: defaultTokenEP, userURL: defaultUserEP}
}

// PlatformName 返回平台标识。
func (a *Adapter) PlatformName() string { return "dingtalk" }

// BuildAuthorizationURL 拼接钉钉授权地址。
func (a *Adapter) BuildAuthorizationURL(state string, cfg *authkit.PlatformConfig, _ map[string]string) (string, error) {
	scope := strings.Join(cfg.Scopes, ",")
	if scope == "" {
		scope = "openid"
	}
	q := url.Values{}
	q.Set("redirect_uri", cfg.RedirectURI)
	q.Set("response_type", "code")
	q.Set("client_id", cfg.ClientID)
	q.Set("scope", scope)
	q.Set("state", state)
	q.Set("prompt", "consent")
	if corpID := cfg.GetExtra("corpId", ""); corpID != "" {
		q.Set("corpId", corpID)
	}
	return a.authURL + "?" + q.Encode(), nil
}

// ExchangeToken 用授权 code 换取用户 accessToken。
func (a *Adapter) ExchangeToken(ctx context.Context, code string, cfg *authkit.PlatformConfig) (*authkit.TokenResult, error) {
	body := map[string]any{
		"clientId":     cfg.ClientID,
		"clientSecret": cfg.ClientSecret,
		"code":         code,
		"grantType":    "authorization_code",
	}
	resp, err := authkit.DoJSON(ctx, a.PlatformName(), http.MethodPost, a.tokenURL, nil, body)
	if err != nil {
		return nil, err
	}
	accessToken := authkit.Str(resp, "accessToken")
	if accessToken == "" {
		return nil, fmt.Errorf("dingtalk exchange token: empty accessToken")
	}
	return &authkit.TokenResult{
		AccessToken:  accessToken,
		RefreshToken: authkit.Str(resp, "refreshToken"),
		ExpiresIn:    authkit.Num(resp, "expireIn"),
		TokenType:    "Bearer",
		Raw:          resp,
	}, nil
}

// FetchUserInfo 拉取当前用户详情。
func (a *Adapter) FetchUserInfo(ctx context.Context, token *authkit.TokenResult, _ *authkit.PlatformConfig) (*authkit.ThirdPartyUser, error) {
	header := map[string]string{"x-acs-dingtalk-access-token": token.AccessToken}
	resp, err := authkit.DoJSON(ctx, a.PlatformName(), http.MethodGet, a.userURL, header, nil)
	if err != nil {
		return nil, err
	}
	return &authkit.ThirdPartyUser{
		Platform:  a.PlatformName(),
		OpenID:    firstNonEmpty(authkit.Str(resp, "openId"), authkit.Str(resp, "userId")),
		UnionID:   authkit.Str(resp, "unionId"),
		Nickname:  authkit.Str(resp, "nick"),
		AvatarURL: authkit.Str(resp, "avatarUrl"),
		Mobile:    authkit.Str(resp, "mobile"),
		Email:     authkit.Str(resp, "email"),
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
