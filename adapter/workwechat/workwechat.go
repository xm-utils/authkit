// Package workwechat 提供企业微信扫码登录适配器。
// 需在 PlatformConfig.Extra 中配置 agentId；ClientID=corpid，ClientSecret=corpsecret。
package workwechat

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
	defaultAuthEndpoint   = "https://login.work.weixin.qq.com/wwlogin/sso/login"
	defaultCorpTokenEP    = "https://qyapi.weixin.qq.com/cgi-bin/gettoken"
	defaultUserInfoAuthEP = "https://qyapi.weixin.qq.com/cgi-bin/auth/getuserinfo"
	defaultUserDetailEP   = "https://qyapi.weixin.qq.com/cgi-bin/user/get"
)

// Adapter 企业微信适配器。HTTP 出口统一走弹性客户端单例。
type Adapter struct {
	authURL       string
	corpTokenURL  string
	userInfoURL   string
	userDetailURL string
}

// NewAdapter 构建适配器，端点默认指向企业微信官方地址。
func NewAdapter() *Adapter {
	return &Adapter{
		authURL:       defaultAuthEndpoint,
		corpTokenURL:  defaultCorpTokenEP,
		userInfoURL:   defaultUserInfoAuthEP,
		userDetailURL: defaultUserDetailEP,
	}
}

// PlatformName 返回平台标识。
func (a *Adapter) PlatformName() string { return "work_wechat" }

// BuildAuthorizationURL 拼接企业微信扫码授权地址。
func (a *Adapter) BuildAuthorizationURL(state string, cfg *authkit.PlatformConfig, _ map[string]string) (string, error) {
	q := url.Values{}
	q.Set("login_type", "CorpApp")
	q.Set("appid", cfg.ClientID)
	if agentID := cfg.GetExtra("agentId", ""); agentID != "" {
		q.Set("agentid", agentID)
	}
	q.Set("redirect_uri", cfg.RedirectURI)
	q.Set("state", state)
	if len(cfg.Scopes) > 0 {
		q.Set("scope", strings.Join(cfg.Scopes, ","))
	}
	return a.authURL + "?" + q.Encode(), nil
}

// corpAccessToken 用 corpid+corpsecret 换取企业 access_token。
func (a *Adapter) corpAccessToken(ctx context.Context, cfg *authkit.PlatformConfig) (string, error) {
	q := url.Values{}
	q.Set("corpid", cfg.ClientID)
	q.Set("corpsecret", cfg.ClientSecret)
	resp, err := authkit.DoJSON(ctx, a.PlatformName(), http.MethodGet, a.corpTokenURL+"?"+q.Encode(), nil, nil)
	if err != nil {
		return "", err
	}
	if e := authkit.PlatformError(resp); e != "" {
		return "", fmt.Errorf("workwechat corp token: %s", e)
	}
	tok := authkit.Str(resp, "access_token")
	if tok == "" {
		return "", fmt.Errorf("workwechat corp token: empty access_token")
	}
	return tok, nil
}

// ExchangeToken 换取企业 access_token，并把授权 code 暂存于 Raw，供 FetchUserInfo 解析身份。
// 企业微信换取用户身份需要「access_token + code」两步，而 PlatformAdapter 接口只在
// ExchangeToken 传入 code，故在此把 code 保存到 TokenResult.Raw 中向后传递。
func (a *Adapter) ExchangeToken(ctx context.Context, code string, cfg *authkit.PlatformConfig) (*authkit.TokenResult, error) {
	tok, err := a.corpAccessToken(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return &authkit.TokenResult{
		AccessToken: tok,
		TokenType:   "corp_access_token",
		Raw:         map[string]any{"code": code},
	}, nil
}

// FetchUserInfo 用 code 解析 userid，再拉取成员详情。
func (a *Adapter) FetchUserInfo(ctx context.Context, token *authkit.TokenResult, cfg *authkit.PlatformConfig) (*authkit.ThirdPartyUser, error) {
	code, _ := token.Raw["code"].(string)
	if code == "" {
		return nil, fmt.Errorf("workwechat fetch user: missing code in token.Raw")
	}

	q := url.Values{}
	q.Set("access_token", token.AccessToken)
	q.Set("code", code)
	resp, err := authkit.DoJSON(ctx, a.PlatformName(), http.MethodGet, a.userInfoURL+"?"+q.Encode(), nil, nil)
	if err != nil {
		return nil, err
	}
	if e := authkit.PlatformError(resp); e != "" {
		return nil, fmt.Errorf("workwechat getuserinfo: %s", e)
	}
	userID := firstNonEmpty(authkit.Str(resp, "userid"), authkit.Str(resp, "openid"))
	if userID == "" {
		return nil, fmt.Errorf("workwechat getuserinfo: empty userid")
	}

	user := &authkit.ThirdPartyUser{
		Platform: a.PlatformName(),
		OpenID:   userID,
		Raw:      resp,
	}

	// 企业成员可进一步拉取详情；外部联系人(仅 openid)无详情接口，忽略失败。
	dq := url.Values{}
	dq.Set("access_token", token.AccessToken)
	dq.Set("userid", userID)
	detail, err := authkit.DoJSON(ctx, a.PlatformName(), http.MethodGet, a.userDetailURL+"?"+dq.Encode(), nil, nil)
	if err == nil && authkit.PlatformError(detail) == "" {
		user.Nickname = firstNonEmpty(authkit.Str(detail, "name"), authkit.Str(detail, "alias"))
		user.AvatarURL = authkit.Str(detail, "avatar")
		user.Mobile = authkit.Str(detail, "mobile")
		user.Email = authkit.Str(detail, "email")
		user.UnionID = authkit.Str(detail, "unionid")
		user.Raw = detail
	}
	return user, nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
