package main

import (
	"context"
	"net/url"

	"github.com/xm-utils/authkit"
)

// DemoAdapter 是一个离线可运行的平台适配器示例，不发起任何真实 HTTP 请求。
// 真实平台（微信 / 企业微信 / 钉钉 / GitHub / 支付宝 / 抖音）请使用 authkit 内置的 adapter 包，
// 支付宝/抖音的接入方式见 main.go（httptest mock 端点注入）；
// 接入自有 SSO / CAS 时按此结构实现 authkit.PlatformAdapter 即可。
type DemoAdapter struct{}

func (DemoAdapter) PlatformName() string { return "demo" }

func (DemoAdapter) BuildAuthorizationURL(state string, cfg *authkit.PlatformConfig, _ map[string]string) (string, error) {
	q := url.Values{}
	q.Set("client_id", cfg.ClientID)
	q.Set("redirect_uri", cfg.RedirectURI)
	q.Set("state", state)
	return "https://demo.example.com/oauth/authorize?" + q.Encode(), nil
}

func (DemoAdapter) ExchangeToken(_ context.Context, code string, _ *authkit.PlatformConfig) (*authkit.TokenResult, error) {
	return &authkit.TokenResult{
		AccessToken: "demo-access-token-for-" + code,
		TokenType:   "Bearer",
		ExpiresIn:   7200,
		Raw:         map[string]any{"scope": "user"},
	}, nil
}

// FetchUserInfo 返回一个固定的演示用户；真实实现会调用平台接口并归一化。
func (DemoAdapter) FetchUserInfo(_ context.Context, _ *authkit.TokenResult, _ *authkit.PlatformConfig) (*authkit.ThirdPartyUser, error) {
	return &authkit.ThirdPartyUser{
		Platform:  "demo",
		OpenID:    "demo-open-0001",
		UnionID:   "demo-union-0001",
		Nickname:  "演示用户",
		AvatarURL: "https://demo.example.com/avatar.png",
		Email:     "demo@example.com",
		Raw:       map[string]any{"from": "demo-adapter"},
	}, nil
}

// jwtLoginSuccessHandler 演示登录成功钩子：签发业务令牌并写入 LoginResult.Ext。
// 组件不生成/不管理会话，钩子内的令牌签发完全由业务决定。
type jwtLoginSuccessHandler struct{}

func (jwtLoginSuccessHandler) OnLoginSuccess(_ context.Context, result *authkit.LoginResult) (map[string]any, error) {
	return map[string]any{
		"token":  "jwt-for-user-" + result.LocalUserID,
		"userId": result.LocalUserID,
	}, nil
}
