package wechat

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/xm-utils/authkit"
)

func TestWeChatExchangeTokenAndFetchUser(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// 令牌接口带 grant_type，用户信息接口不带，据此分流。
		if r.URL.Query().Get("grant_type") != "" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token":  "ACCESS",
				"expires_in":    7200,
				"refresh_token": "REFRESH",
				"scope":         "snsapi_login",
				"openid":        "OPEN123",
				"unionid":       "UNION456",
			})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"openid":     "OPEN123",
			"nickname":   "张三",
			"headimgurl": "https://img.example.com/1.png",
			"unionid":    "UNION456",
		})
	}))
	defer srv.Close()

	a := NewAdapter()
	a.tokenURL = srv.URL
	a.userURL = srv.URL

	cfg := &authkit.PlatformConfig{Platform: "wechat", ClientID: "cid", ClientSecret: "secret", RedirectURI: "https://login.example.com/cb"}

	tok, err := a.ExchangeToken(context.Background(), "CODE", cfg)
	if err != nil {
		t.Fatalf("ExchangeToken: %v", err)
	}
	if tok.AccessToken != "ACCESS" || tok.Raw["openid"] != "OPEN123" {
		t.Fatalf("unexpected token: %+v", tok)
	}

	user, err := a.FetchUserInfo(context.Background(), tok, cfg)
	if err != nil {
		t.Fatalf("FetchUserInfo: %v", err)
	}
	if user.OpenID != "OPEN123" || user.UnionID != "UNION456" || user.Nickname != "张三" {
		t.Fatalf("unexpected user: %+v", user)
	}
	if user.Platform != "wechat" {
		t.Fatalf("platform not normalized: %+v", user)
	}
}

func TestWeChatExchangeTokenPlatformError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"errcode": 40029, "errmsg": "invalid code"})
	}))
	defer srv.Close()

	a := NewAdapter()
	a.tokenURL = srv.URL
	if _, err := a.ExchangeToken(context.Background(), "bad", &authkit.PlatformConfig{}); err == nil {
		t.Fatal("expected error on platform errcode")
	}
}

func TestWeChatBuildAuthorizationURL(t *testing.T) {
	a := NewAdapter()
	cfg := &authkit.PlatformConfig{ClientID: "cid", RedirectURI: "https://x.example.com/cb", Scopes: []string{"snsapi_login"}}
	u, err := a.BuildAuthorizationURL("STATE", cfg, nil)
	if err != nil {
		t.Fatalf("BuildAuthorizationURL: %v", err)
	}
	for _, want := range []string{defaultAuthEndpoint, "appid=cid", "state=STATE", "#wechat_redirect"} {
		if !strings.Contains(u, want) {
			t.Fatalf("auth url missing %q: %s", want, u)
		}
	}
}
