package dingtalk

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/xm-utils/authkit"
)

func TestDingTalkFullFlow(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost { // 换取用户 accessToken
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["code"] != "AUTHCODE" {
				_ = json.NewEncoder(w).Encode(map[string]any{"message": "invalid code"})
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"accessToken":  "AT",
				"refreshToken": "RT",
				"expireIn":     7200,
			})
			return
		}
		// 拉取当前用户详情
		if r.Header.Get("x-acs-dingtalk-access-token") != "AT" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"nick":      "王五",
			"avatarUrl": "https://img.example.com/wang.png",
			"openId":    "DT_OPEN",
			"unionId":   "DT_UNION",
			"mobile":    "13900000000",
			"email":     "wangwu@example.com",
		})
	}))
	defer srv.Close()

	a := NewAdapter()
	a.tokenURL = srv.URL
	a.userURL = srv.URL

	cfg := &authkit.PlatformConfig{Platform: "dingtalk", ClientID: "appkey", ClientSecret: "appsecret", RedirectURI: "https://login.example.com/cb"}

	tok, err := a.ExchangeToken(context.Background(), "AUTHCODE", cfg)
	if err != nil {
		t.Fatalf("ExchangeToken: %v", err)
	}
	if tok.AccessToken != "AT" || tok.TokenType != "Bearer" || tok.ExpiresIn != 7200 {
		t.Fatalf("unexpected token: %+v", tok)
	}

	user, err := a.FetchUserInfo(context.Background(), tok, cfg)
	if err != nil {
		t.Fatalf("FetchUserInfo: %v", err)
	}
	if user.OpenID != "DT_OPEN" || user.UnionID != "DT_UNION" || user.Nickname != "王五" || user.Email != "wangwu@example.com" {
		t.Fatalf("unexpected user: %+v", user)
	}
}

func TestDingTalkBuildAuthorizationURL(t *testing.T) {
	a := NewAdapter()
	cfg := &authkit.PlatformConfig{ClientID: "appkey", RedirectURI: "https://x.example.com/cb", Extra: map[string]string{"corpId": "ding123"}}
	u, err := a.BuildAuthorizationURL("STATE", cfg, nil)
	if err != nil {
		t.Fatalf("BuildAuthorizationURL: %v", err)
	}
	for _, want := range []string{defaultAuthEndpoint, "client_id=appkey", "corpId=ding123", "state=STATE", "prompt=consent"} {
		if !strings.Contains(u, want) {
			t.Fatalf("auth url missing %q: %s", want, u)
		}
	}
}
