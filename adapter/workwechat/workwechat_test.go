package workwechat

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/xm-utils/authkit"
)

func TestWorkWeChatFullFlow(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		q := r.URL.Query()
		switch {
		case q.Has("corpid"): // 换取企业 access_token
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "CORP", "expires_in": 7200, "errcode": 0})
		case q.Has("code"): // 用 code 解析成员 userid
			_ = json.NewEncoder(w).Encode(map[string]any{"userid": "manager123", "errcode": 0})
		case q.Has("userid"): // 拉取成员详情
			_ = json.NewEncoder(w).Encode(map[string]any{
				"name":    "李四",
				"mobile":  "13800000000",
				"email":   "lisi@example.com",
				"avatar":  "https://img.example.com/li.png",
				"unionid": "UNION_LI",
				"errcode": 0,
			})
		default:
			_ = json.NewEncoder(w).Encode(map[string]any{"errcode": 40013, "errmsg": "invalid corpsecret"})
		}
	}))
	defer srv.Close()

	a := NewAdapter()
	a.corpTokenURL = srv.URL
	a.userInfoURL = srv.URL
	a.userDetailURL = srv.URL

	cfg := &authkit.PlatformConfig{Platform: "work_wechat", ClientID: "corpid", ClientSecret: "secret", RedirectURI: "https://login.example.com/cb", Extra: map[string]string{"agentId": "100"}}

	tok, err := a.ExchangeToken(context.Background(), "AUTHCODE", cfg)
	if err != nil {
		t.Fatalf("ExchangeToken: %v", err)
	}
	if tok.AccessToken != "CORP" || tok.Raw["code"] != "AUTHCODE" {
		t.Fatalf("unexpected token: %+v", tok)
	}

	user, err := a.FetchUserInfo(context.Background(), tok, cfg)
	if err != nil {
		t.Fatalf("FetchUserInfo: %v", err)
	}
	if user.OpenID != "manager123" || user.UnionID != "UNION_LI" || user.Nickname != "李四" || user.Email != "lisi@example.com" {
		t.Fatalf("unexpected user: %+v", user)
	}
}

func TestWorkWeChatCorpTokenError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"errcode": 40013, "errmsg": "invalid corpid"})
	}))
	defer srv.Close()

	a := NewAdapter()
	a.corpTokenURL = srv.URL
	if _, err := a.ExchangeToken(context.Background(), "c", &authkit.PlatformConfig{}); err == nil {
		t.Fatal("expected error on corp token failure")
	}
}

func TestWorkWeChatBuildAuthorizationURL(t *testing.T) {
	a := NewAdapter()
	cfg := &authkit.PlatformConfig{ClientID: "corpid", RedirectURI: "https://x.example.com/cb", Extra: map[string]string{"agentId": "100"}}
	u, err := a.BuildAuthorizationURL("STATE", cfg, nil)
	if err != nil {
		t.Fatalf("BuildAuthorizationURL: %v", err)
	}
	for _, want := range []string{defaultAuthEndpoint, "login_type=CorpApp", "agentid=100", "state=STATE"} {
		if !strings.Contains(u, want) {
			t.Fatalf("auth url missing %q: %s", want, u)
		}
	}
}
