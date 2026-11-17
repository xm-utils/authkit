package github

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/xm-utils/authkit"
)

func TestGitHubFullFlow(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost: // 令牌接口（表单请求）
			_ = r.ParseForm()
			if r.Form.Get("code") != "AUTHCODE" {
				_ = json.NewEncoder(w).Encode(map[string]any{"error": "bad_verification_code"})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token":  "GH_AT",
				"token_type":    "bearer",
				"scope":         "user:email",
				"expires_in":    3600,
				"refresh_token": "GH_RT",
			})
		case strings.HasSuffix(r.URL.Path, "/user/emails"): // 邮箱列表（顶层数组）
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{"email": "backup@example.com", "verified": true, "primary": false},
				{"email": "octocat@example.com", "verified": true, "primary": true},
			})
		case strings.HasSuffix(r.URL.Path, "/user"): // 用户信息
			// 隐私账号 email 字段为空，触发 /user/emails 补取。
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":         583231,
				"login":      "octocat",
				"name":       "The Octocat",
				"avatar_url": "https://avatars.example.com/octocat.png",
				"email":      nil,
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	a := NewAdapter()
	a.tokenURL = srv.URL + "/login/oauth/access_token"
	a.userURL = srv.URL + "/user"
	a.userEmailsURL = srv.URL + "/user/emails"

	cfg := &authkit.PlatformConfig{Platform: "github", ClientID: "cid", ClientSecret: "secret", RedirectURI: "https://login.example.com/cb"}

	tok, err := a.ExchangeToken(context.Background(), "AUTHCODE", cfg)
	if err != nil {
		t.Fatalf("ExchangeToken: %v", err)
	}
	if tok.AccessToken != "GH_AT" || tok.TokenType != "bearer" || tok.ExpiresIn != 3600 {
		t.Fatalf("unexpected token: %+v", tok)
	}

	user, err := a.FetchUserInfo(context.Background(), tok, cfg)
	if err != nil {
		t.Fatalf("FetchUserInfo: %v", err)
	}
	if user.OpenID != "583231" {
		t.Fatalf("unexpected openid: %q", user.OpenID)
	}
	if user.Nickname != "The Octocat" {
		t.Fatalf("unexpected nickname: %q", user.Nickname)
	}
	// 主邮箱补取应命中 primary+verified 的 octocat@example.com。
	if user.Email != "octocat@example.com" {
		t.Fatalf("expected primary email补取, got %q", user.Email)
	}
}

func TestGitHubExchangeTokenError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"error": "bad_verification_code", "error_description": "code expired"})
	}))
	defer srv.Close()

	a := NewAdapter()
	a.tokenURL = srv.URL
	if _, err := a.ExchangeToken(context.Background(), "bad", &authkit.PlatformConfig{}); err == nil {
		t.Fatal("expected error on github token error")
	}
}

// TestWithEndpoints 验证端点注入：非空覆盖、空串保留默认。
func TestWithEndpoints(t *testing.T) {
	a := NewAdapter(WithEndpoints("https://mock/authorize", "https://mock/token", "", ""))
	if a.authURL != "https://mock/authorize" || a.tokenURL != "https://mock/token" {
		t.Fatalf("endpoints not overridden: %+v", a)
	}
	if a.userURL != defaultUserEP || a.userEmailsURL != defaultUserEmailsEP {
		t.Fatalf("empty endpoint should keep default: %+v", a)
	}
	if got, _ := a.BuildAuthorizationURL("S", &authkit.PlatformConfig{ClientID: "c", RedirectURI: "r"}, nil); !strings.HasPrefix(got, "https://mock/authorize?") {
		t.Fatalf("auth url not using injected endpoint: %s", got)
	}
}

func TestGitHubBuildAuthorizationURL_PKCE(t *testing.T) {
	a := NewAdapter()
	cfg := &authkit.PlatformConfig{ClientID: "cid", RedirectURI: "https://x.example.com/cb", Scopes: []string{"user:email"}}
	ext := map[string]string{
		authkit.ExtraKeyCodeChallenge:       "CHAL",
		authkit.ExtraKeyCodeChallengeMethod: "S256",
	}
	u, err := a.BuildAuthorizationURL("STATE", cfg, ext)
	if err != nil {
		t.Fatalf("BuildAuthorizationURL: %v", err)
	}
	for _, want := range []string{defaultAuthEP, "client_id=cid", "state=STATE", "code_challenge=CHAL", "code_challenge_method=S256"} {
		if !strings.Contains(u, want) {
			t.Fatalf("auth url missing %q: %s", want, u)
		}
	}
}
