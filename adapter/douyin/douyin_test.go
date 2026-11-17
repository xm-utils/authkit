package douyin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/xm-utils/authkit"
)

func TestBuildAuthorizationURL(t *testing.T) {
	a := &Adapter{authURL: defaultAuthEndpoint}
	cfg := &authkit.PlatformConfig{ClientID: "CLIENT_KEY", RedirectURI: "https://example.com/cb"}
	got, err := a.BuildAuthorizationURL("STATE9", cfg, nil)
	if err != nil {
		t.Fatalf("BuildAuthorizationURL: %v", err)
	}
	for _, want := range []string{"client_key=CLIENT_KEY", "scope=user_info", "state=STATE9", "redirect_uri="} {
		if !strings.Contains(got, want) {
			t.Errorf("auth url %q missing %q", got, want)
		}
	}
}

func TestWithEndpoints(t *testing.T) {
	// 空字符串保留默认，非空覆盖。
	a := NewAdapter(WithEndpoints("", "https://mock.local/token", "https://mock.local/userinfo"))
	if a.authURL != defaultAuthEndpoint || a.tokenURL != "https://mock.local/token" || a.userURL != "https://mock.local/userinfo" {
		t.Errorf("unexpected endpoints: %+v", a)
	}
}

func TestDouyinFullFlow(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/access_token") {
			q := r.URL.Query()
			if q.Get("client_key") != "DK" || q.Get("code") != "AUTHCODE" || q.Get("grant_type") != "authorization_code" {
				t.Errorf("unexpected token params: %+v", q)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{
					"access_token":  "DY_AT",
					"refresh_token": "DY_RT",
					"expires_in":    86400,
					"open_id":       "DY_OPEN",
					"scope":         "user_info",
				},
				"error_code":  json.Number("0"),
				"description": "",
			})
			return
		}
		// 用户信息接口
		if r.URL.Query().Get("access_token") != "DY_AT" {
			t.Errorf("missing access_token: %q", r.URL.Query().Get("access_token"))
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"open_id":  "DY_OPEN",
				"nickname": "抖音用户",
				"avatar":   "https://avatar.example.com/d.jpg",
			},
			"error_code": float64(0),
		})
	}))
	defer srv.Close()

	a := &Adapter{authURL: srv.URL + "/connect", tokenURL: srv.URL + "/access_token", userURL: srv.URL + "/userinfo"}
	cfg := &authkit.PlatformConfig{ClientID: "DK", ClientSecret: "DS"}

	token, err := a.ExchangeToken(context.Background(), "AUTHCODE", cfg)
	if err != nil {
		t.Fatalf("ExchangeToken: %v", err)
	}
	if token.AccessToken != "DY_AT" || token.RefreshToken != "DY_RT" || token.ExpiresIn != 86400 {
		t.Errorf("unexpected token: %+v", token)
	}

	user, err := a.FetchUserInfo(context.Background(), token, cfg)
	if err != nil {
		t.Fatalf("FetchUserInfo: %v", err)
	}
	if user.OpenID != "DY_OPEN" || user.Nickname != "抖音用户" || user.AvatarURL != "https://avatar.example.com/d.jpg" {
		t.Errorf("unexpected user: %+v", user)
	}
}

func TestDouyinTokenError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error_code":  2100005, // 数值型错误码
			"description": "invalid code",
		})
	}))
	defer srv.Close()

	a := &Adapter{tokenURL: srv.URL + "/access_token", userURL: srv.URL + "/userinfo"}
	_, err := a.ExchangeToken(context.Background(), "BAD", &authkit.PlatformConfig{ClientID: "DK", ClientSecret: "DS"})
	if err == nil {
		t.Fatal("expected error for non-zero error_code")
	}
	if !strings.Contains(err.Error(), "2100005") {
		t.Errorf("error should contain code, got: %v", err)
	}
}

func TestDouyinUserError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error_code":  "2100002", // 字符串型错误码
			"description": "invalid access_token",
		})
	}))
	defer srv.Close()

	a := &Adapter{tokenURL: srv.URL + "/access_token", userURL: srv.URL + "/userinfo"}
	_, err := a.FetchUserInfo(context.Background(), &authkit.TokenResult{AccessToken: "BAD"}, nil)
	if err == nil {
		t.Fatal("expected error for user info failure")
	}
}
