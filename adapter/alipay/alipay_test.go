package alipay

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/xm-utils/authkit"
)

// genKey 生成测试用 RSA 密钥对，私钥以 PKCS1 DER 返回。
func genKey(t *testing.T) (*rsa.PrivateKey, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	return key, x509.MarshalPKCS1PrivateKey(key)
}

func baseCfg(keyDER []byte) *authkit.PlatformConfig {
	return &authkit.PlatformConfig{
		Platform:    "alipay",
		ClientID:    "2021000000000000",
		RedirectURI: "https://example.com/callback",
		Extra:       map[string]string{"PrivateKey": base64.StdEncoding.EncodeToString(keyDER)},
	}
}

// withAdapter 指向 httptest 网关。
func withAdapter(url string) *Adapter {
	return &Adapter{authURL: url + "/authorize", gatewayURL: url + "/gateway.do"}
}

func TestBuildAuthorizationURL(t *testing.T) {
	a := withAdapter("https://invalid.invalid")
	cfg := baseCfg([]byte("unused"))
	got, err := a.BuildAuthorizationURL("STATE123", cfg, nil)
	if err != nil {
		t.Fatalf("BuildAuthorizationURL: %v", err)
	}
	for _, want := range []string{"app_id=2021000000000000", "scope=auth_user", "state=STATE123", "redirect_uri="} {
		if !strings.Contains(got, want) {
			t.Errorf("auth url %q missing %q", got, want)
		}
	}
}

func TestWithEndpoints(t *testing.T) {
	// 空字符串保留默认，非空覆盖。
	a := NewAdapter(WithEndpoints("https://mock.local/authorize", ""))
	if a.authURL != "https://mock.local/authorize" || a.gatewayURL != defaultGatewayURL {
		t.Errorf("unexpected endpoints: %+v", a)
	}
}

func TestAlipayExchangeTokenAndFetchUser(t *testing.T) {
	_, keyDER := genKey(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("sign") == "" || q.Get("sign_type") != "RSA2" || q.Get("nonce") == "" {
			t.Errorf("missing sign params: sign=%q sign_type=%q", q.Get("sign"), q.Get("sign_type"))
		}
		w.Header().Set("Content-Type", "application/json")
		switch q.Get("method") {
		case "alipay.system.oauth.token":
			if q.Get("grant_type") != "authorization_code" || q.Get("code") != "AUTHCODE" {
				t.Errorf("unexpected token params: %+v", q)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"alipay_system_oauth_token_response": map[string]any{
					"access_token":  "ALIPAY_AT",
					"refresh_token": "ALIPAY_RT",
					"expires_in":    1234,
					"open_id":       "OPEN_1",
					"union_id":      "UNION_1",
				},
			})
		case "alipay.user.info.share":
			if q.Get("alipay_auth_token") != "ALIPAY_AT" {
				t.Errorf("missing alipay_auth_token, got %q", q.Get("alipay_auth_token"))
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"alipay_user_info_share_response": map[string]any{
					"code":      "10000",
					"open_id":   "OPEN_1",
					"union_id":  "UNION_1",
					"nick_name": "支付宝用户",
					"avatar":    "https://avatar.example.com/a.jpg",
					"mobile":    "13800000000",
				},
			})
		default:
			t.Errorf("unexpected method %q", q.Get("method"))
		}
	}))
	defer srv.Close()

	a := withAdapter(srv.URL)
	cfg := baseCfg(keyDER)

	token, err := a.ExchangeToken(context.Background(), "AUTHCODE", cfg)
	if err != nil {
		t.Fatalf("ExchangeToken: %v", err)
	}
	if token.AccessToken != "ALIPAY_AT" || token.RefreshToken != "ALIPAY_RT" || token.ExpiresIn != 1234 {
		t.Errorf("unexpected token: %+v", token)
	}
	if authkit.Str(token.Raw, "open_id") != "OPEN_1" {
		t.Errorf("token.Raw missing open_id: %+v", token.Raw)
	}

	user, err := a.FetchUserInfo(context.Background(), token, cfg)
	if err != nil {
		t.Fatalf("FetchUserInfo: %v", err)
	}
	if user.OpenID != "OPEN_1" || user.UnionID != "UNION_1" || user.Nickname != "支付宝用户" {
		t.Errorf("unexpected user: %+v", user)
	}
	if user.BindKey() != "UNION_1" {
		t.Errorf("BindKey should prefer union_id, got %q", user.BindKey())
	}
}

func TestAlipayRefreshToken(t *testing.T) {
	_, keyDER := genKey(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("grant_type") != "refresh_token" || q.Get("refresh_token") != "OLD_RT" {
			t.Errorf("unexpected refresh params: %+v", q)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"alipay_system_oauth_token_response": map[string]any{
				"access_token": "NEW_AT", "expires_in": "3600", // 兼容字符串数字
			},
		})
	}))
	defer srv.Close()

	a := withAdapter(srv.URL)
	token, err := a.RefreshToken(context.Background(), "OLD_RT", baseCfg(keyDER))
	if err != nil {
		t.Fatalf("RefreshToken: %v", err)
	}
	if token.AccessToken != "NEW_AT" || token.ExpiresIn != 3600 {
		t.Errorf("unexpected refreshed token: %+v", token)
	}
}

func TestAlipayErrorResponse(t *testing.T) {
	_, keyDER := genKey(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error_response": map[string]any{
				"code": "40002", "msg": "Invalid Arguments", "sub_msg": "缺少必选参数",
			},
		})
	}))
	defer srv.Close()

	if _, err := withAdapter(srv.URL).ExchangeToken(context.Background(), "X", baseCfg(keyDER)); err == nil {
		t.Fatal("expected error for error_response")
	} else if !strings.Contains(err.Error(), "40002") {
		t.Errorf("error should contain code, got: %v", err)
	}
}

func TestAlipayMissingPrivateKey(t *testing.T) {
	cfg := &authkit.PlatformConfig{Platform: "alipay", ClientID: "APP"}
	if _, err := withAdapter("https://invalid.invalid").ExchangeToken(context.Background(), "X", cfg); err == nil {
		t.Fatal("expected error for missing PrivateKey")
	}
}

// TestAlipayResponseVerify 覆盖响应验签：正确签名通过、篡改签名拒绝。
func TestAlipayResponseVerify(t *testing.T) {
	key, keyDER := genKey(t)
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}

	// 按适配器约定构造待签串：业务节点字段（string 值）按 key 升序 k=v& 拼接。
	biz := map[string]string{"code": "10000", "open_id": "OPEN_1", "nick_name": "已签名用户"}
	signStr := sortedJoin(biz)
	digest := sha256.Sum256([]byte(signStr))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var sign string
		switch r.URL.Query().Get("method") {
		case "alipay.user.info.share": // 正确签名
			sig, err := rsa.SignPKCS1v15(rand.Reader, key, 5 /* crypto.SHA256 */, digest[:])
			if err != nil {
				t.Fatalf("sign: %v", err)
			}
			sign = base64.StdEncoding.EncodeToString(sig)
		default: // 令牌接口给错误签名，模拟篡改
			sign = base64.StdEncoding.EncodeToString([]byte("bogus"))
		}
		w.Header().Set("Content-Type", "application/json")
		// 关闭 HTML 转义，保证字段原文与待签串一致（与支付宝真实网关行为一致）。
		enc := json.NewEncoder(w)
		enc.SetEscapeHTML(false)
		_ = enc.Encode(map[string]any{
			"alipay_user_info_share_response": map[string]any{
				"code": biz["code"], "open_id": biz["open_id"], "nick_name": biz["nick_name"],
			},
			"alipay_system_oauth_token_response": map[string]any{
				"code": biz["code"], "open_id": biz["open_id"], "nick_name": biz["nick_name"],
			},
			"sign": sign,
		})
	}))
	defer srv.Close()

	cfg := baseCfg(keyDER)
	cfg.Extra["AlipayPublicKey"] = base64.StdEncoding.EncodeToString(pubDER)

	a := withAdapter(srv.URL)
	if _, err := a.ExchangeToken(context.Background(), "AUTHCODE", cfg); err == nil {
		t.Fatal("expected verify failure for bogus signature")
	}

	user, err := a.FetchUserInfo(context.Background(), &authkit.TokenResult{AccessToken: "ALIPAY_AT"}, cfg)
	if err != nil {
		t.Fatalf("FetchUserInfo with valid signature: %v", err)
	}
	if user.Nickname != "已签名用户" {
		t.Errorf("unexpected user: %+v", user)
	}
}

func sortedJoin(m map[string]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	// 小规模直接插入排序，避免额外导入 sort。
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j] < keys[j-1]; j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
	pairs := make([]string, 0, len(keys))
	for _, k := range keys {
		pairs = append(pairs, k+"="+m[k])
	}
	return strings.Join(pairs, "&")
}
