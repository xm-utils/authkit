package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
)

// mock_platform.go 用 httptest 在本地模拟支付宝 OpenAPI 网关、抖音开放平台与 GitHub OAuth 的接口行为，
// 让 example 完全离线运行，同时演示「真实适配器 + WithEndpoints 注入」的装配方式。
// 生产接入时删除本文件、使用 NewAdapter() 默认官方端点即可。

// startMockPlatform 启动覆盖两个平台路径的 mock 服务，返回服务与「支付宝公钥」（Base64 PKIX），
// 后者配到 Extra.AlipayPublicKey 即可演示响应验签。
// 支付宝按 method 参数分流，抖音按 URL 路径分流。
func startMockPlatform() (*httptest.Server, string) {
	// 演示响应验签：mock 侧持有「支付宝密钥对」，客户端配置对应公钥。
	alipayKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic("example: generate mock alipay key: " + err.Error())
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&alipayKey.PublicKey)
	if err != nil {
		panic("example: marshal mock public key: " + err.Error())
	}
	alipayPubB64 := base64.StdEncoding.EncodeToString(pubDER)

	mux := http.NewServeMux()

	// ---- 支付宝 OpenAPI 网关（GET /gateway.do，按 method 参数分流）----
	mux.HandleFunc("/gateway.do", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("sign_type") != "RSA2" || q.Get("sign") == "" {
			writeJSON(w, map[string]any{
				"error_response": map[string]any{"code": "40002", "msg": "Invalid Arguments", "sub_msg": "缺少签名"},
			})
			return
		}
		var biz map[string]any
		switch q.Get("method") {
		case "alipay.system.oauth.token":
			biz = map[string]any{
				"code": "10000", "open_id": "alipay-open-9001", "union_id": "alipay-union-9001",
				// 演示验签：节点字段统一用字符串，与待签串原文一一对应。
				"access_token": "mock-alipay-at", "refresh_token": "mock-alipay-rt", "expires_in": "3600",
			}
		case "alipay.user.info.share":
			biz = map[string]any{
				"code": "10000", "open_id": "alipay-open-9001", "union_id": "alipay-union-9001",
				"nick_name": "支付宝演示用户", "avatar": "https://mock.example.com/alipay-avatar.png",
			}
		default:
			writeJSON(w, map[string]any{
				"error_response": map[string]any{"code": "40002", "msg": "Invalid Arguments", "sub_msg": "未知方法 " + q.Get("method")},
			})
			return
		}
		resultKey := strings.ReplaceAll(q.Get("method"), ".", "_") + "_response"
		sign := alipayMockSign(alipayKey, biz)
		writeJSONEscapeOff(w, map[string]any{resultKey: biz, "sign": sign, "sign_type": "RSA2"})
	})

	// ---- 抖音开放平台（按路径分流，响应统一 data 包裹）----
	mockDouyin := func(biz map[string]any) func(http.ResponseWriter, *http.Request) {
		return func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, map[string]any{"data": biz, "error_code": 0, "description": ""})
		}
	}
	mux.HandleFunc("/oauth/access_token", mockDouyin(map[string]any{
		"access_token": "mock-dy-at", "refresh_token": "mock-dy-rt",
		"expires_in": 86400, "open_id": "douyin-open-8001", "scope": "user_info",
	}))
	mux.HandleFunc("/oauth/userinfo", mockDouyin(map[string]any{
		"open_id": "douyin-open-8001", "nickname": "抖音演示用户",
		"avatar": "https://mock.example.com/douyin-avatar.png",
	}))

	return httptest.NewServer(mux), alipayPubB64
}

// startMockGitHub 启动模拟 GitHub OAuth 的 httptest 服务（离线演示用）：
// 令牌接口按表单 code 校验，用户接口返回隐私账号（email 为空）以触发 /user/emails 主邮箱补取。
func startMockGitHub() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/login/oauth/access_token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		w.Header().Set("Content-Type", "application/json")
		if r.Form.Get("code") == "" {
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "bad_verification_code"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "mock-gh-at", "token_type": "bearer",
			"scope": "user:email", "expires_in": 3600,
		})
	})
	mux.HandleFunc("/user/emails", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, []map[string]any{
			{"email": "backup@example.com", "verified": true, "primary": false},
			{"email": "octocat@example.com", "verified": true, "primary": true},
		})
	})
	mux.HandleFunc("/user", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{
			"id": 583231, "login": "octocat", "name": "The Octocat",
			"avatar_url": "https://mock.example.com/octocat.png", "email": nil,
		})
	})
	return httptest.NewServer(mux)
}

// newMockAlipayKeyPair 成对生成演示用应用私钥/公钥（均为 Base64 DER）：
// 私钥配到 Extra.PrivateKey 供请求签名，公钥配到 Extra.AlipayPublicKey 供响应验签。
func newMockAlipayKeyPair() (privB64, pubB64 string) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic("example: generate mock alipay key pair: " + err.Error())
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		panic("example: marshal public key: " + err.Error())
	}
	return base64.StdEncoding.EncodeToString(x509.MarshalPKCS1PrivateKey(key)),
		base64.StdEncoding.EncodeToString(pubDER)
}

// alipayMockSign 按支付宝规范对业务节点签名：字段按 key 升序 k=v& 拼接（字符串取原文、null 剔除），
// SHA256withRSA 后 Base64。与 adapter/alipay 的验签实现互为镜像。
func alipayMockSign(key *rsa.PrivateKey, node map[string]any) string {
	keys := make([]string, 0, len(node))
	for k := range node {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	pairs := make([]string, 0, len(keys))
	for _, k := range keys {
		switch v := node[k].(type) {
		case nil:
			continue
		case string:
			pairs = append(pairs, k+"="+v)
		default:
			raw, _ := json.Marshal(v)
			pairs = append(pairs, k+"="+string(raw))
		}
	}
	digest := sha256.Sum256([]byte(strings.Join(pairs, "&")))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		panic("example: sign mock response: " + err.Error())
	}
	return base64.StdEncoding.EncodeToString(sig)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// writeJSONEscapeOff 关闭 HTML 转义，保证中文字段原文与待签串一致（与支付宝真实网关行为一致）。
func writeJSONEscapeOff(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}
