// Package alipay 提供支付宝第三方网站登录适配器（OpenAPI 授权令牌 + 用户信息接口）。
// ClientID=AppID，ClientSecret 不使用；签名私钥通过 Extra 配置：
//
//	PrivateKey       应用私钥（RSA2/PKCS1 或 PKCS8，PEM 或纯 Base64），必填
//	AlipayPublicKey  支付宝公钥（PEM 或纯 Base64），配置后对响应做验签，可选
//	AppCertSN        证书模式可选，放入 app_cert_sn 参数
//	PublicKeySN      证书模式可选，放入 public_key_sn 参数
package alipay

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/xm-utils/authkit"
)

// 平台默认接口地址，可通过 NewAdapter 的 WithEndpoints 选项覆盖（指向 httptest 服务等）。
const (
	defaultAuthEndpoint = "https://openauth.alipay.com/oauth2/publicAppAuthorize.htm"
	defaultGatewayURL   = "https://openapi.alipay.com/gateway.do"
)

// Option 适配器构建选项。
type Option func(*Adapter)

// WithEndpoints 覆盖平台接口地址，空字符串保留默认值。
// 单元测试与离线示例可指向 httptest 服务，生产环境无需使用。
func WithEndpoints(authURL, gatewayURL string) Option {
	return func(a *Adapter) {
		if authURL != "" {
			a.authURL = authURL
		}
		if gatewayURL != "" {
			a.gatewayURL = gatewayURL
		}
	}
}

// Adapter 支付宝适配器。HTTP 出口统一走弹性客户端单例。
type Adapter struct {
	authURL    string
	gatewayURL string
}

// NewAdapter 构建适配器，端点默认指向支付宝官方地址，可用 WithEndpoints 覆盖。
func NewAdapter(opts ...Option) *Adapter {
	a := &Adapter{authURL: defaultAuthEndpoint, gatewayURL: defaultGatewayURL}
	for _, opt := range opts {
		opt(a)
	}
	return a
}

// PlatformName 返回平台标识。
func (a *Adapter) PlatformName() string { return "alipay" }

// BuildAuthorizationURL 拼接支付宝授权地址。scope 默认 auth_user。
func (a *Adapter) BuildAuthorizationURL(state string, cfg *authkit.PlatformConfig, _ map[string]string) (string, error) {
	scope := strings.Join(cfg.Scopes, ",")
	if scope == "" {
		scope = "auth_user"
	}
	q := url.Values{}
	q.Set("app_id", cfg.ClientID)
	q.Set("scope", scope)
	q.Set("redirect_uri", cfg.RedirectURI)
	q.Set("state", state)
	return a.authURL + "?" + q.Encode(), nil
}

// ExchangeToken 用授权码换取访问令牌（alipay.system.oauth.token，grant_type=authorization_code）。
func (a *Adapter) ExchangeToken(ctx context.Context, code string, cfg *authkit.PlatformConfig) (*authkit.TokenResult, error) {
	return a.oauthToken(ctx, cfg, url.Values{"code": {code}}, "authorization_code")
}

// RefreshToken 用刷新令牌换取新令牌，实现 authkit.TokenRefresher。
func (a *Adapter) RefreshToken(ctx context.Context, refreshToken string, cfg *authkit.PlatformConfig) (*authkit.TokenResult, error) {
	return a.oauthToken(ctx, cfg, url.Values{"refresh_token": {refreshToken}}, "refresh_token")
}

func (a *Adapter) oauthToken(ctx context.Context, cfg *authkit.PlatformConfig, biz url.Values, grantType string) (*authkit.TokenResult, error) {
	biz.Set("grant_type", grantType)
	resp, err := a.call(ctx, cfg, "alipay.system.oauth.token", biz, "")
	if err != nil {
		return nil, err
	}
	if e := respError(resp); e != "" {
		return nil, fmt.Errorf("alipay exchange token: %s", e)
	}
	return &authkit.TokenResult{
		AccessToken:  authkit.Str(resp, "access_token"),
		RefreshToken: authkit.Str(resp, "refresh_token"),
		ExpiresIn:    alipayExpiresIn(resp),
		TokenType:    "Bearer",
		Raw:          resp,
	}, nil
}

// FetchUserInfo 拉取支付宝用户信息（alipay.user.info.share，需用户已授权 auth_user）。
func (a *Adapter) FetchUserInfo(ctx context.Context, token *authkit.TokenResult, cfg *authkit.PlatformConfig) (*authkit.ThirdPartyUser, error) {
	resp, err := a.call(ctx, cfg, "alipay.user.info.share", nil, token.AccessToken)
	if err != nil {
		return nil, err
	}
	if e := respError(resp); e != "" {
		return nil, fmt.Errorf("alipay fetch user: %s", e)
	}
	return &authkit.ThirdPartyUser{
		Platform:  a.PlatformName(),
		OpenID:    firstNonEmpty(authkit.Str(resp, "open_id"), authkit.Str(resp, "user_id")),
		UnionID:   authkit.Str(resp, "union_id"),
		Nickname:  authkit.Str(resp, "nick_name"),
		AvatarURL: authkit.Str(resp, "avatar"),
		Mobile:    authkit.Str(resp, "mobile"),
		Raw:       resp,
	}, nil
}

// call 组装公共参数、RSA2 签名并发起网关 GET 请求，返回解析后的业务响应节点。
// authToken 非空时附带 alipay_auth_token 参数。
func (a *Adapter) call(ctx context.Context, cfg *authkit.PlatformConfig, method string, bizParams url.Values, authToken string) (map[string]any, error) {
	privateKey, err := parsePrivateKey(cfg.GetExtra("PrivateKey", ""))
	if err != nil {
		return nil, fmt.Errorf("alipay: %w", err)
	}

	params := url.Values{}
	params.Set("app_id", cfg.ClientID)
	params.Set("method", method)
	params.Set("format", "JSON")
	params.Set("charset", "utf-8")
	params.Set("sign_type", "RSA2")
	params.Set("timestamp", time.Now().Format("2006-01-02 15:04:05"))
	params.Set("version", "1.0")
	params.Set("nonce", nonce())
	if sn := cfg.GetExtra("AppCertSN", ""); sn != "" {
		params.Set("app_cert_sn", sn)
	}
	if sn := cfg.GetExtra("PublicKeySN", ""); sn != "" {
		params.Set("public_key_sn", sn)
	}
	if authToken != "" {
		params.Set("alipay_auth_token", authToken)
	}
	for k, vs := range bizParams {
		for _, v := range vs {
			params.Add(k, v)
		}
	}

	signStr := encodeParams(params)
	signature, err := rsa256Sign(privateKey, signStr)
	if err != nil {
		return nil, fmt.Errorf("alipay: sign: %w", err)
	}
	params.Set("sign", signature)

	resp, err := authkit.DoJSON(ctx, a.PlatformName(), http.MethodGet, a.gatewayURL+"?"+params.Encode(), nil, nil)
	if err != nil {
		return nil, err
	}

	// 响应形如 {"alipay_system_oauth_token_response":{...},"error_response":{...}}，
	// 目标节点 key 为完整方法名点号转下划线加 _response 后缀。
	resultKey := strings.ReplaceAll(method, ".", "_") + "_response"
	if pubKey := cfg.GetExtra("AlipayPublicKey", ""); pubKey != "" {
		if err := verifyResponse(resp[resultKey], authkit.Str(resp, "sign"), authkit.Str(resp, "sign_type"), pubKey); err != nil {
			return nil, fmt.Errorf("alipay: %w", err)
		}
	}
	if node, ok := resp[resultKey].(map[string]any); ok {
		return node, nil
	}
	return resp, nil // 无目标节点时（如 error_response 场景）交给我方 respError 判错。
}

// encodeParams 按 key 升序拼接 k=v&k=v，作为待签名串（不含 sign）。
func encodeParams(params url.Values) string {
	keys := make([]string, 0, len(params))
	for k := range params {
		if k == "sign" {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	pairs := make([]string, 0, len(keys))
	for _, k := range keys {
		pairs = append(pairs, k+"="+params.Get(k))
	}
	return strings.Join(pairs, "&")
}

// rsa256Sign SHA256withRSA 签名并 Base64 编码。
func rsa256Sign(key *rsa.PrivateKey, content string) (string, error) {
	digest := sha256.Sum256([]byte(content))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}

// rsa256Verify 校验 SHA256withRSA 签名。
func rsa256Verify(pub *rsa.PublicKey, content, sigB64 string) error {
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return fmt.Errorf("verify: decode signature: %w", err)
	}
	digest := sha256.Sum256([]byte(content))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
		return fmt.Errorf("verify: invalid response signature: %w", err)
	}
	return nil
}

// verifyResponse 对业务响应节点做验签：节点 JSON 去掉 sign/sign_type 后按 key 升序拼接。
// 节点或公钥异常时返回错误（fail-closed），公钥未配置时不调用本函数。
func verifyResponse(node any, sign, signType, publicKeyPEM string) error {
	if sign == "" {
		return fmt.Errorf("verify: response signature missing while AlipayPublicKey configured")
	}
	if signType != "" && signType != "RSA2" {
		return fmt.Errorf("verify: unsupported sign_type %q", signType)
	}
	obj, ok := node.(map[string]any)
	if !ok {
		return nil // 网关级错误（error_response）无验签语义，交由 respError 判错。
	}
	pub, err := parsePublicKey(publicKeyPEM)
	if err != nil {
		return fmt.Errorf("verify: %w", err)
	}
	clean := make(map[string]any, len(obj))
	for k, v := range obj {
		if k == "sign" || k == "sign_type" {
			continue
		}
		clean[k] = v
	}
	fields, err := json.Marshal(clean)
	if err != nil {
		return fmt.Errorf("verify: marshal: %w", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(fields, &m); err != nil {
		return fmt.Errorf("verify: unmarshal: %w", err)
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	pairs := make([]string, 0, len(keys))
	for _, k := range keys {
		if v, ok := rawValue(m[k]); ok {
			pairs = append(pairs, k+"="+v)
		}
	}
	return rsa256Verify(pub, strings.Join(pairs, "&"), sign)
}

// rawValue 将响应字段的 JSON 原文解码为待签串表示：字符串取原文（去引号），
// 数值/布尔取文本形式，null 字段按支付宝规范不参与签名（返回 ok=false）。
func rawValue(raw json.RawMessage) (string, bool) {
	s := string(raw)
	if len(s) >= 2 && s[0] == '"' {
		var v string
		if err := json.Unmarshal(raw, &v); err == nil {
			return v, true
		}
		return s, true
	}
	if s == "null" {
		return "", false
	}
	return s, true
}

// respError 读取支付宝业务错误节点 error_response 或响应内的 code/sub_msg。
func respError(m map[string]any) string {
	if m == nil {
		return ""
	}
	if errNode, ok := m["error_response"].(map[string]any); ok {
		return fmt.Sprintf("code=%s msg=%s sub_msg=%s",
			authkit.Str(errNode, "code"), authkit.Str(errNode, "msg"), authkit.Str(errNode, "sub_msg"))
	}
	if code := authkit.Str(m, "code"); code != "" && code != "10000" {
		return fmt.Sprintf("code=%s msg=%s sub_msg=%s", code, authkit.Str(m, "msg"), authkit.Str(m, "sub_msg"))
	}
	return ""
}

// alipayExpiresIn 读取过期秒数，兼容数值与字符串两种返回。
func alipayExpiresIn(m map[string]any) int64 {
	if v := authkit.Num(m, "expires_in"); v != 0 {
		return v
	}
	if s := authkit.Str(m, "expires_in"); s != "" {
		var n int64
		if _, err := fmt.Sscanf(s, "%d", &n); err == nil {
			return n
		}
	}
	return 0
}

// parsePrivateKey 解析应用私钥：支持 PEM（PKCS1/PKCS8）与裸 Base64 PKCS1。
func parsePrivateKey(s string) (*rsa.PrivateKey, error) {
	if s == "" {
		return nil, fmt.Errorf("Extra.PrivateKey is required")
	}
	if key, err := x509.ParsePKCS1PrivateKey(derBytes(s)); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(derBytes(s)); err == nil {
		if rsaKey, ok := key.(*rsa.PrivateKey); ok {
			return rsaKey, nil
		}
		return nil, fmt.Errorf("private key is not RSA")
	}
	return nil, fmt.Errorf("invalid private key: not a PKCS1/PKCS8 RSA key")
}

// parsePublicKey 解析支付宝公钥：支持 PEM 与裸 Base64 PKIX。
func parsePublicKey(s string) (*rsa.PublicKey, error) {
	der := derBytes(s)
	if key, err := x509.ParsePKIXPublicKey(der); err == nil {
		if rsaKey, ok := key.(*rsa.PublicKey); ok {
			return rsaKey, nil
		}
		return nil, fmt.Errorf("public key is not RSA")
	}
	if key, err := x509.ParsePKCS1PublicKey(der); err == nil {
		return key, nil
	}
	return nil, fmt.Errorf("invalid public key")
}

// derBytes 将 PEM 或裸 Base64 内容统一解码为 DER 字节。
func derBytes(s string) []byte {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "-----BEGIN") {
		if block, _ := pem.Decode([]byte(s)); block != nil {
			return block.Bytes
		}
	}
	if raw, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(s), "")); err == nil {
		return raw
	}
	return nil
}

// nonce 生成一次性随机串，用于防重放。
func nonce() string {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return n.Text(36)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
