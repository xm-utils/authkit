package authkit

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"strings"
)

// generateState 生成 32 字节加密随机串（hex 编码，64 字符），用于防 CSRF。
func generateState() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand 在正常系统上不会失败；极端情况用其错误信息派生，保证不 panic。
		return hex.EncodeToString(sha256New([]byte(err.Error())))[:64]
	}
	return hex.EncodeToString(b)
}

// generateCodeVerifier 生成 PKCE code_verifier（RFC 7636，43 字符 base64url）。
func generateCodeVerifier() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// codeChallenge 由 verifier 派生 S256 code_challenge。
func codeChallenge(verifier string) string {
	return base64.RawURLEncoding.EncodeToString(sha256New([]byte(verifier)))
}

// sha256New 计算 SHA-256 摘要。
func sha256New(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}

// checkCallbackWhitelist 校验回调地址是否命中白名单，防开放重定向。
// 白名单为空时拒绝任何回调地址。
func checkCallbackWhitelist(rawURI string, hosts []string) error {
	if rawURI == "" || len(hosts) == 0 {
		return ErrCallbackNotAllowed
	}
	u, err := url.Parse(rawURI)
	if err != nil {
		return ErrCallbackNotAllowed
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return ErrCallbackNotAllowed
	}
	for _, allowed := range hosts {
		a := strings.ToLower(strings.TrimSpace(allowed))
		if a == "" {
			continue
		}
		if strings.HasPrefix(a, ".") {
			// 后缀匹配：".example.com" 命中 "login.example.com" 与 "example.com"。
			domain := a[1:]
			if host == domain || strings.HasSuffix(host, "."+domain) {
				return nil
			}
			continue
		}
		if host == a {
			return nil
		}
	}
	return ErrCallbackNotAllowed
}

// MaskSecret 掩码密钥类字段，仅保留前 2 后 2 字符。
func MaskSecret(s string) string {
	if s == "" {
		return ""
	}
	if len(s) <= 4 {
		return "****"
	}
	return s[:2] + "****" + s[len(s)-2:]
}

// MaskMobile 掩码手机号，保留前 3 后 4。
func MaskMobile(s string) string {
	if len(s) < 7 {
		return "****"
	}
	return s[:3] + "****" + s[len(s)-4:]
}

// MaskEmail 掩码邮箱，保留用户名首字符与完整域名。
func MaskEmail(s string) string {
	at := strings.IndexByte(s, '@')
	if at <= 0 {
		return "****"
	}
	name := s[:at]
	domain := s[at:]
	if len(name) <= 1 {
		return "*" + domain
	}
	return name[:1] + "****" + domain
}

// copyExt 复制 map，避免修改调用方传入的原始数据。
func copyExt(src map[string]string) map[string]string {
	dst := make(map[string]string, len(src)+3)
	for k, v := range src {
		dst[k] = v
	}
	return dst
}
