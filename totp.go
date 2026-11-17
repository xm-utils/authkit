package authkit

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"fmt"
	"hash"
	"math/big"
	"net/url"
	"strings"
	"time"
)

// TOTPProvider 第二因子验证提供方契约。它抽象的是「验证用户提交的动态口令」这一能力，
// 与建立身份的 PlatformAdapter 正交：TOTP 不产生用户身份，只校验已登录用户是否持有共享密钥。
// 内置实现见 NewTOTPProvider（RFC 6238）；接入企业自建 / 集中式 2FA 校验服务时，
// 实现本接口即可（可基于 HTTP，用 httptest 单测覆盖）。
type TOTPProvider interface {
	// Name 提供方标识（如 "totp"），参与防重放 subject 构造，避免不同提供方互相影响。
	Name() string

	// GenerateSecret 生成一个新的共享密钥（不透明密串，如 base32）。
	GenerateSecret(ctx context.Context) (string, error)

	// ProvisioningURI 由密钥与账号名拼出 otpauth:// 地址，供验证器扫码绑定。
	ProvisioningURI(secret, account string) string

	// Verify 校验一次性口令是否与密钥匹配（实现方内部处理时间窗与时钟偏移容忍）。
	// 返回 true 表示通过；口令错误返回 (false, nil)，仅底层异常返回 error。
	Verify(ctx context.Context, secret, code string) (bool, error)
}

// SecondFactorPolicy 决定某次登录是否需要第二因子。可选注入：
// 未注入时组件采用默认策略「用户已绑定密钥即要求」。
// 典型自定义：仅对管理员 / 异地登录 / 新设备要求二次验证。
// 返回 error 时组件按 fail-closed 处理（视为需要第二因子并中止本次登录）。
type SecondFactorPolicy interface {
	RequireSecondFactor(ctx context.Context, userID, tenantID string) (bool, error)
}

// TOTPConfig 内置 RFC 6238 提供方参数，零值字段取默认。
type TOTPConfig struct {
	Issuer    string        // otpauth issuer，如应用名，默认 "authkit"
	Digits    int           // 口令位数，默认 6
	Period    time.Duration // 时间步长，默认 30s
	Skew      int           // 前后各容忍的窗口数（时钟偏移），默认 1
	Algorithm string        // "SHA1"(默认) / "SHA256" / "SHA512"
}

func (c *TOTPConfig) normalize() {
	if c.Digits <= 0 {
		c.Digits = 6
	}
	if c.Period <= 0 {
		c.Period = 30 * time.Second
	}
	if c.Skew < 0 {
		c.Skew = 1
	}
	switch c.Algorithm {
	case "", "SHA1":
		c.Algorithm = "SHA1"
	case "SHA256", "SHA512":
	default:
		c.Algorithm = "SHA1"
	}
	if c.Issuer == "" {
		c.Issuer = "authkit"
	}
}

// totpProvider 是 TOTPProvider 的内置实现，纯标准库、无网络依赖、无内部状态，可并发共享。
type totpProvider struct {
	cfg     TOTPConfig
	nowFunc func() time.Time // 便于单测注入时间，生产为 nil 时用 time.Now
}

// NewTOTPProvider 构建内置 RFC 6238 TOTP 提供方。
func NewTOTPProvider(cfg TOTPConfig) TOTPProvider {
	cfg.normalize()
	return &totpProvider{cfg: cfg}
}

// Name 返回提供方标识。
func (p *totpProvider) Name() string { return "totp" }

// GenerateSecret 生成 20 字节随机密钥并 base32 编码（RFC 4226 推荐 ≥128bit）。
func (p *totpProvider) GenerateSecret(_ context.Context) (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("totp: generate secret: %w", err)
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b), nil
}

// ProvisioningURI 拼出 otpauth://totp/{issuer}:{account}?secret=...&issuer=...&digits=...&period=...&algorithm=...
func (p *totpProvider) ProvisioningURI(secret, account string) string {
	label := url.PathEscape(p.cfg.Issuer + ":" + account)
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", p.cfg.Issuer)
	q.Set("algorithm", p.cfg.Algorithm)
	q.Set("digits", fmt.Sprintf("%d", p.cfg.Digits))
	q.Set("period", fmt.Sprintf("%d", int64(p.cfg.Period.Seconds())))
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// Verify 在当前时间步及 ±Skew 窗口内寻找与 code 匹配的 HOTP 值。
func (p *totpProvider) Verify(_ context.Context, secret, code string) (bool, error) {
	key, err := decodeSecret(secret)
	if err != nil {
		return false, err
	}
	if code == "" {
		return false, nil
	}
	hasher, err := p.hasher()
	if err != nil {
		return false, err
	}
	counter := int64(p.now().Unix() / int64(p.cfg.Period.Seconds()))
	for i := -p.cfg.Skew; i <= p.cfg.Skew; i++ {
		if hotp(key, counter+int64(i), p.cfg.Digits, hasher) == code {
			return true, nil
		}
	}
	return false, nil
}

func (p *totpProvider) now() time.Time {
	if p.nowFunc != nil {
		return p.nowFunc()
	}
	return time.Now()
}

func (p *totpProvider) hasher() (func() hash.Hash, error) {
	switch p.cfg.Algorithm {
	case "SHA1":
		return sha1.New, nil
	case "SHA256":
		return sha256.New, nil
	case "SHA512":
		return sha512.New, nil
	default:
		return nil, fmt.Errorf("totp: unsupported algorithm %q", p.cfg.Algorithm)
	}
}

// decodeSecret 归一化并 base32 解码密钥：去空格、补 padding、大小写不敏感。
func decodeSecret(secret string) ([]byte, error) {
	s := strings.ToUpper(strings.Join(strings.Fields(secret), ""))
	s = strings.TrimRight(s, "=")
	if s == "" {
		return nil, fmt.Errorf("totp: empty secret")
	}
	if pad := len(s) % 8; pad != 0 {
		s += strings.Repeat("=", 8-pad)
	}
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.TrimRight(s, "="))
	if err != nil {
		return nil, fmt.Errorf("totp: decode secret: %w", err)
	}
	if len(key) == 0 {
		return nil, fmt.Errorf("totp: empty secret key")
	}
	return key, nil
}

// hotp 按 RFC 4226 动态截断计算定长口令。
func hotp(key []byte, counter int64, digits int, hasher func() hash.Hash) string {
	buf := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		buf[i] = byte(counter & 0xff)
		counter >>= 8
	}
	m := hmac.New(hasher, key)
	m.Write(buf)
	sum := m.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	binary := (uint32(sum[offset]&0x7f) << 24) |
		(uint32(sum[offset+1]) << 16) |
		(uint32(sum[offset+2]) << 8) |
		uint32(sum[offset+3])
	mod := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(digits)), nil)
	val := new(big.Int).Mod(big.NewInt(int64(binary)), mod)
	return fmt.Sprintf("%0"+fmt.Sprint(digits)+"d", val)
}
