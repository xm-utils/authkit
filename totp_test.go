//go:build test

package authkit

import (
	"context"
	"crypto/sha1"
	"strings"
	"testing"
	"time"
)

// rfc6238Secret 是 RFC 6238 附录 B 的标准测试密钥（ASCII "12345678901234567890"）的 base32。
const rfc6238Secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

// TestTOTP_RFC6238Vectors 用 RFC 6238 附录 B（SHA1、8 位、30s）标准向量校验内置实现正确性。
func TestTOTP_RFC6238Vectors(t *testing.T) {
	vectors := []struct {
		timeUnix int64
		want     string
	}{
		{59, "94287082"},
		{1111111109, "07081804"},
		{1111111111, "14050471"},
		{1234567890, "89005924"},
		{2000000000, "69279037"},
		{20000000000, "65353130"},
	}
	for _, v := range vectors {
		p := NewTOTPProvider(TOTPConfig{Digits: 8, Period: 30 * time.Second, Skew: 0}).(*totpProvider)
		p.nowFunc = func() time.Time { return time.Unix(v.timeUnix, 0) }
		ok, err := p.Verify(context.Background(), rfc6238Secret, v.want)
		if err != nil {
			t.Fatalf("Verify(%d): %v", v.timeUnix, err)
		}
		if !ok {
			t.Errorf("T=%d: expected code %s to verify", v.timeUnix, v.want)
		}
	}
}

// TestTOTP_InvalidAndSkew 校验错误口令拒绝、时钟偏移窗口容忍。
func TestTOTP_InvalidAndSkew(t *testing.T) {
	hasher := sha1.New
	key := mustDecode(t, rfc6238Secret)
	// 固定当前时间为 T=59，counter=1；构造相邻窗口 counter=2 的口令。
	const counter int64 = 59 / 30
	nextCode := hotp(key, counter+1, 8, hasher)
	curCode := hotp(key, counter, 8, hasher)

	// skew=0：仅当前窗口口令通过，相邻窗口拒绝。
	p0 := NewTOTPProvider(TOTPConfig{Digits: 8, Period: 30 * time.Second, Skew: 0}).(*totpProvider)
	p0.nowFunc = func() time.Time { return time.Unix(59, 0) }
	if ok, _ := p0.Verify(context.Background(), rfc6238Secret, curCode); !ok {
		t.Errorf("skew=0 should accept current-window code")
	}
	if ok, _ := p0.Verify(context.Background(), rfc6238Secret, nextCode); ok {
		t.Errorf("skew=0 should reject next-window code")
	}
	if ok, _ := p0.Verify(context.Background(), rfc6238Secret, "00000000"); ok {
		t.Errorf("expected invalid code rejected")
	}

	// skew=1：相邻窗口口令也应通过。
	p1 := NewTOTPProvider(TOTPConfig{Digits: 8, Period: 30 * time.Second, Skew: 1}).(*totpProvider)
	p1.nowFunc = func() time.Time { return time.Unix(59, 0) }
	if ok, _ := p1.Verify(context.Background(), rfc6238Secret, nextCode); !ok {
		t.Errorf("skew=1 should accept adjacent-window code")
	}
}

// TestTOTP_SecretNormalization 校验密钥大小写/空格/去 padding 归一化，以及 6 位默认长度自洽。
func TestTOTP_SecretNormalization(t *testing.T) {
	p := NewTOTPProvider(TOTPConfig{}).(*totpProvider) // 默认 6 位、SHA1、skew=1
	// 用一个口令在两个格式等价的密钥间自洽：先算出当前口令，再用带空格小写形式验证。
	now := time.Now()
	p.nowFunc = func() time.Time { return now }
	counter := int64(now.Unix() / 30)
	hasher, _ := p.hasher()
	code := hotp(mustDecode(t, rfc6238Secret), counter, 6, hasher)

	messy := strings.ToLower("gez dgnb vgy3 tqoj qgez dgnb vgy3 tqoj q")
	ok, err := p.Verify(context.Background(), messy, code)
	if err != nil || !ok {
		t.Fatalf("normalized secret verify failed: ok=%v err=%v", ok, err)
	}
}

func mustDecode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := decodeSecret(s)
	if err != nil {
		t.Fatalf("decode secret: %v", err)
	}
	return b
}

// TestTOTP_ProvisioningURI 校验 otpauth 地址包含关键参数。
func TestTOTP_ProvisioningURI(t *testing.T) {
	p := NewTOTPProvider(TOTPConfig{Issuer: "Acme", Digits: 6, Period: 30 * time.Second})
	uri := p.ProvisioningURI(rfc6238Secret, "alice@acme.com")
	for _, want := range []string{"otpauth://totp/", "secret=" + rfc6238Secret, "issuer=Acme", "digits=6", "period=30"} {
		if !strings.Contains(uri, want) {
			t.Errorf("uri %q missing %q", uri, want)
		}
	}
}

// TestTOTP_GenerateSecret 校验生成的密钥可用于自校验回路。
func TestTOTP_GenerateSecret(t *testing.T) {
	p := NewTOTPProvider(TOTPConfig{})
	secret, err := p.GenerateSecret(context.Background())
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	if _, err := decodeSecret(secret); err != nil {
		t.Fatalf("generated secret not decodable: %v", err)
	}
	// 用生成的密钥算当前口令，应能通过 Verify。
	now := time.Now()
	tp := p.(*totpProvider)
	tp.nowFunc = func() time.Time { return now }
	counter := int64(now.Unix() / int64(tp.cfg.Period.Seconds()))
	hasher, _ := tp.hasher()
	code := hotp(mustDecode(t, secret), counter, tp.cfg.Digits, hasher)
	if ok, _ := tp.Verify(context.Background(), secret, code); !ok {
		t.Fatalf("self-generated code failed to verify")
	}
}
