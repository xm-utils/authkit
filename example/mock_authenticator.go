package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"fmt"
	"strings"
	"time"
)

// mock_authenticator.go 模拟「手机验证器 App」：演示脚本没有真实的谷歌身份验证器，
// 就用绑定时拿到的 Secret 按 RFC 6238（HMAC-SHA1 / 6 位 / 30s）现算当前口令。
// 仅用于让 example 可离线闭环运行，真实接入时由用户手机端生成，业务侧永远拿不到 Secret 之外的输入。

const (
	authPeriod = 30 * time.Second // 与内置 NewTOTPProvider 默认步长一致
	authDigits = 6                // 与默认口令位数一致
)

// authenticatorCode 计算 secret 在时间 t 对应的 6 位动态口令。
func authenticatorCode(secret string, t time.Time) string {
	key, err := decodeBase32(secret)
	if err != nil {
		panic("example: mock authenticator decode secret: " + err.Error())
	}
	counter := t.Unix() / int64(authPeriod.Seconds())

	// HOTP（RFC 4226）：counter 8 字节大端 → HMAC-SHA1 → 动态截断 → 模 10^6。
	buf := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		buf[i] = byte(counter & 0xff)
		counter >>= 8
	}
	m := hmac.New(sha1.New, key)
	m.Write(buf)
	sum := m.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	binary := uint32(sum[offset]&0x7f)<<24 |
		uint32(sum[offset+1])<<16 |
		uint32(sum[offset+2])<<8 |
		uint32(sum[offset+3])
	return fmt.Sprintf("%06d", binary%1_000_000)
}

// decodeBase32 容错解析密钥：大小写不敏感、去空格、自动补 padding（与验证器扫码行为一致）。
func decodeBase32(secret string) ([]byte, error) {
	s := strings.ToUpper(strings.Join(strings.Fields(secret), ""))
	s = strings.TrimRight(s, "=")
	if pad := len(s) % 8; pad != 0 {
		s += strings.Repeat("=", 8-pad)
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.TrimRight(s, "="))
}
