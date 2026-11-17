package authkit

import "encoding/base64"

// base64Std 把二维码图片字节编码后随会话返回。
func base64Std(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
