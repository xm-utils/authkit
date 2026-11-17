// Package authkit 为适配器提供统一的 HTTP 出口，底层代理
// github.com/xm-utils/tools/httpclient 弹性客户端（内置重试 + 熔断 + 请求日志）。
package authkit

import (
	"context"
	"encoding/json"
	"fmt"

	xmhttp "github.com/xm-utils/tools/httpclient"
)

// ensureInit 保证单例已就绪：未初始化时以默认配置惰性初始化。
func ensureInit() {
	if xmhttp.GetClient() == nil {
		xmhttp.Init(nil, nil)
	}
}

// do 组装 HttpRequest 并调用弹性客户端，返回原始响应。
// serviceType 用于底层请求日志归类（一般传平台标识）。
// ctx 当前不参与底层网络调用（库未透传 context），保留形参以便未来扩展与调用方签名稳定。
func do(_ context.Context, serviceType, method, endpoint string, header map[string]string, body any) (*xmhttp.HttpResponse, error) {
	ensureInit()

	h := make(map[string]string, len(header)+1)
	for k, v := range header {
		h[k] = v
	}
	if _, ok := h["Accept"]; !ok {
		h["Accept"] = "application/json"
	}
	// 底层库依据 Content-Type 选择序列化方式：非表单时走 json.Marshal，但不会自动补请求头，
	// 故当携带请求体且未显式指定 Content-Type 时，默认按 JSON 处理。
	if body != nil {
		if _, ok := h["Content-Type"]; !ok {
			h["Content-Type"] = "application/json"
		}
	}

	req := &xmhttp.HttpRequest{
		Method:      method,
		URL:         endpoint,
		Headers:     h,
		Body:        body,
		ServiceType: serviceType,
	}

	resp, err := xmhttp.GetClient().DoRequest(req)
	if err != nil {
		if resp != nil {
			return nil, fmt.Errorf("httpclient: request failed: %w: %s", err, snippet(resp.Body))
		}
		return nil, fmt.Errorf("httpclient: request failed: %w", err)
	}
	if resp == nil {
		return nil, fmt.Errorf("httpclient: nil response")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("httpclient: unexpected status %d: %s", resp.StatusCode, snippet(resp.Body))
	}
	return resp, nil
}

// DoJSON 发起请求并把 JSON 对象响应解析为 map。
// body 为 nil 表示无请求体；form 表单请求由调用方通过 Header["Content-Type"]=
// "application/x-www-form-urlencoded" + 带 url tag 的结构体触发（库内部按 Content-Type 选择序列化方式）。
func DoJSON(ctx context.Context, serviceType, method, endpoint string, header map[string]string, body any) (map[string]any, error) {
	resp, err := do(ctx, serviceType, method, endpoint, header, body)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(resp.Body, &out); err != nil {
		return nil, fmt.Errorf("httpclient: decode json: %w: %s", err, snippet(resp.Body))
	}
	return out, nil
}

// DoJSONArray 发起请求并把 JSON 数组响应解析为 []map，用于返回顶层为数组的接口（如 GitHub /user/emails）。
func DoJSONArray(ctx context.Context, serviceType, method, endpoint string, header map[string]string, body any) ([]map[string]any, error) {
	resp, err := do(ctx, serviceType, method, endpoint, header, body)
	if err != nil {
		return nil, err
	}
	var out []map[string]any
	if err := json.Unmarshal(resp.Body, &out); err != nil {
		return nil, fmt.Errorf("httpclient: decode json array: %w: %s", err, snippet(resp.Body))
	}
	return out, nil
}

// snippet 截取响应体前 256 字节用于错误信息，避免打印超长内容。
func snippet(b []byte) string {
	const max = 256
	if len(b) > max {
		return string(b[:max]) + "..."
	}
	return string(b)
}

// Str 从响应 map 安全读取字符串字段。
func Str(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// Num 从响应 map 安全读取数值字段。
func Num(m map[string]any, key string) int64 {
	if m == nil {
		return 0
	}
	if v, ok := m[key]; ok {
		if f, ok := v.(float64); ok {
			return int64(f)
		}
	}
	return 0
}

// PlatformError 读取常见错误码字段（errcode/errmsg、error/error_description），
// 返回非空字符串表示平台返回了业务错误。
func PlatformError(m map[string]any) string {
	if m == nil {
		return ""
	}
	if c := Num(m, "errcode"); c != 0 {
		return fmt.Sprintf("errcode=%d errmsg=%s", c, Str(m, "errmsg"))
	}
	if e := Str(m, "error"); e != "" {
		return fmt.Sprintf("error=%s description=%s", e, Str(m, "error_description"))
	}
	return ""
}
