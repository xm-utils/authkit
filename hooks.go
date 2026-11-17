package authkit

import (
	"context"
	"log/slog"
	"time"
)

// LoginSuccessHandler 登录成功钩子。
// 在已绑定用户登录成功或扫码确认成功后调用，返回值写入 LoginResult.Ext。
// 执行异常不阻断主流程：组件记录日志并继续返回登录结果。
type LoginSuccessHandler interface {
	OnLoginSuccess(ctx context.Context, result *LoginResult) (map[string]any, error)
}

// UserInfoConverter 把 ThirdPartyUser 映射为业务自有用户模型，避免业务侧重复字段处理。
type UserInfoConverter interface {
	Convert(ctx context.Context, user *ThirdPartyUser) (any, error)
}

// ExceptionHandler 把组件错误统一转为业务错误码与提示文案。返回 nil 表示保留原错误。
type ExceptionHandler interface {
	Handle(ctx context.Context, err error) error
}

// QrCodeGenerator 自定义二维码样式（品牌 Logo、尺寸、配色），返回二维码图片字节。
type QrCodeGenerator interface {
	Generate(ctx context.Context, qrUUID string, ttl time.Duration) ([]byte, error)
}

// Logger 组件自定义的最小日志接口，便于桥接 log/slog、zap、logrus 等实现。
// kv 为交替的 key-value 参数（与 slog 语义一致）。
type Logger interface {
	Debug(msg string, kv ...any)
	Info(msg string, kv ...any)
	Warn(msg string, kv ...any)
	Error(msg string, kv ...any)
}

// nopLogger 是未注入 Logger 时的默认实现，丢弃所有日志。
type nopLogger struct{}

func (nopLogger) Debug(string, ...any) {}
func (nopLogger) Info(string, ...any)  {}
func (nopLogger) Warn(string, ...any)  {}
func (nopLogger) Error(string, ...any) {}

// SlogLogger 基于标准库 log/slog 的 Logger 桥接实现。
type SlogLogger struct{ l *slog.Logger }

// NewSlogLogger 用给定 slog.Logger 构建组件 Logger。l 为 nil 时使用默认 Logger。
func NewSlogLogger(l *slog.Logger) Logger {
	if l == nil {
		l = slog.Default()
	}
	return &SlogLogger{l: l}
}

func (s *SlogLogger) Debug(msg string, kv ...any) { s.l.Debug(msg, kv...) }
func (s *SlogLogger) Info(msg string, kv ...any)  { s.l.Info(msg, kv...) }
func (s *SlogLogger) Warn(msg string, kv ...any)  { s.l.Warn(msg, kv...) }
func (s *SlogLogger) Error(msg string, kv ...any) { s.l.Error(msg, kv...) }
