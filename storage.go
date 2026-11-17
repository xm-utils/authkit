package authkit

import (
	"context"
	"sync"
	"time"
)

// StateStorage 存储一次性使用的授权 state。
// 实现方必须保证：state 读取后立即失效（原子性 get-and-delete），并支持 TTL。
type StateStorage interface {
	SaveState(ctx context.Context, state string, meta StateMeta, ttl time.Duration) error
	// GetAndDeleteState 原子取出并删除；不存在或已过期返回 ErrStateNotFound。
	GetAndDeleteState(ctx context.Context, state string) (*StateMeta, error)
}

type memState struct {
	meta   StateMeta
	expire time.Time
}

// MemStateStorage 实现 authkit.StateStorage，读取即删，保证一次性使用。
type MemStateStorage struct {
	mu   sync.Mutex
	data map[string]memState
}

func NewMemStateStorage() *MemStateStorage {
	return &MemStateStorage{data: map[string]memState{}}
}

func (s *MemStateStorage) SaveState(_ context.Context, state string, meta StateMeta, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[state] = memState{meta: meta, expire: time.Now().Add(ttl)}
	return nil
}

func (s *MemStateStorage) GetAndDeleteState(_ context.Context, state string) (*StateMeta, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.data[state]
	if !ok {
		return nil, ErrStateNotFound
	}
	delete(s.data, state) // 读取即删，天然防重放
	if time.Now().After(e.expire) {
		return nil, ErrStateNotFound
	}
	meta := e.meta
	return &meta, nil
}

// ConfigStorage 提供各平台、各租户的接入配置。
// 实现方应支持配置热更新，组件每次调用都实时读取，不做本地缓存。
// 配置缺失时返回 ErrPlatformNotConfigured。
type ConfigStorage interface {
	GetConfig(ctx context.Context, platform, tenantID string) (*PlatformConfig, error)
}

// UserMappingStorage 维护本地用户与三方平台账号的绑定关系。
type UserMappingStorage interface {
	// GetLocalUserID 查询绑定关系，found 为 false 表示未绑定（不是错误）。
	GetLocalUserID(ctx context.Context, platform, thirdPartyUserID, tenantID string) (localUserID string, found bool, err error)

	// BindUser 建立绑定关系，实现方需保证同一 (platform, thirdPartyUserID, tenantID) 唯一。
	BindUser(ctx context.Context, localUserID string, user ThirdPartyUser, tenantID string) error

	// UnbindUser 解除绑定。组件主流程不直接调用，接口保留给使用方在账号体系内使用。
	UnbindUser(ctx context.Context, localUserID, platform, tenantID string) error
}

// QrSessionStorage 管理扫码登录会话的全生命周期。
type QrSessionStorage interface {
	CreateQrSession(ctx context.Context, qrUUID string, session QrSession, ttl time.Duration) error

	// UpdateQrStatus 更新状态，实现方需保证状态流转的原子性（建议 CAS）。
	UpdateQrStatus(ctx context.Context, qrUUID string, status QrStatus, localUserID string) error

	GetQrSession(ctx context.Context, qrUUID string) (*QrSession, error)

	DeleteQrSession(ctx context.Context, qrUUID string) error
}

// TOTPSecretStorage 存储用户第二因子（如 TOTP）的共享密钥。组件不感知密钥含义，
// 仅按 (userID, tenantID) 存取 Provider 生成的不透明密串。
// 实现方必须对密钥静态加密（KMS / 信封加密），且不得写入日志。
type TOTPSecretStorage interface {
	// SaveSecret 写入或覆盖密钥。
	SaveSecret(ctx context.Context, userID, tenantID, secret string) error
	// GetSecret 读取密钥，found=false 表示未绑定（不是错误）。
	GetSecret(ctx context.Context, userID, tenantID string) (secret string, found bool, err error)
	// DeleteSecret 删除密钥（解绑）。
	DeleteSecret(ctx context.Context, userID, tenantID string) error
}

// OTPConsumeStorage 记录一次性码的使用情况，保证同一验证码在有效窗口内不可重放。
// 建议用 Redis SETNX + TTL 实现，并保证原子性。
type OTPConsumeStorage interface {
	// MarkUsed 原子登记某主体本次使用的一次性码；
	// firstUse=false 表示该码在 ttl 内已被使用（重放）。实现方可内部对 code 做摘要存储。
	MarkUsed(ctx context.Context, subject, code string, ttl time.Duration) (firstUse bool, err error)
}
