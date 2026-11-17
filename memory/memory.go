//go:build test

// Package memory 提供四个存储 SPI 接口的进程内实现，仅用于测试构建（//go:build test）。
// 生产环境禁止使用：内存实现不跨进程共享，集群部署会出现会话不一致。
package memory

import (
	"context"
	"sync"
	"time"

	"github.com/xm-utils/authkit"
)

type entry[T any] struct {
	val       T
	expiresAt time.Time
}

func (e entry[T]) expired(now time.Time) bool {
	return !e.expiresAt.IsZero() && now.After(e.expiresAt)
}

// StateStorage 是基于内存的 authkit.StateStorage 测试实现。
type StateStorage struct {
	mu   sync.Mutex
	data map[string]entry[authkit.StateMeta]
}

// NewStateStorage 创建内存 state 存储。
func NewStateStorage() *StateStorage {
	return &StateStorage{data: map[string]entry[authkit.StateMeta]{}}
}

// SaveState 保存 state，ttl<=0 表示不过期。
func (s *StateStorage) SaveState(_ context.Context, state string, meta authkit.StateMeta, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[state] = entry[authkit.StateMeta]{val: meta, expiresAt: expAt(ttl)}
	return nil
}

// GetAndDeleteState 原子取出并删除；不存在或过期返回 ErrStateNotFound。
func (s *StateStorage) GetAndDeleteState(_ context.Context, state string) (*authkit.StateMeta, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.data[state]
	if !ok {
		return nil, authkit.ErrStateNotFound
	}
	delete(s.data, state)
	if e.expired(time.Now()) {
		return nil, authkit.ErrStateNotFound
	}
	meta := e.val
	return &meta, nil
}

// ConfigStorage 是基于内存的 authkit.ConfigStorage 测试实现。
type ConfigStorage struct {
	mu   sync.RWMutex
	data map[string]*authkit.PlatformConfig
}

// NewConfigStorage 创建内存配置存储。
func NewConfigStorage() *ConfigStorage {
	return &ConfigStorage{data: map[string]*authkit.PlatformConfig{}}
}

func configKey(platform, tenantID string) string { return platform + "|" + tenantID }

// Put 写入或更新一个平台配置（模拟配置中心热更新）。
func (s *ConfigStorage) Put(cfg *authkit.PlatformConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[configKey(cfg.Platform, cfg.TenantID)] = cfg
}

// GetConfig 读取配置，缺失返回 ErrPlatformNotConfigured。
func (s *ConfigStorage) GetConfig(_ context.Context, platform, tenantID string) (*authkit.PlatformConfig, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cfg, ok := s.data[configKey(platform, tenantID)]
	if !ok {
		return nil, authkit.ErrPlatformNotConfigured
	}
	return cfg, nil
}

// UserMappingStorage 是基于内存的 authkit.UserMappingStorage 测试实现。
type UserMappingStorage struct {
	mu   sync.RWMutex
	data map[string]string // bindKey -> localUserID
}

// NewUserMappingStorage 创建内存绑定存储。
func NewUserMappingStorage() *UserMappingStorage {
	return &UserMappingStorage{data: map[string]string{}}
}

func mappingKey(platform, thirdID, tenantID string) string {
	return platform + "|" + tenantID + "|" + thirdID
}

// GetLocalUserID 查询绑定关系。
func (s *UserMappingStorage) GetLocalUserID(_ context.Context, platform, thirdPartyUserID, tenantID string) (string, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	uid, ok := s.data[mappingKey(platform, thirdPartyUserID, tenantID)]
	return uid, ok, nil
}

// BindUser 建立绑定关系，重复绑定覆盖。
func (s *UserMappingStorage) BindUser(_ context.Context, localUserID string, user authkit.ThirdPartyUser, tenantID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[mappingKey(user.Platform, user.BindKey(), tenantID)] = localUserID
	return nil
}

// UnbindUser 解除绑定。
func (s *UserMappingStorage) UnbindUser(_ context.Context, _, platform, tenantID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// 内存实现按 localUserID 无法反查，测试场景直接清空该用户所有平台绑定不可行；
	// 这里仅作为占位，真实业务应维护反向索引。
	_ = platform
	_ = tenantID
	return nil
}

// QrSessionStorage 是基于内存的 authkit.QrSessionStorage 测试实现。
type QrSessionStorage struct {
	mu   sync.Mutex
	data map[string]entry[authkit.QrSession]
}

// NewQrSessionStorage 创建内存扫码会话存储。
func NewQrSessionStorage() *QrSessionStorage {
	return &QrSessionStorage{data: map[string]entry[authkit.QrSession]{}}
}

// CreateQrSession 建档并设置 TTL。
func (s *QrSessionStorage) CreateQrSession(_ context.Context, qrUUID string, session authkit.QrSession, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[qrUUID] = entry[authkit.QrSession]{val: session, expiresAt: expAt(ttl)}
	return nil
}

// UpdateQrStatus 更新状态；不存在返回 ErrQrSessionNotFound。
func (s *QrSessionStorage) UpdateQrStatus(_ context.Context, qrUUID string, status authkit.QrStatus, localUserID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.data[qrUUID]
	if !ok || e.expired(time.Now()) {
		return authkit.ErrQrSessionNotFound
	}
	e.val.Status = status
	if localUserID != "" {
		e.val.LocalUserID = localUserID
	}
	s.data[qrUUID] = e
	return nil
}

// GetQrSession 读取会话；不存在或过期返回 ErrQrSessionNotFound。
func (s *QrSessionStorage) GetQrSession(_ context.Context, qrUUID string) (*authkit.QrSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.data[qrUUID]
	if !ok {
		return nil, authkit.ErrQrSessionNotFound
	}
	if e.expired(time.Now()) {
		delete(s.data, qrUUID)
		return nil, authkit.ErrQrSessionNotFound
	}
	session := e.val
	return &session, nil
}

// DeleteQrSession 删除会话。
func (s *QrSessionStorage) DeleteQrSession(_ context.Context, qrUUID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, qrUUID)
	return nil
}

// TOTPSecretStorage 是基于内存的 authkit.TOTPSecretStorage 测试实现（密钥明文存，仅测试用）。
type TOTPSecretStorage struct {
	mu   sync.RWMutex
	data map[string]string
}

// NewTOTPSecretStorage 创建内存密钥存储。
func NewTOTPSecretStorage() *TOTPSecretStorage {
	return &TOTPSecretStorage{data: map[string]string{}}
}

func totpKey(userID, tenantID string) string { return tenantID + "|" + userID }

// SaveSecret 写入或覆盖密钥。
func (s *TOTPSecretStorage) SaveSecret(_ context.Context, userID, tenantID, secret string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[totpKey(userID, tenantID)] = secret
	return nil
}

// GetSecret 读取密钥。
func (s *TOTPSecretStorage) GetSecret(_ context.Context, userID, tenantID string) (string, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sec, ok := s.data[totpKey(userID, tenantID)]
	return sec, ok, nil
}

// DeleteSecret 删除密钥。
func (s *TOTPSecretStorage) DeleteSecret(_ context.Context, userID, tenantID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, totpKey(userID, tenantID))
	return nil
}

// OTPConsumeStorage 是基于内存的 authkit.OTPConsumeStorage 测试实现，模拟 SETNX+TTL。
type OTPConsumeStorage struct {
	mu   sync.Mutex
	data map[string]entry[struct{}]
}

// NewOTPConsumeStorage 创建内存防重放存储。
func NewOTPConsumeStorage() *OTPConsumeStorage {
	return &OTPConsumeStorage{data: map[string]entry[struct{}]{}}
}

// MarkUsed 原子登记已用口令；窗口内重复使用返回 firstUse=false。
func (s *OTPConsumeStorage) MarkUsed(_ context.Context, subject, code string, ttl time.Duration) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := subject + "|" + code
	if e, ok := s.data[k]; ok && !e.expired(time.Now()) {
		return false, nil
	}
	s.data[k] = entry[struct{}]{expiresAt: expAt(ttl)}
	return true, nil
}

func expAt(ttl time.Duration) time.Time {
	if ttl <= 0 {
		return time.Time{}
	}
	return time.Now().Add(ttl)
}
