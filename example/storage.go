package main

import (
	"context"
	"sync"
	"time"

	"github.com/xm-utils/authkit"
)

// 本文件演示如何用自有存储（生产环境通常是 Redis/MySQL/配置中心）实现组件的 SPI 接口。
// 必选 4 个：State / Config / UserMapping / QrSession；
// 启用第二因子时再加 2 个：TOTPSecret / OTPConsume（生产建议分别用 MySQL 与 Redis SETNX+TTL）。
// 这里用进程内 map + TTL 简化实现，仅用于可离线运行的示例，切勿用于生产。

// ---- StateStorage ----

// ---- ConfigStorage ----

// MemConfigStorage 实现 authkit.ConfigStorage，模拟配置中心，支持热更新与密钥解密。
type MemConfigStorage struct {
	mu   sync.RWMutex
	data map[string]*authkit.PlatformConfig
}

func NewMemConfigStorage() *MemConfigStorage {
	return &MemConfigStorage{data: map[string]*authkit.PlatformConfig{}}
}

func configKey(platform, tenantID string) string { return platform + "|" + tenantID }

// Put 写入/更新平台配置（生产环境由配置中心下发，ClientSecret 建议在实现内部解密后返回）。
func (s *MemConfigStorage) Put(cfg *authkit.PlatformConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[configKey(cfg.Platform, cfg.TenantID)] = cfg
}

func (s *MemConfigStorage) GetConfig(_ context.Context, platform, tenantID string) (*authkit.PlatformConfig, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cfg, ok := s.data[configKey(platform, tenantID)]
	if !ok {
		return nil, authkit.ErrPlatformNotConfigured
	}
	return cfg, nil
}

// ---- UserMappingStorage ----

// MemUserMappingStorage 实现 authkit.UserMappingStorage，维护本地用户与三方账号绑定关系。
// 生产环境应对 (tenant_id, platform, open_id) 建唯一索引。
type MemUserMappingStorage struct {
	mu    sync.RWMutex
	binds map[string]string // bindKey -> localUserID
}

func NewMemUserMappingStorage() *MemUserMappingStorage {
	return &MemUserMappingStorage{binds: map[string]string{}}
}

func mappingKey(platform, thirdID, tenantID string) string {
	return platform + "|" + tenantID + "|" + thirdID
}

func (s *MemUserMappingStorage) GetLocalUserID(_ context.Context, platform, thirdPartyUserID, tenantID string) (string, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	uid, ok := s.binds[mappingKey(platform, thirdPartyUserID, tenantID)]
	return uid, ok, nil
}

func (s *MemUserMappingStorage) BindUser(_ context.Context, localUserID string, user authkit.ThirdPartyUser, tenantID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.binds[mappingKey(user.Platform, user.BindKey(), tenantID)] = localUserID
	return nil
}

func (s *MemUserMappingStorage) UnbindUser(_ context.Context, _, platform, tenantID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// 演示用：示例仅按正向键存储，真实实现应维护反向索引以支持按 localUserID 解绑。
	_ = platform
	_ = tenantID
	return nil
}

// ---- QrSessionStorage ----

type memQr struct {
	session authkit.QrSession
	expire  time.Time
}

// MemQrSessionStorage 实现 authkit.QrSessionStorage，生产环境应使用 Redis 并保证状态流转 CAS 原子性。
type MemQrSessionStorage struct {
	mu   sync.Mutex
	data map[string]memQr
}

func NewMemQrSessionStorage() *MemQrSessionStorage {
	return &MemQrSessionStorage{data: map[string]memQr{}}
}

func (s *MemQrSessionStorage) CreateQrSession(_ context.Context, qrUUID string, session authkit.QrSession, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[qrUUID] = memQr{session: session, expire: time.Now().Add(ttl)}
	return nil
}

func (s *MemQrSessionStorage) UpdateQrStatus(_ context.Context, qrUUID string, status authkit.QrStatus, localUserID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.data[qrUUID]
	if !ok || time.Now().After(e.expire) {
		return authkit.ErrQrSessionNotFound
	}
	e.session.Status = status
	if localUserID != "" {
		e.session.LocalUserID = localUserID
	}
	s.data[qrUUID] = e
	return nil
}

func (s *MemQrSessionStorage) GetQrSession(_ context.Context, qrUUID string) (*authkit.QrSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.data[qrUUID]
	if !ok || time.Now().After(e.expire) {
		return nil, authkit.ErrQrSessionNotFound
	}
	session := e.session
	return &session, nil
}

func (s *MemQrSessionStorage) DeleteQrSession(_ context.Context, qrUUID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, qrUUID)
	return nil
}

// ---- TOTPSecretStorage ----

// MemTOTPSecretStorage 实现 authkit.TOTPSecretStorage，存用户 TOTP 共享密钥。
// 生产环境密钥属于高敏感数据，应加密落库（如 KMS 信封加密）。
type MemTOTPSecretStorage struct {
	mu      sync.RWMutex
	secrets map[string]string // "tenantID|userID" -> secret
}

func NewMemTOTPSecretStorage() *MemTOTPSecretStorage {
	return &MemTOTPSecretStorage{secrets: map[string]string{}}
}

func totpKey(userID, tenantID string) string { return tenantID + "|" + userID }

func (s *MemTOTPSecretStorage) SaveSecret(_ context.Context, userID, tenantID, secret string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.secrets[totpKey(userID, tenantID)] = secret
	return nil
}

func (s *MemTOTPSecretStorage) GetSecret(_ context.Context, userID, tenantID string) (string, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sec, ok := s.secrets[totpKey(userID, tenantID)]
	return sec, ok, nil
}

func (s *MemTOTPSecretStorage) DeleteSecret(_ context.Context, userID, tenantID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.secrets, totpKey(userID, tenantID))
	return nil
}

// ---- OTPConsumeStorage ----

// MemOTPConsumeStorage 实现 authkit.OTPConsumeStorage，模拟 Redis SETNX+TTL：
// 同一主体（provider|userID|tenantID）的同一口令在窗口内仅首次使用返回 firstUse=true。
type MemOTPConsumeStorage struct {
	mu       sync.Mutex
	expireAt map[string]time.Time // "subject|code" -> 重放窗口截止时间
}

func NewMemOTPConsumeStorage() *MemOTPConsumeStorage {
	return &MemOTPConsumeStorage{expireAt: map[string]time.Time{}}
}

func (s *MemOTPConsumeStorage) MarkUsed(_ context.Context, subject, code string, ttl time.Duration) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	key := subject + "|" + code
	if exp, ok := s.expireAt[key]; ok && now.Before(exp) {
		return false, nil // 窗口内重放
	}
	s.expireAt[key] = now.Add(ttl)
	return true, nil
}
