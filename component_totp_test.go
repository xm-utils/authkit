//go:build test

package authkit_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/xm-utils/authkit"
	"github.com/xm-utils/authkit/memory"
)

// fixedProvider 是本地固定口令的 TOTPProvider 测试替身，隔离真实算法，专注流程编排。
type fixedProvider struct {
	name string
	code string // 仅该口令通过
	uri  string
}

func (f fixedProvider) Name() string { return f.name }

func (f fixedProvider) GenerateSecret(context.Context) (string, error) { return "TESTSECRET", nil }

func (f fixedProvider) ProvisioningURI(secret, account string) string {
	if f.uri != "" {
		return f.uri
	}
	return "otpauth://totp/" + account + "?secret=" + secret
}

func (f fixedProvider) Verify(_ context.Context, secret, code string) (bool, error) {
	return secret == "TESTSECRET" && code == f.code, nil
}

// countingSuccess 记录登录成功钩子被调用次数，用于断言会话签发时机。
type countingSuccess struct{ n int }

func (h *countingSuccess) OnLoginSuccess(_ context.Context, r *authkit.LoginResult) (map[string]any, error) {
	h.n++
	return map[string]any{"token": "jwt-" + r.LocalUserID}, nil
}

type sfFixture struct {
	c        authkit.Component
	cs       *memory.ConfigStorage
	ms       *memory.UserMappingStorage
	secrets  *memory.TOTPSecretStorage
	consume  *memory.OTPConsumeStorage
	success  *countingSuccess
	provider authkit.TOTPProvider
}

func newSFComponent(t *testing.T, provider authkit.TOTPProvider, policy authkit.SecondFactorPolicy) *sfFixture {
	t.Helper()
	cs := memory.NewConfigStorage()
	cs.Put(&authkit.PlatformConfig{Platform: "github", ClientID: "cid", ClientSecret: "s", RedirectURI: "https://login.example.com/cb"})
	ms := memory.NewUserMappingStorage()
	secrets := memory.NewTOTPSecretStorage()
	consume := memory.NewOTPConsumeStorage()
	success := &countingSuccess{}
	opts := []authkit.Option{
		authkit.WithConfig(authkit.Config{StateTTL: 300 * time.Second, QrTTL: 60 * time.Second, SFReplayWindow: time.Minute}),
		authkit.WithStateStorage(memory.NewStateStorage()),
		authkit.WithConfigStorage(cs),
		authkit.WithUserMappingStorage(ms),
		authkit.WithQrSessionStorage(memory.NewQrSessionStorage()),
		authkit.WithAdapter(&fakeAdapter{platform: "github", user: &authkit.ThirdPartyUser{Platform: "github", OpenID: "12345"}}),
		authkit.WithCallbackWhitelist("login.example.com"),
		authkit.WithLoginSuccessHandler(success),
		authkit.WithTOTPProvider(provider),
		authkit.WithTOTPSecretStorage(secrets),
		authkit.WithOTPConsumeStorage(consume),
	}
	if policy != nil {
		opts = append(opts, authkit.WithSecondFactorPolicy(policy))
	}
	c, err := authkit.New(opts...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return &sfFixture{c: c, cs: cs, ms: ms, secrets: secrets, consume: consume, success: success, provider: provider}
}

func TestNew_RequiresTOTPTrioTogether(t *testing.T) {
	// 只注入部分三件套应构造失败。
	_, err := authkit.New(
		authkit.WithStateStorage(memory.NewStateStorage()),
		authkit.WithConfigStorage(memory.NewConfigStorage()),
		authkit.WithUserMappingStorage(memory.NewUserMappingStorage()),
		authkit.WithQrSessionStorage(memory.NewQrSessionStorage()),
		authkit.WithTOTPProvider(fixedProvider{}),
	)
	if !errors.Is(err, authkit.ErrStorageNotConfigured) {
		t.Fatalf("expected ErrStorageNotConfigured for partial TOTP trio, got %v", err)
	}
}

func TestEnrollVerifyDisable(t *testing.T) {
	f := newSFComponent(t, fixedProvider{name: "totp", code: "111111"}, nil)
	ctx := context.Background()

	res, err := f.c.EnrollTOTP(ctx, authkit.TOTPEnrollRequest{LocalUserID: "u1"})
	if err != nil {
		t.Fatalf("EnrollTOTP: %v", err)
	}
	if res.Secret != "TESTSECRET" || res.ProvisioningURI == "" {
		t.Fatalf("unexpected enroll result: %+v", res)
	}

	// 重复绑定且未允许覆盖应报错。
	if _, err := f.c.EnrollTOTP(ctx, authkit.TOTPEnrollRequest{LocalUserID: "u1"}); !errors.Is(err, authkit.ErrSecondFactorAlreadyEnrolled) {
		t.Fatalf("expected already enrolled, got %v", err)
	}
	// Overwrite 允许重新绑定。
	if _, err := f.c.EnrollTOTP(ctx, authkit.TOTPEnrollRequest{LocalUserID: "u1", Overwrite: true}); err != nil {
		t.Fatalf("overwrite enroll: %v", err)
	}

	lr, err := f.c.VerifyTOTP(ctx, authkit.TOTPVerifyRequest{LocalUserID: "u1", Code: "111111"})
	if err != nil {
		t.Fatalf("VerifyTOTP: %v", err)
	}
	if !lr.Bound || lr.Ext["token"] != "jwt-u1" {
		t.Fatalf("expected session issued, got %+v", lr)
	}

	// 关闭后不再需要二因子，且密钥被删除。
	if err := f.c.DisableTOTP(ctx, "u1", ""); err != nil {
		t.Fatalf("DisableTOTP: %v", err)
	}
	if req, _ := f.c.RequireSecondFactor(ctx, "u1", ""); req {
		t.Fatalf("expected no requirement after disable")
	}
	if _, err := f.c.VerifyTOTP(ctx, authkit.TOTPVerifyRequest{LocalUserID: "u1", Code: "111111"}); !errors.Is(err, authkit.ErrSecondFactorNotEnrolled) {
		t.Fatalf("expected not enrolled after disable, got %v", err)
	}
}

func TestVerify_BadCodeAndReplay(t *testing.T) {
	f := newSFComponent(t, fixedProvider{name: "totp", code: "222222"}, nil)
	ctx := context.Background()
	if _, err := f.c.EnrollTOTP(ctx, authkit.TOTPEnrollRequest{LocalUserID: "u2"}); err != nil {
		t.Fatalf("enroll: %v", err)
	}

	if _, err := f.c.VerifyTOTP(ctx, authkit.TOTPVerifyRequest{LocalUserID: "u2", Code: "000000"}); !errors.Is(err, authkit.ErrOTPInvalid) {
		t.Fatalf("expected ErrOTPInvalid, got %v", err)
	}
	// 首次正确口令通过。
	if _, err := f.c.VerifyTOTP(ctx, authkit.TOTPVerifyRequest{LocalUserID: "u2", Code: "222222"}); err != nil {
		t.Fatalf("first verify: %v", err)
	}
	// 同一口令窗口内重放被拒。
	if _, err := f.c.VerifyTOTP(ctx, authkit.TOTPVerifyRequest{LocalUserID: "u2", Code: "222222"}); !errors.Is(err, authkit.ErrOTPReused) {
		t.Fatalf("expected ErrOTPReused, got %v", err)
	}
}

// TestHandleCallback_SecondFactorWiring 验证已绑定用户登录时被要求二因子、会话签发延后。
func TestHandleCallback_SecondFactorWiring(t *testing.T) {
	f := newSFComponent(t, fixedProvider{name: "totp", code: "333333"}, nil)
	ctx := context.Background()

	// 预绑定 github:12345 -> local-9，并为其登记 TOTP 密钥。
	if err := f.ms.BindUser(ctx, "local-9", authkit.ThirdPartyUser{Platform: "github", OpenID: "12345"}, ""); err != nil {
		t.Fatalf("prepare bind: %v", err)
	}
	if _, err := f.c.EnrollTOTP(ctx, authkit.TOTPEnrollRequest{LocalUserID: "local-9"}); err != nil {
		t.Fatalf("enroll: %v", err)
	}

	url, _ := f.c.BuildAuthURL(ctx, authkit.AuthURLRequest{Platform: "github", ClientIP: "1.1.1.1"})
	res, err := f.c.HandleCallback(ctx, authkit.CallbackRequest{Platform: "github", Code: "c", State: extractState(t, url), ClientIP: "1.1.1.1"})
	if err != nil {
		t.Fatalf("HandleCallback: %v", err)
	}
	if !res.Bound || !res.RequireSecondFactor {
		t.Fatalf("expected bound + require second factor, got %+v", res)
	}
	if res.Ext["token"] != nil {
		t.Fatalf("session must NOT be issued before 2FA, got %v", res.Ext["token"])
	}
	if f.success.n != 0 {
		t.Fatalf("login success handler should not fire pre-2FA, fired=%d", f.success.n)
	}

	// 补齐二因子后签发会话。
	final, err := f.c.VerifyTOTP(ctx, authkit.TOTPVerifyRequest{LocalUserID: "local-9", Code: "333333"})
	if err != nil {
		t.Fatalf("VerifyTOTP: %v", err)
	}
	if final.Ext["token"] != "jwt-local-9" || f.success.n != 1 {
		t.Fatalf("expected session issued after 2FA, result=%+v fired=%d", final, f.success.n)
	}
}

// TestHandleCallback_NoSecondFactorBackwardCompatible 验证未绑定 TOTP 的用户登录行为与旧版一致。
func TestHandleCallback_NoSecondFactorBackwardCompatible(t *testing.T) {
	f := newSFComponent(t, fixedProvider{name: "totp", code: "999999"}, nil)
	ctx := context.Background()
	if err := f.ms.BindUser(ctx, "local-plain", authkit.ThirdPartyUser{Platform: "github", OpenID: "12345"}, ""); err != nil {
		t.Fatalf("prepare bind: %v", err)
	}

	url, _ := f.c.BuildAuthURL(ctx, authkit.AuthURLRequest{Platform: "github", ClientIP: "2.2.2.2"})
	res, err := f.c.HandleCallback(ctx, authkit.CallbackRequest{Platform: "github", Code: "c", State: extractState(t, url), ClientIP: "2.2.2.2"})
	if err != nil {
		t.Fatalf("HandleCallback: %v", err)
	}
	if res.RequireSecondFactor || !res.Bound || res.Ext["token"] != "jwt-local-plain" {
		t.Fatalf("expected normal login (no 2FA), got %+v", res)
	}
}

// TestConfirmQrLogin_SecondFactorWiring 验证扫码确认在二因子下的会话延后。
func TestConfirmQrLogin_SecondFactorWiring(t *testing.T) {
	f := newSFComponent(t, fixedProvider{name: "totp", code: "444444"}, nil)
	ctx := context.Background()
	if _, err := f.c.EnrollTOTP(ctx, authkit.TOTPEnrollRequest{LocalUserID: "qr-user"}); err != nil {
		t.Fatalf("enroll: %v", err)
	}

	sess, err := f.c.CreateQrSession(ctx, authkit.QrSessionRequest{TTL: 60 * time.Second, Device: authkit.DeviceInfo{Model: "PC"}})
	if err != nil {
		t.Fatalf("create qr: %v", err)
	}
	if _, err := f.c.HandleQrScanned(ctx, sess.QrUUID); err != nil {
		t.Fatalf("scanned: %v", err)
	}
	// 确认成功，但因需要二因子，登录钩子此时不应触发。
	if err := f.c.ConfirmQrLogin(ctx, sess.QrUUID, "qr-user", ""); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	if f.success.n != 0 {
		t.Fatalf("handler should be deferred under 2FA, fired=%d", f.success.n)
	}
	req, err := f.c.RequireSecondFactor(ctx, "qr-user", "")
	if err != nil || !req {
		t.Fatalf("expected requirement true, got %v err %v", req, err)
	}
	// 补齐二因子后签发。
	if _, err := f.c.VerifyTOTP(ctx, authkit.TOTPVerifyRequest{LocalUserID: "qr-user", Code: "444444"}); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if f.success.n != 1 {
		t.Fatalf("expected handler fired once after 2FA, fired=%d", f.success.n)
	}
}

// policyAlwaysRequire 是自定义策略示例：无条件要求二因子。
type policyAlwaysRequire struct{}

func (policyAlwaysRequire) RequireSecondFactor(context.Context, string, string) (bool, error) {
	return true, nil
}

func TestSecondFactorPolicyOverride(t *testing.T) {
	// 无自定义策略、未绑定密钥时不要求；注入 always-require 策略后即便未绑定也要求。
	f := newSFComponent(t, fixedProvider{name: "totp", code: "555555"}, policyAlwaysRequire{})
	ctx := context.Background()
	if err := f.ms.BindUser(ctx, "pol-user", authkit.ThirdPartyUser{Platform: "github", OpenID: "12345"}, ""); err != nil {
		t.Fatalf("bind: %v", err)
	}
	url, _ := f.c.BuildAuthURL(ctx, authkit.AuthURLRequest{Platform: "github"})
	res, err := f.c.HandleCallback(ctx, authkit.CallbackRequest{Platform: "github", Code: "c", State: extractState(t, url)})
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	if !res.RequireSecondFactor {
		t.Fatalf("custom policy should force requirement, got %+v", res)
	}
}

// httpTOTPProvider 通过 HTTP 调用远程 2FA 校验服务，演示 TOTPProvider 可网络化的可插拔设计。
type httpTOTPProvider struct {
	baseURL string
	client  *http.Client
}

func (h httpTOTPProvider) Name() string { return "remote-totp" }
func (h httpTOTPProvider) GenerateSecret(context.Context) (string, error) {
	return "REMOTESECRET", nil
}
func (h httpTOTPProvider) ProvisioningURI(secret, account string) string {
	return "otpauth://totp/" + account + "?secret=" + secret
}
func (h httpTOTPProvider) Verify(ctx context.Context, secret, code string) (bool, error) {
	body, _ := json.Marshal(map[string]string{"secret": secret, "code": code})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.baseURL+"/verify", bytes.NewReader(body))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := h.client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	var out struct {
		OK bool `json:"ok"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return false, err
	}
	return out.OK, nil
}

// TestRemoteProviderViaHTTPTest 用 httptest 模拟集中式 2FA 校验服务，端到端验证可插拔 Provider。
func TestRemoteProviderViaHTTPTest(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Secret string `json:"secret"`
			Code   string `json:"code"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		ok := in.Secret == "REMOTESECRET" && in.Code == "654321"
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]bool{"ok": ok})
	}))
	defer srv.Close()

	provider := httpTOTPProvider{baseURL: srv.URL, client: srv.Client()}
	f := newSFComponent(t, provider, nil)
	ctx := context.Background()

	if _, err := f.c.EnrollTOTP(ctx, authkit.TOTPEnrollRequest{LocalUserID: "remote-1"}); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	// 错误口令：远程服务返回 ok=false。
	if _, err := f.c.VerifyTOTP(ctx, authkit.TOTPVerifyRequest{LocalUserID: "remote-1", Code: "000000"}); !errors.Is(err, authkit.ErrOTPInvalid) {
		t.Fatalf("expected ErrOTPInvalid from remote, got %v", err)
	}
	// 正确口令：经远程 HTTP 校验通过并签发会话。
	lr, err := f.c.VerifyTOTP(ctx, authkit.TOTPVerifyRequest{LocalUserID: "remote-1", Code: "654321"})
	if err != nil {
		t.Fatalf("verify via remote: %v", err)
	}
	if lr.Ext["token"] != "jwt-remote-1" {
		t.Fatalf("expected token issued via remote provider, got %+v", lr)
	}
}
