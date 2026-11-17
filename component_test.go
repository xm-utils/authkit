//go:build test

package authkit_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/xm-utils/authkit"
	"github.com/xm-utils/authkit/memory"
)

// fakeAdapter 是用于测试的内存平台适配器，不发起真实 HTTP 请求。
type fakeAdapter struct {
	platform string
	user     *authkit.ThirdPartyUser
	exchErr  error
	userErr  error
}

func (f *fakeAdapter) PlatformName() string { return f.platform }

func (f *fakeAdapter) BuildAuthorizationURL(state string, cfg *authkit.PlatformConfig, _ map[string]string) (string, error) {
	return "https://fake.example.com/authorize?state=" + state + "&app=" + cfg.ClientID, nil
}

func (f *fakeAdapter) ExchangeToken(_ context.Context, code string, _ *authkit.PlatformConfig) (*authkit.TokenResult, error) {
	if f.exchErr != nil {
		return nil, f.exchErr
	}
	return &authkit.TokenResult{AccessToken: "tok-" + code, Raw: map[string]any{}}, nil
}

func (f *fakeAdapter) FetchUserInfo(_ context.Context, _ *authkit.TokenResult, _ *authkit.PlatformConfig) (*authkit.ThirdPartyUser, error) {
	if f.userErr != nil {
		return nil, f.userErr
	}
	u := *f.user
	return &u, nil
}

func newComponent(t *testing.T, a authkit.PlatformAdapter, whitelist ...string) (authkit.Component, *memory.ConfigStorage, *memory.UserMappingStorage, *memory.QrSessionStorage) {
	t.Helper()
	cs := memory.NewConfigStorage()
	cs.Put(&authkit.PlatformConfig{Platform: "github", ClientID: "cid", ClientSecret: "secret", RedirectURI: "https://login.example.com/cb"})
	ms := memory.NewUserMappingStorage()
	qs := memory.NewQrSessionStorage()
	if len(whitelist) == 0 {
		whitelist = []string{"login.example.com"}
	}
	c, err := authkit.New(
		authkit.WithConfig(authkit.Config{StateTTL: 300 * time.Second, QrTTL: 60 * time.Second}),
		authkit.WithStateStorage(memory.NewStateStorage()),
		authkit.WithConfigStorage(cs),
		authkit.WithUserMappingStorage(ms),
		authkit.WithQrSessionStorage(qs),
		authkit.WithAdapter(a),
		authkit.WithCallbackWhitelist(whitelist...),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c, cs, ms, qs
}

func TestBuildAuthURLAndCallback_Bound(t *testing.T) {
	adapter := &fakeAdapter{platform: "github", user: &authkit.ThirdPartyUser{
		Platform: "github", OpenID: "12345", Nickname: "alice",
	}}
	c, _, ms, _ := newComponent(t, adapter)
	ctx := context.Background()

	authURL, err := c.BuildAuthURL(ctx, authkit.AuthURLRequest{
		Platform: "github", RedirectURI: "https://login.example.com/cb", ClientIP: "1.2.3.4",
	})
	if err != nil {
		t.Fatalf("BuildAuthURL: %v", err)
	}
	// 从 URL 提取 state。
	state := extractState(t, authURL)

	// 预先建立绑定关系。
	if err := ms.BindUser(ctx, "local-1", authkit.ThirdPartyUser{Platform: "github", OpenID: "12345"}, ""); err != nil {
		t.Fatalf("prepare bind: %v", err)
	}

	res, err := c.HandleCallback(ctx, authkit.CallbackRequest{
		Platform: "github", Code: "code-abc", State: state, ClientIP: "1.2.3.4",
	})
	if err != nil {
		t.Fatalf("HandleCallback: %v", err)
	}
	if !res.Bound || res.LocalUserID != "local-1" {
		t.Fatalf("expected bound result, got %+v", res)
	}
	if res.Token == nil || res.Token.AccessToken != "tok-code-abc" {
		t.Fatalf("unexpected token: %+v", res.Token)
	}
}

func TestHandleCallback_NeedBind(t *testing.T) {
	adapter := &fakeAdapter{platform: "github", user: &authkit.ThirdPartyUser{
		Platform: "github", OpenID: "999",
	}}
	c, _, _, _ := newComponent(t, adapter)
	ctx := context.Background()

	url, _ := c.BuildAuthURL(ctx, authkit.AuthURLRequest{Platform: "github", ClientIP: "5.6.7.8"})
	state := extractState(t, url)

	res, err := c.HandleCallback(ctx, authkit.CallbackRequest{Platform: "github", Code: "c", State: state, ClientIP: "5.6.7.8"})
	if err != nil {
		t.Fatalf("HandleCallback: %v", err)
	}
	if res.Bound {
		t.Fatalf("expected unbound")
	}
	if res.ThirdUser == nil || res.ThirdUser.OpenID != "999" {
		t.Fatalf("expected third user, got %+v", res.ThirdUser)
	}
}

func TestHandleCallback_StateReplay(t *testing.T) {
	adapter := &fakeAdapter{platform: "github", user: &authkit.ThirdPartyUser{Platform: "github", OpenID: "1"}}
	c, _, _, _ := newComponent(t, adapter)
	ctx := context.Background()

	url, _ := c.BuildAuthURL(ctx, authkit.AuthURLRequest{Platform: "github"})
	state := extractState(t, url)

	if _, err := c.HandleCallback(ctx, authkit.CallbackRequest{Platform: "github", Code: "c", State: state}); err != nil {
		t.Fatalf("first callback: %v", err)
	}
	// 第二次使用同一 state 应被拒绝。
	_, err := c.HandleCallback(ctx, authkit.CallbackRequest{Platform: "github", Code: "c", State: state})
	if !errors.Is(err, authkit.ErrStateNotFound) {
		t.Fatalf("expected ErrStateNotFound on replay, got %v", err)
	}
}

func TestHandleCallback_IPMismatch(t *testing.T) {
	adapter := &fakeAdapter{platform: "github", user: &authkit.ThirdPartyUser{Platform: "github", OpenID: "1"}}
	c, _, _, _ := newComponent(t, adapter)
	ctx := context.Background()

	url, _ := c.BuildAuthURL(ctx, authkit.AuthURLRequest{Platform: "github", ClientIP: "1.1.1.1"})
	state := extractState(t, url)

	_, err := c.HandleCallback(ctx, authkit.CallbackRequest{Platform: "github", Code: "c", State: state, ClientIP: "2.2.2.2"})
	if !errors.Is(err, authkit.ErrStateInvalid) {
		t.Fatalf("expected ErrStateInvalid, got %v", err)
	}
}

func TestBuildAuthURL_CallbackNotAllowed(t *testing.T) {
	adapter := &fakeAdapter{platform: "github", user: &authkit.ThirdPartyUser{Platform: "github", OpenID: "1"}}
	c, _, _, _ := newComponent(t, adapter, "login.example.com")
	_, err := c.BuildAuthURL(context.Background(), authkit.AuthURLRequest{
		Platform: "github", RedirectURI: "https://evil.com/cb",
	})
	if !errors.Is(err, authkit.ErrCallbackNotAllowed) {
		t.Fatalf("expected ErrCallbackNotAllowed, got %v", err)
	}
}

func TestNew_RequiresStorages(t *testing.T) {
	_, err := authkit.New(authkit.WithAdapter(&fakeAdapter{platform: "github"}))
	if !errors.Is(err, authkit.ErrStorageNotConfigured) {
		t.Fatalf("expected ErrStorageNotConfigured, got %v", err)
	}
}

func TestQrFlowStateMachine(t *testing.T) {
	adapter := &fakeAdapter{platform: "github", user: &authkit.ThirdPartyUser{Platform: "github", OpenID: "1"}}
	c, _, _, _ := newComponent(t, adapter)
	ctx := context.Background()

	sess, err := c.CreateQrSession(ctx, authkit.QrSessionRequest{
		TTL:    60 * time.Second,
		Device: authkit.DeviceInfo{Model: "iPhone", IP: "9.9.9.9"},
	})
	if err != nil {
		t.Fatalf("CreateQrSession: %v", err)
	}
	if sess.Status != authkit.QrStatusPending {
		t.Fatalf("expected pending, got %v", sess.Status)
	}

	// 未扫码直接确认应冲突。
	if err := c.ConfirmQrLogin(ctx, sess.QrUUID, "local-1", ""); !errors.Is(err, authkit.ErrQrStatusConflict) {
		t.Fatalf("expected conflict before scan, got %v", err)
	}

	dev, err := c.HandleQrScanned(ctx, sess.QrUUID)
	if err != nil {
		t.Fatalf("HandleQrScanned: %v", err)
	}
	if dev.Model != "iPhone" {
		t.Fatalf("expected device info, got %+v", dev)
	}

	if err := c.ConfirmQrLogin(ctx, sess.QrUUID, "local-1", ""); err != nil {
		t.Fatalf("ConfirmQrLogin: %v", err)
	}

	got, err := c.GetQrSession(ctx, sess.QrUUID)
	if err != nil {
		t.Fatalf("GetQrSession: %v", err)
	}
	if got.Status != authkit.QrStatusConfirmed || got.LocalUserID != "local-1" {
		t.Fatalf("expected confirmed session, got %+v", got)
	}

	// 终态后不可再变。
	if err := c.CancelQrLogin(ctx, sess.QrUUID); !errors.Is(err, authkit.ErrQrStatusConflict) {
		t.Fatalf("expected conflict cancel after confirm, got %v", err)
	}
}

func TestQrFlowExpired(t *testing.T) {
	adapter := &fakeAdapter{platform: "github", user: &authkit.ThirdPartyUser{Platform: "github", OpenID: "1"}}
	c, _, _, _ := newComponent(t, adapter)
	ctx := context.Background()

	// TTL 极短，制造过期。
	sess, err := c.CreateQrSession(ctx, authkit.QrSessionRequest{TTL: time.Nanosecond})
	if err != nil {
		t.Fatalf("CreateQrSession: %v", err)
	}
	time.Sleep(time.Millisecond)
	if _, err := c.HandleQrScanned(ctx, sess.QrUUID); err == nil {
		t.Fatalf("expected expired error")
	}
}

// extractState 从 fakeAdapter 生成的 URL 中取出 state 参数。
func extractState(t *testing.T, u string) string {
	t.Helper()
	i := len("https://fake.example.com/authorize?state=")
	if len(u) <= i {
		t.Fatalf("unexpected url: %s", u)
	}
	rest := u[i:]
	for j := 0; j < len(rest); j++ {
		if rest[j] == '&' {
			return rest[:j]
		}
	}
	return rest
}
