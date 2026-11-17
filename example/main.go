package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"time"

	"github.com/xm-utils/authkit"
	"github.com/xm-utils/authkit/adapter/alipay"
	"github.com/xm-utils/authkit/adapter/douyin"
	"github.com/xm-utils/authkit/adapter/github"
)

// 本示例演示 authkit 的完整接入方式，可离线直接运行：
//
//	go run ./example
//
// 覆盖：组件初始化、三方授权登录（未绑定→绑定→已绑定）、扫码登录状态机全流程、
// 真实适配器（支付宝 / 抖音）通过 WithEndpoints 注入 httptest mock 端点的装配方式、
// TOTP 第二因子与 GitHub OAuth / 扫码共存的两段式登录（三件套注入 + RequireSecondFactor 衔接）。
// 业务侧接入成本被压缩为三件事：实现存储 SPI、注册平台适配器、按需注册钩子。
func main() {
	logger := authkit.NewSlogLogger(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})))

	// 1. 注入存储 SPI（生产环境替换为 Redis / MySQL / 配置中心实现）。
	stateStore := authkit.NewMemStateStorage()
	configStore := NewMemConfigStorage()
	mappingStore := NewMemUserMappingStorage()
	qrStore := NewMemQrSessionStorage()

	// 配置一个 demo 平台（演示用，真实场景配置 wechat/github 等）。
	configStore.Put(&authkit.PlatformConfig{
		Platform:     "demo",
		ClientID:     "demo-client-id",
		ClientSecret: "demo-client-secret",
		RedirectURI:  "https://login.example.com/auth/callback",
		Scopes:       []string{"user"},
	})

	// 启动本地 mock 平台（httptest），把真实支付宝/抖音/GitHub 适配器的端点注入到 mock 服务，
	// 全程离线运行；生产环境直接 NewAdapter() 使用官方默认端点，无需 WithEndpoints。
	mockSrv, mockAlipayPubB64 := startMockPlatform()
	defer mockSrv.Close()
	ghSrv := startMockGitHub()
	defer ghSrv.Close()
	mockPrivB64, _ := newMockAlipayKeyPair() // 演示用应用私钥（请求签名），公钥以 mock 侧为准

	configStore.Put(&authkit.PlatformConfig{
		Platform:    "alipay",
		ClientID:    "2021000000000000", // AppID
		RedirectURI: "https://login.example.com/auth/callback/alipay",
		Scopes:      []string{"auth_user"},
		Extra: map[string]string{
			"PrivateKey":      mockPrivB64,      // 应用私钥：请求签名必填
			"AlipayPublicKey": mockAlipayPubB64, // 支付宝公钥：配置后对响应验签
		},
	})
	configStore.Put(&authkit.PlatformConfig{
		Platform:     "douyin",
		ClientID:     "mock-client-key",
		ClientSecret: "mock-client-secret",
		RedirectURI:  "https://login.example.com/auth/callback/douyin",
		Scopes:       []string{"user_info"},
	})
	configStore.Put(&authkit.PlatformConfig{
		Platform:     "github",
		ClientID:     "mock-client-id",
		ClientSecret: "mock-client-secret",
		RedirectURI:  "https://login.example.com/auth/callback/github",
		Scopes:       []string{"user:email"},
	})

	// 第二因子存储（启用 TOTP 时额外需要的 2 个 SPI）。
	totpSecretStore := NewMemTOTPSecretStorage()
	otpConsumeStore := NewMemOTPConsumeStorage()

	// 2. 构建组件：显式注入配置、存储、适配器、白名单、钩子。
	component, err := authkit.New(
		authkit.WithConfig(authkit.Config{
			StateTTL:   300 * time.Second,
			QrTTL:      120 * time.Second,
			EnablePKCE: true, // 演示 PKCE 开启
		}),
		authkit.WithStateStorage(stateStore),
		authkit.WithConfigStorage(configStore),
		authkit.WithUserMappingStorage(mappingStore),
		authkit.WithQrSessionStorage(qrStore),
		authkit.WithAdapter(DemoAdapter{}),
		authkit.WithAdapter(alipay.NewAdapter(alipay.WithEndpoints(mockSrv.URL+"/authorize.htm", mockSrv.URL+"/gateway.do"))),
		authkit.WithAdapter(douyin.NewAdapter(douyin.WithEndpoints(
			mockSrv.URL+"/platform/oauth/connect",
			mockSrv.URL+"/oauth/access_token",
			mockSrv.URL+"/oauth/userinfo",
		))),
		authkit.WithAdapter(github.NewAdapter(github.WithEndpoints(
			ghSrv.URL+"/login/oauth/authorize",
			ghSrv.URL+"/login/oauth/access_token",
			ghSrv.URL+"/user",
			ghSrv.URL+"/user/emails",
		))),
		authkit.WithCallbackWhitelist("login.example.com"),
		authkit.WithLogger(logger),
		authkit.WithLoginSuccessHandler(jwtLoginSuccessHandler{}),
		// 第二因子三件套：必须同时注入，缺一则 New 直接报 ErrStorageNotConfigured；
		// 不注入则组件行为与旧版完全一致（纯加法扩展，上方 demo/alipay/douyin 流程不受影响）。
		authkit.WithTOTPProvider(authkit.NewTOTPProvider(authkit.TOTPConfig{Issuer: "authkit-demo"})),
		authkit.WithTOTPSecretStorage(totpSecretStore),
		authkit.WithOTPConsumeStorage(otpConsumeStore),
	)
	if err != nil {
		fmt.Println("初始化组件失败:", err)
		os.Exit(1)
	}

	ctx := context.Background()

	fmt.Println("==================== 三方授权登录 ====================")
	thirdLogin(ctx, component)

	fmt.Println()
	fmt.Println("==================== 扫码登录 ========================")
	qrLogin(ctx, component)

	fmt.Println()
	fmt.Println("============ 真实适配器（支付宝 / 抖音）================")
	realAdapterLogin(ctx, component, "alipay", "local-user-2001")
	realAdapterLogin(ctx, component, "douyin", "local-user-2002")

	fmt.Println()
	fmt.Println("======== TOTP 第二因子 × GitHub OAuth 两段式 =======")
	totpOAuthLogin(ctx, component)

	fmt.Println()
	fmt.Println("======== TOTP 第二因子 × 扫码登录两段式 ==========")
	totpQrLogin(ctx, component)
}

// thirdLogin 演示三方授权登录：首次未绑定 → 业务引导绑定 → 再次登录已绑定。
func thirdLogin(ctx context.Context, c authkit.Component) {
	// 1) 前端请求授权地址。
	authURL, err := c.BuildAuthURL(ctx, authkit.AuthURLRequest{
		Platform:    "demo",
		RedirectURI: "https://login.example.com/auth/callback",
		ClientIP:    "203.0.113.10",
	})
	if err != nil {
		fmt.Println("BuildAuthURL 失败:", err)
		return
	}
	fmt.Println("授权跳转地址:", authURL)

	state := parseState(authURL)

	// 2) 模拟用户在 demo 平台授权后，平台回调携带 code+state。
	result, err := c.HandleCallback(ctx, authkit.CallbackRequest{
		Platform: "demo",
		Code:     "auth-code-xyz",
		State:    state,
		ClientIP: "203.0.113.10",
	})
	if err != nil {
		fmt.Println("HandleCallback 失败:", err)
		return
	}

	if !result.Bound {
		fmt.Printf("未绑定：需引导注册/绑定，三方用户=%s(%s)\n", result.ThirdUser.Nickname, result.ThirdUser.OpenID)
		// 3) 业务侧引导用户绑定到本地账号（例如 local-user-1001）。
		if err := c.BindUser(ctx, "local-user-1001", *result.ThirdUser, ""); err != nil {
			fmt.Println("BindUser 失败:", err)
			return
		}
		fmt.Println("已完成绑定：local-user-1001 <-> ", result.ThirdUser.OpenID)
	}

	// 4) 重新走一次登录，验证已绑定分支并触发登录成功钩子。
	authURL2, _ := c.BuildAuthURL(ctx, authkit.AuthURLRequest{Platform: "demo", ClientIP: "203.0.113.10"})
	result2, err := c.HandleCallback(ctx, authkit.CallbackRequest{
		Platform: "demo", Code: "auth-code-2", State: parseState(authURL2), ClientIP: "203.0.113.10",
	})
	if err != nil {
		fmt.Println("第二次 HandleCallback 失败:", err)
		return
	}
	fmt.Printf("已绑定登录：Bound=%v LocalUserID=%s 业务令牌=%v\n", result2.Bound, result2.LocalUserID, result2.Ext["token"])

	// 5) 演示防重放：同一 state 再次使用会被拒绝。
	if _, err := c.HandleCallback(ctx, authkit.CallbackRequest{
		Platform: "demo", Code: "auth-code-2", State: parseState(authURL2), ClientIP: "203.0.113.10",
	}); err != nil {
		fmt.Println("重放被拒绝（预期）:", err)
	}
}

// realAdapterLogin 演示真实适配器的完整编排：同一个组件实例下，支付宝/抖音与 demo 平台
// 共用存储、安全校验与钩子，差异全部收敛在适配器内部（签名、响应解包等）。
// 流程：取授权地址 → 模拟回调（未绑定）→ BindUser → 再次登录（已绑定，触发钩子）。
func realAdapterLogin(ctx context.Context, c authkit.Component, platform, localUserID string) {
	authURL, err := c.BuildAuthURL(ctx, authkit.AuthURLRequest{
		Platform: platform,
		ClientIP: "203.0.113.20",
	})
	if err != nil {
		fmt.Printf("[%s] BuildAuthURL 失败: %v\n", platform, err)
		return
	}
	fmt.Printf("[%s] 授权跳转地址: %s\n", platform, authURL)

	result, err := c.HandleCallback(ctx, authkit.CallbackRequest{
		Platform: platform,
		Code:     "mock-auth-code",
		State:    parseState(authURL),
		ClientIP: "203.0.113.20",
	})
	if err != nil {
		fmt.Printf("[%s] HandleCallback 失败: %v\n", platform, err)
		return
	}
	if !result.Bound {
		fmt.Printf("[%s] 未绑定，三方用户=%s(open_id=%s union_id=%s)\n",
			platform, result.ThirdUser.Nickname, result.ThirdUser.OpenID, result.ThirdUser.UnionID)
		if err := c.BindUser(ctx, localUserID, *result.ThirdUser, ""); err != nil {
			fmt.Printf("[%s] BindUser 失败: %v\n", platform, err)
			return
		}
		fmt.Printf("[%s] 已完成绑定: %s <-> %s\n", platform, localUserID, result.ThirdUser.BindKey())
	}

	// 再次登录，验证已绑定分支并触发登录成功钩子。
	authURL2, _ := c.BuildAuthURL(ctx, authkit.AuthURLRequest{Platform: platform, ClientIP: "203.0.113.20"})
	result2, err := c.HandleCallback(ctx, authkit.CallbackRequest{
		Platform: platform, Code: "mock-auth-code-2", State: parseState(authURL2), ClientIP: "203.0.113.20",
	})
	if err != nil {
		fmt.Printf("[%s] 第二次 HandleCallback 失败: %v\n", platform, err)
		return
	}
	fmt.Printf("[%s] 已绑定登录：Bound=%v LocalUserID=%s 业务令牌=%v\n", platform, result2.Bound, result2.LocalUserID, result2.Ext["token"])
}

// qrLogin 演示扫码登录状态机：创建 → 扫码 → 确认 → 获取结果。
func qrLogin(ctx context.Context, c authkit.Component) {
	session, err := c.CreateQrSession(ctx, authkit.QrSessionRequest{
		TTL: 60 * time.Second,
		Device: authkit.DeviceInfo{
			DeviceID: "pc-001", Model: "MacBook Pro", IP: "198.51.100.7", Location: "上海",
		},
	})
	if err != nil {
		fmt.Println("CreateQrSession 失败:", err)
		return
	}
	fmt.Printf("二维码已生成: qr_uuid=%s 过期=%s 状态=%s\n", session.QrUUID, session.ExpiresAt.Format("15:04:05"), session.Status)

	// 移动端扫码，拿到发起端设备信息展示给用户核对（防钓鱼）。
	device, err := c.HandleQrScanned(ctx, session.QrUUID)
	if err != nil {
		fmt.Println("HandleQrScanned 失败:", err)
		return
	}
	fmt.Printf("已扫码，请核对发起设备: %s / %s / %s\n", device.Model, device.IP, device.Location)

	// 移动端确认登录。
	if err := c.ConfirmQrLogin(ctx, session.QrUUID, "local-user-1001", ""); err != nil {
		fmt.Println("ConfirmQrLogin 失败:", err)
		return
	}

	// 发起端轮询获取最终结果。
	got, err := c.GetQrSession(ctx, session.QrUUID)
	if err != nil {
		fmt.Println("GetQrSession 失败:", err)
		return
	}
	fmt.Printf("扫码登录完成: 状态=%s 本地用户=%s\n", got.Status, got.LocalUserID)
}

// totpOAuthLogin 演示 GitHub OAuth 与 TOTP 第二因子共存的两段式登录：
// 首次登录（未绑二因子，正常签发）→ 绑定验证器 → 再次登录被要求二因子（会话延后）→ 补口令后签发。
func totpOAuthLogin(ctx context.Context, c authkit.Component) {
	// 1) 首次 GitHub 登录：未绑定三方账号 → 引导绑定。此时尚未绑 TOTP，行为与普通登录一致。
	authURL, err := c.BuildAuthURL(ctx, authkit.AuthURLRequest{Platform: "github", ClientIP: "203.0.113.30"})
	if err != nil {
		fmt.Println("[github] BuildAuthURL 失败:", err)
		return
	}
	result, err := c.HandleCallback(ctx, authkit.CallbackRequest{
		Platform: "github", Code: "gh-auth-code", State: parseState(authURL), ClientIP: "203.0.113.30",
	})
	if err != nil {
		fmt.Println("[github] HandleCallback 失败:", err)
		return
	}
	if !result.Bound {
		if err := c.BindUser(ctx, "local-user-3001", *result.ThirdUser, ""); err != nil {
			fmt.Println("[github] BindUser 失败:", err)
			return
		}
		fmt.Printf("[github] 已完成绑定: local-user-3001 <-> %s(%s)\n", result.ThirdUser.Nickname, result.ThirdUser.OpenID)
	}

	// 2) 绑定验证器：拿到 Secret 与 otpauth 地址（真实场景渲染为二维码用谷歌身份验证器扫码）。
	enroll, err := c.EnrollTOTP(ctx, authkit.TOTPEnrollRequest{LocalUserID: "local-user-3001", AccountName: "octocat@example.com"})
	if err != nil {
		fmt.Println("[github] EnrollTOTP 失败:", err)
		return
	}
	fmt.Println("[github] 验证器绑定成功, 扫码地址:", enroll.ProvisioningURI)

	// 3) 再次登录：身份已确认，但被要求第二因子 —— RequireSecondFactor=true 且会话未签发。
	authURL2, _ := c.BuildAuthURL(ctx, authkit.AuthURLRequest{Platform: "github", ClientIP: "203.0.113.30"})
	res, err := c.HandleCallback(ctx, authkit.CallbackRequest{
		Platform: "github", Code: "gh-auth-code-2", State: parseState(authURL2), ClientIP: "203.0.113.30",
	})
	if err != nil {
		fmt.Println("[github] 第二段 HandleCallback 失败:", err)
		return
	}
	fmt.Printf("[github] 第一段完成: Bound=%v RequireSecondFactor=%v 会话令牌=%v（预期为空，签发已延后）\n",
		res.Bound, res.RequireSecondFactor, res.Ext["token"])

	// 4) 前端跳验证码页 → 用户提交 6 位口令 → VerifyTOTP 补签会话。
	// 演示用 mock_authenticator 按绑定时拿到的 Secret 现算口令（真实场景由手机端生成）。
	code := authenticatorCode(enroll.Secret, time.Now())
	final, err := c.VerifyTOTP(ctx, authkit.TOTPVerifyRequest{LocalUserID: res.LocalUserID, Code: code})
	if err != nil {
		fmt.Println("[github] VerifyTOTP 失败:", err)
		return
	}
	fmt.Printf("[github] 第二段完成: 验证码=%s 已签发会话令牌=%v\n", code, final.Ext["token"])

	// 5) 同一口令重放被拒（防重放窗口内，预期 ErrOTPReused）。
	if _, err := c.VerifyTOTP(ctx, authkit.TOTPVerifyRequest{LocalUserID: "local-user-3001", Code: code}); errors.Is(err, authkit.ErrOTPReused) {
		fmt.Println("[github] 同口令重放被拒绝（预期）:", err)
	} else {
		fmt.Println("[github] 重放未被拒绝，不符合预期:", err)
	}
}

// totpQrLogin 演示扫码登录与 TOTP 共存：已绑验证器的用户确认后会话同样延后，补齐口令才签发；
// 未绑定用户（如前面 qrLogin 演示的 local-user-1001）完全不受影响，两个入口正交共存。
func totpQrLogin(ctx context.Context, c authkit.Component) {
	enroll, err := c.EnrollTOTP(ctx, authkit.TOTPEnrollRequest{LocalUserID: "local-user-3002", AccountName: "qr-user@example.com"})
	if err != nil {
		fmt.Println("[qr+totp] EnrollTOTP 失败:", err)
		return
	}

	session, err := c.CreateQrSession(ctx, authkit.QrSessionRequest{
		TTL: 60 * time.Second,
		Device: authkit.DeviceInfo{
			DeviceID: "pc-002", Model: "Windows PC", IP: "198.51.100.8", Location: "北京",
		},
	})
	if err != nil {
		fmt.Println("[qr+totp] CreateQrSession 失败:", err)
		return
	}
	if _, err := c.HandleQrScanned(ctx, session.QrUUID); err != nil {
		fmt.Println("[qr+totp] HandleQrScanned 失败:", err)
		return
	}
	// 移动端确认：状态机置为已确认，但该用户已绑验证器，会话签发被闸门拦下。
	if err := c.ConfirmQrLogin(ctx, session.QrUUID, "local-user-3002", ""); err != nil {
		fmt.Println("[qr+totp] ConfirmQrLogin 失败:", err)
		return
	}
	got, _ := c.GetQrSession(ctx, session.QrUUID)
	require, _ := c.RequireSecondFactor(ctx, "local-user-3002", "")
	fmt.Printf("[qr+totp] 扫码已确认: 状态=%s 本地用户=%s 需要第二因子=%v（令牌尚未签发）\n", got.Status, got.LocalUserID, require)

	// 补齐口令后签发会话。
	code := authenticatorCode(enroll.Secret, time.Now())
	final, err := c.VerifyTOTP(ctx, authkit.TOTPVerifyRequest{LocalUserID: "local-user-3002", Code: code})
	if err != nil {
		fmt.Println("[qr+totp] VerifyTOTP 失败:", err)
		return
	}
	fmt.Printf("[qr+totp] 二段完成: 验证码=%s 已签发会话令牌=%v\n", code, final.Ext["token"])
}

// parseState 从授权地址中解析 state 参数（模拟平台回调带回的 state）。
func parseState(authURL string) string {
	u, err := url.Parse(authURL)
	if err != nil {
		return ""
	}
	return u.Query().Get("state")
}
