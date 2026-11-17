package authkit

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Component 组件主入口，所有对外能力收敛于此接口。
type Component interface {
	// BuildAuthURL 生成三方授权跳转地址，同时落一笔 state 存储。
	BuildAuthURL(ctx context.Context, req AuthURLRequest) (string, error)

	// HandleCallback 处理三方平台回调，返回统一登录结果。
	HandleCallback(ctx context.Context, req CallbackRequest) (*LoginResult, error)

	// BindUser 建立本地用户与三方账号的绑定关系。
	BindUser(ctx context.Context, localUserID string, user ThirdPartyUser, tenantID string) error

	// UnbindUser 解除绑定关系。
	UnbindUser(ctx context.Context, localUserID, platform, tenantID string) error

	// CreateQrSession 创建扫码会话，返回二维码标识与过期时间。
	CreateQrSession(ctx context.Context, req QrSessionRequest) (*QrSession, error)

	// HandleQrScanned 处理移动端扫码动作，状态置为已扫描，返回发起端设备信息供核对。
	HandleQrScanned(ctx context.Context, qrUUID string) (*DeviceInfo, error)

	// ConfirmQrLogin 处理移动端确认登录，状态置为已确认。
	ConfirmQrLogin(ctx context.Context, qrUUID, localUserID, tenantID string) error

	// CancelQrLogin 处理移动端取消登录。
	CancelQrLogin(ctx context.Context, qrUUID string) error

	// GetQrSession 供发起端查询会话状态，实现轮询或推送后的落地。
	GetQrSession(ctx context.Context, qrUUID string) (*QrSession, error)

	// ---- 第二因子（TOTP / 谷歌验证码等），未装配 Provider 时相关方法返回 ErrSecondFactorUnsupported ----

	// EnrollTOTP 为用户生成并绑定新的第二因子密钥，返回密钥与 otpauth 绑定地址。
	EnrollTOTP(ctx context.Context, req TOTPEnrollRequest) (*TOTPEnrollResult, error)

	// VerifyTOTP 校验第二因子口令；通过后触发登录成功钩子并返回最终 LoginResult。
	// 用于 HandleCallback / ConfirmQrLogin 返回 RequireSecondFactor=true 后的二步收敛。
	VerifyTOTP(ctx context.Context, req TOTPVerifyRequest) (*LoginResult, error)

	// DisableTOTP 解绑用户的第二因子密钥。
	DisableTOTP(ctx context.Context, userID, tenantID string) error

	// RequireSecondFactor 查询指定用户当前是否需要第二因子，供登录 UI 决策。
	// 未装配第二因子时恒返回 (false, nil)。
	RequireSecondFactor(ctx context.Context, userID, tenantID string) (bool, error)
}

// defaultComponent 是 Component 的默认实现，不持有任何会话状态，可集群共享。
type defaultComponent struct {
	cfg       Config
	state     StateStorage
	config    ConfigStorage
	mapping   UserMappingStorage
	qr        QrSessionStorage
	adapters  map[string]PlatformAdapter
	whitelist []string
	logger    Logger

	success   LoginSuccessHandler
	converter UserInfoConverter
	exception ExceptionHandler
	qrGen     QrCodeGenerator

	totpProvider TOTPProvider
	totpSecret   TOTPSecretStorage
	otpConsume   OTPConsumeStorage
	sfPolicy     SecondFactorPolicy
}

// New 构建组件实例，未注入的必需项会在构建阶段直接报错，不留到运行时。
func New(opts ...Option) (Component, error) {
	var o options
	for _, fn := range opts {
		fn(&o)
	}
	o.cfg.normalize()

	// 四项存储为必需依赖，缺失即在构造期报错。
	if o.state == nil {
		return nil, fmt.Errorf("%w: StateStorage", ErrStorageNotConfigured)
	}
	if o.config == nil {
		return nil, fmt.Errorf("%w: ConfigStorage", ErrStorageNotConfigured)
	}
	if o.mapping == nil {
		return nil, fmt.Errorf("%w: UserMappingStorage", ErrStorageNotConfigured)
	}
	if o.qr == nil {
		return nil, fmt.Errorf("%w: QrSessionStorage", ErrStorageNotConfigured)
	}

	adapters := make(map[string]PlatformAdapter, len(o.adapters))
	for _, a := range o.adapters {
		if a == nil {
			return nil, fmt.Errorf("%w: nil adapter", ErrInvalidParam)
		}
		name := a.PlatformName()
		if name == "" {
			return nil, fmt.Errorf("%w: adapter with empty platform name", ErrInvalidParam)
		}
		if _, dup := adapters[name]; dup {
			return nil, fmt.Errorf("%w: duplicate adapter %q", ErrInvalidParam, name)
		}
		adapters[name] = a
	}

	// 第二因子三件套：任一注入则必须全部注入，避免半装配导致安全能力失效。
	sfAny := o.totpProvider != nil || o.totpSecret != nil || o.otpConsume != nil
	if sfAny && (o.totpProvider == nil || o.totpSecret == nil || o.otpConsume == nil) {
		return nil, fmt.Errorf("%w: TOTPProvider/TOTPSecretStorage/OTPConsumeStorage must be injected together", ErrStorageNotConfigured)
	}

	logger := o.logger
	if logger == nil {
		logger = nopLogger{}
	}

	return &defaultComponent{
		cfg:       o.cfg,
		state:     o.state,
		config:    o.config,
		mapping:   o.mapping,
		qr:        o.qr,
		adapters:  adapters,
		whitelist: o.whitelist,
		logger:    logger,
		success:   o.success,
		converter: o.converter,
		exception: o.exception,
		qrGen:     o.qrGen,

		totpProvider: o.totpProvider,
		totpSecret:   o.totpSecret,
		otpConsume:   o.otpConsume,
		sfPolicy:     o.sfPolicy,
	}, nil
}

// adapter 按平台名取适配器，未注册返回 ErrAdapterNotRegistered。
func (c *defaultComponent) adapter(platform string) (PlatformAdapter, error) {
	if platform == "" {
		return nil, fmt.Errorf("%w: empty platform", ErrInvalidParam)
	}
	a, ok := c.adapters[platform]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrAdapterNotRegistered, platform)
	}
	return a, nil
}

// fail 统一经异常处理器转换错误；处理器返回 nil 时保留原错误。
func (c *defaultComponent) fail(ctx context.Context, err error) error {
	if c.exception != nil {
		if mapped := c.exception.Handle(ctx, err); mapped != nil {
			return mapped
		}
	}
	return err
}

// BuildAuthURL 生成三方授权跳转地址。
func (c *defaultComponent) BuildAuthURL(ctx context.Context, req AuthURLRequest) (string, error) {
	a, err := c.adapter(req.Platform)
	if err != nil {
		return "", c.fail(ctx, err)
	}
	cfg, err := c.config.GetConfig(ctx, req.Platform, req.TenantID)
	if err != nil {
		return "", c.fail(ctx, err) // ErrPlatformNotConfigured 原样透出
	}

	redirect := req.RedirectURI
	if redirect == "" {
		redirect = cfg.RedirectURI
	}
	if err := checkCallbackWhitelist(redirect, c.whitelist); err != nil {
		return "", c.fail(ctx, err)
	}

	state := generateState()
	meta := StateMeta{
		State:       state,
		Platform:    req.Platform,
		TenantID:    req.TenantID,
		ClientIP:    req.ClientIP,
		RedirectURI: redirect,
		CreatedAt:   time.Now().UTC(),
		Ext:         req.Ext,
	}
	ext := copyExt(req.Ext)
	if c.cfg.EnablePKCE {
		verifier := generateCodeVerifier()
		meta.CodeVerifier = verifier
		ext[ExtraKeyCodeChallenge] = codeChallenge(verifier)
		ext[ExtraKeyCodeChallengeMethod] = "S256"
	}

	if err := c.state.SaveState(ctx, state, meta, c.cfg.StateTTL); err != nil {
		return "", c.fail(ctx, err)
	}

	authURL, err := a.BuildAuthorizationURL(state, cfg, ext)
	if err != nil {
		return "", c.fail(ctx, err)
	}
	c.logger.Info("authkit: build auth url", "platform", req.Platform, "tenant", req.TenantID)
	return authURL, nil
}

// HandleCallback 处理三方平台回调，返回统一登录结果。
func (c *defaultComponent) HandleCallback(ctx context.Context, req CallbackRequest) (*LoginResult, error) {
	if req.Code == "" || req.State == "" {
		return nil, c.fail(ctx, fmt.Errorf("%w: empty code or state", ErrInvalidParam))
	}
	a, err := c.adapter(req.Platform)
	if err != nil {
		return nil, c.fail(ctx, err)
	}
	cfg, err := c.config.GetConfig(ctx, req.Platform, req.TenantID)
	if err != nil {
		return nil, c.fail(ctx, err)
	}

	// 取出并立即删除 state（原子性由存储保证）。
	meta, err := c.state.GetAndDeleteState(ctx, req.State)
	if err != nil {
		if errors.Is(err, ErrStateNotFound) {
			return nil, c.fail(ctx, ErrStateNotFound)
		}
		return nil, c.fail(ctx, err)
	}
	// 校验 state 与本次请求的绑定关系，任一不符判定为非法。
	if meta.Platform != req.Platform || meta.TenantID != req.TenantID {
		c.logger.Warn("authkit: state platform/tenant mismatch", "platform", req.Platform)
		return nil, c.fail(ctx, ErrStateInvalid)
	}
	if meta.ClientIP != "" && req.ClientIP != "" && meta.ClientIP != req.ClientIP {
		c.logger.Warn("authkit: state client ip mismatch", "platform", req.Platform)
		return nil, c.fail(ctx, ErrStateInvalid)
	}

	// 开启 PKCE 时，把 verifier 通过 cfg.Extra 注入适配器。
	c.applyVerifier(cfg, meta.CodeVerifier)

	token, err := a.ExchangeToken(ctx, req.Code, cfg)
	if err != nil {
		return nil, c.fail(ctx, fmt.Errorf("%w: %v", ErrCodeExchangeFailed, err))
	}
	user, err := a.FetchUserInfo(ctx, token, cfg)
	if err != nil {
		return nil, c.fail(ctx, fmt.Errorf("%w: %v", ErrFetchUserFailed, err))
	}
	if user.Platform == "" {
		user.Platform = req.Platform
	}

	result := &LoginResult{ThirdUser: user, Token: token}

	// 用户信息转换器（可选）。
	if c.converter != nil {
		if converted, cerr := c.converter.Convert(ctx, user); cerr != nil {
			c.logger.Warn("authkit: user info convert failed", "err", cerr)
		} else if converted != nil {
			result.setExt("converted_user", converted)
		}
	}

	// 查询绑定关系，优先 UnionID。
	key := user.BindKey()
	if key == "" {
		return nil, c.fail(ctx, fmt.Errorf("%w: empty bind key", ErrInvalidParam))
	}
	localUserID, found, err := c.mapping.GetLocalUserID(ctx, req.Platform, key, req.TenantID)
	if err != nil {
		return nil, c.fail(ctx, err)
	}

	if found {
		result.Bound = true
		result.LocalUserID = localUserID
		// 经第二因子衔接决定是否即刻签发会话（未配置第二因子时行为与旧版完全一致）。
		if err := c.finalizeLogin(ctx, result, req.TenantID); err != nil {
			return nil, c.fail(ctx, err)
		}
		if result.RequireSecondFactor {
			c.logger.Info("authkit: third-party login pending second factor", "platform", req.Platform)
			return result, nil
		}
		c.logger.Info("authkit: third-party login success", "platform", req.Platform, "bound", true)
		return result, nil
	}

	// 未绑定：返回三方用户信息，由业务侧引导注册或绑定。
	result.Bound = false
	c.logger.Info("authkit: third-party login need bind", "platform", req.Platform)
	return result, nil
}

// applyVerifier 将 code_verifier 注入 cfg.Extra（就地修改，cfg 为每次实时读取的副本）。
func (c *defaultComponent) applyVerifier(cfg *PlatformConfig, verifier string) {
	if verifier == "" {
		return
	}
	if cfg.Extra == nil {
		cfg.Extra = map[string]string{}
	}
	cfg.Extra[ExtraKeyCodeVerifier] = verifier
}

// triggerLoginSuccess 调用登录成功钩子；异常仅记录日志，不阻断主流程。
func (c *defaultComponent) triggerLoginSuccess(ctx context.Context, result *LoginResult) {
	if c.success == nil {
		return
	}
	ext, err := c.success.OnLoginSuccess(ctx, result)
	if err != nil {
		c.logger.Warn("authkit: login success handler error", "err", err)
		return
	}
	for k, v := range ext {
		result.setExt(k, v)
	}
}

// sfConfigured 报告第二因子三件套是否已完整装配。
func (c *defaultComponent) sfConfigured() bool {
	return c.totpProvider != nil && c.totpSecret != nil && c.otpConsume != nil
}

// secondFactorRequired 判定某次登录是否需要第二因子。
// 未装配时恒 false；已装配但无自定义策略时采用「已绑定密钥即要求」。
func (c *defaultComponent) secondFactorRequired(ctx context.Context, userID, tenantID string) (bool, error) {
	if !c.sfConfigured() || userID == "" {
		return false, nil
	}
	if c.sfPolicy != nil {
		return c.sfPolicy.RequireSecondFactor(ctx, userID, tenantID)
	}
	_, found, err := c.totpSecret.GetSecret(ctx, userID, tenantID)
	return found, err
}

// finalizeLogin 是会话签发前的统一闸门：若需第二因子且尚未通过，则置 RequireSecondFactor
// 且不触发 LoginSuccessHandler（避免提前签发会话）。无需二因子时行为与旧版一致。
func (c *defaultComponent) finalizeLogin(ctx context.Context, result *LoginResult, tenantID string) error {
	require, err := c.secondFactorRequired(ctx, result.LocalUserID, tenantID)
	if err != nil {
		return err
	}
	if require {
		result.RequireSecondFactor = true
		return nil
	}
	c.triggerLoginSuccess(ctx, result)
	return nil
}

// EnrollTOTP 为用户生成并绑定第二因子密钥。
func (c *defaultComponent) EnrollTOTP(ctx context.Context, req TOTPEnrollRequest) (*TOTPEnrollResult, error) {
	if !c.sfConfigured() {
		return nil, c.fail(ctx, ErrSecondFactorUnsupported)
	}
	if req.LocalUserID == "" {
		return nil, c.fail(ctx, fmt.Errorf("%w: empty local user id", ErrInvalidParam))
	}
	_, found, err := c.totpSecret.GetSecret(ctx, req.LocalUserID, req.TenantID)
	if err != nil {
		return nil, c.fail(ctx, err)
	}
	if found && !req.Overwrite {
		return nil, c.fail(ctx, ErrSecondFactorAlreadyEnrolled)
	}
	secret, err := c.totpProvider.GenerateSecret(ctx)
	if err != nil {
		return nil, c.fail(ctx, err)
	}
	if err := c.totpSecret.SaveSecret(ctx, req.LocalUserID, req.TenantID, secret); err != nil {
		return nil, c.fail(ctx, err)
	}
	account := req.AccountName
	if account == "" {
		account = req.LocalUserID
	}
	c.logger.Info("authkit: totp enrolled", "user", req.LocalUserID, "tenant", req.TenantID)
	return &TOTPEnrollResult{Secret: secret, ProvisioningURI: c.totpProvider.ProvisioningURI(secret, account)}, nil
}

// VerifyTOTP 校验第二因子口令，通过后签发会话（触发登录成功钩子）。
func (c *defaultComponent) VerifyTOTP(ctx context.Context, req TOTPVerifyRequest) (*LoginResult, error) {
	if !c.sfConfigured() {
		return nil, c.fail(ctx, ErrSecondFactorUnsupported)
	}
	if req.LocalUserID == "" || req.Code == "" {
		return nil, c.fail(ctx, fmt.Errorf("%w: empty user id or code", ErrInvalidParam))
	}
	secret, found, err := c.totpSecret.GetSecret(ctx, req.LocalUserID, req.TenantID)
	if err != nil {
		return nil, c.fail(ctx, err)
	}
	if !found {
		return nil, c.fail(ctx, ErrSecondFactorNotEnrolled)
	}
	ok, err := c.totpProvider.Verify(ctx, secret, req.Code)
	if err != nil {
		return nil, c.fail(ctx, err)
	}
	if !ok {
		c.logger.Warn("authkit: totp verify failed", "user", req.LocalUserID)
		return nil, c.fail(ctx, ErrOTPInvalid)
	}
	// 防重放：同一主体内同一口令在窗口内只能用一次。subject 含提供方名，隔离不同二因子。
	subject := c.totpProvider.Name() + "|" + req.LocalUserID + "|" + req.TenantID
	firstUse, err := c.otpConsume.MarkUsed(ctx, subject, req.Code, c.cfg.SFReplayWindow)
	if err != nil {
		return nil, c.fail(ctx, err)
	}
	if !firstUse {
		c.logger.Warn("authkit: totp code replay", "user", req.LocalUserID)
		return nil, c.fail(ctx, ErrOTPReused)
	}
	result := &LoginResult{Bound: true, LocalUserID: req.LocalUserID}
	c.triggerLoginSuccess(ctx, result)
	c.logger.Info("authkit: totp verified", "user", req.LocalUserID)
	return result, nil
}

// DisableTOTP 解绑用户的第二因子密钥。
func (c *defaultComponent) DisableTOTP(ctx context.Context, userID, tenantID string) error {
	if !c.sfConfigured() {
		return c.fail(ctx, ErrSecondFactorUnsupported)
	}
	if userID == "" {
		return c.fail(ctx, fmt.Errorf("%w: empty user id", ErrInvalidParam))
	}
	if err := c.totpSecret.DeleteSecret(ctx, userID, tenantID); err != nil {
		return c.fail(ctx, err)
	}
	c.logger.Info("authkit: totp disabled", "user", userID, "tenant", tenantID)
	return nil
}

// RequireSecondFactor 查询指定用户当前是否需要第二因子。
func (c *defaultComponent) RequireSecondFactor(ctx context.Context, userID, tenantID string) (bool, error) {
	require, err := c.secondFactorRequired(ctx, userID, tenantID)
	if err != nil {
		return false, c.fail(ctx, err)
	}
	return require, nil
}

// BindUser 建立本地用户与三方账号的绑定关系。
func (c *defaultComponent) BindUser(ctx context.Context, localUserID string, user ThirdPartyUser, tenantID string) error {
	if localUserID == "" {
		return c.fail(ctx, fmt.Errorf("%w: empty local user id", ErrInvalidParam))
	}
	if user.BindKey() == "" {
		return c.fail(ctx, fmt.Errorf("%w: empty third party user id", ErrInvalidParam))
	}
	if err := c.mapping.BindUser(ctx, localUserID, user, tenantID); err != nil {
		return c.fail(ctx, err)
	}
	return nil
}

// UnbindUser 解除绑定关系。
func (c *defaultComponent) UnbindUser(ctx context.Context, localUserID, platform, tenantID string) error {
	if err := c.mapping.UnbindUser(ctx, localUserID, platform, tenantID); err != nil {
		return c.fail(ctx, err)
	}
	return nil
}

// CreateQrSession 创建扫码会话，状态置为 Pending。
func (c *defaultComponent) CreateQrSession(ctx context.Context, req QrSessionRequest) (*QrSession, error) {
	ttl := req.TTL
	if ttl <= 0 {
		ttl = c.cfg.QrTTL
	}
	if c.cfg.MinQrTTL > 0 && ttl < c.cfg.MinQrTTL {
		return nil, c.fail(ctx, fmt.Errorf("%w: ttl %v below min %v", ErrInvalidParam, ttl, c.cfg.MinQrTTL))
	}
	if c.cfg.MaxQrTTL > 0 && ttl > c.cfg.MaxQrTTL {
		return nil, c.fail(ctx, fmt.Errorf("%w: ttl %v above max %v", ErrInvalidParam, ttl, c.cfg.MaxQrTTL))
	}

	now := time.Now().UTC()
	qrUUID := uuid.NewString()
	session := QrSession{
		QrUUID:    qrUUID,
		Status:    QrStatusPending,
		Device:    req.Device,
		TenantID:  req.TenantID,
		CreatedAt: now,
		ExpiresAt: now.Add(ttl),
		Ext:       req.Ext,
	}
	if err := c.qr.CreateQrSession(ctx, qrUUID, session, ttl); err != nil {
		return nil, c.fail(ctx, err)
	}

	// 若注册了二维码生成器，生成图片字节并 base64 附带返回。
	if c.qrGen != nil {
		img, err := c.qrGen.Generate(ctx, qrUUID, ttl)
		if err != nil {
			c.logger.Warn("authkit: qr code generate failed", "err", err)
		} else if img != nil {
			if session.Ext == nil {
				session.Ext = map[string]string{}
			}
			session.Ext["qr_image_base64"] = base64Std(img)
		}
	}
	c.logger.Info("authkit: qr session created", "qr_uuid", qrUUID, "tenant", req.TenantID)
	return &session, nil
}

// HandleQrScanned 处理移动端扫码：会话须存在、未过期且处于 Pending，置为 Scanned。
func (c *defaultComponent) HandleQrScanned(ctx context.Context, qrUUID string) (*DeviceInfo, error) {
	session, err := c.loadQr(ctx, qrUUID)
	if err != nil {
		return nil, c.fail(ctx, err)
	}
	if session.Status != QrStatusPending {
		return nil, c.fail(ctx, ErrQrStatusConflict)
	}
	if err := c.qr.UpdateQrStatus(ctx, qrUUID, QrStatusScanned, ""); err != nil {
		return nil, c.fail(ctx, err)
	}
	device := session.Device
	return &device, nil
}

// ConfirmQrLogin 处理移动端确认登录：状态必须为 Scanned，置为 Confirmed 并写入用户。
func (c *defaultComponent) ConfirmQrLogin(ctx context.Context, qrUUID, localUserID, tenantID string) error {
	if localUserID == "" {
		return c.fail(ctx, fmt.Errorf("%w: empty local user id", ErrInvalidParam))
	}
	session, err := c.loadQr(ctx, qrUUID)
	if err != nil {
		return c.fail(ctx, err)
	}
	if session.Status != QrStatusScanned {
		return c.fail(ctx, ErrQrStatusConflict)
	}
	if tenantID != "" && session.TenantID != "" && tenantID != session.TenantID {
		return c.fail(ctx, ErrQrStatusConflict)
	}
	if err := c.qr.UpdateQrStatus(ctx, qrUUID, QrStatusConfirmed, localUserID); err != nil {
		return c.fail(ctx, err)
	}
	// 扫码确认同样经第二因子衔接：需二次验证时不触发登录成功钩子（会话签发延后到 VerifyTOTP）。
	// 发起端轮询得 Confirmed + LocalUserID 后，可调用 RequireSecondFactor 判断并引导输入验证码。
	lr := &LoginResult{Bound: true, LocalUserID: localUserID}
	if err := c.finalizeLogin(ctx, lr, tenantID); err != nil {
		return c.fail(ctx, err)
	}
	c.logger.Info("authkit: qr login confirmed", "qr_uuid", qrUUID, "user", localUserID, "pending_second_factor", lr.RequireSecondFactor)
	return nil
}

// CancelQrLogin 处理移动端取消登录：Pending/Scanned 可取消，终态拒绝。
func (c *defaultComponent) CancelQrLogin(ctx context.Context, qrUUID string) error {
	session, err := c.loadQr(ctx, qrUUID)
	if err != nil {
		return c.fail(ctx, err)
	}
	switch session.Status {
	case QrStatusPending, QrStatusScanned:
		if err := c.qr.UpdateQrStatus(ctx, qrUUID, QrStatusCanceled, ""); err != nil {
			return c.fail(ctx, err)
		}
		return nil
	default:
		return c.fail(ctx, ErrQrStatusConflict)
	}
}

// GetQrSession 供发起端查询会话状态。
func (c *defaultComponent) GetQrSession(ctx context.Context, qrUUID string) (*QrSession, error) {
	session, err := c.loadQr(ctx, qrUUID)
	if err != nil {
		return nil, c.fail(ctx, err)
	}
	return session, nil
}

// loadQr 读取会话并做二次过期校验：非终态且过期时置为 Expired 并返回 ErrQrExpired。
func (c *defaultComponent) loadQr(ctx context.Context, qrUUID string) (*QrSession, error) {
	if qrUUID == "" {
		return nil, fmt.Errorf("%w: empty qr uuid", ErrInvalidParam)
	}
	session, err := c.qr.GetQrSession(ctx, qrUUID)
	if err != nil {
		if errors.Is(err, ErrQrSessionNotFound) {
			return nil, ErrQrSessionNotFound
		}
		return nil, err
	}
	if session == nil {
		return nil, ErrQrSessionNotFound
	}
	if session.Status != QrStatusConfirmed &&
		session.Status != QrStatusCanceled &&
		time.Now().UTC().After(session.ExpiresAt) {
		// 尽力置为过期终态，忽略更新错误（可能已被存储淘汰）。
		_ = c.qr.UpdateQrStatus(ctx, qrUUID, QrStatusExpired, "")
		return nil, ErrQrExpired
	}
	return session, nil
}
