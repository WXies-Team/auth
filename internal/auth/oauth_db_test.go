package auth

import (
	"encoding/base64"
	"strings"
	"testing"
)

// OAuth 的真库端到端（无 TEST_MYSQL_DSN 跳过，留 CI）：登记 → 授权事务 →
// 确认发码 → 换 token → 复用拒 / PKCE 错拒 / redirect 不一致拒 / secret 轮换。

// oauthSetup 造一套完整现场：super 管理员 + 一个已注册用户 + calorie-diary 的
// 客户端登记（回 client_id 与一次性 secret）。
type oauthFixture struct {
	svc      *Service
	mailer   *recordMailer
	super    Caller
	user     Caller
	clientID string
	secret   string
}

func newOAuthFixture(t *testing.T) *oauthFixture {
	t.Helper()
	svc, mailer := newTestService(t)
	super := seedAdminUser(t, svc, mailer, "oauth-super@example.com", adminRoleSuper)
	user := newPasskeyUser(t, svc, mailer, "oauth-user@example.com")
	res, err := svc.AdminConfigureOAuth(super, AdminScope{Super: true}, "calorie-diary", AdminOAuthInput{
		RedirectUris: []string{"https://app.example.com/cb"},
	})
	if err != nil {
		t.Fatalf("开通 OAuth 客户端: %v", err)
	}
	if res.ClientID == "" || len(res.Secret) == 0 {
		t.Fatalf("首调应回 client_id 与一次性 secret，得到 %+v", res)
	}
	return &oauthFixture{svc: svc, mailer: mailer, super: super, user: user,
		clientID: res.ClientID, secret: res.Secret}
}

// verifier/challenge 对：verifier 从合法 base64url 字符集构造——RFC 7636 要求
// 43~128 位（pkceValueOK 按这个口径收），32 字节种子 base64url 后恰为 43 位。
func oauthPKCEPair(t *testing.T) (verifier, challenge string) {
	t.Helper()
	verifier = base64.RawURLEncoding.EncodeToString([]byte("fixed-verifier-seed-0001abcdefgh"))
	if !pkceValueOK(verifier) {
		t.Fatalf("测试 verifier 应合法: %q", verifier)
	}
	return verifier, pkceS256(verifier)
}

func TestOAuthEndToEndCodeFlow(t *testing.T) {
	f := newOAuthFixture(t)
	verifier, challenge := oauthPKCEPair(t)

	// ① 发起授权：验参数、落事务
	tx, app, err := f.svc.OAuthBeginAuthorize(OAuthAuthorizeRequest{
		ResponseType: "code", ClientID: f.clientID,
		RedirectURI: "https://app.example.com/cb", State: "st-1",
		CodeChallenge: challenge, CodeChallengeMethod: "S256",
	})
	if err != nil {
		t.Fatalf("发起授权: %v", err)
	}
	if app != "calorie-diary" || tx == "" {
		t.Fatalf("应解析到项目并回 tx，得到 app=%q tx=%q", app, tx)
	}

	// ② 确认页视图：绑定 uid + 展示信息齐
	view, err := f.svc.OAuthAuthorizeView(tx, f.user.UID)
	if err != nil {
		t.Fatalf("确认页视图: %v", err)
	}
	if view.AppName != "热量日记" || view.RedirectHost != "app.example.com" || view.Email != f.user.Email {
		t.Errorf("确认页信息不对: %+v", view)
	}

	// ③ deny：uid=0（未登录）拒
	if _, err := f.svc.OAuthAuthorizeView(tx, 0); err == nil {
		t.Error("未登录不该拿到确认页")
	}

	// ④ 确认 allow：回跳带 code+state
	redirect, err := f.svc.OAuthDecide(f.user.UID, tx, "allow", testMeta)
	if err != nil {
		t.Fatalf("确认授权: %v", err)
	}
	if !strings.Contains(redirect, "code=") || !strings.Contains(redirect, "state=st-1") {
		t.Fatalf("回跳应带 code 与 state，得到 %q", redirect)
	}
	code := redirect[strings.Index(redirect, "code=")+5:]
	code = code[:strings.IndexAny(code, "&")]

	// ⑤ 换 token：成功，JWT 可校验且 aud=calorie-diary
	res, err := f.svc.OAuthExchangeToken(OAuthTokenRequest{
		GrantType: "authorization_code", Code: code,
		RedirectURI: "https://app.example.com/cb",
		ClientID:    f.clientID, ClientSecret: f.secret, CodeVerifier: verifier,
	})
	if err != nil {
		t.Fatalf("换 token: %v", err)
	}
	if res.UID != f.user.UID || res.Email != f.user.Email || res.AccessToken == "" {
		t.Errorf("token 回执不对: %+v", res)
	}
	caller, err := f.svc.ValidUserID("Bearer " + res.AccessToken)
	if err != nil {
		t.Fatalf("签出的 JWT 应可校验: %v", err)
	}
	if caller.App != "calorie-diary" || caller.UID != f.user.UID {
		t.Errorf("JWT aud/uid 不对: %+v", caller)
	}

	// ⑥ 复用同一个 code：expired_token
	_, err = f.svc.OAuthExchangeToken(OAuthTokenRequest{
		GrantType: "authorization_code", Code: code,
		RedirectURI: "https://app.example.com/cb",
		ClientID:    f.clientID, ClientSecret: f.secret, CodeVerifier: verifier,
	})
	if oe, ok := err.(*OAuthError); !ok || oe.Code != "expired_token" {
		t.Errorf("复用应回 expired_token，得到 %v", err)
	}
}

func TestOAuthExchangeRejections(t *testing.T) {
	f := newOAuthFixture(t)
	verifier, challenge := oauthPKCEPair(t)

	issue := func(t *testing.T, redirectURI string) string {
		t.Helper()
		tx, _, err := f.svc.OAuthBeginAuthorize(OAuthAuthorizeRequest{
			ResponseType: "code", ClientID: f.clientID, RedirectURI: redirectURI,
			State: "s", CodeChallenge: challenge, CodeChallengeMethod: "S256",
		})
		if err != nil {
			t.Fatalf("发起授权: %v", err)
		}
		if _, err := f.svc.OAuthAuthorizeView(tx, f.user.UID); err != nil {
			t.Fatalf("确认页视图: %v", err)
		}
		redirect, err := f.svc.OAuthDecide(f.user.UID, tx, "allow", testMeta)
		if err != nil {
			t.Fatalf("确认: %v", err)
		}
		return redirect[strings.Index(redirect, "code=")+5:]
	}

	t.Run("错 secret", func(t *testing.T) {
		code := issue(t, "https://app.example.com/cb")
		_, err := f.svc.OAuthExchangeToken(OAuthTokenRequest{
			GrantType: "authorization_code", Code: code[:strings.IndexAny(code, "&")],
			RedirectURI: "https://app.example.com/cb",
			ClientID:    f.clientID, ClientSecret: "wrong-secret", CodeVerifier: verifier,
		})
		if oe, ok := err.(*OAuthError); !ok || oe.Status != 401 || oe.Code != "invalid_client" {
			t.Errorf("错 secret 应 401 invalid_client，得到 %v", err)
		}
	})

	t.Run("redirect_uri 不一致", func(t *testing.T) {
		code := issue(t, "https://app.example.com/cb")
		_, err := f.svc.OAuthExchangeToken(OAuthTokenRequest{
			GrantType: "authorization_code", Code: code[:strings.IndexAny(code, "&")],
			RedirectURI: "https://app.example.com/other",
			ClientID:    f.clientID, ClientSecret: f.secret, CodeVerifier: verifier,
		})
		if oe, ok := err.(*OAuthError); !ok || oe.Code != "invalid_grant" {
			t.Errorf("redirect_uri 不一致应 invalid_grant，得到 %v", err)
		}
	})

	t.Run("PKCE 错 verifier", func(t *testing.T) {
		code := issue(t, "https://app.example.com/cb")
		// 合法形态（43 位）但 seed 不同：验的是 S256 比对本身，不是格式闸
		bad := base64.RawURLEncoding.EncodeToString([]byte("another-verifier-seed-0001abcdef"))
		_, err := f.svc.OAuthExchangeToken(OAuthTokenRequest{
			GrantType: "authorization_code", Code: code[:strings.IndexAny(code, "&")],
			RedirectURI: "https://app.example.com/cb",
			ClientID:    f.clientID, ClientSecret: f.secret, CodeVerifier: bad,
		})
		if oe, ok := err.(*OAuthError); !ok || oe.Code != "invalid_grant" {
			t.Errorf("错 verifier 应 invalid_grant，得到 %v", err)
		}
	})

	t.Run("非法 grant_type", func(t *testing.T) {
		_, err := f.svc.OAuthExchangeToken(OAuthTokenRequest{GrantType: "password"})
		if oe, ok := err.(*OAuthError); !ok || oe.Code != "unsupported_grant_type" {
			t.Errorf("非法 grant_type 应 unsupported_grant_type，得到 %v", err)
		}
	})

	t.Run("未登记 client", func(t *testing.T) {
		_, err := f.svc.OAuthExchangeToken(OAuthTokenRequest{
			GrantType: "authorization_code", Code: "whatever",
			ClientID: "not-a-client", ClientSecret: "x", CodeVerifier: verifier, RedirectURI: "u",
		})
		if oe, ok := err.(*OAuthError); !ok || oe.Code != "invalid_client" {
			t.Errorf("未登记 client 应 invalid_client，得到 %v", err)
		}
	})
}

// 确认页 deny：回跳 error=access_denied + state，且事务消耗。
// 事务经 OAuthAuthorizeView 绑定 uid（现行安全语义：防登录甲确认乙的事务），
// 之后才能 deny。
func TestOAuthDecideDeny(t *testing.T) {
	f := newOAuthFixture(t)
	_, challenge := oauthPKCEPair(t)
	tx, _, err := f.svc.OAuthBeginAuthorize(OAuthAuthorizeRequest{
		ResponseType: "code", ClientID: f.clientID, RedirectURI: "https://app.example.com/cb",
		State: "st-deny", CodeChallenge: challenge, CodeChallengeMethod: "S256",
	})
	if err != nil {
		t.Fatalf("发起: %v", err)
	}
	if _, err := f.svc.OAuthAuthorizeView(tx, f.user.UID); err != nil {
		t.Fatalf("确认页视图（绑 uid）: %v", err)
	}
	redirect, err := f.svc.OAuthDecide(f.user.UID, tx, "deny", testMeta)
	if err != nil {
		t.Fatalf("deny 不该报错: %v", err)
	}
	if !strings.Contains(redirect, "error=access_denied") || !strings.Contains(redirect, "state=st-deny") {
		t.Errorf("deny 回跳应带 error=access_denied 与原 state，得到 %q", redirect)
	}
	// 事务已消耗：再确认一次应 400
	if _, err := f.svc.OAuthDecide(f.user.UID, tx, "allow", testMeta); err == nil {
		t.Error("deny 后事务应已消耗")
	}
}

// 发码后用户被封禁：换 token 时 deny 兜底拦下（access_denied）。
func TestOAuthExchangeDeniedAfterBan(t *testing.T) {
	f := newOAuthFixture(t)
	verifier, challenge := oauthPKCEPair(t)
	tx, _, err := f.svc.OAuthBeginAuthorize(OAuthAuthorizeRequest{
		ResponseType: "code", ClientID: f.clientID, RedirectURI: "https://app.example.com/cb",
		State: "s", CodeChallenge: challenge, CodeChallengeMethod: "S256",
	})
	if err != nil {
		t.Fatalf("发起: %v", err)
	}
	if _, err := f.svc.OAuthAuthorizeView(tx, f.user.UID); err != nil {
		t.Fatalf("视图: %v", err)
	}
	redirect, err := f.svc.OAuthDecide(f.user.UID, tx, "allow", testMeta)
	if err != nil {
		t.Fatalf("确认: %v", err)
	}
	code := redirect[strings.Index(redirect, "code=")+5:]
	code = code[:strings.IndexAny(code, "&")]

	// 确认之后、换 token 之前被全站封禁
	if err := f.svc.AdminBan(f.super, AdminScope{Super: true}, f.user.UID,
		AdminBanInput{App: "*"}); err != nil {
		t.Fatalf("封禁: %v", err)
	}
	_, err = f.svc.OAuthExchangeToken(OAuthTokenRequest{
		GrantType: "authorization_code", Code: code,
		RedirectURI: "https://app.example.com/cb",
		ClientID:    f.clientID, ClientSecret: f.secret, CodeVerifier: verifier,
	})
	if oe, ok := err.(*OAuthError); !ok || oe.Code != "access_denied" || oe.Status != 403 {
		t.Errorf("封禁用户换 token 应 403 access_denied，得到 %v", err)
	}
}

// 管理端：首调自动生成 client_id+secret；不轮换时 secret 不变（旧 secret 照用）；
// 轮换后旧 secret 立即失效；app-admin 越权 403；名单外项目 400。
func TestOAuthAdminConfigureLifecycle(t *testing.T) {
	f := newOAuthFixture(t)

	// 不轮换更新 redirect：secret 不回执
	res, err := f.svc.AdminConfigureOAuth(f.super, AdminScope{Super: true}, "calorie-diary", AdminOAuthInput{
		RedirectUris: []string{"https://app.example.com/cb", "https://app.example.com/cb2"},
	})
	if err != nil {
		t.Fatalf("更新: %v", err)
	}
	if res.Secret != "" || res.ClientID != f.clientID || len(res.RedirectURIs) != 2 {
		t.Errorf("不轮换的回执不对: %+v", res)
	}
	// 旧 secret 仍可用（换一个新 code 验证）
	verifier, challenge := oauthPKCEPair(t)
	tx, _, err := f.svc.OAuthBeginAuthorize(OAuthAuthorizeRequest{
		ResponseType: "code", ClientID: f.clientID, RedirectURI: "https://app.example.com/cb2",
		State: "s", CodeChallenge: challenge, CodeChallengeMethod: "S256",
	})
	if err != nil {
		t.Fatalf("发起（新地址应已生效）: %v", err)
	}
	if _, err := f.svc.OAuthAuthorizeView(tx, f.user.UID); err != nil {
		t.Fatalf("视图: %v", err)
	}
	redirect, err := f.svc.OAuthDecide(f.user.UID, tx, "allow", testMeta)
	if err != nil {
		t.Fatalf("确认: %v", err)
	}
	code := redirect[strings.Index(redirect, "code=")+5:]
	code = code[:strings.IndexAny(code, "&")]
	if _, err := f.svc.OAuthExchangeToken(OAuthTokenRequest{
		GrantType: "authorization_code", Code: code, RedirectURI: "https://app.example.com/cb2",
		ClientID: f.clientID, ClientSecret: f.secret, CodeVerifier: verifier,
	}); err != nil {
		t.Errorf("未轮换时旧 secret 应仍可用: %v", err)
	}

	// 轮换：旧 secret 立即失效
	res, err = f.svc.AdminConfigureOAuth(f.super, AdminScope{Super: true}, "calorie-diary", AdminOAuthInput{
		RedirectUris: []string{"https://app.example.com/cb"}, RotateSecret: true,
	})
	if err != nil {
		t.Fatalf("轮换: %v", err)
	}
	if res.Secret == "" || res.Secret == f.secret {
		t.Errorf("轮换应回新 secret，得到 %+v", res)
	}
	tx, _, _ = f.svc.OAuthBeginAuthorize(OAuthAuthorizeRequest{
		ResponseType: "code", ClientID: f.clientID, RedirectURI: "https://app.example.com/cb",
		State: "s", CodeChallenge: challenge, CodeChallengeMethod: "S256",
	})
	if _, err := f.svc.OAuthAuthorizeView(tx, f.user.UID); err != nil {
		t.Fatalf("视图: %v", err)
	}
	redirect, _ = f.svc.OAuthDecide(f.user.UID, tx, "allow", testMeta)
	code = redirect[strings.Index(redirect, "code=")+5:]
	code = code[:strings.IndexAny(code, "&")]
	if _, err := f.svc.OAuthExchangeToken(OAuthTokenRequest{
		GrantType: "authorization_code", Code: code, RedirectURI: "https://app.example.com/cb",
		ClientID: f.clientID, ClientSecret: f.secret, CodeVerifier: verifier,
	}); err == nil {
		t.Error("轮换后旧 secret 应立即失效")
	}

	// 审计落行且不带 secret
	var detail string
	if err := f.svc.pool.QueryRow(
		"SELECT detail FROM audit_logs WHERE action = ? AND result = 'ok' ORDER BY id DESC LIMIT 1",
		AuditOAuthClientWrite).Scan(&detail); err != nil {
		t.Fatalf("查 OAuth 客户端审计: %v", err)
	}
	if !strings.Contains(detail, `"app":"calorie-diary"`) || !strings.Contains(detail, `"rotateSecret":"true"`) {
		t.Errorf("审计 detail 缺字段: %s", detail)
	}
	if strings.Contains(detail, res.Secret) || strings.Contains(detail, res.ClientID) {
		t.Errorf("审计 detail 不该带 secret/client_id: %s", detail)
	}

	// 权限：app-admin 越权（未授权项目）403；名单外项目 400
	appAdmin := seedAdminUser(t, f.svc, f.mailer, "oauth-appadmin@example.com", adminRoleAdmin)
	if _, err := f.svc.AdminConfigureOAuth(appAdmin, AdminScope{Apps: []string{"expense-diary"}},
		"calorie-diary", AdminOAuthInput{RedirectUris: []string{"https://x.example.com/cb"}}); err == nil {
		t.Error("app-admin 管未授权项目应 403")
	}
	if _, err := f.svc.AdminConfigureOAuth(f.super, AdminScope{Super: true}, "not-an-app",
		AdminOAuthInput{RedirectUris: []string{"https://x.example.com/cb"}}); err == nil {
		t.Error("名单外项目应 400")
	}
	// 授权后 app-admin 可管自己项目
	if err := f.svc.AdminSetScope(f.super, appAdmin.UID, "expense-diary", true); err != nil {
		t.Fatalf("授 scope: %v", err)
	}
	res, err = f.svc.AdminConfigureOAuth(appAdmin, AdminScope{Apps: []string{"expense-diary"}},
		"expense-diary", AdminOAuthInput{RedirectUris: []string{"https://x.example.com/cb"}})
	if err != nil || res.ClientID == "" {
		t.Errorf("app-admin 管授权项目应成功，得到 %+v err=%v", res, err)
	}

	// OAuthClientIDFor：未开通回空串
	if cid, _ := f.svc.OAuthClientIDFor("expense-diary"); cid != res.ClientID {
		t.Errorf("OAuthClientIDFor 应回登记的 client_id，得到 %q", cid)
	}
}

// AdminListProjects 带上 clientId/redirectUris（B2 项目访问页的 Web 接入卡数据源）。
func TestAdminListProjectsCarriesOAuth(t *testing.T) {
	f := newOAuthFixture(t)
	projects, err := f.svc.AdminListProjects(AdminScope{Super: true})
	if err != nil {
		t.Fatalf("列项目: %v", err)
	}
	var found bool
	for _, p := range projects {
		if p.App != "calorie-diary" {
			continue
		}
		found = true
		if p.ClientID != f.clientID || len(p.RedirectURIs) != 1 || p.RedirectURIs[0] != "https://app.example.com/cb" {
			t.Errorf("项目回执应带 OAuth 登记，得到 %+v", p)
		}
	}
	if !found {
		t.Fatal("列表里应有 calorie-diary")
	}
}
