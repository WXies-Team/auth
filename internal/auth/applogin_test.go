package auth

import (
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/WXies-Team/auth/internal/webauthntest"
)

// C 批：三条登录编排（密码两步 / passkey）按请求里的 app 分流——空 = web 流程
//（cookie 会话，逐字节不变），白名单 = App 流程（业务 JWT + app=<app> 的会话行，
// 不下发 cookie）。本文件钉住分流点本身与「JWT 真过 /internal/verify 的那套校验」。

// 密码登录（无 2FA）：App 支回 JWT、会话行带 app 与 reauth 时间戳；白名单外 400
// 且不落任何行；web 支（app 缺省）不掺 JWT。
func TestAppPasswordLoginIssuesJWT(t *testing.T) {
	svc, mailer := newTestService(t)
	reg := registerViaCode(t, svc, mailer, "app-login@example.com", "secret123")
	uid := tokenClaimUID(t, reg.Token)
	meta := SessionMeta{IP: "203.0.113.77", UserAgent: "GoTest/1.0 (app login)"}

	// 白名单外的 app：400，先于凭据校验（客户端 bug 不该被 401 误导成凭据问题）
	_, err := svc.WebLoginPassword("app-login@example.com", "secret123", meta, "evil-app")
	if code, msg := httpMsg(err); code != 400 || !strings.Contains(msg, "参数不正确") {
		t.Fatalf("白名单外的 app 应 400「参数不正确」，得到 %d %v", code, err)
	}
	var afterBadApp int
	if err := svc.pool.QueryRow("SELECT COUNT(*) FROM sessions WHERE user_id = ?", uid).Scan(&afterBadApp); err != nil {
		t.Fatalf("查会话: %v", err)
	}

	res, err := svc.WebLoginPassword("app-login@example.com", "secret123", meta, "calorie-diary")
	if err != nil {
		t.Fatalf("App 密码登录: %v", err)
	}
	if res.Session != nil || res.JWT == "" || res.App != "calorie-diary" {
		t.Fatalf("App 支应回 JWT 且不建 cookie 会话，得到 %+v", res)
	}
	if n := strings.Count(res.JWT, "."); n != 2 {
		t.Fatalf("应是三段式 JWT，得到 %q", res.JWT)
	}
	// 拒掉的那次没留下任何痕迹（一行会话都没有，且这次成功的才是唯一一行）
	var total int
	if err := svc.pool.QueryRow("SELECT COUNT(*) FROM sessions WHERE user_id = ?", uid).Scan(&total); err != nil {
		t.Fatalf("查会话: %v", err)
	}
	if total != 2 { // 注册即登录 1 行 + 本次 App 登录 1 行
		t.Errorf("白名单外的请求不该建会话，得到 %d 行", total)
	}

	// /internal/verify 的实现就是这道校验：签名、aud 精确匹配、ver 与会话都活着
	vr, err := svc.Verify("Bearer "+res.JWT, "calorie-diary")
	if err != nil {
		t.Fatalf("JWT 应过 /internal/verify: %v", err)
	}
	if vr.UID != uid || vr.App != "calorie-diary" || vr.Email != "app-login@example.com" {
		t.Errorf("verify 回执不对: %+v", vr)
	}
	if _, err := svc.Verify("Bearer "+res.JWT, "expense-diary"); err == nil {
		t.Error("aud 不匹配的下游不该认这枚 token")
	}
	// 会话行：app=<app>、不写 web cookie 的两列、reauth_at 已打（passkey 注册的
	// Bearer reauth 窗靠它）
	var (
		rowApp   string
		webToken sql.NullString
		webCSRF  sql.NullString
		reauth   sql.NullInt64
	)
	err = svc.pool.QueryRow(
		"SELECT app, web_token_hash, web_csrf_hash, reauth_at FROM sessions WHERE id = ?", res.SID).
		Scan(&rowApp, &webToken, &webCSRF, &reauth)
	if err != nil {
		t.Fatalf("查会话行: %v", err)
	}
	if rowApp != "calorie-diary" || webToken.Valid || webCSRF.Valid {
		t.Errorf("App 会话应 app=calorie-diary 且无 web cookie 列: app=%q token=%v csrf=%v",
			rowApp, webToken.Valid, webCSRF.Valid)
	}
	if !reauth.Valid {
		t.Error("登录即强认证：App 会话必须打 reauth_at")
	}
	// 设备列表能看到这台（App 会话与网页会话同一张表）；App bearer 视角只看本 app
	list, err := svc.ListSessions(uid, res.SID, []string{"calorie-diary"})
	if err != nil {
		t.Fatalf("查设备列表: %v", err)
	}
	found := false
	for _, it := range list {
		if it.ID == sidStr(res.SID) && it.App == "calorie-diary" {
			found = true
		}
	}
	if !found {
		t.Errorf("App 会话应出现在 /api/sessions 的列表里，得到 %+v", list)
	}
	// 审计：login.success method=password 带上 app
	var detail string
	if err := svc.pool.QueryRow(
		"SELECT detail FROM audit_logs WHERE action = 'login.success' AND actor_uid = ? ORDER BY id DESC LIMIT 1",
		uid).Scan(&detail); err != nil {
		t.Fatalf("查登录审计: %v", err)
	}
	if !strings.Contains(detail, `"app":"calorie-diary"`) || !strings.Contains(detail, `"method":"password"`) {
		t.Errorf("审计 detail 应带 method 与 app，得到 %s", detail)
	}
}

// 两步登录：app 由第一步写进 login_states.app、第二步读回来决定发 JWT；恢复码路
// 同样带得下去；web 流程（app 空）存 'web' 且回会话 token。
func TestAppTwoStepCarriesAppThroughLoginState(t *testing.T) {
	svc, mailer := newTestService(t)
	reg := registerViaCode(t, svc, mailer, "app-2fa@example.com", "secret123")
	c, err := svc.ValidUserID("Bearer " + reg.Token)
	if err != nil {
		t.Fatalf("取身份: %v", err)
	}
	setup, err := svc.SetupTOTP(c)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	codes, err := svc.EnableTOTP(c, currentCode(t, setup.Secret))
	if err != nil {
		t.Fatalf("enable: %v", err)
	}
	meta := SessionMeta{IP: "198.51.100.44", UserAgent: "GoTest/1.0 (2fa)"}

	stateApp := func(token string) string {
		t.Helper()
		var label string
		if err := svc.pool.QueryRow("SELECT app FROM login_states WHERE token_hash = ?", sha256Hex(token)).
			Scan(&label); err != nil {
			t.Fatalf("查中间态 app: %v", err)
		}
		return label
	}

	// 第一步（App 支）：中间态带着 expense-diary，回执本身不含 token
	step1, err := svc.WebLoginPassword("app-2fa@example.com", "secret123", meta, "expense-diary")
	if err != nil || step1.Status != "2fa_required" || step1.JWT != "" {
		t.Fatalf("应进两步且不发 JWT: %+v err=%v", step1, err)
	}
	if got := stateApp(step1.LoginToken); got != "expense-diary" {
		t.Errorf("login_states.app 应带住 expense-diary，得到 %q", got)
	}
	// 第二步（TOTP 码）→ JWT，aud 是第一步声明的那个应用
	res, err := svc.WebLoginTOTP(step1.LoginToken, codeAt(t, setup.Secret, 30*time.Second), "", "", meta)
	if err != nil || res.JWT == "" || res.Session != nil {
		t.Fatalf("第二步应回 JWT: %+v err=%v", res, err)
	}
	if vr, err := svc.Verify("Bearer "+res.JWT, "expense-diary"); err != nil || vr.UID != c.UID {
		t.Errorf("两步登录的 JWT 应过 verify: %+v err=%v", vr, err)
	}
	// 会话行带 app 与 reauth
	var rowApp string
	var reauth sql.NullInt64
	if err := svc.pool.QueryRow("SELECT app, reauth_at FROM sessions WHERE id = ?", res.SID).
		Scan(&rowApp, &reauth); err != nil {
		t.Fatalf("查会话行: %v", err)
	}
	if rowApp != "expense-diary" || !reauth.Valid {
		t.Errorf("App 会话应 app=expense-diary 且带 reauth_at，得到 %q / %v", rowApp, reauth.Valid)
	}
	// 用后即焚：中间态不能再换一次
	if _, err := svc.WebLoginTOTP(step1.LoginToken, currentCode(t, setup.Secret), "", "", meta); err == nil {
		t.Error("中间态必须单次使用")
	}

	// 恢复码路：换一个应用声明，照样带得下去
	step2, err := svc.WebLoginPassword("app-2fa@example.com", "secret123", meta, "calorie-diary")
	if err != nil || step2.Status != "2fa_required" {
		t.Fatalf("应再进两步: %+v err=%v", step2, err)
	}
	if got := stateApp(step2.LoginToken); got != "calorie-diary" {
		t.Errorf("恢复码路的 login_states.app 应是 calorie-diary，得到 %q", got)
	}
	res2, err := svc.WebLoginTOTP(step2.LoginToken, "", codes[len(codes)-1], "", meta)
	if err != nil || res2.JWT == "" {
		t.Fatalf("恢复码应换出 JWT: %+v err=%v", res2, err)
	}
	if vr, err := svc.Verify("Bearer "+res2.JWT, "calorie-diary"); err != nil || vr.UID != c.UID {
		t.Errorf("恢复码换出的 JWT 应过 verify: %+v err=%v", vr, err)
	}
	// 审计记到用掉的是恢复码（method 沿用既有取值）
	var methodDetail string
	if err := svc.pool.QueryRow(
		"SELECT detail FROM audit_logs WHERE action = 'login.success' AND actor_uid = ? ORDER BY id DESC LIMIT 1",
		c.UID).Scan(&methodDetail); err != nil {
		t.Fatalf("查登录审计: %v", err)
	}
	if !strings.Contains(methodDetail, `"method":"recovery"`) || !strings.Contains(methodDetail, `"app":"calorie-diary"`) {
		t.Errorf("恢复码登录的审计 detail 不对: %s", methodDetail)
	}

	// web 支：app 空 → 中间态存 'web'，第二步回的是会话 token（无 JWT）
	step3, err := svc.WebLoginPassword("app-2fa@example.com", "secret123", meta, "")
	if err != nil || step3.Status != "2fa_required" {
		t.Fatalf("web 流程也应进两步: %+v err=%v", step3, err)
	}
	if got := stateApp(step3.LoginToken); got != "web" {
		t.Errorf("web 流程的 login_states.app 应是 web，得到 %q", got)
	}
	// 同一 30 秒窗口内只放得下一次验码（步进闸 step<=lastStep 拒），而本用例看的是
	// app 分流不是回放防护——回放闸另有 totp_test 钉，这里显式归零再验第三次。
	if _, err := svc.pool.Exec("UPDATE totp_factors SET last_used_timestep = 0 WHERE user_id = ?", c.UID); err != nil {
		t.Fatalf("归零步进闸: %v", err)
	}
	res3, err := svc.WebLoginTOTP(step3.LoginToken, codeAt(t, setup.Secret, 30*time.Second), "", "", meta)
	if err != nil || res3.Session == nil || res3.JWT != "" {
		t.Fatalf("web 流程第二步应回会话 token 且不签 JWT: %+v err=%v", res3, err)
	}
	if _, err := svc.ValidWebSession(res3.Session.Token); err != nil {
		t.Errorf("web 会话应可校验: %v", err)
	}
}

// Passkey 登录的两支：App 支（对象形态 response + app）拿 JWT 并标 current 凭证，
// web 支（无 app）拿会话 token 且 JWT 语义不混入；白名单外 400 **且不烧仪式**。
func TestPasskeyLoginAppAndWebFlow(t *testing.T) {
	svc, mailer := newTestService(t)
	c := newPasskeyUser(t, svc, mailer, "pk-appflow@example.com")
	au, err := webauthntest.New()
	if err != nil {
		t.Fatalf("造合成 passkey: %v", err)
	}
	if _, err := svc.insertCredential(c.UID, "测试通行密钥", au.Credential); err != nil {
		t.Fatalf("落凭证: %v", err)
	}
	begin := func() (int64, string) {
		t.Helper()
		assertion, id, err := svc.BeginPasskeyLogin()
		if err != nil {
			t.Fatalf("发起登录仪式: %v", err)
		}
		return id, assertion.Response.Challenge.String()
	}
	assertionFor := func(ch string) []byte {
		t.Helper()
		body, err := au.Assertion(ch, c.UID)
		if err != nil {
			t.Fatalf("造断言: %v", err)
		}
		return body
	}

	// App 支
	id, challenge := begin()
	res, err := svc.WebPasskeyLogin(id, assertionFor(challenge), "calorie-diary", testMeta)
	if err != nil {
		t.Fatalf("App passkey 登录: %v", err)
	}
	if res.Session != nil || res.JWT == "" || res.App != "calorie-diary" {
		t.Fatalf("App 支应回 JWT: %+v", res)
	}
	vr, err := svc.Verify("Bearer "+res.JWT, "calorie-diary")
	if err != nil || vr.UID != c.UID {
		t.Fatalf("passkey 签的 JWT 应过 verify: %+v err=%v", vr, err)
	}
	var rowApp string
	var reauth sql.NullInt64
	if err := svc.pool.QueryRow("SELECT app, reauth_at FROM sessions WHERE id = ?", res.SID).
		Scan(&rowApp, &reauth); err != nil {
		t.Fatalf("查会话行: %v", err)
	}
	if rowApp != "calorie-diary" || !reauth.Valid {
		t.Errorf("App 会话应 app=calorie-diary 且带 reauth_at，得到 %q / %v", rowApp, reauth.Valid)
	}
	// 本会话用哪把 passkey 登录（列表页 current 标记）在 App 支同样记下
	list, err := svc.ListPasskeys(c.UID, res.SID)
	if err != nil || len(list) != 1 || !list[0].Current {
		t.Errorf("App 会话应标出 current 凭证: %+v err=%v", list, err)
	}
	var detail string
	if err := svc.pool.QueryRow(
		"SELECT detail FROM audit_logs WHERE action = 'login.success' AND actor_uid = ? ORDER BY id DESC LIMIT 1",
		c.UID).Scan(&detail); err != nil {
		t.Fatalf("查登录审计: %v", err)
	}
	if !strings.Contains(detail, `"method":"passkey"`) || !strings.Contains(detail, `"app":"calorie-diary"`) {
		t.Errorf("passkey 登录审计 detail 不对: %s", detail)
	}

	// web 支
	id2, challenge2 := begin()
	res2, err := svc.WebPasskeyLogin(id2, assertionFor(challenge2), "", testMeta)
	if err != nil {
		t.Fatalf("web passkey 登录: %v", err)
	}
	if res2.Session == nil || res2.JWT != "" {
		t.Fatalf("web 支应回会话 token 且不签 JWT: %+v", res2)
	}
	if _, err := svc.ValidWebSession(res2.Session.Token); err != nil {
		t.Errorf("web 会话应可校验: %v", err)
	}
	if _, err := svc.Verify("Bearer "+res2.Session.Token, "calorie-diary"); err == nil {
		t.Error("web 会话 token 不是 JWT，/internal/verify 必须拒（语义不许混入）")
	}

	// 白名单外：400，且 normalize 先于仪式校验——这次的 ceremonyId 还没被消费
	id3, challenge3 := begin()
	_, err = svc.WebPasskeyLogin(id3, assertionFor(challenge3), "evil-app", testMeta)
	if code, _ := httpMsg(err); code != 400 {
		t.Fatalf("白名单外的 app 应 400，得到 %d %v", code, err)
	}
	res3, err := svc.WebPasskeyLogin(id3, assertionFor(challenge3), "expense-diary", testMeta)
	if err != nil || res3.JWT == "" {
		t.Fatalf("被拒的请求不该烧掉仪式，换对 app 应照常登录: %+v err=%v", res3, err)
	}
	if vr, err := svc.Verify("Bearer "+res3.JWT, "expense-diary"); err != nil || vr.UID != c.UID {
		t.Errorf("白名单内换 app 后的 JWT 应过 verify: %+v err=%v", vr, err)
	}
}
