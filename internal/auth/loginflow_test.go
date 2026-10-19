package auth

import (
	"strings"
	"testing"
	"time"
)

// 无 2FA：密码验过直接建 web 会话；有 2FA：只发 5 分钟单次中间态，
// 错 5 次烧毁，验过才建会话。
func TestWebLoginPasswordFlow(t *testing.T) {
	svc, mailer := newTestService(t)
	reg := registerViaCode(t, svc, mailer, "web-login@example.com", "secret123")
	meta := SessionMeta{IP: "203.0.113.20", UserAgent: "Mozilla/5.0 Chrome"}

	// 未开 2FA → 一步到位
	res, err := svc.WebLoginPassword("web-login@example.com", "secret123", meta, "")
	if err != nil {
		t.Fatalf("密码登录: %v", err)
	}
	if res.Session == nil || res.Status != "" {
		t.Fatalf("未开 2FA 应直接建成会话，得到 %+v", res)
	}
	// app 缺省 = web 流程：回的是会话 token，**不掺 JWT**
	if res.JWT != "" || res.App != "" {
		t.Errorf("web 流程不该出现 JWT/app，得到 JWT=%q app=%q", res.JWT, res.App)
	}
	wc, err := svc.ValidWebSession(res.Session.Token)
	if err != nil || wc.UID == 0 || wc.App != "web" {
		t.Errorf("签出的会话应可校验且 app=web: %+v err=%v", wc, err)
	}
	// 错密码照旧 401（与老端点同一句，不泄露账号状态）
	_, err = svc.WebLoginPassword("web-login@example.com", "wrong-pass", meta, "")
	if code, _ := httpMsg(err); code != 401 {
		t.Errorf("错密码应 401，得到 %d %v", code, err)
	}

	// 开 2FA → 中间态
	c, err := svc.ValidUserID("Bearer " + reg.Token)
	if err != nil {
		t.Fatalf("取身份: %v", err)
	}
	if _, err := svc.SetupTOTP(c); err != nil {
		t.Fatalf("setup totp: %v", err)
	}
	if _, err := svc.pool.Exec("UPDATE totp_factors SET enabled = 1, confirmed_at = ? WHERE user_id = ?",
		time.Now().UnixMilli(), c.UID); err != nil {
		t.Fatalf("置 enabled: %v", err)
	}
	res2, err := svc.WebLoginPassword("web-login@example.com", "secret123", meta, "")
	if err != nil {
		t.Fatalf("带 2FA 的密码登录: %v", err)
	}
	if res2.Status != "2fa_required" || res2.LoginToken == "" || res2.Session != nil {
		t.Fatalf("应回两步中间态，得到 %+v", res2)
	}
	if len(res2.Methods) != 2 || res2.Methods[0] != "totp" || res2.Methods[1] != "recovery" {
		t.Errorf("methods 应为 totp/recovery，得到 %+v", res2.Methods)
	}
	// 中间态要带着目标应用：web 流程存 'web'（列默认值），第二步据此决定发什么
	var label string
	if err := svc.pool.QueryRow("SELECT app FROM login_states WHERE user_id = ?", c.UID).Scan(&label); err != nil {
		t.Fatalf("查中间态 app: %v", err)
	}
	if label != "web" {
		t.Errorf("web 流程的 login_states.app 应为 web，得到 %q", label)
	}
	// 中间态明文不落库
	var hashed string
	if err := svc.pool.QueryRow("SELECT token_hash FROM login_states WHERE user_id = ?", c.UID).Scan(&hashed); err != nil {
		t.Fatalf("查中间态: %v", err)
	}
	if hashed == res2.LoginToken || len(hashed) != 64 {
		t.Errorf("库里应是 sha256，得到 %q", hashed)
	}
}

// 两步登录第二步：错码计数、5 次烧毁、真码放行、恢复码放行。
func TestWebLoginSecondStep(t *testing.T) {
	svc, mailer := newTestService(t)
	reg := registerViaCode(t, svc, mailer, "web-2fa@example.com", "secret123")
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
	meta := SessionMeta{IP: "198.51.100.44", UserAgent: "Firefox"}

	begin := func() *WebLoginResult {
		t.Helper()
		res, err := svc.WebLoginPassword("web-2fa@example.com", "secret123", meta, "")
		if err != nil || res.Status != "2fa_required" {
			t.Fatalf("应进两步: %+v err=%v", res, err)
		}
		return res
	}
	// 错码计数：5 次内都是「验证码错误」，第 5 次那次把中间态烧掉
	res := begin()
	for i := 0; i < loginStateFails; i++ {
		_, err := svc.WebLoginTOTP(res.LoginToken, "000000", "", meta)
		if err == nil || !strings.Contains(err.Error(), "验证码错误") {
			t.Fatalf("第 %d 次错码应报验证码错误，得到 %v", i+1, err)
		}
	}
	// 已烧毁：哪怕码是对的也回「过期」，逼用户回第一步重来
	_, err = svc.WebLoginTOTP(res.LoginToken, currentCode(t, setup.Secret), "", meta)
	if err == nil || !strings.Contains(err.Error(), "过期") {
		t.Errorf("烧毁后即使码对也应过期，得到 %v", err)
	}

	// 真码 → 建会话（用没被用过的码：上一轮全部是错码，未消耗任何步进）
	res2 := begin()
	// 当下码可能与 enable 时同步进（被防重放挡），换下一个步进的码稳定可过
	ok, err := svc.WebLoginTOTP(res2.LoginToken, codeAt(t, setup.Secret, 30*time.Second), "", meta)
	if err != nil || ok.Session == nil {
		t.Fatalf("真码应放行: %+v err=%v", ok, err)
	}
	if _, err := svc.ValidWebSession(ok.Session.Token); err != nil {
		t.Errorf("第二步签的会话应可校验: %v", err)
	}
	if ok.JWT != "" {
		t.Errorf("web 流程第二步也不该签 JWT，得到 %q", ok.JWT)
	}
	// 用后即焚：同一个中间态不能再换一次
	if _, err := svc.WebLoginTOTP(res2.LoginToken, currentCode(t, setup.Secret), "", meta); err == nil {
		t.Error("中间态必须单次使用")
	}

	// 恢复码路
	res3 := begin()
	// codes[1] 还没用过；codes[0] 在 disable 用例里没涉及，这里用最后一个
	used, err := svc.WebLoginTOTP(res3.LoginToken, "", codes[len(codes)-1], meta)
	if err != nil || used.Session == nil {
		t.Fatalf("恢复码应能完成登录: %+v err=%v", used, err)
	}
	var remain int
	if err := svc.pool.QueryRow("SELECT COUNT(*) FROM recovery_codes WHERE user_id = ? AND used = 0", c.UID).
		Scan(&remain); err != nil || remain != recoveryCodeCount-1 {
		t.Errorf("恢复码应用一少一，得到剩余 %d err=%v", remain, err)
	}
}

// m4 回归：第二步爆破可归因——WebLoginTOTP 失败路径的审计行必须带 st.uid 与
// 掩码邮箱（旧实现失败时 res=nil，actor 全空，第二步被爆破查不到是谁的账号）。
func TestWebLoginTOTPFailureCarriesActor(t *testing.T) {
	svc, mailer := newTestService(t)
	reg := registerViaCode(t, svc, mailer, "web-2fa-actor@example.com", "secret123")
	c, err := svc.ValidUserID("Bearer " + reg.Token)
	if err != nil {
		t.Fatalf("取身份: %v", err)
	}
	setup, err := svc.SetupTOTP(c)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	if _, err := svc.EnableTOTP(c, currentCode(t, setup.Secret)); err != nil {
		t.Fatalf("enable: %v", err)
	}
	meta := SessionMeta{IP: "203.0.113.50", UserAgent: "Firefox"}

	res, err := svc.WebLoginPassword("web-2fa-actor@example.com", "secret123", meta, "")
	if err != nil || res.Status != "2fa_required" {
		t.Fatalf("应进两步: %+v err=%v", res, err)
	}
	// 错码 → 失败审计应记 actor_uid 与掩码邮箱
	if _, err := svc.WebLoginTOTP(res.LoginToken, "000000", "", meta); err == nil {
		t.Fatal("错码应失败")
	}
	var (
		uid    int64
		email  string
		action string
	)
	if err := svc.pool.QueryRow(
		"SELECT actor_uid, actor_email, action FROM audit_logs WHERE action = 'login.fail' ORDER BY id DESC LIMIT 1").
		Scan(&uid, &email, &action); err != nil {
		t.Fatalf("查失败审计: %v", err)
	}
	if uid != c.UID {
		t.Errorf("失败审计 actor_uid 应为 %d，得到 %d", c.UID, uid)
	}
	if email != "w***@example.com" {
		t.Errorf("失败审计 actor_email 应为掩码邮箱，得到 %q", email)
	}
	// 恢复码失败路同样归因
	if _, err := svc.WebLoginTOTP(res.LoginToken, "", "AAAA-BBBB-CCCC-DDDD", meta); err == nil {
		t.Fatal("乱造恢复码应失败")
	}
	if err := svc.pool.QueryRow(
		"SELECT actor_uid, actor_email FROM audit_logs WHERE action = 'login.fail' ORDER BY id DESC LIMIT 1").
		Scan(&uid, &email); err != nil {
		t.Fatalf("查恢复码失败审计: %v", err)
	}
	if uid != c.UID || email != "w***@example.com" {
		t.Errorf("恢复码失败审计也应归因，得到 uid=%d email=%q", uid, email)
	}
}

// 邮箱验证码登录：一路建到底、不叠 TOTP（邮件通道本身就是持有因子）。
func TestWebLoginEmailCode(t *testing.T) {
	svc, mailer := newTestService(t)
	registerViaCode(t, svc, mailer, "web-code@example.com", "secret123")
	if err := svc.SendCode("web-code@example.com", PurposeLogin, ""); err != nil {
		t.Fatalf("发登录码: %v", err)
	}
	code := codeIn(t, mailer)
	res, err := svc.WebLoginEmailCode("web-code@example.com", code,
		SessionMeta{IP: "192.0.2.9", UserAgent: "Safari"})
	if err != nil || res.Session == nil {
		t.Fatalf("验证码登录应直接建成会话: %+v err=%v", res, err)
	}
	if _, err := svc.ValidWebSession(res.Session.Token); err != nil {
		t.Errorf("会话应可校验: %v", err)
	}
	// 码是一次性的
	_, err = svc.WebLoginEmailCode("web-code@example.com", code, SessionMeta{})
	if err == nil {
		t.Error("同一个码不该登录两次")
	}
}

// 老端点的兼容开关 totp_enforce_apps：默认（未配置 / 空名单）一行影响都没有；
// 名单内且账号开了 2FA 才拦，回 401 提示升级。
func TestEnforceAppsSwitch(t *testing.T) {
	svc, mailer := newTestService(t)
	reg := registerViaCode(t, svc, mailer, "web-enforce@example.com", "secret123")
	c, err := svc.ValidUserID("Bearer " + reg.Token)
	if err != nil {
		t.Fatalf("取身份: %v", err)
	}

	// 没开 2FA：开关开着也不拦。名单只放 calorie-diary，好让下面 expense-diary
	// 那条走「名单外放行」的分支（假实现也得像真的：只回请求的那个键的值）
	svc.SetEnforceApps(func(string) (string, error) { return "calorie-diary", nil })
	if _, err := svc.Login("web-enforce@example.com", "secret123", "calorie-diary", testMeta); err != nil {
		t.Errorf("未开 2FA 不该被拦: %v", err)
	}

	// 开 2FA 后：名单内的 app 拦、名单外的 app 放行
	if _, err := svc.SetupTOTP(c); err != nil {
		t.Fatalf("setup: %v", err)
	}
	if _, err := svc.pool.Exec("UPDATE totp_factors SET enabled = 1, confirmed_at = ? WHERE user_id = ?",
		time.Now().UnixMilli(), c.UID); err != nil {
		t.Fatalf("置 enabled: %v", err)
	}
	_, err = svc.Login("web-enforce@example.com", "secret123", "calorie-diary", testMeta)
	if err == nil || !strings.Contains(err.Error(), "升级应用") {
		t.Errorf("名单内应 401 提示升级，得到 %v", err)
	}
	if code, _ := httpMsg(err); code != 401 {
		t.Errorf("应是 401，得到 %d", code)
	}
	if _, err := svc.Login("web-enforce@example.com", "secret123", "expense-diary", testMeta); err != nil {
		t.Errorf("名单外的 app 不该被拦: %v", err)
	}

	// 键没配 / 读失败 → 放行（兼容开关不该把老客户端锁死）
	svc.SetEnforceApps(func(string) (string, error) { return "", nil })
	if _, err := svc.Login("web-enforce@example.com", "secret123", "calorie-diary", testMeta); err != nil {
		t.Errorf("空名单应放行: %v", err)
	}
	svc.SetEnforceApps(func(string) (string, error) { return "", errBoom })
	if _, err := svc.Login("web-enforce@example.com", "secret123", "calorie-diary", testMeta); err != nil {
		t.Errorf("读键失败应放行: %v", err)
	}
	// 不设开关（默认形态）
	svc.SetEnforceApps(nil)
	if _, err := svc.Login("web-enforce@example.com", "secret123", "calorie-diary", testMeta); err != nil {
		t.Errorf("未注入开关应放行: %v", err)
	}
}

// errBoom 是「读配置键失败」的假实现，用 HTTPError 形态免得再引一个 errors 名字。
var errBoom = &HTTPError{500, "boom"}
