package auth

import (
	"strings"
	"testing"
	"time"
)

// web 会话主链：签发（双 token 只存 hash）→ 校验往返 → 改 token 即 401 →
// CSRF 常数时间比对 → 强认证窗 2 小时。
func TestWebSessionRoundTrip(t *testing.T) {
	svc, mailer := newTestService(t)
	reg := registerViaCode(t, svc, mailer, "web-round@example.com", "secret123")
	caller, err := svc.ValidUserID("Bearer " + reg.Token)
	if err != nil {
		t.Fatalf("注册 token 校验失败: %v", err)
	}

	ws, err := svc.CreateWebSession(caller.UID, SessionMeta{IP: "203.0.113.5", UserAgent: "Mozilla/5.0 (X11; Linux x86_64) Chrome/120"})
	if err != nil {
		t.Fatalf("建 web 会话: %v", err)
	}
	if len(ws.Token) < 40 || len(ws.CSRFToken) < 40 {
		t.Errorf("token 应是 32 字节 CSPRNG 的 base64url（≥40 字符），得到 %d/%d", len(ws.Token), len(ws.CSRFToken))
	}
	if ws.Token == ws.CSRFToken {
		t.Error("会话 token 与 CSRF token 不能同值")
	}
	// 明文绝不能进库：库里只有 sha256
	var stored string
	if err := svc.pool.QueryRow("SELECT web_token_hash FROM sessions WHERE id = ?", ws.SID).Scan(&stored); err != nil {
		t.Fatalf("查库里的 token hash: %v", err)
	}
	if stored == ws.Token || len(stored) != 64 || strings.ToLower(stored) != stored {
		t.Errorf("库里应是 64 位小写 hex 的 sha256，得到 %q", stored)
	}

	wc, err := svc.ValidWebSession(ws.Token)
	if err != nil {
		t.Fatalf("web token 应通过校验: %v", err)
	}
	if wc.UID != caller.UID || wc.Email != "web-round@example.com" || wc.SID != ws.SID {
		t.Errorf("身份对不上: %+v", wc.Caller)
	}
	if wc.App != "web" {
		t.Errorf("sessions.app 应为 web，得到 %q", wc.App)
	}
	if !wc.ViaCookie {
		t.Error("cookie 路径进来应标 ViaCookie")
	}
	if !wc.CheckCSRF(ws.CSRFToken) {
		t.Error("正确的 CSRF token 应通过")
	}
	if wc.CheckCSRF("wrong-token") || wc.CheckCSRF("") {
		t.Error("错的 / 空的 CSRF token 必须被拒")
	}

	// 换一个字符就 401：cookie 值必须逐位匹配（库里存 hash，没有可暴力比对的对象）
	mutated := ws.Token[:len(ws.Token)-1] + "x"
	if mutated == ws.Token {
		mutated = ws.Token[:len(ws.Token)-1] + "y"
	}
	_, badErr := svc.ValidWebSession(mutated)
	if code, _ := httpMsg(badErr); code != 401 {
		t.Errorf("篡改 token 应 401，得到 %d %v", code, badErr)
	}
	_, emptyErr := svc.ValidWebSession("")
	if code, _ := httpMsg(emptyErr); code != 401 {
		t.Errorf("空 token 应 401，得到 %d", code)
	}

	// 强认证窗：刚标记即放行；回拨 90 分钟（老的 15 分钟窗早已超时）仍在 2 小时窗内
	// → 放行，回拨 3 小时（超 2 小时）→ 401 + 固定文案（前端据此弹重验框）。
	// 两个断言一起把窗钉在 (90 分钟, 3 小时] 之间，防止有人把它改回 15 分钟。
	if err := svc.MarkReauth(ws.SID); err != nil {
		t.Fatalf("标记强认证: %v", err)
	}
	if err := svc.RequireReauth(ws.SID); err != nil {
		t.Errorf("2 小时窗内应放行: %v", err)
	}
	if _, err := svc.pool.Exec("UPDATE sessions SET reauth_at = ? WHERE id = ?",
		time.Now().Add(-90*time.Minute).UnixMilli(), ws.SID); err != nil {
		t.Fatalf("回拨 reauth 90 分钟: %v", err)
	}
	if err := svc.RequireReauth(ws.SID); err != nil {
		t.Errorf("回拨 90 分钟仍在 2 小时窗内，应放行: %v", err)
	}
	if _, err := svc.pool.Exec("UPDATE sessions SET reauth_at = ? WHERE id = ?",
		time.Now().Add(-3*time.Hour).UnixMilli(), ws.SID); err != nil {
		t.Fatalf("回拨 reauth 3 小时: %v", err)
	}
	if err := svc.RequireReauth(ws.SID); err == nil || err.Error() != MsgReauthRequired {
		t.Errorf("超窗应 401 %q，得到 %v", MsgReauthRequired, err)
	}
}

// 两道超时与吊销闸：空闲 7 天、绝对 90 天、被踢——任一都要当场 401。
func TestWebSessionTimeoutsAndRevocation(t *testing.T) {
	svc, mailer := newTestService(t)
	reg := registerViaCode(t, svc, mailer, "web-timeout@example.com", "secret123")
	caller, err := svc.ValidUserID("Bearer " + reg.Token)
	if err != nil {
		t.Fatalf("注册 token 校验失败: %v", err)
	}
	newWeb := func() *WebSession {
		t.Helper()
		ws, err := svc.CreateWebSession(caller.UID, SessionMeta{IP: "203.0.113.9", UserAgent: "Chrome"})
		if err != nil {
			t.Fatalf("建 web 会话: %v", err)
		}
		return ws
	}
	assert401 := func(ws *WebSession, label string) {
		t.Helper()
		_, err := svc.ValidWebSession(ws.Token)
		if code, _ := httpMsg(err); code != 401 {
			t.Errorf("%s 应 401，得到 %d %v", label, code, err)
		}
	}

	// 空闲：last_seen_at 回拨 8 天（created_at 仍新鲜）
	idle := newWeb()
	if _, err := svc.pool.Exec("UPDATE sessions SET last_seen_at = ? WHERE id = ?",
		time.Now().Add(-8*24*time.Hour).UnixMilli(), idle.SID); err != nil {
		t.Fatalf("回拨活跃时间: %v", err)
	}
	assert401(idle, "空闲 7 天")

	// 绝对：created_at 回拨 91 天，last_seen 拉到当下（只触发绝对闸）
	abs := newWeb()
	if _, err := svc.pool.Exec("UPDATE sessions SET created_at = ?, last_seen_at = ? WHERE id = ?",
		time.Now().Add(-91*24*time.Hour).UnixMilli(), time.Now().UnixMilli(), abs.SID); err != nil {
		t.Fatalf("回拨创建时间: %v", err)
	}
	assert401(abs, "绝对 90 天")

	// 吊销：踢掉即刻失效（复用老会话闸，网页登录没有第二套开关）；
	// 自行吊销不受作用域限制（与 /web/logout 同口径，apps=nil）
	rev := newWeb()
	if err := svc.RevokeSession(caller.UID, rev.SID, nil); err != nil {
		t.Fatalf("踢会话: %v", err)
	}
	assert401(rev, "被吊销")

	// 活着的那条不受影响
	ok := newWeb()
	if _, err := svc.ValidWebSession(ok.Token); err != nil {
		t.Errorf("新鲜会话应通过: %v", err)
	}
}

// 双凭据并存互不串用：web token 过不了 JWT 校验，JWT 过不了 web 校验；
// 但两条路各自都要撞会话与版本闸。
func TestWebBearerAndJWTCoexist(t *testing.T) {
	svc, mailer := newTestService(t)
	reg := registerViaCode(t, svc, mailer, "web-dual@example.com", "secret123")

	ws, err := svc.CreateWebSession(tokenClaimUID(t, reg.Token), SessionMeta{IP: "198.51.100.7", UserAgent: "Safari"})
	if err != nil {
		t.Fatalf("建 web 会话: %v", err)
	}

	// web token 当 Bearer 用（C 批 App 的形态）：web 校验认，JWT 校验不认
	if _, err := svc.ValidWebBearer("Bearer " + ws.Token); err != nil {
		t.Errorf("web token 当 Bearer 应通过: %v", err)
	}
	_, e1 := svc.ValidUserID("Bearer " + ws.Token)
	if code, _ := httpMsg(e1); code != 401 {
		t.Errorf("web token 不该过 JWT 校验，得到 %d", code)
	}
	// JWT 反向：JWT 校验认，web 校验不认（同一前缀，靠 hash 点查区分）
	if _, err := svc.ValidUserID("Bearer " + reg.Token); err != nil {
		t.Errorf("JWT 应通过其自身校验: %v", err)
	}
	_, e2 := svc.ValidWebBearer("Bearer " + reg.Token)
	if code, _ := httpMsg(e2); code != 401 {
		t.Errorf("JWT 不该过 web 校验，得到 %d", code)
	}
	// 无前缀 / 空头一律不认
	_, e3 := svc.ValidWebBearer(reg.Token)
	if code, _ := httpMsg(e3); code != 401 {
		t.Errorf("缺 Bearer 前缀应 401，得到 %d", code)
	}
}

// 重新验证（POST /web/reauth）的恢复码路：三选一的分流、格式判定、单次使用、
// 以及「恢复码粘进两步验证码框也认」的一框二选一（与安全页同款格式分流）。
func TestReauthWithRecoveryCode(t *testing.T) {
	svc, mailer := newTestService(t)
	c := newPasskeyUser(t, svc, mailer, "reauth-rc@example.com")
	// 绑定两步验证并拿到一组恢复码
	setup, err := svc.SetupTOTP(c)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	codes, err := svc.EnableTOTP(c, currentCode(t, setup.Secret))
	if err != nil || len(codes) == 0 {
		t.Fatalf("enable: %v", err)
	}
	stale := func() {
		t.Helper()
		if _, err := svc.pool.Exec("UPDATE sessions SET reauth_at = NULL WHERE id = ?", c.SID); err != nil {
			t.Fatalf("清强认证时间: %v", err)
		}
	}
	stale()

	// 三者皆空 → 400 且点名三种输入
	if code, msg := httpMsg(svc.Reauth(c, "", "", "")); code != 400 || !strings.Contains(msg, "恢复码") {
		t.Errorf("空输入应 400 且点名恢复码，得到 %d %q", code, msg)
	}
	// 形态不像恢复码的 recoveryCode → 400 说格式
	if code, msg := httpMsg(svc.Reauth(c, "", "", "123456")); code != 400 || !strings.Contains(msg, "格式") {
		t.Errorf("错格式应 400 且说格式，得到 %d %q", code, msg)
	}
	// 格式对但没这一个码 → 400「恢复码不正确或已使用」
	if code, msg := httpMsg(svc.Reauth(c, "", "", "AAAA-BBBB-CCCC-DDDD")); code != 400 || !strings.Contains(msg, "恢复码不正确") {
		t.Errorf("错码应 400 且点名恢复码，得到 %d %q", code, msg)
	}
	if err := svc.RequireReauth(c.SID); err == nil {
		t.Error("失败的尝试不该刷新强认证窗")
	}

	// 正确的恢复码 → 强认证窗刷新
	if err := svc.Reauth(c, "", "", codes[0]); err != nil {
		t.Fatalf("恢复码重新验证: %v", err)
	}
	if err := svc.RequireReauth(c.SID); err != nil {
		t.Errorf("恢复码验证后强认证窗应生效: %v", err)
	}
	// 单次使用：同一个码再用 → 400
	if code, msg := httpMsg(svc.Reauth(c, "", "", codes[0])); code != 400 || !strings.Contains(msg, "已使用") {
		t.Errorf("恢复码应单次使用，得到 %d %q", code, msg)
	}

	// 一框二选一：恢复码粘进两步验证码框（totpCode）也按恢复码认
	stale()
	if err := svc.Reauth(c, "", codes[1], ""); err != nil {
		t.Errorf("验证码框里的恢复码应被认出: %v", err)
	}
	if err := svc.RequireReauth(c.SID); err != nil {
		t.Errorf("强认证窗应生效: %v", err)
	}
	// 审计：reauth 事件按 method=recovery 落行
	var methods int
	if err := svc.pool.QueryRow(
		"SELECT COUNT(*) FROM audit_logs WHERE action = 'reauth' AND result = 'ok' AND detail LIKE '%\"method\":\"recovery\"%'").
		Scan(&methods); err != nil || methods == 0 {
		t.Errorf("恢复码 reauth 应落 method=recovery 审计，得到 %d err=%v", methods, err)
	}
}
