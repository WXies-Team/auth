package auth

import (
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// W3 注销七天宽限 + W4 强制改密的用例：撤销 token 纯单测（本机真跑）
// + 真库端到端（无 TEST_MYSQL_DSN 跳过）。

// ---- 纯单测（无 DB）----

// 撤销链接 JWT：签发/验签回环；篡改 / 登录形态冒充 / 异密钥 / 过期统一 400 同文案
//（不给「哪一步错了」的探针面）。
func TestDeleteCancelTokenRoundTrip(t *testing.T) {
	s := &Service{secret: testSecret}
	tok, err := s.createDeleteCancelToken(1234567)
	if err != nil {
		t.Fatalf("签发撤销 token: %v", err)
	}
	uid, err := s.parseDeleteCancelToken(tok)
	if err != nil || uid != 1234567 {
		t.Fatalf("回环应得 uid=1234567，得到 %d err=%v", uid, err)
	}
	if _, err := s.parseDeleteCancelToken(tok + "x"); err == nil {
		t.Error("篡改 token 应被拒")
	} else if code, _ := httpMsg(err); code != 400 {
		t.Errorf("篡改 token 应 400，得到 %d", code)
	}
	// 登录形态 JWT 冒充（有 aud/uid、无 purpose）→ 拒
	forged, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"aud": "calorie-diary", "iss": issuer, "uid": 1234567,
		"exp": time.Now().Add(time.Hour).Unix(),
	}).SignedString([]byte(testSecret))
	_, forgedErr := s.parseDeleteCancelToken(forged)
	if code, _ := httpMsg(forgedErr); code != 400 {
		t.Errorf("登录 JWT 冒充撤销 token 应 400，得到 %d %v", code, forgedErr)
	}
	// purpose 对但已过期 → 拒
	expired, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"purpose": deleteCancelPurpose, "iss": issuer, "uid": 1234567,
		"exp": time.Now().Add(-time.Hour).Unix(),
	}).SignedString([]byte(testSecret))
	_, expiredErr := s.parseDeleteCancelToken(expired)
	if code, _ := httpMsg(expiredErr); code != 400 {
		t.Errorf("过期撤销 token 应 400，得到 %d %v", code, expiredErr)
	}
	// 异密钥 → 拒
	evil, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"purpose": deleteCancelPurpose, "iss": issuer, "uid": 1234567,
		"exp": time.Now().Add(time.Hour).Unix(),
	}).SignedString([]byte("some-other-secret-at-least-32-bytes-long!"))
	_, evilErr := s.parseDeleteCancelToken(evil)
	if code, _ := httpMsg(evilErr); code != 400 {
		t.Errorf("异密钥签名应 400，得到 %d %v", code, evilErr)
	}
}

// ---- 真库端到端（TEST_MYSQL_DSN 缺席即跳过）----

// 申请注销：不删任何数据、全会话下线、pending 落库、确认信带撤销链接与到期时间；
// 宽限期内登录即撤销（回执 DeletePendingCancelled=true、pending 清零、撤销信 + 审计）。
func TestDeleteRequestThenLoginCancels(t *testing.T) {
	svc, mailer := newTestService(t)
	c := newPasskeyUser(t, svc, mailer, "w3-flow@example.com")
	// 第二台设备
	if _, err := svc.Login(c.Email, "secret123", "expense-diary", testMeta); err != nil {
		t.Fatalf("造第二会话: %v", err)
	}

	// 邮箱与注册邮箱不一致 → 400（可执行文案）
	merr := svc.RequestAccountDeletion(c, "other@example.com", "123456")
	if code, msg := httpMsg(merr); code != 400 || !strings.Contains(msg, "注册邮箱") {
		t.Errorf("邮箱不一致应 400 点名注册邮箱，得到 %d %q", code, msg)
	}

	// 发注销确认码（purpose=delete 走既有发码闸）
	if err := svc.SendCode(c.Email, PurposeDelete, ""); err != nil {
		t.Fatalf("发注销码: %v", err)
	}
	code := codeIn(t, mailer)
	if err := svc.RequestAccountDeletion(c, c.Email, code); err != nil {
		t.Fatalf("申请注销: %v", err)
	}

	// pending 落库、数据不动、会话全杀
	var pending int64
	if err := svc.pool.QueryRow("SELECT pending_delete_at FROM users WHERE id = ?", c.UID).Scan(&pending); err != nil || pending == 0 {
		t.Fatalf("pending_delete_at 应落库，得到 %d err=%v", pending, err)
	}
	var users, alive int
	_ = svc.pool.QueryRow("SELECT COUNT(*) FROM users").Scan(&users)
	_ = svc.pool.QueryRow("SELECT COUNT(*) FROM sessions WHERE user_id = ? AND revoked_at IS NULL", c.UID).Scan(&alive)
	if users != 1 || alive != 0 {
		t.Errorf("申请注销不该删数据（users=%d），但要杀全部会话（alive=%d）", users, alive)
	}
	// 确认信：主题（已按「已排期」改版——scheduled 与「注销已完成」在收件箱一眼
	// 分信别）、撤销链接、删除内容清单、到期时间
	if !strings.Contains(mailer.subject, "注销申请已提交，将于") || !strings.Contains(mailer.subject, "执行") {
		t.Errorf("确认信主题应把排期说进主题里，得到 %q", mailer.subject)
	}
	for _, want := range []string{"/web/delete-cancel?token=", "不可恢复", "撤销"} {
		if !strings.Contains(mailer.html, want) {
			t.Errorf("确认信缺 %q", want)
		}
	}
	// 审计 account.delete_requested
	var requested int
	if err := svc.pool.QueryRow(
		"SELECT COUNT(*) FROM audit_logs WHERE action = ? AND result = 'ok'", AuditDeleteRequested).Scan(&requested); err != nil || requested == 0 {
		t.Errorf("申请注销应落审计，得到 n=%d err=%v", requested, err)
	}

	// 宽限期内登录 = 撤销
	resp, err := svc.Login(c.Email, "secret123", "calorie-diary", testMeta)
	if err != nil {
		t.Fatalf("宽限期内登录应成功: %v", err)
	}
	if !resp.DeletePendingCancelled {
		t.Error("登录回执 deletePendingCancelled 应为 true")
	}
	_ = svc.pool.QueryRow("SELECT pending_delete_at FROM users WHERE id = ?", c.UID).Scan(&pending)
	if pending != 0 {
		t.Errorf("登录即撤销应清 pending，得到 %d", pending)
	}
	// 撤销信按主题取：注销已杀光全部会话，随后那次登录对 B8 来说是「新设备」，
	// 提醒信会插到「最后一封」位上——断言改为「撤销信确已发出」。
	mailer.lastMailMatching(t, "注销已撤销")
	var cancelled int
	if err := svc.pool.QueryRow(
		"SELECT COUNT(*) FROM audit_logs WHERE action = ? AND result = 'ok'", AuditDeleteCancelled).Scan(&cancelled); err != nil || cancelled == 0 {
		t.Errorf("撤销应落审计，得到 n=%d err=%v", cancelled, err)
	}
	_ = svc.pool.QueryRow("SELECT COUNT(*) FROM users").Scan(&users)
	if users != 1 {
		t.Errorf("撤销后账号应还在，得到 %d", users)
	}
}

// 撤销页链路：确认信里的 token → CheckDeleteCancel 放行 → CancelDelete 清 pending；
// 重复撤销 400（无待执行）、垃圾 token 400。
func TestDeleteCancelPageFlow(t *testing.T) {
	svc, mailer := newTestService(t)
	c := newPasskeyUser(t, svc, mailer, "w3-cancel@example.com")
	if err := svc.SendCode(c.Email, PurposeDelete, ""); err != nil {
		t.Fatalf("发注销码: %v", err)
	}
	if err := svc.RequestAccountDeletion(c, c.Email, codeIn(t, mailer)); err != nil {
		t.Fatalf("申请注销: %v", err)
	}
	m := regexp.MustCompile(`/web/delete-cancel\?token=([A-Za-z0-9._-]+)`).FindStringSubmatch(mailer.html)
	if len(m) != 2 {
		t.Fatalf("确认信里抠不出撤销 token: %s", mailer.html)
	}
	if err := svc.CheckDeleteCancel(m[1]); err != nil {
		t.Errorf("有效 token 的确认页校验应通过: %v", err)
	}
	if err := svc.CancelDelete(m[1]); err != nil {
		t.Fatalf("撤销提交: %v", err)
	}
	var pending int64
	_ = svc.pool.QueryRow("SELECT pending_delete_at FROM users WHERE id = ?", c.UID).Scan(&pending)
	if pending != 0 {
		t.Errorf("撤销后 pending 应清零，得到 %d", pending)
	}
	// 重复撤销 → 400「没有待执行」
	recancelErr := svc.CancelDelete(m[1])
	if code, msg := httpMsg(recancelErr); code != 400 || !strings.Contains(msg, "没有待执行") {
		t.Errorf("重复撤销应 400，得到 %d %q", code, msg)
	}
	// 垃圾 token → 400（同一句友好文案）
	bogusErr := svc.CheckDeleteCancel("bogus-token")
	if code, msg := httpMsg(bogusErr); code != 400 || !strings.Contains(msg, "撤销链接无效") {
		t.Errorf("垃圾 token 应 400，得到 %d %q", code, msg)
	}
}

// 到期清扫：pending 拨到 8 天前 → sweepPendingDeletes 走完整注销管线
//（users/按 uid 存的行全清 + 完成信 + account.delete 审计）。
func TestSweepExecutesDueDeletes(t *testing.T) {
	svc, mailer := newTestService(t)
	c := newPasskeyUser(t, svc, mailer, "w3-sweep@example.com")
	if _, err := svc.pool.Exec(
		"INSERT INTO admin_scopes (uid, app, granted_by, granted_at) VALUES (?, 'calorie-diary', 0, ?)",
		c.UID, time.Now().UnixMilli()); err != nil {
		t.Fatalf("种授权行: %v", err)
	}
	past := time.Now().Add(-8 * 24 * time.Hour).UnixMilli()
	if _, err := svc.pool.Exec("UPDATE users SET pending_delete_at = ? WHERE id = ?", past, c.UID); err != nil {
		t.Fatalf("拨到期: %v", err)
	}
	svc.sweepPendingDeletes()

	var users, scopes int
	_ = svc.pool.QueryRow("SELECT COUNT(*) FROM users WHERE id = ?", c.UID).Scan(&users)
	_ = svc.pool.QueryRow("SELECT COUNT(*) FROM admin_scopes WHERE uid = ?", c.UID).Scan(&scopes)
	if users != 0 || scopes != 0 {
		t.Errorf("到期注销应清掉账号与按 uid 的行，得到 users=%d scopes=%d", users, scopes)
	}
	if !strings.Contains(mailer.subject, "注销已完成") {
		t.Errorf("完成信主题不对: %q", mailer.subject)
	}
	var done int
	if err := svc.pool.QueryRow(
		"SELECT COUNT(*) FROM audit_logs WHERE action = ? AND result = 'ok'", AuditAccountDelete).Scan(&done); err != nil || done == 0 {
		t.Errorf("到期注销应落 account.delete 审计，得到 n=%d err=%v", done, err)
	}
}

// 登录时宽限期已过（清扫滞后）：同步执行注销管线并拒绝登录（该账号已注销）。
func TestLoginPastDeadlinePurgesAndDenies(t *testing.T) {
	svc, mailer := newTestService(t)
	c := newPasskeyUser(t, svc, mailer, "w3-expired@example.com")
	past := time.Now().Add(-8 * 24 * time.Hour).UnixMilli()
	if _, err := svc.pool.Exec("UPDATE users SET pending_delete_at = ? WHERE id = ?", past, c.UID); err != nil {
		t.Fatalf("拨到期: %v", err)
	}
	_, err := svc.Login(c.Email, "secret123", "calorie-diary", testMeta)
	if code, msg := httpMsg(err); code != 401 || !strings.Contains(msg, "该账号已注销") {
		t.Errorf("过期注销的登录应 401「该账号已注销」，得到 %d %q", code, msg)
	}
	var users int
	_ = svc.pool.QueryRow("SELECT COUNT(*) FROM users WHERE id = ?", c.UID).Scan(&users)
	if users != 0 {
		t.Errorf("过期登录应同步执行注销，账号应已删，得到 %d", users)
	}
	if !strings.Contains(mailer.subject, "注销已完成") {
		t.Errorf("同步执行也应发完成信，得到 %q", mailer.subject)
	}
}

// W4 强制改密：password_must_change=1 且 reauth 窗内允许空 oldPassword（passkey
// 登录者不知道临时密码）；flag 清零、换发新凭据、确认信发出；flag=0 或窗过期一律拒。
// 顺带钉住「登录成功刷新 reauth 窗」（W4 的 MarkReauth 补点：走真 Login 拿会话）。
func TestChangePasswordForcedWithoutOldPassword(t *testing.T) {
	svc, mailer := newTestService(t)
	c := newPasskeyUser(t, svc, mailer, "w4-forced@example.com")

	// flag=0：空 oldPassword 400
	_, blankErr := svc.ChangePassword(c, "", "newsecret1")
	if code, _ := httpMsg(blankErr); code != 400 {
		t.Errorf("未置强制改密位时代空 oldPassword 应 400，得到 %d %v", code, blankErr)
	}
	// 置 flag=1（管理员重置的落点）；注册会话没有 reauth_at → 401 固定文案
	if _, err := svc.pool.Exec("UPDATE users SET password_must_change = 1 WHERE id = ?", c.UID); err != nil {
		t.Fatalf("置强制改密位: %v", err)
	}
	_, staleErr := svc.ChangePassword(c, "", "newsecret1")
	if code, msg := httpMsg(staleErr); code != 401 || msg != MsgReauthRequired {
		t.Errorf("无 reauth 窗时空 oldPassword 应 401 固定文案，得到 %d %q", code, msg)
	}

	// 真登录（W4：登录成功即 MarkReauth → 窗内）
	resp, err := svc.Login(c.Email, "secret123", "calorie-diary", testMeta)
	if err != nil {
		t.Fatalf("登录: %v", err)
	}
	if !resp.MustChangePassword {
		t.Fatal("强制改密位应出现在登录回执")
	}
	cur, err := svc.ValidUserID("Bearer " + resp.Token)
	if err != nil {
		t.Fatalf("取身份: %v", err)
	}
	next, err := svc.ChangePassword(cur, "", "newsecret9")
	if err != nil {
		t.Fatalf("窗内空 oldPassword 应放行: %v", err)
	}
	if next.Token == "" {
		t.Error("App 会话改密应换发新 JWT")
	}
	if next.MustChangePassword {
		t.Error("改密后回执 mustChangePassword 应为 false")
	}
	if _, err := svc.ValidUserID("Bearer " + resp.Token); err == nil {
		t.Error("改密后旧 token 应失效")
	}
	reissued, err := svc.ValidUserID("Bearer " + next.Token)
	if err != nil {
		t.Fatalf("换发的新 token 应可用: %v", err)
	}
	var flag int
	_ = svc.pool.QueryRow("SELECT password_must_change FROM users WHERE id = ?", c.UID).Scan(&flag)
	if flag != 0 {
		t.Errorf("改密应清强制改密位，得到 %d", flag)
	}
	// flag 已清：空 oldPassword 不再放行
	_, clearedErr := svc.ChangePassword(reissued, "", "again123x")
	if code, _ := httpMsg(clearedErr); code != 400 {
		t.Errorf("清位后再传空 oldPassword 应 400，得到 %d %v", code, clearedErr)
	}
	// 确认信（W8 第 2 封）：时间 + 入口，不含任何密码
	changedMail := mailer.lastMailMatching(t, "密码已修改")
	if strings.Contains(changedMail.html, "newsecret9") {
		t.Error("改密确认信不该带密码本体")
	}
	// 入口按 CTA 落点钉：文案已从「账号台」改版为「管理账号」，链接仍是账号台
	//（accountURL）——断言落在入口本体上，不再依赖 CTA 文案字面量。
	if !strings.Contains(changedMail.html, accountURL) || !strings.Contains(changedMail.html, "管理账号") {
		t.Errorf("改密确认信应带账号台入口（CTA「管理账号」→ %s），得到 %s", accountURL, changedMail.subject)
	}

	// reauth 窗过期 + flag 重置：空 oldPassword 401
	if _, err := svc.pool.Exec("UPDATE sessions SET reauth_at = ? WHERE id = ?",
		time.Now().Add(-3*time.Hour).UnixMilli(), reissued.SID); err != nil {
		t.Fatalf("回拨 reauth: %v", err)
	}
	if _, err := svc.pool.Exec("UPDATE users SET password_must_change = 1 WHERE id = ?", c.UID); err != nil {
		t.Fatalf("重置强制改密位: %v", err)
	}
	_, windowErr := svc.ChangePassword(reissued, "", "another1x")
	if code, msg := httpMsg(windowErr); code != 401 || msg != MsgReauthRequired {
		t.Errorf("窗过期时空 oldPassword 应 401 固定文案，得到 %d %q", code, msg)
	}
}
