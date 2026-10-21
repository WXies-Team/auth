package auth

import (
	"database/sql"
	"strconv"
	"strings"
	"testing"
	"time"
)

// seedAdminUser 直接把一个已注册用户提成指定角色（业务层造管理身份的最快路径；
// 授予动作本身另有 TestAdminSetScopeGrantRevoke 覆盖）。
func seedAdminUser(t *testing.T, svc *Service, m *recordMailer, email, role string) Caller {
	t.Helper()
	c := newPasskeyUser(t, svc, m, email)
	if _, err := svc.pool.Exec("UPDATE users SET role = ? WHERE id = ?", role, c.UID); err != nil {
		t.Fatalf("设角色 %s: %v", role, err)
	}
	c.Meta = testMeta
	return c
}

// 授予/回收的完整生命周期：user 被授 app 即提 admin、行落库、审计落行；
// 多 app 叠加；收光最后一行使 role 降回 user（定案）；非法输入各有其报。
func TestAdminSetScopeGrantRevoke(t *testing.T) {
	svc, mailer := newTestService(t)
	super := seedAdminUser(t, svc, mailer, "scope-super@example.com", adminRoleSuper)
	target := newPasskeyUser(t, svc, mailer, "scope-target@example.com")

	// 授予前：user、无行
	if got, _ := svc.SessionRole(target.UID); got != adminRoleUser {
		t.Fatalf("初始 role 应为 user，得到 %q", got)
	}

	// ① 授予 calorie-diary：role 提 admin、行落库、granted_by/granted_at 有值
	if err := svc.AdminSetScope(super, target.UID, "calorie-diary", true); err != nil {
		t.Fatalf("授予应用: %v", err)
	}
	if got, _ := svc.SessionRole(target.UID); got != adminRoleAdmin {
		t.Errorf("授予后 role 应为 admin，得到 %q", got)
	}
	var by int64
	var at int64
	if err := svc.pool.QueryRow("SELECT granted_by, granted_at FROM admin_scopes WHERE uid = ? AND app = ?",
		target.UID, "calorie-diary").Scan(&by, &at); err != nil {
		t.Fatalf("授权行应落库: %v", err)
	}
	if by != super.UID || at == 0 {
		t.Errorf("granted_by 应为操作者、granted_at 非零，得到 by=%d at=%d", by, at)
	}

	// ② 重复授予幂等（INSERT IGNORE，不报错不重复行）
	if err := svc.AdminSetScope(super, target.UID, "calorie-diary", true); err != nil {
		t.Errorf("重复授予应幂等: %v", err)
	}
	var rows int
	_ = svc.pool.QueryRow("SELECT COUNT(*) FROM admin_scopes WHERE uid = ?", target.UID).Scan(&rows)
	if rows != 1 {
		t.Errorf("重复授予不该多出行为 %d", rows)
	}

	// ③ 第二个 app 叠加（一人管多个项目）
	if err := svc.AdminSetScope(super, target.UID, "expense-diary", true); err != nil {
		t.Fatalf("授予第二个应用: %v", err)
	}
	apps, err := svc.AdminScopes(target.UID)
	if err != nil || len(apps) != 2 || apps[0] != "calorie-diary" || apps[1] != "expense-diary" {
		t.Errorf("应持两 app 授权且定序，得到 %v err=%v", apps, err)
	}

	// ④ 收一个：仍是 admin（还剩一行）
	if err := svc.AdminSetScope(super, target.UID, "calorie-diary", false); err != nil {
		t.Fatalf("回收应用: %v", err)
	}
	if got, _ := svc.SessionRole(target.UID); got != adminRoleAdmin {
		t.Errorf("尚有剩余授权时 role 应保持 admin，得到 %q", got)
	}

	// ⑤ 收光最后一个：role 降回 user（定案：零 scope 的 admin 是无权限空壳）
	if err := svc.AdminSetScope(super, target.UID, "expense-diary", false); err != nil {
		t.Fatalf("回收最后应用: %v", err)
	}
	if got, _ := svc.SessionRole(target.UID); got != adminRoleUser {
		t.Errorf("收光授权后 role 应降回 user，得到 %q", got)
	}

	// ⑥ 非法输入：名单外 app 400；查无 uid 404；授予 super 400
	if code, msg := httpMsg(svc.AdminSetScope(super, target.UID, "evil-app", true)); code != 400 || !strings.Contains(msg, "未知项目") {
		t.Errorf("名单外 app 应 400「未知项目」，得到 %d %q", code, msg)
	}
	if code, _ := httpMsg(svc.AdminSetScope(super, 999999999999999999, "calorie-diary", true)); code != 404 {
		t.Errorf("查无 uid 应 404，得到 %d", code)
	}
	if code, msg := httpMsg(svc.AdminSetScope(super, super.UID, "calorie-diary", true)); code != 400 || !strings.Contains(msg, "平台管理员") {
		t.Errorf("给 super 授应用应 400，得到 %d %q", code, msg)
	}

	// ⑦ 审计两条都落行且 detail 只带 app（grant 有多条，按 detail 里的 app 精确找）
	var grantDetail string
	if err := svc.pool.QueryRow(
		`SELECT detail FROM audit_logs WHERE action = ? AND result = 'ok' AND detail LIKE '%"app":"calorie-diary"%'
		 ORDER BY id DESC LIMIT 1`, AuditRoleGrant).Scan(&grantDetail); err != nil {
		t.Fatalf("查 grant 审计: %v", err)
	}
	if !strings.Contains(grantDetail, `"app":"calorie-diary"`) {
		t.Errorf("grant 审计应带 app，得到 %s", grantDetail)
	}
	var revokeDetail string
	if err := svc.pool.QueryRow(
		"SELECT detail FROM audit_logs WHERE action = ? AND result = 'ok' ORDER BY id DESC LIMIT 1",
		AuditRoleRevoke).Scan(&revokeDetail); err != nil {
		t.Fatalf("查 revoke 审计: %v", err)
	}
	if !strings.Contains(revokeDetail, `"app":"expense-diary"`) {
		t.Errorf("revoke 审计应带 app，得到 %s", revokeDetail)
	}
}

// 平台角色（super 的授予/回收）与三值角色调整已合并到 admin.go 的 AdminSetRole
//（POST /admin/users/{uid}/role），用例见 admin_test.go 的 TestAdminSetRole 与
// TestAdminSetRoleRootSuperOnly（含根 su 收口、清 scopes、幂等与审计分流）。

func TestAdminListSessionsAppsFilter(t *testing.T) {
	svc, mailer := newTestService(t)
	newPasskeyUser(t, svc, mailer, "sessfilter@example.com")
	if _, err := svc.Login("sessfilter@example.com", "secret123", "calorie-diary", testMeta); err != nil {
		t.Fatalf("calorie 登录: %v", err)
	}
	if _, err := svc.Login("sessfilter@example.com", "secret123", "expense-diary", testMeta); err != nil {
		t.Fatalf("expense 登录: %v", err)
	}

	all, _, _, err := svc.AdminListSessions(0, nil, "", 50, 0)
	if err != nil || len(all) < 3 {
		t.Fatalf("全量应至少 3 行（注册 + 两 app），得到 %d err=%v", len(all), err)
	}
	cal, _, _, err := svc.AdminListSessions(0, []string{"calorie-diary"}, "", 50, 0)
	if err != nil || len(cal) == 0 {
		t.Fatalf("按 app 过滤应有行，得到 %d err=%v", len(cal), err)
	}
	for _, it := range cal {
		if it.App != "calorie-diary" {
			t.Errorf("过滤后不该出现 %s 的行: %+v", it.App, it)
		}
	}
	both, _, _, err := svc.AdminListSessions(0, []string{"calorie-diary", "expense-diary"}, "", 50, 0)
	if err != nil || len(both) < 2 {
		t.Errorf("双 app 过滤应含两 app 的行，得到 %d err=%v", len(both), err)
	}
}

// 吊销的 app 边界：app-admin 只能踢授权 app 的会话，越界 403；super 不限；
// 不存在的 id 仍幂等成功（不因收权改变老语义）。
func TestAdminRevokeSessionScopeBoundary(t *testing.T) {
	svc, mailer := newTestService(t)
	adminA := seedAdminUser(t, svc, mailer, "kick-a@example.com", adminRoleAdmin)
	if _, err := svc.pool.Exec("INSERT INTO admin_scopes (uid, app, granted_by, granted_at) VALUES (?,?,?,?)",
		adminA.UID, "calorie-diary", adminA.UID, time.Now().UnixMilli()); err != nil {
		t.Fatalf("落授权行: %v", err)
	}
	user := newPasskeyUser(t, svc, mailer, "kick-victim@example.com")
	if _, err := svc.Login("kick-victim@example.com", "secret123", "calorie-diary", testMeta); err != nil {
		t.Fatalf("calorie 登录: %v", err)
	}
	if _, err := svc.Login("kick-victim@example.com", "secret123", "expense-diary", testMeta); err != nil {
		t.Fatalf("expense 登录: %v", err)
	}
	// 两台的 sid 直接从会话表按 app 反查（业务层测试不必绕 JWT claims）
	sidOf := func(app string) int64 {
		var sid int64
		if err := svc.pool.QueryRow("SELECT id FROM sessions WHERE user_id = ? AND app = ? AND revoked_at IS NULL",
			user.UID, app).Scan(&sid); err != nil {
			t.Fatalf("查 %s 会话: %v", app, err)
		}
		return sid
	}
	calSID, expSID := sidOf("calorie-diary"), sidOf("expense-diary")

	// 越界：踢 expense 会话 → 403，会话仍活着
	if code, msg := httpMsg(svc.AdminRevokeSession(adminA, expSID, []string{"calorie-diary"})); code != 403 || !strings.Contains(msg, "没有该项目") {
		t.Errorf("越界踢会话应 403，得到 %d %q", code, msg)
	}
	var revoked sql.NullInt64
	if err := svc.pool.QueryRow("SELECT revoked_at FROM sessions WHERE id = ?", expSID).Scan(&revoked); err != nil || revoked.Valid {
		t.Errorf("被拒的吊销不该生效（revoked_at 应为 NULL），得到 valid=%v err=%v", revoked.Valid, err)
	}
	// 边界内：踢 calorie 会话 → 成功
	if err := svc.AdminRevokeSession(adminA, calSID, []string{"calorie-diary"}); err != nil {
		t.Errorf("授权 app 内踢会话应成功: %v", err)
	}
	// super（apps=nil）不限
	if err := svc.AdminRevokeSession(adminA, expSID, nil); err != nil {
		t.Errorf("apps=nil 应不限: %v", err)
	}
	// 不存在的 id 幂等成功
	if err := svc.AdminRevokeSession(adminA, 1234567890123456789, []string{"calorie-diary"}); err != nil {
		t.Errorf("不存在的 id 应幂等成功: %v", err)
	}
	// 越界尝试落 fail 审计
	var fails int
	_ = svc.pool.QueryRow("SELECT COUNT(*) FROM audit_logs WHERE action = ? AND result = 'fail'",
		AuditAdminSession).Scan(&fails)
	if fails == 0 {
		t.Error("越界吊销应记 fail 审计")
	}
}

// 审计的 app 过滤：app-admin 只见 detail 带自己 app 标记的条目；空 = 全量。
func TestQueryAuditAppsFilter(t *testing.T) {
	svc, mailer := newTestService(t)
	newPasskeyUser(t, svc, mailer, "auditfilter@example.com")
	if _, err := svc.Login("auditfilter@example.com", "secret123", "calorie-diary", testMeta); err != nil {
		t.Fatalf("登录: %v", err)
	}

	// 登录事件的 detail 带 {"app":"calorie-diary"}
	_, allTotal, err := svc.QueryAudit(AuditQuery{Limit: 50})
	if err != nil || allTotal == 0 {
		t.Fatalf("全量审计应有行，total=%d err=%v", allTotal, err)
	}
	cal, calTotal, err := svc.QueryAudit(AuditQuery{Limit: 50, Apps: []string{"calorie-diary"}})
	if err != nil || calTotal == 0 {
		t.Fatalf("按 app 过滤审计应有行，total=%d err=%v", calTotal, err)
	}
	if calTotal > allTotal {
		t.Errorf("过滤后不该多于全量: %d > %d", calTotal, allTotal)
	}
	for _, it := range cal {
		if it.Detail["app"] != "calorie-diary" {
			t.Errorf("过滤结果混入非本 app 条目: %+v", it)
		}
	}
	// 名单外 app 过滤出空（route 层已挡名单外，这里验证口径本身）
	exp, expTotal, err := svc.QueryAudit(AuditQuery{Limit: 50, Apps: []string{"expense-diary"}})
	if err != nil {
		t.Fatalf("expense 过滤: %v", err)
	}
	if expTotal != 0 {
		t.Errorf("expense 视角不该看到 calorie 登录条目，得到 %d: %+v", expTotal, exp)
	}
}

// AI 用量的 app 过滤：app-admin 只见「该 app 用户」的行，global 行被隐藏；
// 空 = 全量（含 global）。用户归属按 sessions 行判定，直接落行钉口径
//（不过注册链——注册固定 calorie 会话，会把 u2 也算成 calorie 用户）。
func TestAdminAIUsageAppsFilter(t *testing.T) {
	svc, _ := newTestService(t)
	day := time.Now().Format("2006-01-02")
	if _, err := svc.pool.Exec("DELETE FROM ai_usage"); err != nil {
		t.Fatalf("清用量表: %v", err)
	}
	t.Cleanup(func() { _, _ = svc.pool.Exec("DELETE FROM ai_usage") })

	// u1 只用 calorie，u2 只用 expense（账号 + 会话行直落）
	u1, u2 := int64(8800001), int64(8800002)
	now := time.Now().UnixMilli()
	for _, u := range []struct {
		id    int64
		email string
		app   string
	}{{u1, "ai-u1@example.com", "calorie-diary"}, {u2, "ai-u2@example.com", "expense-diary"}} {
		if _, err := svc.pool.Exec(
			"INSERT INTO users (id, email, created_at, token_version) VALUES (?,?,?,1)", u.id, u.email, now); err != nil {
			t.Fatalf("落用户: %v", err)
		}
		if _, err := svc.pool.Exec(
			"INSERT INTO sessions (id, user_id, app, device, ip, user_agent, created_at, last_seen_at)"+
				" VALUES (?,?,?,?,?,?,?,?)",
			now+u.id, u.id, u.app, "Test", "127.0.0.1", "AITest/1.0", now, now); err != nil {
			t.Fatalf("落会话: %v", err)
		}
	}
	seed := func(uid int64, count int) {
		if _, err := svc.pool.Exec(
			"INSERT INTO ai_usage (scope, subject, day, `count`) VALUES ('user', ?, ?, ?)",
			strconv.FormatInt(uid, 10), day, count); err != nil {
			t.Fatalf("造用量: %v", err)
		}
	}
	seed(u1, 5)
	seed(u2, 7)
	if _, err := svc.pool.Exec(
		"INSERT INTO ai_usage (scope, subject, day, `count`) VALUES ('global', '', ?, 99)", day); err != nil {
		t.Fatalf("造 global 用量: %v", err)
	}

	// super（nil）：全量 user 行合计；global 行单独走 global.used（不与 user 行相加，
	// 否则真实数据里 global == Σuser 会把总量翻倍）
	full, err := svc.AdminAIUsage(7, nil)
	if err != nil || len(full.Days) == 0 {
		t.Fatalf("全量看板: %v", err)
	}
	if full.Today != 5+7 {
		t.Errorf("全量今日 user 行合计应为 12，得到 %d", full.Today)
	}
	if full.Global == nil || full.Global.Used != 99 {
		t.Errorf("super 视角应带 global.used=99，得到 %+v", full.Global)
	}

	// calorie 视角：只见 u1（5）；u2 与 global 行都在视野外
	cal, err := svc.AdminAIUsage(7, []string{"calorie-diary"})
	if err != nil || len(cal.Days) == 0 {
		t.Fatalf("calorie 看板: %v", err)
	}
	if cal.Today != 5 {
		t.Errorf("calorie 今日合计应为 5，得到 %d", cal.Today)
	}
	if cal.Global != nil {
		t.Errorf("app-admin 视角应隐藏 global 行，得到 %+v", cal.Global)
	}
	for _, u := range cal.Users {
		if u.UID == u2 || u.UID == 0 {
			t.Errorf("calorie 视角混入 global/u2: %+v", u)
		}
	}

	// expense 视角：只见 u2（7）
	exp, err := svc.AdminAIUsage(7, []string{"expense-diary"})
	if err != nil || len(exp.Days) == 0 {
		t.Fatalf("expense 看板: %v", err)
	}
	if exp.Today != 7 {
		t.Errorf("expense 今日合计应为 7，得到 %d", exp.Today)
	}
	if exp.Global != nil {
		t.Errorf("app-admin 视角应隐藏 global 行，得到 %+v", exp.Global)
	}

	// 钻取的收权口径与总览同源：calorie 视角钻 u2（expense 用户）→ 404（不泄露存在性）
	_, derr := svc.AdminAIUsageUser(7, []string{"calorie-diary"}, u2)
	if code, _ := httpMsg(derr); code != 404 {
		t.Errorf("越界钻取应 404，得到 %d", code)
	}
	if _, err := svc.AdminAIUsageUser(7, []string{"calorie-diary"}, u1); err != nil {
		t.Errorf("授权项目内钻取应成功: %v", err)
	}
}
// 注销清 scopes：授权行随账号删除，不留指向已删账号的残留。
func TestDeleteAccountClearsScopes(t *testing.T) {
	svc, mailer := newTestService(t)
	super := seedAdminUser(t, svc, mailer, "del-super@example.com", adminRoleSuper)
	victim := registerViaCode(t, svc, mailer, "del-scope@example.com", "secret123")
	c, err := svc.ValidUserID("Bearer " + victim.Token)
	if err != nil {
		t.Fatalf("解析 victim: %v", err)
	}
	if err := svc.AdminSetScope(super, c.UID, "calorie-diary", true); err != nil {
		t.Fatalf("授予: %v", err)
	}
	var before int
	_ = svc.pool.QueryRow("SELECT COUNT(*) FROM admin_scopes WHERE uid = ?", c.UID).Scan(&before)
	if before == 0 {
		t.Fatal("注销前应有授权行")
	}
	if err := svc.DeleteAccount(c.UID, "secret123"); err != nil {
		t.Fatalf("注销: %v", err)
	}
	var after int
	_ = svc.pool.QueryRow("SELECT COUNT(*) FROM admin_scopes WHERE uid = ?", c.UID).Scan(&after)
	if after != 0 {
		t.Errorf("注销后授权行应清空，剩 %d", after)
	}
}

// 角色值域：IsAdminRole 认 admin/super，IsSuperRole 只认 super。
func TestIsAdminRole(t *testing.T) {
	for _, c := range []struct {
		role  string
		admin bool
		super bool
	}{{"user", false, false}, {"admin", true, false}, {"super", true, true}, {"", false, false}, {"root", false, false}} {
		if got := IsAdminRole(c.role); got != c.admin {
			t.Errorf("IsAdminRole(%q) = %v，应 %v", c.role, got, c.admin)
		}
		if got := IsSuperRole(c.role); got != c.super {
			t.Errorf("IsSuperRole(%q) = %v，应 %v", c.role, got, c.super)
		}
	}
}
