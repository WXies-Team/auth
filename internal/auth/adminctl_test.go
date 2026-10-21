package auth

import (
	"strings"
	"testing"
	"time"
	"unicode"
)

// W1/W2/W5 的业务层用例：纯判定（本机真跑）+ 真库端到端（无 TEST_MYSQL_DSN 跳过，
// 与本仓其它真库用例同策略）。

// ---- 纯单测（无 DB）----

// 临时密码（generate 模式）：恒 16 位、大小写字母数字三类齐全、过得了自身的密码
// 规则——少任何一类都是生成器被改坏。
func TestGenerateTempPasswordStrength(t *testing.T) {
	for i := 0; i < 50; i++ {
		pw, err := generateTempPassword()
		if err != nil {
			t.Fatalf("第 %d 次生成失败: %v", i, err)
		}
		if len([]rune(pw)) != tempPasswordLen {
			t.Fatalf("临时密码应 %d 位，得到 %d（%q）", tempPasswordLen, len([]rune(pw)), pw)
		}
		var upper, lower, digit bool
		for _, r := range pw {
			switch {
			case unicode.IsUpper(r):
				upper = true
			case unicode.IsLower(r):
				lower = true
			case unicode.IsDigit(r):
				digit = true
			}
		}
		if !upper || !lower || !digit {
			t.Errorf("第 %d 次生成缺字符类 upper=%v lower=%v digit=%v（%q）", i, upper, lower, digit, pw)
		}
		if err := validatePassword(pw); err != nil {
			t.Errorf("生成的临时密码过不了自身规则: %v", err)
		}
	}
}

// manual 模式的弱密码判定（契约 6 的 400 口径）：空 / 不足 8 位 / 单一字符类全拒，
// 字母+数字混合放行。
func TestValidateManualPassword(t *testing.T) {
	cases := []struct {
		name, pw string
		wantOK   bool
	}{
		{"空", "", false},
		{"纯空白", "   ", false},
		{"不足8位", "ab12", false},
		{"纯小写", "abcdefgh", false},
		{"纯数字", "12345678", false},
		{"字母+数字", "abc12345", true},
		{"大小写+数字", "Abc12345", true},
		{"字母+符号", "abcd!efg", true},
	}
	for _, c := range cases {
		err := validateManualPassword(c.pw)
		if c.wantOK {
			if err != nil {
				t.Errorf("%s（%q）应通过，得到 %v", c.name, c.pw, err)
			}
			continue
		}
		if code, _ := httpMsg(err); code != 400 {
			t.Errorf("%s（%q）应 400，得到 code=%d err=%v", c.name, c.pw, code, err)
		}
	}
}

// 封禁文案（W2 钉死的元素拼装）：永久与限时两种形态、原因可选、固定尾句。
func TestBanMessageShapes(t *testing.T) {
	permanent := banMessage("恶意刷量", 0)
	for _, want := range []string{"账号已被封禁", "：恶意刷量", "为永久封禁", "如有疑问请联系管理员"} {
		if !strings.Contains(permanent, want) {
			t.Errorf("永久封禁文案缺 %q，得到 %q", want, permanent)
		}
	}
	timed := banMessage("", time.Now().Add(48*time.Hour).UnixMilli())
	for _, want := range []string{"账号已被封禁", "，将于 ", " 解除", "如有疑问请联系管理员"} {
		if !strings.Contains(timed, want) {
			t.Errorf("限时封禁文案缺 %q，得到 %q", want, timed)
		}
	}
	if strings.Contains(timed, "为永久封禁") || strings.Contains(timed, "：") {
		t.Errorf("限时且无原因时不该出现永久段/原因段，得到 %q", timed)
	}
}

// 项目展示序与 allowedApps 白名单同集：加应用只改一处就会被这里抓住。
func TestKnownAppOrderMatchesWhitelist(t *testing.T) {
	if len(knownAppOrder) != len(allowedApps) {
		t.Errorf("knownAppOrder 有 %d 项、allowedApps 有 %d 项，必须同集", len(knownAppOrder), len(allowedApps))
	}
	for _, app := range knownAppOrder {
		if !allowedApps[app] {
			t.Errorf("%s 在展示序里却不在白名单", app)
		}
	}
	for app := range allowedApps {
		if !containsStr(knownAppOrder, app) {
			t.Errorf("%s 在白名单里却不在展示序（项目列表会漏掉它）", app)
		}
	}
}

// 项目拒绝文案带项目名（品牌注册表取名）。
func TestRestrictedMessageNamesProject(t *testing.T) {
	msg := restrictedMessage("calorie-diary")
	if !strings.Contains(msg, "热量日记") || !strings.Contains(msg, "仅限受邀用户登录") {
		t.Errorf("项目拒绝文案应带项目名与固定语义，得到 %q", msg)
	}
}

// ---- 真库端到端（TEST_MYSQL_DSN 缺席即跳过）----

// W1 管理员重置：generate 强随机 + forceChange 置位 + 全会话吊销 + 新密码可登录
//（回执 mustChangePassword=true）+ 通知信含临时密码 + 审计 detail 不落密码。
func TestAdminResetPasswordForcedChangeFlow(t *testing.T) {
	svc, mailer := newTestService(t)
	actor := seedAdminUser(t, svc, mailer, "w1-super@example.com", adminRoleSuper)
	target := newPasskeyUser(t, svc, mailer, "w1-target@example.com")
	// 目标在场一台 App 会话（重置后必须被杀）
	if _, err := svc.Login(target.Email, "secret123", "calorie-diary", testMeta); err != nil {
		t.Fatalf("造目标会话: %v", err)
	}

	// manual 弱密码（纯数字）→ 400
	_, weakErr := svc.AdminResetPassword(actor, AdminScope{Super: true}, target.UID, AdminPasswordReset{
		Mode: "manual", Password: "12345678",
	})
	if code, _ := httpMsg(weakErr); code != 400 {
		t.Errorf("manual 纯数字应 400，得到 %d %v", code, weakErr)
	}
	// 非法 mode → 400
	_, modeErr := svc.AdminResetPassword(actor, AdminScope{Super: true}, target.UID, AdminPasswordReset{
		Mode: "random",
	})
	if code, _ := httpMsg(modeErr); code != 400 {
		t.Errorf("非法 mode 应 400，得到 %d %v", code, modeErr)
	}

	tmp, err := svc.AdminResetPassword(actor, AdminScope{Super: true}, target.UID, AdminPasswordReset{
		Mode: "generate", ForceChange: true, Notify: true, Reason: "测试重置",
	})
	if err != nil {
		t.Fatalf("重置应成功: %v", err)
	}
	if len([]rune(tmp)) != tempPasswordLen {
		t.Errorf("回执临时密码应 %d 位，得到 %d", tempPasswordLen, len([]rune(tmp)))
	}
	// flag 置位
	var flag int
	if err := svc.pool.QueryRow("SELECT password_must_change FROM users WHERE id = ?", target.UID).Scan(&flag); err != nil || flag != 1 {
		t.Errorf("password_must_change 应置 1，得到 %d err=%v", flag, err)
	}
	// 全部会话被杀
	var alive int
	if err := svc.pool.QueryRow("SELECT COUNT(*) FROM sessions WHERE user_id = ? AND revoked_at IS NULL", target.UID).Scan(&alive); err != nil || alive != 0 {
		t.Errorf("重置后目标应无活跃会话，得到 %d err=%v", alive, err)
	}
	// 临时密码可登录，回执必须带 mustChangePassword=true（契约 4）
	resp, err := svc.Login(target.Email, tmp, "calorie-diary", testMeta)
	if err != nil {
		t.Fatalf("临时密码应可登录: %v", err)
	}
	if !resp.MustChangePassword {
		t.Error("强制改密态的登录回执 mustChangePassword 应为 true")
	}
	// 通知信：收件人 + 主题 + 正文含临时密码（W8 第 1 封）。注意临时密码登录是
	// 「全新设备」（重置已杀光旧会话），B8 的登录提醒信会插队——按主题取重置信。
	resetMail := mailer.lastMailMatching(t, "密码重置通知")
	if resetMail.to != target.Email {
		t.Errorf("重置通知应发给目标，得到 to=%q", resetMail.to)
	}
	if !strings.Contains(resetMail.html, tmp) {
		t.Errorf("重置通知正文应含临时密码本体")
	}
	// 审计：detail 记 mode/forceChange/notify/reason，**不记密码**
	var detail string
	if err := svc.pool.QueryRow(
		"SELECT detail FROM audit_logs WHERE action = 'password.reset' AND result = 'ok' ORDER BY id DESC LIMIT 1").
		Scan(&detail); err != nil {
		t.Fatalf("查 password.reset 审计: %v", err)
	}
	for _, want := range []string{`"mode":"generate"`, `"forceChange":"true"`, `"notify":"true"`, `"reason":"测试重置"`} {
		if !strings.Contains(detail, want) {
			t.Errorf("审计 detail 缺 %s，得到 %s", want, detail)
		}
	}
	if strings.Contains(detail, tmp) {
		t.Errorf("审计 detail 泄露了临时密码: %s", detail)
	}
}

// W1 权限矩阵：app-admin 只能动「在任一其授权项目下有会话」的用户；根账号仅根本人；
// 目标不存在 404。
func TestAdminResetPasswordPermissions(t *testing.T) {
	svc, mailer := newTestService(t)
	root := seedAdminUser(t, svc, mailer, RootSuperEmail, adminRoleSuper)
	other := seedAdminUser(t, svc, mailer, "w1-other-super@example.com", adminRoleSuper)
	appAdmin := seedAdminUser(t, svc, mailer, "w1-appadmin@example.com", adminRoleAdmin)
	if err := svc.AdminSetScope(root, appAdmin.UID, "calorie-diary", true); err != nil {
		t.Fatalf("授 app-admin scope: %v", err)
	}
	target := newPasskeyUser(t, svc, mailer, "w1-perm-target@example.com")
	// 注册即登录会给目标一台 calorie 会话——403 那条断言的前置是「无任何会话」，
	// 先吊销注册会话把它造出来（否则 W1 的放行判定本就该过）。
	if _, err := svc.pool.Exec(
		"UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL",
		time.Now().UnixMilli(), target.UID); err != nil {
		t.Fatalf("清目标会话: %v", err)
	}
	scope := AdminScope{Apps: []string{"calorie-diary"}}

	// 目标无任何会话 → 403 你没有该用户的管理权限
	_, err := svc.AdminResetPassword(appAdmin, scope, target.UID, AdminPasswordReset{Mode: "generate"})
	if code, msg := httpMsg(err); code != 403 || !strings.Contains(msg, "你没有该用户的管理权限") {
		t.Fatalf("无会话目标应 403，得到 %d %q", code, msg)
	}
	// 目标在 calorie 有会话 → 放行
	if _, err := svc.Login(target.Email, "secret123", "calorie-diary", testMeta); err != nil {
		t.Fatalf("造目标会话: %v", err)
	}
	if _, err := svc.AdminResetPassword(appAdmin, scope, target.UID, AdminPasswordReset{Mode: "generate"}); err != nil {
		t.Errorf("在任一授权项目下有会话的目标应放行: %v", err)
	}
	// 非根本人动 root 账号 → 403（root 判定按 uid：lazy resolve 已在首轮判定时补齐）
	_, rootErr := svc.AdminResetPassword(other, AdminScope{Super: true}, root.UID, AdminPasswordReset{Mode: "generate"})
	if code, msg := httpMsg(rootErr); code != 403 || !strings.Contains(msg, "根管理员") {
		t.Errorf("非根本人动 root 账号应 403 点名根管理员，得到 %d %q", code, msg)
	}
	// 目标不存在 → 404
	_, ghostErr := svc.AdminResetPassword(root, AdminScope{Super: true}, 999999999, AdminPasswordReset{Mode: "generate"})
	if code, _ := httpMsg(ghostErr); code != 404 {
		t.Errorf("不存在的目标应 404，得到 %d %v", code, ghostErr)
	}
}

// W2 封禁端到端：app 范围封禁拦该 app 登录（文案元素齐）、其它项目不受牵连；
// 旁路写入的封禁行由 /internal/verify 侧的 denyReason 接住（403）；解封恢复；
// 过期限时行惰性清理；admin 传 '*' / 过去的 until / 未知 slug 各有其报。
func TestAdminBanBlocksLoginAndVerify(t *testing.T) {
	svc, mailer := newTestService(t)
	admin := seedAdminUser(t, svc, mailer, "w2-super@example.com", adminRoleSuper)
	user := newPasskeyUser(t, svc, mailer, "w2-user@example.com")
	resp, err := svc.Login(user.Email, "secret123", "calorie-diary", testMeta)
	if err != nil {
		t.Fatalf("造会话: %v", err)
	}

	// 参数闸（都不该落库）：admin 传 '*'、until 已过去、未知 slug
	starErr := svc.AdminBan(admin, AdminScope{Apps: []string{"calorie-diary"}}, user.UID,
		AdminBanInput{App: "*"})
	if code, _ := httpMsg(starErr); code != 400 {
		t.Errorf("app-admin 传 '*' 应 400，得到 %d %v", code, starErr)
	}
	pastErr := svc.AdminBan(admin, AdminScope{Super: true}, user.UID,
		AdminBanInput{App: "calorie-diary", Until: time.Now().Add(-time.Minute).UnixMilli()})
	if code, _ := httpMsg(pastErr); code != 400 {
		t.Errorf("until 已过去应 400，得到 %d %v", code, pastErr)
	}
	slugErr := svc.AdminBan(admin, AdminScope{Super: true}, user.UID,
		AdminBanInput{App: "evil-app"})
	if code, _ := httpMsg(slugErr); code != 400 {
		t.Errorf("未知 slug 应 400，得到 %d %v", code, slugErr)
	}

	// 旁路直插封禁行（不触发 AdminBan 的会话吊销）→ verify 这道闸必须 403：
	// 它接住的正是吊销竞态与旁路写入的活会话
	if _, err := svc.pool.Exec(
		"INSERT INTO user_bans (uid, app, until_ms, reason, banned_by, created_at) VALUES (?,?,0,'旁路写入',?,?)",
		user.UID, "calorie-diary", admin.UID, time.Now().UnixMilli()); err != nil {
		t.Fatalf("种封禁行: %v", err)
	}
	_, verr := svc.Verify("Bearer "+resp.Token, "calorie-diary")
	if code, msg := httpMsg(verr); code != 403 || !strings.Contains(msg, "账号已被封禁") {
		t.Errorf("被封项目的 verify 应 403 报封禁，得到 %d %q", code, msg)
	}
	// 正式封禁（upsert 覆盖旁路行）：会话当场吊销 + 文案元素齐
	if err := svc.AdminBan(admin, AdminScope{Super: true}, user.UID, AdminBanInput{
		App: "calorie-diary", Until: 0, Reason: "违规操作",
	}); err != nil {
		t.Fatalf("封禁应成功: %v", err)
	}
	_, banLogin := svc.Login(user.Email, "secret123", "calorie-diary", testMeta)
	if code, msg := httpMsg(banLogin); code != 403 ||
		!strings.Contains(msg, "账号已被封禁") || !strings.Contains(msg, "：违规操作") ||
		!strings.Contains(msg, "为永久封禁") || !strings.Contains(msg, "如有疑问请联系管理员") {
		t.Errorf("封禁后 calorie 登录应 403 且文案元素齐，得到 %d %q", code, msg)
	}
	// 范围隔离：expense 项目不受牵连
	if _, err := svc.Login(user.Email, "secret123", "expense-diary", testMeta); err != nil {
		t.Errorf("app 范围封禁不该牵连其它项目登录: %v", err)
	}
	// 详情页 bans 回执（契约 6）
	detail, err := svc.AdminUserDetail(user.UID)
	if err != nil {
		t.Fatalf("取详情: %v", err)
	}
	if len(detail.Bans) != 1 || detail.Bans[0].App != "calorie-diary" || detail.Bans[0].Until != 0 || detail.Bans[0].Reason != "违规操作" {
		t.Errorf("详情 bans 不对: %+v", detail.Bans)
	}
	// 解封 → 恢复登录；重复解封幂等
	if err := svc.AdminUnban(admin, AdminScope{Super: true}, user.UID, "calorie-diary", ""); err != nil {
		t.Fatalf("解封: %v", err)
	}
	if err := svc.AdminUnban(admin, AdminScope{Super: true}, user.UID, "calorie-diary", ""); err != nil {
		t.Errorf("重复解封应幂等: %v", err)
	}
	if _, err := svc.Login(user.Email, "secret123", "calorie-diary", testMeta); err != nil {
		t.Errorf("解封后应恢复登录: %v", err)
	}

	// 过期的限时行：判定即视为已解封并惰性删行（无需定时任务）
	past := time.Now().Add(-time.Minute).UnixMilli()
	if _, err := svc.pool.Exec(
		"INSERT INTO user_bans (uid, app, until_ms, reason, banned_by, created_at) VALUES (?,?,?, '', ?, ?)",
		user.UID, "calorie-diary", past, admin.UID, time.Now().UnixMilli()); err != nil {
		t.Fatalf("种过期封禁: %v", err)
	}
	if _, err := svc.Login(user.Email, "secret123", "calorie-diary", testMeta); err != nil {
		t.Errorf("过期封禁不该拦登录: %v", err)
	}
	var left int
	_ = svc.pool.QueryRow("SELECT COUNT(*) FROM user_bans WHERE uid = ? AND app = ?", user.UID, "calorie-diary").Scan(&left)
	if left != 0 {
		t.Errorf("过期封禁行应被惰性删光，剩 %d 行", left)
	}
	// 审计两事件落行
	for _, action := range []string{AuditUserBan, AuditUserUnban} {
		var n int
		if err := svc.pool.QueryRow("SELECT COUNT(*) FROM audit_logs WHERE action = ? AND result = 'ok'", action).Scan(&n); err != nil || n == 0 {
			t.Errorf("%s 应落审计，得到 n=%d err=%v", action, n, err)
		}
	}
}

// W5 项目登录白名单：开限制即清场（不合规会话吊销）、名单内外登录分流（文案带
// 项目名）、su 无限制、移除成员即下线且幂等、关限制恢复、app-admin 越权 403、
// 项目列表回执形状与按 scope 收权。
func TestProjectRestrictionAndAccess(t *testing.T) {
	svc, mailer := newTestService(t)
	super := seedAdminUser(t, svc, mailer, "w5-super@example.com", adminRoleSuper)
	stranger := newPasskeyUser(t, svc, mailer, "w5-stranger@example.com")
	member := newPasskeyUser(t, svc, mailer, "w5-member@example.com")
	appAdmin := seedAdminUser(t, svc, mailer, "w5-appadmin@example.com", adminRoleAdmin)
	if err := svc.AdminSetScope(super, appAdmin.UID, "expense-diary", true); err != nil {
		t.Fatalf("授 app-admin scope: %v", err)
	}
	superScope := AdminScope{Super: true}
	appScope := AdminScope{Apps: []string{"expense-diary"}}

	// stranger 在限制前先登录 calorie（活跃会话，开限制时应被清场）
	if _, err := svc.Login(stranger.Email, "secret123", "calorie-diary", testMeta); err != nil {
		t.Fatalf("造 stranger 会话: %v", err)
	}
	// 开限制：不合规用户的该项目会话当场吊销
	if err := svc.AdminSetRestricted(super, superScope, "calorie-diary", true); err != nil {
		t.Fatalf("开限制: %v", err)
	}
	var strangerAlive int
	if err := svc.pool.QueryRow(
		"SELECT COUNT(*) FROM sessions WHERE user_id = ? AND app = 'calorie-diary' AND revoked_at IS NULL",
		stranger.UID).Scan(&strangerAlive); err != nil || strangerAlive != 0 {
		t.Errorf("开限制应吊销不合规用户的该项目会话，剩 %d err=%v", strangerAlive, err)
	}
	// 名单外用户被拒：文案带项目名与固定语义
	_, denyMsg := svc.Login(stranger.Email, "secret123", "calorie-diary", testMeta)
	if code, msg := httpMsg(denyMsg); code != 403 ||
		!strings.Contains(msg, "热量日记") || !strings.Contains(msg, "仅限受邀用户登录") {
		t.Errorf("名单外登录应 403 且带项目名，得到 %d %q", code, msg)
	}
	// 其它项目不受牵连
	if _, err := svc.Login(stranger.Email, "secret123", "expense-diary", testMeta); err != nil {
		t.Errorf("限制只该作用于本项目: %v", err)
	}
	// su 无限制
	if _, err := svc.Login(super.Email, "secret123", "calorie-diary", testMeta); err != nil {
		t.Errorf("super 不受项目限制: %v", err)
	}

	// 加名单：登录放行；重复加幂等；未知邮箱 404
	if err := svc.AdminGrantAccess(super, superScope, "calorie-diary", member.Email); err != nil {
		t.Fatalf("加名单: %v", err)
	}
	if err := svc.AdminGrantAccess(super, superScope, "calorie-diary", member.Email); err != nil {
		t.Errorf("重复加名单应幂等: %v", err)
	}
	ghostGrant := svc.AdminGrantAccess(super, superScope, "calorie-diary", "ghost@example.com")
	if code, _ := httpMsg(ghostGrant); code != 404 {
		t.Errorf("未知邮箱加名单应 404，得到 %d %v", code, ghostGrant)
	}
	if _, err := svc.Login(member.Email, "secret123", "calorie-diary", testMeta); err != nil {
		t.Errorf("在册用户应可登录: %v", err)
	}

	// 项目列表（super 全量 / app-admin 仅授权项目）
	projects, err := svc.AdminListProjects(superScope)
	if err != nil {
		t.Fatalf("列项目: %v", err)
	}
	if len(projects) != 2 || projects[0].App != "calorie-diary" || projects[0].Name != "热量日记" || !projects[0].Restricted {
		t.Errorf("super 项目列表不对: %+v", projects)
	}
	foundMember := false
	for _, m := range projects[0].Members {
		if m.UID == member.UID && m.Email == member.Email {
			foundMember = true
		}
	}
	if !foundMember {
		t.Errorf("calorie 名单应含 member: %+v", projects[0].Members)
	}
	appProjects, err := svc.AdminListProjects(appScope)
	if err != nil || len(appProjects) != 1 || appProjects[0].App != "expense-diary" {
		t.Errorf("app-admin 只该见授权项目: %+v err=%v", appProjects, err)
	}

	// app-admin 越权：管 calorie 的限制与名单一律 403；未知 slug 400
	restrictErr := svc.AdminSetRestricted(appAdmin, appScope, "calorie-diary", false)
	if code, _ := httpMsg(restrictErr); code != 403 {
		t.Errorf("app-admin 越权改限制应 403，得到 %d %v", code, restrictErr)
	}
	grantErr := svc.AdminGrantAccess(appAdmin, appScope, "calorie-diary", member.Email)
	if code, _ := httpMsg(grantErr); code != 403 {
		t.Errorf("app-admin 越权加名单应 403，得到 %d %v", code, grantErr)
	}
	restrictSlugErr := svc.AdminSetRestricted(super, superScope, "evil-app", true)
	if code, _ := httpMsg(restrictSlugErr); code != 400 {
		t.Errorf("未知 slug 应 400，得到 %d %v", code, restrictSlugErr)
	}

	// 移除成员：删行 + 该项目会话吊销 + 再登录拒；未知邮箱幂等 ok
	if err := svc.AdminRevokeAccess(super, superScope, "calorie-diary", member.Email); err != nil {
		t.Fatalf("移出名单: %v", err)
	}
	var memberAlive int
	_ = svc.pool.QueryRow(
		"SELECT COUNT(*) FROM sessions WHERE user_id = ? AND app = 'calorie-diary' AND revoked_at IS NULL",
		member.UID).Scan(&memberAlive)
	if memberAlive != 0 {
		t.Errorf("移出名单应吊销该项目会话，剩 %d", memberAlive)
	}
	_, memberDeny := svc.Login(member.Email, "secret123", "calorie-diary", testMeta)
	if code, _ := httpMsg(memberDeny); code != 403 {
		t.Errorf("移出名单后登录应 403，得到 %d %v", code, memberDeny)
	}
	if err := svc.AdminRevokeAccess(super, superScope, "calorie-diary", "ghost@example.com"); err != nil {
		t.Errorf("移除未知邮箱应幂等 ok: %v", err)
	}

	// 关限制：恢复登录
	if err := svc.AdminSetRestricted(super, superScope, "calorie-diary", false); err != nil {
		t.Fatalf("关限制: %v", err)
	}
	if _, err := svc.Login(stranger.Email, "secret123", "calorie-diary", testMeta); err != nil {
		t.Errorf("关限制后应恢复登录: %v", err)
	}

	// 四个审计事件落行
	for _, action := range []string{AuditProjectRestrictOn, AuditProjectRestrictOff,
		AuditProjectAccessGrant, AuditProjectAccessRevoke} {
		var n int
		if err := svc.pool.QueryRow("SELECT COUNT(*) FROM audit_logs WHERE action = ? AND result = 'ok'", action).Scan(&n); err != nil || n == 0 {
			t.Errorf("%s 应落审计，得到 n=%d err=%v", action, n, err)
		}
	}
}

// ---- B5：管理员更换邮箱 / 重置资料 ----

// 管理员更换邮箱端到端（真库）：邮箱立即生效且**不 bump token_version**（会话全保留）、
// 在途自助改邮码被烧（防覆盖竞态）、老 token 的 /internal/verify 立即回新邮箱
// （email 读库而非 claim）、新旧邮箱都收管理员措辞通知信、审计 user.email_change
// detail 三键掩码；同邮箱 / 已占用 / 坏格式各有其报。
func TestAdminChangeEmailFlow(t *testing.T) {
	svc, mailer := newTestService(t)
	admin := seedAdminUser(t, svc, mailer, "b5-super@example.com", adminRoleSuper)
	target := newPasskeyUser(t, svc, mailer, "b5-old@example.com")
	registerViaCode(t, svc, mailer, "b5-taken@example.com", "secret123")
	resp, err := svc.Login(target.Email, "secret123", "calorie-diary", testMeta)
	if err != nil {
		t.Fatalf("造目标会话: %v", err)
	}

	// 种一条在途的自助改邮码（发给目标打算改去的地址），改邮后必须被烧
	if err := svc.SendChangeEmailCode(target, "b5-pending@example.com"); err != nil {
		t.Fatalf("造在途改邮码: %v", err)
	}
	var pendingBefore int
	_ = svc.pool.QueryRow("SELECT COUNT(*) FROM otp_codes WHERE email = 'b5-pending@example.com' AND purpose = 'email_change' AND used = 0").Scan(&pendingBefore)
	if pendingBefore == 0 {
		t.Fatal("在途改邮码应处于活跃态")
	}

	// 参数闸：坏格式 / 同邮箱 / 已占用
	badErr := svc.AdminChangeEmail(admin, AdminScope{Super: true}, target.UID, AdminEmailChange{Email: "not-an-email"})
	if code, _ := httpMsg(badErr); code != 400 {
		t.Errorf("坏格式应 400，得到 %d %v", code, badErr)
	}
	sameErr := svc.AdminChangeEmail(admin, AdminScope{Super: true}, target.UID, AdminEmailChange{Email: "b5-OLD@example.com"})
	if code, msg := httpMsg(sameErr); code != 400 || !strings.Contains(msg, "邮箱未变化") {
		t.Errorf("同邮箱（归一化后）应 400「邮箱未变化」，得到 %d %q", code, msg)
	}
	takenErr := svc.AdminChangeEmail(admin, AdminScope{Super: true}, target.UID, AdminEmailChange{Email: "b5-taken@example.com"})
	if code, msg := httpMsg(takenErr); code != 400 || !strings.Contains(msg, "该邮箱已被其它账号使用") {
		t.Errorf("已占用应 400「该邮箱已被其它账号使用」，得到 %d %q", code, msg)
	}

	// 成功路径
	if err := svc.AdminChangeEmail(admin, AdminScope{Super: true}, target.UID, AdminEmailChange{
		Email: "b5-new@example.com", Reason: "用户申诉换绑",
	}); err != nil {
		t.Fatalf("管理员换邮应成功: %v", err)
	}
	var gotEmail string
	var ver int
	if err := svc.pool.QueryRow("SELECT email, token_version FROM users WHERE id = ?", target.UID).Scan(&gotEmail, &ver); err != nil {
		t.Fatalf("查目标: %v", err)
	}
	if gotEmail != "b5-new@example.com" {
		t.Errorf("users.email 应为新值，得到 %q", gotEmail)
	}
	// 不 bump token_version：老 token 仍活（会话全保留），且 verify 立即回新邮箱
	vr, verr := svc.Verify("Bearer "+resp.Token, "calorie-diary")
	if verr != nil {
		t.Errorf("换邮不该吊销会话（不 bump token_version）: %v", verr)
	} else if vr.Email != "b5-new@example.com" {
		t.Errorf("verify 的 email 应读库回新值，得到 %q", vr.Email)
	}
	// 在途自助改邮码被烧
	var pendingAfter int
	_ = svc.pool.QueryRow("SELECT COUNT(*) FROM otp_codes WHERE email = 'b5-pending@example.com' AND purpose = 'email_change' AND used = 0").Scan(&pendingAfter)
	if pendingAfter != 0 {
		t.Errorf("管理员换邮后在途改邮码应全部作废，剩 %d", pendingAfter)
	}
	// 两封管理员措辞通知信：旧邮箱是安全警报（含新邮箱 + 改密指引），新邮箱是指引
	var oldNotice, newNotice bool
	for _, m := range mailer.sent {
		if m.to == "b5-old@example.com" && m.subject == "【Auth】登录邮箱已被管理员更换" &&
			strings.Contains(m.html, "b5-new@example.com") && strings.Contains(m.html, "立即修改密码") {
			oldNotice = true
		}
		if m.to == "b5-new@example.com" && m.subject == "【Auth】新邮箱已生效" &&
			strings.Contains(m.html, "下次登录请使用新邮箱") {
			newNotice = true
		}
	}
	if !oldNotice || !newNotice {
		t.Errorf("新旧邮箱都该收管理员通知信，得到 旧=%v 新=%v", oldNotice, newNotice)
	}
	// 审计：detail 只有 newEmail / oldEmail / reason 三键，且邮箱掩码
	var detail string
	if err := svc.pool.QueryRow(
		"SELECT detail FROM audit_logs WHERE action = 'user.email_change' AND result = 'ok' ORDER BY id DESC LIMIT 1").
		Scan(&detail); err != nil {
		t.Fatalf("查 user.email_change 审计: %v", err)
	}
	for _, want := range []string{`"newEmail":"b***@example.com"`, `"oldEmail":"b***@example.com"`, `"reason":"用户申诉换绑"`} {
		if !strings.Contains(detail, want) {
			t.Errorf("审计 detail 缺 %s，得到 %s", want, detail)
		}
	}
	if strings.Contains(detail, "b5-new@example.com") || strings.Contains(detail, "b5-old@example.com") {
		t.Errorf("审计 detail 泄露了完整邮箱: %s", detail)
	}
}

// 管理员换邮权限矩阵：app-admin 只能动「在任一其授权项目下有会话」的目标；
// 根账号仅根本人；目标不存在 404。
func TestAdminChangeEmailPermissions(t *testing.T) {
	svc, mailer := newTestService(t)
	root := seedAdminUser(t, svc, mailer, RootSuperEmail, adminRoleSuper)
	other := seedAdminUser(t, svc, mailer, "b5p-other-super@example.com", adminRoleSuper)
	appAdmin := seedAdminUser(t, svc, mailer, "b5p-appadmin@example.com", adminRoleAdmin)
	if err := svc.AdminSetScope(root, appAdmin.UID, "calorie-diary", true); err != nil {
		t.Fatalf("授 app-admin scope: %v", err)
	}
	target := newPasskeyUser(t, svc, mailer, "b5p-target@example.com")
	// 注册即登录自带一台 calorie 会话：先吊销，造出「无任何会话」的 403 前置
	//（B5 的矩阵是「app-admin 只能动在授权项目下有活跃会话的用户」）。
	if _, err := svc.pool.Exec(
		"UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL",
		time.Now().UnixMilli(), target.UID); err != nil {
		t.Fatalf("清目标会话: %v", err)
	}
	scope := AdminScope{Apps: []string{"calorie-diary"}}

	denied := svc.AdminChangeEmail(appAdmin, scope, target.UID, AdminEmailChange{Email: "x1@example.com"})
	if code, msg := httpMsg(denied); code != 403 || !strings.Contains(msg, "你没有该用户的管理权限") {
		t.Errorf("无会话目标应 403，得到 %d %q", code, msg)
	}
	if _, err := svc.Login(target.Email, "secret123", "calorie-diary", testMeta); err != nil {
		t.Fatalf("造目标会话: %v", err)
	}
	if err := svc.AdminChangeEmail(appAdmin, scope, target.UID, AdminEmailChange{Email: "x1@example.com"}); err != nil {
		t.Errorf("在任一授权项目下有会话的目标应放行: %v", err)
	}
	rootErr := svc.AdminChangeEmail(other, AdminScope{Super: true}, root.UID, AdminEmailChange{Email: "x2@example.com"})
	if code, msg := httpMsg(rootErr); code != 403 || !strings.Contains(msg, "根管理员") {
		t.Errorf("非根本人动 root 账号应 403 点名根管理员，得到 %d %q", code, msg)
	}
	ghostErr := svc.AdminChangeEmail(root, AdminScope{Super: true}, 999999999, AdminEmailChange{Email: "x3@example.com"})
	if code, _ := httpMsg(ghostErr); code != 404 {
		t.Errorf("不存在的目标应 404，得到 %d %v", code, ghostErr)
	}
}

// 管理员重置资料（真库）：avatar 清图+色归 0、nickname 清空；无档案行幂等；
// 全否 400；审计 user.profile_reset 的 cleared 如实；不动凭证（token_version 不变）。
func TestAdminResetProfile(t *testing.T) {
	svc, mailer := newTestService(t)
	admin := seedAdminUser(t, svc, mailer, "b5r-super@example.com", adminRoleSuper)
	target := newPasskeyUser(t, svc, mailer, "b5r-target@example.com")
	caller, err := svc.ValidUserID("Bearer " + registerViaCode(t, svc, mailer, "b5r-plain@example.com", "secret123").Token)
	if err != nil {
		t.Fatalf("校验失败: %v", err)
	}

	noneErr := svc.AdminResetProfile(admin, AdminScope{Super: true}, target.UID, AdminProfileReset{})
	if code, msg := httpMsg(noneErr); code != 400 || !strings.Contains(msg, "至少选择") {
		t.Errorf("全否应 400「请至少选择要重置的一项」，得到 %d %q", code, msg)
	}

	// 写满档案再重置
	avatar := base64Of(512)
	if _, err := svc.UpdateProfile(target, putReq("管理员可重置的昵称", 5, &avatar)); err != nil {
		t.Fatalf("写档案: %v", err)
	}
	verBefore, _ := svc.tokenVersion(target.UID)
	if err := svc.AdminResetProfile(admin, AdminScope{Super: true}, target.UID,
		AdminProfileReset{Avatar: true, Nickname: true}); err != nil {
		t.Fatalf("重置资料应成功: %v", err)
	}
	prof, err := svc.GetProfile(target.UID)
	if err != nil {
		t.Fatalf("读档案: %v", err)
	}
	if prof.Nickname != "" || prof.AvatarColor != 0 || prof.AvatarImage != nil {
		t.Errorf("重置后档案应回默认，得到 %+v", prof)
	}
	// 不动凭证：token_version 不变
	if verAfter, _ := svc.tokenVersion(target.UID); verAfter != verBefore {
		t.Errorf("资料重置不该动 token_version，得到 %d → %d", verBefore, verAfter)
	}
	// 无档案行的目标：幂等 no-op
	if err := svc.AdminResetProfile(admin, AdminScope{Super: true}, caller.UID,
		AdminProfileReset{Avatar: true}); err != nil {
		t.Errorf("无档案行重置应幂等成功: %v", err)
	}
	// 审计 cleared 如实。按 target_uid 圈定：后面那次「无档案行幂等 no-op」重置
	// 也落审计（cleared=avatar），ORDER BY id DESC 取最新会读到那条。
	var detail string
	if err := svc.pool.QueryRow(
		"SELECT detail FROM audit_logs WHERE action = 'user.profile_reset' AND result = 'ok' AND target_uid = ? ORDER BY id DESC LIMIT 1",
		target.UID).Scan(&detail); err != nil {
		t.Fatalf("查 user.profile_reset 审计: %v", err)
	}
	if !strings.Contains(detail, `"cleared":"avatar,nickname"`) {
		t.Errorf("审计 detail 应记 cleared=avatar,nickname，得到 %s", detail)
	}
}

// 管理员换邮通知信（纯单测）：中性品牌【Auth】前缀；旧邮箱是安全警报（新邮箱入文 +
// 非本人改密联系管理员），新邮箱是指引（下次登录用新邮箱）；邮箱过 HTML 转义。
func TestAdminChangeEmailNoticeEmail(t *testing.T) {
	b := brandFor("")
	subjectOld, bodyOld, _ := adminChangeEmailNoticeEmail(b, false, "old@example.com", "new@example.com")
	if subjectOld != "【Auth】登录邮箱已被管理员更换" {
		t.Errorf("旧邮箱信主题不对: %q", subjectOld)
	}
	for _, want := range []string{"new@example.com", "old@example.com", "立即修改密码", "联系管理员", "管理员"} {
		if !strings.Contains(bodyOld, want) {
			t.Errorf("旧邮箱信缺 %q", want)
		}
	}
	subjectNew, bodyNew, _ := adminChangeEmailNoticeEmail(b, true, "old@example.com", "new@example.com")
	if subjectNew != "【Auth】新邮箱已生效" {
		t.Errorf("新邮箱信主题不对: %q", subjectNew)
	}
	for _, want := range []string{"下次登录请使用新邮箱", "new@example.com"} {
		if !strings.Contains(bodyNew, want) {
			t.Errorf("新邮箱信缺 %q", want)
		}
	}
	// 注入面：邮箱进正文前转义
	_, body, _ := adminChangeEmailNoticeEmail(b, false, `a<b>@x.com`, "n@y.com")
	if strings.Contains(body, "a<b>@x.com") {
		t.Error("旧邮箱未转义，存在注入面")
	}
}
