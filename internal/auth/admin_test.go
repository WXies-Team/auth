package auth

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

// 用户查询：按邮箱片段与精确 uid 检索、默认 role=user、凭证摘要按 uid 批量回填。
func TestAdminSearchUsers(t *testing.T) {
	svc, mailer := newTestService(t)
	a := newPasskeyUser(t, svc, mailer, "admin-search-a@example.com")
	b := newPasskeyUser(t, svc, mailer, "admin-search-b@example.com")

	// 给 a 开两步验证并加一把 passkey：摘要列要回填出来
	setup, err := svc.SetupTOTP(a)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	if _, err := svc.EnableTOTP(a, currentCode(t, setup.Secret)); err != nil {
		t.Fatalf("enable: %v", err)
	}
	if _, err := svc.insertCredential(a.UID, "A", &webauthn.Credential{ID: []byte("cred-search-a"), PublicKey: []byte{1}}); err != nil {
		t.Fatalf("落凭证: %v", err)
	}

	// 空查询 = 列全部
	all, total, err := svc.AdminSearchUsers("", 20, 0)
	if err != nil {
		t.Fatalf("列用户: %v", err)
	}
	if total < 2 || len(all) != total {
		t.Fatalf("应列出全部用户，total=%d len=%d", total, len(all))
	}
	for _, u := range all {
		if u.Role != adminRoleUser {
			t.Errorf("新用户 role 应为 user，得到 %q（uid %d）", u.Role, u.UID)
		}
	}
	// 摘要回填
	var seenA bool
	for _, u := range all {
		if u.UID == a.UID {
			seenA = true
			if !u.TotpEnabled || u.PasskeyCount != 1 {
				t.Errorf("a 的凭证摘要不对: %+v", u)
			}
		}
		if u.UID == b.UID && (u.TotpEnabled || u.PasskeyCount != 0) {
			t.Errorf("b 没绑任何凭证: %+v", u)
		}
	}
	if !seenA {
		t.Fatal("没查到 a")
	}

	// 邮箱片段
	hits, _, err := svc.AdminSearchUsers("search-b", 20, 0)
	if err != nil || len(hits) != 1 || hits[0].UID != b.UID {
		t.Errorf("按片段应只命中 b，得到 %+v err=%v", hits, err)
	}
	// 精确 uid
	byUID, _, err := svc.AdminSearchUsers("0", 20, 0)
	_ = byUID
	if err != nil {
		t.Fatalf("uid 查询不该报错: %v", err)
	}
	exact, _, err := svc.AdminSearchUsers(strconv.FormatInt(a.UID, 10), 20, 0)
	if err != nil || len(exact) != 1 || exact[0].UID != a.UID {
		t.Errorf("按 uid 应精确命中 a，得到 %+v err=%v", exact, err)
	}
	// n2：带尾巴的串（uid+"x"）不是纯数字，应走邮箱片段 LIKE 而不是被 Sscan
	// 按前缀解成 uid 精确匹配——否则搜 "123abc" 会错命中 uid=123 的行
	mixed, _, err := svc.AdminSearchUsers(strconv.FormatInt(a.UID, 10)+"x", 20, 0)
	if err != nil {
		t.Fatalf("混合串查询不该报错: %v", err)
	}
	for _, u := range mixed {
		if u.UID == a.UID {
			t.Error("uid+字母的混合串不该按 uid 精确命中（应走邮箱片段）")
		}
	}
	// 邮箱片段里带数字仍按 LIKE 命中
	digitHit, _, err := svc.AdminSearchUsers("search-a", 20, 0)
	if err != nil || len(digitHit) != 1 || digitHit[0].UID != a.UID {
		t.Errorf("邮箱片段应照常命中，得到 %+v err=%v", digitHit, err)
	}
	// 分页：limit 收敛到合法区间
	page, _, err := svc.AdminSearchUsers("", 1, 1)
	if err != nil || len(page) > 1 {
		t.Errorf("limit=1 应每页至多 1 条，得到 %d err=%v", len(page), err)
	}
}

// 角色变更：能升能降，但**不能降级自己**、非法角色拒绝、查无此 uid 回 404，且都进审计。
func TestAdminSetRole(t *testing.T) {
	svc, mailer := newTestService(t)
	actor := newPasskeyUser(t, svc, mailer, "admin-actor@example.com")
	target := newPasskeyUser(t, svc, mailer, "admin-target@example.com")
	actor.Meta = testMeta

	if err := svc.AdminSetRole(actor, target.UID, adminRoleAdmin); err != nil {
		t.Fatalf("升目标为 admin: %v", err)
	}
	var role string
	if err := svc.pool.QueryRow("SELECT role FROM users WHERE id = ?", target.UID).Scan(&role); err != nil || role != adminRoleAdmin {
		t.Errorf("role 应为 admin，得到 %q err=%v", role, err)
	}
	// 降级别人：允许
	if err := svc.AdminSetRole(actor, target.UID, adminRoleUser); err != nil {
		t.Fatalf("降目标为 user: %v", err)
	}
	// 降级自己：拒绝（否则一次误操作把所有人锁在门外）
	if err := svc.AdminSetRole(actor, actor.UID, adminRoleUser); err == nil || !strings.Contains(err.Error(), "自己") {
		t.Errorf("应拒绝降级自己，得到 %v", err)
	}
	// 非法角色
	if err := svc.AdminSetRole(actor, target.UID, "superuser"); err == nil {
		t.Error("未知角色应 400")
	}
	// 查无此 uid → 404
	cerr := svc.AdminSetRole(actor, 999999999999999999, adminRoleAdmin)
	if code, _ := httpMsg(cerr); code != 404 {
		t.Errorf("不存在的用户应 404，得到 %d", code)
	}
	// 审计：admin.user.role_change 落表，target 与 detail.role 齐全。
	// 只看成功的那条——后面几次被拒的尝试也各记了一条 fail，取最新会取错。
	var detail string
	var targetSet int64
	if err := svc.pool.QueryRow(
		`SELECT target_uid, detail FROM audit_logs
		 WHERE action = 'admin.user.role_change' AND result = 'ok' AND target_uid = ?
		 ORDER BY id DESC LIMIT 1`, target.UID).
		Scan(&targetSet, &detail); err != nil {
		t.Fatalf("查角色审计: %v", err)
	}
	if targetSet != target.UID || !strings.Contains(detail, `role":"user"`) {
		t.Errorf("审计应带 target 与新角色，得到 target=%d detail=%s", targetSet, detail)
	}
	// 失败的降级自己也应被记（授权失败同样要留痕）
	var failCount int
	if err := svc.pool.QueryRow(
		"SELECT COUNT(*) FROM audit_logs WHERE action = 'admin.user.role_change' AND result = 'fail'").
		Scan(&failCount); err != nil || failCount == 0 {
		t.Errorf("被拒的角色变更应记 fail，得到 %d err=%v", failCount, err)
	}
}

// 会话总览与两种吊销：按 uid 过滤、单吊幂等、整户踢干净后会话当场失效。
func TestAdminSessionsAndRevocation(t *testing.T) {
	svc, mailer := newTestService(t)
	c := newPasskeyUser(t, svc, mailer, "admin-sess@example.com")
	c.Meta = testMeta

	// 两台：一个 web 会话 + 一个 JWT 会话
	ws, err := svc.CreateWebSession(c.UID, SessionMeta{IP: "203.0.113.77", UserAgent: "Chrome"})
	if err != nil {
		t.Fatalf("建 web 会话: %v", err)
	}
	jwtResp, err := svc.Login("admin-sess@example.com", "secret123", "calorie-diary",
		SessionMeta{IP: "198.51.100.7", UserAgent: "Mozilla/5.0 (Linux; Android 14; Pixel 8) Chrome/120 Mobile"})
	if err != nil {
		t.Fatalf("JWT 登录: %v", err)
	}

	all, total, err := svc.AdminListSessions(0, nil, 20, 0)
	if err != nil || total < 2 {
		t.Fatalf("总览应至少 2 条，得到 total=%d err=%v", total, err)
	}
	// 三条：注册即登录那台（newPasskeyUser）+ 本用例建的 web + JWT 各一台
	mine, _, err := svc.AdminListSessions(c.UID, nil, 20, 0)
	if err != nil || len(mine) != 3 {
		t.Fatalf("按 uid 过滤应 3 条，得到 %d err=%v", len(mine), err)
	}
	for _, it := range all {
		if it.UID == 0 || it.Email == "" {
			t.Errorf("总览行应带 uid 与邮箱: %+v", it)
		}
	}

	// 单吊：web 会话被踢后当场 401；重复吊销幂等
	actor := c
	actor.Meta = testMeta
	if err := svc.AdminRevokeSession(actor, ws.SID, nil); err != nil {
		t.Fatalf("吊销会话: %v", err)
	}
	_, werr := svc.ValidWebSession(ws.Token)
	if code, _ := httpMsg(werr); code != 401 {
		t.Errorf("被吊销的 web 会话应 401，得到 %d", code)
	}
	if err := svc.AdminRevokeSession(actor, ws.SID, nil); err != nil {
		t.Errorf("重复吊销应幂等成功: %v", err)
	}
	if err := svc.AdminRevokeSession(actor, 1234567890123456789, nil); err != nil {
		t.Errorf("吊销不存在的 id 也应成功（幂等）: %v", err)
	}

	// 整户踢干净：JWT 会话一并失效（token 的 sid 行没了，verify 当场 401）
	if err := svc.AdminRevokeUserSessions(actor, c.UID); err != nil {
		t.Fatalf("整户吊销: %v", err)
	}
	_, jerr := svc.ValidUserID("Bearer " + jwtResp.Token)
	if code, _ := httpMsg(jerr); code != 401 {
		t.Errorf("被踢用户的 JWT 应 401，得到 %d", code)
	}
	rest, _, err := svc.AdminListSessions(c.UID, nil, 20, 0)
	if err != nil || len(rest) != 0 {
		t.Errorf("踢干净后应 0 条，得到 %d err=%v", len(rest), err)
	}
	// 审计两条管理动作都在
	for _, want := range []string{"admin.session.revoke:ok", "admin.user.session_revoke:ok"} {
		if list := auditList(t, svc); !hasEvent(list, want) {
			t.Errorf("应有 %s，得到 %v", want, list)
		}
	}
}

// 配置中心：secret 只回末 4 位、白名单外的键不出现、写入只记 key 不记值。
func TestAdminConfigMaskingAndWrite(t *testing.T) {
	svc, mailer := newTestService(t)
	actor := newPasskeyUser(t, svc, mailer, "admin-cfg@example.com")
	actor.Meta = testMeta

	// 测试库的 app_config 归本用例管（其它用例的配置都走假 ConfigFunc，不碰这张表）
	const secretKey = "mail_client_secret"
	const secretValue = "super-secret-mail-value-8f3a"
	if _, err := svc.pool.Exec("DELETE FROM app_config"); err != nil {
		t.Fatalf("清配置表: %v", err)
	}
	t.Cleanup(func() { _, _ = svc.pool.Exec("DELETE FROM app_config") })
	seed := map[string]string{
		"mail_client_secret": secretValue,
		"mail_tenant_id":     "tenant-abc",
		"hook_token":         "hook-secret-token-value",
		"llm_model":          "gpt-x",
		"web_private_key":    "should-be-secret", // 前缀不在白名单 → 不该出现
		"panel_debug":        "0",                // 同上
	}
	for k, v := range seed {
		if _, err := svc.pool.Exec("INSERT INTO app_config (`key`, `value`) VALUES (?,?)", k, v); err != nil {
			t.Fatalf("种配置 %s: %v", k, err)
		}
	}

	items, err := svc.AdminListConfig()
	if err != nil {
		t.Fatalf("列配置: %v", err)
	}
	byKey := map[string]ConfigItem{}
	for _, it := range items {
		byKey[it.Key] = it
	}
	// 白名单外的键一个都不许露
	for _, banned := range []string{"web_private_key", "panel_debug"} {
		if _, ok := byKey[banned]; ok {
			t.Errorf("白名单外的键 %s 不该出现在响应里", banned)
		}
	}
	// secret：configured + 末 4 位，Value 必须为空
	for _, key := range []string{"mail_client_secret", "hook_token"} {
		it, ok := byKey[key]
		if !ok {
			t.Fatalf("缺 secret 键 %s", key)
		}
		if !it.Secret || !it.Configured || it.Value != "" {
			t.Errorf("secret 应回 Configured+hint、不回全文: %+v", it)
		}
		if len(it.Hint) != 4 {
			t.Errorf("hint 应是末 4 位，得到 %q", it.Hint)
		}
	}
	// 非 secret：回全文
	if it := byKey["mail_tenant_id"]; it.Value != "tenant-abc" || it.Secret {
		t.Errorf("非 secret 应回全文: %+v", it)
	}
	// 白盒：整个响应序列化后不得出现任何 secret 原值
	raw, err := json.Marshal(items)
	if err != nil {
		t.Fatalf("序列化配置: %v", err)
	}
	for _, leak := range []string{secretValue, "hook-secret-token-value", "should-be-secret"} {
		if strings.Contains(string(raw), leak) {
			t.Errorf("配置响应泄露了 secret: %s", leak)
		}
	}

	// 写：更新已有键 → 值生效（读回现值，不走缓存）
	if err := svc.AdminSetConfig(actor, "llm_model", "gpt-y"); err != nil {
		t.Fatalf("写配置: %v", err)
	}
	items, _ = svc.AdminListConfig()
	found := false
	for _, it := range items {
		if it.Key == "llm_model" {
			found = it.Value == "gpt-y"
		}
	}
	if !found {
		t.Error("写入后读回应是新值（不走 10 秒缓存）")
	}
	// 未知键 → 404；超长值 → 400
	cerr := svc.AdminSetConfig(actor, "random_key", "x")
	if code, _ := httpMsg(cerr); code != 404 {
		t.Errorf("白名单外的键应 404，得到 %d", code)
	}
	cerr2 := svc.AdminSetConfig(actor, "llm_model", strings.Repeat("x", adminMaxConfigValue+1))
	if code, _ := httpMsg(cerr2); code != 400 {
		t.Errorf("超长值应 400，得到 %d", code)
	}
	// 空串 = 清除
	if err := svc.AdminSetConfig(actor, "llm_model", ""); err != nil {
		t.Fatalf("清配置: %v", err)
	}
	afterClear, err := svc.AdminListConfig()
	if err != nil {
		t.Fatalf("清除后再查: %v", err)
	}
	for _, x := range afterClear {
		if x.Key == "llm_model" && x.Configured {
			t.Error("清除后该键不该还是已配置")
		}
	}

	// 审计白盒：只记 key 与旧值是否已配置，**值本身不得出现**
	var detail string
	if err := svc.pool.QueryRow(
		"SELECT detail FROM audit_logs WHERE action = 'admin.config.set' ORDER BY id DESC LIMIT 1").
		Scan(&detail); err != nil {
		t.Fatalf("查配置审计: %v", err)
	}
	if strings.Contains(detail, "gpt-y") || strings.Contains(detail, secretValue) {
		t.Errorf("配置审计泄露了值: %s", detail)
	}
	if !strings.Contains(detail, `"key"`) {
		t.Errorf("审计应记 key: %s", detail)
	}
}

// AI 用量看板：空表如实空（不造数）、聚合与 Top10 截断、限额缺省 20/8/500/5000。
func TestAdminAIUsage(t *testing.T) {
	svc, _ := newTestService(t)

	// 空表：days 为空数组，页面据此显示「暂无记录」
	empty, err := svc.AdminAIUsage(30, nil)
	if err != nil {
		t.Fatalf("查空看板: %v", err)
	}
	if len(empty.Days) != 0 {
		t.Errorf("空表应回空 days，得到 %+v", empty.Days)
	}
	// 限额四档：没配置时用与 quota.go 一致的默认值，configured=false
	q := empty.Quota
	if q.Configured || q.PerMinute != 20 || q.Concurrency != 8 ||
		q.DailyPerUser != 500 || q.DailyGlobal != 5000 {
		t.Errorf("限额缺省应为 20/8/500/5000 且标记未配置，得到 %+v", q)
	}

	// 造两天用量：总量累加、单日 Top10 截断
	day1 := time.Now().Format("2006-01-02")
	day2 := time.Now().AddDate(0, 0, -1).Format("2006-01-02")
	if _, err := svc.pool.Exec("DELETE FROM ai_usage"); err != nil {
		t.Fatalf("清用量表: %v", err)
	}
	t.Cleanup(func() { _, _ = svc.pool.Exec("DELETE FROM ai_usage") })
	for i := 0; i < 12; i++ {
		if _, err := svc.pool.Exec(
			"INSERT INTO ai_usage (scope, subject, day, count) VALUES ('user', ?, ?, ?)",
			strconv.Itoa(1000+i), day1, 3); err != nil {
			t.Fatalf("造用量: %v", err)
		}
	}
	if _, err := svc.pool.Exec(
		"INSERT INTO ai_usage (scope, subject, day, count) VALUES ('user', '2000', ?, 7)", day2); err != nil {
		t.Fatalf("造次日用量: %v", err)
	}

	report, err := svc.AdminAIUsage(30, nil)
	if err != nil {
		t.Fatalf("查看板: %v", err)
	}
	if len(report.Days) != 2 {
		t.Fatalf("应有两天数据，得到 %+v", report.Days)
	}
	// 倒序：最新一天在前
	if report.Days[0].Day != day1 {
		t.Errorf("应按日期倒序，得到首日 %s", report.Days[0].Day)
	}
	if report.Days[0].Total != 36 {
		t.Errorf("day1 总量应 36，得到 %d", report.Days[0].Total)
	}
	if len(report.Days[0].ByUserTop) != 10 {
		t.Errorf("单日 Top10 应截断到 10，得到 %d", len(report.Days[0].ByUserTop))
	}
	if report.Days[1].Total != 7 {
		t.Errorf("day2 总量应 7，得到 %d", report.Days[1].Total)
	}

	// 配齐限额键 → configured=true 且用配置值
	for _, kv := range [][2]string{
		{"ai_rate_per_minute", "33"},
		{"ai_concurrency", "9"},
		{"ai_daily_per_user", "600"},
		{"ai_daily_global", "6666"},
	} {
		if _, err := svc.pool.Exec(
			"INSERT INTO app_config (`key`, `value`) VALUES (?,?) ON DUPLICATE KEY UPDATE `value` = VALUES(`value`)",
			kv[0], kv[1]); err != nil {
			t.Fatalf("种限额键 %s: %v", kv[0], err)
		}
	}
	t.Cleanup(func() {
		_, _ = svc.pool.Exec("DELETE FROM app_config WHERE `key` LIKE 'ai_%'")
	})
	withQuota, err := svc.AdminAIUsage(30, nil)
	if err != nil {
		t.Fatalf("复查看板: %v", err)
	}
	qq := withQuota.Quota
	if !qq.Configured || qq.PerMinute != 33 || qq.Concurrency != 9 ||
		qq.DailyPerUser != 600 || qq.DailyGlobal != 6666 {
		t.Errorf("配置后应回配置值，得到 %+v", qq)
	}
}

// m6/m7 回归：配置中心写入闸——key 长度与字符集校验、ai_* 键值必须正整数、
// ai_usage_merged_at 只读（防全站 AI 计数翻倍），非法输入 400 带中文文案。
func TestAdminSetConfigValidation(t *testing.T) {
	svc, mailer := newTestService(t)
	actor := newPasskeyUser(t, svc, mailer, "admin-cfgval@example.com")
	actor.Meta = testMeta
	if _, err := svc.pool.Exec("DELETE FROM app_config"); err != nil {
		t.Fatalf("清配置表: %v", err)
	}
	t.Cleanup(func() { _, _ = svc.pool.Exec("DELETE FROM app_config") })

	// ai_* 键值必须是正整数：负数 / 0 / 非数字 / 带尾巴的数字全拒，且库中不落行
	for _, bad := range []string{"-1", "0", "abc", "12abc", "1.5", " 3x"} {
		err := svc.AdminSetConfig(actor, "ai_rate_per_minute", bad)
		code, msg := httpMsg(err)
		if code != 400 || !strings.Contains(msg, "正整数") {
			t.Errorf("ai_rate_per_minute=%q 应 400 且提示正整数，得到 %d %q", bad, code, msg)
		}
	}
	var leaked int
	if err := svc.pool.QueryRow(
		"SELECT COUNT(*) FROM app_config WHERE `key` = 'ai_rate_per_minute'").Scan(&leaked); err != nil || leaked != 0 {
		t.Errorf("被拒的值不该落库，得到 %d (err=%v)", leaked, err)
	}
	// 合法正整数照写
	if err := svc.AdminSetConfig(actor, "ai_rate_per_minute", "30"); err != nil {
		t.Errorf("正整数应写入成功: %v", err)
	}
	// 空串 = 删键的语义保留（ai_* 键的清除按钮仍可用）
	if err := svc.AdminSetConfig(actor, "ai_rate_per_minute", ""); err != nil {
		t.Errorf("空串应走清除: %v", err)
	}

	// key 长度 ≤64、字符集限 [A-Za-z0-9_]：超长与带点/横线/空格/中文的一律 400
	for _, badKey := range []string{
		"ai_" + strings.Repeat("k", 64), // 总长 67
		"ai.bad.key",
		"ai-bad-key",
		"ai bad key",
		"ai_配置键",
	} {
		err := svc.AdminSetConfig(actor, badKey, "1")
		code, msg := httpMsg(err)
		if code != 400 || !strings.Contains(msg, "配置键") {
			t.Errorf("非法键 %q 应 400 且提示配置键格式，得到 %d %q", badKey, code, msg)
		}
	}
	// 合法键（64 字符整）照常走到白名单判定（不在白名单前缀内 → 404）
	okKey := strings.Repeat("k", 64)
	if code, _ := httpMsg(svc.AdminSetConfig(actor, okKey, "1")); code != 404 {
		t.Errorf("64 字符合法键应过格式闸、落在白名单 404，得到 %d", code)
	}

	// m7：ai_usage_merged_at 只读——写与删都拒，且文案点名迁移脚本
	errPut := svc.AdminSetConfig(actor, "ai_usage_merged_at", "1700000000")
	if code, msg := httpMsg(errPut); code != 400 || !strings.Contains(msg, "迁移脚本") {
		t.Errorf("写合并标记键应 400「此键由迁移脚本写入，不可编辑」，得到 %d %q", code, msg)
	}
	errDel := svc.AdminSetConfig(actor, "ai_usage_merged_at", "")
	if code, msg := httpMsg(errDel); code != 400 || !strings.Contains(msg, "迁移脚本") {
		t.Errorf("删合并标记键应同样 400，得到 %d %q", code, msg)
	}
	if _, err := svc.pool.Exec(
		"INSERT INTO app_config (`key`, `value`) VALUES ('ai_usage_merged_at','1690000000')"); err != nil {
		t.Fatalf("种合并标记键: %v", err)
	}
	// GET 照常列得出（只读 ≠ 不可见）
	items, err := svc.AdminListConfig()
	if err != nil {
		t.Fatalf("列配置: %v", err)
	}
	var seen bool
	for _, it := range items {
		if it.Key == "ai_usage_merged_at" && it.Configured {
			seen = true
		}
	}
	if !seen {
		t.Error("ai_usage_merged_at 应照常出现在 GET 列表里（只读不隐藏）")
	}
}

// 管理后台的 MFA 门槛：没绑任何凭据的管理员不算数。
func TestHasMFA(t *testing.T) {
	svc, mailer := newTestService(t)
	c := newPasskeyUser(t, svc, mailer, "admin-mfa@example.com")
	if ok, err := svc.HasMFA(c.UID); err != nil || ok {
		t.Errorf("纯密码账号不该算 MFA，得到 ok=%v err=%v", ok, err)
	}
	if _, err := svc.insertCredential(c.UID, "M", &webauthn.Credential{ID: []byte("cred-mfa-1"), PublicKey: []byte{1}}); err != nil {
		t.Fatalf("落凭证: %v", err)
	}
	if ok, err := svc.HasMFA(c.UID); err != nil || !ok {
		t.Errorf("绑了 passkey 应算 MFA，得到 ok=%v err=%v", ok, err)
	}
}
