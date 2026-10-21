package auth

import (
	"encoding/json"
	"math"
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

// 角色变更（合并端点 POST /admin/users/{uid}/role 的业务层）：user↔admin 直改、
// super 只有根 su 能授予/回收、不能改自己、非法角色拒绝、查无此 uid 回 404，
// 且全部进审计（涉 super 落 admin.role.change，其余落 admin.user.role_change）。
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
	// 降级自己：拒绝（否则一次误操作把所有人锁在门外）——任何目标角色都拒
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

// super 角色的收口规则（本批拍板）：只有根 su（RootSuperEmail）能授予/取消 super；
// 其余 su 一律 403；根 su 的升降都落 admin.role.change 审计；降回 user 清授权行。
func TestAdminSetRoleRootSuperOnly(t *testing.T) {
	svc, mailer := newTestService(t)
	root := seedAdminUser(t, svc, mailer, RootSuperEmail, adminRoleSuper)
	other := seedAdminUser(t, svc, mailer, "setrole-super@example.com", adminRoleSuper)
	target := newPasskeyUser(t, svc, mailer, "setrole-target@example.com")
	if err := svc.AdminSetScope(root, target.UID, "calorie-diary", true); err != nil {
		t.Fatalf("造 app-admin: %v", err)
	}

	// 非根 su 授 super → 403 且点名根管理员
	if code, msg := httpMsg(svc.AdminSetRole(other, target.UID, adminRoleSuper)); code != 403 || !strings.Contains(msg, "根管理员") {
		t.Errorf("非根 su 授 super 应 403，得到 %d %q", code, msg)
	}
	// 非根 su 取消他人的 super → 同样 403
	if code, msg := httpMsg(svc.AdminSetRole(other, root.UID, adminRoleAdmin)); code != 403 || !strings.Contains(msg, "根管理员") {
		t.Errorf("非根 su 取消 super 应 403，得到 %d %q", code, msg)
	}
	// 根 su 授 super → 200，且审计落 admin.role.change
	if err := svc.AdminSetRole(root, target.UID, adminRoleSuper); err != nil {
		t.Fatalf("根 su 授 super: %v", err)
	}
	if got, _ := svc.SessionRole(target.UID); got != adminRoleSuper {
		t.Errorf("升后应为 super，得到 %q", got)
	}
	var changes int
	if err := svc.pool.QueryRow(
		"SELECT COUNT(*) FROM audit_logs WHERE action = 'admin.role.change' AND result = 'ok' AND target_uid = ?", target.UID).
		Scan(&changes); err != nil || changes == 0 {
		t.Errorf("涉 super 的角色调整应落 admin.role.change，得到 %d err=%v", changes, err)
	}
	// 根 su 取消（降 admin）→ 200；已无授权行可清（super 本就不带 scope）
	if err := svc.AdminSetRole(root, target.UID, adminRoleAdmin); err != nil {
		t.Fatalf("根 su 降 super: %v", err)
	}
	// 非根 su 的涉 super 尝试也要留痕（fail 行落到 admin.role.change）
	var fails int
	if err := svc.pool.QueryRow(
		"SELECT COUNT(*) FROM audit_logs WHERE action = 'admin.role.change' AND result = 'fail'").
		Scan(&fails); err != nil || fails == 0 {
		t.Errorf("被拒的 super 调整应记 fail，得到 %d err=%v", fails, err)
	}
	// 降 user 清 scopes（残留行不许在下次提权时复活）
	if err := svc.AdminSetRole(root, target.UID, adminRoleUser); err != nil {
		t.Fatalf("降 user: %v", err)
	}
	var left int
	_ = svc.pool.QueryRow("SELECT COUNT(*) FROM admin_scopes WHERE uid = ?", target.UID).Scan(&left)
	if left != 0 {
		t.Errorf("降 user 应清空授权行，剩 %d", left)
	}
	// idempotent：已是目标角色时 200 且不写库
	if err := svc.AdminSetRole(root, target.UID, adminRoleUser); err != nil {
		t.Errorf("重复设为同角色应幂等成功: %v", err)
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

	all, total, _, err := svc.AdminListSessions(0, nil, "", 20, 0)
	if err != nil || total < 2 {
		t.Fatalf("总览应至少 2 条，得到 total=%d err=%v", total, err)
	}
	// 三条：注册即登录那台（newPasskeyUser）+ 本用例建的 web + JWT 各一台
	mine, _, _, err := svc.AdminListSessions(c.UID, nil, "", 20, 0)
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
	rest, _, _, err := svc.AdminListSessions(c.UID, nil, "", 20, 0)
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

// 会话总览的服务端搜索（A4#3）：query 是邮箱片段或精确 uid，过滤在 SQL 里做
//（邮箱条件要 join users），total / totalUsers 按同一条件数——前端不再拿本页
// 100 条会话自己过滤（那会漏掉本页之外的用户，页码也数不出用户数）。
// 真库用例：无 TEST_MYSQL_DSN 时 Skip（与本包其它真库用例同策略），留给 CI。
func TestAdminListSessionsQuery(t *testing.T) {
	svc, mailer := newTestService(t)
	a := newPasskeyUser(t, svc, mailer, "sessq-alpha@example.com")
	b := newPasskeyUser(t, svc, mailer, "sessq-beta@example.com")
	if _, err := svc.CreateWebSession(a.UID, SessionMeta{IP: "203.0.113.10", UserAgent: "Chrome"}); err != nil {
		t.Fatalf("给 a 加第二台设备: %v", err)
	}
	if _, err := svc.CreateWebSession(b.UID, SessionMeta{IP: "203.0.113.11", UserAgent: "Safari"}); err != nil {
		t.Fatalf("给 b 建会话: %v", err)
	}

	// 邮箱片段：只回 a 的会话（注册 1 + 新建 1 = 2 条），用户数 1
	list, total, users, err := svc.AdminListSessions(0, nil, "sessq-alpha", 100, 0)
	if err != nil {
		t.Fatalf("按邮箱片段查会话: %v", err)
	}
	if total != 2 || users != 1 || len(list) != 2 {
		t.Fatalf("片段过滤应 total=2 / totalUsers=1 / 2 行，得到 total=%d users=%d len=%d",
			total, users, len(list))
	}
	for _, it := range list {
		if it.UID != a.UID || !strings.Contains(it.Email, "sessq-alpha") {
			t.Errorf("过滤结果混进了别人的行: %+v", it)
		}
	}

	// 纯数字 query = uid 精确匹配（与 AdminSearchUsers 同一套全串校验分流）
	byUID, totalByUID, usersByUID, err := svc.AdminListSessions(0, nil, strconv.FormatInt(a.UID, 10), 100, 0)
	if err != nil || totalByUID != 2 || usersByUID != 1 || len(byUID) != 2 {
		t.Errorf("按 uid 应同样回 a 的 2 条，得到 total=%d users=%d len=%d err=%v",
			totalByUID, usersByUID, len(byUID), err)
	}
	// 带字母的混合串不能被按前缀解成 uid（否则会错命中 uid 恰好等于前缀的用户）
	mixed, mixedTotal, _, err := svc.AdminListSessions(0, nil, strconv.FormatInt(a.UID, 10)+"x", 100, 0)
	if err != nil || mixedTotal != 0 || len(mixed) != 0 {
		t.Errorf("uid+字母的混合串应走邮箱 LIKE、查无此邮箱即 0 行，得到 total=%d len=%d err=%v",
			mixedTotal, len(mixed), err)
	}

	// 无匹配：空回执且两个计数都为 0（页码文案不许拿旧值糊弄）
	none, nTotal, nUsers, err := svc.AdminListSessions(0, nil, "sessq-nobody", 100, 0)
	if err != nil || nTotal != 0 || nUsers != 0 || len(none) != 0 {
		t.Errorf("查无匹配应全 0，得到 total=%d users=%d len=%d err=%v", nTotal, nUsers, len(none), err)
	}

	// 空 query = 全量口径不变：本用例至少 3 条（a 2 条 + b 1 条）、至少 2 位用户
	all, allTotal, allUsers, err := svc.AdminListSessions(0, nil, "", 100, 0)
	if err != nil || allTotal < 3 || allUsers < 2 || len(all) != allTotal {
		t.Errorf("空 query 应回全量，得到 total=%d users=%d len=%d err=%v",
			allTotal, allUsers, len(all), err)
	}
	// 与 apps 过滤叠加：query + scope 同时生效（app-admin 的数据边界不被搜索绕开）
	if _, err := svc.Login("sessq-alpha@example.com", "secret123", "calorie-diary", testMeta); err != nil {
		t.Fatalf("calorie 登录: %v", err)
	}
	cal, calTotal, _, err := svc.AdminListSessions(0, []string{"calorie-diary"}, "sessq-alpha", 100, 0)
	if err != nil || calTotal == 0 {
		t.Fatalf("query + app 过滤叠加应有行，得到 total=%d err=%v", calTotal, err)
	}
	for _, it := range cal {
		if it.App != "calorie-diary" || it.UID != a.UID {
			t.Errorf("叠加过滤后混进越权行: %+v", it)
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

// AI 用量看板：空表回补零整窗（不造数）、按天升序、today/yesterday/activeToday、
// per-user 聚合与「区间用量降序 + share」、限额四档的默认值（defaultsUsed）与配齐取值。
func TestAdminAIUsage(t *testing.T) {
	svc, _ := newTestService(t)
	now := time.Now()

	// 空表：days 仍是补零的整窗、users 空、today=0（页面据此显示「暂无记录」）
	empty, err := svc.AdminAIUsage(7, nil)
	if err != nil {
		t.Fatalf("查空看板: %v", err)
	}
	if len(empty.Days) != 7 || empty.Today != 0 || empty.Yesterday != 0 || len(empty.Users) != 0 {
		t.Fatalf("空表应为 7 天补零整窗 + 空 users，得到 days=%v users=%v", empty.Days, empty.Users)
	}
	for i, d := range empty.Days {
		if d.Count != 0 {
			t.Errorf("空表第 %d 天应为 0，得到 %+v", i, d)
		}
	}
	if empty.Days[6].Date != now.Format("2006-01-02") || empty.Days[0].Date != now.AddDate(0, 0, -6).Format("2006-01-02") {
		t.Errorf("days 应按日期升序铺满窗口、末位是今天，得到 %+v", empty.Days)
	}
	// 限额四档：没配置时 defaultsUsed=4，per-user 与 global 限额用默认 500 / 5000
	if empty.DefaultsUsed != 4 {
		t.Errorf("四档全走默认时 defaultsUsed 应为 4，得到 %d", empty.DefaultsUsed)
	}
	if empty.Global == nil || empty.Global.Limit != 5000 || empty.Global.Used != 0 {
		t.Errorf("无 global 行时应回 limit=5000/used=0，得到 %+v", empty.Global)
	}

	// 造两天用量：12 个用户今天各 3 次；另一个用户昨天 7 次
	day1 := now.Format("2006-01-02")
	day2 := now.AddDate(0, 0, -1).Format("2006-01-02")
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
	if report.Today != 36 || report.Yesterday != 7 || report.ActiveToday != 12 {
		t.Errorf("today/yesterday/activeToday 应 36/7/12，得到 %d/%d/%d",
			report.Today, report.Yesterday, report.ActiveToday)
	}
	// users 按区间用量降序：昨天 7 次的 2000 排第一（今天为 0 的用户 Today 排序在后）
	if len(report.Users) != 13 {
		t.Fatalf("应有 13 个用户，得到 %d", len(report.Users))
	}
	top := report.Users[0]
	if top.UID != 2000 || top.Range != 7 || top.Today != 0 || top.Share != math.Round(7.0/43.0*10000)/10000 {
		t.Errorf("首行应是 uid=2000（range=7, share=7/43），得到 %+v", top)
	}
	// 默认 per-user 限额 500
	if top.LimitToday != 500 {
		t.Errorf("默认 per-user 限额应 500，得到 %d", top.LimitToday)
	}
	for _, u := range report.Users[1:] {
		if u.Range != 3 || u.Today != 3 {
			t.Errorf("12 个今日用户应各 range=3/today=3，得到 %+v", u)
			break
		}
	}

	// 配齐限额键 → defaultsUsed=0 且用配置值
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
	if withQuota.DefaultsUsed != 0 || withQuota.Global == nil || withQuota.Global.Limit != 6666 {
		t.Errorf("配齐后 defaultsUsed=0、global.limit=6666，得到 %+v", withQuota)
	}
	if withQuota.Users[0].LimitToday != 600 {
		t.Errorf("配齐后 per-user 限额应 600，得到 %d", withQuota.Users[0].LimitToday)
	}

	// 钻取：单用户整窗 + today + limitToday；查无此 uid 404
	detail, err := svc.AdminAIUsageUser(30, nil, 2000)
	if err != nil {
		t.Fatalf("钻取: %v", err)
	}
	if detail.UID != 2000 || detail.Today != 0 || len(detail.Days) != 30 || detail.LimitToday != 600 {
		t.Errorf("钻取回执不对: %+v", detail)
	}
	var sawY bool
	for _, d := range detail.Days {
		if d.Date == day2 {
			sawY = d.Count == 7
		}
	}
	if !sawY {
		t.Errorf("钻取的 days 应含昨日 7 次: %+v", detail.Days)
	}
	_, derr := svc.AdminAIUsageUser(30, nil, 999999999)
	if code, _ := httpMsg(derr); code != 404 {
		t.Errorf("查无 uid 应 404，得到 %d", code)
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
