package auth

import (
	"strings"
	"testing"
	"time"
)

// auditList 回当前测试库里全部审计事件，形如 "login.success:ok"。
func auditList(t *testing.T, svc *Service) []string {
	t.Helper()
	rows, err := svc.pool.Query("SELECT action, result FROM audit_logs ORDER BY id")
	if err != nil {
		t.Fatalf("查审计: %v", err)
	}
	defer func() { _ = rows.Close() }()
	out := make([]string, 0, 16)
	for rows.Next() {
		var action, result string
		if err := rows.Scan(&action, &result); err != nil {
			t.Fatalf("读审计: %v", err)
		}
		out = append(out, action+":"+result)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("遍历审计: %v", err)
	}
	return out
}

func hasEvent(list []string, want string) bool {
	for _, it := range list {
		if it == want {
			return true
		}
	}
	return false
}

// 审计主链：注册、登录成败、改密都落表；actor_email 掩码、来源（IP/UA）在场。
func TestAuditCoreEvents(t *testing.T) {
	svc, mailer := newTestService(t)
	reg := registerViaCode(t, svc, mailer, "audit-flow@example.com", "secret123")
	c, err := svc.ValidUserID("Bearer " + reg.Token)
	if err != nil {
		t.Fatalf("取身份: %v", err)
	}
	c.Meta = testMeta // 路由层会填，测试里手动补上（审计的来源字段来自它）

	// 注册（registerViaCode 内部走 Register）→ register:ok
	if list := auditList(t, svc); !hasEvent(list, "register:ok") {
		t.Errorf("应有 register:ok，得到 %v", list)
	}

	// 登录失败 → login.fail:fail；成功 → login.success:ok，detail.method=password
	if _, err := svc.Login("audit-flow@example.com", "wrong-pass", "calorie-diary", testMeta); err == nil {
		t.Fatal("错密码应失败")
	}
	if _, err := svc.Login("audit-flow@example.com", "secret123", "calorie-diary", testMeta); err != nil {
		t.Fatalf("正确密码应成功: %v", err)
	}
	list := auditList(t, svc)
	if !hasEvent(list, "login.fail:fail") || !hasEvent(list, "login.success:ok") {
		t.Errorf("登录成败都该记，得到 %v", list)
	}

	// 改密（原密码版）→ password.change:ok
	if _, err := svc.ChangePassword(c, "secret123", "newsecret456"); err != nil {
		t.Fatalf("改密: %v", err)
	}
	if list := auditList(t, svc); !hasEvent(list, "password.change:ok") {
		t.Errorf("应有 password.change:ok，得到 %v", list)
	}
	// 改密后旧 token 失效，取不到身份是预期（顺带确认改密确实吊销了）
	if _, err := svc.ValidUserID("Bearer " + reg.Token); err == nil {
		t.Error("改密后旧 token 应失效")
	}

	// actor_email 必须是掩码：全表逐行比对，任何一行漏出完整邮箱都算失败
	var full, masked int
	rows, err := svc.pool.Query("SELECT actor_email FROM audit_logs WHERE actor_email <> ''")
	if err != nil {
		t.Fatalf("查掩码: %v", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var email string
		if err := rows.Scan(&email); err != nil {
			t.Fatalf("读邮箱: %v", err)
		}
		// 完整泄漏的判据看本地部分前缀：掩码形态是 "a***@…"，不含 "audit-flow@"
		if strings.HasPrefix(email, "audit-flow@") {
			full++
		}
		if strings.Contains(email, "***") {
			masked++
		}
	}
	if full != 0 || masked == 0 {
		t.Errorf("actor_email 应全部掩码：完整 %d 行 / 掩码 %d 行", full, masked)
	}
	// 来源字段要落（IP/UA 是排查「谁在哪儿动了账号」的关键）
	var ip, ua string
	if err := svc.pool.QueryRow(
		"SELECT ip, user_agent FROM audit_logs WHERE action = 'register' ORDER BY id LIMIT 1").
		Scan(&ip, &ua); err != nil || ip != testMeta.IP || ua != testMeta.UserAgent {
		t.Errorf("注册事件应带来源: ip=%q ua=%q err=%v", ip, ua, err)
	}
}

// 白盒断言：**任何审计行的 detail 都不得出现密钥类明文**——口令、TOTP secret、
// 恢复码、JWT 密钥。审计表是管理台能看的东西，它自己不能成为泄密面。
func TestAuditDetailCarriesNoSecrets(t *testing.T) {
	svc, mailer := newTestService(t)
	const password = "super-secret-pass-9"
	reg := registerViaCode(t, svc, mailer, "audit-secret@example.com", password)
	c, err := svc.ValidUserID("Bearer " + reg.Token)
	if err != nil {
		t.Fatalf("取身份: %v", err)
	}
	c.Meta = testMeta

	// 走一条会碰 TOTP secret 与恢复码的链路
	setup, err := svc.SetupTOTP(c)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	codes, err := svc.EnableTOTP(c, currentCode(t, setup.Secret))
	if err != nil {
		t.Fatalf("enable: %v", err)
	}
	if _, err := svc.ChangePassword(c, password, "another-pass-77"); err != nil {
		t.Fatalf("改密: %v", err)
	}
	// 用掉一个恢复码（recovery.consume 事件）
	if ok, err := svc.consumeRecoveryCode(c.UID, codes[0], testMeta); err != nil || !ok {
		t.Fatalf("消费恢复码: ok=%v err=%v", ok, err)
	}
	// 换发恢复码（recovery.generate 事件）
	if _, err := svc.pool.Exec("UPDATE totp_factors SET enabled = 1 WHERE user_id = ?", c.UID); err != nil {
		t.Fatalf("置 enabled: %v", err)
	}
	// 换发用下一个步进的码：enable 已把当步进记进防重放账，同一个码会被自己挡下
	if _, err := svc.RegenerateRecoveryCodes(c, codeAt(t, setup.Secret, 30*time.Second)); err != nil {
		t.Fatalf("换发恢复码: %v", err)
	}

	secrets := []string{password, setup.Secret, testSecret}
	for _, rc := range codes {
		secrets = append(secrets, rc, strings.ReplaceAll(rc, "-", ""))
	}
	rows, err := svc.pool.Query("SELECT action, detail FROM audit_logs")
	if err != nil {
		t.Fatalf("查 detail: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var scanned int
	for rows.Next() {
		var action string
		var detail []byte
		if err := rows.Scan(&action, &detail); err != nil {
			t.Fatalf("读 detail: %v", err)
		}
		scanned++
		for _, secret := range secrets {
			if secret != "" && strings.Contains(string(detail), secret) {
				t.Errorf("事件 %s 的 detail 泄露了密钥材料: %s", action, detail)
			}
		}
		// JSON 键名层面也不许出现口令/令牌类字段（值里出现 method=password 是
		// 规格要求的因子标注，形如 "method":"password"，不匹配下面这些键写法）
		lower := strings.ToLower(string(detail))
		for _, banned := range []string{`"password":`, `"secret":`, `"token":`, `"jwt"`} {
			if strings.Contains(lower, banned) {
				t.Errorf("事件 %s 的 detail 出现敏感键名: %s", action, detail)
			}
		}
	}
	if scanned == 0 {
		t.Error("审计表是空的——链路没记上，白盒断言也就没意义")
	}
}

// 保留期：90 天前的行在清理后消失，新行保留。
func TestAuditRetentionCleanup(t *testing.T) {
	svc, _ := newTestService(t)
	now := time.Now().UnixMilli()
	old := svc.ids.Generate().Int64()
	fresh := svc.ids.Generate().Int64()
	if _, err := svc.pool.Exec(
		"INSERT INTO audit_logs (id, ts, actor_uid, actor_email, action, result, ip, user_agent) VALUES (?,?,?,?,?,?,?,?)",
		old, now-auditRetention.Milliseconds()-86400000, 1, "a***@x.com", "login.success", "ok", "", ""); err != nil {
		t.Fatalf("插过期行: %v", err)
	}
	if _, err := svc.pool.Exec(
		"INSERT INTO audit_logs (id, ts, actor_uid, actor_email, action, result, ip, user_agent) VALUES (?,?,?,?,?,?,?,?)",
		fresh, now, 1, "a***@x.com", "login.success", "ok", "", ""); err != nil {
		t.Fatalf("插新行: %v", err)
	}
	svc.CleanAuditLogs()
	var n int
	if err := svc.pool.QueryRow("SELECT COUNT(*) FROM audit_logs WHERE id = ?", old).Scan(&n); err != nil || n != 0 {
		t.Errorf("过期行应被清掉，得到 n=%d err=%v", n, err)
	}
	if err := svc.pool.QueryRow("SELECT COUNT(*) FROM audit_logs WHERE id = ?", fresh).Scan(&n); err != nil || n != 1 {
		t.Errorf("新行必须保留，得到 n=%d err=%v", n, err)
	}
}

// 审计查询：按 action / actor 过滤、倒序分页、总数与页数据一致。
func TestAuditQueryFilters(t *testing.T) {
	svc, mailer := newTestService(t)
	reg := registerViaCode(t, svc, mailer, "audit-query@example.com", "secret123")
	c, _ := svc.ValidUserID("Bearer " + reg.Token)
	c.Meta = testMeta
	if _, err := svc.Login("audit-query@example.com", "nope", "calorie-diary", testMeta); err == nil {
		t.Fatal("错密码应失败")
	}
	if _, err := svc.Login("audit-query@example.com", "secret123", "calorie-diary", testMeta); err != nil {
		t.Fatalf("登录: %v", err)
	}
	_ = reg

	all, total, err := svc.QueryAudit(AuditQuery{Limit: 5})
	if err != nil {
		t.Fatalf("查审计: %v", err)
	}
	if total < 3 || len(all) == 0 || len(all) > 5 {
		t.Errorf("应有分页数据：total=%d len=%d", total, len(all))
	}
	// 倒序：首行应是最新事件（上面最后一次登录）
	if len(all) >= 2 && all[0].TS < all[1].TS {
		t.Error("应按时间倒序")
	}
	// 按 action 过滤
	fails, failTotal, err := svc.QueryAudit(AuditQuery{Action: "login.fail"})
	if err != nil {
		t.Fatalf("按 action 查: %v", err)
	}
	if failTotal == 0 || len(fails) == 0 {
		t.Fatalf("应查得到登录失败事件，得到 total=%d", failTotal)
	}
	for _, row := range fails {
		if row.Action != "login.fail" || row.Result != "fail" {
			t.Errorf("过滤失效: %+v", row)
		}
	}
	// 按 actor 过滤
	byActor, actorTotal, err := svc.QueryAudit(AuditQuery{Actor: c.UID})
	if err != nil || actorTotal == 0 {
		t.Fatalf("按 actor 查: total=%d err=%v", actorTotal, err)
	}
	for _, row := range byActor {
		if row.ActorUID != c.UID {
			t.Errorf("actor 过滤失效: %+v", row)
		}
	}
	// 匿名/不存在的 actor → 0 行
	_, none, err := svc.QueryAudit(AuditQuery{Actor: 999999999999999999})
	if err != nil || none != 0 {
		t.Errorf("查无 actor 应 0 行，得到 %d err=%v", none, err)
	}
}
