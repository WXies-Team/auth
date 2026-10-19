package auth

import (
	"strings"
	"testing"

	"github.com/WXies-Team/auth/internal/protocol"
)

func strPtr(s string) *string { return &s }

// 存量并入的主链路：已有邮箱只回 uid 且**一行不改**；新邮箱按入参建行
// （7 位随机 uid、原样 hash、入参 created_at）；响应顺序与入参一致；整批可重跑。
func TestEnsureUsersMigratesExistingAndNew(t *testing.T) {
	svc, mailer := newTestService(t)
	reg := registerViaCode(t, svc, mailer, "old@example.com", "secret123")
	claimUID := tokenClaimUID(t, reg.Token)

	var beforeHash string
	var beforeCreated int64
	if err := svc.pool.QueryRow(
		"SELECT password_hash, created_at FROM users WHERE email = 'old@example.com'").
		Scan(&beforeHash, &beforeCreated); err != nil {
		t.Fatalf("读已有行: %v", err)
	}

	// 迁移来的旧哈希原样落库：不重算（重算需要明文），也不校验格式
	const legacyHash = "$2a$12$QkT7v0Kq8mJd1sXf3yNpOeR5cA6bB9hH0gG4iI2jJ1kL5mM6nN7oP"
	entries := []protocol.EnsureUserEntry{
		// 已有邮箱：入参里的 hash 与 created_at 都不该落到库里
		{Email: "  OLD@Example.COM ", PasswordHash: strPtr("must-not-land"), CreatedAt: 1699999999999},
		{Email: "new@example.com", PasswordHash: strPtr(legacyHash), CreatedAt: 1600000000123},
		// 纯邮箱验证码用户：password_hash 落 NULL
		{Email: "codeonly@example.com", PasswordHash: nil, CreatedAt: 1600000000456},
	}
	res, err := svc.EnsureUsers(entries)
	if err != nil {
		t.Fatalf("并入失败: %v", err)
	}
	if len(res) != 3 {
		t.Fatalf("应回 3 条，得到 %d 条", len(res))
	}
	// 顺序与入参一致、邮箱是归一化后的写法
	wantEmails := []string{"old@example.com", "new@example.com", "codeonly@example.com"}
	for i, r := range res {
		if r.Email != wantEmails[i] {
			t.Errorf("第 %d 条邮箱应为 %q，得到 %q", i, wantEmails[i], r.Email)
		}
		// 新号必在 7 位号段内（见 newUserID）
		if r.UID < uidMin || r.UID > uidMax {
			t.Errorf("第 %d 条 uid 应落在 %d~%d，得到 %d", i, uidMin, uidMax, r.UID)
		}
	}
	if res[0].UID != claimUID {
		t.Errorf("已有邮箱应回既有 uid: %d vs 库中 %d", res[0].UID, claimUID)
	}
	if res[1].UID == res[0].UID || res[2].UID == res[1].UID {
		t.Errorf("新邮箱应各拿新 uid，得到 %d / %d / %d", res[0].UID, res[1].UID, res[2].UID)
	}

	// 已有行一个字段都没动
	var afterHash string
	var afterCreated int64
	if err := svc.pool.QueryRow(
		"SELECT password_hash, created_at FROM users WHERE email = 'old@example.com'").
		Scan(&afterHash, &afterCreated); err != nil {
		t.Fatalf("复查已有行: %v", err)
	}
	if afterHash != beforeHash || afterCreated != beforeCreated {
		t.Errorf("已有行被改动: hash %q→%q created_at %d→%d",
			beforeHash, afterHash, beforeCreated, afterCreated)
	}

	// 新行的三个字段都按入参落库
	var gotID int64
	var gotHash string
	var gotCreated int64
	if err := svc.pool.QueryRow(
		"SELECT id, password_hash, created_at FROM users WHERE email = 'new@example.com'").
		Scan(&gotID, &gotHash, &gotCreated); err != nil {
		t.Fatalf("读新行: %v", err)
	}
	if gotID != res[1].UID || gotHash != legacyHash || gotCreated != 1600000000123 {
		t.Errorf("新行落库不对: id=%d hash=%q created_at=%d", gotID, gotHash, gotCreated)
	}
	// NULL hash（纯验证码用户）必须真的落成 NULL，而不是空串——
	// 空串会让 Login 走 bcrypt 解析并报错，NULL 才是「这账号没有密码」
	var nullHash interface{}
	if err := svc.pool.QueryRow(
		"SELECT password_hash FROM users WHERE email = 'codeonly@example.com'").Scan(&nullHash); err != nil {
		t.Fatalf("读验证码用户行: %v", err)
	}
	if nullHash != nil {
		t.Errorf("password_hash 应落 NULL，得到 %#v", nullHash)
	}
	// NULL 形态的账号：免密登录照常可用，密码登录按「密码不匹配」失败
	if _, err := svc.Login("codeonly@example.com", "whatever123", "calorie-diary", testMeta); err == nil {
		t.Error("没有密码的账号不该能用密码登录")
	}
	if err := svc.SendCode("codeonly@example.com", PurposeLogin, "calorie-diary"); err != nil {
		t.Errorf("验证码登录链路应可用: %v", err)
	}

	// 幂等：整批重跑返回同样的 uid、行数不变
	again, err := svc.EnsureUsers(entries)
	if err != nil {
		t.Fatalf("重跑失败: %v", err)
	}
	for i := range again {
		if again[i].UID != res[i].UID {
			t.Errorf("重跑第 %d 条 uid 变了: %d → %d", i, res[i].UID, again[i].UID)
		}
	}
	var count int
	if err := svc.pool.QueryRow("SELECT COUNT(*) FROM users").Scan(&count); err != nil || count != 3 {
		t.Errorf("重跑不该多出账号，得到 %d 条 (err=%v)", count, err)
	}
}

// 非法条目整条 400 并报下标，且**前面已插入的条目跟着事务一起回滚**——
// 迁移中途出错绝不能留下半批用户。
func TestEnsureUsersRejectsInvalidEmailAndRollsBack(t *testing.T) {
	svc, _ := newTestService(t)

	_, err := svc.EnsureUsers([]protocol.EnsureUserEntry{
		{Email: "good@example.com", CreatedAt: 1600000000000},
		{Email: "not-an-email", CreatedAt: 1600000000001},
	})
	if code, msg := httpMsg(err); code != 400 || !strings.Contains(msg, "下标 1") {
		t.Errorf("非法邮箱应 400 并指明下标，得到 %d %q", code, msg)
	}
	var count int
	if err := svc.pool.QueryRow("SELECT COUNT(*) FROM users").Scan(&count); err != nil || count != 0 {
		t.Errorf("下标 0 已插入过，必须随事务回滚，库里还有 %d 条 (err=%v)", count, err)
	}

	// 首条就非法：同样 400 + 下标 0
	_, err = svc.EnsureUsers([]protocol.EnsureUserEntry{{Email: "bad", CreatedAt: 1}})
	if code, msg := httpMsg(err); code != 400 || !strings.Contains(msg, "下标 0") {
		t.Errorf("首条非法应 400「下标 0…」，得到 %d %q", code, msg)
	}
}

// 批量边界：空批合法（一条不写），超上限整批拒。
func TestEnsureUsersBatchLimits(t *testing.T) {
	svc, _ := newTestService(t)

	res, err := svc.EnsureUsers(nil)
	if err != nil || len(res) != 0 {
		t.Errorf("空批应返回空结果，得到 %d 条 err=%v", len(res), err)
	}

	tooMany := make([]protocol.EnsureUserEntry, maxEnsureBatch+1)
	_, err = svc.EnsureUsers(tooMany)
	if code, msg := httpMsg(err); code != 400 || !strings.Contains(msg, "最多") {
		t.Errorf("超过 %d 条应 400，得到 %d %q", maxEnsureBatch, code, msg)
	}
	var count int
	if err := svc.pool.QueryRow("SELECT COUNT(*) FROM users").Scan(&count); err != nil || count != 0 {
		t.Errorf("被拒的批次不该落库，得到 %d 条 (err=%v)", count, err)
	}
}
