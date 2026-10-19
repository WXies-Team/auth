package db

import (
	"os"
	"testing"
)

// 老库补列的三件事：探测到位（缺则补）、二跑幂等、DDL 不进 schema.sql。
// 需要真库（TEST_MYSQL_DSN），缺省跳过——与本仓其它真库用例同策略。
func TestEnsureColumnProbesAndIsIdempotent(t *testing.T) {
	dsn := os.Getenv("TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("未设置 TEST_MYSQL_DSN，跳过补列真库测试")
	}
	pool, err := Open(dsn)
	if err != nil {
		t.Fatalf("连接测试库: %v", err)
	}
	t.Cleanup(func() { _ = pool.Close() })

	const scratch = "scratch_ensure_column"
	// 造一张没有目标列的「老表」，跑两次 ensureColumn：第一次补列，第二次必须 no-op
	//（重复 ADD COLUMN 会报 1060，二跑失败就是探测没生效）。
	if _, err := pool.Exec("DROP TABLE IF EXISTS " + scratch); err != nil {
		t.Fatalf("清 scratch 表: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec("DROP TABLE IF EXISTS " + scratch) })
	if _, err := pool.Exec("CREATE TABLE " + scratch + " (id BIGINT NOT NULL PRIMARY KEY)"); err != nil {
		t.Fatalf("建 scratch 表: %v", err)
	}
	ddl := "ALTER TABLE " + scratch + " ADD COLUMN probe_col CHAR(64) NULL"
	if err := ensureColumn(pool, scratch, "probe_col", ddl); err != nil {
		t.Fatalf("首次补列: %v", err)
	}
	if err := ensureColumn(pool, scratch, "probe_col", ddl); err != nil {
		t.Fatalf("二次补列应 no-op: %v", err)
	}
	var n int
	if err := pool.QueryRow(
		"SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = ? AND column_name = ?",
		scratch, "probe_col").Scan(&n); err != nil || n != 1 {
		t.Errorf("列应已存在，得到 n=%d err=%v", n, err)
	}
}

// EnsureSchema 二跑必须幂等，且四个新列（role / web_token_hash / web_csrf_hash /
// reauth_at）与六张新表都要就位——它们是 web 管理台的地基，缺一列启动后的第一次
// web 登录就会炸在 SQL 上。
func TestEnsureSchemaIdempotentWithWebColumns(t *testing.T) {
	dsn := os.Getenv("TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("未设置 TEST_MYSQL_DSN，跳过建表真库测试")
	}
	pool, err := Open(dsn)
	if err != nil {
		t.Fatalf("连接测试库: %v", err)
	}
	t.Cleanup(func() { _ = pool.Close() })

	for i := 0; i < 2; i++ {
		if err := EnsureSchema(pool); err != nil {
			t.Fatalf("第 %d 次 EnsureSchema: %v", i+1, err)
		}
	}
	for _, c := range extraColumns {
		var n int
		if err := pool.QueryRow(
			"SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = ? AND column_name = ?",
			c.table, c.column).Scan(&n); err != nil || n != 1 {
			t.Errorf("列 %s.%s 应存在，得到 n=%d err=%v", c.table, c.column, n, err)
		}
	}
	for _, table := range []string{"passkeys", "totp_factors", "recovery_codes", "webauthn_challenges", "login_states", "ai_usage"} {
		var n int
		if err := pool.QueryRow(
			"SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = ?", table).
			Scan(&n); err != nil || n != 1 {
			t.Errorf("表 %s 应存在，得到 n=%d err=%v", table, n, err)
		}
	}
	// web_token_hash 的 UNIQUE 索引要跟着列一起建：查询按它点查，且 DB 层兜住
	// 同一 token 落两行。
	var idx int
	if err := pool.QueryRow(
		"SELECT COUNT(*) FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'sessions' AND index_name = 'uq_sessions_web_token'").
		Scan(&idx); err != nil || idx < 1 {
		t.Errorf("sessions.uq_sessions_web_token 应存在，得到 n=%d err=%v", idx, err)
	}
}
