package auth

import (
	"database/sql"
	"testing"
	"time"
)

// n4：ai_usage 只删 90 天前的行——看板 30 天窗口不受影响，user / global 两层
// 同批清，映射守卫键（app_config）不在本表。
func TestCleanAIUsageDropsExpiredRows(t *testing.T) {
	svc, _ := newTestService(t)
	today := time.Now().Format("2006-01-02")
	old := time.Now().Add(-aiUsageRetention - 24*time.Hour).Format("2006-01-02")
	for _, row := range []struct{ scope, subject, day string }{
		{"user", "7654321", old},   // 过期个人行 → 清
		{"global", "", old},        // 过期全站行 → 清
		{"user", "7654321", today}, // 窗口内个人行 → 留
		{"global", "", today},      // 窗口内全站行 → 留
	} {
		if _, err := svc.pool.Exec(
			"INSERT INTO ai_usage (scope, subject, day, `count`) VALUES (?,?,?,1)",
			row.scope, row.subject, row.day); err != nil {
			t.Fatalf("落用量行 %v: %v", row, err)
		}
	}
	svc.CleanAIUsage()
	for _, want := range []struct {
		scope, subject, day string
		n                   int
	}{
		{"user", "7654321", old, 0},
		{"global", "", old, 0},
		{"user", "7654321", today, 1},
		{"global", "", today, 1},
	} {
		var n int
		if err := svc.pool.QueryRow(
			"SELECT COUNT(*) FROM ai_usage WHERE scope = ? AND subject = ? AND day = ?",
			want.scope, want.subject, want.day).Scan(&n); err != nil {
			t.Fatalf("读用量行: %v", err)
		}
		if n != want.n {
			t.Errorf("%s/%s/%s 应剩 %d 行，得到 %d", want.scope, want.subject, want.day, want.n, n)
		}
	}
}

// n6：会话僵尸行——撤销满 30 天 / 绝对寿命（90 天）过满 30 天才删；
// 近期撤销行（回看窗内）与活跃行都留着。
func TestCleanDeadSessionsDropsZombies(t *testing.T) {
	svc, _ := newTestService(t)
	const uid = int64(7654321)
	ms := time.Now().UnixMilli()
	day := 24 * time.Hour.Milliseconds()
	revoked := func(age int64) sql.NullInt64 { return sql.NullInt64{Int64: ms - age*day, Valid: true} }
	// created_at 各行错开一天，断言按 created_at 定位行
	rows := []struct {
		name       string
		createdAge int64
		revoked_at sql.NullInt64
	}{
		{"撤销 40 天（死透）", 200, revoked(40)},
		{"撤销 10 天（回看窗内）", 30, revoked(10)},
		{"创建 130 天未撤销（寿命+保留已过）", 130, sql.NullInt64{}},
		{"创建 20 天未撤销（活跃）", 20, sql.NullInt64{}},
	}
	for i, r := range rows {
		sid := svc.ids.Generate().Int64() + int64(i)
		created := ms - r.createdAge*day
		if _, err := svc.pool.Exec(
			"INSERT INTO sessions (id, user_id, app, device, ip, user_agent, created_at, last_seen_at, revoked_at)"+
				" VALUES (?,?,?,?,?,?,?,?,?)",
			sid, uid, "calorie-diary", "Test", "127.0.0.1", "ua", created, created, r.revoked_at); err != nil {
			t.Fatalf("落会话行 %s: %v", r.name, err)
		}
	}
	svc.CleanDeadSessions()
	for i, r := range rows {
		var n int
		if err := svc.pool.QueryRow(
			"SELECT COUNT(*) FROM sessions WHERE user_id = ? AND device = 'Test' AND created_at = ?",
			uid, ms-r.createdAge*day).Scan(&n); err != nil {
			t.Fatalf("读会话行: %v", err)
		}
		want := 1
		if i == 0 || i == 2 {
			want = 0
		}
		if n != want {
			t.Errorf("%s 应剩 %d 行，得到 %d", r.name, want, n)
		}
	}
}
