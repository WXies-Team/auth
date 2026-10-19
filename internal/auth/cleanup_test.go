package auth

import (
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
