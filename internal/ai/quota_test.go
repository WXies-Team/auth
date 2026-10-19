package ai

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/WXies-Team/auth/internal/db"
)

// newTestQuota 连真库（无 TEST_MYSQL_DSN 跳过，与仓内其它真库测试同策略），
// 每轮清空 ai_usage。
func newTestQuota(t *testing.T) *Service {
	t.Helper()
	dsn := os.Getenv("TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("未设置 TEST_MYSQL_DSN，跳过 ai 真库测试")
	}
	pool, err := db.Open(dsn)
	if err != nil {
		t.Fatalf("连接测试库: %v", err)
	}
	t.Cleanup(func() { _ = pool.Close() })
	if err := db.EnsureSchema(pool); err != nil {
		t.Fatalf("建表: %v", err)
	}
	if _, err := pool.Exec("DELETE FROM ai_usage"); err != nil {
		t.Fatalf("清空 ai_usage: %v", err)
	}
	return NewService(pool, nil)
}

// intCfgOf 造一个「全键取指定值」的配置函数。
func intCfgOf(kv map[string]int) IntConfig {
	return func(key string, def int) int {
		if v, ok := kv[key]; ok {
			return v
		}
		return def
	}
}

func dayToday(t *testing.T) string {
	t.Helper()
	// **与 calorie quota.go 逐字一致的口径**：本地时区、YYYY-MM-DD。这里独立
	// 写一遍同样的表达式做断言——两处若有一方改成 UTC/时区换算，此测试即红。
	return time.Now().Format("2006-01-02")
}

// 速率闸：拒/放跟随窗口判定；键按 uid（不含 App，跨 App 合一）；上限取配置值。
func TestAIRateWindowRejectsAndAllows(t *testing.T) {
	var mu sync.Mutex
	var keys []string
	var maxes []int
	allowed := 1
	svc := &Service{
		ttl: slotTTL,
		allow: func(key string, max int, _ time.Duration) bool {
			mu.Lock()
			defer mu.Unlock()
			keys = append(keys, key)
			maxes = append(maxes, max)
			if allowed > 0 {
				allowed--
				return true
			}
			return false
		},
	}
	cfg := intCfgOf(map[string]int{"ai_rate_per_minute": 7})

	uid := int64(1234567)
	if got := svc.AllowRate(cfg, uid); got != QuotaOK {
		t.Fatalf("首放应 QuotaOK，得到 %v", got)
	}
	if got := svc.AllowRate(cfg, uid); got != QuotaRate {
		t.Fatalf("超限应 QuotaRate，得到 %v", got)
	}
	if keys[0] != "ai-uid:1234567" {
		t.Errorf("速率键应按 uid 且不含 App，得到 %s", keys[0])
	}
	if maxes[0] != 7 {
		t.Errorf("上限应取配置值 7，得到 %d", maxes[0])
	}
	// nil allow 直放（与 calorie 的 NewQuotaService 同款降级）
	if got := NewService(nil, nil).AllowRate(cfg, uid); got != QuotaOK {
		t.Errorf("无窗口实现应直放，得到 %v", got)
	}
}

// 并发槽：占满拒、release 归还、无槽 release 幂等、过期槽自动回收。
func TestAIConcurrencyFillReleaseTTL(t *testing.T) {
	svc := &Service{slots: map[int64][]time.Time{}, ttl: slotTTL}
	cfg := intCfgOf(map[string]int{"ai_concurrency": 2})
	uid := int64(2345678)

	if svc.Acquire(cfg, uid) != QuotaOK || svc.Acquire(cfg, uid) != QuotaOK {
		t.Fatal("前两槽应放行")
	}
	if got := svc.Acquire(cfg, uid); got != QuotaConcurrency {
		t.Fatalf("占满应 QuotaConcurrency，得到 %v", got)
	}
	// 跨 uid 互不影响（并发按 uid，不是全站一个池）
	if got := svc.Acquire(cfg, 3456789); got != QuotaOK {
		t.Errorf("另一个 uid 不该被挤兑，得到 %v", got)
	}
	svc.Release(uid)
	if got := svc.Acquire(cfg, uid); got != QuotaOK {
		t.Errorf("release 后应能再占，得到 %v", got)
	}
	// 无槽 release 幂等：不 panic、不产生负数槽（再 Acquire 仍受上限约束）
	svc.Release(9999999)
	svc.Release(uid)
	svc.Release(uid)
	svc.Release(uid) // 多还几次也不会「倒欠」
	if got := svc.Acquire(cfg, uid); got != QuotaOK {
		t.Errorf("多还不欠槽，首槽应放行，得到 %v", got)
	}
	if got := svc.Acquire(cfg, uid); got != QuotaOK {
		t.Errorf("第二槽应放行，得到 %v", got)
	}
	if got := svc.Acquire(cfg, uid); got != QuotaConcurrency {
		t.Errorf("上限仍应是 2，得到 %v", got)
	}

	// TTL 自动回收：调用方崩溃漏 release 的槽过期即失效
	svc2 := &Service{slots: map[int64][]time.Time{}, ttl: 30 * time.Millisecond}
	fast := intCfgOf(map[string]int{"ai_concurrency": 1})
	if svc2.Acquire(fast, uid) != QuotaOK {
		t.Fatal("首槽应放行")
	}
	if got := svc2.Acquire(fast, uid); got != QuotaConcurrency {
		t.Fatal("占满应拒")
	}
	time.Sleep(60 * time.Millisecond)
	if got := svc2.Acquire(fast, uid); got != QuotaOK {
		t.Errorf("过期槽应自动回收后放行，得到 %v", got)
	}
}

// 日额度预检：user 达标拒、global 达标拒、都未达放行、无行放行。
func TestAIDailyQuotaRejects(t *testing.T) {
	svc := newTestQuota(t)
	ctx := context.Background()
	day := dayToday(t)
	cfg := intCfgOf(map[string]int{"ai_daily_per_user": 5, "ai_daily_global": 10})

	seed := func(t *testing.T, scope, subject string, count int) {
		t.Helper()
		if _, err := svc.pool.Exec(
			"INSERT INTO ai_usage (scope, subject, day, `count`) VALUES (?,?,?,?)",
			scope, subject, day, count); err != nil {
			t.Fatalf("造计数: %v", err)
		}
	}
	seed(t, "user", "1111111", 5)
	seed(t, "global", "", 10)
	if got, err := svc.CheckDaily(ctx, cfg, 1111111); err != nil || got != QuotaDaily {
		t.Errorf("user 达标应 QuotaDaily，得到 %v / %v", got, err)
	}
	seed(t, "user", "2222222", 1)
	if got, err := svc.CheckDaily(ctx, cfg, 2222222); err != nil || got != QuotaGlobal {
		t.Errorf("global 达标应 QuotaGlobal，得到 %v / %v", got, err)
	}
	// global 放宽后放行
	cfg = intCfgOf(map[string]int{"ai_daily_per_user": 5, "ai_daily_global": 100})
	if got, err := svc.CheckDaily(ctx, cfg, 2222222); err != nil || got != QuotaOK {
		t.Errorf("两层未达应 QuotaOK，得到 %v / %v", got, err)
	}
	// 无任何行的新用户直接放行
	if got, err := svc.CheckDaily(ctx, cfg, 3333333); err != nil || got != QuotaOK {
		t.Errorf("无行应 QuotaOK，得到 %v / %v", got, err)
	}
	// day 口径：预检只认「今天」，昨天的行不算数（按天固定窗口）
	if _, err := svc.pool.Exec(
		"INSERT INTO ai_usage (scope, subject, day, `count`) VALUES ('user','4444444',?,?)",
		time.Now().AddDate(0, 0, -1).Format("2006-01-02"), 999); err != nil {
		t.Fatalf("造昨日计数: %v", err)
	}
	if got, err := svc.CheckDaily(ctx, cfg, 4444444); err != nil || got != QuotaOK {
		t.Errorf("昨日计数不该挡今天，得到 %v / %v", got, err)
	}
}

// 入账：user 与 global 两行同增、跨 App 相加、回执即库内计数、越线也照记、day 落今天。
func TestAIConsumeCountsAndCrossApp(t *testing.T) {
	svc := newTestQuota(t)
	ctx := context.Background()
	day := dayToday(t)
	uid := int64(5555555)

	// 模拟同一用户在两个 App 各记一次（weight 1 + 2，图片折算 2 的语义）
	dailyUser, dailyGlobal, err := svc.Consume(ctx, uid, 1)
	if err != nil {
		t.Fatalf("首次入账: %v", err)
	}
	if dailyUser != 1 || dailyGlobal != 1 {
		t.Errorf("首次入账回执应 1/1，得到 %d/%d", dailyUser, dailyGlobal)
	}
	dailyUser, dailyGlobal, err = svc.Consume(ctx, uid, 2)
	if err != nil {
		t.Fatalf("二次入账: %v", err)
	}
	if dailyUser != 3 || dailyGlobal != 3 {
		t.Errorf("跨 App 相加回执应 3/3，得到 %d/%d", dailyUser, dailyGlobal)
	}
	// 另一个用户的消耗只进 global 层
	if _, _, err := svc.Consume(ctx, 6666666, 4); err != nil {
		t.Fatalf("他人入账: %v", err)
	}

	rows, err := svc.pool.Query("SELECT scope, subject, day, `count` FROM ai_usage ORDER BY scope, subject")
	if err != nil {
		t.Fatalf("读库核对: %v", err)
	}
	defer func() { _ = rows.Close() }()
	type row struct {
		scope, subject, day string
		count               int
	}
	var got []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.scope, &r.subject, &r.day, &r.count); err != nil {
			t.Fatalf("扫描: %v", err)
		}
		got = append(got, r)
	}
	want := []row{
		{"global", "", day, 7}, // 3（uid 5555555 两次）+ 4（uid 6666666）
		{"user", "5555555", day, 3},
		{"user", "6666666", day, 4},
	}
	if len(got) != len(want) {
		t.Fatalf("行数应 %d，得到 %+v", len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("第 %d 行应 %+v，得到 %+v", i, want[i], got[i])
		}
	}

	// 越线也照记：user 行已到 500（默认限额）再入账 2 → 502，回执如实
	if _, err := svc.pool.Exec(
		"INSERT INTO ai_usage (scope, subject, day, `count`) VALUES ('user','7777777',?,500)", day); err != nil {
		t.Fatalf("造满额行: %v", err)
	}
	dailyUser, _, err = svc.Consume(ctx, 7777777, 2)
	if err != nil {
		t.Fatalf("越线入账: %v", err)
	}
	if dailyUser != 502 {
		t.Errorf("越线应照记为 502，得到 %d", dailyUser)
	}
}

// 并发 Acquire/Release 的竞态：并发跑不炸、跑完回到 0 在途。
func TestAIConcurrencyRace(t *testing.T) {
	svc := &Service{slots: map[int64][]time.Time{}, ttl: slotTTL}
	cfg := intCfgOf(map[string]int{"ai_concurrency": 4})
	uid := int64(1999999)
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if svc.Acquire(cfg, uid) == QuotaOK {
				svc.Release(uid)
			}
		}()
	}
	wg.Wait()
	if got := len(svc.liveLocked(uid, time.Now())); got != 0 {
		t.Errorf("跑完应回到 0 在途，得到 %d", got)
	}
}
