// Package ai 执行两个日记 App 的 AI 三层限额与用量记账（auth 侧统一）。
//
// 日记服务的 quota.go 改道后只打三个 HTTP 端点（/internal/ai/{check,consume,release}），
// 三层闸门与 ai_usage 记账全部收在本包。语义权威 = calorie 侧现状（internal/llm/quota.go）：
// 同一套 app_config 键、同一批默认值、同样的 429 文案与 Retry-After、同样的 day 口径。
//
// ============================ 统一记账口径（本批拍板） ============================
//  1. 速率与并发 **按 uid 全局**（跨 App 合一）：一个用户在两个 App 的 AI 请求共用
//     每分钟 ai_rate_per_minute 次与 ai_concurrency 个在途槽——统一预算的意义就是
//     换个 App 不能多打。
//  2. 日额度 **按 uid 与 global 两层、跨 App 相加**：user 层按 (uid, day) 汇总两 App
//     的消耗，global 层按 (day) 全站汇总。合并历史用量由
//     scripts/migrate-ai-usage-to-auth.sh 完成，合并后两层都从「统一预算」起算。
//  3. day 口径与 calorie 逐字一致：time.Now().Format("2006-01-02")，服务器本地时区，
//     不做时区换算——auth 与两个日记服务同机部署，同一次「今天」。
//  4. weight 语义照现状：日记路由按请求体是否含图片判 1 或 2（图片折算 2 次），
//     不采信客户端自报；本包只按调用方给的 weight 入账。
package ai

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"sync"
	"time"
)

// Quota 与日记侧枚举一一对应，路由据此给出不同的状态码、文案与 Retry-After。
type Quota int

const (
	QuotaOK Quota = iota
	QuotaRate
	QuotaConcurrency
	QuotaDaily
	QuotaGlobal
)

// allowFunc 是进程内滑动窗口（与路由的 IP 限流共用同一实现，单实例部署语义与
// 日记侧一致）。键由本包拼成 "ai-uid:<uid>"，**跨 App 合一**。
type allowFunc func(key string, max int, window time.Duration) bool

// slotTTL 是并发槽的自动回收时长：调用方（日记服务）崩溃或漏 Release 时，
// 槽最多占 10 分钟就自动失效——上游 LLM 最长 60s，10 分钟是它的 10 倍，
// 足够宽松不误伤慢请求，又不至于让泄漏的槽永久吃掉全站并发。
const slotTTL = 10 * time.Minute

// Service 是三层闸门 + 记账的执行体。并发/速率状态在进程内（本仓单实例假设，
// 与日记侧、auth 自己的限流同款）；ai_usage 落库用真库事务。
type Service struct {
	pool  *sql.DB
	allow allowFunc

	mu    sync.Mutex
	slots map[int64][]time.Time // uid → 在途槽的获取时刻（进程内，重启即清零）
	ttl   time.Duration         // 槽的自动回收时长，构造时取 slotTTL（测试可调短）
}

// NewService 构造执行体。allow 为 nil 时速率闸直放（与 calorie 的 NewQuotaService 同款）。
func NewService(pool *sql.DB, allow allowFunc) *Service {
	return &Service{pool: pool, allow: allow, slots: map[int64][]time.Time{}, ttl: slotTTL}
}

// IntConfig 取数字型配置（限额），缺省/非数字用默认值——签名与 calorie 的同名类型一致，
// 由路由层用 config.Store 适配（10s 热读，改库即生效）。
type IntConfig func(key string, def int) int

// rateKey 拼速率/并发的键：**只含 uid，不含 App**（统一口径第 1 条）。
func rateKey(uid int64) string { return "ai-uid:" + strconv.FormatInt(uid, 10) }

// AllowRate 第一层（速率）：每 uid 每分钟 ai_rate_per_minute（默认 20）。
// 返回非 QuotaOK 表示该用户本分钟次数用完。
func (s *Service) AllowRate(cfg IntConfig, uid int64) Quota {
	if s.allow == nil {
		return QuotaOK
	}
	rate := cfg("ai_rate_per_minute", 20)
	if !s.allow(rateKey(uid), rate, time.Minute) {
		return QuotaRate
	}
	return QuotaOK
}

// Acquire 第二层（并发）：每 uid 在途 ai_concurrency 个（默认 8），满即拒不排队。
// 返回 QuotaConcurrency 表示在途已满。**调用方必须配对 Release**（拿到 200 就要
// Release，用 defer：错误返回与 panic 都要走）——10 分钟 TTL 只是崩溃兜底，不是常规路径。
func (s *Service) Acquire(cfg IntConfig, uid int64) Quota {
	limit := cfg("ai_concurrency", 8)
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	// 惰性清理：键太多时把**全是过期槽**的 uid 整个删掉，避免长期不来的用户
	// 让 map 无限攒（与路由层 rateLimiter 的 >4096 清理同思路）。
	if len(s.slots) > 4096 {
		for u := range s.slots {
			if len(s.liveLocked(u, now)) == 0 {
				delete(s.slots, u)
			}
		}
	}
	live := s.liveLocked(uid, now)
	if len(live) >= limit {
		if len(live) == 0 {
			delete(s.slots, uid)
		} else {
			s.slots[uid] = live
		}
		return QuotaConcurrency
	}
	s.slots[uid] = append(live, now)
	return QuotaOK
}

// Release 归还一个并发槽；**幂等**——没有在途槽时是无操作（调用方崩溃重试、
// 重复 Release 都不会把计数打负）。
func (s *Service) Release(uid int64) {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	live := s.liveLocked(uid, now)
	if len(live) == 0 {
		delete(s.slots, uid)
		return
	}
	s.slots[uid] = live[:len(live)-1]
}

// liveLocked 返回该 uid 未过期的槽时刻（新切片，顺手丢掉过期项）；调用方必须持锁。
func (s *Service) liveLocked(uid int64, now time.Time) []time.Time {
	held := s.slots[uid]
	if len(held) == 0 {
		return nil
	}
	out := make([]time.Time, 0, len(held))
	for _, t := range held {
		if now.Sub(t) < s.ttl {
			out = append(out, t)
		}
	}
	return out
}

// CheckDaily 第三层预检：当日 user / global 计数**已达限额就拒**（只读不写）。
// 计数写入统一在 Consume（原子加，即使加完越线也照记——越线由下一次 check 拒）。
func (s *Service) CheckDaily(ctx context.Context, cfg IntConfig, uid int64) (Quota, error) {
	day := time.Now().Format("2006-01-02") // 与 calorie quota.go 逐字一致：本地时区 YYYY-MM-DD
	daily := cfg("ai_daily_per_user", 500)
	global := cfg("ai_daily_global", 5000)

	var userCount int
	err := s.pool.QueryRowContext(ctx,
		"SELECT `count` FROM ai_usage WHERE scope = 'user' AND subject = ? AND day = ?",
		strconv.FormatInt(uid, 10), day).Scan(&userCount)
	if err != nil && err != sql.ErrNoRows {
		return QuotaOK, fmt.Errorf("读个人日额: %w", err)
	}
	if userCount >= daily {
		return QuotaDaily, nil
	}
	var globalCount int
	err = s.pool.QueryRowContext(ctx,
		"SELECT `count` FROM ai_usage WHERE scope = 'global' AND subject = '' AND day = ?",
		day).Scan(&globalCount)
	if err != nil && err != sql.ErrNoRows {
		return QuotaOK, fmt.Errorf("读全站日额: %w", err)
	}
	if globalCount >= global {
		return QuotaGlobal, nil
	}
	return QuotaOK, nil
}

// Consume 原子入账：user 与 global 两行同增 weight（**一个事务**，加锁顺序恒为
// user → global，与日记侧一致不交叉死锁），**不设上限判定**——即使加完越线也照记，
// 越线由下一次 CheckDaily 拒。返回入账后的两层计数，回执即看板数据。
//
// 占行用 INSERT … ON DUPLICATE KEY UPDATE（直接对不存在的行 UPDATE 会拿 gap 键锁，
// 两个首请求互持再改同一行会撞死锁——日记侧踩过，见其 bumpCount 注释）。
func (s *Service) Consume(ctx context.Context, uid int64, weight int) (dailyUser, dailyGlobal int, err error) {
	day := time.Now().Format("2006-01-02")
	subject := strconv.FormatInt(uid, 10)

	tx, err := s.pool.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, fmt.Errorf("开记账事务: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := bumpCount(ctx, tx, "user", subject, day, weight); err != nil {
		return 0, 0, err
	}
	if err := bumpCount(ctx, tx, "global", "", day, weight); err != nil {
		return 0, 0, err
	}
	// 读回入账后的两层计数（同一事务内，与自增原子一致）
	if err := tx.QueryRowContext(ctx,
		"SELECT `count` FROM ai_usage WHERE scope = 'user' AND subject = ? AND day = ?",
		subject, day).Scan(&dailyUser); err != nil {
		return 0, 0, fmt.Errorf("读个人计数: %w", err)
	}
	if err := tx.QueryRowContext(ctx,
		"SELECT `count` FROM ai_usage WHERE scope = 'global' AND subject = '' AND day = ?",
		day).Scan(&dailyGlobal); err != nil {
		return 0, 0, fmt.Errorf("读全站计数: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, 0, fmt.Errorf("提交记账: %w", err)
	}
	return dailyUser, dailyGlobal, nil
}

// bumpCount 占行 + 自增一行计数。必须在事务里按 user → global 的固定顺序调用。
func bumpCount(ctx context.Context, tx *sql.Tx, scope, subject, day string, weight int) error {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO ai_usage (scope, subject, day, `+"`count`"+`) VALUES (?,?,?,?)
		ON DUPLICATE KEY UPDATE `+"`count`"+` = `+"`count`"+` + VALUES(`+"`count`"+`)`,
		scope, subject, day, weight)
	if err != nil {
		return fmt.Errorf("入账 %s/%s: %w", scope, subject, err)
	}
	return nil
}
