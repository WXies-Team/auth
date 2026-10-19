package auth

import (
	"context"
	"database/sql"
	"log/slog"
	"time"
)

// 过期行的顺路清理（与 otp_codes / audit_logs 同一套路）：不引入后台 goroutine
//（规格 A1.4 的取舍——多一个永不退出的循环就多一份测试面与「到底跑没跑」的排障
// 成本），挂在发码这条高频路径上周期性执行（见 otp.go issue）。本文件两张表都
// 只有几十~几千行，全表扫可忽略（同 otp_codes / audit_logs 的清理口径）。

// aiUsageRetention 是 ai_usage 行的保留期（n4）。管理后台看板只读近 30 天，
// 再久的行只剩「历史总量」的对账价值，90 天后即删——不删的话每天新增两层
// （user × global）行，这张无索引小表也会随年月无限长。
const aiUsageRetention = 90 * 24 * time.Hour

// CleanAIUsage 删掉超过保留期的 ai_usage 行（挂发码路径，与 CleanAuditLogs 同批）。
func (s *Service) CleanAIUsage() { cleanAIUsage(s.pool) }

func cleanAIUsage(pool *sql.DB) {
	// day 是 'YYYY-MM-DD' 的本地日期串，字典序即时间序，直接比大小；
	// user / global 两层同一天到期，一并清（看板 30 天窗口不受影响）。
	if _, err := pool.ExecContext(context.Background(),
		"DELETE FROM ai_usage WHERE day < ?", time.Now().Add(-aiUsageRetention).Format("2006-01-02")); err != nil {
		slog.Warn("清理过期 AI 用量行失败（下次发码再试）", "err", err)
	}
}

// sessionKeepAfterDeath 是死会话行的**额外**保留期（n6）：吊销或绝对过期满 30 天
// 才真删。行被吊销后就从用户设备页与管理台的列表里消失了（两处都只列
// revoked_at IS NULL），但「这台设备什么时候被踢的」近 30 天里仍要留着回看与排障。
const sessionKeepAfterDeath = 30 * 24 * time.Hour

// CleanDeadSessions 删掉死透的会话行（挂发码路径，与 CleanAuditLogs 同批）。
// App（JWT）会话与 web 会话同表同行，判死口径也一致，不必分 app 两套：
// App 会话的绝对寿命是 JWT 的 90 天 TTL，web 会话的绝对超时同为 90 天（webAbsoluteTTL），
// 过了这个点任何凭据都验不过，行只剩僵尸。
func (s *Service) CleanDeadSessions() { cleanDeadSessions(s.pool) }

func cleanDeadSessions(pool *sql.DB) {
	now := time.Now()
	// 撤销行从 revoked_at 起算保留；未撤销行从 created_at 起算「寿命 + 保留」。
	// web 会话的**空闲** 7 天超时不参与删行——它只影响验票，按 last_seen_at 删会把
	// 一台刚闲置过久、仍在回看窗内的行提前抹掉。
	if _, err := pool.ExecContext(context.Background(),
		"DELETE FROM sessions WHERE (revoked_at IS NOT NULL AND revoked_at < ?)"+
			" OR (revoked_at IS NULL AND created_at < ?)",
		now.Add(-sessionKeepAfterDeath).UnixMilli(),
		now.Add(-webAbsoluteTTL-sessionKeepAfterDeath).UnixMilli()); err != nil {
		slog.Warn("清理过期会话行失败（下次发码再试）", "err", err)
	}
}
