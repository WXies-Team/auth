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
