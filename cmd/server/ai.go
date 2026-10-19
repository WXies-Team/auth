package main

import (
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/WXies-Team/auth/internal/ai"
	"github.com/WXies-Team/auth/internal/auth"
	"github.com/WXies-Team/auth/internal/config"
	"github.com/WXies-Team/auth/internal/protocol"
)

// ---- AI 限额三端点（日记服务 quota.go 改道后调用）----
//
// 统一记账口径（本批拍板，权威表述见 internal/ai 包注释）：
// 速率与并发按 uid 全局（跨 App 合一），日额度按 uid 与 global 两层、跨 App 相加。
// 四档数值仍来自 app_config（ai_rate_per_minute=20 / ai_concurrency=8 /
// ai_daily_per_user=500 / ai_daily_global=5000，10s 热读），与日记侧逐字一致。
//
// 暴露面照抄既有 /internal/*：loopbackOnly 守卫在最外层（公网来源 403），
// nginx 已整段 404 /internal/*；**不挂 JWT 鉴权**——调用方是同机的日记服务，
// uid 已由各自的 withUID 验过，这里再验一次 token 既无凭据也无必要。
// 429 文案与 Retry-After 逐字沿用日记侧现行口径（calorie main.go 的 AI 路由）。

// aiRatePerApp 是三端点每个 app 每分钟的兜底上限，口径与 /internal/verify 一致
//（600 = 给多租户共享留的余量）。真正管住流量的是每 uid 的 ai_rate_per_minute，
// 这道闸只挡「误配置 + 随机 uid」把 DB 查询打爆的放大面。
const aiRatePerApp = 600

// aiIntCfg 把 config.Store 适配成 ai.IntConfig：键缺失/空/非数字都用默认值，
// 与 calorie 侧 intCfg 闭包同义（改库 ≤10s 热生效）。
func aiIntCfg(cfg *config.Store) ai.IntConfig {
	return func(key string, def int) int {
		v, err := cfg.Get(key)
		if err != nil || v == "" {
			return def
		}
		n, convErr := strconv.Atoi(v)
		if convErr != nil {
			return def
		}
		return n
	}
}

// decodeAIRequest 解析 {app, uid} 并做入参闸：app 必须在 aud 白名单（与登录同一份
// allowedApps），uid 必须落在 7 位随机号段——打错的调用方在进闸门前就 400，
// 不该烧掉一次限流计数或 DB 查询。返回 false 时已写好 400 回执。
func decodeAIRequest(w http.ResponseWriter, r *http.Request, req *protocol.AIQuotaRequest) bool {
	if !decodeOr400(w, r, req) {
		return false
	}
	if !auth.AppAllowed(req.App) || req.UID < 1000000 || req.UID > 9999999 {
		writeError(w, http.StatusBadRequest, "参数不正确")
		return false
	}
	return true
}

// aiLimitPerApp 按 app 分键的兜底限流（键里不含来源：调用方都是同机回环，
// 按 IP 分键会把全站挤成一个桶——同 /internal/verify 的注释）。拒绝回执与
// limit429 同构（429 + Retry-After 60 + 日志），只是 scope 标 ai。
func aiLimitPerApp(w http.ResponseWriter, r *http.Request, app string) bool {
	if limiter.allow("ai-app:"+app, aiRatePerApp, time.Minute) {
		return true
	}
	limit429(w, r, "ai-app:"+app)
	return false
}

// internalAICheck 第一、二、三层闸的编排：POST /internal/ai/check {app,uid}。
//
// 顺序与日记侧路由逐字一致：滑动窗口速率闸（拒 = 429/Retry-After 30）→ 并发槽
// 获取（满 = 429/Retry-After 30，不排队）→ 日额度预检（user 达标 429/Retry-After
// 3600「今日识别次数已用完，明天再来」，global 达标 3600「今日识别服务已达上限，
// 请明天再试」）。
//
// **槽的归属**：check 返回 200 = 槽已占，调用方必须在（且只在）拿到 200 后配对
// 调 release（defer 保证错误/panic 两条路径都释放）；check 返回 429 时本处理器
// 自己把已占的槽还掉——被拒的请求不占并发，调用方也不该对一次失败的 check 调 release。
// 日额度被拒而释放槽发生在返回前，槽不会泄漏到 TTL（10 分钟）。
func internalAICheck(cfg *config.Store, quotaSvc *ai.Service) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req protocol.AIQuotaRequest
		if !decodeAIRequest(w, r, &req) {
			return
		}
		if !aiLimitPerApp(w, r, req.App) {
			return
		}
		intCfg := aiIntCfg(cfg)

		// 第一层：速率（按 uid，跨 App 合一）
		switch quotaSvc.AllowRate(intCfg, req.UID) {
		case ai.QuotaRate:
			ai429(w, 30, "操作过于频繁，请稍后再试")
			return
		}
		// 第二层：并发槽（按 uid，跨 App 合一）
		if quotaSvc.Acquire(intCfg, req.UID) != ai.QuotaOK {
			ai429(w, 30, "操作过于频繁，请稍后再试")
			return
		}
		// 第三层：日额度**预检**（只读；写入在 consume）。
		q, err := quotaSvc.CheckDaily(r.Context(), intCfg, req.UID)
		if err != nil {
			quotaSvc.Release(req.UID) // 槽必须还：DB 抖动不欠并发债
			slog.Error("AI 日额度预检失败", "uid", req.UID, "err", err)
			writeError(w, http.StatusServiceUnavailable, "服务暂时不可用，请稍后重试")
			return
		}
		if q == ai.QuotaDaily {
			quotaSvc.Release(req.UID)
			ai429(w, 3600, "今日识别次数已用完，明天再来")
			return
		}
		if q == ai.QuotaGlobal {
			quotaSvc.Release(req.UID)
			ai429(w, 3600, "今日识别服务已达上限，请明天再试")
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	})
}

// internalAIConsume 入账：POST /internal/ai/consume {app,uid,weight} →
// {dailyUser,dailyGlobal}。原子加 user 与 global 两行（一个事务），**不设上限判定**
// ——即使加完越线也照记，越线由下一次 check 拒；回执即看板数据（与 /admin/ai-usage
// 同源同数）。weight 由日记路由按请求体是否含图片判 1/2，这里只做合法性下限校验。
func internalAIConsume(quotaSvc *ai.Service) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req protocol.AIConsumeRequest
		if !decodeOr400(w, r, &req) {
			return
		}
		if !auth.AppAllowed(req.App) || req.UID < 1000000 || req.UID > 9999999 || req.Weight < 1 {
			writeError(w, http.StatusBadRequest, "参数不正确")
			return
		}
		if !aiLimitPerApp(w, r, req.App) {
			return
		}
		dailyUser, dailyGlobal, err := quotaSvc.Consume(r.Context(), req.UID, req.Weight)
		if err != nil {
			slog.Error("AI 用量入账失败", "uid", req.UID, "err", err)
			writeError(w, http.StatusServiceUnavailable, "服务暂时不可用，请稍后重试")
			return
		}
		writeJSON(w, http.StatusOK, protocol.AIConsumeResponse{DailyUser: dailyUser, DailyGlobal: dailyGlobal})
	})
}

// internalAIRelease 归还并发槽：POST /internal/ai/release {app,uid} → {ok:true}。
// **幂等**：没有在途槽也算成功（崩溃恢复、重复释放都不该报错）。
func internalAIRelease(quotaSvc *ai.Service) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req protocol.AIQuotaRequest
		if !decodeAIRequest(w, r, &req) {
			return
		}
		if !aiLimitPerApp(w, r, req.App) {
			return
		}
		quotaSvc.Release(req.UID)
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	})
}

// ai429 是三端点限流拒绝的统一回执：429 + Retry-After + 一条 429 状态日志
//（同 limit429 的「运维可见」理由）。retryAfter 秒数与文案必须与日记侧一致。
func ai429(w http.ResponseWriter, retryAfter int, message string) {
	w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
	writeError(w, http.StatusTooManyRequests, message)
}
