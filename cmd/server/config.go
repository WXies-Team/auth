package main

// ---- POST /internal/config：给两个日记服务分发本 app 的配置 ----
//
// 背景：两个日记 App 的 LLM / 推送配置一直各自散在自己服务的 app_config 读取里
//（键是同一套 `llm_*` / `push_admin_token`，值全在 auth 的 app_config 表），
// 调用方改成向本服务要一份「自己这个 app 用的」混合配置（非秘密 + 秘密一起给）。
//
// FCM 凭据（fcm_project_id / fcm_service_account）已**退出本端点**：两个 App 端
// 已改为只拉 llm_* + push_admin_token，FCM 凭据种入各 App 自己的库——auth 不再
// 经手推送凭据，本表的 fcm_* 旧键已随 2026-10-21 的清理删除（配置中心与库里都不
// 再有 fcm_* 行，无需再惦记手工清理）。
//
// 暴露面与 /internal/ai/* **完全同款**：loopbackOnly 守卫在最外层（公网来源 403），
// 内层再套 internalTokenGate（X-Internal-Token 对 app_config 的 hook_token
// 做常数时间比对）——环回只挡「公网误配反代」，同机的任何进程都打得到，凭据闸才挡得住。
// nginx 已整段 404 /internal/*。
//
// 三件事是硬约束：
//  1. 白名单外的 app 一律 400（借不到别家的 LLM key 与推送令牌）；
//  2. **键缺失就省略该字段**（omitempty）：调用方能区分「没配」与「配了值」；
//  3. 值全部现读 app_config（config.Store 的 10s 热缓存，改库即热生效），
//     不在本包另起缓存、不落盘。

import (
	"log/slog"
	"net/http"

	"github.com/WXies-Team/auth/internal/auth"
	"github.com/WXies-Team/auth/internal/config"
)

// internalConfigResponse 是端点回执。字段名是**对外契约**（日记服务按这些键取值），
// 逐个 json tag 写死；omitempty 让「app_config 里没有这个键」在 JSON 里表现为
// 字段整体缺席——而不是空串（空串在 config.Store 里等价于没配，回空串是骗人）。
type internalConfigResponse struct {
	LLMAPIKey      string `json:"llmApiKey,omitempty"`
	LLMBaseURL     string `json:"llmBaseUrl,omitempty"`
	LLMModel       string `json:"llmModel,omitempty"`
	PushAdminToken string `json:"pushAdminToken,omitempty"`
}

// internalConfig 是 POST /internal/config {app} → 上面这张回执的 handler。
// 环回与 X-Internal-Token 两道闸在路由层（loopbackOnly + internalTokenGate），
// 本函数只管白名单、取值与回执形状。
func internalConfig(cfg *config.Store) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			App string `json:"app"`
		}
		if !decodeOr400(w, r, &req) {
			return
		}
		// 白名单 = JWT aud 白名单（{calorie-diary, expense-diary}）：与登录、AI 三端点
		// 同一份 allowedApps，两处一起加应用。空 app 同样 400。
		if !auth.AppAllowed(req.App) {
			writeError(w, http.StatusBadRequest, "参数不正确，请检查 app 字段后重试")
			return
		}
		// 逐键现读（Require 把 ErrNotFound 折成空 = 没配 → 字段省略）。
		// **真错误（读库失败）回 503 而不是省略字段**：把 DB 抖动当成「没配」，
		// 调用方会拿着空 LLM key 去打上游，排障方向直接带偏。
		var resp internalConfigResponse
		ok := true
		need := func(dst *string, key string) {
			if !ok {
				return
			}
			v, err := cfg.Require(key)
			if err != nil {
				slog.Error("读配置键失败", "key", key, "err", err)
				writeError(w, http.StatusServiceUnavailable, "服务暂时不可用，请稍后重试")
				ok = false
				return
			}
			*dst = v
		}
		need(&resp.LLMAPIKey, "llm_api_key")
		need(&resp.LLMBaseURL, "llm_base_url")
		need(&resp.LLMModel, "llm_model")
		need(&resp.PushAdminToken, "push_admin_token")
		if !ok {
			return
		}
		writeJSON(w, http.StatusOK, resp)
	})
}
