package main

import (
	"net/http"
	"strconv"
	"time"

	"github.com/WXies-Team/auth/internal/auth"
)

// 管理后台的 HTTP 层（规格 A2.5）。授权四道闸全部在这里，每请求都过：
//
//	① 只收 cookie（Bearer 不给后台钥匙——日记 App 侧的 token 被盗不牵连后台）；
//	② role=admin，**每请求现查 users 行**（撤销资格必须当场生效）；
//	③ 强制 MFA：没绑 TOTP/passkey 的管理员进不来（OWASP MFA CS）；
//	④ reauth ≤15 分钟（ASVS V7.5.1），401 后前端弹重新验证框。
//
// 数据操作与审计都在 internal/auth，这里只做参数与回执。
func registerAdminRoutes(mux *http.ServeMux, svc *auth.Service) {
	admin := func(scope string, h func(c auth.WebCaller, w http.ResponseWriter, r *http.Request)) http.Handler {
		return withLogging(withUID(svc, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c := r.Context().Value(webCallerKey).(auth.WebCaller)
			if !c.ViaCookie {
				writeError(w, http.StatusUnauthorized, "管理后台请在网页端登录")
				return
			}
			role, err := svc.SessionRole(c.UID)
			if err != nil {
				writeResult(w, nil, err)
				return
			}
			if role != "admin" {
				writeError(w, http.StatusForbidden, "没有管理权限")
				return
			}
			mfa, err := svc.HasMFA(c.UID)
			if err != nil {
				writeResult(w, nil, err)
				return
			}
			if !mfa {
				writeError(w, http.StatusForbidden, "管理后台要求先绑定两步验证或 Passkey")
				return
			}
			if err := svc.RequireReauth(c.SID); err != nil {
				writeResult(w, nil, err)
				return
			}
			if !limiter.allow(scope+":"+strconv.FormatInt(c.UID, 10), 60, time.Minute) {
				w.Header().Set("Retry-After", "60")
				writeError(w, http.StatusTooManyRequests, "操作过于频繁，请稍后再试")
				return
			}
			h(c, w, r)
		})))
	}

	// ---- 用户 ----
	mux.Handle("GET /admin/users", admin("admin-users", func(c auth.WebCaller, w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		list, total, err := svc.AdminSearchUsers(q.Get("query"), queryInt(q.Get("limit")), queryInt(q.Get("offset")))
		if err != nil {
			writeResult(w, nil, err)
			return
		}
		writeJSON(w, http.StatusOK, page{Items: list, Total: total})
	}))
	mux.Handle("GET /admin/users/{uid}", admin("admin-users", func(c auth.WebCaller, w http.ResponseWriter, r *http.Request) {
		uid, ok := pathInt64(w, r.PathValue("uid"))
		if !ok {
			return
		}
		detail, err := svc.AdminUserDetail(uid)
		if err != nil {
			writeResult(w, nil, err)
			return
		}
		writeJSON(w, http.StatusOK, detail)
	}))
	mux.Handle("PATCH /admin/users/{uid}", admin("admin-role", func(c auth.WebCaller, w http.ResponseWriter, r *http.Request) {
		uid, ok := pathInt64(w, r.PathValue("uid"))
		if !ok {
			return
		}
		var req struct {
			Role string `json:"role"`
		}
		if !decodeOr400(w, r, &req) {
			return
		}
		if err := svc.AdminSetRole(c.Caller, uid, req.Role); err != nil {
			writeResult(w, nil, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}))
	mux.Handle("POST /admin/users/{uid}/revoke-sessions", admin("admin-kick", func(c auth.WebCaller, w http.ResponseWriter, r *http.Request) {
		uid, ok := pathInt64(w, r.PathValue("uid"))
		if !ok {
			return
		}
		if err := svc.AdminRevokeUserSessions(c.Caller, uid); err != nil {
			writeResult(w, nil, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}))

	// ---- 会话总览 ----
	mux.Handle("GET /admin/sessions", admin("admin-sessions", func(c auth.WebCaller, w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		list, total, err := svc.AdminListSessions(queryInt64(q.Get("uid")), queryInt(q.Get("limit")), queryInt(q.Get("offset")))
		if err != nil {
			writeResult(w, nil, err)
			return
		}
		writeJSON(w, http.StatusOK, page{Items: list, Total: total})
	}))
	mux.Handle("DELETE /admin/sessions/{id}", admin("admin-session-kick", func(c auth.WebCaller, w http.ResponseWriter, r *http.Request) {
		id, ok := pathInt64(w, r.PathValue("id"))
		if !ok {
			return
		}
		if err := svc.AdminRevokeSession(c.Caller, id); err != nil {
			writeResult(w, nil, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}))

	// ---- 审计 ----
	mux.Handle("GET /admin/audit", admin("admin-audit", func(c auth.WebCaller, w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		list, total, err := svc.QueryAudit(auth.AuditQuery{
			Action: q.Get("action"),
			Actor:  queryInt64(q.Get("actor")),
			Target: queryInt64(q.Get("target")),
			From:   queryInt64(q.Get("from")),
			To:     queryInt64(q.Get("to")),
			Limit:  queryInt(q.Get("limit")),
			Offset: queryInt(q.Get("offset")),
		})
		if err != nil {
			writeResult(w, nil, err)
			return
		}
		// 看审计本身也是管理动作（谁在查谁的痕迹），记一条不带查询条件的轻量事件
		svc.Audit(auth.AuditEvent{
			Action: auth.AuditAdminAuditView, OK: true, ActorUID: &c.UID,
			ActorEmail: c.Email, Meta: c.Meta,
		})
		writeJSON(w, http.StatusOK, page{Items: list, Total: total})
	}))

	// ---- 配置中心 ----
	mux.Handle("GET /admin/config", admin("admin-config", func(c auth.WebCaller, w http.ResponseWriter, _ *http.Request) {
		items, err := svc.AdminListConfig()
		if err != nil {
			writeResult(w, nil, err)
			return
		}
		writeJSON(w, http.StatusOK, items)
	}))
	mux.Handle("PUT /admin/config/{key}", admin("admin-config-write", func(c auth.WebCaller, w http.ResponseWriter, r *http.Request) {
		var req struct {
			Value string `json:"value"`
		}
		if !decodeOr400(w, r, &req) {
			return
		}
		if err := svc.AdminSetConfig(c.Caller, r.PathValue("key"), req.Value); err != nil {
			writeResult(w, nil, err)
			return
		}
		// app_config 读取带 10 秒进程缓存：改动要明说生效窗口，否则「保存了没生效」
		// 会被当成 bug 反复重试
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "hotWithinSeconds": 10})
	}))

	// ---- AI 用量看板 ----
	mux.Handle("GET /admin/ai-usage", admin("admin-ai-usage", func(c auth.WebCaller, w http.ResponseWriter, r *http.Request) {
		report, err := svc.AdminAIUsage(queryInt(r.URL.Query().Get("days")))
		if err != nil {
			writeResult(w, nil, err)
			return
		}
		writeJSON(w, http.StatusOK, report)
	}))
}

// page 是后台分页列表的统一回执：items 是本页数据，total 是过滤后的总条数
//（翻页按钮按它判断还有没有下一页）。
type page struct {
	Items any `json:"items"`
	Total int `json:"total"`
}

// queryInt / queryInt64 解查询参数：缺省与非法值都按「没给」处理（0 = 不限 / 用默认），
// 不给后台一个拿 ?limit=abc 触发 500 的入口。
func queryInt(raw string) int {
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0
	}
	return n
}

func queryInt64(raw string) int64 {
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || n < 0 {
		return 0
	}
	return n
}
