package main

import (
	"net/http"
	"strconv"
	"time"

	"github.com/WXies-Team/auth/internal/auth"
)

// 管理后台的 HTTP 层（规格 A2.5 + W2 分级授权）。授权闸全部在这里，每请求都过：
//
//	① 只收 cookie（Bearer 不给后台钥匙——日记 App 侧的 token 被盗不牵连后台）；
//	② role ∈ {admin, super}，**每请求现查 users 行**（撤销资格必须当场生效）；
//	③ 强制 MFA：没绑 TOTP/passkey 的管理员进不来（OWASP MFA CS）；
//	④ reauth ≤15 分钟（ASVS V7.5.1），401 后前端弹重新验证框。
//
// 过完四道闸再叠 W2 的 scope 收权（adminCtx）：
//
//	super    平台管理员——users 目录/角色/注销/配置中心/roles 三端点全放开，
//	         数据端点可用 ?app= 过滤（不给 = 全量）；
//	app-admin 只见/只管自己 admin_scopes 里的 app：sessions/audit/ai-usage 按
//	         scope 过滤（?app= 越界即 403），users/roles/config 端点 403。
//
// 数据操作与审计都在 internal/auth，这里只做参数与回执。
func registerAdminRoutes(mux *http.ServeMux, svc *auth.Service) {
	// adminCtx 是过完四道闸之后的调用现场：身份 + 是否平台管理员 + 授权 app 清单。
	// app-admin 的清单每请求现查（撤销 scope 当场生效，与 role 现查同款理由）。
	type adminCtx struct {
		caller auth.WebCaller
		super  bool
		apps   []string // app-admin 的授权清单；super 为 nil（数据端点不限）
	}
	admin := func(scope string, h func(c adminCtx, w http.ResponseWriter, r *http.Request)) http.Handler {
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
			if !auth.IsAdminRole(role) {
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
			ac := adminCtx{caller: c, super: auth.IsSuperRole(role)}
			if !ac.super {
				if ac.apps, err = svc.AdminScopes(c.UID); err != nil {
					writeResult(w, nil, err)
					return
				}
			}
			h(ac, w, r)
		})))
	}
	// requireSuper 挡掉 app-admin 对 super 专属端点的访问（用户目录/角色/注销/
	// 配置中心都是平台级数据）。放行即 true。
	requireSuper := func(w http.ResponseWriter, ac adminCtx) bool {
		if !ac.super {
			writeError(w, http.StatusForbidden, "此功能仅平台管理员可用")
			return false
		}
		return true
	}
	// effectiveApps 解析数据端点的 app 范围（?app= 与 scope 的交集判定）：
	//   - super：?app= 空 = 全量（nil）；给了且合法 = 单 app 过滤；名单外 403；
	//   - app-admin：?app= 空 = 全部授权 app；给了且在授权内 = 单 app；越界 403；
	//     零 scope 的 admin 任何数据端点都 403（role=admin 且无行 = 无权限）。
	effectiveApps := func(w http.ResponseWriter, ac adminCtx, r *http.Request) ([]string, bool) {
		want := r.URL.Query().Get("app")
		if ac.super {
			if want == "" {
				return nil, true
			}
			if !auth.AppAllowed(want) {
				writeError(w, http.StatusForbidden, "未知应用")
				return nil, false
			}
			return []string{want}, true
		}
		if len(ac.apps) == 0 {
			writeError(w, http.StatusForbidden, "尚未授予任何应用的管理权限，请联系平台管理员")
			return nil, false
		}
		if want == "" {
			return ac.apps, true
		}
		for _, a := range ac.apps {
			if a == want {
				return []string{want}, true
			}
		}
		writeError(w, http.StatusForbidden, "没有该应用的管理权限")
		return nil, false
	}

	// ---- 用户（super only：目录与凭证是平台级数据） ----
	mux.Handle("GET /admin/users", admin("admin-users", func(ac adminCtx, w http.ResponseWriter, r *http.Request) {
		if !requireSuper(w, ac) {
			return
		}
		q := r.URL.Query()
		list, total, err := svc.AdminSearchUsers(q.Get("query"), queryInt(q.Get("limit")), queryInt(q.Get("offset")))
		if err != nil {
			writeResult(w, nil, err)
			return
		}
		writeJSON(w, http.StatusOK, page{Items: list, Total: total})
	}))
	mux.Handle("GET /admin/users/{uid}", admin("admin-users", func(ac adminCtx, w http.ResponseWriter, r *http.Request) {
		if !requireSuper(w, ac) {
			return
		}
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
	// 角色调整走老端点的只有 user↔admin（W2 起 super 的授予/回收收进 /admin/roles/{uid}/role，
	// 那里有「最后一个 super」守卫；本端点见 AdminSetRole 的三条守卫注释）
	mux.Handle("PATCH /admin/users/{uid}", admin("admin-role", func(ac adminCtx, w http.ResponseWriter, r *http.Request) {
		if !requireSuper(w, ac) {
			return
		}
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
		if err := svc.AdminSetRole(ac.caller.Caller, uid, req.Role); err != nil {
			writeResult(w, nil, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}))
	mux.Handle("POST /admin/users/{uid}/revoke-sessions", admin("admin-kick", func(ac adminCtx, w http.ResponseWriter, r *http.Request) {
		if !requireSuper(w, ac) {
			return
		}
		uid, ok := pathInt64(w, r.PathValue("uid"))
		if !ok {
			return
		}
		if err := svc.AdminRevokeUserSessions(ac.caller.Caller, uid); err != nil {
			writeResult(w, nil, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}))

	// ---- 角色管理（super only，W2 新端点） ----
	// GET /admin/roles?query= 用户 + role + scopes 摘要（角色管理页的数据源）。
	mux.Handle("GET /admin/roles", admin("admin-roles", func(ac adminCtx, w http.ResponseWriter, r *http.Request) {
		if !requireSuper(w, ac) {
			return
		}
		q := r.URL.Query()
		list, total, err := svc.AdminListRoles(q.Get("query"), queryInt(q.Get("limit")), queryInt(q.Get("offset")))
		if err != nil {
			writeResult(w, nil, err)
			return
		}
		writeJSON(w, http.StatusOK, page{Items: list, Total: total})
	}))
	// POST /admin/roles/{uid}/scope {app, op:grant|revoke}：授予/回收 app-admin。
	// grant 隐含把 role 提为 admin；revoke 到 0 行时 role 降回 user（定案见
	// AdminSetScope 注释）。业务层落 admin.role.grant / admin.role.revoke 审计。
	mux.Handle("POST /admin/roles/{uid}/scope", admin("admin-role-write", func(ac adminCtx, w http.ResponseWriter, r *http.Request) {
		if !requireSuper(w, ac) {
			return
		}
		uid, ok := pathInt64(w, r.PathValue("uid"))
		if !ok {
			return
		}
		var req struct {
			App string `json:"app"`
			Op  string `json:"op"`
		}
		if !decodeOr400(w, r, &req) {
			return
		}
		var err error
		switch req.Op {
		case "grant":
			err = svc.AdminSetScope(ac.caller.Caller, uid, req.App, true)
		case "revoke":
			err = svc.AdminSetScope(ac.caller.Caller, uid, req.App, false)
		default:
			writeError(w, http.StatusBadRequest, "op 只能是 grant 或 revoke")
			return
		}
		if err != nil {
			writeResult(w, nil, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}))
	// POST /admin/roles/{uid}/role {role}：仅 super↔admin 间调整；不能自贬
	//（也不能动自己），最后一个 super 不可降级——防把平台锁死。业务层落
	// admin.role.change 审计。
	mux.Handle("POST /admin/roles/{uid}/role", admin("admin-role-write", func(ac adminCtx, w http.ResponseWriter, r *http.Request) {
		if !requireSuper(w, ac) {
			return
		}
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
		if err := svc.AdminChangeRole(ac.caller.Caller, uid, req.Role); err != nil {
			writeResult(w, nil, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}))

	// ---- 会话总览（scoped：app-admin 只见/只踢自己 app 的会话） ----
	mux.Handle("GET /admin/sessions", admin("admin-sessions", func(ac adminCtx, w http.ResponseWriter, r *http.Request) {
		apps, ok := effectiveApps(w, ac, r)
		if !ok {
			return
		}
		q := r.URL.Query()
		list, total, err := svc.AdminListSessions(queryInt64(q.Get("uid")), apps, queryInt(q.Get("limit")), queryInt(q.Get("offset")))
		if err != nil {
			writeResult(w, nil, err)
			return
		}
		writeJSON(w, http.StatusOK, page{Items: list, Total: total})
	}))
	mux.Handle("DELETE /admin/sessions/{id}", admin("admin-session-kick", func(ac adminCtx, w http.ResponseWriter, r *http.Request) {
		id, ok := pathInt64(w, r.PathValue("id"))
		if !ok {
			return
		}
		// 踢出的 app 边界与列表同源：super 不限（nil），app-admin 只踢授权 app 的会话
		if err := svc.AdminRevokeSession(ac.caller.Caller, id, ac.apps); err != nil {
			writeResult(w, nil, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}))

	// ---- 审计（scoped：app-admin 只见 detail 带自己 app 标记的条目） ----
	mux.Handle("GET /admin/audit", admin("admin-audit", func(ac adminCtx, w http.ResponseWriter, r *http.Request) {
		apps, ok := effectiveApps(w, ac, r)
		if !ok {
			return
		}
		q := r.URL.Query()
		list, total, err := svc.QueryAudit(auth.AuditQuery{
			Action: q.Get("action"),
			Actor:  queryInt64(q.Get("actor")),
			Target: queryInt64(q.Get("target")),
			From:   queryInt64(q.Get("from")),
			To:     queryInt64(q.Get("to")),
			Limit:  queryInt(q.Get("limit")),
			Offset: queryInt(q.Get("offset")),
			Apps:   apps,
		})
		if err != nil {
			writeResult(w, nil, err)
			return
		}
		// 看审计本身也是管理动作（谁在查谁的痕迹），记一条不带查询条件的轻量事件
		svc.Audit(auth.AuditEvent{
			Action: auth.AuditAdminAuditView, OK: true, ActorUID: &ac.caller.UID,
			ActorEmail: ac.caller.Email, Meta: ac.caller.Meta,
		})
		writeJSON(w, http.StatusOK, page{Items: list, Total: total})
	}))

	// ---- 配置中心（super only：全局配置，app-admin 不能碰） ----
	mux.Handle("GET /admin/config", admin("admin-config", func(ac adminCtx, w http.ResponseWriter, r *http.Request) {
		if !requireSuper(w, ac) {
			return
		}
		items, err := svc.AdminListConfig()
		if err != nil {
			writeResult(w, nil, err)
			return
		}
		writeJSON(w, http.StatusOK, items)
	}))
	mux.Handle("PUT /admin/config/{key}", admin("admin-config-write", func(ac adminCtx, w http.ResponseWriter, r *http.Request) {
		if !requireSuper(w, ac) {
			return
		}
		var req struct {
			Value string `json:"value"`
		}
		if !decodeOr400(w, r, &req) {
			return
		}
		if err := svc.AdminSetConfig(ac.caller.Caller, r.PathValue("key"), req.Value); err != nil {
			writeResult(w, nil, err)
			return
		}
		// app_config 读取带 10 秒进程缓存：改动要明说生效窗口，否则「保存了没生效」
		// 会被当成 bug 反复重试
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "hotWithinSeconds": 10})
	}))

	// ---- AI 用量看板（scoped：app-admin 只见自己 app 用户的用量） ----
	mux.Handle("GET /admin/ai-usage", admin("admin-ai-usage", func(ac adminCtx, w http.ResponseWriter, r *http.Request) {
		apps, ok := effectiveApps(w, ac, r)
		if !ok {
			return
		}
		report, err := svc.AdminAIUsage(queryInt(r.URL.Query().Get("days")), apps)
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
