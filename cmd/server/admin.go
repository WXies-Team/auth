package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/WXies-Team/auth/internal/auth"
)

// 管理后台的 HTTP 层（规格 A2.5 + W2 分级授权）。授权闸全部在这里，每请求都过：
//
//	① 只收 cookie（Bearer 不给后台钥匙——日记 App 侧的 token 被盗不牵连后台）；
//	② role ∈ {admin, super}，**每请求现查 users 行**（撤销资格必须当场生效）；
//	③ 强制 MFA：没绑 TOTP/passkey 的管理员进不来（OWASP MFA CS）；
//	④ reauth ≤2 小时（ASVS V7.5.1），401 后前端弹重新验证框；成功的**非 GET**
//	   管理操作经 slideReauth 滑动续期 reauth_at（GitHub sudo mode 口径；GET 读
//	   操作不续期，W7-1）。
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
	// adminN 是过完四道闸的请求包装（cookie + role + MFA + reauth），max 为本
	// scope 的每分钟额度。默认口径 60/分/uid（admin 薄壳）；逐行渲染的取图口对
	// 60 太紧（会话总览一页 100 行，后 40 张头像会掉 429 回退色块），单独放宽。
	adminN := func(scope string, max int, h func(c adminCtx, w http.ResponseWriter, r *http.Request)) http.Handler {
		return withLogging(withUID(svc, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c := r.Context().Value(webCallerKey).(auth.WebCaller)
			if !c.ViaCookie {
				writeError(w, http.StatusUnauthorized, "管理后台只认网页登录态，请在控制台用密码或 Passkey 登录")
				return
			}
			role, err := svc.SessionRole(c.UID)
			if err != nil {
				writeResult(w, nil, err)
				return
			}
			if !auth.IsAdminRole(role) {
				writeError(w, http.StatusForbidden, "你不是管理后台成员，请联系平台管理员开通")
				return
			}
			mfa, err := svc.HasMFA(c.UID)
			if err != nil {
				writeResult(w, nil, err)
				return
			}
			if !mfa {
				writeError(w, http.StatusForbidden, "管理后台要求先绑定两步验证或 Passkey，请到「两步验证」页绑定后再试")
				return
			}
			if err := svc.RequireReauth(c.SID); err != nil {
				writeResult(w, nil, err)
				return
			}
			if !limiter.allow(scope+":"+strconv.FormatInt(c.UID, 10), max, time.Minute) {
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
			// GET 读操作不滑动续期（W7-1）：滑动只属于真正改状态的写操作
			slideReauth(svc, c.SID, r.Method, w, func(w http.ResponseWriter) { h(ac, w, r) })
		})))
	}
	// admin 是默认额度（60/分/uid）的薄壳：绝大多数管理端点走它。
	admin := func(scope string, h func(c adminCtx, w http.ResponseWriter, r *http.Request)) http.Handler {
		return adminN(scope, 60, h)
	}
	// requireSuper 挡掉 app-admin 对 super 专属端点的访问（用户目录/角色/注销/
	// 配置中心都是平台级数据）。放行即 true。
	requireSuper := func(w http.ResponseWriter, ac adminCtx) bool {
		if !ac.super {
			writeError(w, http.StatusForbidden, "此功能仅平台管理员可用，请联系平台管理员操作")
			return false
		}
		return true
	}
	// adminScope 把路由层现查的授权现场透传给业务层（super 恒 nil apps，app-admin
	// 带本请求现查的清单——撤销 scope 当场生效）。
	adminScope := func(ac adminCtx) auth.AdminScope {
		return auth.AdminScope{Super: ac.super, Apps: ac.apps}
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
				writeError(w, http.StatusForbidden, "未知项目，请重新选择后重试")
				return nil, false
			}
			return []string{want}, true
		}
		if len(ac.apps) == 0 {
			writeError(w, http.StatusForbidden, "尚未授予任何项目的管理权限，请联系平台管理员开通")
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
		writeError(w, http.StatusForbidden, "没有该项目的管理权限，请联系平台管理员开通")
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
	// ---- W3 头像真图：GET /admin/users/{uid}/avatar ----
	// 档案里的 avatarImage 是**裸 base64**（无 data: 前缀，validateProfile 只收标准
	// 字母表带 padding），这里解码回图片字节原样回。Content-Type 按字节嗅探
	//（DetectContentType），不猜扩展名；无图 / 解不动 / 嗅不出 image/* 一律 404 ——
	// 前端 <img> 的 onerror 据此回退「色块 + 首字」（回退方向是图 → 占位符）。
	// 弱缓存：max-age=300 + ETag=sha256(字节)，条件请求回 304（头像换新走
	// PUT /api/profile，5 分钟陈旧可接受；一页 20~100 行重复进页面不该每次拖字节）。
	// 权限挂 admin 总闸（cookie + role + MFA + reauth）+ 300/分/uid 限流：头像对
	// 全体管理员可见——会话总览的 app-admin 也要渲染自己范围内的用户头像，不设
	// super 专属（super 专属的是用户目录/详情等平台级数据端点）。
	mux.Handle("GET /admin/users/{uid}/avatar", adminN("admin-avatar", 300, func(ac adminCtx, w http.ResponseWriter, r *http.Request) {
		uid, ok := pathInt64(w, r.PathValue("uid"))
		if !ok {
			return
		}
		prof, err := svc.GetProfile(uid)
		if err != nil {
			writeResult(w, nil, err)
			return
		}
		if prof == nil || prof.AvatarImage == nil || *prof.AvatarImage == "" {
			http.NotFound(w, r)
			return
		}
		raw, err := base64.StdEncoding.DecodeString(*prof.AvatarImage)
		if err != nil || len(raw) == 0 {
			http.NotFound(w, r)
			return
		}
		ctype := http.DetectContentType(raw)
		if !strings.HasPrefix(ctype, "image/") {
			http.NotFound(w, r)
			return
		}
		sum := sha256.Sum256(raw)
		etag := `"` + hex.EncodeToString(sum[:]) + `"`
		if inm := r.Header.Get("If-None-Match"); inm != "" && strings.Contains(inm, etag) {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("Content-Type", ctype)
		w.Header().Set("Cache-Control", "max-age=300")
		w.Header().Set("ETag", etag)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		_, _ = w.Write(raw)
	}))
	// POST /admin/users/{uid}/role {role:user|admin|super}：**唯一**的角色调整端点
	//（本批把 PATCH /admin/users/{uid} 与 POST /admin/roles/{uid}/role 合并到这里，
	// 旧端点已删——内部前端无外部兼容负担）。授权规则与守卫都在业务层
	//（AdminSetRole）：只有根 su 能授予/回收 super、不能改自己、最后一个 super
	// 不可降级；审计沿用 admin.role.change / admin.user.role_change 两个事件名。
	mux.Handle("POST /admin/users/{uid}/role", admin("admin-role-write", func(ac adminCtx, w http.ResponseWriter, r *http.Request) {
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

	// ---- B9 邀请建号（su 与 app-admin 都可进：项目边界在业务层 adminTargetScope 判，
	// 与封禁/重置密码同一套 400/403 口径） ----
	// POST /admin/users/invite {email, app?} → {ok, expiresAt}：token 只存 sha256、
	// 24h 过期，邀请信尽力而为（投递失败不翻 500，可在列表重发）。
	// 审计 user.invite 在业务层记——路由层不再补（与其它管理动作同惯例）。
	mux.Handle("POST /admin/users/invite", admin("admin-invite", func(ac adminCtx, w http.ResponseWriter, r *http.Request) {
		var req struct {
			Email string `json:"email"`
			App   string `json:"app"`
		}
		if !decodeOr400(w, r, &req) {
			return
		}
		expiresAt, err := svc.AdminCreateInvite(ac.caller.Caller, adminScope(ac), req.Email, req.App)
		if err != nil {
			writeResult(w, nil, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "expiresAt": expiresAt})
	}))
	// GET /admin/users/invites?query=：四态是读时派生（accepted/revoked/expired/pending），
	// 不落库；su 全量、app-admin 仅其授权项目（零 scope admin 回空列表）。
	mux.Handle("GET /admin/users/invites", admin("admin-invite", func(ac adminCtx, w http.ResponseWriter, r *http.Request) {
		list, err := svc.AdminListInvites(adminScope(ac), r.URL.Query().Get("query"))
		if err != nil {
			writeResult(w, nil, err)
			return
		}
		writeJSON(w, http.StatusOK, struct {
			Invites []auth.AdminInvite `json:"invites"`
		}{Invites: list})
	}))
	// 重发（换新 token + 续 24h，旧链接即刻失效；已接受/已撤销 → 400）。
	mux.Handle("POST /admin/users/invite/{id}/resend", admin("admin-invite", func(ac adminCtx, w http.ResponseWriter, r *http.Request) {
		id, ok := pathInt64(w, r.PathValue("id"))
		if !ok {
			return
		}
		if err := svc.AdminResendInvite(ac.caller.Caller, adminScope(ac), id); err != nil {
			writeResult(w, nil, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}))
	// 撤销（幂等：已撤销再撤回 ok；已接受 → 400）。
	mux.Handle("POST /admin/users/invite/{id}/revoke", admin("admin-invite", func(ac adminCtx, w http.ResponseWriter, r *http.Request) {
		id, ok := pathInt64(w, r.PathValue("id"))
		if !ok {
			return
		}
		if err := svc.AdminRevokeInvite(ac.caller.Caller, adminScope(ac), id); err != nil {
			writeResult(w, nil, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
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
			writeError(w, http.StatusBadRequest, "op 只能是 grant 或 revoke，请检查后重试")
			return
		}
		if err != nil {
			writeResult(w, nil, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}))

	// ---- W1 管理员重置密码（super 与 app-admin 都可进，权限在业务层按 W1 口径判） ----
	// body {mode:"generate"|"manual", password?, forceChange, notify, reason?} →
	// 200 {temporaryPassword}。临时密码只在回执出现一次（不落日志、不进审计）；
	// 审计 password.reset 在业务层记。
	mux.Handle("POST /admin/users/{uid}/password", admin("admin-password-reset", func(ac adminCtx, w http.ResponseWriter, r *http.Request) {
		uid, ok := pathInt64(w, r.PathValue("uid"))
		if !ok {
			return
		}
		var req struct {
			Mode        string `json:"mode"`
			Password    string `json:"password"`
			ForceChange bool   `json:"forceChange"`
			Notify      bool   `json:"notify"`
			Reason      string `json:"reason"`
		}
		if !decodeOr400(w, r, &req) {
			return
		}
		tmp, err := svc.AdminResetPassword(ac.caller.Caller, adminScope(ac), uid, auth.AdminPasswordReset{
			Mode: req.Mode, Password: req.Password, ForceChange: req.ForceChange,
			Notify: req.Notify, Reason: req.Reason,
		})
		if err != nil {
			writeResult(w, nil, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"temporaryPassword": tmp})
	}))

	// ---- W1 管理员更换邮箱（B5）：权限矩阵与密码重置逐字同款（su 对任何人 /
	// root 目标仅根本人 / app-admin 目标须在任一其授权项目下有活跃会话，判定都在
	// 业务层 AdminChangeEmail）。body {email, reason?} → {ok:true}。不 bump
	// token_version（uid 是权威标识，会话全保留）；新旧邮箱必收管理员措辞的通知信。
	// 审计 user.email_change 在业务层记。
	mux.Handle("POST /admin/users/{uid}/email", admin("admin-email-change", func(ac adminCtx, w http.ResponseWriter, r *http.Request) {
		uid, ok := pathInt64(w, r.PathValue("uid"))
		if !ok {
			return
		}
		var req struct {
			Email  string `json:"email"`
			Reason string `json:"reason"`
		}
		if !decodeOr400(w, r, &req) {
			return
		}
		if err := svc.AdminChangeEmail(ac.caller.Caller, adminScope(ac), uid, auth.AdminEmailChange{
			Email: req.Email, Reason: req.Reason,
		}); err != nil {
			writeResult(w, nil, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}))

	// ---- W3 管理员重置资料（B5）：body {avatar, nickname}（至少一项）→ {ok:true}。
	// 只清 user_profile 的列（头像图+色 / 昵称），不动凭证不吊销会话；审计
	// user.profile_reset 在业务层记。
	mux.Handle("POST /admin/users/{uid}/profile-reset", admin("admin-profile-reset", func(ac adminCtx, w http.ResponseWriter, r *http.Request) {
		uid, ok := pathInt64(w, r.PathValue("uid"))
		if !ok {
			return
		}
		var req struct {
			Avatar   bool `json:"avatar"`
			Nickname bool `json:"nickname"`
		}
		if !decodeOr400(w, r, &req) {
			return
		}
		if err := svc.AdminResetProfile(ac.caller.Caller, adminScope(ac), uid, auth.AdminProfileReset{
			Avatar: req.Avatar, Nickname: req.Nickname,
		}); err != nil {
			writeResult(w, nil, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}))

	// ---- W2 封禁 / 解除（super 管 '*' 与任意项目；app-admin 只管授权项目、禁 '*'） ----
	mux.Handle("POST /admin/users/{uid}/ban", admin("admin-ban", func(ac adminCtx, w http.ResponseWriter, r *http.Request) {
		uid, ok := pathInt64(w, r.PathValue("uid"))
		if !ok {
			return
		}
		var req struct {
			App    string `json:"app"`
			Until  int64  `json:"until"`
			Reason string `json:"reason"`
		}
		if !decodeOr400(w, r, &req) {
			return
		}
		if err := svc.AdminBan(ac.caller.Caller, adminScope(ac), uid, auth.AdminBanInput{
			App: req.App, Until: req.Until, Reason: req.Reason,
		}); err != nil {
			writeResult(w, nil, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}))
	mux.Handle("DELETE /admin/users/{uid}/ban", admin("admin-ban", func(ac adminCtx, w http.ResponseWriter, r *http.Request) {
		uid, ok := pathInt64(w, r.PathValue("uid"))
		if !ok {
			return
		}
		var req struct {
			App string `json:"app"`
		}
		if !decodeOr400(w, r, &req) {
			return
		}
		if err := svc.AdminUnban(ac.caller.Caller, adminScope(ac), uid, req.App, ""); err != nil {
			writeResult(w, nil, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}))

	// ---- B9 批量操作：一次配置套用到所选用户，逐用户与单发同语义（权限矩阵在
	// 业务层逐项跑，越权项落成单条失败而不是整批 403） ----
	// body {kind: password_reset|ban|unban, uids:[...], app?, until?, reason?} →
	// BulkResult（批次号 + 汇总 + 逐项成败）。批量重置的临时密码**不进回执**，
	// 只随逐用户通知邮件走（凭证卫生）；审计 admin.bulk_action 在业务层记。
	mux.Handle("POST /admin/users/bulk", admin("admin-bulk", func(ac adminCtx, w http.ResponseWriter, r *http.Request) {
		var req struct {
			Kind   string  `json:"kind"`
			UIDs   []int64 `json:"uids"`
			App    string  `json:"app"`
			Until  int64   `json:"until"`
			Reason string  `json:"reason"`
		}
		if !decodeOr400(w, r, &req) {
			return
		}
		res, err := svc.AdminBulk(ac.caller.Caller, adminScope(ac), req.Kind, req.UIDs,
			auth.AdminBanInput{App: req.App, Until: req.Until, Reason: req.Reason})
		if err != nil {
			writeResult(w, nil, err)
			return
		}
		writeJSON(w, http.StatusOK, res)
	}))

	// ---- W5 项目登录白名单（super 管全部项目；app-admin 只管授权项目） ----
	mux.Handle("GET /admin/projects", admin("admin-projects", func(ac adminCtx, w http.ResponseWriter, _ *http.Request) {
		list, err := svc.AdminListProjects(adminScope(ac))
		if err != nil {
			writeResult(w, nil, err)
			return
		}
		writeJSON(w, http.StatusOK, struct {
			Projects []auth.AdminProject `json:"projects"`
		}{Projects: list})
	}))
	mux.Handle("POST /admin/projects/{app}/access", admin("admin-projects-write", func(ac adminCtx, w http.ResponseWriter, r *http.Request) {
		var req struct {
			Email string `json:"email"`
		}
		if !decodeOr400(w, r, &req) {
			return
		}
		if err := svc.AdminGrantAccess(ac.caller.Caller, adminScope(ac), r.PathValue("app"), req.Email); err != nil {
			writeResult(w, nil, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}))
	mux.Handle("DELETE /admin/projects/{app}/access", admin("admin-projects-write", func(ac adminCtx, w http.ResponseWriter, r *http.Request) {
		var req struct {
			Email string `json:"email"`
		}
		if !decodeOr400(w, r, &req) {
			return
		}
		if err := svc.AdminRevokeAccess(ac.caller.Caller, adminScope(ac), r.PathValue("app"), req.Email); err != nil {
			writeResult(w, nil, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}))
	mux.Handle("POST /admin/projects/{app}/restrict", admin("admin-projects-write", func(ac adminCtx, w http.ResponseWriter, r *http.Request) {
		var req struct {
			Restricted bool `json:"restricted"`
		}
		if !decodeOr400(w, r, &req) {
			return
		}
		if err := svc.AdminSetRestricted(ac.caller.Caller, adminScope(ac), r.PathValue("app"), req.Restricted); err != nil {
			writeResult(w, nil, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}))
	// B4 OAuth 客户端登记：开通/更新回跳地址（首调自动生成 client_id），
	// rotateSecret=true 时换新 secret 并一次性回执（旧 secret 即刻失效）。
	// 权限在业务层（su 全部项目 / app-admin 仅 scopes 内项目）。
	mux.Handle("POST /admin/projects/{app}/oauth", admin("admin-projects-write", func(ac adminCtx, w http.ResponseWriter, r *http.Request) {
		var req struct {
			RedirectUris []string `json:"redirectUris"`
			RotateSecret bool     `json:"rotateSecret"`
		}
		if !decodeOr400(w, r, &req) {
			return
		}
		res, err := svc.AdminConfigureOAuth(ac.caller.Caller, adminScope(ac), r.PathValue("app"),
			auth.AdminOAuthInput{RedirectUris: req.RedirectUris, RotateSecret: req.RotateSecret})
		if err != nil {
			writeResult(w, nil, err)
			return
		}
		writeJSON(w, http.StatusOK, res)
	}))

	// ---- 会话总览（scoped：app-admin 只见/只踢自己 app 的会话） ----
	mux.Handle("GET /admin/sessions", admin("admin-sessions", func(ac adminCtx, w http.ResponseWriter, r *http.Request) {
		apps, ok := effectiveApps(w, ac, r)
		if !ok {
			return
		}
		q := r.URL.Query()
		list, total, totalUsers, err := svc.AdminListSessions(queryInt64(q.Get("uid")), apps,
			q.Get("query"), queryInt(q.Get("limit")), queryInt(q.Get("offset")))
		if err != nil {
			writeResult(w, nil, err)
			return
		}
		writeJSON(w, http.StatusOK, sessionPage{Items: list, Total: total, TotalUsers: totalUsers})
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

	// ---- AI 用量看板（scoped：app-admin 只见授权项目用户集的用量、global 行隐藏）----
	// 不带 uid = 总览；带 ?uid= = 钻取单用户（app-admin 只能钻授权项目内的用户，
	// 越界与查无此 uid 同回 404，不给存在性探针）。限额修改仍走
	// PUT /admin/config/{ai_*}（super only，app-admin 只读）——本端点没有写能力。
	mux.Handle("GET /admin/ai-usage", admin("admin-ai-usage", func(ac adminCtx, w http.ResponseWriter, r *http.Request) {
		apps, ok := effectiveApps(w, ac, r)
		if !ok {
			return
		}
		q := r.URL.Query()
		days := queryInt(q.Get("days"))
		if raw := q.Get("uid"); raw != "" {
			uid, perr := strconv.ParseInt(raw, 10, 64)
			if perr != nil || uid <= 0 {
				writeError(w, http.StatusBadRequest, "参数不正确，请检查 uid 后重试")
				return
			}
			detail, err := svc.AdminAIUsageUser(days, apps, uid)
			if err != nil {
				writeResult(w, nil, err)
				return
			}
			writeJSON(w, http.StatusOK, detail)
			return
		}
		report, err := svc.AdminAIUsage(days, apps)
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

// sessionPage 是 GET /admin/sessions 的回执（比 page 多一个用户计数）：
// total 是会话条数（分页 offset 按会话走），totalUsers 是同条件下去重后的用户数——
// 会话总览的表格一行一位用户，页码文案「第 N 页 · 共 M 位用户」按它说。
type sessionPage struct {
	Items      any `json:"items"`
	Total      int `json:"total"`
	TotalUsers int `json:"totalUsers"`
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
