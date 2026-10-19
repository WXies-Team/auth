package main

import (
	"database/sql"
	"net/http"
	"strconv"
	"time"

	"github.com/WXies-Team/auth/internal/auth"
	"github.com/WXies-Team/auth/internal/config"
	"github.com/WXies-Team/auth/internal/protocol"
)

// registerRoutes 挂全部端点：
//
//	老端点 /health、/auth/*、/api/sessions*、/internal/* —— 形状是已发布日记 App
//	的契约，一个字节都不能动；
//	新端点 /web/*、/webauthn/*、/api/{totp,passkeys}/*、/admin/* 与页面 —— Web 管理台。
//
// 抽成函数是为了让**老端点的请求/响应形状**能被路由级测试钉住：形状只有打到
// handler 上才作数，只测业务层证明不了「字节不变」。
func registerRoutes(mux *http.ServeMux, authSvc *auth.Service, cfg *config.Store, pool *sql.DB) {
	// 健康检查要**碰数据库**：DB 挂了回 5xx，ci/deploy-server.sh 靠 `curl -fsS`
	// 判定失败并自动回滚。若改成「永远 200」，部署脚本会在数据库已挂时误判健康。
	// 限流给到 120/分：部署脚本的回滚/健康轮询 15 次只占 30 秒，且它从 127.0.0.1
	// 直连、与外部监控不同键；120/分仍能挡住对 /health 的打库轰炸。
	mux.Handle("GET /health", withLogging(limitN("health", 120, health(pool, cfg))))

	// ---- 无登录态端点 ----
	// 限流口径与日记服务的 /auth/* 一致：register/login/login-code 每 IP 15 次/分
	//（撞库与爆破的主要目标），发码是**真的投一封信**、更贵，每 IP 5 次/分；
	// 每邮箱 60 秒冷却 + 每日 10 条 + 收件人总闸 15 条在 auth 内部，换 IP 也躲不掉。
	// 响应只回 sent=true，不回任何关于邮箱存在与否的额外信息（业务文案走 writeResult）。
	mux.Handle("POST /auth/register", withLogging(limit("register", jsonBody[protocol.AuthRequest](func(r *protocol.AuthRequest, w http.ResponseWriter, req *http.Request) {
		resp, err := authSvc.Register(r.Email, r.Password, r.Code, r.App, sessMeta(req))
		writeResult(w, resp, err)
	}))))
	// send-code 的 app 是可选字段：只决定这封验证码邮件的品牌（空白 = 中性品牌
	// Auth，未知值 400），不参与限流与验证码语义。
	mux.Handle("POST /auth/send-code", withLogging(limitN("send-code", 5, jsonBody[protocol.SendCodeRequest](func(r *protocol.SendCodeRequest, w http.ResponseWriter, _ *http.Request) {
		writeResult(w, map[string]bool{"sent": true}, authSvc.SendCode(r.Email, r.Purpose, r.App))
	}))))
	mux.Handle("POST /auth/reset-password", withLogging(limitN("reset-password", 5, jsonBody[protocol.ResetPasswordRequest](func(r *protocol.ResetPasswordRequest, w http.ResponseWriter, req *http.Request) {
		err := authSvc.ResetPassword(r.Email, r.Code, r.Password)
		// 匿名事件（无会话身份）：actor_uid 空，邮箱按掩码记——找回密码是
		// 「有人在改这个账号的口令」的直接证据
		auditRoute(authSvc, auth.AuditPasswordReset, nil, req, nil, err, withEmail(auth.MaskEmail(r.Email)))
		writeResult(w, map[string]bool{"ok": true}, err)
	}))))
	mux.Handle("POST /auth/login", withLogging(limit("login", jsonBody[protocol.AuthRequest](func(r *protocol.AuthRequest, w http.ResponseWriter, req *http.Request) {
		resp, err := authSvc.Login(r.Email, r.Password, r.App, sessMeta(req))
		writeResult(w, resp, err)
	}))))
	mux.Handle("POST /auth/login-code", withLogging(limit("login-code", jsonBody[protocol.LoginCodeRequest](func(r *protocol.LoginCodeRequest, w http.ResponseWriter, req *http.Request) {
		resp, err := authSvc.LoginByEmailCode(r.Email, r.Code, r.App, sessMeta(req))
		writeResult(w, resp, err)
	}))))

	// ---- 需要登录态的端点 ----
	// 先解 Bearer 拿 Caller（uid+email+aud），再交业务处理——改密重发 token 的
	// aud/email 直接取自现会话，客户端不用再传。
	authed := func(h func(c auth.Caller, w http.ResponseWriter, r *http.Request)) http.Handler {
		return withLogging(withUID(authSvc, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h(r.Context().Value(callerKey).(auth.Caller), w, r)
		})))
	}
	// authedLimited 同 authed，但**按 uid 限流**：改密/注销是持被盗 token 在线爆破
	// 旧密码的主入口，按 IP 限流挡不住分布式来源，按账号限才能兜住。
	// 外层再套一道按 IP 的宽限流：uid 限流在 JWT 校验之后，而每次校验都要一次
	// DB 查询（token_version）——被盗 token 高频打这些路由可先把连接池的认证查询
	// 打满，IP 层 120/分挡在查询之前，把放大面掐掉。
	authedLimited := func(scope string, max int, h func(c auth.Caller, w http.ResponseWriter, r *http.Request)) http.Handler {
		return limitN(scope+"-ip", 120, authed(func(c auth.Caller, w http.ResponseWriter, r *http.Request) {
			if !limiter.allow(scope+":"+strconv.FormatInt(c.UID, 10), max, time.Minute) {
				w.Header().Set("Retry-After", "60")
				writeError(w, http.StatusTooManyRequests, "操作过于频繁，请稍后再试")
				return
			}
			h(c, w, r)
		}))
	}
	mux.Handle("POST /auth/logout", authedLimited("logout", 10, func(c auth.Caller, w http.ResponseWriter, r *http.Request) {
		err := authSvc.Logout(c.UID)
		// 老端点的业务方法签名里不带来源（IP/UA 只在请求上），审计在路由层补
		auditRoute(authSvc, auth.AuditLogout, &c, r, nil, err)
		writeResult(w, map[string]bool{"ok": true}, err)
	}))
	mux.Handle("POST /auth/change-password", authedLimited("change-password", 10, reauthThen(authSvc, func(c auth.Caller, w http.ResponseWriter, r *http.Request) {
		var req protocol.ChangePasswordRequest
		if !decodeOr400(w, r, &req) {
			return
		}
		resp, err := authSvc.ChangePassword(c, req.OldPassword, req.NewPassword)
		writeResult(w, resp, err)
	})))
	// 改密码的验证码版：发码端点收件人由 **uid 查库**决定，客户端传不了收件人——
	// 改密码码只能发进账号本人的绑定邮箱。限流按 uid（authedLimited），
	// 码本身的冷却、日限额、5 次错即作废在 auth 包内。
	mux.Handle("POST /auth/send-change-code", authedLimited("send-change-code", 10, func(c auth.Caller, w http.ResponseWriter, _ *http.Request) {
		writeResult(w, map[string]bool{"sent": true}, authSvc.SendChangeCode(c))
	}))
	mux.Handle("POST /auth/change-password-code", authedLimited("change-password-code", 10, reauthThen(authSvc, func(c auth.Caller, w http.ResponseWriter, r *http.Request) {
		var req protocol.ChangePasswordCodeRequest
		if !decodeOr400(w, r, &req) {
			return
		}
		resp, err := authSvc.ChangePasswordByCode(c, req.Code, req.Password)
		writeResult(w, resp, err)
	})))
	// 改邮箱：发码与提交都按 uid 限流。码发到**新**邮箱（purpose=email_change，
	// 与改密码的 change 码互不串用），提交时密码重验 + 验码双闸，查重在服务端；
	// 成功回 {ok:true} 且**不 bump token_version**——改邮箱不是凭证变更，
	// 现会话保持登录（与改密相反），新旧邮箱各收一封通知信。
	mux.Handle("POST /auth/send-change-email-code", authedLimited("send-change-email-code", 10, func(c auth.Caller, w http.ResponseWriter, r *http.Request) {
		var req protocol.SendChangeEmailCodeRequest
		if !decodeOr400(w, r, &req) {
			return
		}
		writeResult(w, map[string]bool{"sent": true}, authSvc.SendChangeEmailCode(c, req.Email))
	}))
	mux.Handle("POST /auth/change-email", authedLimited("change-email", 10, reauthThen(authSvc, func(c auth.Caller, w http.ResponseWriter, r *http.Request) {
		var req protocol.ChangeEmailRequest
		if !decodeOr400(w, r, &req) {
			return
		}
		writeResult(w, map[string]bool{"ok": true}, authSvc.ChangeEmail(c, req.Password, req.Email, req.Code))
	})))
	mux.Handle("POST /auth/delete", authedLimited("delete-account", 10, func(c auth.Caller, w http.ResponseWriter, r *http.Request) {
		var req protocol.DeleteAccountRequest
		if !decodeOr400(w, r, &req) {
			return
		}
		err := authSvc.DeleteAccount(c.UID, req.Password)
		auditRoute(authSvc, auth.AuditAccountDelete, &c, r, nil, err)
		writeResult(w, map[string]bool{"ok": true}, err)
	}))

	// ---- 已登录设备（会话管理）----
	// 三个端点都走 authed + 按 uid 限流。列表单独一个 scope：设备页多刷几次
	// 不该把「踢人」的额度挤掉（同 scope 会共用 uid 那一个桶）。
	mux.Handle("GET /api/sessions", authedLimited("sessions", 30, func(c auth.Caller, w http.ResponseWriter, _ *http.Request) {
		list, err := authSvc.ListSessions(c.UID, c.SID)
		writeResult(w, list, err)
	}))
	// 踢单台：别人会话与不存在的 id 同回 404（不给存在性探针），幂等 200；
	// 踢掉当前 sid 也放行——客户端自己处理本地登出。
	mux.Handle("DELETE /api/sessions/{id}", authedLimited("session-kick", 10, func(c auth.Caller, w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "参数不正确")
			return
		}
		revErr := authSvc.RevokeSession(c.UID, id)
		auditRoute(authSvc, auth.AuditSessionKick, &c, r, map[string]string{
			"session": strconv.FormatInt(id, 10),
			"scope":   "one",
		}, revErr)
		writeResult(w, map[string]bool{"ok": true}, revErr)
	}))
	// 退出其它设备：只动会话层（不 bump token_version），当前 token 照用。
	mux.Handle("POST /api/sessions/revoke-others", authedLimited("session-revoke-others", 10, func(c auth.Caller, w http.ResponseWriter, r *http.Request) {
		revErr := authSvc.RevokeOtherSessions(c.UID, c.SID)
		auditRoute(authSvc, auth.AuditSessionKick, &c, r, map[string]string{"scope": "others"}, revErr)
		writeResult(w, map[string]bool{"ok": true}, revErr)
	}))

	// ---- 内部校验（日记服务的 withUID 中间件调用）----
	// 验签 + token_version 比对 + aud 精确匹配期望应用 + 会话未被踢（sid 行健在）。
	// 限流按来源 IP 600/分：
	// 调用方是同机的日记服务（一次业务请求调一次 verify），正常量级远低于此；
	// 600 是给多租户共享留的余量，挡的是误配置成公网可达后的打爆。
	// 环回/受信内网守卫在限流之外：先把公网来源挡在读体与限流计数之前。
	mux.Handle("POST /internal/verify", withLogging(loopbackOnly(limitN("verify", 600, internalVerify(authSvc)))))

	// ---- 内部校验（存量迁移）----
	// 两个日记服务的历史用户并入本服务的唯一入口：Bearer hook_token 鉴权 +
	// 单批 ≤100 条 + 整批一个事务。同样只该被同机脚本调到，不挂公网限流（见 loopbackOnly）。
	mux.Handle("POST /internal/users/ensure", withLogging(loopbackOnly(internalEnsure(cfg.Require, authSvc))))

	// ---- Web 管理台（自助台 + 管理后台 + 页面）----
	// 全部挂在 /web、/webauthn、/api/{totp,passkeys}、/admin 新路径下：
	// 老端点的请求/响应形状一个字节不动，已发布的日记 App 不受影响。
	registerPageRoutes(mux, authSvc)
	registerWebRoutes(mux, authSvc)
	registerAdminRoutes(mux, authSvc)
}
