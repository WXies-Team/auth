package main

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/WXies-Team/auth/internal/auth"
	"github.com/WXies-Team/auth/internal/protocol"
)

// Web 管理台的 HTTP 层：cookie 签发/清除、CSRF 与 Origin 两道守卫、
// 以及规格 A2.1~A2.3 列出的全部新端点。老端点一个字节都不动（见 main.go）。
//
// 分层口径：业务判定全在 internal/auth（可单测、不碰 HTTP），这里只做
// 「请求 → 参数 → 调用 → 回执」与 cookie/头这类传输层的事。

// registerWebRoutes 挂 /web/* 与 /webauthn/*、/api/totp*、/api/passkeys*。
// 所有需要登录态的路由都走 withUID：cookie 与 Bearer 双凭据 + 非 GET 的 CSRF 校验。
func registerWebRoutes(mux *http.ServeMux, svc *auth.Service) {
	// authed：双凭据 + 按 uid 限流。限流键带 uid，登录态下的滥用挡在业务之前；
	// IP 层的外圈由各端点自己的 limitN 兜（IP 限流挡在读体/JWT 之前）。
	authed := func(scope string, max int, h func(c auth.WebCaller, w http.ResponseWriter, r *http.Request)) http.Handler {
		return withLogging(withUID(svc, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c := r.Context().Value(webCallerKey).(auth.WebCaller)
			if !limiter.allow(scope+":"+strconv.FormatInt(c.UID, 10), max, time.Minute) {
				w.Header().Set("Retry-After", "60")
				writeError(w, http.StatusTooManyRequests, "操作过于频繁，请稍后再试")
				return
			}
			h(c, w, r)
		})))
	}
	// reauthed：在 authed 之上再要一道 15 分钟内的强认证（ASVS V7.5.1）。
	// 401 + 固定文案，前端据此弹「重新验证」框后调 /web/reauth。
	reauthed := func(scope string, max int, h func(c auth.WebCaller, w http.ResponseWriter, r *http.Request)) http.Handler {
		return authed(scope, max, func(c auth.WebCaller, w http.ResponseWriter, r *http.Request) {
			if err := svc.RequireReauth(c.SID); err != nil {
				writeResult(w, nil, err)
				return
			}
			h(c, w, r)
		})
	}
	// ---- 登录（无登录态，只有 Origin 同源校验：此时没有可搭的 cookie 顺风车）----
	mux.Handle("POST /web/login/password", withLogging(originGuard(limitN("web-login", 15,
		jsonBody[protocol.WebLoginRequest](func(req *protocol.WebLoginRequest, w http.ResponseWriter, r *http.Request) {
			res, err := svc.WebLoginPassword(req.Email, req.Password, sessMeta(r))
			if err != nil {
				writeResult(w, nil, err)
				return
			}
			writeLoginResult(svc, w, res)
		})))))
	mux.Handle("POST /web/login/email-code", withLogging(originGuard(limitN("web-login-code", 15,
		jsonBody[protocol.WebLoginCodeRequest](func(req *protocol.WebLoginCodeRequest, w http.ResponseWriter, r *http.Request) {
			res, err := svc.WebLoginEmailCode(req.Email, req.Code, sessMeta(r))
			if err != nil {
				writeResult(w, nil, err)
				return
			}
			writeLoginResult(svc, w, res)
		})))))
	mux.Handle("POST /web/login/totp", withLogging(originGuard(limitN("web-login-totp", 15,
		jsonBody[protocol.WebLoginTOTPRequest](func(req *protocol.WebLoginTOTPRequest, w http.ResponseWriter, r *http.Request) {
			res, err := svc.WebLoginTOTP(req.LoginToken, req.Code, req.RecoveryCode, sessMeta(r))
			if err != nil {
				writeResult(w, nil, err)
				return
			}
			writeLoginResult(svc, w, res)
		})))))

	// ---- 会话（当前身份 / 重新验证 / 登出）----
	mux.Handle("POST /web/session", authed("web-session", 60,
		func(c auth.WebCaller, w http.ResponseWriter, r *http.Request) {
			totpOn, err := svc.TOTPEnabled(c.UID)
			if err != nil {
				writeResult(w, nil, err)
				return
			}
			keys, err := svc.ListPasskeys(c.UID, c.SID)
			if err != nil {
				writeResult(w, nil, err)
				return
			}
			hasPassword, err := svc.HasPassword(c.UID)
			if err != nil {
				writeResult(w, nil, err)
				return
			}
			// csrfToken 从可读 cookie 取回一份（Bearer 调用没有 cookie，回空串）
			csrf := ""
			if ck, err := r.Cookie(auth.WebCSRFCookieName); err == nil {
				csrf = ck.Value
			}
			writeJSON(w, http.StatusOK, protocol.WebSessionResponse{
				UID: c.UID, Email: c.Email, Role: c.Role, CSRFToken: csrf,
				TotpEnabled: totpOn, PasskeyCount: len(keys), PasswordSet: hasPassword,
			})
		}))
	mux.Handle("POST /web/reauth", authed("web-reauth", 10,
		func(c auth.WebCaller, w http.ResponseWriter, r *http.Request) {
			var req protocol.WebReauthRequest
			if !decodeOr400(w, r, &req) {
				return
			}
			if err := svc.Reauth(c.Caller, req.Password, req.TOTPCode); err != nil {
				writeResult(w, nil, err)
				return
			}
			writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
		}))
	mux.Handle("POST /web/logout", authed("web-logout", 10,
		func(c auth.WebCaller, w http.ResponseWriter, _ *http.Request) {
			// 只吊销本行（web 会话），不动 token_version：同账号的其它设备照常用
			err := svc.RevokeSession(c.UID, c.SID)
			svc.Audit(auth.AuditEvent{
				Action: auth.AuditLogout, OK: err == nil, ActorUID: &c.UID,
				ActorEmail: c.Email, Meta: c.Meta,
			})
			if err != nil {
				writeResult(w, nil, err)
				return
			}
			clearWebCookies(w)
			// 同源下的登出顺带清存储：让 PWA/缓存里的登录态也一起消失
			w.Header().Set("Clear-Site-Data", `"cookies", "storage"`)
			writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
		}))

	// ---- Passkey 仪式 ----
	mux.Handle("POST /webauthn/register/options", authed("passkey-options", 30,
		func(c auth.WebCaller, w http.ResponseWriter, _ *http.Request) {
			creation, id, err := svc.BeginPasskeyRegistration(c.Caller)
			if err != nil {
				writeResult(w, nil, err)
				return
			}
			writeJSON(w, http.StatusOK, ceremonyResponse{PublicKey: creation.Response, CeremonyID: id})
		}))
	mux.Handle("POST /webauthn/register/finish", reauthed("passkey-register", 10, jsonAuthedWrapper(
		func(c auth.WebCaller, req *protocol.PasskeyFinishRequest, w http.ResponseWriter, r *http.Request) {
			info, err := svc.FinishPasskeyRegistration(c.Caller, req.CeremonyID, req.Response, sessMeta(r))
			if err != nil {
				writeResult(w, nil, err)
				return
			}
			writeJSON(w, http.StatusOK, info)
		})))
	mux.Handle("POST /webauthn/login/options", withLogging(originGuard(limitN("passkey-login-options", 30,
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			assertion, id, err := svc.BeginPasskeyLogin()
			if err != nil {
				writeResult(w, nil, err)
				return
			}
			writeJSON(w, http.StatusOK, ceremonyResponse{PublicKey: assertion.Response, CeremonyID: id})
		})))))
	mux.Handle("POST /webauthn/login/finish", withLogging(originGuard(limitN("passkey-login-finish", 15,
		jsonBody[protocol.PasskeyFinishRequest](func(req *protocol.PasskeyFinishRequest, w http.ResponseWriter, r *http.Request) {
			uid, email, credID, err := svc.FinishPasskeyLogin(req.CeremonyID, req.Response)
			if err != nil {
				writeResult(w, nil, err)
				return
			}
			ws, err := svc.CreateWebSession(uid, sessMeta(r))
			if err != nil {
				writeResult(w, nil, err)
				return
			}
			svc.MarkPasskeyLogin(ws.SID, credID)
			svc.Audit(auth.AuditEvent{
				Action: auth.AuditLogin, OK: true, ActorUID: &uid, ActorEmail: email,
				Meta:   sessMeta(r),
				Detail: map[string]string{"method": "passkey"},
			})
			setWebCookies(w, ws)
			writeJSON(w, http.StatusOK, protocol.AuthResponse{Token: ws.Token, Email: email})
		})))))

	// ---- Passkey 管理 ----
	mux.Handle("GET /api/passkeys", authed("passkey-list", 30,
		func(c auth.WebCaller, w http.ResponseWriter, _ *http.Request) {
			list, err := svc.ListPasskeys(c.UID, c.SID)
			if err != nil {
				writeResult(w, nil, err)
				return
			}
			writeJSON(w, http.StatusOK, list)
		}))
	mux.Handle("PATCH /api/passkeys/{id}", authed("passkey-rename", 10,
		func(c auth.WebCaller, w http.ResponseWriter, r *http.Request) {
			id, ok := pathInt64(w, r.PathValue("id"))
			if !ok {
				return
			}
			var req protocol.PasskeyRenameRequest
			if !decodeOr400(w, r, &req) {
				return
			}
			if err := svc.RenamePasskey(c.Caller, id, req.Name); err != nil {
				writeResult(w, nil, err)
				return
			}
			writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
		}))
	mux.Handle("DELETE /api/passkeys/{id}", reauthed("passkey-delete", 10,
		func(c auth.WebCaller, w http.ResponseWriter, r *http.Request) {
			id, ok := pathInt64(w, r.PathValue("id"))
			if !ok {
				return
			}
			if err := svc.DeletePasskey(c.Caller, id); err != nil {
				writeResult(w, nil, err)
				return
			}
			writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
		}))

	// ---- TOTP ----
	mux.Handle("GET /api/totp", authed("totp-status", 30,
		func(c auth.WebCaller, w http.ResponseWriter, _ *http.Request) {
			st, err := svc.TOTPStatus(c.UID)
			if err != nil {
				writeResult(w, nil, err)
				return
			}
			writeJSON(w, http.StatusOK, st)
		}))
	mux.Handle("POST /api/totp/setup", reauthed("totp-setup", 10,
		func(c auth.WebCaller, w http.ResponseWriter, _ *http.Request) {
			setup, err := svc.SetupTOTP(c.Caller)
			if err != nil {
				writeResult(w, nil, err)
				return
			}
			writeJSON(w, http.StatusOK, setup)
		}))
	mux.Handle("POST /api/totp/enable", reauthed("totp-enable", 10,
		func(c auth.WebCaller, w http.ResponseWriter, r *http.Request) {
			var req protocol.CodeRequest
			if !decodeOr400(w, r, &req) {
				return
			}
			codes, err := svc.EnableTOTP(c.Caller, req.Code)
			if err != nil {
				writeResult(w, nil, err)
				return
			}
			// 恢复码只在这一刻回一次：此后服务端只有哈希，谁也要不回来
			writeJSON(w, http.StatusOK, protocol.RecoveryCodesResponse{RecoveryCodes: codes})
		}))
	mux.Handle("POST /api/totp/disable", reauthed("totp-disable", 10,
		func(c auth.WebCaller, w http.ResponseWriter, r *http.Request) {
			var req protocol.CodeRequest
			if !decodeOr400(w, r, &req) {
				return
			}
			if err := svc.DisableTOTP(c.Caller, req.Code); err != nil {
				writeResult(w, nil, err)
				return
			}
			writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
		}))
	mux.Handle("POST /api/totp/regenerate-recovery-codes", reauthed("totp-recovery", 10,
		func(c auth.WebCaller, w http.ResponseWriter, r *http.Request) {
			var req protocol.CodeRequest
			if !decodeOr400(w, r, &req) {
				return
			}
			codes, err := svc.RegenerateRecoveryCodes(c.Caller, req.Code)
			if err != nil {
				writeResult(w, nil, err)
				return
			}
			writeJSON(w, http.StatusOK, protocol.RecoveryCodesResponse{RecoveryCodes: codes})
		}))
}

// jsonAuthedWrapper 把「解 JSON 体」这步折进 reauthed 的签名里
//（reauthed 的 handler 形状是固定三参，包一层再解体最省事）。
func jsonAuthedWrapper(h func(c auth.WebCaller, req *protocol.PasskeyFinishRequest, w http.ResponseWriter, r *http.Request)) func(auth.WebCaller, http.ResponseWriter, *http.Request) {
	return func(c auth.WebCaller, w http.ResponseWriter, r *http.Request) {
		var req protocol.PasskeyFinishRequest
		if !decodeOr400(w, r, &req) {
			return
		}
		h(c, &req, w, r)
	}
}

// ceremonyResponse 是 /webauthn/*/options 的回执：publicKey 是库给浏览器的
// 创建/断言选项整体，ceremonyId 是我们这边的单次中间态 id。
type ceremonyResponse struct {
	PublicKey  any   `json:"publicKey"`
	CeremonyID int64 `json:"ceremonyId"`
}

// writeLoginResult 分流登录回执：完成 → 签 cookie + {token,email}（与 AuthResponse
// 同形，C 批零新解析）；还差第二步 → {status,loginToken,methods}。
func writeLoginResult(svc *auth.Service, w http.ResponseWriter, res *auth.WebLoginResult) {
	if res.Session == nil {
		writeJSON(w, http.StatusOK, protocol.WebLoginPending{
			Status: res.Status, LoginToken: res.LoginToken, Methods: res.Methods,
		})
		return
	}
	setWebCookies(w, res.Session)
	writeJSON(w, http.StatusOK, protocol.AuthResponse{Token: res.Session.Token, Email: res.Email})
}

// setWebCookies 签发双 cookie：会话 cookie HttpOnly（脚本读不到），CSRF cookie
// 非 HttpOnly（JS 要读它塞进 X-CSRF-Token）。__Host- 前缀要求 Secure + Path=/，
// 与 auth.WebCookieName 的定义配套。
func setWebCookies(w http.ResponseWriter, ws *auth.WebSession) {
	http.SetCookie(w, &http.Cookie{
		Name: auth.WebCookieName, Value: ws.Token, Path: "/",
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
		MaxAge: auth.WebCookieMaxAgeSeconds, Expires: ws.ExpiresAt,
	})
	http.SetCookie(w, &http.Cookie{
		Name: auth.WebCSRFCookieName, Value: ws.CSRFToken, Path: "/",
		HttpOnly: false, Secure: true, SameSite: http.SameSiteStrictMode,
		MaxAge: auth.WebCookieMaxAgeSeconds, Expires: ws.ExpiresAt,
	})
}

// clearWebCookies 把两枚 cookie 置为立即过期（登出与 401 清态都用它）。
func clearWebCookies(w http.ResponseWriter) {
	past := time.Unix(1, 0)
	for _, name := range []string{auth.WebCookieName, auth.WebCSRFCookieName} {
		http.SetCookie(w, &http.Cookie{
			Name: name, Value: "", Path: "/", HttpOnly: name == auth.WebCookieName,
			Secure: true, SameSite: http.SameSiteStrictMode,
			MaxAge: -1, Expires: past,
		})
	}
}

// originGuard 对**无登录态**的状态变更请求做同源校验（登录 CSRF 的兜底：
// SameSite=Strict 管的是「带不带 cookie」，这一步管的是「谁在提交表单」）。
//
// Origin 缺席时放行——浏览器跨站提交必带 Origin，缺席的是 App/curl 这类
// 非浏览器客户端，它们本来就没有 cookie 可冒用。
func originGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !readMethod(r.Method) && !sameOrigin(r) {
			writeError(w, http.StatusForbidden, "请求来源校验失败，请从本站页面重试")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// sameOrigin 比对 Origin 头与请求 Host（只比 scheme+host，端口含在 host 里）。
func sameOrigin(r *http.Request) bool {
	raw := r.Header.Get("Origin")
	if raw == "" {
		return true
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		// "null"（sandbox iframe / file://）与乱串一律不当同源
		return false
	}
	return strings.EqualFold(u.Host, r.Host)
}

// auditRoute 在**老端点**的路由层补一条审计。
//
// 为什么在路由层而不是业务层：logout / 找回密码 / 注销 / 踢设备这几个老方法的
// 签名里不带来源（IP/UA 只在请求上），而「谁在哪儿动的」正是审计的主键信息。
// 新方法（登录、改密、凭据操作）都自带 Caller/meta，审计在业务层里记。
//
// 无会话身份的端点（找回密码）传 c=nil，用 withEmail 补一个**已掩码**的邮箱。
func auditRoute(svc *auth.Service, action string, c *auth.Caller, r *http.Request,
	detail map[string]string, err error, opts ...func(*auth.AuditEvent)) {
	ev := auth.AuditEvent{Action: action, OK: err == nil, Meta: sessMeta(r), Detail: detail}
	if c != nil {
		uid := c.UID
		ev.ActorUID = &uid
		ev.ActorEmail = auth.MaskEmail(c.Email)
	}
	for _, opt := range opts {
		opt(&ev)
	}
	svc.Audit(ev)
}

// withEmail 给匿名审计事件补一个已掩码的 actor 邮箱。
func withEmail(email string) func(*auth.AuditEvent) {
	return func(ev *auth.AuditEvent) { ev.ActorEmail = email }
}

// pathInt64 解析路径里的雪花 id；非法回 400（这类 id 只有服务端发过）。
func pathInt64(w http.ResponseWriter, raw string) (int64, bool) {
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || id <= 0 {
		writeError(w, http.StatusBadRequest, "参数不正确")
		return 0, false
	}
	return id, true
}
