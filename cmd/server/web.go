package main

import (
	"encoding/json"
	"errors"
	"html"
	"io"
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
	// reauthed：在 authed 之上再要一道 2 小时内的强认证（ASVS V7.5.1）。
	// 401 + 固定文案，前端据此弹「重新验证」框后调 /web/reauth；成功的**写**操作
	// 顺带滑动续期 reauth_at（slideReauth 的 sudo mode 语义；GET 读操作不续期，W7-1）。
	reauthed := func(scope string, max int, h func(c auth.WebCaller, w http.ResponseWriter, r *http.Request)) http.Handler {
		return authed(scope, max, func(c auth.WebCaller, w http.ResponseWriter, r *http.Request) {
			if err := svc.RequireReauth(c.SID); err != nil {
				writeResult(w, nil, err)
				return
			}
			slideReauth(svc, c.SID, r.Method, w, func(w http.ResponseWriter) { h(c, w, r) })
		})
	}
	// ---- 登录（无登录态，只有 Origin 同源校验：此时没有可搭的 cookie 顺风车）----
	mux.Handle("POST /web/login/password", withLogging(originGuard(limitN("web-login", 15,
		jsonBody[protocol.WebLoginRequest](func(req *protocol.WebLoginRequest, w http.ResponseWriter, r *http.Request) {
			res, err := svc.WebLoginPassword(req.Email, req.Password, webSessMeta(r), req.App)
			if err != nil {
				writeResult(w, nil, err)
				return
			}
			writeLoginResult(svc, w, res)
		})))))
	mux.Handle("POST /web/login/email-code", withLogging(originGuard(limitN("web-login-code", 15,
		jsonBody[protocol.WebLoginCodeRequest](func(req *protocol.WebLoginCodeRequest, w http.ResponseWriter, r *http.Request) {
			res, err := svc.WebLoginEmailCode(req.Email, req.Code, webSessMeta(r))
			if err != nil {
				writeResult(w, nil, err)
				return
			}
			writeLoginResult(svc, w, res)
		})))))
	mux.Handle("POST /web/login/totp", withLogging(originGuard(limitN("web-login-totp", 15,
		jsonBody[protocol.WebLoginTOTPRequest](func(req *protocol.WebLoginTOTPRequest, w http.ResponseWriter, r *http.Request) {
			res, err := svc.WebLoginTOTP(req.LoginToken, req.Code, req.RecoveryCode, req.EmailCode, webSessMeta(r))
			if err != nil {
				writeResult(w, nil, err)
				return
			}
			writeLoginResult(svc, w, res)
		})))))

	// ---- 注销撤销页（W3）：**不挂 withUID**——已登出的用户也要能撤（申请注销时
	// 全部会话已被吊销），撤销 token 即凭证、不可猜。GET 渲染确认页 / 友好错误页，
	// POST 提交；两路各吃 IP 10/分 限流。页面 HTML 内嵌在本文件（不进
	// internal/ui 的模板集——那批文件由并行批次维护，且这页无需登录壳）。
	mux.Handle("GET /web/delete-cancel", withLogging(limitN("delete-cancel", 10,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := r.URL.Query().Get("token")
			if err := svc.CheckDeleteCancel(token); err != nil {
				writeDeleteCancelPage(w, token, false, errText(err))
				return
			}
			writeDeleteCancelPage(w, token, true, "")
		}))))
	mux.Handle("POST /web/delete-cancel", withLogging(limitN("delete-cancel", 10,
		jsonBody[deleteCancelRequest](func(req *deleteCancelRequest, w http.ResponseWriter, _ *http.Request) {
			if err := svc.CancelDelete(req.Token); err != nil {
				writeResult(w, nil, err)
				return
			}
			writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
		}))))

	// ---- 接受邀请（B9）：纯 HTML 表单 POST（零 JS，invite.html 直接 method=post）。
	// 与登录/OAuth 确认同款守卫组合——无登录态可搭 withUID 的 CSRF 头闸，靠
	// originGuard（跨站表单必带 Origin，不同源即 403）+ SameSite=Strict 双闸兜底；
	// 限流 unauthed 15/分/IP（与 GET 同一 web-invite 桶）。成功 = 建号 + 种 web
	// cookie 302 回控制台（AcceptInvite 内已建会话并单次消费邀请）。
	mux.Handle("POST /web/invite", withLogging(originGuard(limitN("web-invite", 15,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// 表单只有 token/password/nickname 三个字段，8KB 上限足够
			//（与 OAuth confirm 同款防膨口径：不给匿名端点塞 10MB 默认值的机会）
			r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
			if err := r.ParseForm(); err != nil {
				renderInviteError(w, "请求格式不正确，请从邀请邮件重新打开")
				return
			}
			token, password := r.PostFormValue("token"), r.PostFormValue("password")
			res, err := svc.AcceptInvite(token, password, r.PostFormValue("nickname"), webSessMeta(r))
			if err != nil {
				// 业务打回就地重渲染：token 仍有效（密码不合规）→ 表单 + 字段下报错；
				// token 已失效 → 同模板错误变体（renderInvitePage 内部分流）
				renderInvitePage(svc, w, token, errText(err))
				return
			}
			setWebCookies(w, res.Session)
			http.Redirect(w, r, "/web/console", http.StatusFound)
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
			// 密码 / 两步验证码 / 恢复码三选一的分流在业务层（Reauth），与安全页的
			//「一框二选一」同一套格式判定
			if err := svc.Reauth(c.Caller, req.Password, req.TOTPCode, req.RecoveryCode); err != nil {
				writeResult(w, nil, err)
				return
			}
			writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
		}))
	// 重新验证的 Passkey 路（弹框「Passkey / 两步验证码二选一」里的前者）：与
	// POST /web/reauth 同为 authed——不是 reauthed，这两支正是要刷新 reauth 窗的
	// 本体。额度与密码/验证码路同档：选项 30/min/uid、回执 10/min/uid。
	mux.Handle("POST /web/reauth/webauthn/options", authed("reauth-passkey-options", 30,
		func(c auth.WebCaller, w http.ResponseWriter, _ *http.Request) {
			assertion, id, err := svc.BeginPasskeyReauth(c.Caller)
			if err != nil {
				writeResult(w, nil, err)
				return
			}
			writeJSON(w, http.StatusOK, ceremonyResponse{PublicKey: assertion.Response, CeremonyID: id})
		}))
	mux.Handle("POST /web/reauth/webauthn/finish", authed("reauth-passkey-finish", 10, jsonAuthedWrapper(
		func(c auth.WebCaller, req *protocol.PasskeyFinishRequest, w http.ResponseWriter, _ *http.Request) {
			body, ok := credentialJSON(w, req.Response)
			if !ok {
				return
			}
			// 仪式绑 uid + 凭证属主验签 + MarkReauth + 审计都在业务层
			//（FinishPasskeyReauth）；路由层只做参数与 response 形态归一。
			if err := svc.FinishPasskeyReauth(c.Caller, req.CeremonyID, body); err != nil {
				writeResult(w, nil, err)
				return
			}
			writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
		})))
	mux.Handle("POST /web/logout", authed("web-logout", 10,
		func(c auth.WebCaller, w http.ResponseWriter, _ *http.Request) {
			// 只吊销本行（web 会话），不动 token_version：同账号的其它设备照常用。
			// 自行登出不受会话作用域限制（踢的就是手上这把凭据指向的行）。
			err := svc.RevokeSession(c.UID, c.SID, nil)
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
			body, ok := credentialJSON(w, req.Response)
			if !ok {
				return
			}
			info, err := svc.FinishPasskeyRegistration(c.Caller, req.CeremonyID, body, sessMeta(r))
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
			body, ok := credentialJSON(w, req.Response)
			if !ok {
				return
			}
			// 建会话、签 JWT / 记凭证、审计都在业务层（WebPasskeyLogin）：
			// 路由层只负责「请求 → 参数 → 回执」与 response 形态的归一。
			res, err := svc.WebPasskeyLogin(req.CeremonyID, body, req.App, webSessMeta(r))
			if err != nil {
				writeResult(w, nil, err)
				return
			}
			writeLoginResult(svc, w, res)
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

// writeLoginResult 分流登录回执，两支的回体都是 {token,email}（AuthResponse 同形，
// C 批零新解析）：还差第二步 → {status,loginToken,methods}；web 流程 → 签双 cookie，
// **回体 token 恒空串**（凭据只在 HttpOnly cookie 里，回给脚本一个能直连双凭据
// 路由的会话 token 等于把 CSRF 闸拆了——internal/ui/app.js 全程不读 body token）；
// App 流程 → 回 JWT 且**一枚 cookie 都不发**（调用方是原生 App，没有 cookie 可用，
// 也就没有 cookie 会话的 CSRF 闸要吃）。
func writeLoginResult(svc *auth.Service, w http.ResponseWriter, res *auth.WebLoginResult) {
	if res.Session == nil && res.JWT == "" {
		// 中间态回执两支同形：app 不在这里，服务端已随 login_states 带到第二步
		writeJSON(w, http.StatusOK, protocol.WebLoginPending{
			Status: res.Status, LoginToken: res.LoginToken, Methods: res.Methods,
		})
		return
	}
	// 契约 4：完成步的回执带两个账号态位（无 omitempty，bool 默认值也要显式出现）
	if res.App != "" {
		writeJSON(w, http.StatusOK, protocol.AuthResponse{
			Token: res.JWT, Email: res.Email,
			MustChangePassword:     res.MustChangePassword,
			DeletePendingCancelled: res.DeletePendingCancelled,
		})
		return
	}
	setWebCookies(w, res.Session)
	writeJSON(w, http.StatusOK, protocol.AuthResponse{
		Token: "", Email: res.Email,
		MustChangePassword:     res.MustChangePassword,
		DeletePendingCancelled: res.DeletePendingCancelled,
	})
}

// deleteCancelRequest 是 POST /web/delete-cancel 的请求体（W3 撤销提交）。
type deleteCancelRequest struct {
	Token string `json:"token"`
}

// errText 把业务错误翻成页面可展示的一句话：HTTPError 取自带文案，其余一律中性
// 503 白话（根因进 writeResult 的服务端日志，这里不复述）。
func errText(err error) string {
	var he *auth.HTTPError
	if errors.As(err, &he) {
		return he.Message
	}
	return "服务暂时不可用，请稍后重试"
}

// writeDeleteCancelPage 渲染注销撤销页（W3）：ok=true 是确认页（按钮 → POST →
// 成功后展示结果 + 登录入口），否则是友好错误页（400 + 一句可执行的下一步）。
// HTML/CSS/JS 全内嵌：这页没有登录态、不进 internal/ui 的模板集（那批文件由
// 并行批次维护），也不依赖任何外链资源。
func writeDeleteCancelPage(w http.ResponseWriter, token string, ok bool, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	const head = `<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>注销确认</title>
<style>
:root { color-scheme: light dark; }
body { margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center;
       background:#f7f7f7; color:#000; font-family:MiSans,-apple-system,"HarmonyOS Sans SC","PingFang SC","Noto Sans CJK SC","Microsoft YaHei",sans-serif; }
.card { background:#fff; border-radius:24px; padding:32px 32px 28px; width:100%; max-width:440px; margin:16px;
        box-shadow:0 8px 32px rgba(0,0,0,.06); }
h1 { font-size:20px; font-weight:400; margin:0 0 12px; }
p  { font-size:15px; line-height:1.7; margin:0 0 10px; color:#333; }
.warn { color:#e94634; }
.btn { display:block; width:100%; margin-top:20px; padding:13px 0; border:0; border-radius:16px;
       background:#3482ff; color:#fff; font-size:16px; cursor:pointer; }
.btn:disabled { opacity:.6; cursor:default; }
.link { display:inline-block; margin-top:14px; color:#3482ff; text-decoration:none; font-size:15px; }
.err { color:#e94634; font-size:14px; margin-top:10px; }
.hidden { display:none; }
@media (prefers-color-scheme: dark) {
  body { background:#000; color:#e6ffffff; }
  .card { background:#242424; box-shadow:none; }
  p { color:#b4b4b4; }
}
</style></head><body><div class="card">`
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		msg := html.EscapeString(message)
		_, _ = io.WriteString(w, head+`<h1>无法撤销注销</h1>
<p>`+msg+`</p>
<a class="link" href="/web/login">前往登录</a>
</div></body></html>`)
		return
	}
	tokJSON, err := json.Marshal(token)
	if err != nil {
		tokJSON = []byte(`""`)
	}
	_, _ = io.WriteString(w, head+`<div id="main">
<h1>注销确认</h1>
<p>你正在撤销此前提交的注销申请。撤销后账号与数据一切如常，随时可以重新登录。</p>
<p class="warn">如果不是你本人操作，请撤销后立即修改密码并检查登录设备。</p>
<button class="btn" id="go">撤销注销</button>
<p class="err hidden" id="err"></p>
</div>
<div class="hidden" id="done">
<h1>注销已撤销</h1>
<p>你的注销申请已撤销，账号与数据一切如常。</p>
<a class="link" href="/web/login">前往登录</a>
</div>
<script>
const TOKEN = ` + string(tokJSON) + `;
const go = document.getElementById('go');
go.addEventListener('click', async () => {
  go.disabled = true; go.textContent = '处理中…';
  const errEl = document.getElementById('err');
  try {
    const res = await fetch('/web/delete-cancel', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({token: TOKEN})
    });
    const data = await res.json().catch(() => ({}));
    if (res.ok) {
      document.getElementById('main').classList.add('hidden');
      document.getElementById('done').classList.remove('hidden');
      return;
    }
    errEl.textContent = data.message || '撤销失败，请稍后重试';
  } catch (e) {
    errEl.textContent = '网络异常，请稍后重试';
  }
  errEl.classList.remove('hidden');
  go.disabled = false; go.textContent = '撤销注销';
});
</script>
</div></body></html>`)
}

// credentialJSON 把 response 归一成库要的 PublicKeyCredential **对象字节**，
// 两种已上线的形态都收：
//
//	网页端（internal/ui/app.js）传 JSON 对象 → 原样透传，web 路的字节一个不变；
//	日记 App 传 Credential Manager 的 authenticationResponseJson → 那是 JSON **字符串**
//	（WebAuthDtos.kt 的 response: String），解一层再交库——不解的话库拿到带引号的
//	字符串，解析直接 400，App 的 passkey 登录/注册全废。
//
// 解不动回 400「请求格式不正确，请检查后重试」（与 decodeOr400 同一句），不留到库那层变 500。
func credentialJSON(w http.ResponseWriter, raw json.RawMessage) ([]byte, bool) {
	if len(raw) == 0 {
		writeError(w, http.StatusBadRequest, "请求格式不正确，请检查后重试")
		return nil, false
	}
	if raw[0] != '"' {
		return raw, true
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil || len(s) == 0 {
		writeError(w, http.StatusBadRequest, "请求格式不正确，请检查后重试")
		return nil, false
	}
	return []byte(s), true
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

// statusWriter 记下 handler 实际写出的第一笔状态码（writeJSON 一律显式 WriteHeader，
// 200/4xx/5xx 由此可判；嵌入 ResponseWriter，本包 handler 不用 Flusher/Hijacker）。
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

// slideReauth 执行一个受 reauth 闸保护的敏感操作，**成功回执（<400）落笔后**把本
// 会话 reauth_at 刷到现在：2 小时强认证窗的滑动续期（GitHub sudo mode 口径——
// 「两次提示之间为 2 小时，期间任何敏感操作都会重置计时器」）。
//
// **W7-1：GET/HEAD/OPTIONS 读操作不续期**——读列表不该给强认证窗续命（滑动只属于
// 真正动了状态的写操作）；失败（≥400 / 没写出状态）同样不刷：刷了等于给爆破者续命。
func slideReauth(svc *auth.Service, sid int64, method string, w http.ResponseWriter, run func(http.ResponseWriter)) {
	if readMethod(method) {
		run(w)
		return
	}
	sw := &statusWriter{ResponseWriter: w}
	run(sw)
	if sw.status >= 200 && sw.status < 400 {
		_ = svc.MarkReauth(sid)
	}
}

// reauthThen 给**敏感写操作**补 2 小时强认证窗，但只对凭 cookie 进来的会话生效。
//
// 为什么区别对待：规格 A1.2 要求改密码/改邮箱前近期认证过，而这几个端点同时
// 也是老客户端在用的——已发布的日记 App 没有 /web/reauth、也不该被这道新闸
// 挡死（老客户端零破坏是硬约束）。Bearer 侧照旧只靠「原密码 / 验证码」本身，
// cookie 侧则必须 reauth ≤2 小时，前端 401 后会自动弹框重试。
//
// 过闸且成功的操作经 slideReauth 滑动续期；Bearer 调用没吃这道闸，也就不刷——
// 续期只属于「被强认证窗放行」的操作。
func reauthThen(svc *auth.Service, h func(auth.Caller, http.ResponseWriter, *http.Request)) func(auth.Caller, http.ResponseWriter, *http.Request) {
	return func(c auth.Caller, w http.ResponseWriter, r *http.Request) {
		if wc, ok := r.Context().Value(webCallerKey).(auth.WebCaller); ok && wc.ViaCookie {
			if err := svc.RequireReauth(wc.SID); err != nil {
				writeResult(w, nil, err)
				return
			}
			slideReauth(svc, wc.SID, r.Method, w, func(w http.ResponseWriter) { h(c, w, r) })
			return
		}
		h(c, w, r)
	}
}

// pathInt64 解析路径里的数字 id（uid 与会话/凭证等内部行 id 都走它）；
// 非法回 400（这类 id 只有服务端发过）。
func pathInt64(w http.ResponseWriter, raw string) (int64, bool) {
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || id <= 0 {
		writeError(w, http.StatusBadRequest, "参数不正确，请检查 id 后重试")
		return 0, false
	}
	return id, true
}
