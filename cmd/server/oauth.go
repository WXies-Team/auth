package main

import (
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/WXies-Team/auth/internal/auth"
	"github.com/WXies-Team/auth/internal/ui"
)

// OAuth 跳转授权的 HTTP 层（B4）：
//
//	GET  /oauth/authorize          授权入口：fail-fast 校验 → 未登录托管登录页（tx 续跑）→ 已登录轻确认
//	GET  /oauth/resume?tx=…        登录后续跑（app.js finishLogin 按 ?tx= 跳这里）
//	POST /oauth/authorize/confirm  确认页表单提交（继续/取消同表单，decision 分流）
//	POST /oauth/token              授权码换 JWT（应用后端调，form 或 JSON）
//
// 分层口径同全仓：判定在 internal/auth，这里只做「请求 → 参数 → 调用 → 回执」与
// cookie/重定向这类传输层的事。

// registerOAuthRoutes 挂四个端点。限流口径：authorize/resume/confirm 走 unauthed
// 15/分/IP（limitN 同名桶），token 端点单独一桶 15/分/IP。
// confirm 是纯 HTML 表单 POST（无 JS、设不了 X-CSRF-Token）：走 originGuard +
// SameSite=Strict cookie 双闸——跨站表单根本不带 cookie，Origin 不同源再挡一道
//（与登录端点同款守卫组合，不进 withUID 的 CSRF 头闸）。
func registerOAuthRoutes(mux *http.ServeMux, svc *auth.Service) {
	const scope = "oauth-authorize"
	mux.Handle("GET /oauth/authorize", withLogging(limitN(scope, 15,
		http.HandlerFunc(oauthAuthorize(svc)))))
	mux.Handle("GET /oauth/resume", withLogging(limitN(scope, 15,
		http.HandlerFunc(oauthResume(svc)))))
	mux.Handle("POST /oauth/authorize/confirm", withLogging(originGuard(limitN(scope, 15,
		http.HandlerFunc(oauthConfirm(svc))))))
	mux.Handle("POST /oauth/token", withLogging(limitN("oauth-token", 15,
		http.HandlerFunc(oauthToken(svc)))))
}

// oauthWebCaller 直接用会话 cookie 换身份（**不经 withUID**：授权页是表单流，
// 与 /web/delete-cancel 同款「cookie 即凭证」口径；CSRF 由 SameSite=Strict +
// originGuard 兜）。无效/缺失回 (zero,false)。
func oauthWebCaller(svc *auth.Service, r *http.Request) (auth.WebCaller, bool) {
	ck, err := r.Cookie(auth.WebCookieName)
	if err != nil || ck.Value == "" {
		return auth.WebCaller{}, false
	}
	wc, werr := svc.ValidWebSession(ck.Value)
	return wc, werr == nil
}

// oauthAuthorize 是 GET /oauth/authorize：fail-fast 校验（client 登记 / redirect
// 精确匹配 / PKCE S256 / state）在业务层；过了验：
//
//	无 web 会话 → 302 /web/login?tx=…（授权事务已在内存，登录成功后按 tx 续跑；
//	               tx 只含已验参数，站内固定路径，无开放重定向面）；
//	有会话     → 渲染轻确认页（always 显示，不静默）。
func oauthAuthorize(svc *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		tx, _, err := svc.OAuthBeginAuthorize(auth.OAuthAuthorizeRequest{
			ResponseType:        q.Get("response_type"),
			ClientID:            q.Get("client_id"),
			RedirectURI:         q.Get("redirect_uri"),
			State:               q.Get("state"),
			CodeChallenge:       q.Get("code_challenge"),
			CodeChallengeMethod: q.Get("code_challenge_method"),
		})
		if err != nil {
			renderOAuthError(w, err, "无法发起授权")
			return
		}
		if wc, ok := oauthWebCaller(svc, r); ok {
			renderOAuthConfirm(svc, w, tx, wc.UID)
			return
		}
		http.Redirect(w, r, "/web/login?tx="+url.QueryEscape(tx), http.StatusFound)
	}
}

// oauthResume 是 GET /oauth/resume?tx=…：app.js finishLogin 在登录（含强制改密
// 完成、2FA 第二步、Passkey）后按 ?tx= 跳到这里续跑原授权。未登录（会话已过期）
// 再推回登录页带着同一个 tx；tx 过期/不存在回错误页（不回跳——redirect 参数还没
// 经过确认页那道用户可见的核对）。
func oauthResume(svc *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tx := r.URL.Query().Get("tx")
		wc, ok := oauthWebCaller(svc, r)
		if !ok {
			if strings.TrimSpace(tx) == "" {
				http.Redirect(w, r, "/web/login", http.StatusFound)
				return
			}
			http.Redirect(w, r, "/web/login?tx="+url.QueryEscape(tx), http.StatusFound)
			return
		}
		renderOAuthConfirm(svc, w, tx, wc.UID)
	}
}

// oauthConfirm 是确认页的表单 POST：decision=allow → 发码回跳；deny →
// error=access_denied 回跳。两者都消耗一次性 tx；表单重放/跨账号回放统一
// 400 错误页（业务层校验 tx 存活与 uid 绑定）。
func oauthConfirm(svc *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 表单体只有 tx + decision 两个字段，8KB 上限足够（与 token 端点同款防膨口径）
		r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
		if err := r.ParseForm(); err != nil {
			writeOAuthErr(w, http.StatusBadRequest, "invalid_request", "请求格式不正确，请从授权页重试")
			return
		}
		tx := r.PostFormValue("tx")
		decision := r.PostFormValue("decision")
		wc, ok := oauthWebCaller(svc, r)
		if !ok {
			http.Redirect(w, r, "/web/login?tx="+url.QueryEscape(tx), http.StatusFound)
			return
		}
		redirect, err := svc.OAuthDecide(wc.UID, tx, decision, webSessMeta(r))
		if err != nil {
			renderOAuthError(w, err, "无法完成授权")
			return
		}
		http.Redirect(w, r, redirect, http.StatusFound)
	}
}

// oauthToken 是 POST /oauth/token（RFC 6749 §4.1.3 + PKCE）。请求体收两种形态：
// 标准 form（application/x-www-form-urlencoded）与 JSON——两个日记服务的后端
// 调用方用哪个顺手用哪个。失败统一 OAuth 形状 {error,error_description}。
func oauthToken(svc *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req auth.OAuthTokenRequest
		if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
			if !decodeOr400(w, r, &req) {
				return
			}
		} else {
			// 与 JSON 支路同款 64KB 上限：ParseForm 默认放到 10MB，认证端点不该给
			r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
			if err := r.ParseForm(); err != nil {
				writeOAuthErr(w, http.StatusBadRequest, "invalid_request", "请求格式不正确，请用表单或 JSON 提交")
				return
			}
			req = auth.OAuthTokenRequest{
				GrantType:    r.PostFormValue("grant_type"),
				Code:         r.PostFormValue("code"),
				RedirectURI:  r.PostFormValue("redirect_uri"),
				ClientID:     r.PostFormValue("client_id"),
				ClientSecret: r.PostFormValue("client_secret"),
				CodeVerifier: r.PostFormValue("code_verifier"),
			}
		}
		res, err := svc.OAuthExchangeToken(req)
		if err != nil {
			var oe *auth.OAuthError
			if errors.As(err, &oe) {
				writeOAuthErr(w, oe.Status, oe.Code, oe.Description)
				return
			}
			// 内部错误（DB 抖动等）：根因进日志，对外只回中性 server_error
			slog.Error("oauth token exchange failed", "err", err, "cause", err.Error())
			writeOAuthErr(w, http.StatusInternalServerError, "server_error", "服务出了点问题，请稍后重试")
			return
		}
		writeJSON(w, http.StatusOK, res)
	}
}

// writeOAuthErr 是 OAuth 端点的统一失败回执（§5.2 形状）。
func writeOAuthErr(w http.ResponseWriter, status int, code, description string) {
	writeJSON(w, status, map[string]string{"error": code, "error_description": description})
}

// renderOAuthConfirm 渲染轻确认页：业务层取项目名/回跳域名/账号邮箱并做
// deny 复查，这里只搬运到模板。失败按错误页兜（错误页与确认页同一张卡片语言）。
func renderOAuthConfirm(svc *auth.Service, w http.ResponseWriter, tx string, uid int64) {
	view, err := svc.OAuthAuthorizeView(tx, uid)
	if err != nil {
		renderOAuthError(w, err, "无法继续授权")
		return
	}
	if err := ui.Render(w, "authorize", ui.Data{
		Title: "授权登录", Minimal: true,
		OAuth: &ui.OAuthView{
			Tx: view.Tx, App: view.App, AppName: view.AppName,
			RedirectHost: view.RedirectHost, Email: view.Email,
		},
	}); err != nil {
		slog.Error("渲染授权页失败", "err", err)
	}
}

// renderOAuthError 渲染授权错误页（友好中文、错误=出错+下一步、站内模板与动效）。
// 状态码取业务 HTTPError 的原值（403 封禁/白名单、400 参数错），兜底 400。
func renderOAuthError(w http.ResponseWriter, err error, title string) {
	status := http.StatusBadRequest
	var he *auth.HTTPError
	if errors.As(err, &he) {
		status = he.Code
	}
	if rerr := ui.Render(w, "authorize", ui.Data{
		Title: title, Minimal: true, Status: status,
		OAuth: &ui.OAuthView{ErrorTitle: title, ErrorMessage: errText(err)},
	}); rerr != nil {
		slog.Error("渲染授权错误页失败", "err", rerr)
	}
}
