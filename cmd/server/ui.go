package main

import (
	"log/slog"
	"net/http"
	"os"

	"github.com/WXies-Team/auth/internal/auth"
	"github.com/WXies-Team/auth/internal/ui"
)

// 页面路由：服务端先做**登录态门禁**再渲染壳——没登录直接 302 去登录页，
// 管理页非管理员 302 回概览。这样首屏不会先闪一帧「空控制台」再跳走。
// 页面里的数据由 JS 调 /web/session 等端点现取（响应 no-store，不落中间层缓存）。
type pageGate int

const (
	gatePublic pageGate = iota // 登录页：已登录就别再看登录页
	gateAuth                   // 自助台：未登录跳登录页
	gateAdmin                  // 管理后台：未登录跳登录页，非管理员跳概览
)

// registerPageRoutes 挂全部页面壳（规格 B2 的页面清单）。
func registerPageRoutes(mux *http.ServeMux, svc *auth.Service) {
	type pageDef struct {
		path  string
		name  string
		title string
		nav   []ui.NavItem
		gate  pageGate
	}
	defs := []pageDef{
		{"/web/login", "login", "登录", nil, gatePublic},
		{"/web/console", "console", "概览", ui.ConsoleNav("console"), gateAuth},
		{"/web/console/sessions", "sessions", "登录会话", ui.ConsoleNav("sessions"), gateAuth},
		{"/web/console/passkeys", "passkeys", "Passkey", ui.ConsoleNav("passkeys"), gateAuth},
		{"/web/console/security", "security", "两步验证", ui.ConsoleNav("security"), gateAuth},
		{"/web/console/account", "account", "账号", ui.ConsoleNav("account"), gateAuth},
		{"/web/admin", "admin-users", "用户管理", ui.AdminNav("admin-users"), gateAdmin},
		{"/web/admin/sessions", "admin-sessions", "会话总览", ui.AdminNav("admin-sessions"), gateAdmin},
		{"/web/admin/audit", "admin-audit", "审计日志", ui.AdminNav("admin-audit"), gateAdmin},
		{"/web/admin/config", "admin-config", "配置中心", ui.AdminNav("admin-config"), gateAdmin},
		{"/web/admin/ai-usage", "admin-ai", "AI 用量", ui.AdminNav("admin-ai-usage"), gateAdmin},
	}
	for _, d := range defs {
		if !ui.Has(d.name) {
			// 模板缺了要在启动时炸，别等用户点开 500
			slog.Error("页面模板缺失", "name", d.name)
			os.Exit(1)
		}
		mux.Handle("GET "+d.path, pageHandler(svc, d.name, d.title, d.nav, d.gate))
	}

	// /web 根：有会话进控制台，没有进登录页；/web/ 子树的未匹配路径也归到这里
	mux.Handle("GET /web", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if webSessionOK(svc, r) {
			http.Redirect(w, r, "/web/console", http.StatusFound)
			return
		}
		http.Redirect(w, r, "/web/login", http.StatusFound)
	}))
	mux.Handle("GET /web/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/web", http.StatusFound)
	}))
}

// registerStaticRoutes 挂静态资产（favicon 三件套）与根路径重定向。
//
// 三个文件都随二进制内嵌（internal/ui 的 embed），不依赖磁盘布局：部署产物就一个
// 二进制。Cache-Control 7 天——指纹图标极低频改动，换图属于发版动作，客户端晚几天
// 拿到无伤；no-store 反而会让每次进站都多一次往返。
//
// `/` 现状是 404（真实入口都在 /web 与 /auth），按定案 302 到登录页：浏览器手敲
// 域名不该撞一堵墙。**只匹配根路径本身**（`/{$}` 精确匹配），不做全站兜底——
// 打错的 API 路径仍要 404，不能被 302 成 HTML 把排障带偏。
func registerStaticRoutes(mux *http.ServeMux) {
	for _, name := range ui.StaticNames() {
		mux.Handle("GET /"+name, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			data, ctype, ok := ui.Static(name)
			if !ok {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", ctype)
			w.Header().Set("Cache-Control", "public, max-age=604800")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			_, _ = w.Write(data)
		}))
	}
	mux.Handle("GET /{$}", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/web/login", http.StatusFound)
	}))
}

// webSessionOK 只判「cookie 会话现在是否有效」（页面门禁用，不需要 Caller 细节）。
func webSessionOK(svc *auth.Service, r *http.Request) bool {
	ck, err := r.Cookie(auth.WebCookieName)
	if err != nil || ck.Value == "" {
		return false
	}
	_, err = svc.ValidWebSession(ck.Value)
	return err == nil
}

// pageHandler 渲染一个页面：按 gate 决定放行还是 302。
func pageHandler(svc *auth.Service, name, title string, nav []ui.NavItem, gate pageGate) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var (
			ok    bool
			wc    auth.WebCaller
			haveC bool
			email string
			admin bool
		)
		if ck, err := r.Cookie(auth.WebCookieName); err == nil && ck.Value != "" {
			if c, err := svc.ValidWebSession(ck.Value); err == nil {
				ok, wc, haveC = true, c, true
			}
		}
		if haveC {
			email, admin = wc.Email, ui.IsAdminRole(wc.Role)
		}
		switch gate {
		case gatePublic:
			if ok {
				http.Redirect(w, r, "/web/console", http.StatusFound)
				return
			}
		case gateAuth:
			if !ok {
				http.Redirect(w, r, "/web/login", http.StatusFound)
				return
			}
		case gateAdmin:
			if !ok {
				http.Redirect(w, r, "/web/login", http.StatusFound)
				return
			}
			// 角色在会话解析时已现查（ValidWebSession 取 users.role），非管理员
			// 连管理页的 HTML 都拿不到——数据层另有 requireAdmin 逐请求再挡一道
			if haveC && wc.Role != "admin" {
				http.Redirect(w, r, "/web/console", http.StatusFound)
				return
			}
		}
		// 顶栏账号胶囊与「管理后台」入口的渲染依据：邮箱取自现查过的会话身份，
		// 管理入口按 users.role 判定（ui.IsAdminRole 与后台闸同一口径）——
		// 非管理员的 HTML 里根本没有这个按钮，不是前端藏一下。
		if err := ui.Render(w, name, ui.Data{
			Title: title, Nav: nav, Minimal: gate == gatePublic,
			Email: email, IsAdmin: admin,
		}); err != nil {
			// 头多半已经写出（Execute 中途失败），只能记日志让 500 兜底
			slog.Error("渲染页面失败", "page", name, "err", err)
		}
	})
}
