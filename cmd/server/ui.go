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
//
// W2 分级授权在页面层的三道收口（与 /admin/* 数据端点同源判定）：
//   - gateSuper 页（用户/角色/配置）app-admin 直接 302 去会话总览——入口不渲染
//     是模板层的事，直接敲 URL 也进不来；
//   - 后台导航按角色分叉（super 六项 / app-admin 三项），非 super 的 HTML 里
//     没有 users/roles/config 的入口；
//   - 数据三页的 ?app= 越权直接 403 页（友好文案），不让越权过滤器落到 JS 层
//     才报错。
type pageGate int

const (
	gatePublic pageGate = iota // 登录页：已登录就别再看登录页
	gateAuth                   // 自助台：未登录跳登录页
	gateAdmin                  // 管理后台：未登录跳登录页，非管理员跳概览
	gateSuper                  // 平台级页（用户/角色/配置）：app-admin 跳会话总览
)

// scopedPages 是读 ?app= 过滤的数据页：渲染前先验 app 参数与该管理员的授权，
// 越权渲染 403 页（不进 JS）。
var scopedPages = map[string]bool{
	"admin-sessions": true,
	"admin-audit":    true,
	"admin-ai":       true,
}

// registerPageRoutes 挂全部页面壳（规格 B2 的页面清单）。
func registerPageRoutes(mux *http.ServeMux, svc *auth.Service) {
	type pageDef struct {
		path  string
		name  string
		title string
		gate  pageGate
	}
	defs := []pageDef{
		{"/web/login", "login", "登录", gatePublic},
		{"/web/console", "console", "概览", gateAuth},
		{"/web/console/sessions", "sessions", "登录会话", gateAuth},
		{"/web/console/passkeys", "passkeys", "Passkey", gateAuth},
		{"/web/console/security", "security", "两步验证", gateAuth},
		{"/web/console/account", "account", "账号", gateAuth},
		{"/web/admin", "admin-users", "用户管理", gateSuper},
		{"/web/admin/roles", "admin-roles", "角色管理", gateSuper},
		{"/web/admin/sessions", "admin-sessions", "会话总览", gateAdmin},
		{"/web/admin/audit", "admin-audit", "审计日志", gateAdmin},
		{"/web/admin/config", "admin-config", "配置中心", gateSuper},
		{"/web/admin/ai-usage", "admin-ai", "AI 用量", gateAdmin},
	}
	for _, d := range defs {
		if !ui.Has(d.name) {
			// 模板缺了要在启动时炸，别等用户点开 500
			slog.Error("页面模板缺失", "name", d.name)
			os.Exit(1)
		}
		mux.Handle("GET "+d.path, pageHandler(svc, d.name, d.title, d.gate))
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

// pageHandler 渲染一个页面：按 gate 决定放行还是 302，再按角色装配导航与
// 项目切换器（W2）。adminScopes/adminRole 每次渲染现查——页面壳本身也带着
// 授权语义（切换器选项、super 专属入口），缓存它等于缓存撤销。
func pageHandler(svc *auth.Service, name, title string, gate pageGate) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var (
			ok    bool
			wc    auth.WebCaller
			haveC bool
			email string
		)
		if ck, err := r.Cookie(auth.WebCookieName); err == nil && ck.Value != "" {
			if c, err := svc.ValidWebSession(ck.Value); err == nil {
				ok, wc, haveC = true, c, true
			}
		}
		if haveC {
			email = wc.Email
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
		case gateAdmin, gateSuper:
			if !ok {
				http.Redirect(w, r, "/web/login", http.StatusFound)
				return
			}
			// 角色在会话解析时已现查（ValidWebSession 取 users.role），非管理员
			// 连管理页的 HTML 都拿不到——数据层另有 admin 闸逐请求再挡一道
			if !ui.IsAdminRole(wc.Role) {
				http.Redirect(w, r, "/web/console", http.StatusFound)
				return
			}
		}

		// ---- 后台页的 W2 装配：role/scopes → 导航、切换器、?app= 校验 ----
		// isSuper 无条件算（概览页的顶栏入口指向也靠它：super 指用户页，app-admin
		// 指会话总览）；scopes/nav/切换器只有后台页需要。
		isSuper := haveC && auth.IsSuperRole(wc.Role)
		var (
			scopes []string
			nav    []ui.NavItem
			apps   []ui.AppChoice
			curApp string
		)
		if gate == gateAdmin || gate == gateSuper {
			if !isSuper {
				var err error
				if scopes, err = svc.AdminScopes(wc.UID); err != nil {
					slog.Error("查应用授权失败", "uid", wc.UID, "err", err)
					http.Error(w, "服务暂时不可用，请稍后重试", http.StatusServiceUnavailable)
					return
				}
			}
			// gateSuper 页对 app-admin 关门：直接敲 URL 也 302 去会话总览
			if gate == gateSuper && !isSuper {
				http.Redirect(w, r, "/web/admin/sessions", http.StatusFound)
				return
			}
			// 数据三页的 ?app= 在渲染前定罪：名单外或未授权直接 403 页
			curApp = r.URL.Query().Get("app")
			if scopedPages[name] && curApp != "" {
				if (!isSuper && !containsStrGo(scopes, curApp)) || (isSuper && !auth.AppAllowed(curApp)) {
					renderDenied(w, curApp)
					return
				}
			}
			nav = ui.AdminNav(name, isSuper)
			apps = ui.SwitchApps(isSuper, scopes, curApp)
		} else {
			nav = ui.ConsoleNav(name)
		}

		// 顶栏账号胶囊与「管理后台」入口的渲染依据：邮箱取自现查过的会话身份，
		// 管理入口按 users.role 判定（ui.IsAdminRole 与后台闸同一口径）——
		// 非管理员的 HTML 里根本没有这个按钮，不是前端藏一下。
		if err := ui.Render(w, name, ui.Data{
			Title: title, Nav: nav, Minimal: gate == gatePublic,
			Email: email, IsAdmin: haveC && ui.IsAdminRole(wc.Role),
			IsSuper: isSuper, Apps: apps, CurrentApp: curApp,
		}); err != nil {
			// 头多半已经写出（Execute 中途失败），只能记日志让 500 兜底
			slog.Error("渲染页面失败", "page", name, "err", err)
		}
	})
}

// containsStrGo 是 []string 的线性查找（cmd 层的小工具，与业务层的同名函数各归各家）。
func containsStrGo(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

// renderDenied 渲染 ?app= 越权的 403 页（友好文案 + 回会话总览的出路）。
// 文案点名是「应用范围」问题，避免被误读成登录态失效。
func renderDenied(w http.ResponseWriter, app string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	if err := ui.Render(w, "denied", ui.Data{
		Title: "无权访问", Minimal: true, DeniedApp: app,
	}); err != nil {
		slog.Error("渲染 403 页失败", "err", err)
	}
}
