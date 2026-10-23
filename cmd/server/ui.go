package main

import (
	"net/http"

	"github.com/WXies-Team/auth/internal/auth"
	"github.com/WXies-Team/auth/internal/ui"
)

// 页面路由：Kotlin/Wasm SPA（web/ 工程）。服务端仍做**登录态与角色门禁**再下发
// 壳——没登录 302 去登录页、非管理员 302 回概览，首屏不会先闪一帧空壳再跳走。
// 页面里的数据由 SPA 调 JSON API 现取（响应 no-store，不落中间层缓存）。
//
// 门禁只挡「壳」；数据层另有 admin 闸逐请求现查角色与授权（W2 的三道收口
// 在数据端点侧照旧成立，页面层不再渲染 403 页——SPA 直接展示 API 的错误文案）。
type pageGate int

const (
	gatePublic pageGate = iota // 登录页：已登录就别再看登录页
	gateAuth                   // 自助台：未登录跳登录页
	gateAdmin                  // 管理后台：未登录跳登录页，非管理员跳概览
	gateSuper                  // 平台级页（用户/配置）：app-admin 跳会话总览
)

// registerPageRoutes 挂全部页面壳。title 是各路由的固定常量（SPAIndex 直拼，
// 无用户输入）。
func registerPageRoutes(mux *http.ServeMux, svc *auth.Service) {
	defs := []struct {
		path  string
		title string
		gate  pageGate
	}{
		{"/web/login", "登录", gatePublic},
		{"/web/console", "概览", gateAuth},
		{"/web/console/sessions", "登录会话", gateAuth},
		{"/web/console/passkeys", "Passkey", gateAuth},
		{"/web/console/security", "两步验证", gateAuth},
		{"/web/console/account", "账号", gateAuth},
		{"/web/admin", "用户", gateSuper},
		{"/web/admin/access", "项目访问", gateAdmin},
		{"/web/admin/sessions", "会话总览", gateAdmin},
		{"/web/admin/audit", "审计日志", gateAdmin},
		{"/web/admin/config", "配置中心", gateSuper},
		{"/web/admin/ai-usage", "AI 用量", gateAdmin},
	}
	for _, d := range defs {
		mux.Handle("GET "+d.path, spaHandler(svc, d.title, d.gate))
	}

	// 接受邀请页（公开页）：token 即凭证，壳直接下发、验证与表单都在 SPA 里做。
	// 限流 unauthed 15/分/IP（与 POST 共用 web-invite 桶）。
	mux.Handle("GET /web/invite", withLogging(limitN("web-invite", 15,
		spaHandler(svc, "接受邀请", gateNone))))

	// 项目注册表 JSON（SPA 的 slug→展示名唯一出口）。公开只读：展示名不是秘密
	//（邀请页/邮件同款对外）；回执走 writeJSON（no-store）。
	mux.Handle("GET /web/registry", withLogging(limitN("web-registry", 30,
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusOK, ui.Registry())
		}))))

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

// gateNone：无门禁的公开壳（接受邀请页——token 即凭证，登录态没有需要保护的语义）。
const gateNone = pageGate(99)

// spaHandler 按 gate 过门禁后下发 SPA 壳（no-store + UA Client Hints opt-in）。
func spaHandler(svc *auth.Service, title string, gate pageGate) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var (
			ok    bool
			wc    auth.WebCaller
			haveC bool
		)
		if ck, err := r.Cookie(auth.WebCookieName); err == nil && ck.Value != "" {
			if c, err := svc.ValidWebSession(ck.Value); err == nil {
				ok, wc, haveC = true, c, true
			}
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
			// 连管理壳都拿不到——数据层另有 admin 闸逐请求再挡一道
			if !haveC || !auth.IsAdminRole(wc.Role) {
				http.Redirect(w, r, "/web/console", http.StatusFound)
				return
			}
			if gate == gateSuper && !auth.IsSuperRole(wc.Role) {
				http.Redirect(w, r, "/web/admin/sessions", http.StatusFound)
				return
			}
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Accept-CH", ui.ClientHintsHeader)
		_, _ = w.Write([]byte(ui.SPAIndex(title)))
	})
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

// registerStaticRoutes 挂静态资产（favicon 三件套 + 品牌 logo）与根路径重定向。
//
// 三个 favicon 与全部品牌 logo 都随二进制内嵌（internal/ui 的 embed），不依赖磁盘
// 布局：部署产物就一个二进制。favicon Cache-Control 7 天——品牌图标极低频改动，
// 换图属于发版动作，客户端晚几天拿到无伤；no-store 反而会让每次进站都多一次往返。
// 品牌 logo 走 **immutable 长缓存**：文件名自带版本段（<slug>-v1.png），换图 =
// 新文件名，旧 URL 永不改内容。
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
	mux.Handle("GET /brand/{name}", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, ctype, ok := ui.BrandStatic(r.PathValue("name"))
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", ctype)
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		_, _ = w.Write(data)
	}))
	mux.Handle("GET /{$}", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/web/login", http.StatusFound)
	}))
}

// registerWasmRoutes 挂 Kotlin/Wasm 前端产物（/wasm/*，全部内嵌进二进制）。
// authweb.js no-cache（内容常换、名字不变）；其余是内容哈希名，immutable 长缓存。
func registerWasmRoutes(mux *http.ServeMux) {
	mux.Handle("GET /wasm/{name...}", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, ctype, cache, ok := ui.WasmAsset(r.PathValue("name"))
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", ctype)
		w.Header().Set("Cache-Control", cache)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		_, _ = w.Write(data)
	}))
}
