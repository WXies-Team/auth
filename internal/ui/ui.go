// Package ui 是 Web 管理台的页面层：html/template + 内嵌 CSS/JS，**零外链**
//（无 CDN、无字体外链、图标是内联 SVG——见 icons.go 的 ISC 出处）。
//
// 分层口径：页面只负责「长什么样、点了调哪个端点」；鉴权与业务判定全在
// cmd/server 的路由层与 internal/auth。模板按页加载（layout + 该页），
// 后解析的 define 覆盖先解析的空壳，于是每页都能有自己的 content/style/js。
package ui

import (
	"embed"
	"fmt"
	"html/template"
	"net/http"
	"strings"
)

//go:embed templates/*.html style.css app.js
var files embed.FS

// NavItem 是顶部导航的一条。
type NavItem struct {
	Href   string
	Label  string
	Icon   string
	Active bool
}

// Data 是页面渲染上下文。Style/Script 在 Render 里注入（内联进 HTML，
// 不额外产生请求），页面模板里不用关心。
type Data struct {
	Title   string
	Nav     []NavItem
	Minimal bool // 登录页这类无导航的壳
	Style   template.CSS
	Script  template.JS
}

var (
	pages    = map[string]*template.Template{}
	styleCSS template.CSS
	appJS    template.JS
)

func init() {
	css, err := files.ReadFile("style.css")
	if err != nil {
		panic(fmt.Errorf("读内联样式: %w", err))
	}
	styleCSS = template.CSS(string(css)) //nolint:gosec // 静态自有资源，内容可信
	js, err := files.ReadFile("app.js")
	if err != nil {
		panic(fmt.Errorf("读内联脚本: %w", err))
	}
	appJS = template.JS(string(js)) //nolint:gosec // 静态自有资源，内容可信

	layout, err := files.ReadFile("templates/layout.html")
	if err != nil {
		panic(fmt.Errorf("读页面骨架: %w", err))
	}
	entries, err := files.ReadDir("templates")
	if err != nil {
		panic(fmt.Errorf("列页面模板: %w", err))
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".html") || e.Name() == "layout.html" {
			continue
		}
		name := strings.TrimSuffix(e.Name(), ".html")
		page, err := files.ReadFile("templates/" + e.Name())
		if err != nil {
			panic(fmt.Errorf("读页面模板 %s: %w", e.Name(), err))
		}
		// 骨架先解析（其中的空 style/js define 是默认值），页面后解析覆盖——
		// 同名 define 后者生效，页面不写 style/js 也成立。
		t, err := template.New(name).Funcs(template.FuncMap{"icon": iconHTML}).Parse(string(layout) + "\n" + string(page))
		if err != nil {
			panic(fmt.Errorf("解析页面 %s: %w", name, err))
		}
		pages[name] = t
	}
}

// Has 判断某个页面模板是否存在（路由层登记时用，少一处拼错名字的机会）。
func Has(name string) bool {
	_, ok := pages[name]
	return ok
}

// Render 渲染一个页面。响应一律 no-store：页面本身会内嵌登录态相关的骨架，
// 让中间层缓存住带状态的 HTML 是给自己找麻烦。
func Render(w http.ResponseWriter, name string, data Data) error {
	t, ok := pages[name]
	if !ok {
		return fmt.Errorf("页面模板不存在: %s", name)
	}
	data.Style, data.Script = styleCSS, appJS
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "same-origin")
	return t.Execute(w, data)
}

// iconHTML 把清单里的图标套上统一外壳：同 viewBox、同线宽、currentColor 取色，
// aria-hidden 让读屏跳过装饰性图形（按钮的文字标签才是给读屏的）。
func iconHTML(name string) template.HTML {
	body, ok := icons[name]
	if !ok {
		return template.HTML("") //nolint:gosec // 常量名单的查表结果
	}
	return template.HTML(`<svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" ` + //nolint:gosec
		`stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">` +
		body + `</svg>`)
}

// ConsoleNav 是自助台五个入口；active 传当前页 key（空则无高亮）。
func ConsoleNav(active string) []NavItem {
	return []NavItem{
		{Href: "/web/console", Label: "概览", Icon: "layout-dashboard", Active: active == "console"},
		{Href: "/web/console/sessions", Label: "已登录设备", Icon: "monitor-smartphone", Active: active == "sessions"},
		{Href: "/web/console/passkeys", Label: "Passkey", Icon: "key-round", Active: active == "passkeys"},
		{Href: "/web/console/security", Label: "两步验证", Icon: "shield-check", Active: active == "security"},
		{Href: "/web/console/account", Label: "账号", Icon: "settings", Active: active == "account"},
	}
}

// AdminNav 是后台五个入口（key 与页面名对应）。
func AdminNav(active string) []NavItem {
	return []NavItem{
		{Href: "/web/admin", Label: "用户", Icon: "users", Active: active == "admin-users"},
		{Href: "/web/admin/sessions", Label: "会话总览", Icon: "monitor", Active: active == "admin-sessions"},
		{Href: "/web/admin/audit", Label: "审计日志", Icon: "scroll-text", Active: active == "admin-audit"},
		{Href: "/web/admin/config", Label: "配置中心", Icon: "sliders-horizontal", Active: active == "admin-config"},
		{Href: "/web/admin/ai-usage", Label: "AI 用量", Icon: "chart-column", Active: active == "admin-ai-usage"},
	}
}
