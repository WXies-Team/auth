// Package ui 是 Web 管理台的页面层：html/template + 内嵌 CSS/JS，**零外链**
//（无 CDN、无字体外链、图标是内联 SVG——见 icons.go 的 ISC 出处）。
//
// 分层口径：页面只负责「长什么样、点了调哪个端点」；鉴权与业务判定全在
// cmd/server 的路由层与 internal/auth。模板按页加载（layout + 该页），
// 后解析的 define 覆盖先解析的空壳，于是每页都能有自己的 content/style/js。
package ui

import (
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"sort"
	"strings"
)

//go:embed templates/*.html style.css app.js static/*
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
//
// Email/Initial/IsAdmin 是**顶栏账号胶囊与管理入口**的渲染依据：由路由层从
// 现查过的会话身份（users.role）带进来，模板层据此决定「管理后台」按钮出不出现——
// 非管理员的 HTML 里就没有这个按钮，而不是前端 display:none 藏一下。
//
// IsSuper/Apps/CurrentApp 是 W2 项目切换器的渲染依据（同样来自现查的
// role/admin_scopes）：super 见「全部」+ 两 app，app-admin 只见自己授权的 app。
type Data struct {
	Title   string
	Nav     []NavItem
	Minimal bool // 登录页这类无导航的壳
	Email   string
	Initial string // 账号胶囊头像占位首字母（无档案头像时的兜底）
	IsAdmin bool
	IsSuper bool
	// InAdmin = 本页在管理后台区内：顶栏入口此时应显示「返回控制台」而不是
	// 「管理后台」（pageHandler 按 gate 传入）。
	InAdmin bool
	Apps    []AppChoice // 非空 = 顶栏渲染项目切换器（只有消费 ?app= 的数据页给值）
	// CurrentApp 是 ?app= 的当前取值（切换器高亮 + 数据页过滤器），空 = 全部/默认
	CurrentApp string
	// DeniedApp 是 403 页上点名的越权应用（denied 模板用，其余页面忽略）
	DeniedApp string
	// AppsJSON 是服务端 knownApps 注册表的 JSON（template.JS 直出进
	// <script type="application/json">），前端 appLabel/应用授权开关从它取
	// 清单——app 清单只此一份（Go 侧 knownApps），JS 不再硬编码。
	AppsJSON template.JS
	Style    template.CSS
	Script   template.JS
}

var (
	pages    = map[string]*template.Template{}
	styleCSS template.CSS
	appJS    template.JS
)

// staticTypes 是站点静态资产清单（favicon 三件套，由 scripts/genicons 生成）：
// 文件名 → Content-Type。路由层按这份清单逐个挂 `GET /<name>`，清单改这里即可。
var staticTypes = map[string]string{
	"favicon.ico":          "image/x-icon",
	"favicon.svg":          "image/svg+xml; charset=utf-8",
	"apple-touch-icon.png": "image/png",
}

var staticFiles = map[string][]byte{}

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

	// 静态资产随二进制一起打包（零外链口径）：缺一个就在启动时炸
	for name := range staticTypes {
		data, err := files.ReadFile("static/" + name)
		if err != nil {
			panic(fmt.Errorf("读静态资产 %s: %w", name, err))
		}
		staticFiles[name] = data
	}

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

// IsAdminRole 判定「顶栏要不要渲染管理后台入口」。口径与 cmd/server 后台闸
// （role ∈ {admin, super}，每请求现查 users 行）同源：模板层放行的按钮，数据层
// 一定挡得住——auth.IsAdminRole 与本函数是同一值域的两份最小实现（ui 不 import
// auth 保叶子包，两侧各自被测试钉住：TestIsAdminRole 与 auth 侧的角色用例）。
func IsAdminRole(role string) bool { return role == "admin" || role == "super" }

// IsSuperRole 判定平台管理员（super 专属页与「全部」切换项的渲染依据）。
func IsSuperRole(role string) bool { return role == "super" }

// AppChoice 是项目切换器的一项：Key 是 ?app= 的取值（空串 = 全部），
// Label 是展示名，Active 是当前选中。
type AppChoice struct {
	Key    string
	Label  string
	Active bool
}

// knownApps 是项目切换器/应用授权开关的展示名（与 auth.allowedApps 同源的两 app；
// 新应用加这里 + allowedApps 两处）。定序即展示序。前端不存第二份清单——
// Render 把它序列化成 JSON 注进页面（Data.AppsJSON），JS 从那里读。
var knownApps = []struct{ key, label string }{
	{"calorie-diary", "热量日记"},
	{"expense-diary", "开支日记"},
}

// knownAppsJSON 把注册表序列化成 [{key,label},...]——模板/JS 唯一的 app 清单来源。
func knownAppsJSON() template.JS {
	type entry struct {
		Key   string `json:"key"`
		Label string `json:"label"`
	}
	out := make([]entry, 0, len(knownApps))
	for _, a := range knownApps {
		out = append(out, entry{Key: a.key, Label: a.label})
	}
	b, err := json.Marshal(out)
	if err != nil {
		panic(fmt.Errorf("序列化应用注册表: %w", err))
	}
	return template.JS(b) //nolint:gosec // 自有静态数据，无用户输入
}

// SwitchApps 生成项目切换器的选项：
//
//	super     「全部」+ 两 app（currentApp 空 = 「全部」高亮）；
//	app-admin 只回自己授权的 app（无「全部」项——scope 是硬边界，「全部」对它
//	          没有语义）；currentApp 不在其内时不高亮任何项（页面层已把越权
//	          ?app= 挡成 403，走到这里只剩空串的默认态）。
func SwitchApps(super bool, scopes []string, currentApp string) []AppChoice {
	if super {
		out := make([]AppChoice, 0, len(knownApps)+1)
		out = append(out, AppChoice{Key: "", Label: "全部", Active: currentApp == ""})
		for _, a := range knownApps {
			out = append(out, AppChoice{Key: a.key, Label: a.label, Active: currentApp == a.key})
		}
		return out
	}
	out := make([]AppChoice, 0, len(scopes))
	for _, s := range scopes {
		label := s
		for _, a := range knownApps {
			if a.key == s {
				label = a.label
				break
			}
		}
		out = append(out, AppChoice{Key: s, Label: label, Active: currentApp == s})
	}
	return out
}

// initialOf 取邮箱首字符做账号胶囊的头像占位字（无档案头像时的兜底）；
// 空邮箱（登录页等 Minimal 壳）回空串，模板里就不渲染这颗字母。
func initialOf(email string) string {
	for _, r := range strings.TrimSpace(email) {
		return strings.ToUpper(string(r))
	}
	return ""
}

// StaticNames 列出可挂载的静态资产文件名（定序），路由层据此逐个挂 `GET /<name>`。
func StaticNames() []string {
	names := make([]string, 0, len(staticTypes))
	for name := range staticTypes {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Static 取一份静态资产的内容与 Content-Type；名单外回 ("", "", false)。
func Static(name string) ([]byte, string, bool) {
	ctype, ok := staticTypes[name]
	if !ok {
		return nil, "", false
	}
	return staticFiles[name], ctype, true
}

// Render 渲染一个页面。响应一律 no-store：页面本身会内嵌登录态相关的骨架，
// 让中间层缓存住带状态的 HTML 是给自己找麻烦。
func Render(w http.ResponseWriter, name string, data Data) error {
	t, ok := pages[name]
	if !ok {
		return fmt.Errorf("页面模板不存在: %s", name)
	}
	data.Style, data.Script = styleCSS, appJS
	if data.AppsJSON == "" {
		data.AppsJSON = knownAppsJSON()
	}
	if data.Initial == "" {
		data.Initial = initialOf(data.Email)
	}
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
		{Href: "/web/console/sessions", Label: "登录会话", Icon: "monitor-smartphone", Active: active == "sessions"},
		{Href: "/web/console/passkeys", Label: "Passkey", Icon: "key-round", Active: active == "passkeys"},
		{Href: "/web/console/security", Label: "两步验证", Icon: "shield-check", Active: active == "security"},
		{Href: "/web/console/account", Label: "账号", Icon: "settings", Active: active == "account"},
	}
}

// AdminNav 是后台入口（key 与页面名对应），按角色分叉（W2）：
//
//	super     用户 / 会话总览 / 审计日志 / 配置中心 / AI 用量 五项；
//	app-admin 只有会话总览 / 审计日志 / AI 用量 三项（已按 scope 过滤的数据页）——
//	          用户目录、配置是平台级功能，入口在它的 HTML 里根本不出现。
//（原「角色管理」页已并入用户页：详情面板内直接改角色与应用授权。）
func AdminNav(active string, isSuper bool) []NavItem {
	if isSuper {
		return []NavItem{
			{Href: "/web/admin", Label: "用户", Icon: "users", Active: active == "admin-users"},
			{Href: "/web/admin/sessions", Label: "会话总览", Icon: "monitor", Active: active == "admin-sessions"},
			{Href: "/web/admin/audit", Label: "审计日志", Icon: "scroll-text", Active: active == "admin-audit"},
			{Href: "/web/admin/config", Label: "配置中心", Icon: "sliders-horizontal", Active: active == "admin-config"},
			{Href: "/web/admin/ai-usage", Label: "AI 用量", Icon: "chart-column", Active: active == "admin-ai"},
		}
	}
	return []NavItem{
		{Href: "/web/admin/sessions", Label: "会话总览", Icon: "monitor", Active: active == "admin-sessions"},
		{Href: "/web/admin/audit", Label: "审计日志", Icon: "scroll-text", Active: active == "admin-audit"},
		{Href: "/web/admin/ai-usage", Label: "AI 用量", Icon: "chart-column", Active: active == "admin-ai-usage"},
	}
}
