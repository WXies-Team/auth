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
	"math"
	"net/http"
	"sort"
	"strconv"
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
	// UID 是当前登录者的用户 id（W3 头像底色派生用）：avatarColor 未设（0/越界）时
	// 按 uid%8 从同一 8 色色板派生，与 app.js avatarHex 同式。仅登录态页面有值。
	UID int64
	// B5 资料三件套（顶栏头像/昵称升级的渲染数据）：Nickname 空 = 未设置（顶栏回退
	// 邮箱前缀）；AvatarImage 非空 = 档案头像 base64（无 data: 前缀，与两 App 存储
	// 格式同源）；AvatarColor 是色板下标（AvatarPalette 同序，0 回退首位）。
	Nickname    string
	AvatarColor int
	AvatarImage string
	// AcctName 是顶栏账号胶囊的显示名：昵称优先，无昵称回退邮箱前缀（@ 前）。
	// Render 里派生，页面层不用填。
	AcctName string
	// AvatarColorHex / AvatarInkHex / AvatarSrc 是 Render 派生的渲染成品：色块底色
	// hex、**首字墨色**（avatarInkFor 按底色亮度挑的黑/白墨——顶栏不再写死白墨，
	// 白墨对 8 色色板只有 1.92~4.49:1，全线低于 4.5:1 正文线）、头像图的 data URL
	//（空 = 无图走色块回退）。AvatarSrc 用 template.URL 是因为 html/template 会把
	// data: URL 刷成 #ZgotmplZ——内容是服务端拼的 base64（validateProfile 只收标准
	// 字母表），无注入面。
	AvatarColorHex string
	AvatarInkHex   string
	AvatarSrc      template.URL
	IsAdmin        bool
	IsSuper        bool
	// InAdmin = 本页在管理后台区内：顶栏入口此时应显示「返回控制台」而不是
	// 「管理后台」（pageHandler 按 gate 传入）。
	InAdmin bool
	Apps    []AppChoice // 非空 = 顶栏渲染项目切换器（只有消费 ?app= 的数据页给值）
	// CurrentApp 是 ?app= 的当前取值（切换器高亮 + 数据页过滤器），空 = 全部/默认
	CurrentApp string
	// DeniedApp 是 403 页上点名的越权应用（denied 模板用，其余页面忽略）
	DeniedApp string
	// OAuth 是授权页（authorize 模板）的渲染上下文：确认态带项目/回跳域名/事务号，
	// 错误态带标题与下一步文案（同一张卡片语言，cmd/server/oauth.go 填）。
	OAuth *OAuthView
	// Invite 是接受邀请页（invite 模板）的渲染上下文（cmd/server 的
	// GET/POST /web/invite 填）：Token 原样回填表单隐藏域（它就是凭证，URL 里已有），
	// ErrorTitle 非空 = 同模板的错误变体（token 无效/过期/已用，400 起头），
	// Error 非空 = 表单下方的就地报错（提交被业务打回时连表单一起重渲染）。
	Invite *InviteView
	// Status 非零时以该状态码起头（授权错误页要 400/403；0 = 200）
	Status int
	// AppsJSON 是服务端 knownApps 注册表的 JSON（template.JS 直出进
	// <script type="application/json">），前端 appLabel/应用授权开关从它取
	// 清单——app 清单只此一份（Go 侧 knownApps），JS 不再硬编码。
	AppsJSON template.JS
	// PaletteJSON 是头像色板的 JSON（B5 账号资料卡的色块 chips 从它取色，
	// 与 Go avatarPalette / 两 App AvatarPalette 同一份值）。
	PaletteJSON template.JS
	Style       template.CSS
	Script      template.JS
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

// brandFiles 是 /brand/ 下的品牌 logo 资产（scripts/genicons 生成、随二进制内嵌）：
// 文件名 → 内容。init 里现读 embed 目录登记，缺品牌资产就在启动时炸。
var brandFiles = map[string][]byte{}

// brandContentType 按扩展名给 /brand/ 资产定 Content-Type（清单式，不猜）。
func brandContentType(name string) string {
	switch {
	case strings.HasSuffix(name, ".png"):
		return "image/png"
	case strings.HasSuffix(name, ".svg"):
		return "image/svg+xml; charset=utf-8"
	default:
		return "application/octet-stream"
	}
}

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

	// 品牌邮件 logo（/brand/<slug>-v1.png + 矢量源 <slug>.svg）：邮件以绝对 URL 引用
	// （见 internal/auth 的 brand.logoURL），这里登记成可挂载的静态资产。
	brandEntries, berr := files.ReadDir("static/brand")
	if berr != nil {
		panic(fmt.Errorf("列品牌 logo: %w", berr))
	}
	for _, e := range brandEntries {
		if e.IsDir() {
			continue
		}
		data, err := files.ReadFile("static/brand/" + e.Name())
		if err != nil {
			panic(fmt.Errorf("读品牌 logo %s: %w", e.Name(), err))
		}
		brandFiles[e.Name()] = data
	}
	if len(brandFiles) == 0 {
		panic("ui: static/brand/ 下没有品牌 logo——先跑 go run ./scripts/genicons")
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

// OAuthView 是授权页（authorize.html）的渲染上下文（cmd/server/oauth.go 填）：
// Tx 是一次性授权事务号（确认表单回传）；ErrorTitle 非空 = 同模板的错误页变体。
// AppName/RedirectHost/Email 都是服务端已验过的值（模板自动转义）。
type OAuthView struct {
	Tx           string
	App          string
	AppName      string
	RedirectHost string
	Email        string
	ErrorTitle   string
	ErrorMessage string
}

// InviteView 是接受邀请页（invite 模板）的渲染上下文（cmd/server 的
// GET/POST /web/invite 填）：与 authorize 同一套「同模板双变体」做法——
// ErrorTitle 非空 = 错误变体整卡替换（token 无效/过期/已用），否则渲染表单，
// Error 只做表单下方的就地报错（提交被业务打回后连表单一起重渲染）。
type InviteView struct {
	Token        string
	Email        string
	App          string
	AppName      string // App 的展示名（空 = 账号级邀请，文案不点名项目）
	Error        string
	ErrorTitle   string
	ErrorMessage string
}

// AppLabel 返回项目 slug 的展示名（invite 页文案用）：未知 slug 回原串，'' 回 ""。
// 展示名唯一来源是 knownApps 注册表——与序列化进页面的 AppsJSON 同一份值。
func AppLabel(key string) string {
	for _, a := range knownApps {
		if a.key == key {
			return a.label
		}
	}
	return key
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

// avatarPalette 是头像色板（B5，与两个日记 App 的 AvatarPalette.kt **逐值同序**：
// #5B8DEF #7C6AF2 #E2556B #FF8A3D #2BB673 #14A8A0 #E6B422 #8B7355）。档案里的
// avatarColor 存的是这里的下标，0（或越界）回退首位——与 App 侧 colorAt 同口径。
var avatarPalette = []string{
	"#5B8DEF", "#7C6AF2", "#E2556B", "#FF8A3D",
	"#2BB673", "#14A8A0", "#E6B422", "#8B7355",
}

// AvatarPaletteHex 返回色板下标对应的 hex（越界回退首位，与 App 的 colorAt 一致）。
func AvatarPaletteHex(index int) string {
	if index < 0 || index >= len(avatarPalette) {
		return avatarPalette[0]
	}
	return avatarPalette[index]
}

// AvatarPaletteHexFor 是 W3 的**展示色派生**（顶栏账号胶囊用）：显式设过的色
//（index>0）原样用；未设（0 = 从未写过档案，或越界）按 uid%8 从同一 8 色色板
// 派生——没有自定义头像的用户也是彩色首字，而不是全员一个色。0 与「未设」不可
// 分（user_profile.avatarColor 默认 0），口径与 app.js avatarHex 同式镜像，
// TestAvatarDeriveByUID 钉住两侧口径的 Go 半边。
func AvatarPaletteHexFor(uid int64, index int) string {
	if index > 0 && index < len(avatarPalette) {
		return avatarPalette[index]
	}
	if uid > 0 {
		return avatarPalette[int(uid%int64(len(avatarPalette)))]
	}
	return avatarPalette[0]
}

// PaletteJSON 把色板序列化成 JSON 数组——前端色板 chips 与首字回退从这里取色，
// 色值不进 JS 硬编码（与 knownApps 同一「服务端唯一清单」口径）。
func PaletteJSON() template.JS {
	b, err := json.Marshal(avatarPalette)
	if err != nil {
		panic(fmt.Errorf("序列化头像色板: %w", err))
	}
	return template.JS(b) //nolint:gosec // 自有静态色值，无用户输入
}

// avatarInkFor 给固定底色挑**首字墨色**：按 WCAG 相对亮度取白墨/黑墨里对比更高
// 的那一支（与两个日记 App 的 AvatarPalette.inkFor 同规则，参考其取色审计注释——
// 不用 0.5 亮度阈值：阈值会把 #E6B422 判成「深色」给白墨，实测仅 1.92:1）。
//
// 色板 8 色实测对比度（白墨 / 黑墨，2026-10-21 头像取色审计）：
//
//	#5B8DEF 3.23/6.50 · #7C6AF2 4.04/5.20 · #E2556B 3.66/5.75 · #FF8A3D 2.35/8.95
//	#2BB673 2.61/8.04 · #14A8A0 2.94/7.14 · #E6B422 1.92/10.92 · #8B7355 4.49/4.68
//
// 白墨全数低于 4.5:1 正文线（其中 4 色连 3:1 大字线都不过），黑墨全数 ≥4.5——
// 本色板实际全取黑墨，但规则按亮度自选（换色板仍成立）。TestAvatarInkContrast
// 钉住「每色 ≥4.5:1」；app.js avatarInk 是同式镜像（JS 侧无单测，改规则请同 PR 同步）。
func avatarInkFor(bg string) string {
	l, ok := hexLuminance(bg)
	if !ok {
		// 走不到（底色只来自常量色板）；兜底黑墨 = 8 色里全部 ≥4.5:1 的那一支
		return "#000000"
	}
	if white := 1.05 / (l + 0.05); white >= (l+0.05)/0.05 {
		return "#ffffff"
	}
	return "#000000"
}

// hexLuminance 解 #RRGGBB 的 WCAG 相对亮度：sRGB 通道线性化（≤0.04045 走除 12.92，
// 否则 (c+0.055)/1.055 的 2.4 次方）后按 0.2126/0.7152/0.0722 加权。
func hexLuminance(hex string) (float64, bool) {
	if len(hex) != 7 || hex[0] != '#' {
		return 0, false
	}
	n, err := strconv.ParseUint(hex[1:], 16, 32)
	if err != nil {
		return 0, false
	}
	lin := func(c uint8) float64 {
		f := float64(c) / 255
		if f <= 0.04045 {
			return f / 12.92
		}
		return math.Pow((f+0.055)/1.055, 2.4)
	}
	return 0.2126*lin(uint8(n>>16)) + 0.7152*lin(uint8(n>>8)) + 0.0722*lin(uint8(n)), true
}

// initialOf 取邮箱首字符做账号胶囊的头像占位字（无档案头像时的兜底）；
// 空邮箱（登录页等 Minimal 壳）回空串，模板里就不渲染这颗字母。
func initialOf(email string) string {
	for _, r := range strings.TrimSpace(email) {
		return strings.ToUpper(string(r))
	}
	return ""
}

// initialFor 是 B5 的首字回退链：昵称首字符优先，无昵称退邮箱首字符
//（与前端 avatarInitial 同一逻辑，两处口径都钉在各自测试里）。
func initialFor(nickname, email string) string {
	if s := strings.TrimSpace(nickname); s != "" {
		for _, r := range s {
			return strings.ToUpper(string(r))
		}
	}
	return initialOf(email)
}

// emailPrefix 是邮箱 @ 前的本地名（顶栏无昵称时的显示名回退）。
func emailPrefix(email string) string {
	local, _, ok := strings.Cut(strings.TrimSpace(email), "@")
	if !ok {
		return strings.TrimSpace(email)
	}
	return local
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

// BrandStatic 取一份品牌 logo 资产（/brand/ 下的文件名）的内容与 Content-Type；
// 名单外回 ("", "", false)。文件名带 -v1 版本段：换图 = 新文件名 + 新 brand.logoPath，
// 旧 URL 恒可用（immutable 缓存的前提）。
func BrandStatic(name string) ([]byte, string, bool) {
	data, ok := brandFiles[name]
	if !ok {
		return nil, "", false
	}
	return data, brandContentType(name), true
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
	if data.PaletteJSON == "" {
		data.PaletteJSON = PaletteJSON()
	}
	// B5 顶栏账号胶囊的派生数据：显示名（昵称 > 邮箱前缀）、首字（昵称首字符 >
	// 邮箱首字符）、色块底色、头像图 data URL（有图则顶栏用图，无图走色块+首字）
	if data.AcctName == "" {
		if n := strings.TrimSpace(data.Nickname); n != "" {
			data.AcctName = n
		} else {
			data.AcctName = emailPrefix(data.Email)
		}
	}
	if data.Initial == "" {
		data.Initial = initialFor(data.Nickname, data.Email)
	}
	data.AvatarColorHex = AvatarPaletteHexFor(data.UID, data.AvatarColor) // W3：未设色按 uid 派生
	data.AvatarInkHex = avatarInkFor(data.AvatarColorHex) // 首字墨色与底色成对注入
	if img := strings.TrimSpace(data.AvatarImage); img != "" {
		data.AvatarSrc = template.URL("data:image/jpeg;base64," + img) //nolint:gosec // 内容是服务端校验过的标准 base64（validateProfile 只收该字母表），无注入面
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "same-origin")
	// UA Client Hints 采集的 opt-in（页面响应是唯一收口：登录页/授权页/邀请页
	// 全走 Render，浏览器见到后才在本站后续请求自动带上高熵的 Sec-CH-UA-Model，
	// 登录建会话时把机型并进设备名——见 internal/auth.SessionMeta/uaWithCH）。
	// Platform 是低熵提示（默认就带），列在这里一并声明；Firefox/Safari 不支持
	// Client Hints，头照收不误，取不到就回退 UA 解析（零回归）。
	w.Header().Set("Accept-CH", "Sec-CH-UA-Platform, Sec-CH-UA-Model")
	// Status 非零 = 以该状态码起头（必须在 Execute 写体之前，晚了头就作废）
	if data.Status != 0 {
		w.WriteHeader(data.Status)
	}
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

// AdminNav 是后台入口（key 与页面名对应），按角色分叉（W2/W4）：
//
//	super     用户 / 项目访问 / 会话总览 / 审计日志 / 配置中心 / AI 用量 六项；
//	app-admin 项目访问 / 会话总览 / 审计日志 / AI 用量 四项（已按 scope 过滤的数据页
//	          ——项目访问页它也只拿到自己授权的项目；用户目录、配置是平台级功能，
//	          入口在它的 HTML 里根本不出现）。
//（原「角色管理」页已并入用户页：详情面板内直接改角色与应用授权。）
func AdminNav(active string, isSuper bool) []NavItem {
	if isSuper {
		return []NavItem{
			{Href: "/web/admin", Label: "用户", Icon: "users", Active: active == "admin-users"},
			{Href: "/web/admin/access", Label: "项目访问", Icon: "lock", Active: active == "admin-access"},
			{Href: "/web/admin/sessions", Label: "会话总览", Icon: "monitor", Active: active == "admin-sessions"},
			{Href: "/web/admin/audit", Label: "审计日志", Icon: "scroll-text", Active: active == "admin-audit"},
			{Href: "/web/admin/config", Label: "配置中心", Icon: "sliders-horizontal", Active: active == "admin-config"},
			{Href: "/web/admin/ai-usage", Label: "AI 用量", Icon: "chart-column", Active: active == "admin-ai"},
		}
	}
	return []NavItem{
		{Href: "/web/admin/access", Label: "项目访问", Icon: "lock", Active: active == "admin-access"},
		{Href: "/web/admin/sessions", Label: "会话总览", Icon: "monitor", Active: active == "admin-sessions"},
		{Href: "/web/admin/audit", Label: "审计日志", Icon: "scroll-text", Active: active == "admin-audit"},
		{Href: "/web/admin/ai-usage", Label: "AI 用量", Icon: "chart-column", Active: active == "admin-ai"},
	}
}
