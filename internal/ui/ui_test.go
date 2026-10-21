package ui

import (
	"regexp"
	"strings"
	"testing"
)

// 所有页面共用 layout 骨架：<head> 必须带三件套 link 与 theme-color，
// 顶栏品牌区挂 favicon.svg（透明底 + #3482FF 裸蓝 hexagon，与站点 favicon 同源）。
func TestLayoutHeadHasIconLinks(t *testing.T) {
	raw, err := files.ReadFile("templates/layout.html")
	if err != nil {
		t.Fatalf("读页面骨架: %v", err)
	}
	head := string(raw)
	for _, want := range []string{
		`<link rel="icon" href="/favicon.svg" type="image/svg+xml">`,
		`<link rel="icon" href="/favicon.ico" sizes="48x48">`,
		`<link rel="apple-touch-icon" href="/apple-touch-icon.png">`,
		`<meta name="theme-color" content="#3482FF">`,
		`<img src="/favicon.svg" alt="" width="28" height="28">`,
		`name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover"`,
	} {
		if !strings.Contains(head, want) {
			t.Errorf("layout <head> 缺 %s", want)
		}
	}
	// 装饰性图片 alt 必须为空串：紧随其后的品牌名文字才是给读屏的
	if !strings.Contains(head, `class="brand-mark" aria-hidden="true"><img src="/favicon.svg" alt=""`) {
		t.Error("顶栏品牌图标应是 aria-hidden 包裹的空 alt 装饰图")
	}
}

// 静态资产清单三件齐全、可按名取到，且 Content-Type 不缺。
func TestStaticAssetRegistry(t *testing.T) {
	want := []string{"apple-touch-icon.png", "favicon.ico", "favicon.svg"}
	got := StaticNames()
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("静态清单应为 %v（定序），得到 %v", want, got)
	}
	for _, name := range want {
		data, ctype, ok := Static(name)
		if !ok {
			t.Errorf("Static(%q) 未命中", name)
			continue
		}
		if len(data) == 0 || ctype == "" {
			t.Errorf("Static(%q) 内容或类型为空", name)
		}
	}
	if _, _, ok := Static("nope.png"); ok {
		t.Error("名单外的静态名不该命中")
	}
}

// 页面模板一个不缺：路由层登记了 11 个页面，模板缺一个就启动即炸（ui.go 的
// Has 会被 cmd/server 逐个查），这里在包内先钉住数量与关键页。
func TestPageTemplatesPresent(t *testing.T) {
	for _, name := range []string{"login", "console", "admin-config", "admin-ai"} {
		if !Has(name) {
			t.Errorf("页面模板缺失: %s", name)
		}
	}
	if Has("not-a-page") {
		t.Error("未知页名不该命中")
	}
}

// cssRule 取一条以行首选择器开头的规则体（含大括号）。要求行首是为了不被
// `.btn .ico` 这类更长的选择器抢匹配。
func cssRule(css, selector string) (string, bool) {
	i := strings.Index(css, "\n"+selector+" ")
	if i < 0 {
		return "", false
	}
	open := strings.Index(css[i:], "{")
	if open < 0 {
		return "", false
	}
	start := i + open
	end := strings.Index(css[start:], "}")
	if end < 0 {
		return "", false
	}
	return css[start : start+end], true
}

// 骨架与响应头：窄屏可用（viewport-fit=cover）+ safe-area 内边距在 CSS 里有落地。
func TestNarrowScreenShellReady(t *testing.T) {
	raw, err := files.ReadFile("templates/layout.html")
	if err != nil {
		t.Fatalf("读页面骨架: %v", err)
	}
	if !strings.Contains(string(raw), "viewport-fit=cover") {
		t.Error("layout 缺 viewport-fit=cover（刘海屏 safe-area 前提）")
	}
	cssBytes, err := files.ReadFile("style.css")
	if err != nil {
		t.Fatalf("读 style.css: %v", err)
	}
	css := string(cssBytes)
	if !strings.Contains(css, "env(safe-area-inset-") {
		t.Error("style.css 缺 safe-area 内边距")
	}
	if !strings.Contains(css, "@media (min-width: 900px)") {
		t.Error("style.css 缺 900px 断点（侧栏导航的切换点）")
	}
	// 表格类页面（会话/审计/用户）窄屏靠 .table-wrap 横滚，不破版
	if !strings.Contains(css, ".table-wrap") || !strings.Contains(css, "overflow-x: auto") {
		t.Error("表格容器应是 overflow-x:auto 的横滚盒")
	}
}

// 设备页：本设备会话行不可退出——退出按钮只在 it.current 为假时渲染（JS 源码级
// 钉住，无 DOM 的单测拿不到渲染结果；服务端语义另由 TestSessionLifecycle 钉 current 标记）。
func TestSessionsPageCurrentRowNeverKickable(t *testing.T) {
	jsBytes, err := files.ReadFile("app.js")
	if err != nil {
		t.Fatalf("读 app.js: %v", err)
	}
	js := string(jsBytes)
	if !strings.Contains(js, "${it.current ? '' : '<button type=\"button\" class=\"btn small danger\">退出</button>'}") {
		t.Error("本设备会话行不该渲染退出按钮（it.current 分支应为空串）")
	}
	if !strings.Contains(js, "'<span class=\"badge on\">本设备</span>'") {
		t.Error("本设备会话行应带「本设备」徽标")
	}
	// 会话 id 一律按字符串处理（雪花 id 的 JS 精度陷阱）：列表请求的回执是
	// {sessions:[...]}，且踢人路径用 sessTag/字符串拼接
	if !strings.Contains(js, "res.sessions || []") {
		t.Error("会话列表应从 {sessions:[...]} 回执取数组")
	}
	if !strings.Contains(js, "const sessTag = id => 'session' + String(id).slice(-4)") {
		t.Error("会话条目应有 session+末4位 的字符串短标识")
	}
	// 按设备分组 + 组级批量退出走 revoke-many
	if !strings.Contains(js, "/api/sessions/revoke-many") {
		t.Error("设备组级退出应调 POST /api/sessions/revoke-many")
	}
}

// 顶栏账号胶囊与管理后台入口都在 layout 里，且管理入口由 .IsAdmin 门控
//（role 判定发生在 cmd/server 的 pageHandler，非管理员的 HTML 里没有这个按钮）。
// 进入后台后入口变「返回控制台」（.InAdmin 门控）。
func TestTopbarAccountAndAdminEntry(t *testing.T) {
	raw, err := files.ReadFile("templates/layout.html")
	if err != nil {
		t.Fatalf("读页面骨架: %v", err)
	}
	head := string(raw)
	for _, want := range []string{
		`{{if .IsAdmin}}<a class="btn small admin-entry" href="{{if .InAdmin}}/web/console{{else if .IsSuper}}/web/admin{{else}}/web/admin/sessions{{end}}" id="admin-entry">`,
		`{{if .InAdmin}}返回控制台{{else}}管理后台{{end}}`,
		`<span class="acct-email" id="topbar-email">{{.Email}}</span>`,
		`<span class="avatar" id="me-avatar" aria-hidden="true">{{.Initial}}</span>`,
	} {
		if !strings.Contains(head, want) {
			t.Errorf("layout 顶栏缺 %s", want)
		}
	}
	// 登录页（Minimal）没有顶栏：管理入口与账号胶囊都包在 not Minimal 里
	if !strings.Contains(head, "{{if not .Minimal}}\n<!-- 顶栏常驻") {
		t.Error("顶栏应整体由 not Minimal 门控（登录页无顶栏）")
	}
	// 登录页/403 页也不渲染底部 footer（整体 not Minimal 门控，连容器都不出）
	if !strings.Contains(head, "{{if not .Minimal}}\n<footer class=\"foot\">") {
		t.Error("footer 应整体由 not Minimal 门控（Minimal 页无页脚）")
	}
	// 服务端应用注册表 JSON 注入点存在
	if !strings.Contains(head, `<script type="application/json" id="known-apps">{{.AppsJSON}}</script>`) {
		t.Error("layout 应注入 known-apps 应用注册表 JSON")
	}
	if got := initialOf("someone@example.com"); got != "S" {
		t.Errorf("账号胶囊首字母应取邮箱首字符大写，得到 %q", got)
	}
	if !IsAdminRole("admin") || !IsAdminRole("super") || IsAdminRole("user") || IsAdminRole("") {
		t.Error("IsAdminRole 认 admin 与 super 两档")
	}
	if !IsSuperRole("super") || IsSuperRole("admin") {
		t.Error("IsSuperRole 只认 super")
	}
}

// W2 项目切换器与角色页：切换器 markup 在 layout、SwitchApps 按角色分叉、
// 403 页模板齐备、导航按 super 分叉（角色管理已并入用户页，导航只剩五项）。
func TestAppSwitchAndRolesPage(t *testing.T) {
	// 1. layout 带切换器容器（在 admin-entry 与 acct 之间）
	raw, err := files.ReadFile("templates/layout.html")
	if err != nil {
		t.Fatalf("读 layout: %v", err)
	}
	head := string(raw)
	sw := strings.Index(head, `id="app-switch"`)
	ae := strings.Index(head, `id="admin-entry"`)
	ac := strings.Index(head, `class="acct"`)
	if sw < 0 {
		t.Fatal("layout 缺项目切换器容器 id=app-switch")
	}
	if ae > 0 && !(ae < sw && sw < ac) {
		t.Errorf("切换器应在 admin-entry 与 acct 之间，得到 ae=%d sw=%d ac=%d", ae, sw, ac)
	}

	// 2. SwitchApps：super 三选项（全部高亮当 currentApp 空）；app-admin 只回授权项
	super := SwitchApps(true, nil, "")
	if len(super) != 3 || super[0].Key != "" || super[0].Label != "全部" || !super[0].Active {
		t.Errorf("super 切换器应三项且「全部」默认高亮，得到 %+v", super)
	}
	superCal := SwitchApps(true, nil, "calorie-diary")
	if superCal[0].Active || !superCal[1].Active {
		t.Errorf("?app=calorie 时应高亮该项，得到 %+v", superCal)
	}
	one := SwitchApps(false, []string{"calorie-diary"}, "")
	if len(one) != 1 || one[0].Key != "calorie-diary" {
		t.Errorf("app-admin 切换器只该有授权项，得到 %+v", one)
	}
	for _, c := range one {
		if c.Label == "全部" {
			t.Error("app-admin 的切换器不该有「全部」")
		}
	}

	// 3. 角色管理模板已删（并入用户页），403 页仍在
	if Has("admin-roles") {
		t.Error("admin-roles 模板应已删除（角色管理并入用户页）")
	}
	if !Has("denied") {
		t.Error("页面模板缺失: denied")
	}

	// 4. AdminNav 按角色分叉：super 五项（用户/会话/审计/配置/AI），app-admin 三项
	navS := AdminNav("", true)
	navA := AdminNav("", false)
	if len(navS) != 5 {
		t.Errorf("super 导航应五项，得到 %d", len(navS))
	}
	if len(navA) != 3 {
		t.Errorf("app-admin 导航应三项，得到 %d", len(navA))
	}
	for _, it := range navA {
		if it.Href == "/web/admin" || it.Href == "/web/admin/config" || it.Href == "/web/admin/roles" {
			t.Errorf("app-admin 导航不该有平台级入口 %q", it.Href)
		}
	}
	// super 导航不该再有独立的角色页入口
	for _, it := range navS {
		if it.Href == "/web/admin/roles" {
			t.Error("角色管理已并入用户页，super 导航不该再有 /web/admin/roles")
		}
	}

	// 5. 切换器样式只用 transition（动效令牌），不新增 keyframe 绕过门禁
	cssBytes, err := files.ReadFile("style.css")
	if err != nil {
		t.Fatalf("读 style.css: %v", err)
	}
	cssRuleStr, ok := cssRule(string(cssBytes), ".app-switch")
	if !ok {
		t.Fatal("style.css 缺 .app-switch 规则")
	}
	for _, frag := range []string{"--card", "--radius-ctl"} {
		if !strings.Contains(cssRuleStr, frag) {
			t.Errorf(".app-switch 缺令牌 %q", frag)
		}
	}
	chipRule, ok := cssRule(string(cssBytes), ".app-chip")
	if !ok {
		t.Fatal("style.css 缺 .app-chip 规则")
	}
	if !strings.Contains(chipRule, "var(--dur-1) var(--ease)") {
		t.Error(".app-chip 的动效应沿用 --dur-1/--ease 令牌")
	}
}

// 危险操作区（注销账号）独立红区：模板用 danger-zone，CSS 有 error 描边 + 淡底。
func TestDangerZoneIsolatedFromSettings(t *testing.T) {
	raw, err := files.ReadFile("templates/account.html")
	if err != nil {
		t.Fatalf("读账号页: %v", err)
	}
	if !strings.Contains(string(raw), `class="danger-zone"`) {
		t.Error("注销账号区应用 danger-zone 独立红区")
	}
	cssBytes, _ := files.ReadFile("style.css")
	css := string(cssBytes)
	rule, ok := cssRule(css, ".danger-zone")
	if !ok {
		t.Fatal("style.css 缺 .danger-zone 规则")
	}
	for _, frag := range []string{"var(--danger)", "var(--danger-bg)"} {
		if !strings.Contains(rule, frag) {
			t.Errorf(".danger-zone 缺 %s（error 描边/淡底）", frag)
		}
	}
}

// 零外链：内联脚本里不许出现任何 http(s):// 引用（favicon/二维码都是同源或运行时注入）。
func TestNoExternalResources(t *testing.T) {
	for _, name := range []string{"app.js", "style.css"} {
		b, err := files.ReadFile(name)
		if err != nil {
			t.Fatalf("读 %s: %v", name, err)
		}
		if strings.Contains(string(b), "http://") || strings.Contains(string(b), "https://") {
			t.Errorf("%s 出现外链引用（零外部依赖规矩）", name)
		}
	}
}

// 动效系统（miuix「丝滑统一」）：全站唯一 easing + 时长梯度令牌、入场/弹入/转圈关键帧、
// reduced-motion 一刀切（动画与过渡都关，且清零 animation-delay）。
func TestMotionSystem(t *testing.T) {
	cssBytes, err := files.ReadFile("style.css")
	if err != nil {
		t.Fatalf("读 style.css: %v", err)
	}
	css := string(cssBytes)

	// 1. 统一 easing 与时长令牌在 :root 里
	rule, ok := cssRule(css, ":root")
	if !ok {
		t.Fatal("style.css 缺 :root 规则")
	}
	for _, frag := range []string{"--ease: cubic-bezier(.2, 0, 0, 1)", "--dur-1", "--dur-2", "--dur-3"} {
		if !strings.Contains(rule, frag) {
			t.Errorf(":root 缺动效令牌 %q（全站唯一 easing/时长梯度）", frag)
		}
	}

	// 2. 关键帧齐备：入场（12px/4px 两档）、淡入、对话框弹入、转圈、徽标浮现
	for _, kf := range []string{
		"@keyframes rise-in", "@keyframes rise-in-sm", "@keyframes fade-in",
		"@keyframes dlg-in", "@keyframes spin", "@keyframes pop-in",
	} {
		if !strings.Contains(css, kf) {
			t.Errorf("style.css 缺 %s", kf)
		}
	}

	// 3. 只动 transform/opacity：关键帧体内不得出现 width/height/margin/top/left 这类 layout 属性
	for _, banned := range []string{
		"height:", "width:", "margin-", "top:", "left:", "padding:",
	} {
		for _, block := range keyframeBodies(css) {
			if strings.Contains(block, banned) {
				t.Errorf("关键帧里出现 layout 属性 %q（只许 transform/opacity，防抖动）：%s", banned, block)
				break
			}
		}
	}

	// 4. 入场错峰与浮层豁免
	for _, want := range []string{
		".content > *:nth-child(3) { animation-delay: 210ms; }",
		".content > #toast, .content > dialog { animation: none; }",
		"tbody tr:nth-child(-n+10)",
		".leaving",
		".dlg[open]",
		".btn[aria-busy=true]::after",
	} {
		if !strings.Contains(css, want) {
			t.Errorf("style.css 缺动效结构 %q", want)
		}
	}

	// 5. reduced-motion 一刀切：动画与过渡都关，且 delay 归零（否则错峰会让内容迟到）
	rms := reducedMotionBlock(css)
	if rms == "" {
		t.Fatal("style.css 缺 prefers-reduced-motion 媒体查询")
	}
	for _, frag := range []string{
		"transition-duration: 0.001ms !important",
		"animation-duration: 0.001ms !important",
		"animation-delay: 0ms !important",
		".btn:active, .tab:active { transform: none; }",
	} {
		if !strings.Contains(rms, frag) {
			t.Errorf("reduced-motion 块缺 %q", frag)
		}
	}

	// 6. JS 侧同一套 easing，且动画入口都尊重用户设置
	jsBytes, err := files.ReadFile("app.js")
	if err != nil {
		t.Fatalf("读 app.js: %v", err)
	}
	js := string(jsBytes)
	for _, want := range []string{
		"cubic-bezier(.2, 0, 0, 1)",
		"(prefers-reduced-motion: reduce)",
		"function swapIn(el)",
		"function popIn(el)",
		"function fadeOutRow(el, done)",
	} {
		if !strings.Contains(js, want) {
			t.Errorf("app.js 缺动效设施 %q", want)
		}
	}
}

// keyframeBodies 抽出每个 @keyframes 的规则体（粗粒度：只要大括号内的文本）。
func keyframeBodies(css string) []string {
	var out []string
	for i := 0; ; {
		j := strings.Index(css[i:], "@keyframes")
		if j < 0 {
			return out
		}
		start := i + j
		open := strings.Index(css[start:], "{")
		if open < 0 {
			return out
		}
		depth, k := 0, start+open
		for ; k < len(css); k++ {
			if css[k] == '{' {
				depth++
			} else if css[k] == '}' {
				depth--
				if depth == 0 {
					break
				}
			}
		}
		out = append(out, css[start:k])
		i = k
	}
}

// reducedMotionBlock 取 prefers-reduced-motion 那个媒体查询块的全文。
func reducedMotionBlock(css string) string {
	i := strings.Index(css, "@media (prefers-reduced-motion: reduce)")
	if i < 0 {
		return ""
	}
	open := strings.Index(css[i:], "{")
	if open < 0 {
		return ""
	}
	depth, k := 0, i+open
	for ; k < len(css); k++ {
		if css[k] == '{' {
			depth++
		} else if css[k] == '}' {
			depth--
			if depth == 0 {
				return css[i : k+1]
			}
		}
	}
	return css[i:]
}

// 品牌区两处（顶栏 `.brand` 与登录页 `.brand-lg`）**同源同款 = favicon.svg 的裸蓝
// 矢量**；全站不得残留任何带底的 logo 图；图标与文字的垂直居中要有双保险
//（flex 的 align-items:center 是主保险，inline 盒子的 vertical-align:middle 是兜底）。
func TestBrandMarksShareFaviconAndCenter(t *testing.T) {
	// 1. 两处品牌区都用同一个 favicon.svg
	for _, tpl := range []string{"templates/layout.html", "templates/login.html"} {
		raw, err := files.ReadFile(tpl)
		if err != nil {
			t.Fatalf("读 %s: %v", tpl, err)
		}
		if !strings.Contains(string(raw), `src="/favicon.svg"`) {
			t.Errorf("%s 的品牌区应引用 /favicon.svg（与站点 favicon 同源），实际没有", tpl)
		}
	}

	// 2. 全模板扫 <img>：src 只允许 /favicon.svg（二维码那张是运行时注入、本身无 src）
	entries, err := files.ReadDir("templates")
	if err != nil {
		t.Fatalf("列模板: %v", err)
	}
	imgTag := regexp.MustCompile(`<img\b[^>]*>`)
	imgSrc := regexp.MustCompile(`\bsrc="([^"]*)"`)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".html") {
			continue
		}
		raw, err := files.ReadFile("templates/" + e.Name())
		if err != nil {
			t.Fatalf("读 %s: %v", e.Name(), err)
		}
		for _, tag := range imgTag.FindAllString(string(raw), -1) {
			m := imgSrc.FindStringSubmatch(tag)
			if m == nil {
				continue // 运行时才补 src（二维码）
			}
			if m[1] != "/favicon.svg" {
				t.Errorf("%s 里有非 favicon 的图片引用 %q——品牌图必须统一成裸蓝矢量，不许带底",
					e.Name(), m[1])
			}
		}
	}

	// 3. 样式：双保险齐备
	cssBytes, err := files.ReadFile("style.css")
	if err != nil {
		t.Fatalf("读 style.css: %v", err)
	}
	css := string(cssBytes)
	if strings.Contains(css, "background-image") {
		t.Error("style.css 不该有 background-image（品牌图标走 <img>，不用底图）")
	}
	for _, want := range []struct{ selector, frag string }{
		{".brand", "align-items: center"},
		{".brand", "vertical-align: middle"},
		{".brand-mark", "align-items: center"},
		{".brand-mark", "vertical-align: middle"},
		{".ico", "vertical-align: middle"},
		{".brand-lg", "align-items: center"},
		{".brand-lg", "justify-content: center"},
	} {
		rule, ok := cssRule(css, want.selector)
		if !ok {
			t.Errorf("style.css 缺规则 %s", want.selector)
			continue
		}
		if !strings.Contains(rule, want.frag) {
			t.Errorf("%s 规则缺 %q（图标与文字垂直居中的保险）：\n%s", want.selector, want.frag, rule)
		}
	}
	// 品牌图标必须是显式尺寸的 <img>，加载前不抖版面
	layout, _ := files.ReadFile("templates/layout.html")
	if !strings.Contains(string(layout), `<img src="/favicon.svg" alt="" width="28" height="28">`) {
		t.Error("顶栏品牌图标应是 alt=\"\" + 显式 28×28 的 img")
	}
	login, _ := files.ReadFile("templates/login.html")
	if !strings.Contains(string(login), `<img class="ico" src="/favicon.svg" alt="" width="28" height="28">`) {
		t.Error("登录页大品牌区应是 alt=\"\" + 显式 28×28 的 img（与顶栏同源）")
	}
}

// 换装矩阵（2026-10-20 作者拍板）：**品牌位**走 favicon.svg 的 hexagon，**passkey 功能位**
// 一律 key-round——两者不许再撞脸。这里钉住三件事：icons.go 有 key-round 且 path 与 lucide
// 官方一致、登录页 Passkey 按钮用的就是它、全模板没有 fingerprint 功能位残留（防回潮）。
func TestPasskeyFunctionalIconIsKeyRound(t *testing.T) {
	glyph, ok := icons["key-round"]
	if !ok {
		t.Fatal("icons.go 缺 key-round 条目（passkey 功能位统一用它）")
	}
	if !strings.Contains(glyph, `M2.586 17.414A2 2 0 0 0 2 18.828V21`) {
		t.Error("key-round 的 path 与 lucide 官方 key-round 不符（字形被改了？）")
	}
	if _, dead := icons["fingerprint"]; dead {
		t.Error("icons.go 不该再有 fingerprint 条目（品牌位已换 hexagon、功能位是 key-round）")
	}

	entries, err := files.ReadDir("templates")
	if err != nil {
		t.Fatalf("列模板: %v", err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".html") {
			continue
		}
		raw, err := files.ReadFile("templates/" + e.Name())
		if err != nil {
			t.Fatalf("读 %s: %v", e.Name(), err)
		}
		if strings.Contains(string(raw), `{{icon "fingerprint"}}`) {
			t.Errorf("%s 还在用 fingerprint 功能图标——passkey 功能位应是 key-round", e.Name())
		}
	}

	login, err := files.ReadFile("templates/login.html")
	if err != nil {
		t.Fatalf("读 login.html: %v", err)
	}
	if !strings.Contains(string(login), `{{icon "key-round"}} 使用 Passkey 登录`) {
		t.Error("登录页 Passkey 按钮应是 {{icon \"key-round\"}} 使用 Passkey 登录")
	}
}
