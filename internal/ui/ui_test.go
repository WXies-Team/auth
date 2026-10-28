package ui

import (
	"math"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// 所有页面共用 layout 骨架：<head> 必须带三件套 link 与 theme-color，
// 顶栏品牌区挂 favicon.svg（透明底 + #3482FF 裸蓝素盾 shield，与站点 favicon 同源）。
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

// 页面模板一个不缺：路由层登记了 12 个页面，模板缺一个就启动即炸（ui.go 的
// Has 会被 cmd/server 逐个查），这里在包内先钉住数量与关键页。
func TestPageTemplatesPresent(t *testing.T) {
	for _, name := range []string{"login", "console", "admin-access", "admin-config", "admin-ai"} {
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
// 列表口径是**扁平**：一行=一条会话，行主标题=设备名（同名设备并排，不做归并），
// 分组渲染与组级批量退出已删干净。
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
	// {sessions:[...]}；行结构 = 设备名主标题 + 「项目名 · 最近活跃」次行
	// + 行尾「详情」展开（首次登录时间与 IP）
	if !strings.Contains(js, "res.sessions || []") {
		t.Error("会话列表应从 {sessions:[...]} 回执取数组")
	}
	if strings.Contains(js, "sessTag") {
		t.Error("session 尾号短标识已退役，app.js 不该再出现 sessTag")
	}
	for _, want := range []string{
		`<span class="title">${esc(it.device)}</span>`,
		`· 最近活跃 ${esc(relTime(it.lastSeenAt))}`,
		`data-act="more"`,
		`<div class="sess-more hidden">首次登录 ${esc(fmtTime(it.createdAt))} · IP ${esc(it.ip)}</div>`,
	} {
		if !strings.Contains(js, want) {
			t.Errorf("会话行应包含 %s（设备名主标题 + 项目名 · 最近活跃 + 详情展开）", want)
		}
	}
	// 页首 hint 钉住「最近活跃」口径（用户问得最多的一句）
	page, err := files.ReadFile("templates/sessions.html")
	if err != nil {
		t.Fatalf("读 sessions.html: %v", err)
	}
	pageStr := string(page)
	if !strings.Contains(pageStr, "最近活跃指该设备最后与服务器通信的时间。") {
		t.Error("sessions.html 页首应有「最近活跃」口径说明")
	}
	// 分组定案已否（同名不同设备被归并=歧义）：分组渲染、组级踢按钮、
	// revoke-many 的组级调用一个字节不留，模板说明也不许再提「分组」
	for _, gone := range []string{"device-group", "group-kick", "/api/sessions/revoke-many"} {
		if strings.Contains(js, gone) {
			t.Errorf("会话页已扁平化，app.js 不该再出现 %q", gone)
		}
	}
	if strings.Contains(pageStr, "分组") {
		t.Error("sessions.html 不该再有「按设备分组」的说明（列表已扁平化）")
	}
}

// UA Client Hints 的 opt-in：Render 是全部页面（登录页/授权页/邀请页/控制台页）
// 的响应头收口，浏览器见到 Accept-CH 后才会在本站后续请求带上高熵的
// Sec-CH-UA-Model（机型），登录建会话时并进设备名（internal/auth 的 uaWithCH）。
func TestRenderOptsIntoClientHints(t *testing.T) {
	rec := httptest.NewRecorder()
	if err := Render(rec, "login", Data{Title: "登录", Minimal: true}); err != nil {
		t.Fatalf("渲染登录页: %v", err)
	}
	if got := rec.Header().Get("Accept-CH"); got != "Sec-CH-UA-Platform, Sec-CH-UA-Model" {
		t.Errorf("登录页响应应带 Accept-CH: Sec-CH-UA-Platform, Sec-CH-UA-Model，得到 %q", got)
	}
	// 控制台页同一收口（不只登录页，所有经 Render 的页面都带）
	rec2 := httptest.NewRecorder()
	if err := Render(rec2, "console", Data{Title: "概览", Email: "u@example.com"}); err != nil {
		t.Fatalf("渲染概览页: %v", err)
	}
	if got := rec2.Header().Get("Accept-CH"); got != "Sec-CH-UA-Platform, Sec-CH-UA-Model" {
		t.Errorf("概览页响应也应带 Accept-CH，得到 %q", got)
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
		// B5：顶栏账号胶囊升级为头像（图/色块+首字）+ 昵称（回退邮箱前缀，完整邮箱在 title）
		`id="topbar-email" title="{{.Email}}"`,
		`id="me-avatar"`,
		`{{if .AvatarSrc}}<img src="{{.AvatarSrc}}" alt="">{{else}}{{.Initial}}{{end}}`,
		`{{.AcctName}}`,
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
// 403 页模板齐备、导航按 super 分叉（角色管理已并入用户页；W4 加「项目访问」，
// super 六项 / app-admin 四项）。
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

	// 4. AdminNav 按角色分叉：super 六项（用户/项目访问/会话/审计/配置/AI），
	// app-admin 四项（项目访问/会话/审计/AI）；项目访问页两级都开
	//（super 见全部项目、app-admin 只见授权项目，数据在服务端裁）
	navS := AdminNav("", true)
	navA := AdminNav("", false)
	if len(navS) != 6 {
		t.Errorf("super 导航应六项，得到 %d", len(navS))
	}
	if len(navA) != 4 {
		t.Errorf("app-admin 导航应四项，得到 %d", len(navA))
	}
	for _, list := range [][]NavItem{navS, navA} {
		n := 0
		for _, it := range list {
			if it.Href == "/web/admin/access" {
				n++
			}
		}
		if n != 1 {
			t.Errorf("导航应恰有一项「项目访问」入口，得到 %d", n)
		}
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

// 授权页（B4 authorize 模板）：确认态带项目名/回跳域名/继续取消双钮（同表单
// decision 分流），错误态是同卡片语言的变体；两态都走 Minimal 壳。
func TestAuthorizeTemplateRendersBothVariants(t *testing.T) {
	if !Has("authorize") {
		t.Fatal("页面模板缺失: authorize")
	}
	raw, err := files.ReadFile("templates/authorize.html")
	if err != nil {
		t.Fatalf("读授权页模板: %v", err)
	}
	tpl := string(raw)
	for _, want := range []string{
		`method="post" action="/oauth/authorize/confirm"`,
		`name="decision" value="allow"`, `name="decision" value="deny"`,
		`name="tx" value=`, `.AppName`, `.RedirectHost`, `.Email`,
		`.ErrorTitle`, `.ErrorMessage`,
		`登录到「`, `它将获得你的账号标识与邮箱`,
	} {
		if !strings.Contains(tpl, want) {
			t.Errorf("授权页模板缺 %q", want)
		}
	}
	// 确认态渲染：项目名、回跳域名、账号邮箱都出现在 HTML 里
	rec := httptest.NewRecorder()
	data := Data{Title: "授权登录", Minimal: true, OAuth: &OAuthView{
		Tx: "tx-1", App: "calorie-diary", AppName: "热量日记",
		RedirectHost: "app.example.com", Email: "u@example.com",
	}}
	if err := Render(rec, "authorize", data); err != nil {
		t.Fatalf("渲染确认页: %v", err)
	}
	body := rec.Body.String()
	for _, want := range []string{"热量日记", "app.example.com", "u@example.com", "tx-1", "继续", "取消"} {
		if !strings.Contains(body, want) {
			t.Errorf("确认页 HTML 缺 %q", want)
		}
	}
	if rec.Code != http.StatusOK {
		t.Errorf("默认应 200，得到 %d", rec.Code)
	}
	// 错误态渲染：带状态码起头 + 标题与文案
	recErr := httptest.NewRecorder()
	if err := Render(recErr, "authorize", Data{
		Title: "无法发起授权", Minimal: true, Status: http.StatusBadRequest,
		OAuth: &OAuthView{ErrorTitle: "无法发起授权", ErrorMessage: "应用未登记，请联系应用管理员在控制台开通后再试"},
	}); err != nil {
		t.Fatalf("渲染错误页: %v", err)
	}
	if recErr.Code != http.StatusBadRequest {
		t.Errorf("错误页应以 400 起头，得到 %d", recErr.Code)
	}
	for _, want := range []string{"无法发起授权", "应用未登记"} {
		if !strings.Contains(recErr.Body.String(), want) {
			t.Errorf("错误页 HTML 缺 %q", want)
		}
	}
}

// 接受邀请页（B9 invite 模板）：与 authorize 同款「同模板双变体」——确认态渲染
// 表单（邮箱只读 + new-password/username/nickname autocomplete + 隐藏 token，零 JS），
// 错误态整卡替换并以 400 起头；AppLabel 与页面里的项目名同源。
func TestInviteTemplateRendersBothVariants(t *testing.T) {
	if !Has("invite") {
		t.Fatal("页面模板缺失: invite")
	}
	raw, err := files.ReadFile("templates/invite.html")
	if err != nil {
		t.Fatalf("读邀请页模板: %v", err)
	}
	tpl := string(raw)
	for _, want := range []string{
		`method="post" action="/web/invite"`,
		`name="token" value=`, `name="password"`, `name="nickname"`,
		`autocomplete="new-password"`, `autocomplete="username"`, `autocomplete="nickname"`,
		`readonly`, `minlength="8"`,
		`.ErrorTitle`, `.ErrorMessage`, `.Error`, `.Email`, `.AppName`,
	} {
		if !strings.Contains(tpl, want) {
			t.Errorf("邀请页模板缺 %q", want)
		}
	}

	// 表单变体：邮箱、项目名、隐藏 token 都进 HTML（200）
	rec := httptest.NewRecorder()
	if err := Render(rec, "invite", Data{
		Title: "接受邀请", Minimal: true,
		Invite: &InviteView{Token: "tok-123", Email: "invitee@example.com",
			App: "calorie-diary", AppName: AppLabel("calorie-diary")},
	}); err != nil {
		t.Fatalf("渲染表单变体: %v", err)
	}
	body := rec.Body.String()
	for _, want := range []string{"invitee@example.com", "tok-123", "热量日记", "设置密码并完成注册"} {
		if !strings.Contains(body, want) {
			t.Errorf("表单变体 HTML 缺 %q", want)
		}
	}
	if rec.Code != http.StatusOK {
		t.Errorf("默认应 200，得到 %d", rec.Code)
	}

	// 错误变体：400 起头 + 标题文案，且不再渲染提交表单
	recErr := httptest.NewRecorder()
	if err := Render(recErr, "invite", Data{
		Title: "无法接受邀请", Minimal: true, Status: http.StatusBadRequest,
		Invite: &InviteView{ErrorTitle: "无法接受邀请", ErrorMessage: "邀请链接已过期（24 小时内有效），请联系邀请人重新发送"},
	}); err != nil {
		t.Fatalf("渲染错误变体: %v", err)
	}
	if recErr.Code != http.StatusBadRequest {
		t.Errorf("错误变体应以 400 起头，得到 %d", recErr.Code)
	}
	errBody := recErr.Body.String()
	for _, want := range []string{"无法接受邀请", "已过期", "前往登录"} {
		if !strings.Contains(errBody, want) {
			t.Errorf("错误变体 HTML 缺 %q", want)
		}
	}
	if strings.Contains(errBody, `action="/web/invite"`) {
		t.Error("错误变体不该渲染提交表单")
	}

	// 提交被打回：表单 + 字段下就地报错（不是整卡错误变体）
	recForm := httptest.NewRecorder()
	if err := Render(recForm, "invite", Data{
		Title: "接受邀请", Minimal: true, Status: http.StatusBadRequest,
		Invite: &InviteView{Token: "tok-1", Email: "a@example.com", Error: "密码至少 8 位"},
	}); err != nil {
		t.Fatalf("渲染就地报错: %v", err)
	}
	if !strings.Contains(recForm.Body.String(), "密码至少 8 位") ||
		!strings.Contains(recForm.Body.String(), `action="/web/invite"`) {
		t.Error("业务打回应重渲染表单并在字段下方报错")
	}

	// AppLabel：注册表内回展示名，未知 slug 回原串，空串回空
	if AppLabel("calorie-diary") != "热量日记" || AppLabel("expense-diary") != "开支日记" {
		t.Errorf("AppLabel 应回注册表展示名，得到 %q / %q", AppLabel("calorie-diary"), AppLabel("expense-diary"))
	}
	if AppLabel("nope") != "nope" || AppLabel("") != "" {
		t.Errorf("未知/空 slug 应回原样，得到 %q / %q", AppLabel("nope"), AppLabel(""))
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
		".btn:active, .tab:active, .app-chip:active, .select-btn:active",
		"input[type=checkbox]:active, input[type=radio]:active { transform: none; }",
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
			// B5 顶栏档案头像：src 是 Render 拼好的 data URL（{{.AvatarSrc}}），
			// 不是外链也不是品牌位——放行，其余仍只许站点 favicon
			if m[1] == "/favicon.svg" || m[1] == "{{.AvatarSrc}}" {
				continue
			}
			t.Errorf("%s 里有非 favicon 的图片引用 %q——品牌图必须统一成裸蓝矢量，不许带底",
				e.Name(), m[1])
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

// 换装矩阵（2026-10-20 拍板，2026-10-21 品牌字形统一为素盾 shield）：**品牌位**走
// favicon.svg 的素盾，**passkey 功能位**
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
		t.Error("icons.go 不该再有 fingerprint 条目（品牌位已换素盾 shield、功能位是 key-round）")
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

// B5 账号资料卡与顶栏升级：账号页渲染出资料卡全套控件（头像/色板/保存/清头像），
// 顶栏派生数据（显示名/首字/色板 hex/头像 data URL）在 Render 里落地；无昵称时
// 显示名回退邮箱前缀、首字回退邮箱首字符。
func TestProfileCardAndTopbarDerivation(t *testing.T) {
	if !Has("account") {
		t.Fatal("页面模板缺失: account")
	}
	// 账号页带档案渲染：资料卡控件 + palette 注入 + 头像 data URL
	rec := httptest.NewRecorder()
	avatar := "aGVsbG8="
	if err := Render(rec, "account", Data{
		Title: "账号", Email: "someone@example.com", Nickname: "阿橘",
		AvatarColor: 3, AvatarImage: avatar,
	}); err != nil {
		t.Fatalf("渲染账号页: %v", err)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"账号资料", `id="pf-avatar"`, `id="pf-palette"`, `id="pf-save"`,
		`id="avatar-palette"`, "阿橘", "data:image/jpeg;base64," + avatar,
		"someone@example.com", `id="topbar-email" title="someone@example.com"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("账号页缺 %q", want)
		}
	}

	// 顶栏派生：无昵称 → 显示名邮箱前缀、首字邮箱首字符；色板越界回退首位
	rec2 := httptest.NewRecorder()
	if err := Render(rec2, "console", Data{Title: "概览", Email: "prefix@example.com", AvatarColor: 99}); err != nil {
		t.Fatalf("渲染概览页: %v", err)
	}
	b2 := rec2.Body.String()
	if !strings.Contains(b2, `id="topbar-email" title="prefix@example.com">prefix<`) {
		t.Error("无昵称时顶栏显示名应回退邮箱前缀")
	}
	if !strings.Contains(b2, ">P<") {
		t.Error("无昵称时顶栏首字应回退邮箱首字符大写")
	}
	if AvatarPaletteHex(99) != AvatarPaletteHex(0) || AvatarPaletteHex(-1) != AvatarPaletteHex(0) {
		t.Error("色板下标越界应回退首位")
	}
	// 色板与两 App AvatarPalette 逐值同序（8 色）
	wantPalette := []string{"#5B8DEF", "#7C6AF2", "#E2556B", "#FF8A3D", "#2BB673", "#14A8A0", "#E6B422", "#8B7355"}
	for i, hex := range wantPalette {
		if AvatarPaletteHex(i) != hex {
			t.Errorf("色板第 %d 位应 %s，得到 %s", i, hex, AvatarPaletteHex(i))
		}
	}
}

// 头像首字墨色（FX6a 必修1）：8 色色板逐色实测——选中的墨对底色 ≥4.5:1（正文线），
// 且确实是黑/白两支里对比更高的一支（与两 App AvatarPalette.inkFor 同规则）。写死
// 白墨的旧实现在这里全线翻车（白墨实测 1.92~4.49）。同时钉住三个注入点：layout 顶栏
// 底色+墨色成对、app.js 有 avatarInk 且被各渲染点调用、style.css .avatar 不再写死
// var(--primary-ink)。
func TestAvatarInkContrast(t *testing.T) {
	// 独立复算（不借 prod 的 hexLuminance，防实现与断言同错）：sRGB 线性化 + WCAG 加权
	lin := func(c uint8) float64 {
		f := float64(c) / 255
		if f <= 0.04045 {
			return f / 12.92
		}
		return math.Pow((f+0.055)/1.055, 2.4)
	}
	lum := func(hex string) float64 {
		n, err := strconv.ParseUint(strings.TrimPrefix(hex, "#"), 16, 32)
		if err != nil {
			t.Fatalf("解析色值 %q: %v", hex, err)
		}
		return 0.2126*lin(uint8(n>>16)) + 0.7152*lin(uint8(n>>8)) + 0.0722*lin(uint8(n))
	}
	ratio := func(a, b string) float64 {
		la, lb := lum(a), lum(b)
		if la < lb {
			la, lb = lb, la
		}
		return (la + 0.05) / (lb + 0.05)
	}
	for _, bg := range avatarPalette {
		ink := avatarInkFor(bg)
		if ink != "#000000" && ink != "#ffffff" {
			t.Errorf("色板 %s 的墨色应是黑/白之一，得到 %q", bg, ink)
			continue
		}
		if got := ratio(ink, bg); got < 4.5 {
			t.Errorf("色板 %s 的墨 %s 对比度 %0.2f < 4.5:1 正文线", bg, ink, got)
		}
		white, black := ratio("#ffffff", bg), ratio("#000000", bg)
		best := "#000000"
		if white >= black { // 平手取白，与 app.js avatarInk / 两 App inkFor 同 tie-break
			best = "#ffffff"
		}
		if ink != best {
			t.Errorf("色板 %s 应取对比更高的 %s（白 %0.2f / 黑 %0.2f），得到 %s", bg, best, white, black, ink)
		}
	}
	// 顶栏渲染：底色与墨色成对进同一行内 style（无档案头像时才出色块；#E6B422 = 下标 6）
	rec := httptest.NewRecorder()
	if err := Render(rec, "console", Data{Title: "概览", Email: "ink@example.com", AvatarColor: 6}); err != nil {
		t.Fatalf("渲染概览页: %v", err)
	}
	if !strings.Contains(rec.Body.String(), `style="background:#E6B422;color:#000000"`) {
		t.Error("顶栏色块应成对注入底色与墨色（background+color 同一 style）")
	}
	// style.css .avatar：不再写死白墨 var(--primary-ink)（默认兜底黑墨）
	cssBytes, err := files.ReadFile("style.css")
	if err != nil {
		t.Fatalf("读 style.css: %v", err)
	}
	rule, ok := cssRule(string(cssBytes), ".avatar")
	if !ok {
		t.Fatal("style.css 缺 .avatar 规则")
	}
	if strings.Contains(rule, "--primary-ink") {
		t.Error(".avatar 不该再写死白墨 var(--primary-ink)（白墨对色板全数 <4.5:1）")
	}
	// app.js avatarInk：定义 + 三处调用（avatarHTML / 资料卡 renderAvatar / 顶栏 updateTopbarAvatar）
	jsBytes, err := files.ReadFile("app.js")
	if err != nil {
		t.Fatalf("读 app.js: %v", err)
	}
	if n := strings.Count(string(jsBytes), "avatarInk("); n < 4 {
		t.Errorf("app.js 应定义并三处调用 avatarInk，只找到 %d 处", n)
	}
}

// W1 底栏清零：登录（含注册/找回 tab）、授权（确认与错误两变体）、邀请（表单与
// 错误两变体）、403 拒绝页**渲染产物里连 <footer> 容器都不出现**——不是 display:none
// 藏一下。逐页 Render 实测（而不是只看模板里的 if 条件），条件被误删时这里先翻车。
func TestMinimalPagesRenderNoFooter(t *testing.T) {
	cases := []struct {
		file string
		data Data
	}{
		{"login", Data{Title: "登录", Minimal: true}},
		{"authorize", Data{Title: "授权登录", Minimal: true, OAuth: &OAuthView{
			Tx: "t", App: "calorie-diary", AppName: "热量日记", RedirectHost: "a.example", Email: "u@example.com"}}},
		{"authorize", Data{Title: "无法发起授权", Minimal: true, Status: http.StatusBadRequest,
			OAuth: &OAuthView{ErrorTitle: "无法发起授权", ErrorMessage: "应用未登记"}}},
		{"invite", Data{Title: "接受邀请", Minimal: true, Invite: &InviteView{
			Token: "t", Email: "a@example.com", App: "calorie-diary", AppName: "热量日记"}}},
		{"invite", Data{Title: "无法接受邀请", Minimal: true, Status: http.StatusBadRequest,
			Invite: &InviteView{ErrorTitle: "无法接受邀请", ErrorMessage: "邀请链接已过期"}}},
		{"denied", Data{Title: "无权访问", Minimal: true, DeniedApp: "calorie-diary"}},
	}
	for _, c := range cases {
		rec := httptest.NewRecorder()
		if err := Render(rec, c.file, c.data); err != nil {
			t.Fatalf("渲染 %s: %v", c.file, err)
		}
		body := rec.Body.String()
		if strings.Contains(body, "<footer") || strings.Contains(body, `class="foot"`) {
			t.Errorf("%s（Minimal 壳）渲染出了底栏——公共页一律无页脚", c.file)
		}
	}
	// 全模板只允许 layout 一处 <footer>（否则门控漏了第二处渲染点）
	entries, err := files.ReadDir("templates")
	if err != nil {
		t.Fatalf("列模板: %v", err)
	}
	n := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".html") {
			continue
		}
		raw, rerr := files.ReadFile("templates/" + e.Name())
		if rerr != nil {
			t.Fatalf("读 %s: %v", e.Name(), rerr)
		}
		n += strings.Count(string(raw), "<footer")
	}
	if n != 1 {
		t.Errorf("模板里应恰有一处 <footer>（layout 且由 not Minimal 门控），得到 %d 处", n)
	}
	// 注销撤销页（cmd/server 的独立 HTML）不进模板集：它自带的整页里也没有页脚
	//（本包只对模板集负责，独立页由 cmd/server 自持——这里只钉模板口径）。
}

// W3 头像底色派生：avatarColor 未设（0/越界）按 uid%8 从同一 8 色色板派生，
// 显式色原样用——顶栏不再「全员一个色」。Go 半边钉 AvatarPaletteHexFor 与
// Render 落地；JS 半边（app.js avatarHex/avatarHTML）钉结构与镜像式。
func TestAvatarDeriveByUID(t *testing.T) {
	want := []string{"#5B8DEF", "#7C6AF2", "#E2556B", "#FF8A3D", "#2BB673", "#14A8A0", "#E6B422", "#8B7355"}
	for _, uid := range []int64{1, 8, 9, 1000001, 1000002, 1000003} {
		if got := AvatarPaletteHexFor(uid, 0); got != want[uid%8] {
			t.Errorf("uid=%d 未设色应派生 palette[uid%%%d]=%s，得到 %s", uid, len(want), want[uid%8], got)
		}
		if got := AvatarPaletteHexFor(uid, 99); got != want[uid%8] {
			t.Errorf("uid=%d 越界色应按未设派生 %s，得到 %s", uid, want[uid%8], got)
		}
		if got := AvatarPaletteHexFor(uid, 3); got != want[3] {
			t.Errorf("uid=%d 显式色 3 应原样用 %s，得到 %s", uid, want[3], got)
		}
	}
	if AvatarPaletteHexFor(0, 0) != want[0] {
		t.Error("无 uid（Minimal 壳）回退色板首位")
	}
	// Render 落地：uid=9（9%8=1）、未设色 → 顶栏色块 #7C6AF2（墨色按亮度择黑）
	rec := httptest.NewRecorder()
	if err := Render(rec, "console", Data{Title: "概览", Email: "u@example.com",
		UID: 9, AvatarColor: 0}); err != nil {
		t.Fatalf("渲染概览: %v", err)
	}
	if !strings.Contains(rec.Body.String(), "background:#7C6AF2") {
		t.Error("顶栏色块应按 uid 派生（uid=9 → #7C6AF2）")
	}
	// app.js 半边：派生式与真图端点/回退结构
	jsBytes, err := files.ReadFile("app.js")
	if err != nil {
		t.Fatalf("读 app.js: %v", err)
	}
	js := string(jsBytes)
	for _, wantFrag := range []string{
		"u % p.length",                        // uid%8 派生式
		"/admin/users/${esc(u.uid)}/avatar",   // 列表/抽屉头像走真图端点
		`class="avatar-img" loading="lazy"`,   // 懒加载
		"wrap.dataset.initial",                // onerror 回退色块+首字
		"avatar-img",                          // 捕获阶段 error 监听的选择器依据
	} {
		if !strings.Contains(js, wantFrag) {
			t.Errorf("app.js 缺 W3 头像结构 %q", wantFrag)
		}
	}
	// 回退方向是「图 → 占位符」：不再有按 avatarImage 直出 data URL 的分支
	if strings.Contains(js, `data:image/jpeg;base64,${esc(u.avatarImage)}`) {
		t.Error("列表/抽屉头像不该再走 data URL 直出（应走 /admin/users/{uid}/avatar + onerror 回退）")
	}
}

// W2 reauth 分步 + W4 Web 接入撤下的 JS/模板同步钉：
// 弹窗只允许「一屏一问」（第一步密码、第二步码），Web 接入的模板与脚本一并撤净。
func TestReauthStagedAndWebAccessRemoved(t *testing.T) {
	layout, err := files.ReadFile("templates/layout.html")
	if err != nil {
		t.Fatalf("读 layout: %v", err)
	}
	head := string(layout)
	for _, want := range []string{`id="reauth-step1"`, `id="reauth-step2"`, `class="hidden"`} {
		if !strings.Contains(head, want) {
			t.Errorf("reauth 弹窗缺分步结构 %q", want)
		}
	}
	// 「一屏全堆」的旧结构不许回潮：密码与码框之间的「或」分隔
	if strings.Contains(head, `<p class="or">或</p>`) {
		t.Error("reauth 弹窗不该再有「密码 或 验证码」的同屏分隔（W2 已改分步）")
	}
	jsBytes, err := files.ReadFile("app.js")
	if err != nil {
		t.Fatalf("读 app.js: %v", err)
	}
	js := string(jsBytes)
	for _, want := range []string{"function reauthShowStep(", "totpEnabled", `body: { password }`, "body: { totpCode, recoveryCode }"} {
		if !strings.Contains(js, want) {
			t.Errorf("app.js 缺 W2 分步接线 %q", want)
		}
	}
	access, err := files.ReadFile("templates/admin-access.html")
	if err != nil {
		t.Fatalf("读 admin-access: %v", err)
	}
	if strings.Contains(string(access), "oauth-secret-dlg") {
		t.Error("Web 接入的一次性 Secret 层应随 W4 撤下")
	}
	if strings.Contains(js, "data-webaccess") || strings.Contains(js, "showOAuthSecret") {
		t.Error("app.js 不该再渲染 Web 接入块（W4：后端端点保留休眠，前端整体撤下）")
	}
}

// W5/W6 发码按钮内联与密码管理器徽章修复的结构钉：
// 验证码行 = 输入 flex + 按钮 flex:none 同一行；徽章锚定收进字段（position:relative
// + 右侧预留 44px）+ :-webkit-autofill 归一保住 FX3 内环。
func TestCodeRowInlineAndBadgeAnchorFix(t *testing.T) {
	cssBytes, err := files.ReadFile("style.css")
	if err != nil {
		t.Fatalf("读 style.css: %v", err)
	}
	css := string(cssBytes)
	codeLine, ok := cssRule(css, ".code-line")
	if !ok {
		t.Fatal("style.css 缺 .code-line 规则（W5 验证码行）")
	}
	for _, frag := range []string{"display: flex", "position: relative"} {
		if !strings.Contains(codeLine, frag) {
			t.Errorf(".code-line 缺 %q", frag)
		}
	}
	// W6 定位锚：.field 必须是 positioned，徽章/下拉才解析回字段自身
	field, ok := cssRule(css, ".field")
	if !ok {
		t.Fatal("style.css 缺 .field 规则")
	}
	if !strings.Contains(field, "position: relative") {
		t.Error(".field 应带 position:relative（W6：凭据徽章的包含块锚点）")
	}
	if !strings.Contains(css, `input[autocomplete="one-time-code"], input[type=password]`) ||
		!strings.Contains(css, "padding-right: 44px") {
		t.Error("凭据/OTP 字段应预留右侧徽章位（padding-right: 44px）")
	}
	if !strings.Contains(css, "input:-webkit-autofill") {
		t.Error("缺 :-webkit-autofill 归一（autofill 底色会盖掉站点内环）")
	}
	// 6 处发码按钮都进了 code-line（grep 全部「获取验证码」按钮的所在行）
	for _, tpl := range []string{"templates/login.html", "templates/account.html"} {
		raw, rerr := files.ReadFile(tpl)
		if rerr != nil {
			t.Fatalf("读 %s: %v", tpl, rerr)
		}
		if n := strings.Count(string(raw), `class="code-line"`); n < 1 {
			t.Errorf("%s 缺 code-line 行（W5 发码按钮内联）", tpl)
		}
		if strings.Contains(string(raw), `style="margin-top:-4px"`) {
			t.Errorf("%s 不该再有负 margin 的独占发码行（W5 已内联）", tpl)
		}
	}
	jsBytes, err := files.ReadFile("app.js")
	if err != nil {
		t.Fatalf("读 app.js: %v", err)
	}
	if !strings.Contains(string(jsBytes), "hide: ['#send-2fa-code']") {
		t.Error("两步邮箱码模式的发码按钮显隐应指向 #send-2fa-code（原独立行已删）")
	}
}

// W8/W9 排版与原生控件 miuix 化：站内下拉（按钮+浮层菜单、值载体保留）、样式
// checkbox/radio、披露行箭头、日期输入吃站内规则、表格窄屏横滚不破版、审计时间档位。
func TestNativeControlsMiuixAndLayoutFixes(t *testing.T) {
	cssBytes, err := files.ReadFile("style.css")
	if err != nil {
		t.Fatalf("读 style.css: %v", err)
	}
	css := string(cssBytes)
	// ① 日期输入必须在输入框规则名单里（W8③ 直接根因：漏了 type=date 就掉回 UA 形态）
	if !strings.Contains(css, "input[type=date]") {
		t.Error("input[type=date] 应并入站内输入框规则（否则审计日期掉回 UA 原生形态）")
	}
	// ② 站内下拉形态与勾选/单选自绘
	for _, frag := range []string{
		".select-btn", ".select-menu", ".select-opt",
		"input[type=checkbox]", "appearance: none",
		"details.section > summary::after",
	} {
		if !strings.Contains(css, frag) {
			t.Errorf("style.css 缺站内控件形态 %q", frag)
		}
	}
	// ③ 窄屏不破版：表格有 min-width（横滚交给 .table-wrap），网格子项压回 min-width:0
	tableRule, _ := cssRule(css, "table")
	if !strings.Contains(tableRule, "min-width") {
		t.Error("table 应带 min-width（窄屏让容器横滚，而不是把列压成一字一行）")
	}
	if !strings.Contains(css, ".content > * { min-width: 0; }") {
		t.Error(".content 网格子项应 min-width:0（防表格把整页撑横滚）")
	}
	// ④ JS 侧：下拉装饰器 + 审计时间快捷档位
	jsBytes, err := files.ReadFile("app.js")
	if err != nil {
		t.Fatalf("读 app.js: %v", err)
	}
	js := string(jsBytes)
	for _, frag := range []string{"function decorateSelect(", "decorateSelects(document)", "data-range", "function setRange("} {
		if !strings.Contains(js, frag) {
			t.Errorf("app.js 缺 W8/W9 结构 %q", frag)
		}
	}
	// ⑤ 审计页模板带四档位 chips（今天/近7天/近30天/自定义）
	audit, err := files.ReadFile("templates/admin-audit.html")
	if err != nil {
		t.Fatalf("读 admin-audit: %v", err)
	}
	for _, frag := range []string{`data-range="today"`, `data-range="7"`, `data-range="30"`, `data-range="custom"`} {
		if !strings.Contains(string(audit), frag) {
			t.Errorf("审计页缺时间快捷档位 %q", frag)
		}
	}
}
