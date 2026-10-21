package auth

// 新设备登录提醒（W1）的判定口径与邮件模板：纯单测（不碰数据库）钉住「机型族级
// 指纹 / 新设备判定 / 项目名取值 / 模板四段式与双形态」；端到端触发发信是真库用例
// （见文件末尾，CI 跑）。

import (
	"strings"
	"testing"
	"time"
)

// UA 指纹是**机型族级**：同机同浏览器跨版本同指纹（版本号不进指纹），换系统/换
// 设备家族不同指纹；App 规范 UA 落到机型段。
func TestUAFingerprintFamilyLevel(t *testing.T) {
	const win120 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	const win131 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
	const macSafari = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15"
	const pixel = "calorie-diary/1.2.3 (Android; Pixel 8)"

	if uaFingerprint(win120) != uaFingerprint(win131) {
		t.Errorf("同机同浏览器跨版本应同指纹：%q vs %q", uaFingerprint(win120), uaFingerprint(win131))
	}
	if uaFingerprint(win120) == uaFingerprint(macSafari) {
		t.Errorf("换系统应是不同指纹，却都是 %q", uaFingerprint(win120))
	}
	if got := uaFingerprint(pixel); got != "Pixel 8" {
		t.Errorf("App UA 的指纹应为机型段 Pixel 8，得到 %q", got)
	}
	if got := uaFingerprint(""); got != "未知设备" {
		t.Errorf("空 UA 应回 未知设备，得到 %q", got)
	}
}

// 新设备判定：其它活跃会话的指纹集合里没有本次指纹才算新。App UA 与浏览器 UA
// 对同一台手机是两个指纹（契约性决策 D3：跨登录形态同样提醒）。
func TestIsNewDeviceDecision(t *testing.T) {
	const winUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	const phoneBrowser = "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36"
	const phoneApp = "calorie-diary/1.2.3 (Android; Pixel 8)"

	// 没有任何活跃会话：首台设备即新设备
	if !isNewDevice(map[string]bool{}, winUA) {
		t.Error("无其它活跃会话时应判为新设备")
	}
	// 同族指纹已存在（跨浏览器版本）：不是新设备
	if isNewDevice(map[string]bool{uaFingerprint(winUA): true}, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0.0.0 Safari/537.36") {
		t.Error("同族指纹（跨浏览器版本）不该判为新设备")
	}
	// 换系统：新设备
	if !isNewDevice(map[string]bool{uaFingerprint(winUA): true}, phoneBrowser) {
		t.Error("换系统应判为新设备")
	}
	// 同一台手机：App 会话在册，浏览器登录仍判新（D3）
	if !isNewDevice(map[string]bool{uaFingerprint(phoneApp): true}, phoneBrowser) {
		t.Error("同机跨登录形态（App 会话在册、浏览器登录）按 D3 应判为新设备")
	}
	// 集合里只有别的设备：本机判新
	if !isNewDevice(map[string]bool{uaFingerprint(phoneBrowser): true}, winUA) {
		t.Error("只存在其它设备会话时本机应判为新设备")
	}
}

// 提醒信里「项目」一行：App 登录 = 品牌名，web 登录 = Auth 控制台。
func TestLoginNotifyAppLabel(t *testing.T) {
	cases := map[string]string{
		"":              "Auth 控制台",
		"calorie-diary": "热量日记",
		"expense-diary": "开支日记",
		"evil-app":      "Auth", // 未知 app 兜底中性品牌（上游已挡，这里只验不 panic）
	}
	for app, want := range cases {
		if got := loginNotifyAppLabel(app); got != want {
			t.Errorf("loginNotifyAppLabel(%q) = %q，应为 %q", app, got, want)
		}
	}
}

// 新登录提醒模板（每品牌）：主题前缀 + 四段式（首句/细节列表/不是我 + 双深链/页脚
// 含管理入口）+ HTML/纯文本双形态并存 + 设备名过转义。
func TestLoginNotifyEmailTemplate(t *testing.T) {
	at := time.Date(2026, 10, 21, 9, 30, 0, 0, time.Local)
	for _, app := range []string{"calorie-diary", "expense-diary", ""} {
		b := brandFor(app)
		device := "Pixel 8"
		project := loginNotifyAppLabel(app)
		subject, htmlBody, text := loginNotifyEmail(b, device, project, at)

		if want := b.prefix + "新设备登录提醒"; subject != want {
			t.Errorf("app=%q 主题应为 %q，得到 %q", app, want, subject)
		}
		for _, want := range []string{
			"检测到新设备登录", device, project, "2026-10-21 09:30",
			"如果这不是你本人的操作，请立即修改密码并退出其它设备。",
			siteBase + "/web/console/security", siteBase + "/web/console/sessions",
			accountURL, b.footer,
		} {
			if !strings.Contains(htmlBody, want) {
				t.Errorf("app=%q HTML 缺 %q", app, want)
			}
			if !strings.Contains(text, want) {
				t.Errorf("app=%q 纯文本缺 %q", app, want)
			}
		}
		// 两个深链按钮下方都要有纯文本 URL（HTML 版）
		for _, url := range []string{siteBase + "/web/console/security", siteBase + "/web/console/sessions"} {
			if n := strings.Count(htmlBody, url); n < 2 {
				t.Errorf("app=%q 的 %q 应出现 ≥2 次（按钮 + 纯文本 URL），得到 %d 次", app, url, n)
			}
		}
	}

	// 注入面：设备名里的尖括号必须转义（设备名来自 UA 解析，不是信任输入）
	_, htmlBody, _ := loginNotifyEmail(neutralBrand, `<script>`, "Auth 控制台", at)
	if strings.Contains(htmlBody, "<script>") || !strings.Contains(htmlBody, "&lt;script&gt;") {
		t.Errorf("设备名未转义，存在 HTML 注入面: %s", htmlBody)
	}
}

// ---- 真库端到端（CI 跑，本地无 TEST_MYSQL_DSN 跳过）----

// 登录触发链：同 UA 重复登录不发提醒；换 UA 发一封（品牌随来源 App）；
// login_notify=0 后换 UA 不发。
func TestLoginNotifyTriggerEndToEnd(t *testing.T) {
	svc, mailer := newTestService(t)
	registerViaCode(t, svc, mailer, "login-notify@example.com", "secret123")
	// 注册建的首行会话用 testMeta 的 UA

	countNotify := func() int {
		n := 0
		for _, m := range mailer.sent {
			if strings.HasSuffix(m.subject, "新设备登录提醒") {
				n++
			}
		}
		return n
	}

	const winUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	// ① 同 UA（注册会话的 UA）重复登录：不是新设备，不发
	if _, err := svc.WebLoginPassword("login-notify@example.com", "secret123", testMeta, "calorie-diary"); err != nil {
		t.Fatalf("同 UA 登录失败: %v", err)
	}
	if got := countNotify(); got != 0 {
		t.Fatalf("同 UA 登录不该发提醒，已发 %d 封", got)
	}
	// ② 换 UA：新设备，发一封（App 登录 → 热量日记品牌）
	res, err := svc.WebLoginPassword("login-notify@example.com", "secret123",
		SessionMeta{IP: "203.0.113.9", UserAgent: winUA}, "calorie-diary")
	if err != nil {
		t.Fatalf("新 UA 登录失败: %v", err)
	}
	if got := countNotify(); got != 1 {
		t.Fatalf("换 UA 登录应发 1 封提醒，已发 %d 封", got)
	}
	last := mailer.sent[len(mailer.sent)-1]
	if last.subject != "【热量日记】新设备登录提醒" || last.from != "热量日记" {
		t.Errorf("提醒信主题/发件人应随来源 App 品牌，得到 %q / %q", last.subject, last.from)
	}
	if last.text == "" || !strings.Contains(last.text, "检测到新设备登录") {
		t.Errorf("提醒信缺纯文本降级或内容不对: %q", last.text)
	}
	// ③ 关掉开关（整份 PUT，带档案三字段）：再换 UA 不发
	caller, err := svc.ValidUserID("Bearer " + res.JWT)
	if err != nil {
		t.Fatalf("校验新会话: %v", err)
	}
	off := false
	req := putReq("已关提醒", 0, nil)
	req.LoginNotify = &off
	if _, err := svc.UpdateProfile(caller, req); err != nil {
		t.Fatalf("关提醒开关: %v", err)
	}
	const iosUA = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"
	if _, err := svc.WebLoginPassword("login-notify@example.com", "secret123",
		SessionMeta{IP: "198.51.100.7", UserAgent: iosUA}, "calorie-diary"); err != nil {
		t.Fatalf("第三台设备登录失败: %v", err)
	}
	if got := countNotify(); got != 1 {
		t.Errorf("开关关闭后换 UA 不该再发提醒，已发 %d 封", got)
	}
}
