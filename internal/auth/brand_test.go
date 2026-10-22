package auth

import (
	"strings"
	"testing"
	"time"
)

// 品牌注册表的取值：两个 App 各回各的串；缺省与未知一律中性品牌 Auth。
func TestBrandForSelection(t *testing.T) {
	cases := []struct{ app, name, prefix, footer string }{
		{"calorie-diary", "热量日记", "【热量日记】", "热量日记 CalorieDiary"},
		{"expense-diary", "开支日记", "【开支日记】", "开支日记 ExpenseDiary"},
		{"", "Auth", "【Auth】", "Auth auth.horatio.cn"},
		{"evil-app", "Auth", "【Auth】", "Auth auth.horatio.cn"},
	}
	for _, c := range cases {
		b := brandFor(c.app)
		if b.name != c.name || b.prefix != c.prefix || b.footer != c.footer {
			t.Errorf("brandFor(%q) = %+v，应为 name=%q prefix=%q footer=%q",
				c.app, b, c.name, c.prefix, c.footer)
		}
		// 落款恒为「name + 空格 + latin」：改名只改一处，四个串不会各漂各的
		if b.footer != b.name+" "+b.latin {
			t.Errorf("%q 的落款应为 name 与 latin 用空格相连，得到 %q（name=%q latin=%q）",
				c.app, b.footer, b.name, b.latin)
		}
	}

	// 注册表键与 JWT aud 白名单必须同集：漏一个键，那个 App 的验证码邮件就掉进
	// 中性品牌——用户在 App 里却收到一封「Auth」的信，正是这次分品牌要防的事。
	if len(brands) != len(allowedApps) {
		t.Errorf("brands 有 %d 个、allowedApps 有 %d 个，数量不一致", len(brands), len(allowedApps))
	}
	for app := range allowedApps {
		if _, ok := brands[app]; !ok {
			t.Errorf("白名单应用 %q 没有品牌条目", app)
		}
	}
}

// 三品牌选串：同一套外壳，主题前缀 / 头部行 / 警示句 / 落款 / 改绑属格逐条照抄定案表
// （热量、开支两品牌的串与日记服务现有模板一字不差）。警示句已按业界对标强化为
//「品牌句 + 无人索码句」（勿分享句的定案新文案，见 codeEmail），品牌可变部分仍走 b.join。
func TestBrandEmailStrings(t *testing.T) {
	cases := []struct {
		app, subject, header, warning, footer, genitive string
	}{
		{"calorie-diary",
			"【热量日记】注册验证码", "热量日记 &middot; 邮箱验证",
			"热量日记不会向你索要验证码。包括平台工作人员在内，任何人都不会向你索要此码——若有人索要，请立即举报。",
			"热量日记 CalorieDiary", "已成为热量日记账号的绑定邮箱"},
		{"expense-diary",
			"【开支日记】注册验证码", "开支日记 &middot; 邮箱验证",
			"开支日记不会向你索要验证码。包括平台工作人员在内，任何人都不会向你索要此码——若有人索要，请立即举报。",
			"开支日记 ExpenseDiary", "已成为开支日记账号的绑定邮箱"},
		{"",
			"【Auth】注册验证码", "Auth &middot; 邮箱验证",
			"Auth 不会向你索要验证码。包括平台工作人员在内，任何人都不会向你索要此码——若有人索要，请立即举报。",
			"Auth auth.horatio.cn", "已成为 Auth 账户的绑定邮箱"},
	}
	for _, c := range cases {
		b := brandFor(c.app)

		subject, body, text := codeEmail(b, "注册", "123456")
		if subject != c.subject {
			t.Errorf("app=%q 主题应为 %q，得到 %q", c.app, c.subject, subject)
		}
		for _, want := range []string{c.header, c.warning, c.footer, "123456", "5 分钟内有效"} {
			if !strings.Contains(body, want) {
				t.Errorf("app=%q 正文缺 %q", c.app, want)
			}
		}
		// 纯文本降级与 HTML 同源同要素（multipart/alternative 的 text/plain 部件）
		for _, want := range []string{c.warning, c.footer, "123456", "此邮件不可回复"} {
			if !strings.Contains(text, want) {
				t.Errorf("app=%q 纯文本版缺 %q", c.app, want)
			}
		}

		// 改绑通知两封：新邮箱那封的属格散文按品牌换，旧邮箱那封主题同源
		newSubject, newBody, _ := changeEmailNoticeEmail(b, true, "old@example.com", "new@example.com")
		if want := b.prefix + "新邮箱已绑定"; newSubject != want {
			t.Errorf("app=%q 新邮箱信主题应为 %q，得到 %q", c.app, want, newSubject)
		}
		if !strings.Contains(newBody, c.genitive) {
			t.Errorf("app=%q 新邮箱信缺属格 %q", c.app, c.genitive)
		}
		oldSubject, _, _ := changeEmailNoticeEmail(b, false, "old@example.com", "new@example.com")
		if want := b.prefix + "绑定邮箱已更换"; oldSubject != want {
			t.Errorf("app=%q 旧邮箱信主题应为 %q，得到 %q", c.app, want, oldSubject)
		}
		if !strings.Contains(newBody, b.footer) {
			t.Errorf("app=%q 通知信缺落款 %q", c.app, b.footer)
		}
	}
}

// 三品牌头部的托管 logo：src 是 https://auth.horatio.cn/brand/<slug>-v1.png、带
// alt 与显式宽高、外层 td 刷品牌主色（裂图时露出的也是品牌色块），且每封信都真的
// 引用它——对不上就会发出**裂图**，logoPath 与静态路由/生成器三方同口径。
func TestBrandEmailLogoURL(t *testing.T) {
	seen := map[string]string{} // logoPath → app，抓「三品牌共用一张图」的偷懒
	for _, app := range []string{"calorie-diary", "expense-diary", ""} {
		b := brandFor(app)
		if b.logoPath == "" || !strings.HasPrefix(b.logoPath, "/brand/") {
			t.Fatalf("app=%q 的品牌缺 /brand/ logo 路径（得到 %q）", app, b.logoPath)
		}
		if other, dup := seen[b.logoPath]; dup {
			t.Errorf("app=%q 与 app=%q 共用 logo %q，三品牌该各有各的图", app, other, b.logoPath)
		}
		seen[b.logoPath] = app

		_, codeBody, _ := codeEmail(b, "注册", "123456")
		_, noticeBody, _ := changeEmailNoticeEmail(b, true, "old@example.com", "new@example.com")
		for name, body := range map[string]string{"验证码信": codeBody, "改绑通知": noticeBody} {
			if !strings.Contains(body, `src="`+b.logoURL()+`"`) {
				t.Errorf("app=%q 的%s正文缺 logo 引用 %q", app, name, b.logoURL())
			}
			// 图标属性：alt（Yahoo 不渲染 alt 的兜底靠旁边的品牌名 live 文本）、
			// 显式宽高（版面不随图片加载抖动）
			for _, want := range []string{
				` alt="` + b.name + `"`, ` width="48"`, ` height="48"`, `border="0"`,
				`>` + b.name + `</span>`,
			} {
				if !strings.Contains(body, want) {
					t.Errorf("app=%q 的%s缺 %q", app, name, want)
				}
			}
		}
		// 品牌主色底随「真按钮」走：验证码信按定案零按钮（「前往账号台」已降级为
		// 正文内联文字链接），主色 <td bgcolor> 只钉仍有主按钮的通知信
		if !strings.Contains(noticeBody, `bgcolor="`+b.primaryHex+`"`) {
			t.Errorf("app=%q 的改绑通知缺主色按钮底 %q", app, b.primaryHex)
		}
		if !strings.Contains(codeBody, `<a href="`+accountURL+`" style="color:`+b.primaryHex) {
			t.Errorf("app=%q 的验证码信应把「前往账号台」排成正文内联文字链", app)
		}
	}
}

// 新外壳的结构性钉子（每品牌抽查验证码信 + 新登录提醒）：HTML 与纯文本并存、
// 按钮 bulletproof（VML 兜底、指标在 td、HTML 不挂裸 URL——降级 URL 归 text 部件）、不出现纯白底/纯黑字、
// 没有模板渲染错误标记。
func TestEmailShellStructure(t *testing.T) {
	for _, app := range []string{"calorie-diary", "expense-diary", ""} {
		b := brandFor(app)
		rendered := map[string][2]string{
			"验证码信": func() [2]string {
				_, h, x := codeEmail(b, "注册", "123456")
				return [2]string{h, x}
			}(),
			"新登录提醒": func() [2]string {
				_, h, x := loginNotifyEmail(b, "Pixel 8", "热量日记", time.Unix(1761000000, 0))
				return [2]string{h, x}
			}(),
		}
		for name, r := range rendered {
			htmlBody, text := r[0], r[1]
			if htmlBody == "" || text == "" {
				t.Fatalf("app=%q 的%s HTML/纯文本有空版本", app, name)
			}
			for _, bad := range []string{"%!", "#FFFFFF;background-color:#FFFFFF", "color:#000000"} {
				if strings.Contains(htmlBody, bad) {
					t.Errorf("app=%q 的%s含 %q", app, name, bad)
				}
			}
			for _, want := range []string{`role="presentation"`, "此邮件不可回复"} {
				if !strings.Contains(htmlBody, want) {
					t.Errorf("app=%q 的%s缺 %q", app, name, want)
				}
			}
			if strings.Contains(htmlBody, "cid:") {
				t.Errorf("app=%q 的%s还引用 cid（已改托管 logo）", app, name)
			}
		}
		// VML 兜底随「真按钮」走：验证码信按业界对标零 CTA 按钮（「前往账号台」是
		// 正文内联文字链接），mso 兜底由仍带主按钮的新登录提醒钉住；验证码信同时
		// 钉住内联链形态，防止按钮被悄悄加回来
		if !strings.Contains(rendered["新登录提醒"][0], "<!--[if mso]>") {
			t.Errorf("app=%q 的新登录提醒缺按钮的 VML 兜底", app)
		}
		if codeHTML := rendered["验证码信"][0]; strings.Contains(codeHTML, "<!--[if mso]>") ||
			!strings.Contains(codeHTML, `<a href="`+accountURL+`" style="color:`+b.primaryHex+`;text-decoration:underline;">前往账号台</a>`) {
			t.Errorf("app=%q 的验证码信应零按钮、账号台入口为内联文字链", app)
		}
	}
}

// 全模板双形态抽查（W2 迁移完成的钉子）：每个模板每品牌都产出 subject/html/text
// 三件套；HTML 带托管 logo 与落款、纯文本带落款与「此邮件不可回复」、两者都没有
// 模板渲染错误标记或已废弃的 cid 引用。
func TestAllEmailTemplatesRenderBothParts(t *testing.T) {
	at := time.Unix(1761000000, 0)
	const cancelURL = "https://auth.horatio.cn/web/delete-cancel?token=abc123"
	for _, app := range []string{"calorie-diary", "expense-diary", ""} {
		b := brandFor(app)
		mails := map[string]func() (string, string, string){
			"验证码":     func() (string, string, string) { return codeEmail(b, "注册", "123456") },
			"改绑新邮箱":  func() (string, string, string) { return changeEmailNoticeEmail(b, true, "old@example.com", "new@example.com") },
			"改绑旧邮箱":  func() (string, string, string) { return changeEmailNoticeEmail(b, false, "old@example.com", "new@example.com") },
			"管理员改邮新": func() (string, string, string) { return adminChangeEmailNoticeEmail(b, true, "old@example.com", "new@example.com") },
			"管理员改邮旧": func() (string, string, string) { return adminChangeEmailNoticeEmail(b, false, "old@example.com", "new@example.com") },
			"管理员重置":  func() (string, string, string) { return passwordResetNoticeEmail(b, "TempPass123") },
			"改密确认":   func() (string, string, string) { return passwordChangedNoticeEmail(b, at) },
			"注销确认":   func() (string, string, string) { return deleteRequestEmail(b, cancelURL, at) },
			"注销撤销":   func() (string, string, string) { return deleteCancelledEmail(b) },
			"注销完成":   func() (string, string, string) { return deleteDoneEmail(b) },
			"新登录提醒":  func() (string, string, string) { return loginNotifyEmail(b, "Pixel 8", "热量日记", at) },
		}
		for name, build := range mails {
			subject, htmlBody, text := build()
			if subject == "" || !strings.HasPrefix(subject, b.prefix) {
				t.Errorf("app=%q 的%s主题应带品牌前缀，得到 %q", app, name, subject)
			}
			if htmlBody == "" || text == "" {
				t.Fatalf("app=%q 的%s缺 HTML 或纯文本版本", app, name)
			}
			for _, want := range []string{b.logoURL(), b.footer, `role="presentation"`} {
				if !strings.Contains(htmlBody, want) {
					t.Errorf("app=%q 的%s HTML 缺 %q", app, name, want)
				}
			}
			for _, want := range []string{b.footer, "此邮件不可回复"} {
				if !strings.Contains(text, want) {
					t.Errorf("app=%q 的%s纯文本缺 %q", app, name, want)
				}
			}
			for _, bad := range []string{"%!", "cid:"} {
				if strings.Contains(htmlBody, bad) {
					t.Errorf("app=%q 的%s HTML 含 %q", app, name, bad)
				}
			}
		}
	}
}
