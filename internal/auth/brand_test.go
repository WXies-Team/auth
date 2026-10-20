package auth

import (
	"strings"
	"testing"

	"github.com/WXies-Team/auth/internal/mail"
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
// （热量、开支两品牌的串与日记服务现有模板一字不差）。
func TestBrandEmailStrings(t *testing.T) {
	cases := []struct {
		app, subject, header, warning, footer, genitive string
	}{
		{"calorie-diary",
			"【热量日记】注册验证码", "热量日记 &middot; 邮箱验证",
			"热量日记不会向你索要验证码，也别把它告诉他人。",
			"热量日记 CalorieDiary", "已成为热量日记账号的绑定邮箱"},
		{"expense-diary",
			"【开支日记】注册验证码", "开支日记 &middot; 邮箱验证",
			"开支日记不会向你索要验证码，也别把它告诉他人。",
			"开支日记 ExpenseDiary", "已成为开支日记账号的绑定邮箱"},
		{"",
			"【Auth】注册验证码", "Auth &middot; 邮箱验证",
			"Auth 不会向你索要验证码，也别把它告诉他人。",
			"Auth auth.horatio.cn", "已成为 Auth 账户的绑定邮箱"},
	}
	for _, c := range cases {
		b := brandFor(c.app)

		subject, body := codeEmail(b, "注册", "123456")
		if subject != c.subject {
			t.Errorf("app=%q 主题应为 %q，得到 %q", c.app, c.subject, subject)
		}
		for _, want := range []string{c.header, c.warning, c.footer, "123456", "5 分钟内有效"} {
			if !strings.Contains(body, want) {
				t.Errorf("app=%q 正文缺 %q", c.app, want)
			}
		}

		// 改绑通知两封：新邮箱那封的属格散文按品牌换，旧邮箱那封主题同源
		newSubject, newBody := changeEmailNoticeEmail(b, true, "old@example.com", "new@example.com")
		if want := b.prefix + "新邮箱已绑定"; newSubject != want {
			t.Errorf("app=%q 新邮箱信主题应为 %q，得到 %q", c.app, want, newSubject)
		}
		if !strings.Contains(newBody, c.genitive) {
			t.Errorf("app=%q 新邮箱信缺属格 %q", c.app, c.genitive)
		}
		oldSubject, _ := changeEmailNoticeEmail(b, false, "old@example.com", "new@example.com")
		if want := b.prefix + "绑定邮箱已更换"; oldSubject != want {
			t.Errorf("app=%q 旧邮箱信主题应为 %q，得到 %q", c.app, want, oldSubject)
		}
		if !strings.Contains(newBody, b.footer) {
			t.Errorf("app=%q 通知信缺落款 %q", c.app, b.footer)
		}
	}
}

// 三品牌头部的内嵌图 cid 必须与 mail 包的内嵌注册表同名（cid = PNG 文件名 + "-icon"），
// 且每封信都真的引用它：对不上就会发出**裂图**——发件箱里看不出来，只有收件人看得见。
func TestBrandEmailInlineIconCID(t *testing.T) {
	seen := map[string]string{} // cid → app，抓「三品牌共用一枚图」的偷懒
	for _, app := range []string{"calorie-diary", "expense-diary", ""} {
		b := brandFor(app)
		if b.icon == "" {
			t.Fatalf("app=%q 的品牌没有内嵌图 cid", app)
		}
		if !mail.HasInlineIcon(b.icon) {
			t.Errorf("app=%q 的 cid %q 在 mail 包里没有对应内嵌 PNG（cid = 文件名 + \"-icon\"）", app, b.icon)
		}
		if other, dup := seen[b.icon]; dup {
			t.Errorf("app=%q 与 app=%q 共用 cid %q，三品牌该各带各的图", app, other, b.icon)
		}
		seen[b.icon] = app

		_, codeBody := codeEmail(b, "注册", "123456")
		_, noticeBody := changeEmailNoticeEmail(b, true, "old@example.com", "new@example.com")
		for name, body := range map[string]string{"验证码信": codeBody, "改绑通知": noticeBody} {
			if !strings.Contains(body, `src="cid:`+b.icon+`"`) {
				t.Errorf("app=%q 的%s正文缺 cid 引用 %q", app, name, b.icon)
			}
			// 图标属性三件套：alt（读屏）、显式宽高（版面不随图片加载抖动）、border=0
			for _, attr := range []string{` alt="`, ` width="44"`, ` height="44"`, `border="0"`} {
				if !strings.Contains(body, attr) {
					t.Errorf("app=%q 的%s里图标缺属性 %q", app, name, attr)
				}
			}
		}
	}
}
