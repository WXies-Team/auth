package auth

import (
	"html"
	"log/slog"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// 邮件模板：**结构一套、品牌按 app 换**。本服务统一为两个日记签发验证码与改绑通知，
// 收件人看到的应是自己在用的那个 App 的名字——主题前缀、头部行、警示句、落款、
// 发件人显示名与托管 logo 都取自下面的品牌注册表；缺省或空 app 用中性品牌 Auth
//（统一账号服务不借任何 App 的名头，也是将来 web 账号台的默认品牌）。
//
// 外壳是本批拍板的新设计规范：
//   - 600px 版心、表格布局、**全内联样式**（Gmail/Outlook 会剥 <style>，不依赖它）；
//   - 每封信 **multipart/alternative：text/html + text/plain**（mail 包拼装），
//     text/plain 由各模板逐封给出，是 HTML 的忠实降级；
//   - 按钮是 bulletproof 形态：<a> 上 bgcolor + VML [if mso] 兜底 + 内边距，
//     **每个按钮下方附纯文本 URL**（纯文本客户端与图片屏蔽场景的出路）；
//   - **抗客户端深色反转**：不出现纯白底/纯黑字（画布 #F1F4F9、卡片 #FAFBFD、
//     正文 #1F2430），按钮色同时写在 <td bgcolor> 上；不追 prefers-color-scheme，
//     深色由客户端自己反色即可；
//   - logo 走 https 托管图（/brand/<slug>-v1.png，internal/ui 静态路由），
//     外层 td 刷品牌主色（裂图时露出的也是品牌色块），品牌名以 live 文本并排
//     （Yahoo 不渲染 alt 的兜底）；**logo 不挂链接**。
//
// 文案四段式：首句发生了什么 → 细节列表（时间/设备等，有则列）→「不是我」/
// 行动入口 → 页脚（落款品牌名 + 此邮件不可回复）。第二人称短句、不堆感叹号。

// siteBase 是托管资产与控制台链接的域名常量。邮件里的 https 链接全部由它拼出
// ——模板不接用户输入的 URL。
const siteBase = "https://auth.horatio.cn"

// accountURL 是模板里唯一的自助落点：账号台（自助台），未登录会 302 到登录页。
const accountURL = siteBase + "/web/console/account"

// brand 是一个品牌的全部可换串：外壳共用，换品牌就是换这几个字段。
type brand struct {
	name   string // 品牌名：头部行、警示句、发件人显示名（热量日记 / 开支日记 / Auth）
	latin  string // 落款第二段：App 拉丁名或域名（CalorieDiary / ExpenseDiary / auth.horatio.cn）
	footer string // 落款整串，形如「<name> <latin>」
	prefix string // 主题前缀，如 「【热量日记】」
	// account 是改绑通知里的属格串。中文品牌直接相接（热量日记账号）；中性品牌按
	// 作者定案用「账户」且拉丁名前留一个空格（" Auth 账户"）——中英混排的空格只在这里
	// 与 join 出现，模板不再逐处手写。
	account string
	// primaryHex 是品牌主色（按钮底、logo 外层 td 底）：两个 App 与中性品牌都用
	// auth web 的 --primary token 同源色值（#3482FF，正文走灰阶）。
	primaryHex string
	// logoPath 是托管 logo 的站内路径（/brand/<slug>-v1.png，internal/ui 静态路由，
	// scripts/genicons 生成）。品牌表按此口径引用，brand_test 逐个断言非空。
	logoPath string
}

// logoURL 返回邮件里 <img src> 的绝对地址（托管图，非 cid）。
func (b brand) logoURL() string { return siteBase + b.logoPath }

// brands 品牌注册表：键与 JWT aud 白名单（allowedApps）同集，两处一起加。
var brands = map[string]brand{
	"calorie-diary": {
		name: "热量日记", latin: "CalorieDiary", footer: "热量日记 CalorieDiary",
		prefix: "【热量日记】", account: "热量日记账号",
		primaryHex: "#3482FF", logoPath: "/brand/calorie-diary-v1.png",
	},
	"expense-diary": {
		name: "开支日记", latin: "ExpenseDiary", footer: "开支日记 ExpenseDiary",
		prefix: "【开支日记】", account: "开支日记账号",
		primaryHex: "#3482FF", logoPath: "/brand/expense-diary-v1.png",
	},
}

// neutralBrand 是缺省品牌 Auth：SendCodeRequest.app 没给（web 账号台口径）与所有
// 拿不到 app 的发信场合都用它。
var neutralBrand = brand{
	name: "Auth", latin: "auth.horatio.cn", footer: "Auth auth.horatio.cn",
	prefix: "【Auth】", account: " Auth 账户",
	primaryHex: "#3482FF", logoPath: "/brand/auth-v1.png",
}

// brandFor 按 app 取品牌，空与未知都回 Auth：非法 app 在上游已被 validateApp 挡成
// 400（或来自 JWT aud 白名单），这里不重复报错，兜底中性品牌最稳。
func brandFor(app string) brand {
	if b, ok := brands[app]; ok {
		return b
	}
	return neutralBrand
}

// join 把品牌名与后接的中文连起来：拉丁名（Auth）补一个空格，中文名不补。
// 中英混排的空格规则集中在这里，模板不逐处手写。
func (b brand) join(zh string) string {
	if b.name != "" && b.name[0] < utf8.RuneSelf {
		return b.name + " " + zh
	}
	return b.name + zh
}

// ---- 外壳组件（全站唯一一套）----

// emailFont 是邮件正文的字体栈：Apple 起手，中文字体依次 PingFang / HarmonyOS Sans /
// MiSans，回落 system-ui / Arial。邮件不能嵌字体，栈是客户端自选的。
const emailFont = `font-family:-apple-system,"PingFang SC","HarmonyOS Sans","MiSans",system-ui,Arial,sans-serif;`

// 外壳色板（抗反转口径：不出现 #FFFFFF 大底与 #000000 正文）。
const (
	mailCanvas  = "#F1F4F9" // 画布
	mailCard    = "#FAFBFD" // 主卡片
	mailInk     = "#1F2430" // 主文
	mailSub     = "#646B7A" // 次文
	mailDim     = "#8C93B0" // 页脚/纯文本 URL
	mailHair    = "#E7EAEF" // 分隔线
	mailCodeBox = "#E8F0FE" // 验证码卡底（品牌主色的淡版）
	mailTipBox  = "#F0F2F5" // 提示卡底
	mailWarn    = "#E94634" // 「不是我」警示红
)

// brandEyebrow 是卡片里的次文眉题（品牌名 · 场景）。
func brandEyebrow(b brand, scene string) string {
	return `            <p style="` + emailFont + `margin:0 0 10px;font-size:16px;line-height:1.5;color:` + mailSub + `;">` + b.name + ` &middot; ` + scene + `</p>
`
}

// brandEyebrowText 是眉题的纯文本降级。
func brandEyebrowText(b brand, scene string) string { return b.name + " · " + scene }

// ctaButton 是主按钮样式（bulletproof 形态，可多 CTA 并用，如登录提醒的双深链）：<a> 上 bgcolor +
// VML [if mso] 兜底 + 内边距顶高（line-height 48px，不依赖盒模型差异）。
// 按钮下方附纯文本 URL：纯文本客户端、图片屏蔽与复制粘贴场景都有出路。
func ctaButton(b brand, label, href string) string {
	// VML 宽度按标签字数估（Outlook 只认这条路径，宁可偏宽也别截字）
	width := 56 + 17*utf8.RuneCountInString(label)
	return `            <table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin:24px 0 0;">
              <tr>
                <td align="center" bgcolor="` + b.primaryHex + `" style="background-color:` + b.primaryHex + `;border-radius:16px;">
                  <!--[if mso]>
                  <v:roundrect xmlns:v="urn:schemas-microsoft-com:vml" xmlns:w="urn:schemas-microsoft-com:office:word" href="` + href + `" style="height:48px;v-text-anchor:middle;width:` + strconv.Itoa(width) + `px;" arcsize="34%" stroke="f" fillcolor="` + b.primaryHex + `">
                    <w:anchorlock/>
                    <center style="color:#FFFFFF;font-family:Arial,sans-serif;font-size:17px;">` + label + `</center>
                  </v:roundrect>
                  <![endif]-->
                  <a href="` + href + `" style="` + emailFont + `display:inline-block;padding:0 28px;line-height:48px;font-size:17px;font-weight:400;color:#FFFFFF;text-decoration:none;border-radius:16px;">` + label + `</a>
                </td>
              </tr>
            </table>
            <p style="` + emailFont + `margin:8px 0 0;font-size:13px;line-height:1.6;color:` + mailDim + `;">` + href + `</p>
`
}

// ctaText 是按钮的纯文本降级：标签一行 + URL 一行。
func ctaText(label, href string) string { return label + "\n" + href }

// emailShell 包一层新外壳（HTML 版）：head（charset/viewport/color-scheme: light）
// + 隐藏 preheader + 600px 卡片 + 品牌头（托管 logo + 品牌名 live 文本）+ inner
// + 页脚（落款 + 此邮件不可回复 + ©）。
func emailShell(b brand, preheader, inner string) string {
	return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light">
<meta name="supported-color-schemes" content="light">
<title>` + html.EscapeString(b.name) + `</title>
</head>
<body style="margin:0;padding:0;background-color:` + mailCanvas + `;">
<div style="display:none;font-size:1px;line-height:1px;max-height:0;max-width:0;opacity:0;overflow:hidden;mso-hide:all;">` + preheader + `&#8199;&#65279;&#8199;&#65279;&#8199;&#65279;&#8199;&#65279;&#8199;&#65279;</div>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="` + mailCanvas + `" style="background-color:` + mailCanvas + `;">
  <tr>
    <td align="center" style="padding:32px 12px;">
      <table role="presentation" width="600" cellpadding="0" cellspacing="0" border="0" bgcolor="` + mailCard + `" style="width:100%;max-width:600px;background-color:` + mailCard + `;border-radius:24px;">
        <tr>
          <td style="padding:28px 32px 32px;">
            <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="margin:0 0 20px;">
              <tr>
                <td bgcolor="` + b.primaryHex + `" style="background-color:` + b.primaryHex + `;padding:8px;border-radius:16px;vertical-align:middle;"><img src="` + b.logoURL() + `" width="48" height="48" alt="` + html.EscapeString(b.name) + `" border="0" style="display:block;width:48px;height:48px;border:0;"></td>
                <td style="padding:0 12px;vertical-align:middle;"><span style="` + emailFont + `font-size:17px;font-weight:400;line-height:1.3;color:` + mailInk + `;">` + b.name + `</span></td>
              </tr>
            </table>
` + inner + `
            <hr style="border:0;border-top:1px solid ` + mailHair + `;margin:28px 0 16px;">
            <p style="` + emailFont + `margin:0 0 4px;font-size:13px;line-height:1.6;color:` + mailDim + `;">` + b.footer + `</p>
            <p style="` + emailFont + `margin:0 0 4px;font-size:13px;line-height:1.6;color:` + mailDim + `;">此邮件不可回复。</p>
            <p style="` + emailFont + `margin:0;font-size:13px;line-height:1.6;color:` + mailDim + `;">© 2026·屑涵</p>
          </td>
        </tr>
      </table>
    </td>
  </tr>
</table>
</body>
</html>`
}

// footText 是纯文本版页脚的落款段（模板把它拼在正文之后）。
func footText(b brand) string {
	return b.footer + "\n此邮件不可回复\n© 2026·屑涵"
}

// mailLog 发信失败要留排障线索：客户端只看到白话，根因（Graph 状态码/响应体）只在
// 服务端日志。邮箱过 maskEmail 脱敏——日志会进排障链路与备份，全文邮箱是 PII。
func mailLog(err error, purpose, email string) {
	slog.Error("发送邮件失败", "purpose", purpose, "email", maskEmail(email), "err", err)
}

// safeTime 是通知信里时间戳的统一形态（本地时区，分钟精度够用户对时）。
func safeTime(t time.Time) string { return t.Format("2006-01-02 15:04") }

// codeEmail 拼验证码信（注册 / 找回密码 / 修改密码 / 登录 / 登录两步验证 / 修改邮箱
// 六类共用）：眉题 → 标题与一句话说明 → 验证码卡 + 有效期 → 单 CTA → 提示卡 →
// 红警示句。
//
// action 只会是上述六个字面量之一（由 purpose 分流，不来自用户输入），code 只含
// 数字——两处都没有 HTML 注入面。
func codeEmail(b brand, action, code string) (subject, htmlBody, text string) {
	subject = b.prefix + action + "验证码"
	inner := brandEyebrow(b, "邮箱验证") + `            <h1 style="` + emailFont + `margin:0 0 8px;font-size:20px;font-weight:400;line-height:1.4;color:` + mailInk + `;">` + action + `验证码</h1>
            <p style="` + emailFont + `margin:0 0 24px;font-size:16px;line-height:1.6;color:` + mailInk + `;">在应用里输入下面的验证码，继续` + action + `。</p>
            <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="` + mailCodeBox + `" style="width:100%;background-color:` + mailCodeBox + `;border-radius:20px;">
              <tr>
                <td align="center" style="padding:26px 12px 22px;">
                  <div class="code" style="` + emailFont + `margin:0;font-size:32px;font-weight:400;line-height:1.2;letter-spacing:10px;text-indent:10px;text-align:center;color:` + mailInk + `;">` + code + `</div>
                  <p style="` + emailFont + `margin:10px 0 0;font-size:13px;line-height:1.6;color:` + mailSub + `;">5 分钟内有效</p>
                </td>
              </tr>
            </table>
` + ctaButton(b, "前往账号台", accountURL) + `            <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="` + mailTipBox + `" style="width:100%;background-color:` + mailTipBox + `;border-radius:16px;margin:24px 0 0;">
              <tr>
                <td style="` + emailFont + `padding:16px 18px;font-size:16px;line-height:1.6;color:` + mailSub + `;">不是你操作？忽略这封邮件即可，账号不会有任何变化。</td>
              </tr>
            </table>
            <p style="` + emailFont + `margin:16px 0 0;font-size:16px;line-height:1.6;color:` + mailWarn + `;">` + b.join("不会向你索要验证码，也别把它告诉他人。") + `</p>`
	text = brandEyebrowText(b, "邮箱验证") + `

` + action + `验证码

在应用里输入下面的验证码，继续` + action + `。

` + code + `
5 分钟内有效

` + ctaText("前往账号台", accountURL) + `

不是你操作？忽略这封邮件即可，账号不会有任何变化。

` + b.join("不会向你索要验证码，也别把它告诉他人。") + `

——
` + footText(b)
	preheader := action + "验证码 5 分钟内有效，" + b.name + "不会向你索要验证码。"
	return subject, emailShell(b, preheader, inner), text
}

// changeEmailNoticeEmail 改绑邮箱后的通知信（旧、新邮箱各一封）：说清「哪个邮箱变成了
// 什么」，再给非本人操作时的下一步（红纯文字警示 + 单 CTA）——两句一事。
// 邮箱进正文前先 html.EscapeString：validateEmail 的正则不拦 `<>&`，不转义就是注入面。
func changeEmailNoticeEmail(b brand, toNew bool, oldEmail, newEmail string) (subject, htmlBody, text string) {
	oldE, newE := html.EscapeString(oldEmail), html.EscapeString(newEmail)
	var title, lead, next string
	if toNew {
		subject = b.prefix + "新邮箱已绑定"
		title = "新邮箱已绑定"
		lead = newE + " 已成为" + b.account + "的绑定邮箱（原绑定邮箱 " + oldE + "），该账号的验证码会发到这里。"
		next = "不是你操作？请立刻让账号主人把邮箱改回去。"
	} else {
		subject = b.prefix + "绑定邮箱已更换"
		title = "绑定邮箱已更换"
		lead = "你的账号绑定邮箱已由 " + oldE + " 改为 " + newE + "。"
		next = "不是你操作？请立刻用「找回密码」重置密码。"
	}
	inner := brandEyebrow(b, "账号安全") + `            <h1 style="` + emailFont + `margin:0 0 8px;font-size:20px;font-weight:400;line-height:1.4;color:` + mailInk + `;">` + title + `</h1>
            <p style="` + emailFont + `margin:0 0 20px;font-size:16px;line-height:1.6;color:` + mailInk + `;">` + lead + `</p>
            <p style="` + emailFont + `margin:0 0 4px;font-size:16px;line-height:1.6;color:` + mailWarn + `;">` + next + `</p>
` + ctaButton(b, "管理账号", accountURL)
	text = brandEyebrowText(b, "账号安全") + `

` + title + `

` + stripTags(lead) + `

` + next + `

` + ctaText("管理账号", accountURL) + `

——
` + footText(b)
	preheader := title + "。" + next
	return subject, emailShell(b, preheader, inner), text
}

// stripTags 是纯文本降级的小工具：模板散文里的品牌属格串可能带 html.EscapeString
// 过的 `<>&` 实体，纯文本版要还原成原字符（只处理这三种实体，不引 regexp）。
func stripTags(s string) string {
	r := strings.NewReplacer("&lt;", "<", "&gt;", ">", "&amp;", "&")
	return r.Replace(s)
}

// ---- 账号生命周期五封信（密码重置 / 改密确认 / 注销确认 / 注销撤销 / 注销完成）----
//
// 五封都是**账号级**通知（与具体 App 无关），品牌走 brandFor("") = 中性 Auth
//（subject 前缀【Auth】，契约钉死）——auth 是统一账号服务，不借任何 App 的名头
// 说「你的热量日记账号被注销了」这类话（AGENTS §7：auth 的文案永远是通用口径）。

// passwordResetNoticeEmail 管理员重置密码的通知信（W1，notify=true 时发）：
// 场景 + 临时密码本体 + 下次登录必须修改 + 非本人操作找管理员——正文最小化，
// 不带 uid、角色、操作者等任何额外账号信息。
func passwordResetNoticeEmail(b brand, temporary string) (subject, htmlBody, text string) {
	subject = b.prefix + "密码重置通知"
	inner := brandEyebrow(b, "账号安全") + `            <h1 style="` + emailFont + `margin:0 0 8px;font-size:20px;font-weight:400;line-height:1.4;color:` + mailInk + `;">你的密码已被管理员重置</h1>
            <p style="` + emailFont + `margin:0 0 24px;font-size:16px;line-height:1.6;color:` + mailInk + `;">你的密码已被管理员重置为下面的临时密码：</p>
            <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="` + mailCodeBox + `" style="width:100%;background-color:` + mailCodeBox + `;border-radius:20px;">
              <tr>
                <td align="center" style="padding:26px 12px 22px;">
                  <div class="code" style="` + emailFont + `margin:0;font-size:26px;font-weight:400;line-height:1.3;letter-spacing:2px;text-align:center;color:` + mailInk + `;">` + html.EscapeString(temporary) + `</div>
                </td>
              </tr>
            </table>
            <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="` + mailTipBox + `" style="width:100%;background-color:` + mailTipBox + `;border-radius:16px;margin:24px 0 0;">
              <tr>
                <td style="` + emailFont + `padding:16px 18px;font-size:16px;line-height:1.6;color:` + mailSub + `;">请在下次登录时修改密码。</td>
              </tr>
            </table>
            <p style="` + emailFont + `margin:16px 0 0;font-size:16px;line-height:1.6;color:` + mailWarn + `;">不是你本人操作？请联系管理员。</p>`
	text = brandEyebrowText(b, "账号安全") + `

你的密码已被管理员重置

你的密码已被管理员重置为下面的临时密码：

` + temporary + `

请在下次登录时修改密码。

不是你本人操作？请联系管理员。

——
` + footText(b)
	preheader := "你的密码已被管理员重置，请在下次登录时修改密码。"
	return subject, emailShell(b, preheader, inner), text
}

// passwordChangedNoticeEmail 自助改密成功后的确认信（Okta 口径：时间 + 入口，
// **不含任何密码字段**）——用户没主动改却收到这封信，就是账号出事的信号。
func passwordChangedNoticeEmail(b brand, at time.Time) (subject, htmlBody, text string) {
	subject = b.prefix + "密码已修改"
	inner := brandEyebrow(b, "账号安全") + `            <h1 style="` + emailFont + `margin:0 0 8px;font-size:20px;font-weight:400;line-height:1.4;color:` + mailInk + `;">密码已修改</h1>
            <p style="` + emailFont + `margin:0 0 20px;font-size:16px;line-height:1.6;color:` + mailInk + `;">你的账号密码已于 ` + safeTime(at) + ` 修改成功。</p>
            <p style="` + emailFont + `margin:0 0 4px;font-size:16px;line-height:1.6;color:` + mailWarn + `;">不是你本人操作？请立刻用「找回密码」重置密码。</p>
` + ctaButton(b, "管理账号", accountURL)
	text = brandEyebrowText(b, "账号安全") + `

密码已修改

你的账号密码已于 ` + safeTime(at) + ` 修改成功。

不是你本人操作？请立刻用「找回密码」重置密码。

` + ctaText("管理账号", accountURL) + `

——
` + footText(b)
	preheader := "你的账号密码已于 " + safeTime(at) + " 修改成功。"
	return subject, emailShell(b, preheader, inner), text
}

// deleteRequestEmail 注销申请的确认信（W3）：后果清单 + 到期执行时间 + 撤销链接。
// cancelURL 是完整撤销链接（token 已内嵌，服务端拼好；模板不接用户输入）。
func deleteRequestEmail(b brand, cancelURL string, dueAt time.Time) (subject, htmlBody, text string) {
	subject = b.prefix + "注销确认"
	inner := brandEyebrow(b, "账号注销") + `            <h1 style="` + emailFont + `margin:0 0 8px;font-size:20px;font-weight:400;line-height:1.4;color:` + mailInk + `;">注销申请已提交</h1>
            <p style="` + emailFont + `margin:0 0 16px;font-size:16px;line-height:1.6;color:` + mailInk + `;">我们已收到你注销账号的申请，将于 ` + safeTime(dueAt) + ` 执行。执行后：</p>
            <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="` + mailTipBox + `" style="width:100%;background-color:` + mailTipBox + `;border-radius:16px;margin:0 0 4px;">
              <tr>
                <td style="` + emailFont + `padding:16px 18px;font-size:16px;line-height:1.8;color:` + mailSub + `;">1. 名下所有项目一并注销；<br>2. 全部数据清空，不可恢复。</td>
              </tr>
            </table>
` + ctaButton(b, "点击此链接撤销注销", cancelURL) + `            <p style="` + emailFont + `margin:16px 0 0;font-size:16px;line-height:1.6;color:` + mailWarn + `;">不是你本人操作？请立刻点击上方链接撤销，并联系管理员。</p>`
	text = brandEyebrowText(b, "账号注销") + `

注销申请已提交

我们已收到你注销账号的申请，将于 ` + safeTime(dueAt) + ` 执行。执行后：

1. 名下所有项目一并注销；
2. 全部数据清空，不可恢复。

` + ctaText("点击此链接撤销注销", cancelURL) + `

不是你本人操作？请立刻点击上方链接撤销，并联系管理员。

——
` + footText(b)
	preheader := "注销将于 " + safeTime(dueAt) + " 执行，点击链接可撤销。"
	return subject, emailShell(b, preheader, inner), text
}

// deleteCancelledEmail 注销已撤销的通知信：只报事实与「非本人怎么办」，不带链接。
func deleteCancelledEmail(b brand) (subject, htmlBody, text string) {
	subject = b.prefix + "注销已撤销"
	inner := brandEyebrow(b, "账号注销") + `            <h1 style="` + emailFont + `margin:0 0 8px;font-size:20px;font-weight:400;line-height:1.4;color:` + mailInk + `;">注销已撤销</h1>
            <p style="` + emailFont + `margin:0 0 20px;font-size:16px;line-height:1.6;color:` + mailInk + `;">你的账号注销申请已撤销，账号与数据一切如常。</p>
            <p style="` + emailFont + `margin:0 0 4px;font-size:16px;line-height:1.6;color:` + mailWarn + `;">不是你本人操作？请立刻修改密码并检查登录设备。</p>
` + ctaButton(b, "管理账号", accountURL)
	text = brandEyebrowText(b, "账号注销") + `

注销已撤销

你的账号注销申请已撤销，账号与数据一切如常。

不是你本人操作？请立刻修改密码并检查登录设备。

` + ctaText("管理账号", accountURL) + `

——
` + footText(b)
	preheader := "你的账号注销申请已撤销，账号与数据一切如常。"
	return subject, emailShell(b, preheader, inner), text
}

// deleteDoneEmail 注销完成的通知信：永久删除、不可恢复、**无任何链接**
//（账号已不存在，再给入口就是死链）。
func deleteDoneEmail(b brand) (subject, htmlBody, text string) {
	subject = b.prefix + "注销已完成"
	inner := brandEyebrow(b, "账号注销") + `            <h1 style="` + emailFont + `margin:0 0 8px;font-size:20px;font-weight:400;line-height:1.4;color:` + mailInk + `;">账号已注销</h1>
            <p style="` + emailFont + `margin:0 0 20px;font-size:16px;line-height:1.6;color:` + mailInk + `;">你的账号已永久删除，名下所有项目的数据已一并清空，不可恢复。</p>`
	text = brandEyebrowText(b, "账号注销") + `

账号已注销

你的账号已永久删除，名下所有项目的数据已一并清空，不可恢复。

——
` + footText(b)
	preheader := "你的账号已永久删除，不可恢复。"
	return subject, emailShell(b, preheader, inner), text
}

// adminChangeEmailNoticeEmail 管理员更换邮箱的通知信（B5）：新旧邮箱各一封，
// 品牌恒中性 Auth（subject 前缀【Auth】，账号级操作不借 App 名头）。
//
// 与自助改绑的 changeEmailNoticeEmail 的差别在措辞归属：这封明确说是**管理员**改的、
// 用户没做任何操作——旧邮箱那封是安全警报（含新邮箱地址 + 「若非本人操作请立即改密
// 并联系管理员」），新邮箱那封是使用指引（「下次登录请使用新邮箱」）。邮箱进正文前
// 先 html.EscapeString（validateEmail 的正则不拦 `<>&`）。
func adminChangeEmailNoticeEmail(b brand, toNew bool, oldEmail, newEmail string) (subject, htmlBody, text string) {
	oldE, newE := html.EscapeString(oldEmail), html.EscapeString(newEmail)
	var title, lead, next string
	if toNew {
		subject = b.prefix + "新邮箱已生效"
		title = "新邮箱已成为登录邮箱"
		lead = newE + " 已成为" + b.account + "的登录邮箱（由管理员设置，原登录邮箱 " + oldE + "），该账号的验证码会发到这里。"
		next = "下次登录请使用新邮箱。不是你本人知情的操作？请联系管理员。"
	} else {
		subject = b.prefix + "登录邮箱已被管理员更换"
		title = "登录邮箱已被管理员更换"
		lead = "你的账号登录邮箱已由管理员从 " + oldE + " 更换为 " + newE + "，验证码将发往新邮箱。"
		next = "若非本人操作，请立即修改密码并联系管理员。"
	}
	inner := brandEyebrow(b, "账号安全") + `            <h1 style="` + emailFont + `margin:0 0 8px;font-size:20px;font-weight:400;line-height:1.4;color:` + mailInk + `;">` + title + `</h1>
            <p style="` + emailFont + `margin:0 0 20px;font-size:16px;line-height:1.6;color:` + mailInk + `;">` + lead + `</p>
            <p style="` + emailFont + `margin:0 0 4px;font-size:16px;line-height:1.6;color:` + mailWarn + `;">` + next + `</p>
` + ctaButton(b, "管理账号", accountURL)
	text = brandEyebrowText(b, "账号安全") + `

` + title + `

` + stripTags(lead) + `

` + next + `

` + ctaText("管理账号", accountURL) + `

——
` + footText(b)
	preheader := title + "。" + next
	return subject, emailShell(b, preheader, inner), text
}

// loginNotifyEmail 新设备登录提醒（W1）：四段式——检测到新设备登录 → 设备/项目/
// 时间细节 → 「不是我」的两步（改密 + 退出其它设备，各带 auth web 深链）→ 页脚
// （含「管理登录提醒」入口）。品牌按登录来源：App 登录取该 App 品牌，web 登录取
// 中性 Auth（调用方 brandFor(app) 传入）。
func loginNotifyEmail(b brand, device, appLabel string, at time.Time) (subject, htmlBody, text string) {
	subject = b.prefix + "新设备登录提醒"
	securityURL, sessionsURL := siteBase+"/web/console/security", siteBase+"/web/console/sessions"
	deviceE := html.EscapeString(device) // HTML 版（含 preheader）统一用转义后的形态
	inner := brandEyebrow(b, "账号安全") + `            <h1 style="` + emailFont + `margin:0 0 8px;font-size:20px;font-weight:400;line-height:1.4;color:` + mailInk + `;">检测到新设备登录</h1>
            <p style="` + emailFont + `margin:0 0 16px;font-size:16px;line-height:1.6;color:` + mailInk + `;">你的账号刚刚在一台新设备上登录。</p>
            <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="` + mailTipBox + `" style="width:100%;background-color:` + mailTipBox + `;border-radius:16px;margin:0 0 4px;">
              <tr>
                <td style="` + emailFont + `padding:16px 18px;font-size:16px;line-height:1.8;color:` + mailSub + `;">设备：` + deviceE + `<br>项目：` + html.EscapeString(appLabel) + `<br>时间：` + safeTime(at) + `</td>
              </tr>
            </table>
            <p style="` + emailFont + `margin:16px 0 0;font-size:16px;line-height:1.6;color:` + mailWarn + `;">如果这不是你本人的操作，请立即修改密码并退出其它设备。</p>
` + ctaButton(b, "账号安全设置", securityURL) + ctaButton(b, "管理登录设备", sessionsURL) + `            <p style="` + emailFont + `margin:20px 0 0;font-size:13px;line-height:1.6;color:` + mailDim + `;">管理登录提醒：<a href="` + accountURL + `" style="color:` + mailDim + `;">` + accountURL + `</a></p>`
	text = brandEyebrowText(b, "账号安全") + `

检测到新设备登录

你的账号刚刚在一台新设备上登录。

设备：` + device + `
项目：` + appLabel + `
时间：` + safeTime(at) + `

如果这不是你本人的操作，请立即修改密码并退出其它设备。

` + ctaText("账号安全设置", securityURL) + `

` + ctaText("管理登录设备", sessionsURL) + `

管理登录提醒：` + accountURL + `

——
` + footText(b)
	preheader := "检测到新设备登录（" + deviceE + "），如果不是你本人操作，请尽快修改密码。"
	return subject, emailShell(b, preheader, inner), text
}

// inviteEmail 邀请建号的链接信（B9）：说清「你被邀请创建账号、链接什么时候失效」，
// 单 CTA 设置密码，页脚照常。品牌按邀请 app（调用方 brandFor 传入，无 app = 中性
// Auth）；URL 由服务端拼好（token 已内嵌），模板不接用户输入的链接——token 是
// 凭证，正文之外不再进任何统计参数。
func inviteEmail(b brand, inviteURL string, expiresAt time.Time) (subject, htmlBody, text string) {
	subject = b.prefix + "账号邀请"
	expireLine := "邀请链接 24 小时内有效（" + safeTime(expiresAt) + " 前）；链接被使用、撤销或过期后即失效。"
	inner := brandEyebrow(b, "账号邀请") + `            <h1 style="` + emailFont + `margin:0 0 8px;font-size:20px;font-weight:400;line-height:1.4;color:` + mailInk + `;">你被邀请创建账号</h1>
            <p style="` + emailFont + `margin:0 0 16px;font-size:16px;line-height:1.6;color:` + mailInk + `;">点击下面的按钮设置密码，即可完成账号创建并直接登录。</p>
            <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="` + mailTipBox + `" style="width:100%;background-color:` + mailTipBox + `;border-radius:16px;margin:0 0 4px;">
              <tr>
                <td style="` + emailFont + `padding:16px 18px;font-size:16px;line-height:1.8;color:` + mailSub + `;">` + expireLine + `</td>
              </tr>
            </table>
` + ctaButton(b, "设置密码并加入", inviteURL) + `            <p style="` + emailFont + `margin:16px 0 0;font-size:16px;line-height:1.6;color:` + mailWarn + `;">不是你本人知情的操作？忽略这封邮件即可，不会有任何变化。</p>`
	text = brandEyebrowText(b, "账号邀请") + `

你被邀请创建账号

点击下面的按钮设置密码，即可完成账号创建并直接登录。

` + expireLine + `

` + ctaText("设置密码并加入", inviteURL) + `

不是你本人知情的操作？忽略这封邮件即可，不会有任何变化。

——
` + footText(b)
	preheader := "你被邀请创建账号，链接 24 小时内有效。"
	return subject, emailShell(b, preheader, inner), text
}

// maskEmail 遮掉本地名、保留域名：`u@b.com` → `u***@b.com`。
// 域名留着是因为它本身就是排障线索（拼错域名、企业邮箱拒收都只看域名）。
func maskEmail(email string) string {
	local, domain, ok := strings.Cut(email, "@")
	if !ok || local == "" || domain == "" {
		return "***"
	}
	return string([]rune(local)[:1]) + "***@" + domain
}
