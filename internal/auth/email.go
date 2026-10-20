package auth

import (
	"html"
	"log/slog"
	"strings"
	"unicode/utf8"
)

// 邮件模板：**结构一套、品牌按 app 换**。本服务统一为两个日记签发验证码与改绑通知，
// 收件人看到的应是自己在用的那个 App 的名字——主题前缀、头部行、警示句、落款、
// 发件人显示名与内嵌图标都取自下面的品牌注册表；缺省或空 app 用中性品牌 Auth
//（统一账号服务不借任何 App 的名头，也是将来 web 账号台的默认品牌）。
//
// 外壳是 **miuix 官方默认 token 的 HTML 翻译**（本批定死的设计规范）：浅色画布
// #F7F7F7 / 主卡片 #FFFFFF 圆角 24px，600px 容器、表格结构、全内联 CSS、
// web-safe 中文字体栈；暗色整套切换走 @media (prefers-color-scheme: dark)
//（Apple Mail / iOS Gmail 生效，Gmail web 剥样式时退回浅色版）。
// 字阶照 miuix textStyles：标题 20px **Normal 字重**（不加粗堆层级）、正文 16px、
// 验证码 32px 居中放宽字距、页脚 13px；主文浅 #000000 / 深 #E6FFFFFF，次文 60% 灰。
//
// 每封信都带品牌内嵌图（cid 引用，见 mail 包的 multipart/related）与 preheader。

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
	// icon 是品牌内嵌图的 Content-ID（<calorie-diary-icon> 等）。**命名口径 =
	// mail 包内嵌 PNG 的文件名 + "-icon"**，由 scripts/genicons 生成；对不上就会
	// 发出裂图，所以 brand_test 逐个断言 mail.HasInlineIcon。
	icon string
}

// brands 品牌注册表：键与 JWT aud 白名单（allowedApps）同集，两处一起加。
var brands = map[string]brand{
	"calorie-diary": {
		name: "热量日记", latin: "CalorieDiary", footer: "热量日记 CalorieDiary",
		prefix: "【热量日记】", account: "热量日记账号", icon: "calorie-diary-icon",
	},
	"expense-diary": {
		name: "开支日记", latin: "ExpenseDiary", footer: "开支日记 ExpenseDiary",
		prefix: "【开支日记】", account: "开支日记账号", icon: "expense-diary-icon",
	},
}

// neutralBrand 是缺省品牌 Auth：SendCodeRequest.app 没给（web 账号台口径）与所有
// 拿不到 app 的发信场合都用它。
var neutralBrand = brand{
	name: "Auth", latin: "auth.horatio.cn", footer: "Auth auth.horatio.cn",
	prefix: "【Auth】", account: " Auth 账户", icon: "auth-icon",
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

// accountURL 是模板里唯一的落点：账号台（自助台），未登录会 302 到登录页。
// 常量串——模板里的链接绝不来自用户输入。
const accountURL = "https://auth.horatio.cn/web/console/account"

// codeEmail 拼验证码信的主题与正文：品牌头 → 一句话说明 → 验证码卡 + 有效期
// → 单 CTA → 提示卡 → error 红警示句 → 落款。
//
// action 只会是「注册 / 找回密码 / 修改密码 / 登录 / 修改邮箱」五个字面量之一
//（由 purpose 分流，不来自用户输入），code 只含数字——两处都没有 HTML 注入面。
func codeEmail(b brand, action, code string) (subject, body string) {
	subject = b.prefix + action + "验证码"
	inner := brandEyebrow(b, "邮箱验证") + `            <h1 class="h1" style="` + emailFont + `margin:0 0 8px;font-size:20px;font-weight:400;line-height:1.4;color:#000000;">` + action + `验证码</h1>
            <p class="lead" style="` + emailFont + `margin:0 0 24px;font-size:16px;line-height:1.6;color:#000000;">在应用里输入下面的验证码，继续` + action + `。</p>
            <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" class="codebox" style="width:100%;background-color:#EAF2FF;border-radius:20px;">
              <tr>
                <td align="center" style="padding:26px 12px 22px;">
                  <div class="code" style="` + emailFont + `margin:0;font-size:32px;font-weight:400;line-height:1.2;letter-spacing:10px;text-indent:10px;text-align:center;color:#000000;">` + code + `</div>
                  <p class="meta" style="` + emailFont + `margin:10px 0 0;font-size:13px;line-height:1.6;color:#666666;">5 分钟内有效</p>
                </td>
              </tr>
            </table>
` + ctaButton("前往账号台", accountURL) + `            <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" class="tipbox" style="width:100%;background-color:#F0F0F0;border-radius:16px;margin:24px 0 0;">
              <tr>
                <td class="tiptext" style="` + emailFont + `padding:16px 18px;font-size:16px;line-height:1.6;color:#666666;">不是你操作？忽略这封邮件即可，账号不会有任何变化。</td>
              </tr>
            </table>
            <p class="warn" style="` + emailFont + `margin:16px 0 0;font-size:16px;line-height:1.6;color:#E94634;">` + b.join("不会向你索要验证码，也别把它告诉他人。") + `</p>`
	preheader := action + "验证码 5 分钟内有效，" + b.name + "不会向你索要验证码。"
	return subject, emailShell(b, preheader, inner)
}

// changeEmailNoticeEmail 改绑邮箱后的通知信（旧、新邮箱各一封）：说清「哪个邮箱变成了
// 什么」，再给非本人操作时的下一步（error 红纯文字警示 + 单 CTA）——两句一事。
// 邮箱进正文前先 html.EscapeString：validateEmail 的正则不拦 `<>&`，不转义就是注入面。
func changeEmailNoticeEmail(b brand, toNew bool, oldEmail, newEmail string) (subject, body string) {
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
	inner := brandEyebrow(b, "账号安全") + `            <h1 class="h1" style="` + emailFont + `margin:0 0 8px;font-size:20px;font-weight:400;line-height:1.4;color:#000000;">` + title + `</h1>
            <p class="lead" style="` + emailFont + `margin:0 0 20px;font-size:16px;line-height:1.6;color:#000000;">` + lead + `</p>
            <p class="warn" style="` + emailFont + `margin:0 0 4px;font-size:16px;line-height:1.6;color:#E94634;">` + next + `</p>
` + ctaButton("管理账号", accountURL)
	preheader := title + "。" + next
	return subject, emailShell(b, preheader, inner)
}

// brandEyebrow 是卡片里的次文眉题（品牌名 · 场景），60% 灰。
func brandEyebrow(b brand, scene string) string {
	return `            <p class="sub" style="` + emailFont + `margin:0 0 10px;font-size:16px;line-height:1.5;color:#666666;">` + b.name + ` &middot; ` + scene + `</p>
`
}

// ctaButton 是全站唯一的主按钮（单 CTA）：#3482FF 白字 17px、圆角 16px、
// 高 46px（line-height 顶高，不依赖 padding 的盒模型差异）。暗色下按钮不动。
func ctaButton(label, href string) string {
	return `            <table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin:24px 0 0;">
              <tr>
                <td align="center" bgcolor="#3482FF" style="background-color:#3482FF;border-radius:16px;">
                  <a href="` + href + `" style="` + emailFont + `display:inline-block;padding:0 28px;line-height:46px;font-size:17px;font-weight:400;color:#FFFFFF;text-decoration:none;border-radius:16px;">` + label + `</a>
                </td>
              </tr>
            </table>
`
}

// emailShell 包一层 miuix 外壳：head（charset/viewport/color-scheme + 暗色与窄屏
// <style>）+ 隐藏 preheader + 600px 卡片 + 品牌头（内嵌图 + 品牌名横排左对齐）+
// inner + 页脚。验证码信与改绑通知共用这一套。
//
// HTML 邮件的硬约束（沿用本仓既有取证结论，来源：CSS-Tricks、Mailchimp 设计参考）：
//   - 表格布局 + **全内联样式**打底：Gmail/Outlook 会剥 <style>，内联才是保底渲染；
//   - 内容列 600px，窄屏靠 width:100%+max-width 回落；
//   - 暗色模式走 <style> 的 prefers-color-scheme 覆盖且**必须 !important**（压得过内联），
//     <style> 被剥也只退回浅色版；color-scheme meta 防客户端强行反色；
//   - 品牌内嵌图一律 alt + 显式宽高 + border=0 + display:block——缺 alt 会被读屏念
//     文件名，缺显式尺寸会在图片加载前把版面顶乱；
//   - preheader 用「display:none + max-height:0 + mso-hide:all」四重保险，
//     收件箱预览看到的是这句话而不是正文首行。
func emailShell(b brand, preheader, inner string) string {
	return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark">
<meta name="supported-color-schemes" content="light dark">
<title>` + html.EscapeString(b.name) + `</title>
<style>
@media (prefers-color-scheme: dark) {
  .bg { background-color:#000000 !important; }
  .card { background-color:#242424 !important; }
  .h1, .lead, .bname, .code { color:#E6FFFFFF !important; }
  .sub, .meta { color:#999999 !important; }
  .codebox { background-color:#2B3B54 !important; }
  .tipbox { background-color:#434343 !important; }
  .tiptext { color:#B4B4B4 !important; }
  .foot { color:#787E96 !important; }
  .hr { border-top-color:#3A3A3A !important; }
}
@media only screen and (max-width: 620px) {
  .wrap { padding:16px 8px !important; }
  .cardin { padding:24px 18px !important; }
  .code { font-size:30px !important; letter-spacing:6px !important; text-indent:6px !important; }
}
</style>
</head>
<body class="bg" style="margin:0;padding:0;background-color:#F7F7F7;">
<div style="display:none;font-size:1px;line-height:1px;max-height:0;max-width:0;opacity:0;overflow:hidden;mso-hide:all;">` + preheader + `&#8199;&#65279;&#8199;&#65279;&#8199;&#65279;&#8199;&#65279;&#8199;&#65279;</div>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" class="bg" style="background-color:#F7F7F7;">
  <tr>
    <td class="wrap" align="center" style="padding:32px 12px;">
      <table role="presentation" width="600" cellpadding="0" cellspacing="0" border="0" class="card" style="width:100%;max-width:600px;background-color:#FFFFFF;border-radius:24px;">
        <tr>
          <td class="cardin" style="padding:28px 32px 32px;">
            <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="margin:0 0 20px;">
              <tr>
                <td style="padding:0 12px 0 0;vertical-align:middle;"><img src="cid:` + b.icon + `" width="44" height="44" alt="` + html.EscapeString(b.name) + `" border="0" style="display:block;width:44px;height:44px;border:0;"></td>
                <td style="vertical-align:middle;"><span class="bname" style="` + emailFont + `font-size:17px;font-weight:400;line-height:1.3;color:#000000;">` + b.name + `</span></td>
              </tr>
            </table>
` + inner + `
            <hr class="hr" style="border:0;border-top:1px solid #EDEDED;margin:28px 0 16px;">
            <p class="foot" style="` + emailFont + `margin:0 0 4px;font-size:13px;line-height:1.6;color:#8C93B0;">` + b.footer + `</p>
            <p class="foot" style="` + emailFont + `margin:0;font-size:13px;line-height:1.6;color:#8C93B0;">© 2026·屑涵</p>
          </td>
        </tr>
      </table>
    </td>
  </tr>
</table>
</body>
</html>`
}

// emailFont 是邮件正文的字体栈：miuix 首选 MiSans，其后是各平台的 web-safe 中文
// 栈，末位必须留 sans-serif——邮件不能嵌字体，栈尾兜底不能少（验证码同栈，不等宽：
// miuix 的验证码用正文族的 32px 居中放宽字距）。
const emailFont = `font-family:MiSans,-apple-system,"HarmonyOS Sans SC","PingFang SC","Noto Sans CJK SC","Microsoft YaHei",sans-serif;`

// mailLog 发信失败要留排障线索：客户端只看到白话，根因（Graph 状态码/响应体）只在
// 服务端日志。邮箱过 maskEmail 脱敏——日志会进排障链路与备份，全文邮箱是 PII。
func mailLog(err error, purpose, email string) {
	slog.Error("发送邮件失败", "purpose", purpose, "email", maskEmail(email), "err", err)
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
