package auth

import (
	"html"
	"log/slog"
	"strings"
)

// 邮件模板。品牌用中性的「Horatio 账号」而不是某个 App 的名字：本服务是统一账号
// 服务，/auth/send-code 的请求体里也没有 app 字段可分流，按 App 品牌发信做不到
// 也不该在这里做（要做是 P2 按 aud 分品牌的事）。结构照行业模板（与热量日记服务
// 同一套外壳）：深色模式、表格布局、全内联样式、AA 对比度、≥15px 字阶。

// codeEmail 拼验证码信的主题与正文：场景标题 → 一句话说明 → 大号验证码 + 有效期
// → 「非本人请忽略 + 别告诉任何人」→ 落款。
//
// action 只会是「注册 / 找回密码 / 修改密码 / 登录 / 修改邮箱」五个字面量之一
//（由 purpose 分流，不来自用户输入），code 只含数字——两处都没有 HTML 注入面。
func codeEmail(action, code string) (subject, html string) {
	subject = "【Horatio 账号】" + action + "验证码"
	inner := `            <p class="muted" style="` + emailFont + `margin:0 0 16px;font-size:15px;line-height:1.5;color:#6e6e73;">Horatio 账号 &middot; 邮箱验证</p>
            <h1 class="h1" style="` + emailFont + `margin:0 0 8px;font-size:20px;font-weight:600;line-height:1.4;color:#1c1c1e;">` + action + `验证码</h1>
            <p class="lead" style="` + emailFont + `margin:0 0 24px;font-size:16px;line-height:1.6;color:#1c1c1e;">在应用里输入下面的验证码，继续` + action + `。</p>
            <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" class="codebox" style="width:100%;background-color:#f2f2f7;border:1px solid #e5e5ea;border-radius:12px;">
              <tr>
                <td align="center" style="padding:20px 12px 16px;">
                  <div class="code" style="font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,'Courier New',monospace;font-size:32px;font-weight:600;letter-spacing:8px;text-indent:4px;color:#1c1c1e;">` + code + `</div>
                  <div class="muted" style="` + emailFont + `margin-top:10px;font-size:15px;color:#6e6e73;">5 分钟内有效</div>
                </td>
              </tr>
            </table>
            <hr class="hr" style="border:0;border-top:1px solid #e5e5ea;margin:24px 0 16px;">
            <p class="muted" style="` + emailFont + `margin:0 0 8px;font-size:15px;line-height:1.6;color:#6e6e73;">不是你操作？忽略这封邮件即可，账号不会有任何变化。</p>
            <p class="muted" style="` + emailFont + `margin:0 0 20px;font-size:15px;line-height:1.6;color:#6e6e73;">Horatio 账号不会向你索要验证码，也别把它告诉他人。</p>
            <p class="foot" style="` + emailFont + `margin:0;font-size:15px;color:#6e6e73;">Horatio 账号 auth.horatio.cn</p>`
	return subject, emailShell(inner)
}

// changeEmailNoticeEmail 改绑邮箱后的通知信（旧、新邮箱各一封）：说清「哪个邮箱变成了
// 什么」，再给非本人操作时的下一步——两句一事，不做多余解释。
// 邮箱进正文前先 html.EscapeString：validateEmail 的正则不拦 `<>&`，不转义就是注入面。
func changeEmailNoticeEmail(toNew bool, oldEmail, newEmail string) (subject, body string) {
	oldE, newE := html.EscapeString(oldEmail), html.EscapeString(newEmail)
	var title, lead, next string
	if toNew {
		subject = "【Horatio 账号】新邮箱已绑定"
		title = "新邮箱已绑定"
		lead = newE + " 已成为 Horatio 账号的绑定邮箱（原绑定邮箱 " + oldE + "），该账号的验证码会发到这里。"
		next = "不是你操作？请立刻让账号主人把邮箱改回去。"
	} else {
		subject = "【Horatio 账号】绑定邮箱已更换"
		title = "绑定邮箱已更换"
		lead = "你的账号绑定邮箱已由 " + oldE + " 改为 " + newE + "。"
		next = "不是你操作？请立刻用「找回密码」重置密码。"
	}
	inner := `            <p class="muted" style="` + emailFont + `margin:0 0 16px;font-size:15px;line-height:1.5;color:#6e6e73;">Horatio 账号 &middot; 账号安全</p>
            <h1 class="h1" style="` + emailFont + `margin:0 0 8px;font-size:20px;font-weight:600;line-height:1.4;color:#1c1c1e;">` + title + `</h1>
            <p class="lead" style="` + emailFont + `margin:0 0 24px;font-size:16px;line-height:1.6;color:#1c1c1e;">` + lead + `</p>
            <hr class="hr" style="border:0;border-top:1px solid #e5e5ea;margin:0 0 16px;">
            <p class="muted" style="` + emailFont + `margin:0 0 20px;font-size:15px;line-height:1.6;color:#6e6e73;">` + next + `</p>
            <p class="foot" style="` + emailFont + `margin:0;font-size:15px;color:#6e6e73;">Horatio 账号 auth.horatio.cn</p>`
	return subject, emailShell(inner)
}

// emailShell 包一层邮件外壳：head（charset/viewport/color-scheme + 深色与窄屏 <style>）
// + 100% 表格 + 520px 卡片，inner 是卡片内容。验证码信与改绑通知共用这一套。
//
// HTML 邮件的硬约束（2026-10-09 联网取证，来源：CSS-Tricks、Mailchimp 设计参考）：
//   - 表格布局 + **全内联样式**打底：Gmail/Outlook 会剥 <style>，内联才是保底渲染；
//   - 内容列 520px（业界口径「别超 600px」），窄屏靠 width:100%+max-width 回落；
//   - 深色模式走 <style> 的 prefers-color-scheme 覆盖且**必须 !important**（压得过内联），
//     <style> 被剥也只退回浅色版；color-scheme meta 防客户端强行反色；
//   - 正文 #1c1c1e、次要 #6e6e73 在白底为 17:1 与 5.1:1，过 WCAG AA（4.5:1）；
//   - 字阶下限 ≥15px（≈11pt）。
func emailShell(inner string) string {
	return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark">
<meta name="supported-color-schemes" content="light dark">
<style>
@media (prefers-color-scheme: dark) {
  .bg { background-color: #000000 !important; }
  .card { background-color: #1c1c1e !important; }
  .h1, .lead, .code { color: #f5f5f7 !important; }
  .muted, .foot { color: #98989d !important; }
  .codebox { background-color: #2c2c2e !important; border-color: #3a3a3c !important; }
  .hr { border-top-color: #3a3a3c !important; }
}
@media only screen and (max-width: 480px) {
  .wrap { padding: 16px 8px !important; }
  .cardin { padding: 24px 16px !important; }
  .code { font-size: 30px !important; letter-spacing: 6px !important; }
}
</style>
</head>
<body class="bg" style="margin:0;background-color:#f2f2f7;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color:#f2f2f7;">
  <tr>
    <td class="wrap" align="center" style="padding:32px 12px;">
      <table role="presentation" width="520" cellpadding="0" cellspacing="0" border="0" class="card" style="width:100%;max-width:520px;background-color:#ffffff;border-radius:16px;">
        <tr>
          <td class="cardin" style="padding:32px 28px;">
` + inner + `
          </td>
        </tr>
      </table>
    </td>
  </tr>
</table>
</body>
</html>`
}

// emailFont 是邮件正文的字体栈：系统中文字体优先、web-safe 兜底——邮件不能嵌字体，
// 栈尾必须留 sans-serif 系兜底（代码块那一处用等宽栈，不走这里）。
const emailFont = `font-family:-apple-system,BlinkMacSystemFont,"PingFang SC","Microsoft YaHei",Arial,sans-serif;`

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
