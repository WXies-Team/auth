# UI 改造差距研究报告（2026-10）

> 范围：`internal/ui/` 16 个模板页 + `app.js` + `style.css`，服务端能力以 `cmd/server/`、`internal/auth/` 现状为准。
> 方法：先读代码逐条落 `现状(file:line)`，再联网核查业界做法（W3C / IETF / NIST / OWASP / WCAG /
> GitHub / Google / Microsoft / Apple / Material / Shopify Polaris / Cloudflare / MDN / miuix 官方源码），
> 每条"业界做法"均附可访问的官方证据 URL；无法访问的产品后台一律不引用、不臆测。
> "是否采纳"列是研究组预判（建议采纳 / 可选 / 暂缓），最终由维护者勾选。

---

## 1. 摘要：按影响排序的 Top 15

| # | 建议 | 位置 | 一句话理由 |
|---|---|---|---|
| 1 | 登录页接入 Passkey **条件式 UI**（`navigator.credentials.get({mediation:'conditional'})` 挂到邮箱输入框，保留密码兜底） | A-1 | web.dev 官方首选做法；服务端已是 discoverable 登录（`internal/auth/passkey.go:316-331`），**只差前端**，密码用户完全无感、Passkey 用户少点一次按钮 |
| 2 | OAuth 授权页把"固定一句话"换成**逐项权限清单** + 应用品牌信息 | A-9 | Google 同意屏的官方口径就是"告诉用户哪个应用在请求、请求哪些 scope"；需后端 `OAuthAuthorizeView` 补 `Scopes` |
| 3 | 全站主色文字对比度修复：主按钮白字在 `#3482FF` 上仅 **3.64:1**，徽标/分段控件主色字在 primary-soft 上仅 **3.23:1**，均低于 WCAG 4.5:1 | E-3 | 全站每个 primary 按钮都中招，属硬性无障碍指标，优先级高于视觉一致性 |
| 4 | 注销账号确认加**手输短语闸**（输入「注销」才解锁主钮，复用批量操作的现成组件） | B-12 | GitHub 删除账号的官方流程即"两字段手输确认"；本仓 `admin-users.html:129-132` 已有同款先例，成本极低 |
| 5 | 所有密码输入框加**「显示密码」开关**（眼睛图标，含登录/重置/强制改密/改密/改邮/邀请页） | B-10 | NIST SP 800-63B §3.1.1.2 原文 "SHOULD offer an option to display the password"，规范级建议而非产品偏好 |
| 6 | 概览页三个串行请求改 `Promise.all` 并行 + 全站"读取中…"换**骨架屏** | B-1、E-2 | 三倍延迟白白串着付；Material 官方过渡规范把 skeleton+淡入列为标准装载形态 |
| 7 | 登录会话行增加**粗略地理位置**（IP 归属地） | B-3 | Google 设备页/ Gmail 活动页的标配字段；需后端接 GeoIP 库输出 `ipRegion` |
| 8 | 401 重定向登录时**保留回跳地址**（`/web/login?next=…`），登录完成回原页 | E-11 | 纯前端改造；现在登录后一律落控制台，后台深层链接全部丢失 |
| 9 | 恢复码页面显示**剩余数量**（如"剩余 7 / 10"）并把"剩余数量无法查询"文案删掉 | B-8 | 现文案在承认体验缺口；需后端在恢复码消费时落 `used` 计数并出只读状态端点 |
| 10 | 后台用户/审计/会话三页的**筛选与分页状态写入 URL**；审计页补"结果（成功/失败）"筛选 | C-1、D-2、D-3 | 可刷新、可分享、可回退；Cloudflare 审计日志官方筛选器即含 result 维度 |
| 11 | 触屏设备交互目标统一抬到 **≥44px**（`.btn.small` 38px、`.app-chip`/`.pf-chip` 28px） | E-5 | Apple HIG 44pt / Material 48dp；本任务书亦明示 ≥44px |
| 12 | 空态统一为 Polaris 式"**为什么空 + 下一步行动**"，替换一句灰字 | E-1 | Polaris 空态官方指南：解释收益、给一个主行动；本仓 passkeys 页已是好样板 |
| 13 | 4xx/5xx/断网的**前端兜底文案**补"下一步"（现在 500 只有"请求失败（500）"） | E-10 | 微软错误文案规范："说清发生了什么、接下来会发生什么、给出可行解法" |
| 14 | 审计日志加 **CSV 导出** | D-5 | 需后端 `format=csv` 流式输出；Cloudflare 审计日志以 Logpush/导出为标准能力 |
| 15 | 暗色模式：徽标/分段控件主色字对比仅 ~3.0:1，`theme-color` 未跟随暗色；对齐 miuix 官方 `darkColorScheme` | E-8 | miuix 官方暗色主色是更深的 `#277AF7`，本仓沿用亮色 `#3482FF` 属漂移 |

---

## 2. 五组差距表

### A 组：公开页（登录 / 邀请 / OAuth 授权 / 403 / 空态与骨架）

| 页面/元素 | 现状(file:line) | 业界做法 | 证据 | 建议 | 是否采纳 |
|---|---|---|---|---|---|
| A-1 登录页 Passkey 入口 | 独立按钮「使用 Passkey 登录」，仅当 `PublicKeyCredential` 存在才显示（`internal/ui/templates/login.html:101-103`，`internal/ui/app.js:720-741`） | 首选"条件式 UI"：把 passkey 塞进邮箱输入框的 autofill 建议里（`mediation:'conditional'`），密码用户零打扰；配套 `allowCredentials` 留空（discoverable）。部署清单还建议密码+2FA 登录成功后**条件式创建** passkey | [web.dev: Sign in with a passkey through form autofill](https://web.dev/articles/passkey-form-autofill)；[web.dev: discoverable credentials deep dive](https://web.dev/articles/webauthn-discoverable-credentials)；[web.dev: passkey deployment checklist](https://web.dev/articles/passkey-checklist)；服务端已就绪：`internal/auth/passkey.go:316-331`（`BeginDiscoverableLogin`，allowCredentials 留空） | `login.html` 邮箱输入框（`#login-email`）获得焦点时启动 conditional get（浏览器不支持则静默跳过）；成功即 `finishLogin`。保留现有按钮作为不支持 conditional 浏览器的兜底，但文案改「使用 Passkey 登录（其它设备）」。第二阶段：密码登录成功且 `res.mustChangePassword` 为假时尝试 conditional create，创建失败静默 | 建议采纳 |
| A-2 登录方式三选（tab） | 密码 / 邮箱验证码 / 找回密码三 tab，`role=tablist` + 键盘方向键（`login.html:6-10`，`app.js:500-511`，`app.js:3205-3220`） | 分模式 tab + ARIA tabs 模式（自动激活、方向键切换）即 WAI-ARIA APG 推荐形态 | [WAI-ARIA APG Tabs Pattern](https://www.w3.org/WAI/ARIA/apg/patterns/tabs/) | 已对齐，不改 | —（已达标） |
| A-3 密码→2FA 分步 | 密码正确后原地切换单输入验证码，三态（验证器/邮箱码/恢复码）换语义（`login.html:12-41`，`app.js:566-668`） | 2FA 第二步用**单输入原地换语义**（GitHub 同款）；`autocomplete=one-time-code` 让系统自动填充 | [GitHub Docs: Configuring two-factor authentication](https://docs.github.com/en/authentication/securing-your-account-with-two-factor-authentication-2fa/configuring-two-factor-authentication)；[web.dev: sign-in form best practices](https://web.dev/articles/sign-in-form-best-practices)（独立 form + autocomplete 属性） | 已对齐，不改 | —（已达标） |
| A-4 发码冷却 | 60 秒禁用 + 「N 秒后重发」（`app.js:167-180`），四处发码钮共用（`login.html:55,72`，`account.html:62,85,129`） | 发码接口必须限流（本仓服务端 5/min/IP，`cmd/server/routes.go:41`）；前端把冷却态显式告知用户 | [NIST SP 800-63B §3.2.2 Rate Limiting](https://pages.nist.gov/800-63-4/sp800-63b.html#throttle) | 已对齐，不改 | —（已达标） |
| A-5 登录失败/锁定文案 | 直接透传服务端 message（`app.js:660-667`）；服务端 429 时前端原样显示 | 限流响应要告诉用户**多久之后能再试**；NIST 允许递增等待（30 秒到 1 小时）作为限流手段 | [NIST SP 800-63B §3.2.2](https://pages.nist.gov/800-63-4/sp800-63b.html#throttle) | 与后端确认 429 文案含时间（如"尝试过于频繁，请 5 分钟后再试"）；前端在 `api()` 对 `status===429` 追加固定后缀"，请稍后再试"，避免裸状态码外露 | 建议采纳 |
| A-6 登录页垃圾箱提示 | 「没收到可查看垃圾箱，60 秒后可重新发送」（`login.html:58`，`app.js:678` toast） | 错误/提示文案要**具体可执行**（告诉用户找哪个发件人、搜什么词），而非泛泛建议 | [Microsoft Writing Style Guide: Writing style](https://learn.microsoft.com/en-us/windows/apps/design/style/writing-style)（"telling the user what went wrong… what will happen next… a realistic solution"） | 文案改「没收到？在垃圾箱里搜索发件人『Auth』；60 秒后可重新发送」（发件人显示名取 `internal/auth/email.go` 的 brand prefix，写死为『Auth』即可，本服务品牌固定） | 建议采纳 |
| A-7 强制改密步 | `mustChangePassword=true` 顶替整卡进"请设置新密码"（`login.html:83-97`，`app.js:534-564`） | 重置/首登必须改密是标准做法；配合"改密后其它会话吊销"提示 | [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)（Password recovery） | 已对齐，不改 | —（已达标） |
| A-8 邀请接受页 | 邮箱只读 + 设密码 + 昵称选填 + 24h 一次性提示；错误变体一页两态（`invite.html:5-34`） | 错误页 = 原因 + 一条出路；表单字段给自动填充语义（`autocomplete=new-password`） | [Microsoft: Error Message Guidelines](https://learn.microsoft.com/en-us/windows/win32/debug/error-message-guidelines)；[web.dev: autofill](https://web.dev/learn/forms/autofill) | 已对齐；小改：密码框加「显示密码」开关（见 B-10，全站统一组件） | 建议采纳（并入 B-10） |
| A-9 OAuth 授权同意页 | 固定文案「它将获得你的账号标识与邮箱」+ 回跳域（`authorize.html:16-26`）；后端视图仅 `{Tx, App, AppName, RedirectHost, Email}`（`cmd/server/oauth.go:186-188`） | 同意屏要**逐项列出 scope**、展示应用名/Logo/支持邮箱等品牌信息、让用户能识别回跳域名；RFC 9700 指出用户在同意屏上"注意到问题"是防钓鱼的一环 | [Google Cloud: OAuth consent screen](https://support.google.com/cloud/answer/13461325)（"tells users which app is requesting access… and what kind of data (scopes) the app needs"）；[Google Cloud: OAuth app branding](https://support.google.com/cloud/answer/15549049)；[RFC 9700 §4.4](https://www.rfc-editor.org/rfc/rfc9700.txt) | ① `authorize.html:19` 的单句换成清单：「登录到『X』后它将获得：· 你的账号标识（uid）· 你的邮箱地址」（逐项来自后端 scope 列表，无 scope 时回落现句）；② 卡头加「回跳至 `example.com`，非本站域名」徽标强调；③「取消」按钮文案改「拒绝并返回」；④ 后端 `OAuthAuthorizeView` 加 `Scopes []string`（见本组末尾） | 建议采纳 |
| A-10 OAuth 错误变体 | `ErrorTitle + ErrorMessage + 回到控制台`（`authorize.html:6-12`） | 错误页 = 出错原因 + 下一步 | [Microsoft: Error Message Guidelines](https://learn.microsoft.com/en-us/windows/win32/debug/error-message-guidelines) | 已对齐，不改 | —（已达标） |
| A-11 403 denied 页 | 原因 + 「回到会话总览 / 回到概览」两条出路（`denied.html:2-9`） | 除解释原因外，要给用户**可实际使用的申诉/求助渠道**（NIST 称之为 redress，要求"容易被找到和使用"） | [NIST SP 800-63B: Redress Requirements](https://pages.nist.gov/800-63-4/sp800-63b.html#AAL_SEC4) | 把「请联系平台管理员」改成具体渠道：「如需调整，请联系平台管理员（管理后台 → 用户页可查管理员邮箱），或回复开通邀请邮件」；并补一行 `<span class="mono">时间 {now}</span>` 便于报障对齐日志 | 建议采纳 |
| A-12 登录页/邀请页空载态 | 首屏即完整表单，无骨架需求 | 登录类页面信息量小，业界亦为直出表单 | —（对照 A-13/管理台，见 E-2） | 不改 | — |
| A-13 空态/骨架（横切预览） | 管理台与自助台各列表初始为「读取中…」灰字（例 `sessions.html:14`、`passkeys.html:11`、`admin-users.html:37`） | skeleton + 内容淡入是官方装载形态；空态要解释并引导 | [Material 3: Transitions](https://m3.material.io/styles/motion/transitions)（skeleton loader + fade-in）；详见 E-1/E-2 | 统一在 E 组处理 | — |

#### A 组需要后端配合的项目

1. **`OAuthAuthorizeView` 增加 scope 列表**（`cmd/server/oauth.go:186-192`、`internal/auth/oauth.go` 的 `OAuthAuthorizeView`）：现在视图只带 App/AppName/RedirectHost/Email，授权页无法列出权限。缺什么：`Scopes []string`（本次 OAuth 应用只有"账号标识+邮箱"一个固定档位，先硬编码该档位的展示文案由后端下发，未来多档位时由 `oauth_clients` 表驱动）。
2. **（A-5）429 响应文案确认**：确认限流中间件返回的 message 含等待时长；不含则在限流层补"请 N 分钟后再试"。

---

### B 组：自助台（概览 / 会话 / Passkey / 两步验证 / 账号）

| 页面/元素 | 现状(file:line) | 业界做法 | 证据 | 建议 | 是否采纳 |
|---|---|---|---|---|---|
| B-1 概览页加载 | `/web/session` → `/api/totp` → `/api/passkeys` **三个串行 await**（`app.js:805-818`）；页面文字「读取中…」（`console.html:10,23,28,33`） | 互不依赖的请求并行取；装载期用骨架占位而非文本 | [Material 3: Transitions](https://m3.material.io/styles/motion/transitions)（skeleton + fade-in） | ① 三请求改 `Promise.all`（`/web/session` 先单独取，角色徽标需它）；② 三行状态文字换成 3 个骨架条（复用 E-2 的 `.skeleton` 类） | 建议采纳 |
| B-2 概览页信息量 | 只有邮箱 + 三登录方式状态 + 退出（`console.html:8-38`） | 安全概览页通常附"最近登录"，帮助用户发现异常（Google 安全检查页列设备活动） | [Google Account Help: See devices with account access](https://support.google.com/accounts/answer/3067630) | 在账号卡加一行「最近登录：{relTime(最近会话 createdAt)} · {IP}」；数据取现有 `GET /api/sessions` 的首条（当前会话即最近活跃，`app.js:874` 说明服务端已按 `last_seen_at DESC` 排序），**无需新端点** | 建议采纳 |
| B-3 会话行字段 | 设备名 + 项目 + 相对时间 + IP + 首次登录 + 本设备徽标（`app.js:876-898`）；行=单会话、不按名归并（`sessions.html:7`） | 会话/设备列表标配"最近活动的**大致位置**"；Google 设备页提示同名多会话要"review their details"，Gmail 活动页直接给"last 10 IP addresses and **approximate locations**" | [Google Account Help: devices with account access](https://support.google.com/accounts/answer/3067630)；[Gmail Help: Last account activity](https://support.google.com/mail/answer/45938) | 会话副行 IP 后追加「· {ipRegion}」（如「IP 114.114.114.114 · 江苏南京」）；拿不到归属地时该段不渲染。需后端（见组末） | 建议采纳 |
| B-4 「退出其它所有会话」 | 按钮常驻页头（`sessions.html:3`）；无其它会话时仍可点，弹「知道了」（`app.js:901-910`） | 上下文动作只在有意义时出现；退出类操作逐条确认、批量退出单独确认 | [OWASP Session Management Cheat Sheet: Manual Session Expiration](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)（应提供主动登出机制）；[Gmail Help](https://support.google.com/mail/answer/45938)（"Sign out of all other web sessions"置于活动区） | `load()` 拿到 `rows` 后 `$('#revoke-others').classList.toggle('hidden', rows.filter(r=>!r.current).length===0)`；确认弹窗文案已点名条数（`app.js:905-907`），保留 | 建议采纳 |
| B-5 Passkey 列表 | 名称 + 本机徽标 + 添加时间 + 最近使用（`app.js:960-975`）；创建无命名步骤，名字由服务端生成（`app.js:1015-1037`） | RP 应让已登录用户查看/删除凭证，并**展示能区分"是哪把、属于哪个认证器"的信息**；注册后提示用户起个友好名字是常见模式 | [MDN: Passkeys](https://developer.mozilla.org/en-US/docs/Web/Security/Authentication/Passkeys)（"the RP should display information to help a user understand which key it is and which authenticator it is associated with"）；[Microsoft Docs: passkeys in ASP.NET Core](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/passkeys?view=aspnetcore-10.0)（"prompt users to provide a friendly name for their passkey"） | 创建成功后（`app.js:1031` 处）行内弹出命名条：「给这把 Passkey 起个名字，方便以后辨认」+ 输入框（预填由 `navigator.userAgentData?.platform || UA 解析` 得到的「iPhone · Safari」式默认名）+「跳过」；提交走现有 `PATCH /api/passkeys/{id}`（`app.js:1003`），**无需后端** | 建议采纳 |
| B-6 Passkey 删除 | 弹窗点名「删除『名称』后立即不能登录」（`app.js:977-981`，`passkeys.html:16-23`） | 破坏性操作弹窗点名对象与后果；初始焦点放安全侧 | [WAI-ARIA APG: dialog-modal](https://www.w3.org/WAI/ARIA/apg/patterns/dialog-modal/)（"focus on the least destructive action"）；`openDialog` 已显式钉焦点（`app.js:3188-3196`） | 已对齐，不改 | —（已达标） |
| B-7 两步验证开启 | 二维码 + 手输密钥 + 验码 → 恢复码只显一次，下载/复制/我已保存（`security.html:16-47`，`app.js:1086-1147`；txt 结构仿 GitHub，`app.js:1115-1131`） | GitHub：Download / Print / Copy + 「I have saved my recovery codes」勾选后才放行；用过即废、可再生成 | [GitHub Docs: recovery methods](https://docs.github.com/en/authentication/securing-your-account-with-two-factor-authentication-2fa/configuring-two-factor-authentication-recovery-methods) | 已对齐；小改：恢复码面板加「打印」按钮（`window.print()` + `@media print` 已兜底动画，`style.css:791-794`），对齐 GitHub 三件套 | 建议采纳 |
| B-8 恢复码剩余数量 | 文案承认「剩余数量无法查询」（`security.html:54`） | 恢复码一次性、用后作废（NIST §4.2.1.1；GitHub 文档亦然）；让用户知道还剩几枚可降低"到用时才发现没码"的风险 | [NIST SP 800-63B §4.2.1.1 Saved Recovery Codes](https://pages.nist.gov/800-63-4/sp800-63b.html#savedrecovery) | `recovery-state` 行改「恢复码：剩余 {used} / {total} 枚（{date} 生成）」；重生成按钮保留 | 建议采纳（需后端，见组末） |
| B-9 关闭两步验证 | 要一个码（2FA 码或恢复码）后关闭，弹窗文案点名后果（`security.html:60`，`app.js:1198-1206`） | 关闭 2FA 前必须重新认证并明示风险；GitHub 同为"密码+2FA 复核" | [GitHub Docs: Configuring two-factor authentication](https://docs.github.com/en/authentication/securing-your-account-with-two-factor-authentication-2fa/configuring-two-factor-authentication) | 已对齐；小改：`askCode` 关闭确认标题从「关闭两步验证」改为「关闭两步验证？」（问句更醒目），描述首句加粗风险：「关闭后账号只剩密码一道防线」 | 建议采纳 |
| B-10 改密码（本机） | 原密码 / 验证码两条路（`account.html:44-71`）；全部密码框无「显示」开关（`account.html:46,49,67,89`，`login.html:20,76,90,93`，`invite.html:25`） | NIST 明确建议提供"显示密码"选项；允许粘贴、允许密码管理器（本仓 autocomplete 已就位） | [NIST SP 800-63B §3.1.1.2](https://pages.nist.gov/800-63-4/sp800-63b.html#passwordver)（"SHOULD offer an option to display the password"） | 做一个 `decoratePassword(input)` 工具：每个 `input[type=password]` 右侧 44px 保留位内加眼睛按钮，`aria-label="显示密码"/"隐藏密码"`，切换 `type=text/password`；DOMContentLoaded 时对全页自动装饰（与 `decorateSelects` 同路数，`app.js:3310-3312`） | 建议采纳 |
| B-11 改邮箱 | 新邮箱验证码 + 当前密码（`account.html:75-93`）；新旧邮箱都发通知（`account.html:93`，`app.js:1284`） | 敏感信息变更需重新认证 + 通知新旧两端 | [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)（Re-authentication for sensitive features） | 已对齐，不改 | —（已达标） |
| B-12 注销账号 | 危险区 + 7 天宽限说明 + 邮箱验证码双确认（`account.html:106-139`） | 破坏性不可逆操作用**手输短语**二次确认（GitHub 删除账号：第一栏输用户名/邮箱，第二栏输提示短语），并列明后果 | [GitHub Docs: Deleting your personal account](https://docs.github.com/en/account-and-profile/how-tos/account-management/deleting-your-personal-account) | `delete-dialog`（`account.html:118-138`）在验证码之后加一栏：「为防误操作，输入『注销』以继续」+ 文本框；「永久注销账号」按钮默认 disabled，`input===注销` 才解锁（复用 `syncBulkGate` 逻辑，`app.js:1903-1906`） | 建议采纳 |
| B-13 登录提醒开关 | 全量 PUT 防清空、失败回滚勾选（`app.js:1549-1580`，`account.html:96-104`） | 开关类设置即时保存 + 失败回滚 | [Material 3: Switch](https://m3.material.io/components/switch)（即时生效语义） | 已对齐；小改：checkbox 自绘样式已给 20px（`style.css:385-410`），触屏下把 label 整行 min-height 抬 44px（并入 E-5） | 建议采纳（并入 E-5） |
| B-14 资料卡（头像/昵称/色板） | 脏值检测、行内编辑、超长即时提示（`app.js:1419-1485`，`account.html:7-34`） | 资料编辑即时校验 + 明确保存入口 | — | 已对齐，不改 | — |

#### B 组需要后端配合的项目

1. **恢复码计数**（B-8）：缺什么——① 恢复码表需有 `used` 标记（或按 `recovery.consume` 审计事件计数）；② 新只读端点 `GET /api/totp/recovery-status → {total, used, generatedAt}`（30/min/uid）。消费路径 `internal/auth/totp.go`（`Recovery` 校验处）需落计数。
2. **会话归属地**（B-3）：缺什么——`internal/auth/session.go` 落库/查询时由 `RemoteAddr` IP 过 GeoLite2（或同级）本地库得到 `ipRegion`，`GET /api/sessions` 与 `/admin/sessions` 行各加 `ipRegion` 字段；查不到回空串（前端不渲染该段）。
3. **`/web/session` 补 `lastLoginAt`**（B-2 的替代路径）：目前概览页要自己再调 `/api/sessions` 取首条；若在 `/web/session`（`cmd/server/web.go:130-156`）顺带返回当前会话 `createdAt/ip`，概览页可省一次请求。可选优化。

---

### C 组：后台用户与项目访问

| 页面/元素 | 现状(file:line) | 业界做法 | 证据 | 建议 | 是否采纳 |
|---|---|---|---|---|---|
| C-1 用户搜索 | 提交式搜索，query 仅存 JS 内存（`admin-users.html:9-14`，`app.js:2331-2338`），刷新即丢 | 过滤条件应反映在 URL（可刷新、可分享、可回退）；审计类产品筛选器与 URL 一一对应 | [MDN: History.replaceState](https://developer.mozilla.org/en-US/docs/Web/API/History/replaceState)；[Cloudflare: Audit Logs](https://developers.cloudflare.com/fundamentals/account/account-security/review-audit-logs/)（dashboard 筛选器体系） | 表单 submit 与 pager 翻页时把 `?query=&offset=` 写入 URL（`replaceState`）；页面加载时从 URL 回填。邀请记录已复用同 query（`app.js:2335`），随 URL 一起恢复 | 建议采纳 |
| C-2 分页 | 上一页/下一页 + `1–20 / 总数`（`admin-users.html:42-46`，`app.js:183-203`） | 列表级 prev/next + 范围文案是常规形态（本仓三页共用一份实现，口径统一） | —（无差距项，不需要外部证据） | 已对齐；保持 | —（已达标） |
| C-3 角色变更 | 下拉 + 保存 → 确认弹窗点名后果（降级为普通用户/收回授权）（`app.js:2070-2078`、`app.js:2184-2197`）；不能改自己（`app.js:2072`） | 权限变更需确认并说明影响；禁止自我降级锁死 | [WAI-ARIA APG: alertdialog 适用场景](https://www.w3.org/WAI/ARIA/apg/patterns/alertdialog/) | 已对齐，不改 | —（已达标） |
| C-4 邀请 | 弹层发邀请；折叠表四态徽标 + 行内重发/撤销；重发说明旧链接失效（`admin-users.html:49-62,85-102`，`app.js:1804-1856,2344-2360`） | 邀请链接一次性 + 有效期；重发=吊旧换新要说清 | [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)（Account creation / verification） | 已对齐（发完自动展开邀请区 `app.js:2356`）；保持 | —（已达标） |
| C-5 批量操作 | 后果逐条 + 邮箱清单 + N>5 手输「确认」闸 + 结果面板可勾选重试（`admin-users.html:104-148`，`app.js:1863-2450`） | 高危批量用强确认（手输短语），结果逐项回报 | [GitHub Docs: deleting an organization](https://docs.github.com/en/enterprise-cloud@latest/organizations/managing-organization-settings/deleting-an-organization-account)（typed confirmation 传统）；[WAI-ARIA APG: alertdialog](https://www.w3.org/WAI/ARIA/apg/patterns/alertdialog/) | 已对齐，不改 | —（已达标） |
| C-6 重置密码回执 | 一次性临时密码弹层，关层清零，明示"仅显示一次"（`admin-users.html:150-160`，`app.js:1757-1777`） | 凭证只写一次（write-only），此后只能更新/删除，不回显 | [GitHub Docs: Using secrets in GitHub Actions](https://docs.github.com/en/actions/security-for-github-actions/security-guides/using-secrets-in-github-actions)（值不回显、日志脱敏） | 已对齐，不改 | —（已达标） |
| C-7 用户表列 | 9 列含两步验证/Passkey 数（`admin-users.html:34`）；**无封禁状态列**（封禁只在详情抽屉，`app.js:2063-2068`） | 管理列表要让管理员"一眼看到需要处理的状态"，危险账号不应点进详情才发现 | [Cloudflare: Audit Logs](https://developers.cloudflare.com/fundamentals/account/account-security/review-audit-logs/)（治理面板把状态前置到列表） | 列表加「封禁」列：有生效封禁显示 `<span class="badge warn">封禁</span>`（悬停 title 列出范围与解除时间），无则「—」。需后端（见组末） | 建议采纳 |
| C-8 项目访问添加名单 | 输入邮箱添加；该邮箱未注册时报「该邮箱不存在」（`app.js:2589-2612`，`app.js:2609`） | "人不在系统里"的正解是发出邀请，而不是死胡同 | [Polaris Empty State 指南](https://shopify.dev/docs/api/app-home/latest/web-components/feedback-and-status-indicators/empty-state)（空/失败态要给下一步主行动） | `err.status===404` 时文案改「{email} 尚未注册。发送邀请邮件让 TA 先注册？」+「发送邀请」按钮；点击直接调现有 `POST /admin/users/invite`（`app.js:2353`，body `{email, app: p.app}`），成功 toast 复用邀请文案 | 建议采纳 |
| C-9 项目访问开关 | 「开放登录/仅限受邀」分段 + 确认点名后果（`app.js:2574-2587`，`admin-access.html:15-22`） | 破坏性开关二次确认并说明影响面 | [WAI-ARIA APG: alertdialog](https://www.w3.org/WAI/ARIA/apg/patterns/alertdialog/) | 已对齐，不改 | —（已达标） |
| C-10 OAuth 接入块（休眠） | Web 接入 UI 已整体撤下，后端 clientId 端点休眠（`app.js:2486-2488`，`admin-access.html:6` 说明段已不含） | OAuth 客户端注册页需应用名/主页/支持邮箱/回跳域（Google 凭据页的品牌要求） | [Google Cloud: OAuth app branding](https://support.google.com/cloud/answer/15549049) | 第一个 web 项目接入时恢复 UI，表单字段按 Google branding 四件套（app name / logo / support email / homepage+redirect）设计；本阶段不动 | 暂缓 |

#### C 组需要后端配合的项目

1. **用户列表封禁列**（C-7）：缺什么——`AdminSearchUsers`（`cmd/server/admin.go:144` → `internal/auth/admin.go`）返回项增加 `bans: [{app, until}]` 或聚合布尔 `banned`（LEFT JOIN `user_bans`，注意 `app='*'` 全局与限时惰性判活）。
2. **（与 D-2 共用）审计 `Result` 筛选**：见 D 组。

---

### D 组：后台会话总览 / 审计 / 配置中心 / AI 用量

| 页面/元素 | 现状(file:line) | 业界做法 | 证据 | 建议 | 是否采纳 |
|---|---|---|---|---|---|
| D-1 会话总览筛选 | 仅 query（邮箱/uid）+ 顶部项目切换（`admin-sessions.html:14-19`，`app.js:2637`）；无 IP / 设备筛选 | 管理侧会话/日志检索按 IP 过滤是标准能力 | [Cloudflare: Get account audit logs](https://developers.cloudflare.com/api/resources/audit_logs/methods/list/)（ip / actor / 时间过滤参数） | 先做纯前端可落地的一半：搜索框 placeholder 改「按邮箱片段或 uid 搜索」已准确；当 query 为纯数字且会话详情中出现该 IP 时无从匹配——真正的 IP 检索放后端（见组末），前端届时加「按 IP 搜索」提示切换 | 建议采纳（分两步） |
| D-2 审计筛选-结果 | 筛选支持 action/actor/target/from/to（`admin-audit.html:7-87`，`app.js:2753-2770`）；**无结果（成功/失败）筛选**；后端 `AuditQuery` 同样无该字段（`cmd/server/admin.go:591-603`） | 审计系统标配按成功/失败过滤（Cloudflare v2 的 `ActionResult`） | [Cloudflare: Audit Logs](https://developers.cloudflare.com/fundamentals/account/account-security/audit-logs/)（按 action/result/actor 过滤，dashboard 默认滤掉 view 噪声） | 前端在筛选行加「结果」下拉：全部 / 成功 / 失败（复用 `.select-drop` 装饰）；后端补 `Result` 字段（见组末）。另建议照 Cloudflare 默认把 `admin.audit.view` 从默认下拉挪到分组末尾，减少误选 | 建议采纳 |
| D-3 审计筛选入 URL | 筛选仅存 DOM 值（`app.js:2802-2840`） | 同 C-1：筛选可分享、可回退 | [MDN: History.replaceState](https://developer.mozilla.org/en-US/docs/Web/API/History/replaceState) | submit/档位 chips/翻页时把全部筛选写入 querystring；加载时回填（档位 chips 的高亮随之恢复） | 建议采纳 |
| D-4 审计详情 | `detail` 列内联键值对（`app.js:2736-2746`）；actor/target 是死文本（`app.js:2784,2791`） | 日志详情应可"顺着线索钻取"（Cloudflare 由条目 id 反推筛选定位上下文） | [Cloudflare: Audit Logs](https://developers.cloudflare.com/fundamentals/account/account-security/audit-logs/)（由条目 id 反推筛选定位上下文） | actor/target 单元格换成链接：`/web/admin?uid={uid}` → 用户页 `openDetail(uid)`（`admin-users.html` 需支持 URL 参数打开抽屉，前端即可）；IP 单元格点击 = 以该 IP 反查会话（依赖 D-1 后端项） | 建议采纳 |
| D-5 审计导出 | 无导出（分页上限 50/页，`app.js:2751`） | 审计日志可导出/推送外部系统是标配 | [Cloudflare: Audit Logs（Logpush 导出）](https://developers.cloudflare.com/logs/logpush/logpush-job/datasets/account/audit_logs/index.md) | 需后端（见组末）：`GET /admin/audit?format=csv`，沿用同一筛选参数流式输出；前端加「导出 CSV」按钮，点击携带当前 filters | 建议采纳（需后端） |
| D-6 配置中心掩码 | secret 只显示末 4 位、原值不回传；留空不改、清除走确认弹层（`admin-config.html:7`，`app.js:2876-2912`） | 凭据 write-only：保存后不可回读，只能替换或删除；日志脱敏 | [GitHub Docs: Using secrets](https://docs.github.com/en/actions/security-for-github-actions/security-guides/using-secrets-in-github-actions) | 已对齐，不改 | —（已达标） |
| D-7 配置保存反馈 | toast「已保存，≤10 秒生效」+ 重取列表刷新 hint（`app.js:2894-2903`） | 保存后即时可见新状态；瞬态提示用 snackbar | [miuix Snackbar.kt](https://github.com/compose-miuix-ui/miuix/blob/main/miuix-ui/src/commonMain/kotlin/top/yukonga/miuix/kmp/basic/Snackbar.kt)（Short=4000ms） | 已对齐；toast 时长并入 E-9 统一调整 | —（已达标） |
| D-8 AI 用量 KPI | 今日/全站余量/活跃/7 日 spark 四卡 + 较昨日环比（`admin-ai.html:19-27`，`app.js:2974-3002`）；app-admin 视角如实置灰（`app.js:2995-2999`） | KPI 卡 + 趋势微图 + 环比是用量面板通行形态；数据变化要可被读屏感知 | [WCAG 2.2 SC 4.1.3 Status Messages](https://www.w3.org/TR/WCAG22/#status-messages) | 已对齐；小改：spark 加 `aria-hidden` 已有（`admin-ai.html:26`），建议给 `#ai-kpis` 容器加 `aria-live="polite"`，区间切换后读屏能感知数字变化（并入 E-7） | 建议采纳（并入 E-7） |
| D-9 AI 用户表钻取 | 行 `role=button tabindex=0` + Enter/Space（`app.js:3041-3053`）；明细面板滑入（`app.js:3095-3108`） | 可点行必须键盘可达；钻取面板回到列表要恢复焦点 | [WAI-ARIA APG: dialog-modal](https://www.w3.org/WAI/ARIA/apg/patterns/dialog-modal/)（焦点管理原则） | 键盘语义已对齐；补一条：`#aid-close`、`#sd-close`、`#ud-close` 关闭面板后把焦点还给触发行（`el.focus()`），现在关闭后焦点落 body | 建议采纳 |
| D-10 AI 限额编辑 | super 专属弹层，四键逐个 PUT，留空不改，正整数校验（`admin-ai.html:74-97`，`app.js:3115-3158`） | 多字段批量保存需明确"部分失败"的中间态 | [Microsoft: Error Message Guidelines](https://learn.microsoft.com/en-us/windows/win32/debug/error-message-guidelines)（说明发生了什么 + 下一步） | 逐键循环 catch 后当前只显示该错误（`app.js:3152-3158`）；改为：失败时错误文案前缀已保存键，如「已保存 2 项；第 3 项『每用户每日』失败：{err}。其余未保存」 | 建议采纳 |
| D-11 AI 用量导出 | 无 | 用量报表可导出对账 | [Cloudflare: Logpush datasets](https://developers.cloudflare.com/logs/logpush/logpush-job/datasets/account/audit_logs/index.md)（导出为标准能力） | 需后端：`GET /admin/ai-usage/export?days=&app=` CSV；前端加「导出」按钮 | 可选（需后端） |

#### D 组需要后端配合的项目

1. **审计结果筛选**（D-2）：`auth.AuditQuery`（`internal/auth/audit.go`）加 `Result int`（-1 全部 / 0 失败 / 1 成功），`cmd/server/admin.go:591-603` 读 `q.Get("result")`；SQL where 补 `result = ?`。
2. **审计 CSV 导出**（D-5）：新增 `GET /admin/audit?format=csv`（admin 门控 + 与现筛选同参数 + `Content-Disposition` 流式写出，注意 UTF-8 BOM 便于 Excel 打开中文）。
3. **会话按 IP 检索**（D-1）：`AdminListSessions`（`internal/auth/admin.go`）加 `ip` 参数（`WHERE ip LIKE ?` 或精确匹配），`cmd/server/admin.go:566-567` 透传 `q.Get("ip")`。
4. **AI 用量导出**（D-11，可选）：同 CSV 方案。

---

### E 组：横切（空态/错误态、加载态、无障碍、暗色、动效、文案）

| 页面/元素 | 现状(file:line) | 业界做法 | 证据 | 建议 | 是否采纳 |
|---|---|---|---|---|---|
| E-1 空态 | 统一 `.empty` 一句居中灰字（`style.css:656`）；passkeys 页已是好样板「还没有 Passkey，点击右上角…创建」（`app.js:956`）；users/audit/sessions/access/config 空态只说"没有"（`app.js:2009,2780,870,2502,2918`） | 空态要解释价值并给**一个**主行动（action-oriented 标题 + primary action），且"永不让用户有挫败感" | [Polaris: Empty state](https://shopify.dev/docs/api/app-home/latest/web-components/feedback-and-status-indicators/empty-state) | 按 passkeys 样板统一改写：`暂无匹配的用户。调整搜索关键词，或点击「邀请用户」创建第一个账号。`（users）、`所选区间内暂无用量记录。换一个时间范围试试。`（audit/ai 已接近，补"换个范围"动作暗示）、`只有当前设备处于登录状态。在新设备上登录后会出现在这里。`（sessions）、`当前没有可管理的项目。`（access 保留，补一句原因：「你被授权的项目会出现在这里」） | 建议采纳 |
| E-2 加载态 | 各列表初始「读取中…」文本行（`sessions.html:14`、`passkeys.html:11`、`admin-users.html:37`、`admin-sessions.html:30`、`admin-audit.html:98`、`admin-ai.html:46`、`admin-access.html:11`、`admin-config.html:11`、`console.html:10,23,28,33`） | skeleton 占位 + 内容淡入；skeleton 可配脉冲动画表达"进行中" | [Material 3: Transitions](https://m3.material.io/styles/motion/transitions)（"Once content is loaded, it quickly fades in on top of the skeleton loader… A pulsing animation indicates indeterminant loading"） | style.css 加 `.skeleton`（`--sub-bg` 底、8px 圆角、`@keyframes sk-pulse` opacity .5↔1 1.2s、`prefers-reduced-motion` 下停脉冲只留底色）；各列表初始行渲染为 3~5 条骨架（复用 `.item`/`<tr>` 骨架占位），数据回来整块替换；`aria-busy="true"` 挂在容器 | 建议采纳 |
| E-3 对比度-文字 | 主按钮 `--primary-ink:#fff` on `--primary:#3482FF` = **3.64:1**（`style.css:11-12,457`）；`.badge.on`/`.app-chip.on`/`.hint-box` 主色字 on `--primary-soft:#EAF2FF` = **3.23:1**（`style.css:13,158,520,282`）；暗色同款 ~3.0:1（`style.css:50,59`） | 文本对比 ≥4.5:1（大字号除外，本仓按钮 16px 非大字）；Apple HIG 同口径：≤17pt 全部字重 4.5:1 | [WCAG 2.2 SC 1.4.3 Contrast (Minimum)](https://www.w3.org/TR/WCAG22/#contrast-minimum)；[Apple HIG: Accessibility](https://developer.apple.com/design/human-interface-guidelines/accessibility) | 二选一（需设计拍板）：**保色**→主按钮文字改黑墨（黑 on #3482FF = 5.78:1，且与 miuix `lightColorScheme` `onSurface=Black` 的墨色观感一致）；**保白字**→按钮底在亮色降为 ≥4.5:1 的深蓝（实测 `#0F62D6` 5.7:1）。徽标/分段选中态文字改用加深主色（实测 `#1D4ED8` on #EAF2FF = 5.9:1），暗色对称处理 | 建议采纳（取值待设计确认） |
| E-4 对比度-控件边框 | 输入框/下拉/勾选框内环 `--line:#E0E0E0` = **1.32:1** on 白卡（`style.css:19,321,360,389`）；这是白底卡片上识别"这是个输入框"的唯一线索 | UI 组件边界/状态指示需 ≥3:1 | [WCAG 2.2 SC 1.4.11 Non-text Contrast](https://www.w3.org/TR/WCAG22/#non-text-contrast) | 交互控件（input/select/textarea/checkbox/radio/自绘下拉）静息内环换 `#949494`（3.05:1）；非交互容器（`.card`/`.item`/`.table-wrap` 的装饰环）保持 `#E0E0E0` 不动。聚焦态已有 2px `--focus` 环（`style.css:427-429`），保持 | 建议采纳 |
| E-5 触屏目标 | `--tap:40px`，coarse 下 `.btn`/input 抬 44（`style.css:38,474-477`）；但 `.btn.small` coarse 仅 38（`style.css:476`）、`.app-chip` 28（`style.css:153`）、`.pf-chip` 28（`style.css:683`）、`.tabnav .nav-item` 仅 padding 撑高（`style.css:213`）、`checkbox/radio` 20px（`style.css:387`，label 行未强制高度） | Apple：控件 ≥44×44pt；Material：≥48×48dp；WCAG AA 底线 24×24（2.5.8），AAA 44×44（2.5.5） | [Apple: UI Design Dos and Don'ts（44×44pt）](https://developer.apple.com/design/tips/)；[WCAG 2.2 SC 2.5.8 Target Size (Minimum)](https://www.w3.org/TR/WCAG22/#target-size-minimum)；[WCAG 2.2 SC 2.5.5](https://www.w3.org/TR/WCAG22/#target-size-enhanced) | `@media (pointer:coarse)` 统一追加：`.btn.small{min-height:44px}`、`.app-chip{min-height:44px}`、`.pf-chip{width:44px;height:44px}`、`input[type=checkbox]/[type=radio]{width:24px;height:24px}` 且 label 行 `.row:has(input)` `min-height:44px` | 建议采纳 |
| E-6 焦点与键盘 | 焦点环统一 2px + offset（`style.css:427-433`）；弹层初始焦点钉安全侧（`app.js:3188-3196`）；tabs 方向键（`app.js:3205-3220`）；自绘下拉有完整键盘（`app.js:3228-3309`）。缺口：① 列表重绘（`innerHTML=''`）后焦点落 body（例 `app.js:923,933`）；② 自绘 listbox 无 `aria-activedescendant`（`app.js:3243-3268`） | 焦点可见（2.4.7）；焦点不被遮挡（2.4.11）；listbox 键盘导航用 activedescendant 关联；动态列表变化后焦点去向要明确 | [WCAG 2.2 SC 2.4.7](https://www.w3.org/TR/WCAG22/#focus-visible)；[WCAG 2.2 SC 2.4.11](https://www.w3.org/TR/WCAG22/#focus-not-obscured-minimum)；[WAI-ARIA APG: combobox（listbox 键盘模型）](https://www.w3.org/WAI/ARIA/apg/patterns/combobox/) | ① `fadeOutRow`/重绘前记下触发按钮的 key（行 id），`load()` 后 `容器.querySelector(...)?.focus()`，无行则聚焦列表容器（加 `tabindex="-1"`）；② `decorateSelect` 给 `menu` 项 `id`、btn 加 `aria-activedescendant` 同步；③ `body` 加 `scroll-padding-top:72px`（sticky 顶栏不压焦点，`style.css:93-98`） | 建议采纳 |
| E-7 aria-live | toast `role=status`（`layout.html:54`）；列表容器 `aria-live=polite`（`sessions.html:13`、`passkeys.html:10`、`admin-access.html:10`、`admin-config.html:10`）；错误 `role=alert`（各页）。缺口：计数类 `#users-total/#sess-total/#audit-total/#ai-kpis` 无播报 | 状态消息（计数变化、加载完成）应可被读屏感知而无需移动焦点 | [WCAG 2.2 SC 4.1.3 Status Messages](https://www.w3.org/TR/WCAG22/#status-messages) | 给 `#users-total`（`admin-users.html:4`）、`#sess-total`（`admin-sessions.html:4`）、`#audit-total`（`admin-audit.html:4`）、`#ai-kpis`（`admin-ai.html:19`）加 `aria-live="polite"` | 建议采纳 |
| E-8 暗色模式 | `prefers-color-scheme` 全套令牌（`style.css:46-65`）+ `color-scheme: light dark` meta（`layout.html:6`）；`theme-color` 恒为 `#3482FF`（`layout.html:8`）；暗色沿用亮色主色 `#3482FF`，而 miuix 官方暗色主色是 `#277AF7`、画布 `#242424`、surface 黑（见第 4 节 Colors.kt） | 系统暗色跟随 + 浏览器 UI 主题色同步；平台设计系统暗色令牌整体迁移而非只换画布 | [MDN: meta theme-color](https://developer.mozilla.org/en-US/docs/Web/HTML/Element/meta/name/theme-color)（支持 media 条件）；[miuix Colors.kt darkColorScheme](https://github.com/compose-miuix-ui/miuix/blob/main/miuix-ui/src/commonMain/kotlin/top/yukonga/miuix/kmp/theme/Colors.kt) | ① `<meta name="theme-color" content="#3482FF" media="(prefers-color-scheme: light)">` + `<meta … content="#242424" media="(prefers-color-scheme: dark)">`；② 暗色 `--primary` 改 `#277AF7`（并连带 E-3 的暗色徽标取值校验 ≥4.5:1）；③ 暗色 `--ok` 等语义色复核（现 `#7EE0A6` on `#242424` 仅用于 12-13px 徽标，需复测） | 建议采纳 |
| E-9 动效 | 全站单 easing `cubic-bezier(.2,0,0,1)`、150/180/200ms 三档（`style.css:29-35`）、只动 transform/opacity（`style.css:700-794`，`app.js:28-75`）、reduced-motion 一刀切（`style.css:774-790`）；toast 固定 2600ms（`app.js:137`） | 微交互 150~300ms 属业界主流档位（M3：standard 300ms、medium1 250ms）；尊重 reduced-motion；snackbar 类提示 4~10s | [Material 3: Easing and duration](https://m3.material.io/styles/motion/easing-and-duration/tokens-specs)；[miuix Snackbar.kt](https://github.com/compose-miuix-ui/miuix/blob/main/miuix-ui/src/commonMain/kotlin/top/yukonga/miuix/kmp/basic/Snackbar.kt)（Short 4000ms / Long 10000ms，无障碍设置可加长） | 时长/曲线已对齐，保持；唯一调整：`toast()` 时长 2600→**4000ms**（对齐 miuix Snackbar Short），错误类 toast（`bad`）6000ms 或右侧带「×」手动关闭 | 建议采纳 |
| E-10 错误文案（前端兜底） | 服务端错误透传（口径已是"什么+下一步"，项目约定见 AGENTS.md）；前端兜底：`请求失败（${res.status}）`（`app.js:410`）、`Passkey 验证失败，请重试`（`app.js:738,323`）、`图片无法解码，请换一张`（`app.js:1602`） | 错误消息说清"发生了什么、接下来会发生什么、用户能做什么"，不甩原始状态码、不责怪用户 | [Microsoft Writing Style Guide: Writing style](https://learn.microsoft.com/en-us/windows/apps/design/style/writing-style)；[Microsoft: Error Message Guidelines](https://learn.microsoft.com/en-us/windows/win32/debug/error-message-guidelines) | `api()` 兜底文案按状态段分级：`400「请求参数有问题，请刷新页面后重试」`、`403「没有权限执行该操作，如需权限请联系平台管理员」`、`429「操作太频繁了，请稍后再试」`、`5xx「服务暂时不可用，请稍后重试；持续出现请联系管理员」`；`fetch` 直接抛 TypeError（断网/DNS）时显示「网络连接中断，请检查网络后重试」 | 建议采纳 |
| E-11 登录回跳 | 401 且非 reauth 时 `location.href='/web/login'`（`app.js:417-419`）；登录完成只回控制台或 OAuth resume（`app.js:520-533`） | 登录后应返回用户原来的页面（return-to 参数），避免打断任务流 | [web.dev: sign-in form best practices](https://web.dev/articles/sign-in-form-best-practices)（登录流程保上下文的通行原则）；return-to 需白名单校验（只允许站内相对路径） | `api()` 跳转改为 `'/web/login?next=' + encodeURIComponent(location.pathname + location.search)`；`finishLogin`/强制改密完成后的 `loginLanding()` 优先取 `?next=`（校验以 `/` 开头且不以 `//` 开头，防开放重定向）；OAuth `?tx=` 逻辑保持最高优先级 | 建议采纳 |

#### E 组需要后端配合的项目

无——E 组全部为前端/CSS 改造。（E-8 暗色主色若要与 miuix Monet 动态色对齐属远期项，本仓无此依赖。）

---

## 3. 后端配合项汇总（跨组）

| 优先级 | 缺口 | 涉及端点/文件 |
|---|---|---|
| 高 | OAuth 授权视图补 `Scopes []string`（A-9） | `cmd/server/oauth.go:176-192`、`internal/auth/oauth.go` `OAuthAuthorizeView`、`internal/ui` OAuthView |
| 高 | 恢复码计数：消费时落 `used`，新增 `GET /api/totp/recovery-status`（B-8） | `internal/auth/totp.go`、`internal/db/schema.sql`（如需新列，按 Boundaries 需先请示）、`cmd/server/routes.go` |
| 高 | 审计 `Result` 筛选字段（D-2） | `internal/auth/audit.go` `AuditQuery`、`cmd/server/admin.go:591-603` |
| 中 | 用户列表行内联封禁状态（C-7） | `internal/auth/admin.go` `AdminSearchUsers`、`cmd/server/admin.go:144` |
| 中 | 会话 `ipRegion`（GeoIP 本地库）（B-3、D-1） | `internal/auth/session.go`、`cmd/server/routes.go` 会话序列化、`cmd/server/admin.go:566` |
| 中 | 审计 CSV 导出（D-5） | `cmd/server/admin.go` `GET /admin/audit` 加 `format=csv` 分支 |
| 低 | 会话按 IP 检索（D-1） | `AdminListSessions` + `cmd/server/admin.go:566-567` |
| 低 | `/web/session` 返回当前会话 `createdAt/ip`（B-2，纯优化） | `cmd/server/web.go:130-156` |
| 低 | AI 用量 CSV 导出（D-11） | `cmd/server/ai.go` |

---

## 4. miuix 官方规范速查表（源：compose-miuix-ui/miuix @ main）

取值全部来自官方源码 raw 文件（`https://raw.githubusercontent.com/compose-miuix-ui/miuix/main/miuix-ui/src/commonMain/kotlin/top/yukonga/miuix/kmp/<路径>`），2026-10-28 抓取。

### 4.1 Colors.kt（`theme/Colors.kt`）

| 令牌 | lightColorScheme | darkColorScheme | 备注（本仓 style.css 对照） |
|---|---|---|---|
| primary | `#3482FF` | `#277AF7` | 本仓暗色沿用 `#3482FF`（`style.css:48`）——与官方暗色漂移，见 E-8 |
| primaryVariant | `#3482FF` | `#0073DD` | dark `#0073DD` 白字 4.67:1，可作 E-3 暗色按钮备选 |
| onPrimaryVariant | `#AECDFF` | `#99C7F1` | — |
| error / onError | `#E94634` / `#FFFFFF` | `#F12522` / `#FFFFFF` | 本仓 `--danger:#E94634`（`style.css:22`）与亮色一致；暗色未跟随 |
| errorContainer / onErrorContainer | `#FDF6F4` / `#410002` | `#2E0603` / `#FFDAD6` | — |
| disabledPrimaryButton | `#C2D9FF` | `#253E64` | 本仓禁用态用 `opacity:.6`（`style.css:434`）近似 |
| primaryContainer | `#5D9BFF` | `#338FE4` | — |
| secondary / secondaryVariant | `#E6E6E6` / `#F0F0F0` | `#505050` / `#434343` | 本仓 `--sub-bg:#F0F0F0` / 暗 `#434343`（`style.css:20,57`）= 官方 secondaryVariant |
| onSecondaryVariant | `#303030` | `#D9D9D9` | 本仓 `--sub-ink:#303030`（`style.css:21`）；暗色本仓用 `--ink`，官方是 `#D9D9D9` |
| tertiaryContainer / onTertiaryContainer | `#EAF2FF` / `#3482FF` | —（对应用 primary-soft 位） | 本仓 `--primary-soft:#EAF2FF` / 暗 `#2B3B54`（`style.css:13,50`）；暗色 `#2B3B54` 为主色系自定值，官方对应位在 dark 无同名对 |
| background / onBackground | `#FFFFFF` / `#000000` | `#242424` / `#E6FFFFFF` | 本仓画布 `#F7F7F7`（`style.css:14`）= 官方 surface（亮）；暗色画布 `#000000`，官方是 `#242424` |
| surface / onSurface | `#F7F7F7` / `#000000` | `#000000` / `#F2F2F2` | — |
| onSurfaceSecondary | `#CC000000`（黑 80%） | `#CCFFFFFF` | 本仓 `--ink` 暗色即 `#FFFFFF 90%`（`style.css:54`） |
| onSurfaceVariantSummary | `#99000000`（黑 60%） | `#80FFFFFF` | 本仓 `--dim:rgba(0,0,0,.6)`（`style.css:18`）= 亮色一致；暗色本仓 60%，官方 50% |
| onSurfaceVariantActions | `#66000000`（黑 40%） | `#66FFFFFF` | — |
| outline | `#D9D9D9` | `#404040` | 官方 outline 本身低对比；E-4 建议交互控件升到 ≥3:1（如 `#949494`），装饰环可留官方值 |
| dividerLine | `#E0E0E0` | `#393939` | 本仓 `--line` 完全一致（`style.css:19,56`） |
| windowDimming | 黑 30% | 黑 60% | 本仓弹层遮罩 `rgba(0,0,0,.4)`（`style.css:569`） |
| surfaceContainerHigh(est) | `#E8E8E8` | `#242424` / `#2D2D2D` | — |

### 4.2 TextStyles.kt（`theme/TextStyles.kt`）

| 样式 | 字号 | 字重 | 备注 |
|---|---|---|---|
| title1 / title2 / title3 / title4 | 32 / 24 / 20 / 18 sp | Normal | 本仓页面标题 22px Normal（`style.css:245`）落在 title2~3 之间，自定值 |
| headline1 / headline2 | 17 / 16 sp | Normal | 本仓卡片 h2=17（`style.css:274`）= headline1 |
| main / paragraph | 17 / 17 sp（行高 1.2em） | Normal | — |
| body1 / body2 | 16 / 14 sp | Normal | 本仓正文 16（`style.css:72`）= body1；表格 14 = body2（`style.css:541`） |
| subtitle | 14 sp | **Bold** | — |
| button | 17 sp | Normal | 本仓按钮继承 16px 正文（`style.css:444`），比官方小 1px |
| footnote1 / footnote2 | 13 / 11 sp | Normal | 本仓 hint 13（`style.css:277`）= footnote1；窄屏底栏 11（`style.css:214`）= footnote2 |

### 4.3 Button.kt（`basic/Button.kt`）

| 常量 | 取值 | 备注 |
|---|---|---|
| MinWidth | 58 dp | — |
| MinHeight | 40 dp | 本仓 `--tap:40px`（`style.css:38`）一致；触屏 44（`style.css:475`）为自定加强 |
| CornerRadius | 16 dp | 本仓 `--radius-ctl:16px` 一致（`style.css:28`） |
| InsideMargin | 水平 16dp / 垂直 13dp | 本仓 `padding:0 19px`（`style.css:442`），水平略宽 |

### 4.4 Card.kt（`basic/Card.kt`）

| 常量 | 取值 | 备注 |
|---|---|---|
| CornerRadius | 16 dp | **本仓 `--radius-card:24px`（`style.css:27`）大于官方默认**——自定超集，窄屏降至 18px（`style.css:696`）；记录差异，不建议改 |
| InsideMargin | 0 dp | 内容留白由组件自理（本仓卡片 padding 20px，`style.css:266`） |

### 4.5 Switch.kt（`basic/Switch.kt`）

| 常量/规格 | 取值 | 备注 |
|---|---|---|
| 轨道尺寸 | 49 × 28 dp | 本仓无 Switch 组件，开关用 checkbox 自绘（`style.css:385-410`） |
| thumb 直径 | 20 dp | — |
| thumb 位移 | 关 4dp → 开 25dp | — |
| thumbOffset spring | damping 0.7 / stiffness 987 | 本仓弹簧仅用于按压回弹 `--spring:cubic-bezier(.34,1.56,.64,1)`（`style.css:32`） |
| thumbScale spring | damping 0.6 / stiffness 987 | — |
| checked 过渡 spring | damping 0.99 / stiffness 438.6 | — |

### 4.6 TextField.kt（`basic/TextField.kt`）

| 常量 | 取值 | 备注 |
|---|---|---|
| CornerRadius | 16 dp | 本仓输入框 `--radius-ctl` 16px 一致（`style.css:319`） |
| InsideMargin | 16 × 16 dp | 本仓 `padding:9px 15px`（`style.css:318`），垂直更紧凑 |
| BorderWidth（聚焦） | 2 dp | 本仓聚焦环 2px outline + offset 2（`style.css:427-429`）等效 |
| LabelFontSizeNormal → Floating | 17 dp → 10 dp | 本仓无浮动 label，标签常驻上方 13px（`style.css:313`） |

### 4.7 Snackbar.kt（`basic/Snackbar.kt`）

| 常量 | 取值 | 备注 |
|---|---|---|
| Short 时长 | **4000 ms** | 本仓 toast 2600ms（`app.js:137`）偏短，见 E-9 |
| Long 时长 | 10000 ms | 错误类 toast 可对齐此档 |
| Indefinite / Custom | 常驻 / 自定 ms（>0） | — |
| 无障碍加长 | 经 `AccessibilityManager.calculateRecommendedTimeoutMillis` 放大 | web 对应：读屏用户可感知的提示不应过短 |
| HostBottomPadding | 12 dp | 本仓 `bottom:max(16px, safe-area)`（`style.css:576`） |
| 圆角 | 10 dp | 本仓胶囊 999px（`style.css:578`），自定形态 |

### 4.8 NavigationBar.kt（`basic/NavigationBar.kt`）

| 常量 | 取值 | 备注 |
|---|---|---|
| ItemHeight | 64 dp | 本仓窄屏玻璃胶囊底栏自定（`style.css:187-221`），item 高约 46px |
| IconSize | 26 dp | 本仓底栏图标 22px（`style.css:216`） |
| FloatingNavigationBar IconSize | 28 dp | — |
| iOS 底部安全区 | 36 dp（caption bar 情形 26dp+insets） | 本仓 `env(safe-area-inset-bottom)` 处理（`style.css:190`）一致 |

---

## 附：证据 URL 一览（均已验证可访问）

- NIST SP 800-63B-4: https://pages.nist.gov/800-63-4/sp800-63b.html
- OWASP Authentication Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
- OWASP Session Management Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
- WCAG 2.2: https://www.w3.org/TR/WCAG22/
- WAI-ARIA APG（dialog-modal / tabs / alertdialog / combobox）: https://www.w3.org/WAI/ARIA/apg/patterns/dialog-modal/
- RFC 9700（OAuth Security BCP）: https://www.rfc-editor.org/rfc/rfc9700.txt
- RFC 9207（iss 参数）: https://www.rfc-editor.org/rfc/rfc9207.txt
- web.dev passkey 条件式 UI: https://web.dev/articles/passkey-form-autofill
- web.dev discoverable credentials: https://web.dev/articles/webauthn-discoverable-credentials
- web.dev passkey 部署清单: https://web.dev/articles/passkey-checklist
- web.dev 登录表单最佳实践: https://web.dev/articles/sign-in-form-best-practices
- MDN Passkeys: https://developer.mozilla.org/en-US/docs/Web/Security/Authentication/Passkeys
- MDN meta theme-color: https://developer.mozilla.org/en-US/docs/Web/HTML/Element/meta/name/theme-color
- MDN History.replaceState: https://developer.mozilla.org/en-US/docs/Web/API/History/replaceState
- Google Cloud OAuth 同意屏: https://support.google.com/cloud/answer/13461325
- Google Cloud OAuth 品牌: https://support.google.com/cloud/answer/15549049
- Google 账号设备页帮助: https://support.google.com/accounts/answer/3067630
- Gmail 最近活动: https://support.google.com/mail/answer/45938
- GitHub 2FA 恢复码: https://docs.github.com/en/authentication/securing-your-account-with-two-factor-authentication-2fa/configuring-two-factor-authentication-recovery-methods
- GitHub 配置 2FA: https://docs.github.com/en/authentication/securing-your-account-with-two-factor-authentication-2fa/configuring-two-factor-authentication
- GitHub 删除个人账号: https://docs.github.com/en/account-and-profile/how-tos/account-management/deleting-your-personal-account
- GitHub 删除组织: https://docs.github.com/en/enterprise-cloud@latest/organizations/managing-organization-settings/deleting-an-organization-account
- GitHub Actions secrets: https://docs.github.com/en/actions/security-for-github-actions/security-guides/using-secrets-in-github-actions
- Cloudflare 审计日志: https://developers.cloudflare.com/fundamentals/account/account-security/review-audit-logs/
- Cloudflare 审计日志 v2: https://developers.cloudflare.com/fundamentals/account/account-security/audit-logs/
- Cloudflare 审计日志 API: https://developers.cloudflare.com/api/resources/audit_logs/methods/list/
- Microsoft 写作风格（错误文案）: https://learn.microsoft.com/en-us/windows/apps/design/style/writing-style
- Microsoft 错误消息准则: https://learn.microsoft.com/en-us/windows/win32/debug/error-message-guidelines
- Microsoft ASP.NET Core passkeys: https://learn.microsoft.com/en-us/aspnet/core/security/authentication/passkeys?view=aspnetcore-10.0
- Apple UI 设计 Dos/Don'ts（44pt）: https://developer.apple.com/design/tips/
- Apple HIG 无障碍（对比度表）: https://developer.apple.com/design/human-interface-guidelines/accessibility
- Material 3 缓动与时长: https://m3.material.io/styles/motion/easing-and-duration/tokens-specs
- Material 3 过渡（skeleton）: https://m3.material.io/styles/motion/transitions
- Shopify Polaris 空态: https://shopify.dev/docs/api/app-home/latest/web-components/feedback-and-status-indicators/empty-state
- miuix 仓库: https://github.com/compose-miuix-ui/miuix
  - Colors.kt: https://raw.githubusercontent.com/compose-miuix-ui/miuix/main/miuix-ui/src/commonMain/kotlin/top/yukonga/miuix/kmp/theme/Colors.kt
  - TextStyles.kt: https://raw.githubusercontent.com/compose-miuix-ui/miuix/main/miuix-ui/src/commonMain/kotlin/top/yukonga/miuix/kmp/theme/TextStyles.kt
  - Button.kt: https://raw.githubusercontent.com/compose-miuix-ui/miuix/main/miuix-ui/src/commonMain/kotlin/top/yukonga/miuix/kmp/basic/Button.kt
  - Card.kt: https://raw.githubusercontent.com/compose-miuix-ui/miuix/main/miuix-ui/src/commonMain/kotlin/top/yukonga/miuix/kmp/basic/Card.kt
  - Switch.kt: https://raw.githubusercontent.com/compose-miuix-ui/miuix/main/miuix-ui/src/commonMain/kotlin/top/yukonga/miuix/kmp/basic/Switch.kt
  - TextField.kt: https://raw.githubusercontent.com/compose-miuix-ui/miuix/main/miuix-ui/src/commonMain/kotlin/top/yukonga/miuix/kmp/basic/TextField.kt
  - Snackbar.kt: https://raw.githubusercontent.com/compose-miuix-ui/miuix/main/miuix-ui/src/commonMain/kotlin/top/yukonga/miuix/kmp/basic/Snackbar.kt
  - NavigationBar.kt: https://raw.githubusercontent.com/compose-miuix-ui/miuix/main/miuix-ui/src/commonMain/kotlin/top/yukonga/miuix/kmp/basic/NavigationBar.kt
