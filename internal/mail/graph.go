// Package mail 通过 Microsoft Graph 发验证码邮件。
//
// **为什么是 Graph 而不是 SMTP**：Exchange Online 的 SMTP 基础认证 2026-12 底对存量租户
// 默认关闭，OAuth + SMTP AUTH 还要自己实现 XOAUTH2 与 MIME 编码；Graph 只需一次
// HTTPS POST，微软官方口径也是「新应用优先 Graph」。热量日记服务联调实测
// （2026-10-08）：token 200、sendMail 202，邮件实际送达——本包照抄其成熟实现。
//
// **凭据只在生产库 `app_config`，仓库不出现任何值**。键：`mail_tenant_id` /
// `mail_client_id` / `mail_client_secret`；缺任一键 Send 回「未配置」错误，
// 路由侧表现为 503，启动日志另有一条 Warn 提醒（省得等用户注册失败才发现）。
//
// **发信身份**：`/users/{upn}` 必须填主邮箱 UPN——别名填进去会得到
// `ErrorInvalidUser`（实测）。
//
// **发件人显示名随信取品牌**：From 落在信封头里（见 buildMIME），地址恒为 sender、
// 显示名是这封信的品牌名（热量日记 / 开支日记 / Auth），与正文品牌同源。
// 历史实测（2026-10-08，热量日记服务）Exchange 会把显示名覆盖成邮箱对象的
// DisplayName：若收件箱仍显示旧名，兜底办法是改邮箱 DisplayName（M365 管理中心 /
// `Set-Mailbox -DisplayName`），改完即生效。
//
// **正文以 raw MIME 实体提交（完整 RFC 5322 信件）**：信封头 + multipart/
// alternative 双部件（text/plain 降级 + text/html，见 buildMIME），整体 base64 后
// 走 Graph 的 MIME 提交路径（sendMail + Content-Type: text/plain，官方文档
// user-sendmail Example 4「Send a new message using MIME format」形态）。
// **不走 JSON 的 message.body.content**：Graph 不解析塞在 JSON 字符串里的 MIME，
// 会把 multipart 原文当正文投出去——收件人看到 boundary 串、样式全无
//（2026-10-22 用户实收证据，本形态即为该次乱码的修复）。
// 品牌 logo 走 https 托管图（auth.horatio.cn/brand/…），不内嵌 CID。
package mail

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"regexp"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

// rfc2047B 按 RFC 2047 的 B 编码（base64）给头值里的非 ASCII 段加编码：Graph 对
// raw MIME 的 Subject/From 不会代编码，裸 UTF-8 头在部分收件链路上被按 Latin-1
// 误读（乱码的另一隐患）。纯 ASCII 原样返回——ASCII 头值不该编码。
func rfc2047B(s string) string {
	if s == "" || isASCII(s) {
		return s
	}
	data := base64.StdEncoding.EncodeToString([]byte(s))
	// RFC 2047 限定单个 encoded-word 的字符数据 ≤76 字符：超长按 76 切段，段间用
	// 折行空白（CRLF + SP，RFC 5322 头折叠）连接。本站主题/品牌名都是短串，切段
	// 实际不触发，但头编码函数不该赌输入长度。
	var b strings.Builder
	for len(data) > 76 {
		b.WriteString("=?UTF-8?B?" + data[:76] + "?=\r\n ")
		data = data[76:]
	}
	b.WriteString("=?UTF-8?B?" + data + "?=")
	return b.String()
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// base64CTE 把正文编成 RFC 2045 的 base64 传输编码（部件头 CTE: base64）：
// 76 字符折行、行尾 CRLF。用 base64 而不是 8bit 裸 UTF-8：裸 8bit 在转发链路上
// 会被某一段重新判定编码（正是本包 2026-10-22 乱码报告的第二隐患）。
func base64CTE(s string) string {
	data := base64.StdEncoding.EncodeToString([]byte(s))
	var b strings.Builder
	for len(data) > 76 {
		b.WriteString(data[:76])
		b.WriteString("\r\n")
		data = data[76:]
	}
	b.WriteString(data)
	b.WriteString("\r\n")
	return b.String()
}

// buildMIME 拼出投给 Graph 的完整 RFC 5322 信件：信封头（Date/From/To/Subject/
// MIME-Version/Content-Type）+ multipart/alternative 正文（text/plain 在前、
// text/html 在后，两部件均 base64 传输编码），所有行尾 CRLF。
//
// **为什么必须补信封头**：旧实现只拼裸 multipart 实体塞进 JSON，Graph 不解析；改走
// raw MIME 提交后（见 Send），收件人与主题只能从信封头来——缺 To/Subject 的 MIME
// 要么被 Exchange 拒、要么丢收件人。Subject/From 含中文时按 RFC 2047 B 编码，
// Graph 不会代编码。
func buildMIME(fromName, to, subject, html, text string, now time.Time) (string, error) {
	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	plain, err := w.CreatePart(textproto.MIMEHeader{
		"Content-Type":              {"text/plain; charset=utf-8"},
		"Content-Transfer-Encoding": {"base64"},
	})
	if err != nil {
		return "", fmt.Errorf("拼纯文本部件: %w", err)
	}
	if _, err := io.WriteString(plain, base64CTE(text)); err != nil {
		return "", fmt.Errorf("写纯文本部件: %w", err)
	}
	part, err := w.CreatePart(textproto.MIMEHeader{
		"Content-Type":              {"text/html; charset=utf-8"},
		"Content-Transfer-Encoding": {"base64"},
	})
	if err != nil {
		return "", fmt.Errorf("拼 HTML 部件: %w", err)
	}
	if _, err := io.WriteString(part, base64CTE(html)); err != nil {
		return "", fmt.Errorf("写 HTML 部件: %w", err)
	}
	if err := w.Close(); err != nil {
		return "", fmt.Errorf("收尾 multipart: %w", err)
	}

	var msg bytes.Buffer
	// Date 走 RFC 5322 date-time（time.RFC1123Z 同型）：Exchange 校验信封头形态。
	fmt.Fprintf(&msg, "Date: %s\r\n", now.Format(time.RFC1123Z))
	fmt.Fprintf(&msg, "From: %s <%s>\r\n", rfc2047B(fromName), sender)
	fmt.Fprintf(&msg, "To: %s\r\n", to)
	fmt.Fprintf(&msg, "Subject: %s\r\n", rfc2047B(subject))
	msg.WriteString("MIME-Version: 1.0\r\n")
	fmt.Fprintf(&msg, "Content-Type: multipart/alternative; boundary=%q\r\n\r\n", w.Boundary())
	msg.Write(body.Bytes())
	return msg.String(), nil
}

const (
	// sender 是发信身份（显示地址，不是密钥），保持常量：它出现在每封信的 From 里，
	// 换它属于产品决策而不是环境差异。
	sender = "service@horatio.cn"

	graphTokenURL = "https://login.microsoftonline.com/" // 后接 {tenant}/oauth2/v2.0/token
	graphSendURL  = "https://graph.microsoft.com/v1.0/users/" + sender + "/sendMail"
)

// ConfigFunc 读 app_config 的一个键（改库即热生效），取不到返回 ""。
type ConfigFunc func(key string) string

// errNoCredential 是「app_config 缺 mail_* 键」的唯一出口，调用方按「邮件服务
// 暂不可用」处理（auth 侧回 503），绝不能当成微软侧故障去重试。
var errNoCredential = errors.New("邮件凭据未配置（app_config 缺 mail_tenant_id / mail_client_id / mail_client_secret）")

// tenantIDUUID 是 Azure AD 租户 ID 的 GUID 形态。mail_tenant_id 会被直接拼进
// token URL（graphTokenURL + tenantID + "/oauth2/v2.0/token"）：不校验形态的话，
// 一个带 "/"、".." 或 "@" 的脏值能把携带 client_secret 的取票请求指到
// login.microsoftonline.com 上的任意路径——凭据虽不至于泄给第三方主机，
// 但会以费解的方式失败并把 secret 打进对端访问日志。生产值恒为 GUID
//（线上核过：app_config 的 mail_tenant_id 是标准 8-4-4-4-12），校验零成本。
var tenantIDUUID = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// errBadTenant 是「mail_tenant_id 不是 GUID」的唯一出口，与 errNoCredential 同样
// 属于配置态错误：路由侧回 503，运维看日志改键，不重试。
var errBadTenant = errors.New("mail_tenant_id 配置无效（应为 GUID 形态）")

// Sender 发一封信。零值不可用，用 [New]。
type Sender struct {
	cfg    ConfigFunc
	client *http.Client
	// 端点覆盖：留空走默认（token 端点按 mail_tenant_id 现拼、sendMail 固定 URL），
	// 测试把这两个字段指到 httptest 才需要填——生产恒空。
	tokenURL string
	sendURL  string
}

// sendTimeout 是**一次 Send 的总预算**，罩住「取 token」与「sendMail」两次网络往返。
// 声明成变量只是让测试能塞进毫秒级预算，生产不改。
var sendTimeout = 15 * time.Second

// New 返回生产实现：凭据从 app_config 现读（10s 缓存），token 走 client credentials，
// 发信 15s 总超时。
//
// **为什么不缓存 token**（每封信现取一次）：clientcredentials 的 TokenSource 要在
// 创建时绑定 context，而「15s 必须是两段之和」只有把截止时刻放进 Send 的 ctx 才成立
// ——复用跨调用缓存源，token 段拿不到 Send 的截止时刻，最坏就是 token 15s +
// 发信 15s = 30s 挂着不回。发码频次极低（每邮箱每日 10 条、每 IP 5 次/分），
// 每封多一次 token 往返（毫秒级）换总预算封顶，划算。
func New(cfg ConfigFunc) *Sender {
	return &Sender{
		cfg:    cfg,
		client: &http.Client{Timeout: sendTimeout},
	}
}

// Send 发一封邮件：正文为完整 RFC 5322 信件（信封头 + multipart/alternative 双部件，
// 见 buildMIME），整体 base64 后走 Graph 的 raw MIME 提交路径（sendMail +
// Content-Type: text/plain）。fromName 是发件人显示名（品牌名），落进信封 From 头
//（非 ASCII 按 RFC 2047 编码）；text 是 HTML 的忠实纯文本降级（auth 模板逐封提供）。
// 成功 = Graph 回 202（已接受；投递仍受 Exchange 限流约束，
// 微软官方口径：sendMail 成功返回 202 Accepted、响应体为空）。
// 失败返回带状态码与响应体片段的错误——只进服务端日志，客户端只看到白话。
//
// **已发送项**：MIME 提交没有 saveToSentItems 开关（那是 JSON 形态的字段），按
// sendMail 文档口径信件会存进发信邮箱的已发送项——与旧 JSON 路径显式 false 不同，
// 属 MIME 提交的固有形态，验证码频次下可接受。
//
// **不自动重试**：429/5xx 的重试语义按微软节流指引要先等 Retry-After 再发，
// 而发码本身有 60 秒冷却与每 IP 5 次/分的闸，重试省不下用户等待、还多一份
// 与「202 但带 Retry-After」撞出重复投递的风险——失败就把码撤销回 503，
// 让用户手动重发，是最短也最安全的路径。
func (s *Sender) Send(ctx context.Context, fromName, to, subject, html, text string) error {
	// 凭据现读（app_config，10s 缺省缓存）：改库即热生效，缺键直接不出网。
	tenantID, clientID, secret := s.cfg("mail_tenant_id"), s.cfg("mail_client_id"), s.cfg("mail_client_secret")
	if tenantID == "" || clientID == "" || secret == "" {
		return errNoCredential
	}
	// 信件先拼：完整信封头 + multipart/alternative（纯文本 + HTML 双部件）
	mimeMsg, err := buildMIME(fromName, to, subject, html, text, time.Now())
	if err != nil {
		return err
	}
	tokenURL := s.tokenURL
	if tokenURL == "" {
		// 拼 URL 前先验 GUID 形态（见 tenantIDUUID）；测试覆盖 tokenURL 时不走这条
		if !tenantIDUUID.MatchString(tenantID) {
			return fmt.Errorf("%w: %q", errBadTenant, tenantID)
		}
		tokenURL = graphTokenURL + tenantID + "/oauth2/v2.0/token"
	}
	sendURL := s.sendURL
	if sendURL == "" {
		sendURL = graphSendURL
	}
	ccfg := &clientcredentials.Config{
		ClientID:     clientID,
		ClientSecret: secret,
		TokenURL:     tokenURL,
		Scopes:       []string{"https://graph.microsoft.com/.default"},
	}

	// 总预算从进 Send 起算：token 与 sendMail 共用同一个截止时刻（见 sendTimeout 注释）。
	ctx, cancel := context.WithTimeout(ctx, sendTimeout)
	defer cancel()
	// oauth2.HTTPClient 决定**取 token** 那次请求用哪个 client（默认无超时的
	// http.DefaultClient），ctx 自带的 deadline 才是它的硬闸。
	ctx = context.WithValue(ctx, oauth2.HTTPClient, s.client)
	tok, err := ccfg.TokenSource(ctx).Token()
	if err != nil {
		return fmt.Errorf("取 Graph 访问令牌: %w", err)
	}
	// Graph 的 raw MIME 提交路径：请求体 = base64(完整 MIME 信件)，Content-Type:
	// text/plain（官方形态，user-sendmail 文档 Example 4「Send a new message using
	// MIME format」）。JSON 形态的 message.body.content 不解析 MIME——那正是乱码根因。
	payload := []byte(base64.StdEncoding.EncodeToString([]byte(mimeMsg)))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, sendURL, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("构造请求: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	req.Header.Set("Content-Type", "text/plain")

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("调用 Graph sendMail: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusAccepted {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("Graph sendMail 返回 %d: %s", resp.StatusCode, string(raw))
	}
	return nil
}
