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
// **发件人显示名随信取品牌**：payload 带 `message.from`，地址恒为 sender、Name 是
// 这封信的品牌名（热量日记 / 开支日记 / Auth），与正文品牌同源。
// 历史实测（2026-10-08，热量日记服务）Exchange 会把显示名覆盖成邮箱对象的
// DisplayName：若收件箱仍显示旧名，兜底办法是改邮箱 DisplayName（M365 管理中心 /
// `Set-Mailbox -DisplayName`），改完即生效。
//
// **正文是 multipart/related**：HTML + Content-ID 内嵌的品牌图标（见 relatedBody）。
// 若线上某客户端把 MIME 头当正文显示，回退方案是改走 Graph 的
// fileAttachment（contentId + isInline）——本包保留 relatedBody 作为唯一发信形态。
package mail

import (
	"bytes"
	"context"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"regexp"
	"sort"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

// 内嵌图标：三品牌各一枚 PNG（scripts/genicons 生成，96px@2x 的纯色 #3482FF
// 超椭圆底 + 白色矢量）。
//
//go:embed icons/*.png
var iconFS embed.FS

// inlineIcons 是 Content-ID → PNG 字节的注册表。**cid = 文件名 + "-icon"**
//（icons/calorie-diary.png → <calorie-diary-icon>），auth 包的品牌表按这个口径引用。
var inlineIcons = func() map[string][]byte {
	m := map[string][]byte{}
	entries, err := fs.ReadDir(iconFS, "icons")
	if err != nil {
		panic(fmt.Errorf("列内嵌图标: %w", err))
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".png") {
			continue
		}
		data, err := iconFS.ReadFile("icons/" + e.Name())
		if err != nil {
			panic(fmt.Errorf("读内嵌图标 %s: %w", e.Name(), err))
		}
		m[strings.TrimSuffix(e.Name(), ".png")+"-icon"] = data
	}
	if len(m) == 0 {
		panic("mail: icons/ 下没有任何内嵌 PNG——先跑 go run ./scripts/genicons")
	}
	return m
}()

// HasInlineIcon 报告某个 cid 是否有对应的内嵌图（auth 侧测试用来钉住
// 「品牌表里的 cid 与注册表同名」，防止邮件里出现裂图）。
func HasInlineIcon(cid string) bool {
	_, ok := inlineIcons[cid]
	return ok
}

// cidRef 从 HTML 里摘出 src="cid:X"（也容忍单引号与无引号写法：正则只吃到
// 引号/空白/尖括号之前）。
var cidRef = regexp.MustCompile(`cid:([A-Za-z0-9][A-Za-z0-9._@+-]*)`)

// referencedCIDs 返回 HTML 引用到的全部 cid（定序去重，保证同一份输入拼出
// 同一份 MIME）。
func referencedCIDs(html string) []string {
	seen := map[string]bool{}
	for _, m := range cidRef.FindAllStringSubmatch(html, -1) {
		seen[m[1]] = true
	}
	out := make([]string, 0, len(seen))
	for cid := range seen {
		out = append(out, cid)
	}
	sort.Strings(out)
	return out
}

// relatedBody 把 HTML 与它引用的内嵌图拼成一个 multipart/related MIME 实体：
// 首部是 Content-Type（含 boundary），随后是 text/html 正文部件与若干
// image/png 内联部件（Content-ID + inline disposition）。
//
// **引用了没内嵌的 cid 直接报错**，不发裂图——cid 与注册表同名是 auth 模板、
// 本包注册表、生成器三方的共同约定，宁可 503 也不投递一封头部裂图的验证码信。
func relatedBody(html string) (string, error) {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	part, err := w.CreatePart(textproto.MIMEHeader{
		"Content-Type":              {"text/html; charset=utf-8"},
		"Content-Transfer-Encoding": {"8bit"},
	})
	if err != nil {
		return "", fmt.Errorf("拼 HTML 部件: %w", err)
	}
	if _, err := io.WriteString(part, html); err != nil {
		return "", fmt.Errorf("写 HTML 部件: %w", err)
	}
	for _, cid := range referencedCIDs(html) {
		data, ok := inlineIcons[cid]
		if !ok {
			return "", fmt.Errorf("邮件引用了未内嵌的 Content-ID %q", cid)
		}
		h := textproto.MIMEHeader{}
		h.Set("Content-Type", `image/png; name="`+cid+`.png"`)
		h.Set("Content-ID", "<"+cid+">")
		h.Set("Content-Disposition", `inline; filename="`+cid+`.png"`)
		h.Set("Content-Transfer-Encoding", "base64")
		p, err := w.CreatePart(h)
		if err != nil {
			return "", fmt.Errorf("拼图标部件 %s: %w", cid, err)
		}
		enc := base64.NewEncoder(base64.StdEncoding, p)
		if _, err := enc.Write(data); err != nil {
			return "", fmt.Errorf("编码图标 %s: %w", cid, err)
		}
		if err := enc.Close(); err != nil {
			return "", fmt.Errorf("收尾图标 %s: %w", cid, err)
		}
	}
	if err := w.Close(); err != nil {
		return "", fmt.Errorf("收尾 multipart: %w", err)
	}
	return "Content-Type: multipart/related; boundary=\"" + w.Boundary() +
		"\"; type=\"text/html\"\r\n\r\n" + buf.String(), nil
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

// emailAddress 是 Graph recipient 的内层对象。**Graph 的 recipient 一律是
// {"emailAddress": {...}} 包一层**——message.from 也是 recipient 型：写成平铺的
// {"address","name"} 会被 sendMail 拒成 400 RequestBodyRead（2026-10-19 线上实测，
// 当天全部验证码信 503）。Name 只给 from 用，omitempty 让收件人 payload 保持原样。
type emailAddress struct {
	Address string `json:"address"`
	Name    string `json:"name,omitempty"`
}

// recipient 既作收件人也作 message.from——复用同型，包层结构就不会只改对一头。
type recipient struct {
	EmailAddress emailAddress `json:"emailAddress"`
}

type message struct {
	From         recipient   `json:"from"`
	Subject      string      `json:"subject"`
	Body         body        `json:"body"`
	ToRecipients []recipient `json:"toRecipients"`
}

type body struct {
	ContentType string `json:"contentType"`
	Content     string `json:"content"`
}

type sendMailRequest struct {
	Message         message `json:"message"`
	SaveToSentItems bool    `json:"saveToSentItems"`
}

// Send 发一封 HTML 邮件（正文为 multipart/related：HTML + cid 内嵌品牌图标）。
// fromName 是发件人显示名（品牌名），落到
// message.from.emailAddress.name；成功 = Graph 回 202（已接受；投递仍受 Exchange 限流约束，
// 微软官方口径：sendMail 成功返回 202 Accepted、响应体为空）。
// 失败返回带状态码与响应体片段的错误——只进服务端日志，客户端只看到白话。
//
// **不自动重试**：429/5xx 的重试语义按微软节流指引要先等 Retry-After 再发，
// 而发码本身有 60 秒冷却与每 IP 5 次/分的闸，重试省不下用户等待、还多一份
// 与「202 但带 Retry-After」撞出重复投递的风险——失败就把码撤销回 503，
// 让用户手动重发，是最短也最安全的路径。
func (s *Sender) Send(ctx context.Context, fromName, to, subject, html string) error {
	// 凭据现读（app_config，10s 缺省缓存）：改库即热生效，缺键直接不出网。
	tenantID, clientID, secret := s.cfg("mail_tenant_id"), s.cfg("mail_client_id"), s.cfg("mail_client_secret")
	if tenantID == "" || clientID == "" || secret == "" {
		return errNoCredential
	}
	// 正文先拼（HTML + 内嵌图）：cid 对不上就直接失败，**不取 token、不出网**
	content, err := relatedBody(html)
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
	m := message{
		From:         recipient{EmailAddress: emailAddress{Address: sender, Name: fromName}},
		Subject:      subject,
		Body:         body{ContentType: "HTML", Content: content},
		ToRecipients: []recipient{{EmailAddress: emailAddress{Address: to}}},
	}
	payload, err := json.Marshal(sendMailRequest{Message: m})
	if err != nil {
		return fmt.Errorf("编码 sendMail 请求: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, sendURL, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("构造请求: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	req.Header.Set("Content-Type", "application/json")

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
