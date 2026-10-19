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
// **发件人显示名不在这里定**：`message.from.name` 会被 Exchange 覆盖成邮箱对象的
// DisplayName（微软官方口径，实测 202 但显示名照旧），所以 payload 里**不带 from**
// ——想让收件人看到账号服务的名字，去把邮箱的 DisplayName 改成它（M365 管理中心 /
// `Set-Mailbox -DisplayName`），改完即生效。
package mail

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

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

type emailAddress struct {
	Address string `json:"address"`
}

type recipient struct {
	EmailAddress emailAddress `json:"emailAddress"`
}

type message struct {
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

// Send 发一封 HTML 邮件。成功 = Graph 回 202（已接受；投递仍受 Exchange 限流约束，
// 微软官方口径：sendMail 成功返回 202 Accepted、响应体为空）。
// 失败返回带状态码与响应体片段的错误——只进服务端日志，客户端只看到白话。
//
// **不自动重试**：429/5xx 的重试语义按微软节流指引要先等 Retry-After 再发，
// 而发码本身有 60 秒冷却与每 IP 5 次/分的闸，重试省不下用户等待、还多一份
// 与「202 但带 Retry-After」撞出重复投递的风险——失败就把码撤销回 503，
// 让用户手动重发，是最短也最安全的路径。
func (s *Sender) Send(ctx context.Context, to, subject, html string) error {
	// 凭据现读（app_config，10s 缺省缓存）：改库即热生效，缺键直接不出网。
	tenantID, clientID, secret := s.cfg("mail_tenant_id"), s.cfg("mail_client_id"), s.cfg("mail_client_secret")
	if tenantID == "" || clientID == "" || secret == "" {
		return errNoCredential
	}
	tokenURL := s.tokenURL
	if tokenURL == "" {
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
		Subject:      subject,
		Body:         body{ContentType: "HTML", Content: html},
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
