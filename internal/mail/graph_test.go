package mail

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// newTestSender 把 token 与 sendMail 两个端点都指到 httptest——只测请求形状，
// 不碰真实 Graph（凭据与邮箱状态随环境变，进不了 CI）。凭据由假 ConfigFunc 注入，
// 生产走 app_config 的 mail_* 键。
func newTestSender(base string) *Sender {
	creds := map[string]string{
		"mail_tenant_id":     "test-tenant",
		"mail_client_id":     "test-id",
		"mail_client_secret": "test-secret",
	}
	return &Sender{
		client:   &http.Client{Timeout: 5 * time.Second},
		cfg:      func(key string) string { return creds[key] },
		tokenURL: base + "/token",
		sendURL:  base + "/sendMail",
	}
}

// message.from 按信带发件人显示名：地址恒为 sender，Name 由调用方（邮件品牌）现传。
// **from 必须是 recipient 包层 {"emailAddress":{...}}**——写平成 {"address","name"}
// 会被 Graph 拒成 400 RequestBodyRead（2026-10-19 线上实测，全站验证码信 503），
// 所以除了解码断言，还在原始串上钉住 emailAddress 键，防结构被改回平铺。
func TestSendCarriesBrandDisplayName(t *testing.T) {
	var gotRaw string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"access_token":"tok-123","token_type":"Bearer","expires_in":3600}`)
			return
		}
		raw, _ := io.ReadAll(r.Body)
		gotRaw = string(raw)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer ts.Close()

	if err := newTestSender(ts.URL).Send(context.Background(),
		"热量日记", "u@example.com", "【热量日记】注册验证码", "<p>654321</p>", "654321"); err != nil {
		t.Fatalf("发送失败: %v", err)
	}

	var payload struct {
		Message struct {
			From struct {
				EmailAddress struct {
					Address string `json:"address"`
					Name    string `json:"name"`
				} `json:"emailAddress"`
			} `json:"from"`
			Subject      string `json:"subject"`
			ToRecipients []struct {
				EmailAddress struct{ Address string } `json:"emailAddress"`
			} `json:"toRecipients"`
		} `json:"message"`
		SaveToSentItems *bool `json:"saveToSentItems"`
	}
	if err := json.Unmarshal([]byte(gotRaw), &payload); err != nil {
		t.Fatalf("请求体不是合法 JSON: %v\n%s", err, gotRaw)
	}
	from := payload.Message.From.EmailAddress
	if from.Address != sender || from.Name != "热量日记" {
		t.Errorf("from.emailAddress 应为 %s / 热量日记，得到 %q / %q", sender, from.Address, from.Name)
	}

	// 负例：解码成功不代表结构对——平铺的 {"address","name"} 解进上面的嵌套结构
	// 只会得到零值，所以要在原始 JSON 上单独钉住包层键
	var probe struct {
		Message struct {
			From map[string]json.RawMessage `json:"from"`
		} `json:"message"`
	}
	if err := json.Unmarshal([]byte(gotRaw), &probe); err != nil {
		t.Fatalf("请求体不是合法 JSON: %v\n%s", err, gotRaw)
	}
	if _, wrapped := probe.Message.From["emailAddress"]; !wrapped {
		t.Errorf("from 必须包一层 emailAddress（Graph recipient），得到 %s", gotRaw)
	}
	if _, flat := probe.Message.From["address"]; flat {
		t.Errorf("from 不该平铺 address——Graph 会回 400 RequestBodyRead: %s", gotRaw)
	}

	if payload.Message.Subject != "【热量日记】注册验证码" {
		t.Errorf("subject 丢了: %q", payload.Message.Subject)
	}
	if len(payload.Message.ToRecipients) != 1 || payload.Message.ToRecipients[0].EmailAddress.Address != "u@example.com" {
		t.Errorf("收件人不对: %+v", payload.Message.ToRecipients)
	}
	if payload.SaveToSentItems == nil || *payload.SaveToSentItems {
		t.Error("saveToSentItems 应显式为 false（验证码不进已发送项）")
	}
}

// 非 202 一律当失败：Graph 只有 202 才表示「已接受」，4xx/5xx 绝不能被当成发成功，
// 否则用户看到「验证码已发送」却永远收不到信。
func TestSendTreatsNonAcceptedAsError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"access_token":"t","token_type":"Bearer","expires_in":3600}`)
			return
		}
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `{"error":{"code":"ErrorMailboxNotEnabled"}}`)
	}))
	defer ts.Close()

	err := newTestSender(ts.URL).Send(context.Background(), "Auth", "u@example.com", "s", "<p>b</p>", "b")
	if err == nil {
		t.Fatal("非 202 必须返回错误")
	}
	// 错误里要带状态码与响应体片段——那才是排障时唯一有用的信息（只进服务端日志）
	if !strings.Contains(err.Error(), "403") || !strings.Contains(err.Error(), "ErrorMailboxNotEnabled") {
		t.Errorf("错误应含状态码与响应体，得到: %v", err)
	}
}

// m13 回归：token URL 拼接前校验 tenantID 的 GUID 形态——带 /、..、@ 的脏值
// 不能进 URL（会把携带 client_secret 的取票请求指到租户端点的任意路径）。
// 覆盖 tokenURL 的测试形态不走拼接、不受影响。
func TestSendRejectsNonGUIDTenantID(t *testing.T) {
	for _, bad := range []string{
		"not-a-guid",
		"evil/../../v2.0/token?x=",
		"e777001e-385e-40e1-9603-90838b1427fb/../x",
		"user@host",
	} {
		s := &Sender{
			client: &http.Client{Timeout: time.Second},
			cfg: func(key string) string {
				return map[string]string{
					"mail_tenant_id":     bad,
					"mail_client_id":     "id",
					"mail_client_secret": "sec",
				}[key]
			},
			// tokenURL 留空 → 走生产拼接路径（不会真出网：GUID 校验先失败）
			tokenURL: "",
			sendURL:  "http://127.0.0.1:0/sendMail",
		}
		err := s.Send(context.Background(), "Auth", "u@example.com", "s", "<p>b</p>", "b")
		if !errors.Is(err, errBadTenant) {
			t.Errorf("tenantID=%q 应报 errBadTenant，得到 %v", bad, err)
		}
	}
	// 合法 GUID 过闸（regex 层直接断言；Send 出网路径由 TestSendCarriesBrandDisplayName
	// 覆盖——那里的测试形态覆盖 tokenURL 不走拼接）
	if !tenantIDUUID.MatchString("e777001e-385e-40e1-9603-90838b1427fb") {
		t.Error("标准 GUID 应过形态校验")
	}
	for _, ok := range []string{
		"E777001E-385E-40E1-9603-90838B1427FB", // 大写同样合法
	} {
		if !tenantIDUUID.MatchString(ok) {
			t.Errorf("%q 应过形态校验", ok)
		}
	}
}

// 缺凭据直接回「未配置」，且一个网络请求都不发：拿空 tenant 去撞微软端点只会
// 得到费解的 401，运维看不出是自己没配。
func TestSendWithoutCredentialFailsOffline(t *testing.T) {
	s := &Sender{
		client:   &http.Client{Timeout: time.Second},
		cfg:      func(string) string { return "" },
		tokenURL: "http://127.0.0.1:0/token",
		sendURL:  "http://127.0.0.1:0/sendMail",
	}
	err := s.Send(context.Background(), "Auth", "u@example.com", "s", "<p>b</p>", "b")
	if !errors.Is(err, errNoCredential) {
		t.Fatalf("缺凭据应回 errNoCredential，得到 %v", err)
	}
}

// 正文必须是 multipart/alternative：text/plain 在前、text/html 在后，两部件与
// 入参逐字一致——只发 HTML（或把纯文本丢了）都会让纯文本客户端收到 MIME 头当正文。
func TestSendBuildsMultipartAlternative(t *testing.T) {
	const htmlBody = `<html><body><p>654321</p></body></html>`
	const textBody = "验证码 654321"
	var gotRaw string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"access_token":"t","token_type":"Bearer","expires_in":3600}`)
			return
		}
		raw, _ := io.ReadAll(r.Body)
		gotRaw = string(raw)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer ts.Close()

	if err := newTestSender(ts.URL).Send(context.Background(),
		"热量日记", "u@example.com", "【热量日记】注册验证码", htmlBody, textBody); err != nil {
		t.Fatalf("发送失败: %v", err)
	}

	var payload struct {
		Message struct {
			Body struct {
				ContentType string `json:"contentType"`
				Content     string `json:"content"`
			} `json:"body"`
		} `json:"message"`
	}
	if err := json.Unmarshal([]byte(gotRaw), &payload); err != nil {
		t.Fatalf("请求体不是合法 JSON: %v\n%s", err, gotRaw)
	}
	b := payload.Message.Body
	if b.ContentType != "HTML" {
		t.Errorf("body.contentType 应为 HTML（Graph 只认 HTML/Text 两值，MIME 实体按 HTML 投递），得到 %q", b.ContentType)
	}
	head, rest, ok := strings.Cut(b.Content, "\r\n\r\n")
	if !ok {
		t.Fatalf("MIME 实体缺头部空行: %q", b.Content)
	}
	value := strings.TrimSpace(strings.TrimPrefix(head, "Content-Type:"))
	mediaType, params, err := mime.ParseMediaType(value)
	if err != nil {
		t.Fatalf("MIME 头部不可解析: %v\n%s", err, value)
	}
	if mediaType != "multipart/alternative" {
		t.Errorf("正文应为 multipart/alternative，得到 %q %v", mediaType, params)
	}

	var gotText, gotHTML string
	mr := multipart.NewReader(strings.NewReader(rest), params["boundary"])
	var order []string
	for {
		p, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("读 MIME 部件: %v", err)
		}
		raw, _ := io.ReadAll(p)
		switch ct := p.Header.Get("Content-Type"); {
		case strings.HasPrefix(ct, "text/plain"):
			gotText = string(raw)
			order = append(order, "plain")
		case strings.HasPrefix(ct, "text/html"):
			gotHTML = string(raw)
			order = append(order, "html")
		default:
			t.Errorf("未知 MIME 部件类型: %q", ct)
		}
	}
	if gotHTML != htmlBody {
		t.Errorf("HTML 部件与入参不一致:\n%s", gotHTML)
	}
	if gotText != textBody {
		t.Errorf("纯文本部件与入参不一致:\n%s", gotText)
	}
	if strings.Join(order, ",") != "plain,html" {
		t.Errorf("部件顺序应为 plain,html（客户端取最后一个能渲染的），得到 %v", order)
	}
}
