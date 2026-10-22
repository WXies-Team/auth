package mail

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/mail"
	"regexp"
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

// base64BodyRe 匹配 Graph raw MIME 提交的合法请求体：纯 base64 字母表，无 JSON、
// 无换行头信息。
var base64BodyRe = regexp.MustCompile(`^[A-Za-z0-9+/=]+$`)

// decodeSubmitBody 把 Graph 提交体（base64 编码的整封 MIME）解回信件原文，
// 顺带钉住两条负例：请求体必须是纯 base64、且**绝不含裸 multipart/MIME 头文本**
// ——把 multipart 原文塞进 Graph 请求（旧 JSON body.content 形态）正是
// 2026-10-22 收件人看到 boundary 串的乱码根因。
func decodeSubmitBody(t *testing.T, raw string) string {
	t.Helper()
	trimmed := strings.TrimSpace(raw)
	if !base64BodyRe.MatchString(trimmed) {
		t.Fatalf("请求体应为纯 base64（Graph raw MIME 提交形态），得到: %.200q", raw)
	}
	if strings.Contains(trimmed, "multipart") || strings.Contains(trimmed, "Content-Type") {
		t.Fatalf("请求体混入裸 MIME 文本——Graph 会把它当正文投出去（乱码根因）: %.200q", raw)
	}
	decoded, err := base64.StdEncoding.DecodeString(trimmed)
	if err != nil {
		t.Fatalf("请求体 base64 不可解: %v", err)
	}
	return string(decoded)
}

// parseMessage 把 MIME 信件原文解析成标准头对象（解析失败直接 Fatal）。
func parseMessage(t *testing.T, msg string) *mail.Message {
	t.Helper()
	parsed, err := mail.ReadMessage(strings.NewReader(msg))
	if err != nil {
		t.Fatalf("MIME 信件不可解析: %v\n%s", err, msg)
	}
	return parsed
}

// 发件人显示名按信带品牌：地址恒为 sender，Name 由调用方（邮件品牌）现传。走 raw
// MIME 后显示名落进信封 From 头——非 ASCII 必须按 RFC 2047 B 编码（Graph 对 raw
// MIME 不代编码，裸 UTF-8 头在部分收件链路上被按 Latin-1 误读）。
func TestSendCarriesBrandDisplayName(t *testing.T) {
	var gotRaw, gotCT string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"access_token":"tok-123","token_type":"Bearer","expires_in":3600}`)
			return
		}
		gotCT = r.Header.Get("Content-Type")
		raw, _ := io.ReadAll(r.Body)
		gotRaw = string(raw)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer ts.Close()

	if err := newTestSender(ts.URL).Send(context.Background(),
		"热量日记", "u@example.com", "【热量日记】注册验证码", "<p>654321</p>", "654321"); err != nil {
		t.Fatalf("发送失败: %v", err)
	}
	if gotCT != "text/plain" {
		t.Errorf("Content-Type 应为 text/plain（Graph raw MIME 提交的官方形态，user-sendmail Example 4），得到 %q", gotCT)
	}

	msg := decodeSubmitBody(t, gotRaw)
	head := parseMessage(t, msg)

	from := head.Header.Get("From")
	if !strings.Contains(from, "<"+sender+">") {
		t.Errorf("From 应含发信身份 <%s>，得到 %q", sender, from)
	}
	dec := new(mime.WordDecoder)
	decodedFrom, err := dec.DecodeHeader(from)
	if err != nil {
		t.Fatalf("From 头 RFC 2047 解码失败: %v（原文 %q）", err, from)
	}
	if decodedFrom != "热量日记 <"+sender+">" {
		t.Errorf("From 解码后应为「热量日记 <%s>」，得到 %q", sender, decodedFrom)
	}
	// 负例：WordDecoder 对裸 UTF-8 也能宽容解回，编码形态必须单独钉住
	if !strings.Contains(from, "=?UTF-8?B?") {
		t.Errorf("非 ASCII 的 From 显示名必须是 RFC 2047 B 编码，得到 %q", from)
	}

	if got := head.Header.Get("To"); got != "u@example.com" {
		t.Errorf("To 头应为 u@example.com，得到 %q", got)
	}
	subj := head.Header.Get("Subject")
	if !strings.Contains(subj, "=?UTF-8?B?") {
		t.Errorf("非 ASCII Subject 必须是 RFC 2047 B 编码，得到 %q", subj)
	}
	decodedSubj, err := dec.DecodeHeader(subj)
	if err != nil {
		t.Fatalf("Subject 头 RFC 2047 解码失败: %v（原文 %q）", err, subj)
	}
	if decodedSubj != "【热量日记】注册验证码" {
		t.Errorf("Subject 解码后应还原原文，得到 %q", decodedSubj)
	}
}

// 信封头逐项钉住（固定时间 → 形态确定）：Date/From/To/Subject/MIME-Version/
// Content-Type。ASCII 主题与显示名保持原样不编码（编码只服务非 ASCII）。
func TestBuildMIMEEnvelope(t *testing.T) {
	now := time.Date(2026, 10, 22, 15, 4, 5, 0, time.UTC)
	msg, err := buildMIME("Auth", "u@example.com", "Auth 注册验证码", "<p>b</p>", "b", now)
	if err != nil {
		t.Fatalf("buildMIME 失败: %v", err)
	}
	head := parseMessage(t, msg)

	wantHeaders := map[string]string{
		"Date":         "Thu, 22 Oct 2026 15:04:05 +0000",
		"From":         "Auth <" + sender + ">",
		"To":           "u@example.com",
		"Subject":      "=?UTF-8?B?" + base64.StdEncoding.EncodeToString([]byte("Auth 注册验证码")) + "?=",
		"MIME-Version": "1.0",
	}
	for k, want := range wantHeaders {
		if got := head.Header.Get(k); got != want {
			t.Errorf("%s 头应为 %q，得到 %q", k, want, got)
		}
	}
	mediaType, params, err := mime.ParseMediaType(head.Header.Get("Content-Type"))
	if err != nil || mediaType != "multipart/alternative" || params["boundary"] == "" {
		t.Errorf("Content-Type 应为带 boundary 的 multipart/alternative，得到 %q（解析错误 %v）",
			head.Header.Get("Content-Type"), err)
	}

	// ASCII 主题/显示名原样直出，不做多余编码
	msgASCII, err := buildMIME("Auth", "u@example.com", "code 123456", "<p>b</p>", "b", now)
	if err != nil {
		t.Fatalf("buildMIME 失败: %v", err)
	}
	headASCII := parseMessage(t, msgASCII)
	if got := headASCII.Header.Get("Subject"); got != "code 123456" {
		t.Errorf("ASCII Subject 应原样，得到 %q", got)
	}
	if got := headASCII.Header.Get("From"); got != "Auth <"+sender+">" {
		t.Errorf("ASCII From 显示名应原样，得到 %q", got)
	}
}

// 正文必须是 multipart/alternative：text/plain 在前、text/html 在后，两部件均为
// base64 传输编码、解码后与入参逐字一致；全信 CRLF 行尾。
// 只发 HTML（或把纯文本丢了）都会让纯文本客户端降级失败。
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

	msg := decodeSubmitBody(t, gotRaw)

	// 全信 CRLF：任何裸 \n/\r 都说明拼装混进了平台行尾（8bit 时代的老隐患）
	if rest := strings.ReplaceAll(msg, "\r\n", ""); strings.ContainsAny(rest, "\r\n") {
		t.Errorf("MIME 行尾必须全部是 CRLF:\n%q", msg)
	}

	head := parseMessage(t, msg)
	if v := head.Header.Get("MIME-Version"); v != "1.0" {
		t.Errorf("MIME-Version 应为 1.0，得到 %q", v)
	}
	if _, err := time.Parse(time.RFC1123Z, head.Header.Get("Date")); err != nil {
		t.Errorf("Date 头应为 RFC 5322 date-time，得到 %q（%v）", head.Header.Get("Date"), err)
	}

	mediaType, params, err := mime.ParseMediaType(head.Header.Get("Content-Type"))
	if err != nil {
		t.Fatalf("MIME 头部不可解析: %v\n%s", err, head.Header.Get("Content-Type"))
	}
	if mediaType != "multipart/alternative" {
		t.Errorf("正文应为 multipart/alternative，得到 %q %v", mediaType, params)
	}

	var gotText, gotHTML string
	var order []string
	mr := multipart.NewReader(head.Body, params["boundary"])
	for {
		p, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("读 MIME 部件: %v", err)
		}
		if cte := p.Header.Get("Content-Transfer-Encoding"); cte != "base64" {
			t.Errorf("部件 %s 的 CTE 应为 base64（8bit 裸 UTF-8 在转发链路上不可靠），得到 %q",
				p.Header.Get("Content-Type"), cte)
		}
		raw, _ := io.ReadAll(p)
		decoded, err := base64.StdEncoding.DecodeString(string(raw))
		if err != nil {
			t.Fatalf("部件 base64 不可解: %v\n%s", err, raw)
		}
		switch ct := p.Header.Get("Content-Type"); {
		case strings.HasPrefix(ct, "text/plain"):
			gotText = string(decoded)
			order = append(order, "plain")
		case strings.HasPrefix(ct, "text/html"):
			gotHTML = string(decoded)
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
