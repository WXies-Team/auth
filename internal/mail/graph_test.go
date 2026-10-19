package mail

import (
	"context"
	"encoding/json"
	"errors"
	"io"
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
// 字段名或层级写错只有这条断言抓得住——Graph 对缺字段照样回 202，静默通过。
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
		"热量日记", "u@example.com", "【热量日记】注册验证码", "<p>654321</p>"); err != nil {
		t.Fatalf("发送失败: %v", err)
	}

	var payload struct {
		Message struct {
			From struct {
				Address string `json:"address"`
				Name    string `json:"name"`
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
	if payload.Message.From.Address != sender || payload.Message.From.Name != "热量日记" {
		t.Errorf("from 应为 %s / 热量日记，得到 %q / %q",
			sender, payload.Message.From.Address, payload.Message.From.Name)
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

	err := newTestSender(ts.URL).Send(context.Background(), "Auth", "u@example.com", "s", "<p>b</p>")
	if err == nil {
		t.Fatal("非 202 必须返回错误")
	}
	// 错误里要带状态码与响应体片段——那才是排障时唯一有用的信息（只进服务端日志）
	if !strings.Contains(err.Error(), "403") || !strings.Contains(err.Error(), "ErrorMailboxNotEnabled") {
		t.Errorf("错误应含状态码与响应体，得到: %v", err)
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
	err := s.Send(context.Background(), "Auth", "u@example.com", "s", "<p>b</p>")
	if !errors.Is(err, errNoCredential) {
		t.Fatalf("缺凭据应回 errNoCredential，得到 %v", err)
	}
}
