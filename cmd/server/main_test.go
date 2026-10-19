package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/WXies-Team/auth/internal/auth"
)

// requireJWTSecret：缺失或短于 32 字节必须拒启——短 secret 等于弱签名。
func TestRequireJWTSecret(t *testing.T) {
	if err := requireJWTSecret(""); err == nil {
		t.Error("空密钥应被拒")
	}
	if err := requireJWTSecret(strings.Repeat("x", 31)); err == nil {
		t.Error("31 字节应被拒")
	}
	if err := requireJWTSecret(strings.Repeat("x", 32)); err != nil {
		t.Errorf("32 字节应通过，得到 %v", err)
	}
}

// fakeVerifier 实现 verifier 接口：路由层的 401/503 翻译与成功回执不依赖真库。
type fakeVerifier struct {
	res *auth.VerifyResult
	err error
	// 记住入参，断言路由层把 Bearer 与 body 里的 app 原样传进来
	gotBearer, gotApp string
}

func (f *fakeVerifier) Verify(bearer, expectApp string) (*auth.VerifyResult, error) {
	f.gotBearer, f.gotApp = bearer, expectApp
	return f.res, f.err
}

func TestInternalVerifySuccess(t *testing.T) {
	f := &fakeVerifier{res: &auth.VerifyResult{UID: 123456789012345, Email: "a@b.com", App: "calorie-diary"}}
	h := internalVerify(f)

	req := httptest.NewRequest(http.MethodPost, "/internal/verify", strings.NewReader(`{"app":"calorie-diary"}`))
	req.Header.Set("Authorization", "Bearer tok")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("应 200，得到 %d（%s）", rec.Code, rec.Body.String())
	}
	if f.gotBearer != "Bearer tok" || f.gotApp != "calorie-diary" {
		t.Errorf("透传错误: bearer=%q app=%q", f.gotBearer, f.gotApp)
	}
	var out struct {
		UID   int64  `json:"uid"`
		Email string `json:"email"`
		App   string `json:"app"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("响应不是合法 JSON: %v", err)
	}
	// uid 是 63 位雪花整数：JSON 数字进、int64 字段出必须无损
	if out.UID != 123456789012345 || out.Email != "a@b.com" || out.App != "calorie-diary" {
		t.Errorf("回执字段错误: %+v", out)
	}
	var raw struct {
		UID json.Number `json:"uid"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("响应解析: %v", err)
	}
	// 精度守卫：整数超 2^53 后 decode 成 float64 会花位——uid 必须仍是纯整数文本
	if strings.ContainsAny(string(raw.UID), ".eE") {
		t.Errorf("uid 被序列化成了浮点: %s", rec.Body.String())
	}
}

func TestInternalVerifyRejectsMissingApp(t *testing.T) {
	f := &fakeVerifier{}
	h := internalVerify(f)
	req := httptest.NewRequest(http.MethodPost, "/internal/verify", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("app 缺失应 400，得到 %d", rec.Code)
	}
	if f.gotApp != "" {
		t.Error("app 缺失时不该调用 Verify（省一次查库）")
	}
}

func TestInternalVerifyTranslatesError(t *testing.T) {
	// 401 与 503 两条翻译路径都要落到 writeResult 的 ApiError 体
	for _, code := range []int{401, 503} {
		f := &fakeVerifier{err: &auth.HTTPError{Code: code, Message: "x"}}
		h := internalVerify(f)
		req := httptest.NewRequest(http.MethodPost, "/internal/verify", strings.NewReader(`{"app":"calorie-diary"}`))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != code {
			t.Errorf("HTTPError %d 应原样翻译，得到 %d", code, rec.Code)
		}
		var apiErr struct {
			Message string `json:"message"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &apiErr); err != nil || apiErr.Message == "" {
			t.Errorf("错误体应是 ApiError，得到 %s", rec.Body.String())
		}
	}
}

// 进程内滑动窗口：达到上限即拒、窗口滑出即放、不同键互不挤占。
func TestRateLimiterSlidingWindow(t *testing.T) {
	l := &rateLimiter{windows: map[string]*window{}}
	const win = time.Minute
	for i := 0; i < 3; i++ {
		if !l.allow("k", 3, win) {
			t.Fatalf("第 %d 次应在额度内", i+1)
		}
	}
	if l.allow("k", 3, win) {
		t.Error("第 4 次应被拒")
	}
	if !l.allow("other", 3, win) {
		t.Error("不同键不该被 k 的额度牵连")
	}
	// 把窗口内的时间戳全部拨出窗口：下一次应重新放行（且只放一次）
	l.mu.Lock()
	for _, w := range l.windows {
		for i := range w.hits {
			w.hits[i] = time.Now().Add(-2 * win)
		}
	}
	l.mu.Unlock()
	if !l.allow("k", 3, win) {
		t.Error("窗口滑出后应重新放行")
	}
}

// clientIP 的信任模型：受信代理的 XFF 从右往左取第一个非受信地址；
// 不可信来源的 XFF 一律不信。
func TestClientIPTrustModel(t *testing.T) {
	cases := []struct {
		name   string
		remote string
		xff    string
		real   string
		want   string
	}{
		{"直连无头", "203.0.113.7:1234", "", "", "203.0.113.7"},
		{"本机 curl", "127.0.0.1:5678", "", "", "127.0.0.1"},
		{"受信代理带 XFF", "127.0.0.1:1", "203.0.113.9", "", "203.0.113.9"},
		{"伪造头来自不可信源", "203.0.113.7:1", "1.2.3.4", "", "203.0.113.7"},
		{"XFF 左端伪造右端真实", "192.168.1.5:1", "9.9.9.9, 203.0.113.9", "", "203.0.113.9"},
		{"只有 X-Real-IP", "127.0.0.1:1", "", "203.0.113.9", "203.0.113.9"},
	}
	for _, c := range cases {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = c.remote
		if c.xff != "" {
			req.Header.Set("X-Forwarded-For", c.xff)
		}
		if c.real != "" {
			req.Header.Set("X-Real-IP", c.real)
		}
		if got := clientIP(req); got != c.want {
			t.Errorf("%s: clientIP = %q，应为 %q", c.name, got, c.want)
		}
	}
}
