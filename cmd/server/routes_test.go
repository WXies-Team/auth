package main

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/WXies-Team/auth/internal/auth"
	"github.com/WXies-Team/auth/internal/ui"
	"github.com/WXies-Team/auth/internal/config"
	"github.com/WXies-Team/auth/internal/db"
	"golang.org/x/crypto/bcrypt"
)

const routeTestSecret = "route-test-secret-0123456789-0123456789"

// routeEnv 是路由级测试的完整装配：真库 + 与 main 同一份 registerRoutes——
// 「老端点的响应形状」只有打到真 handler 上才算数，光测业务层证明不了字节不变。
type routeEnv struct {
	mux  http.Handler
	svc  *auth.Service
	pool *sql.DB
}

func newRouteEnv(t *testing.T) *routeEnv {
	t.Helper()
	dsn := os.Getenv("TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("未设置 TEST_MYSQL_DSN，跳过路由真库测试")
	}
	pool, err := db.Open(dsn)
	if err != nil {
		t.Fatalf("连接测试库: %v", err)
	}
	t.Cleanup(func() { _ = pool.Close() })
	if err := db.EnsureSchema(pool); err != nil {
		t.Fatalf("建表: %v", err)
	}
	// 每轮清干净（与 internal/auth 的用例同一张测试 schema，互不残留）
	for _, table := range []string{"users", "otp_codes", "sessions", "passkeys", "totp_factors",
		"recovery_codes", "webauthn_challenges", "login_states", "audit_logs", "ai_usage", "app_config",
		"user_profile", "admin_scopes", "user_bans", "project_policy", "project_access", "oauth_clients",
		"user_invites"} {
		if _, err := pool.Exec("DELETE FROM " + table); err != nil {
			t.Fatalf("清空 %s: %v", table, err)
		}
	}
	t.Setenv("TOTP_ENC_KEY", strings.Repeat("k", 32))
	// 内部凭据（M3）：AI 三端点要验 X-Internal-Token，路由测试统一给一个 hook_token。
	// 单独验「错头/缺头/键没配」的用例自己改这张表（见 TestAIRouteInternalTokenGate）。
	if _, err := pool.Exec(
		"INSERT INTO app_config (`key`, `value`) VALUES ('hook_token', ?)"+
			" ON DUPLICATE KEY UPDATE `value` = VALUES(`value`)", hookTokenForTest); err != nil {
		t.Fatalf("种内部令牌: %v", err)
	}
	wa, err := auth.NewWebAuthn(nil)
	if err != nil {
		t.Fatalf("NewWebAuthn: %v", err)
	}
	svc, err := auth.NewService(pool, routeTestSecret, nil, auth.NewHooks(func(string) (string, error) { return "", nil }), wa)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	mux := http.NewServeMux()
	registerRoutes(mux, svc, config.New(pool), pool)
	return &routeEnv{mux: mux, svc: svc, pool: pool}
}

var uidSeq atomic.Int64

// seedUser 直接落一行账号（注册链路要发邮件，路由测试用不到；业务层另有覆盖）。
func seedUser(t *testing.T, e *routeEnv, email, password, role string) int64 {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	if err != nil {
		t.Fatalf("散列密码: %v", err)
	}
	uid := time.Now().UnixNano()/1000*1000 + uidSeq.Add(1)
	if _, err := e.pool.Exec(
		"INSERT INTO users (id, email, password_hash, created_at, token_version, role) VALUES (?,?,?,?,1,?)",
		uid, email, string(hash), time.Now().UnixMilli(), role); err != nil {
		t.Fatalf("落账号: %v", err)
	}
	return uid
}

// do 发一个请求并回 recorder。
func (e *routeEnv) do(t *testing.T, method, path, body string, mutate func(*http.Request)) *httptest.ResponseRecorder {
	t.Helper()
	var reader *strings.Reader
	if body == "" {
		reader = strings.NewReader("")
	} else {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, reader)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if mutate != nil {
		mutate(req)
	}
	rec := httptest.NewRecorder()
	e.mux.ServeHTTP(rec, req)
	return rec
}

// keysOf 取 JSON 顶层键集合（按逗号拼成定序串），用于「形状一字不变」的断言。
func keysOf(t *testing.T, raw []byte) string {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("响应不是 JSON 对象: %v (%s)", err, raw)
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	// 排序保证断言稳定
	for i := 0; i < len(keys); i++ {
		for j := i + 1; j < len(keys); j++ {
			if keys[j] < keys[i] {
				keys[i], keys[j] = keys[j], keys[i]
			}
		}
	}
	return strings.Join(keys, ",")
}

// ---- 老端点回归：已发布日记 App 依赖的形状 ----

// /auth/login 的成功回执必须恰好 {token,email,mustChangePassword,deletePendingCancelled}
//（契约 4：两个 bool 无 omitempty、显式出现），失败回执恰好 {message}；
// 且请求体多带未知字段照常工作（decode 不拒未知字段是前向兼容的既定口径）。
func TestLegacyLoginResponseShape(t *testing.T) {
	e := newRouteEnv(t)
	seedUser(t, e, "legacy-login@example.com", "secret123", "user")

	rec := e.do(t, "POST", "/auth/login",
		`{"email":"legacy-login@example.com","password":"secret123","app":"calorie-diary","futureField":"ignored"}`,
		nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("登录应 200，得到 %d（%s）", rec.Code, rec.Body.String())
	}
	if got := keysOf(t, rec.Body.Bytes()); got != "deletePendingCancelled,email,mustChangePassword,token" {
		t.Errorf("登录成功回执形状应恰为 deletePendingCancelled,email,mustChangePassword,token，得到 %s", got)
	}

	rec = e.do(t, "POST", "/auth/login",
		`{"email":"legacy-login@example.com","password":"wrong","app":"calorie-diary"}`, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("错密码应 401，得到 %d", rec.Code)
	}
	if got := keysOf(t, rec.Body.Bytes()); got != "message" {
		t.Errorf("错误回执形状应恰为 message，得到 %s", got)
	}
}

// /api/sessions 的一条会话必须恰好七个字段，且 App 传 Bearer 时行为不变。
func TestLegacySessionsResponseShape(t *testing.T) {
	e := newRouteEnv(t)
	seedUser(t, e, "legacy-sess@example.com", "secret123", "user")
	resp, err := e.svc.Login("legacy-sess@example.com", "secret123", "calorie-diary",
		auth.SessionMeta{IP: "10.1.2.3", UserAgent: "GoTest/1.0"})
	if err != nil {
		t.Fatalf("登录: %v", err)
	}
	rec := e.do(t, "GET", "/api/sessions", "", func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+resp.Token)
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("取设备列表应 200，得到 %d（%s）", rec.Code, rec.Body.String())
	}
	var body struct {
		Sessions []map[string]json.RawMessage `json:"sessions"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.Sessions == nil {
		t.Fatalf("回执应是 {sessions:[...]} 对象信封: %v（%s）", err, rec.Body.String())
	}
	items := body.Sessions
	if len(items) == 0 {
		t.Fatal("登录过应至少一台设备")
	}
	got := make([]string, 0, len(items[0]))
	for k := range items[0] {
		got = append(got, k)
	}
	joined := strings.Join(got, ",")
	for _, want := range []string{"id", "app", "device", "ip", "createdAt", "lastSeenAt", "current"} {
		if !strings.Contains(joined, want) {
			t.Errorf("设备行缺字段 %s，得到 %s", want, joined)
		}
	}
	if len(items[0]) != 7 {
		t.Errorf("设备行应恰好 7 个字段，得到 %d（%s）", len(items[0]), joined)
	}
}

// /health 三真值一个不少、一个不多；DB 正常时 status=ok。
func TestLegacyHealthShape(t *testing.T) {
	e := newRouteEnv(t)
	rec := e.do(t, "GET", "/health", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("健康检查应 200，得到 %d", rec.Code)
	}
	if got := keysOf(t, rec.Body.Bytes()); got != "jwtConfigured,mailConfigured,status" {
		t.Errorf("健康回执形状应恰为三真值，得到 %s", got)
	}
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body["status"] != "ok" || body["jwtConfigured"] != true {
		t.Errorf("三真值应为 ok/true，得到 %v", body)
	}
}

// /internal/verify 的回执形状（环回来源才放行）。
func TestLegacyInternalVerifyShape(t *testing.T) {
	e := newRouteEnv(t)
	seedUser(t, e, "legacy-verify@example.com", "secret123", "user")
	resp, err := e.svc.Login("legacy-verify@example.com", "secret123", "calorie-diary", auth.SessionMeta{})
	if err != nil {
		t.Fatalf("登录: %v", err)
	}
	rec := e.do(t, "POST", "/internal/verify", `{"app":"calorie-diary"}`, func(r *http.Request) {
		r.RemoteAddr = "127.0.0.1:51234"
		r.Header.Set("Authorization", "Bearer "+resp.Token)
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("环回应放行，得到 %d（%s）", rec.Code, rec.Body.String())
	}
	if got := keysOf(t, rec.Body.Bytes()); got != "app,email,uid" {
		t.Errorf("verify 回执形状应恰为 app,email,uid，得到 %s", got)
	}
}

// ---- Web 新端点 ----

// 登录页可渲染、未登录的控制台页 302 去登录页。
func TestWebPageGates(t *testing.T) {
	e := newRouteEnv(t)
	rec := e.do(t, "GET", "/web/login", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("登录页应 200，得到 %d", rec.Code)
	}
	html := rec.Body.String()
	// M4 切流后页面壳 = SPA 宿主页：同源脚本、零外链、no-store + Client Hints opt-in
	for _, want := range []string{"/wasm/authweb.js", "<title>登录 · Auth", "viewport-fit=cover"} {
		if !strings.Contains(html, want) {
			t.Errorf("SPA 壳缺关键结构 %q", want)
		}
	}
	if strings.Contains(html, "https://") {
		t.Error("SPA 壳出现外链")
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("页面壳应 no-store，得到 %q", cc)
	}
	if ch := rec.Header().Get("Accept-CH"); ch != ui.ClientHintsHeader {
		t.Errorf("页面壳应带 Accept-CH opt-in，得到 %q", ch)
	}
	if rec := e.do(t, "GET", "/web/console", "", nil); rec.Code != http.StatusFound {
		t.Errorf("未登录访问控制台应 302，得到 %d", rec.Code)
	}
}

// 密码登录：签双 cookie（属性齐）、回 AuthResponse 同形；同源校验拦跨站提交。
func TestWebLoginIssuesCookies(t *testing.T) {
	e := newRouteEnv(t)
	seedUser(t, e, "web-login@example.com", "secret123", "user")

	// 跨站 Origin 拒绝（Origin 与 Host 不同源）
	rec := e.do(t, "POST", "/web/login/password", `{"email":"web-login@example.com","password":"secret123"}`,
		func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") })
	if rec.Code != http.StatusForbidden {
		t.Fatalf("跨站 Origin 应 403，得到 %d", rec.Code)
	}

	rec = e.do(t, "POST", "/web/login/password", `{"email":"web-login@example.com","password":"secret123"}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("登录应 200，得到 %d（%s）", rec.Code, rec.Body.String())
	}
	if got := keysOf(t, rec.Body.Bytes()); got != "deletePendingCancelled,email,mustChangePassword,token" {
		t.Errorf("登录回执应与 AuthResponse 同形，得到 %s", got)
	}
	jar := map[string]*http.Cookie{}
	for _, c := range rec.Result().Cookies() {
		jar[c.Name] = c
	}
	sess := jar[auth.WebCookieName]
	csrf := jar[auth.WebCSRFCookieName]
	if sess == nil || csrf == nil {
		t.Fatalf("应签发两枚 cookie，得到 %v", keys(jar))
	}
	if !sess.HttpOnly || !sess.Secure || sess.Path != "/" || sess.SameSite != http.SameSiteStrictMode {
		t.Errorf("会话 cookie 属性不对: %+v", sess)
	}
	if csrf.HttpOnly || !csrf.Secure || csrf.SameSite != http.SameSiteStrictMode {
		t.Errorf("CSRF cookie 应可读且同样严格: %+v", csrf)
	}
	// 库里只有 hash：明文 token 不落库
	var stored string
	if err := e.pool.QueryRow("SELECT web_token_hash FROM sessions WHERE user_id = (SELECT id FROM users WHERE email = ?)",
		"web-login@example.com").Scan(&stored); err != nil {
		t.Fatalf("查会话行: %v", err)
	}
	if stored == "" || stored == sess.Value {
		t.Error("库里不该出现 cookie 明文")
	}
}

// CSRF：带 cookie 的非 GET 请求缺 X-CSRF-Token 必须 403——**老端点同样受约束**
//（cookie 是新能力，老客户端走 Bearer 不受它影响）。
func TestWebCSRFEnforcedOnCookieRequests(t *testing.T) {
	e := newRouteEnv(t)
	seedUser(t, e, "web-csrf@example.com", "secret123", "user")
	rec := e.do(t, "POST", "/web/login/password", `{"email":"web-csrf@example.com","password":"secret123"}`, nil)
	sess := cookieNamed(rec, auth.WebCookieName)
	csrf := cookieNamed(rec, auth.WebCSRFCookieName)
	if sess == nil || csrf == nil {
		t.Fatal("登录没签出 cookie")
	}
	// 浏览器会把两枚 cookie 一起带上（同 Path 同域），测试照此模拟
	withCookies := func(r *http.Request) {
		r.AddCookie(sess)
		r.AddCookie(csrf)
	}

	// 缺 CSRF 头 → 403
	rec2 := e.do(t, "POST", "/web/session", `{}`, withCookies)
	if rec2.Code != http.StatusForbidden {
		t.Errorf("缺 CSRF 头应 403，得到 %d（%s）", rec2.Code, rec2.Body.String())
	}
	// 带对的头 → 200，回执含 uid/role/csrfToken
	rec3 := e.do(t, "POST", "/web/session", `{}`, func(r *http.Request) {
		r.AddCookie(sess)
		r.AddCookie(csrf)
		r.Header.Set("X-CSRF-Token", csrf.Value)
	})
	if rec3.Code != http.StatusOK {
		t.Fatalf("带 CSRF 头应 200，得到 %d（%s）", rec3.Code, rec3.Body.String())
	}
	var me struct {
		UID     int64  `json:"uid"`
		Email   string `json:"email"`
		Role    string `json:"role"`
		CSRF    string `json:"csrfToken"`
		HasPass bool   `json:"passwordSet"`
	}
	if err := json.Unmarshal(rec3.Body.Bytes(), &me); err != nil {
		t.Fatalf("解析 /web/session: %v", err)
	}
	if me.Email != "web-csrf@example.com" || me.CSRF != csrf.Value || !me.HasPass {
		t.Errorf("会话回执字段不对: %+v", me)
	}

	// 老端点同样吃这道闸：带 cookie 的 DELETE 没有 CSRF 头 → 403
	rec4 := e.do(t, "DELETE", "/api/sessions/1234567890123456789", "", withCookies)
	if rec4.Code != http.StatusForbidden {
		t.Errorf("cookie 调老端点缺 CSRF 头应 403，得到 %d", rec4.Code)
	}
	// 同一个老端点走 Bearer 完全不受影响（老客户端口径）
	resp, err := e.svc.Login("web-csrf@example.com", "secret123", "calorie-diary", auth.SessionMeta{})
	if err != nil {
		t.Fatalf("取 JWT: %v", err)
	}
	rec5 := e.do(t, "DELETE", "/api/sessions/1234567890123456789", "", func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+resp.Token)
	})
	// 自己的会话才踢得到，别人的 404——形状是 ApiError，且绝不是 403（没被 CSRF 拦）
	if rec5.Code != http.StatusNotFound {
		t.Errorf("Bearer 调老端点不应被 CSRF 拦，得到 %d（%s）", rec5.Code, rec5.Body.String())
	}
}

// 管理后台四道闸：无凭据 401、非 cookie 401、非管理员 403；页面对非管理员 302。
func TestAdminGateKeepsNonAdminsOut(t *testing.T) {
	e := newRouteEnv(t)
	seedUser(t, e, "plain-user@example.com", "secret123", "user")

	// 完全没登录
	rec := e.do(t, "GET", "/admin/users", "", nil)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("未登录访问后台应 401，得到 %d", rec.Code)
	}
	// Bearer 不给后台钥匙
	resp, err := e.svc.Login("plain-user@example.com", "secret123", "calorie-diary", auth.SessionMeta{})
	if err != nil {
		t.Fatalf("取 JWT: %v", err)
	}
	rec = e.do(t, "GET", "/admin/users", "", func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+resp.Token)
	})
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("Bearer 调后台应 401，得到 %d", rec.Code)
	}

	// 普通用户的 cookie：角色闸在前
	login := e.do(t, "POST", "/web/login/password", `{"email":"plain-user@example.com","password":"secret123"}`, nil)
	sess := cookieNamed(login, auth.WebCookieName)
	csrf := cookieNamed(login, auth.WebCSRFCookieName)
	if sess == nil || csrf == nil {
		t.Fatal("登录没签出 cookie")
	}
	rec = e.do(t, "GET", "/admin/users", "", func(r *http.Request) { r.AddCookie(sess) })
	if rec.Code != http.StatusForbidden {
		t.Errorf("非管理员应 403，得到 %d（%s）", rec.Code, rec.Body.String())
	}
	// 后台页面对非管理员 302 回概览
	rec = e.do(t, "GET", "/web/admin", "", func(r *http.Request) { r.AddCookie(sess) })
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/web/console" {
		t.Errorf("非管理员看后台页应 302 到概览，得到 %d %q", rec.Code, rec.Header().Get("Location"))
	}
	// 自助台页面对已登录用户放行
	rec = e.do(t, "GET", "/web/console", "", func(r *http.Request) { r.AddCookie(sess) })
	if rec.Code != http.StatusOK {
		t.Errorf("已登录访问概览应 200，得到 %d", rec.Code)
	}
	// 登出：吊销本行 + Clear-Site-Data + cookie 清除，随后会话立刻 401
	rec = e.do(t, "POST", "/web/logout", `{}`, func(r *http.Request) {
		r.AddCookie(sess)
		r.Header.Set("X-CSRF-Token", csrf.Value)
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("登出应 200，得到 %d（%s）", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Clear-Site-Data") == "" {
		t.Error("登出应带 Clear-Site-Data")
	}
	if c := cookieNamed(rec, auth.WebCookieName); c == nil || c.Value != "" {
		t.Error("登出应清掉会话 cookie")
	}
	after := e.do(t, "POST", "/web/session", `{}`, func(r *http.Request) { r.AddCookie(sess) })
	if after.Code != http.StatusUnauthorized {
		t.Errorf("登出后的会话应 401，得到 %d", after.Code)
	}
}

// 契约 5：cookie 会话调 /auth/change-password **换发**——响应 Set-Cookie 刷新会话
//（旧 cookie 当场失效）、其它会话全被踢、回执 token 恒空串（绝不给 app='web' 的
// 会话签 JWT）、sessions 表不许留下 app='web' 却没有 web_token_hash 的僵尸行。
//（旧 M1「本会话行保活、cookie 照用」口径由本批契约推翻：改密后凭据必须轮换。）
func TestWebChangePasswordRotatesCurrentSession(t *testing.T) {
	e := newRouteEnv(t)
	uid := seedUser(t, e, "web-chpw@example.com", "secret123", "user")
	sess, csrf := loginCookie(t, e, "web-chpw@example.com", "secret123")
	withCSRF := func(r *http.Request) {
		r.AddCookie(sess)
		r.AddCookie(csrf)
		r.Header.Set("X-CSRF-Token", csrf.Value)
	}
	// 另一台设备：App 侧 JWT 登录（改密后应被吊销）
	appResp, err := e.svc.Login("web-chpw@example.com", "secret123", "calorie-diary", auth.SessionMeta{})
	if err != nil {
		t.Fatalf("App 登录: %v", err)
	}

	// 改密（cookie + CSRF；登录即强认证，2 小时窗内直接过）
	rec := e.do(t, "POST", "/auth/change-password",
		`{"oldPassword":"secret123","newPassword":"newsecret9"}`, withCSRF)
	if rec.Code != http.StatusOK {
		t.Fatalf("web 改密应 200，得到 %d（%s）", rec.Code, rec.Body.String())
	}
	// 响应形状仍 {token,email,...}，但 token 必须是空串——绝不给 app='web' 的会话签 JWT
	var resp authResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("改密回执解析: %v（%s）", err, rec.Body.String())
	}
	if resp.Token != "" {
		t.Errorf("web 改密不该回 JWT（aud='web' 是死 token），得到 %q", resp.Token)
	}
	if resp.Email != "web-chpw@example.com" {
		t.Errorf("回执 email 应为库里当前邮箱，得到 %q", resp.Email)
	}
	// 契约 5：Set-Cookie 换发新会话（新值 ≠ 旧值）
	newSess := cookieNamed(rec, auth.WebCookieName)
	newCSRF := cookieNamed(rec, auth.WebCSRFCookieName)
	if newSess == nil || newCSRF == nil || newSess.Value == "" || newSess.Value == sess.Value {
		t.Fatalf("改密响应应 Set-Cookie 换发新会话，得到 sess=%v csrf=%v", newSess, newCSRF)
	}

	// 旧 cookie 当场失效（旧行随全吊销判死）
	oldAfter := e.do(t, "POST", "/web/session", `{}`, withCSRF)
	if oldAfter.Code != http.StatusUnauthorized {
		t.Errorf("改密后旧 cookie 应 401，得到 %d（%s）", oldAfter.Code, oldAfter.Body.String())
	}
	// 新 cookie 可用（换发不是把自己断掉）
	withNew := func(r *http.Request) {
		r.AddCookie(newSess)
		r.AddCookie(newCSRF)
		r.Header.Set("X-CSRF-Token", newCSRF.Value)
	}
	after := e.do(t, "POST", "/web/session", `{}`, withNew)
	if after.Code != http.StatusOK {
		t.Fatalf("换发后的 web 会话应可用，得到 %d（%s）", after.Code, after.Body.String())
	}

	// 其它会话被踢：App 侧 JWT 当场失效
	if _, err := e.svc.Verify("Bearer "+appResp.Token, "calorie-diary"); err == nil {
		t.Error("改密后其它会话应被吊销")
	}

	// sessions 表无僵尸行：web 行要么带 web_token_hash 且活着，要么已吊销；
	// 不许出现 app='web' AND web_token_hash IS NULL AND revoked_at IS NULL
	var zombies int
	if err := e.pool.QueryRow(
		"SELECT COUNT(*) FROM sessions WHERE user_id = ? AND app = 'web' AND web_token_hash IS NULL AND revoked_at IS NULL",
		uid).Scan(&zombies); err != nil || zombies != 0 {
		t.Errorf("不该留下无 web_token_hash 的活 web 行，得到 %d (err=%v)", zombies, err)
	}
	// 活跃行只有换发给本会话这一条（旧 web 行与其它设备都被吊销）
	var active int
	if err := e.pool.QueryRow(
		"SELECT COUNT(*) FROM sessions WHERE user_id = ? AND revoked_at IS NULL", uid).Scan(&active); err != nil || active != 1 {
		t.Errorf("改密后应只剩换发的 1 条活跃行，得到 %d (err=%v)", active, err)
	}
}

// m3 回归：过期/失效的残留 cookie 不再绑架同浏览器的 Bearer 请求——cookie 校验
// 失败但带了 Authorization 头时继续尝试 Bearer，Bearer 成功即放行；两者皆败才 401。
func TestResolveCallerStaleCookieFallsBackToBearer(t *testing.T) {
	e := newRouteEnv(t)
	seedUser(t, e, "stale-cookie@example.com", "secret123", "user")
	resp, err := e.svc.Login("stale-cookie@example.com", "secret123", "calorie-diary", auth.SessionMeta{})
	if err != nil {
		t.Fatalf("取 JWT: %v", err)
	}

	// 残留的失效 cookie + 有效 Bearer：按 Bearer 放行（旧实现被 cookie 绑架成 401）
	rec := e.do(t, "GET", "/api/sessions", "", func(r *http.Request) {
		r.AddCookie(&http.Cookie{Name: auth.WebCookieName, Value: "stale-leftover-token"})
		r.Header.Set("Authorization", "Bearer "+resp.Token)
	})
	if rec.Code != http.StatusOK {
		t.Errorf("残留 cookie + 有效 Bearer 应按 Bearer 放行，得到 %d（%s）", rec.Code, rec.Body.String())
	}
	// 残留 cookie + Bearer 也无效：401（两者皆败）
	rec = e.do(t, "GET", "/api/sessions", "", func(r *http.Request) {
		r.AddCookie(&http.Cookie{Name: auth.WebCookieName, Value: "stale-leftover-token"})
		r.Header.Set("Authorization", "Bearer bogus.token.here")
	})
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("两者皆败应 401，得到 %d（%s）", rec.Code, rec.Body.String())
	}
	// 只有残留 cookie、没带 Bearer：维持原语义 401
	rec = e.do(t, "GET", "/api/sessions", "", func(r *http.Request) {
		r.AddCookie(&http.Cookie{Name: auth.WebCookieName, Value: "stale-leftover-token"})
	})
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("只有失效 cookie 应 401，得到 %d", rec.Code)
	}
	// 正常 cookie 会话不受影响
	sess, csrf := loginCookie(t, e, "stale-cookie@example.com", "secret123")
	rec = e.do(t, "POST", "/web/session", `{}`, func(r *http.Request) {
		r.AddCookie(sess)
		r.AddCookie(csrf)
		r.Header.Set("X-CSRF-Token", csrf.Value)
	})
	if rec.Code != http.StatusOK {
		t.Errorf("正常 cookie 会话应 200，得到 %d（%s）", rec.Code, rec.Body.String())
	}
}

// m11 回归：全部 JSON 响应统一 Cache-Control: no-store（规格 B1 原文要求）——
// 登录/会话回执落在共享缓存或浏览器 bfcache 里等于把凭据外泄给下一个用它的人。
func TestJSONResponsesCarryNoStore(t *testing.T) {
	e := newRouteEnv(t)
	seedUser(t, e, "nostore@example.com", "secret123", "user")
	// web-login 桶按 IP 分键且包级共享，本用例自带来源 IP 别挤别的用例
	ip1 := fromIP("198.51.100.71")
	ip2 := fromIP("198.51.100.72")

	for _, tc := range []struct {
		name, method, path, body string
		mutate                   func(*http.Request)
	}{
		{"登录成功", "POST", "/web/login/password", `{"email":"nostore@example.com","password":"secret123"}`, ip1},
		{"业务错误", "POST", "/auth/login", `{"email":"nostore@example.com","password":"wrong","app":"calorie-diary"}`, ip2},
		{"参数错误", "POST", "/auth/login", `{"email":`, nil},
		{"鉴权回执", "GET", "/api/sessions", "", func(r *http.Request) {
			r.Header.Set("Authorization", "Bearer bogus.token.here")
		}},
	} {
		rec := e.do(t, tc.method, tc.path, tc.body, tc.mutate)
		if got := rec.Header().Get("Cache-Control"); got != "no-store" {
			t.Errorf("%s: Cache-Control 应为 no-store，得到 %q (status=%d)", tc.name, got, rec.Code)
		}
	}
}

// cookieNamed 从响应里取指定名字的 cookie。
func cookieNamed(rec *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// keys 只用于失败信息里的可读列表。
func keys(m map[string]*http.Cookie) string {
	var b bytes.Buffer
	for k := range m {
		b.WriteString(k)
		b.WriteString(" ")
	}
	return b.String()
}

// 后台授权矩阵（规格 A3 第 7 步 + W2 分级授权）：没绑 MFA 的管理员 403、绑了但
// 强认证过期 401、重新验证后放行、降级自己 400——四条各挡各的，缺一条后台就是敞开的。
// boss 是 super（W2：/admin/users 是平台级端点）；app-admin 对它的 403 另见
// TestAdminScopeMatrix。
func TestAdminAuthzMatrix(t *testing.T) {
	e := newRouteEnv(t)
	boss := seedUser(t, e, "boss@example.com", "secret123", "super")
	worker := seedUser(t, e, "worker@example.com", "secret123", "user")

	sess, csrf := loginCookie(t, e, "boss@example.com", "secret123")
	cookies := func(r *http.Request) {
		r.AddCookie(sess)
		r.AddCookie(csrf)
	}
	withCSRF := func(r *http.Request) {
		cookies(r)
		r.Header.Set("X-CSRF-Token", csrf.Value)
	}

	// ① 管理员账号没绑任何 MFA → 403 且提示要先绑定
	rec := e.do(t, "GET", "/admin/users", "", cookies)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "绑定") {
		t.Errorf("未绑 MFA 的管理员应 403 并说明原因，得到 %d %s", rec.Code, rec.Body.String())
	}

	// ② 绑上两步验证（直接落 enabled 行：本用例只看授权闸，不跑验码链路），
	//    但把强认证时间清掉 → 401 + 固定文案（前端据此弹重新验证框）
	enrollMFA(t, e, boss)
	staleReauth(t, e)
	rec = e.do(t, "GET", "/admin/users", "", cookies)
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), auth.MsgReauthRequired) {
		t.Errorf("强认证过期应 401 + 固定文案，得到 %d %s", rec.Code, rec.Body.String())
	}

	// ③ 重新验证（密码路）→ 放行，回分页结构
	rec = e.do(t, "POST", "/web/reauth", `{"password":"secret123"}`, withCSRF)
	if rec.Code != http.StatusOK {
		t.Fatalf("密码重新验证应 200，得到 %d %s", rec.Code, rec.Body.String())
	}
	rec = e.do(t, "GET", "/admin/users?limit=5", "", cookies)
	if rec.Code != http.StatusOK {
		t.Fatalf("授权齐备后应 200，得到 %d %s", rec.Code, rec.Body.String())
	}
	if got := keysOf(t, rec.Body.Bytes()); got != "items,total" {
		t.Errorf("后台列表回执应恰为 items,total，得到 %s", got)
	}

	// ④ 降级自己 → 400（服务端守卫；前端禁用只是提示）。角色调整唯一入口是
	//    POST /admin/users/{uid}/role（旧 PATCH /admin/users/{uid} 已并入并删除）
	rec = e.do(t, "POST", "/admin/users/"+strconv.FormatInt(boss, 10)+"/role", `{"role":"user"}`, withCSRF)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("降级自己应 400，得到 %d %s", rec.Code, rec.Body.String())
	}
	// 给同事升权 → 200，且审计里有 admin.user.role_change
	rec = e.do(t, "POST", "/admin/users/"+strconv.FormatInt(worker, 10)+"/role", `{"role":"admin"}`, withCSRF)
	if rec.Code != http.StatusOK {
		t.Errorf("给他人改角色应 200，得到 %d %s", rec.Code, rec.Body.String())
	}
	var roleChange int
	if err := e.pool.QueryRow(
		"SELECT COUNT(*) FROM audit_logs WHERE action = 'admin.user.role_change' AND result = 'ok'").
		Scan(&roleChange); err != nil || roleChange == 0 {
		t.Errorf("角色变更应进审计，得到 %d err=%v", roleChange, err)
	}
	// 审计查询本身也记一条（谁在看痕迹）
	rec = e.do(t, "GET", "/admin/audit?limit=5", "", cookies)
	if rec.Code != http.StatusOK {
		t.Errorf("审计查询应 200，得到 %d %s", rec.Code, rec.Body.String())
	}
	var viewed int
	if err := e.pool.QueryRow(
		"SELECT COUNT(*) FROM audit_logs WHERE action = 'admin.audit.view'").Scan(&viewed); err != nil || viewed == 0 {
		t.Errorf("查看审计应被记账，得到 %d err=%v", viewed, err)
	}
}

// 配置中心的 secret 永远不回原文：库里放一个凭据键，响应里只有 configured + 末 4 位，
// 写入审计也只记 key（白盒：原值不得出现在任何一处响应或审计里）。
func TestAdminConfigNeverLeaksSecret(t *testing.T) {
	e := newRouteEnv(t)
	uid := seedUser(t, e, "cfg-admin@example.com", "secret123", "super")
	const secret = "leaky-secret-value-8f3a"
	if _, err := e.pool.Exec("INSERT INTO app_config (`key`, `value`) VALUES (?, ?)",
		"mail_client_secret", secret); err != nil {
		t.Fatalf("种配置: %v", err)
	}
	sess, csrf := loginCookie(t, e, "cfg-admin@example.com", "secret123")
	enrollMFA(t, e, uid)
	cookies := func(r *http.Request) { r.AddCookie(sess); r.AddCookie(csrf) }
	withCSRF := func(r *http.Request) {
		cookies(r)
		r.Header.Set("X-CSRF-Token", csrf.Value)
	}
	// 强认证过期 → 先重验（本例主要看回执内容，闸在授权矩阵里已单独覆盖）
	if rec := e.do(t, "POST", "/web/reauth", `{"password":"secret123"}`, withCSRF); rec.Code != http.StatusOK {
		t.Fatalf("重新验证应 200，得到 %d %s", rec.Code, rec.Body.String())
	}

	rec := e.do(t, "GET", "/admin/config", "", cookies)
	if rec.Code != http.StatusOK {
		t.Fatalf("列配置应 200，得到 %d %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if strings.Contains(body, secret) {
		t.Errorf("配置响应泄露了 secret 原值: %s", body)
	}
	if !strings.Contains(body, `"hint":"8f3a"`) || !strings.Contains(body, `"configured":true`) {
		t.Errorf("secret 应回 configured + 末 4 位 hint，得到 %s", body)
	}

	// 写入：审计只记 key 与旧值是否已配置，值本身不得出现
	rec = e.do(t, "PUT", "/admin/config/mail_tenant_id", `{"value":"tenant-new"}`, withCSRF)
	if rec.Code != http.StatusOK {
		t.Fatalf("写配置应 200，得到 %d %s", rec.Code, rec.Body.String())
	}
	var detail string
	if err := e.pool.QueryRow(
		"SELECT detail FROM audit_logs WHERE action = 'admin.config.set' ORDER BY id DESC LIMIT 1").
		Scan(&detail); err != nil {
		t.Fatalf("查配置审计: %v", err)
	}
	if strings.Contains(detail, "tenant-new") || strings.Contains(detail, secret) {
		t.Errorf("配置审计泄露了值: %s", detail)
	}
	// 白名单外的键 404
	rec = e.do(t, "PUT", "/admin/config/some_other_key", `{"value":"x"}`, withCSRF)
	if rec.Code != http.StatusNotFound {
		t.Errorf("白名单外的键应 404，得到 %d", rec.Code)
	}
}

// ---- 用户档案（GET/PUT /api/profile）----

// 回执形状恰好五字段（含 W1 的 loginNotify）、Bearer 与 cookie 会话两种凭据都能读写；
// 未登录 401，cookie 进来的非 GET 照吃 CSRF 闸（老端点同款，Bearer 不受影响）。
func TestProfileRoutesShapeAndSessionKinds(t *testing.T) {
	e := newRouteEnv(t)
	uid := seedUser(t, e, "profile-route@example.com", "secret123", "user")
	resp, err := e.svc.Login("profile-route@example.com", "secret123", "calorie-diary", auth.SessionMeta{})
	if err != nil {
		t.Fatalf("取 JWT: %v", err)
	}
	bearer := func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+resp.Token) }

	// 未登录：401
	if rec := e.do(t, "GET", "/api/profile", "", nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("未登录读档案应 401，得到 %d", rec.Code)
	}

	// 无行 → 默认值，且形状恰好五字段（W1 起新增 loginNotify，默认开）
	rec := e.do(t, "GET", "/api/profile", "", bearer)
	if rec.Code != http.StatusOK {
		t.Fatalf("读档案应 200，得到 %d（%s）", rec.Code, rec.Body.String())
	}
	if got := keysOf(t, rec.Body.Bytes()); got != "avatarColor,avatarImage,loginNotify,nickname,updatedAt" {
		t.Errorf("档案回执形状应恰为五字段（含 loginNotify），得到 %s", got)
	}
	var def struct {
		Nickname    string  `json:"nickname"`
		AvatarColor int     `json:"avatarColor"`
		AvatarImage *string `json:"avatarImage"`
		LoginNotify bool    `json:"loginNotify"`
		UpdatedAt   int64   `json:"updatedAt"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &def); err != nil {
		t.Fatalf("解析默认档案: %v", err)
	}
	if def.Nickname != "" || def.AvatarColor != 0 || def.AvatarImage != nil || def.UpdatedAt != 0 {
		t.Errorf("默认档案应全为零值，得到 %+v", def)
	}
	// 新设备登录提醒缺省开（users.login_notify 默认 1）
	if !def.LoginNotify {
		t.Error("loginNotify 默认应为 true")
	}

	// Bearer PUT → GET 往返
	avatar := base64OfBytes(2048)
	putBody := `{"nickname":"路由昵称","avatarColor":7,"avatarImage":"` + avatar + `"}`
	if rec := e.do(t, "PUT", "/api/profile", putBody, bearer); rec.Code != http.StatusOK {
		t.Fatalf("PUT 档案应 200，得到 %d（%s）", rec.Code, rec.Body.String())
	}
	rec = e.do(t, "GET", "/api/profile", "", bearer)
	var got struct {
		Nickname    string  `json:"nickname"`
		AvatarColor int     `json:"avatarColor"`
		AvatarImage *string `json:"avatarImage"`
		UpdatedAt   int64   `json:"updatedAt"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("解析档案: %v", err)
	}
	if got.Nickname != "路由昵称" || got.AvatarColor != 7 || got.AvatarImage == nil ||
		*got.AvatarImage != avatar || got.UpdatedAt == 0 {
		t.Errorf("PUT→GET 应往返一致，得到 %+v", got)
	}
	// 库里确实落了行（且是这个 uid 的）
	var rows int
	if err := e.pool.QueryRow("SELECT COUNT(*) FROM user_profile WHERE user_id = ?", uid).Scan(&rows); err != nil || rows != 1 {
		t.Errorf("user_profile 应有该 uid 的一行，得到 rows=%d err=%v", rows, err)
	}
	// PUT 落审计（HTTP 链路走通后 profile.update 应有 ok 行）
	var audits int
	if err := e.pool.QueryRow(
		"SELECT COUNT(*) FROM audit_logs WHERE action = 'profile.update' AND result = 'ok' AND actor_uid = ?",
		uid).Scan(&audits); err != nil || audits == 0 {
		t.Errorf("PUT 应落 profile.update 审计，得到 %d err=%v", audits, err)
	}

	// cookie 会话：同吃 CSRF 闸——缺 X-CSRF-Token 的 PUT 403，带上则 200
	sess, csrf := loginCookie(t, e, "profile-route@example.com", "secret123")
	withCookies := func(r *http.Request) { r.AddCookie(sess); r.AddCookie(csrf) }
	if rec := e.do(t, "PUT", "/api/profile", `{"nickname":"x","avatarColor":1,"avatarImage":null}`, withCookies); rec.Code != http.StatusForbidden {
		t.Errorf("cookie 调 PUT 缺 CSRF 头应 403，得到 %d", rec.Code)
	}
	withCSRF := func(r *http.Request) {
		withCookies(r)
		r.Header.Set("X-CSRF-Token", csrf.Value)
	}
	if rec := e.do(t, "PUT", "/api/profile", `{"nickname":"cookie昵称","avatarColor":2,"avatarImage":null}`, withCSRF); rec.Code != http.StatusOK {
		t.Errorf("cookie 带 CSRF 的 PUT 应 200，得到 %d（%s）", rec.Code, rec.Body.String())
	}
	if rec := e.do(t, "GET", "/api/profile", "", withCookies); rec.Code != http.StatusOK ||
		!strings.Contains(rec.Body.String(), "cookie昵称") {
		t.Errorf("cookie GET 应读回刚写的档案，得到 %d %s", rec.Code, rec.Body.String())
	}
}

// 头像体积两层闸：解码后 >700KB（包还在 1.5MB 之内）→ 业务层**具体文案**的 413；
// 请求体整体 >1.5MB → MaxBytesReader 的通用 413。两层都是 413，前者才带 next 指引。
func TestProfileRouteRejectsOversizedAvatar(t *testing.T) {
	e := newRouteEnv(t)
	seedUser(t, e, "profile-big@example.com", "secret123", "user")
	resp, err := e.svc.Login("profile-big@example.com", "secret123", "calorie-diary", auth.SessionMeta{})
	if err != nil {
		t.Fatalf("取 JWT: %v", err)
	}
	bearer := func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+resp.Token) }

	// 解码 701KB 的合法 base64：包约 935KB < 1.5MB，走得到业务层校验
	tooBig := base64OfBytes(701 * 1024)
	rec := e.do(t, "PUT", "/api/profile",
		`{"nickname":"n","avatarColor":1,"avatarImage":"`+tooBig+`"}`, bearer)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("超限头像应 413，得到 %d（%s）", rec.Code, rec.Body.String())
	}
	msg := rec.Body.String()
	if !strings.Contains(msg, "过大") || !strings.Contains(msg, "压缩") {
		t.Errorf("413 文案应带 what+next，得到 %s", msg)
	}
	// 拒掉之后档案不许被写进去
	var rows int
	if err := e.pool.QueryRow("SELECT COUNT(*) FROM user_profile").Scan(&rows); err != nil || rows != 0 {
		t.Errorf("被拒的写入不该留行，得到 %d err=%v", rows, err)
	}
	// 失败也落审计（fail 行）
	var fails int
	if err := e.pool.QueryRow(
		"SELECT COUNT(*) FROM audit_logs WHERE action = 'profile.update' AND result = 'fail'").Scan(&fails); err != nil || fails == 0 {
		t.Errorf("被拒的 PUT 应落 fail 审计，得到 %d err=%v", fails, err)
	}

	// 请求体整体超 1.5MB → 通用 413（连业务校验都不必进）
	huge := base64OfBytes(1600 * 1024) // 解码 1.6MB → base64 约 2.13MB
	rec = e.do(t, "PUT", "/api/profile",
		`{"nickname":"n","avatarColor":1,"avatarImage":"`+huge+`"}`, bearer)
	if rec.Code != http.StatusRequestEntityTooLarge || !strings.Contains(rec.Body.String(), "请求体过大") {
		t.Errorf("包超 1.5MB 应通用 413，得到 %d %s", rec.Code, rec.Body.String())
	}
}

// base64OfBytes 造指定解码字节数的合法 base64（cmd/server 这边不与 internal/auth 共享
// 测试辅助函数，各自一份更直白）。
func base64OfBytes(decodedBytes int) string {
	return base64.StdEncoding.EncodeToString([]byte(strings.Repeat("a", decodedBytes)))
}

// loginCookie 走一遍密码登录，回两枚 cookie（会话 + CSRF）。
func loginCookie(t *testing.T, e *routeEnv, email, password string) (*http.Cookie, *http.Cookie) {
	t.Helper()
	rec := e.do(t, "POST", "/web/login/password", `{"email":"`+email+`","password":"`+password+`"}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("登录 %s 应 200，得到 %d %s", email, rec.Code, rec.Body.String())
	}
	sess := cookieNamed(rec, auth.WebCookieName)
	csrf := cookieNamed(rec, auth.WebCSRFCookieName)
	if sess == nil || csrf == nil {
		t.Fatalf("登录应签两枚 cookie")
	}
	return sess, csrf
}

// enrollMFA 给指定账号直接落一行启用中的 TOTP 因子（授权闸只看在不在，不验码）。
func enrollMFA(t *testing.T, e *routeEnv, uid int64) {
	t.Helper()
	if uid == 0 {
		if err := e.pool.QueryRow("SELECT id FROM users WHERE email = 'cfg-admin@example.com'").Scan(&uid); err != nil {
			t.Fatalf("查管理员 uid: %v", err)
		}
	}
	if _, err := e.pool.Exec(
		"INSERT INTO totp_factors (user_id, secret_cipher, enabled, last_used_timestep, created_at) VALUES (?,?,1,0,?)",
		uid, []byte("test-only-cipher-never-decrypted-in-this-case"), time.Now().UnixMilli()); err != nil {
		t.Fatalf("落 TOTP 因子: %v", err)
	}
}

// staleReauth 把该账号全部会话的强认证时间清空（模拟从未验证过 / 窗已过期）。
func staleReauth(t *testing.T, e *routeEnv) {
	t.Helper()
	if _, err := e.pool.Exec("UPDATE sessions SET reauth_at = NULL WHERE revoked_at IS NULL"); err != nil {
		t.Fatalf("清强认证时间: %v", err)
	}
}

// GET /web/registry 是 SPA 的项目注册表出口：公开只读，回执与页面内联的 AppsJSON
// 同一份值（两个项目齐全、shape 是 [{key,label}]）。
func TestWebRegistryRoute(t *testing.T) {
	e := newRouteEnv(t)
	rec := e.do(t, "GET", "/web/registry", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("注册表应 200，得到 %d", rec.Code)
	}
	got := rec.Body.String()
	for _, want := range []string{`"key":"calorie-diary"`, `"key":"expense-diary"`, `"label":`} {
		if !strings.Contains(got, want) {
			t.Errorf("注册表缺 %s，得到 %s", want, got)
		}
	}
}

// 管理入口的页面门禁按角色分流（M4 SPA 切流后前端自渲染入口，服务端只剩门禁）：
// admin/super 200 拿壳；普通用户 302 去概览；未登录 302 去登录页。
func TestTopbarAdminEntryRendersByRole(t *testing.T) {
	e := newRouteEnv(t)
	seedUser(t, e, "topbar-admin@example.com", "secret123", "admin")
	seedUser(t, e, "topbar-super@example.com", "secret123", "super")
	seedUser(t, e, "topbar-user@example.com", "secret123", "user")

	shellOf := func(email, path string) *httptest.ResponseRecorder {
		drainLoginBucket()
		sess, _ := loginCookie(t, e, email, "secret123")
		return e.do(t, "GET", path, "", func(r *http.Request) { r.AddCookie(sess) })
	}
	// app-admin 只进得了自己的管理页（/web/admin 是 super 专属，对它 302 会话总览）
	if rec := shellOf("topbar-admin@example.com", "/web/admin/sessions"); rec.Code != http.StatusOK ||
		!strings.Contains(rec.Body.String(), "/wasm/authweb.js") {
		t.Errorf("app-admin 打会话总览应 200 拿 SPA 壳，得到 %d", rec.Code)
	}
	if rec := shellOf("topbar-admin@example.com", "/web/admin"); rec.Code != http.StatusFound ||
		rec.Header().Get("Location") != "/web/admin/sessions" {
		t.Errorf("app-admin 打用户页应 302 去会话总览，得到 %d %q", rec.Code, rec.Header().Get("Location"))
	}
	if rec := shellOf("topbar-super@example.com", "/web/admin"); rec.Code != http.StatusOK ||
		!strings.Contains(rec.Body.String(), "/wasm/authweb.js") {
		t.Errorf("super 打用户页应 200 拿 SPA 壳，得到 %d", rec.Code)
	}
	rec := shellOf("topbar-user@example.com", "/web/admin")
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/web/console" {
		t.Errorf("普通用户访问管理页应 302 去概览，得到 %d %q", rec.Code, rec.Header().Get("Location"))
	}
	unauth := e.do(t, "GET", "/web/admin", "", nil)
	if unauth.Code != http.StatusFound || unauth.Header().Get("Location") != "/web/login" {
		t.Errorf("未登录访问管理页应 302 去登录页，得到 %d %q", unauth.Code, unauth.Header().Get("Location"))
	}
}

// 「退出其它所有设备」：cookie 调用必须先过 2 小时强认证窗（401 固定文案），
// 验过后批量踢出并落审计（scope=others + 踢掉台数）；Bearer 老客户端不受这道闸影响。
func TestRevokeOthersForcesReauthAndAudits(t *testing.T) {
	e := newRouteEnv(t)
	uid := seedUser(t, e, "kick-others@example.com", "secret123", "user")
	sess, csrf := loginCookie(t, e, "kick-others@example.com", "secret123")
	withCSRF := func(r *http.Request) {
		r.AddCookie(sess)
		r.AddCookie(csrf)
		r.Header.Set("X-CSRF-Token", csrf.Value)
	}
	// 再造一台「别的设备」：同账号第二次登录（业务层建行，不打 HTTP）
	if _, err := e.svc.Login("kick-others@example.com", "secret123", "calorie-diary",
		auth.SessionMeta{IP: "10.9.9.9", UserAgent: "OtherPhone/1.0"}); err != nil {
		t.Fatalf("造第二台设备: %v", err)
	}

	// ① 强认证窗过期 → 401 + 固定文案（前端据此弹重新验证框）
	staleReauth(t, e)
	rec := e.do(t, "POST", "/api/sessions/revoke-others", `{}`, withCSRF)
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), auth.MsgReauthRequired) {
		t.Fatalf("未强认证的批量踢出应 401 + 固定文案，得到 %d %s", rec.Code, rec.Body.String())
	}
	var alive int
	if err := e.pool.QueryRow(
		"SELECT COUNT(*) FROM sessions WHERE user_id = ? AND revoked_at IS NULL", uid).Scan(&alive); err != nil || alive != 2 {
		t.Fatalf("401 时不该踢掉任何会话，得到 %d err=%v", alive, err)
	}

	// ② 验过 → 200，回执形状仍恰为 {ok:true}（老端点契约），其它会话全被踢
	if rec = e.do(t, "POST", "/web/reauth", `{"password":"secret123"}`, withCSRF); rec.Code != http.StatusOK {
		t.Fatalf("重新验证应 200，得到 %d %s", rec.Code, rec.Body.String())
	}
	rec = e.do(t, "POST", "/api/sessions/revoke-others", `{}`, withCSRF)
	if rec.Code != http.StatusOK {
		t.Fatalf("批量踢出应 200，得到 %d %s", rec.Code, rec.Body.String())
	}
	if got := keysOf(t, rec.Body.Bytes()); got != "ok" {
		t.Errorf("回执形状应恰为 ok，得到 %s", got)
	}
	if err := e.pool.QueryRow(
		"SELECT COUNT(*) FROM sessions WHERE user_id = ? AND revoked_at IS NULL", uid).Scan(&alive); err != nil || alive != 1 {
		t.Errorf("批量踢出后应只剩当前会话，得到 %d err=%v", alive, err)
	}

	// ③ 审计落行：session.kick + scope=others + 踢掉台数
	var detail, result string
	if err := e.pool.QueryRow(
		"SELECT `detail`, result FROM audit_logs WHERE action = 'session.kick' AND result = 'ok' ORDER BY id DESC LIMIT 1").
		Scan(&detail, &result); err != nil {
		t.Fatalf("查审计: %v", err)
	}
	if !strings.Contains(detail, `"scope":"others"`) || !strings.Contains(detail, `"count":"1"`) {
		t.Errorf("批量踢出审计应带 scope=others 与台数，得到 %s", detail)
	}

	// ④ Bearer 老客户端不受 reauth 闸影响（回执 200，不是 401）
	resp, err := e.svc.Login("kick-others@example.com", "secret123", "calorie-diary", auth.SessionMeta{})
	if err != nil {
		t.Fatalf("取 JWT: %v", err)
	}
	staleReauth(t, e)
	rec = e.do(t, "POST", "/api/sessions/revoke-others", `{}`, func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+resp.Token)
	})
	if rec.Code != http.StatusOK {
		t.Errorf("Bearer 调批量踢出不应被 reauth 闸拦，得到 %d %s", rec.Code, rec.Body.String())
	}
}

// reauth 窗 = 2 小时且**滑动续期**（GitHub sudo mode 口径）：三道 reauth 闸
//（reauthThen / reauthed / admin gate）里过闸且成功的**非 GET 写操作**把 reauth_at
// 刷到现在，失败不刷；GET 读操作不续期（W7-1）。回拨 90 分钟仍放行（老的 15 分钟
// 窗早已超时），本身也钉住了 2 小时窗。
func TestReauthWindowSlidesOnSensitiveOps(t *testing.T) {
	e := newRouteEnv(t)
	uid := seedUser(t, e, "slide-reauth@example.com", "secret123", "user")
	drainLoginBucket()
	sess, csrf := loginCookie(t, e, "slide-reauth@example.com", "secret123")
	withCSRF := func(r *http.Request) {
		r.AddCookie(sess)
		r.AddCookie(csrf)
		r.Header.Set("X-CSRF-Token", csrf.Value)
	}
	reauthAt := func(user int64) int64 {
		t.Helper()
		var at int64
		if err := e.pool.QueryRow(
			"SELECT reauth_at FROM sessions WHERE user_id = ? AND app = 'web' AND revoked_at IS NULL",
			user).Scan(&at); err != nil {
			t.Fatalf("查 reauth_at: %v", err)
		}
		return at
	}
	backdate := func(user int64, d time.Duration) {
		t.Helper()
		if _, err := e.pool.Exec(
			"UPDATE sessions SET reauth_at = ? WHERE user_id = ? AND revoked_at IS NULL",
			time.Now().Add(-d).UnixMilli(), user); err != nil {
			t.Fatalf("回拨 reauth_at: %v", err)
		}
	}

	// ① reauthThen 成功：90 分钟前（>老 15 分钟窗，<2 小时窗）仍过闸，成功后滑到现在
	backdate(uid, 90*time.Minute)
	rec := e.do(t, "POST", "/api/sessions/revoke-others", `{}`, withCSRF)
	if rec.Code != http.StatusOK {
		t.Fatalf("回拨 90 分钟仍在 2 小时窗内应放行，得到 %d %s", rec.Code, rec.Body.String())
	}
	if age := time.Since(time.UnixMilli(reauthAt(uid))); age > time.Minute {
		t.Errorf("成功的敏感操作应滑动续期 reauth_at，得到 %v 前", age)
	}

	// ② reauthThen 失败：过闸但业务 400 → reauth_at 停在回拨点（失败不刷）
	backdate(uid, 90*time.Minute)
	rec = e.do(t, "POST", "/api/sessions/revoke-many", `{"ids":["bogus"]}`, withCSRF)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("坏 id 应 400，得到 %d %s", rec.Code, rec.Body.String())
	}
	if age := time.Since(time.UnixMilli(reauthAt(uid))); age < 89*time.Minute {
		t.Errorf("失败的敏感操作不该刷新 reauth_at，得到 %v 前", age)
	}

	// ③ reauthed 闸（/api/totp/* 等）成功同样滑动
	backdate(uid, 90*time.Minute)
	rec = e.do(t, "POST", "/api/totp/setup", `{}`, withCSRF)
	if rec.Code != http.StatusOK {
		t.Fatalf("setup 应 200，得到 %d %s", rec.Code, rec.Body.String())
	}
	if age := time.Since(time.UnixMilli(reauthAt(uid))); age > time.Minute {
		t.Errorf("reauthed 闸的成功操作也应滑动续期，得到 %v 前", age)
	}

	// ④ admin gate 的**写**操作滑动（super 身份，cookie + role + MFA + reauth 四道闸全过）；
	//    GET 读操作不再续期（W7-1）——读列表不该给强认证窗续命
	sup := makeActor(t, e, "slide-super", "super", nil)
	supTarget := seedUser(t, e, "slide-target@example.com", "secret123", "user")
	backdate(sup.uid, 90*time.Minute)
	rec = e.do(t, "POST", "/admin/users/"+strconv.FormatInt(supTarget, 10)+"/revoke-sessions", `{}`, sup.withCSRF)
	if rec.Code != http.StatusOK {
		t.Fatalf("后台写操作应 200，得到 %d %s", rec.Code, rec.Body.String())
	}
	if age := time.Since(time.UnixMilli(reauthAt(sup.uid))); age > time.Minute {
		t.Errorf("admin 写操作成功应滑动续期 reauth_at，得到 %v 前", age)
	}
	backdate(sup.uid, 90*time.Minute)
	rec = e.do(t, "GET", "/admin/users", "", sup.cookieOnly)
	if rec.Code != http.StatusOK {
		t.Fatalf("后台读操作应 200，得到 %d %s", rec.Code, rec.Body.String())
	}
	if age := time.Since(time.UnixMilli(reauthAt(sup.uid))); age < 89*time.Minute {
		t.Errorf("GET 读操作不该滑动 reauth_at，得到 %v 前", age)
	}
}

// UA Client Hints 的建会话链（真库）：web 登录请求带 Sec-CH-UA-Platform/-Model 时，
// sessions.user_agent 落 `原UA + " | CH:<platform>;<model>"` 后缀、设备名（快照列与
// ListSessions 现算同源）出「Android · Pixel 5」；/auth/* 的 App 端点即使收到同款头
// 也不采集（走 sessMeta），App UA 一字节不变。
func TestWebLoginStoresClientHintSuffix(t *testing.T) {
	const chUA = "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36"
	drainLoginBucket()
	t.Cleanup(drainLoginBucket)
	e := newRouteEnv(t)

	// web 流程：CH 两头随请求带 → 并进 user_agent 存储串
	uid := seedUser(t, e, "ch-web@example.com", "secret123", "user")
	rec := e.do(t, "POST", "/web/login/password",
		`{"email":"ch-web@example.com","password":"secret123"}`, func(r *http.Request) {
			fromIP("198.51.100.40")(r)
			r.Header.Set("User-Agent", chUA)
			r.Header.Set("Sec-CH-UA-Platform", `"Android"`)
			r.Header.Set("Sec-CH-UA-Model", `"Pixel 5"`)
		})
	if rec.Code != http.StatusOK {
		t.Fatalf("web 密码登录应 200，得到 %d（%s）", rec.Code, rec.Body.String())
	}
	var stored string
	if err := e.pool.QueryRow(
		"SELECT user_agent FROM sessions WHERE user_id = ? AND app = 'web' ORDER BY id DESC LIMIT 1",
		uid).Scan(&stored); err != nil {
		t.Fatalf("读 web 会话行: %v", err)
	}
	if want := chUA + " | CH:Android;Pixel 5"; stored != want {
		t.Errorf("user_agent 应并入 CH 后缀 %q，得到 %q", want, stored)
	}
	items, err := e.svc.ListSessions(uid, 0, nil)
	if err != nil || len(items) != 1 {
		t.Fatalf("取设备列表: %v（%d 行）", err, len(items))
	}
	if items[0].Device != "Android · Pixel 5" {
		t.Errorf("设备名应按 CH 后缀现算成 %q，得到 %q", "Android · Pixel 5", items[0].Device)
	}

	// App 流程：/auth/login 走 sessMeta，同款头也不采集（App UA 一字节不变）
	appUID := seedUser(t, e, "ch-app@example.com", "secret123", "user")
	appRec := e.do(t, "POST", "/auth/login",
		`{"email":"ch-app@example.com","password":"secret123","app":"calorie-diary"}`, func(r *http.Request) {
			fromIP("198.51.100.41")(r)
			r.Header.Set("User-Agent", chUA)
			r.Header.Set("Sec-CH-UA-Platform", `"Android"`)
			r.Header.Set("Sec-CH-UA-Model", `"Pixel 5"`)
		})
	if appRec.Code != http.StatusOK {
		t.Fatalf("App 登录应 200，得到 %d（%s）", appRec.Code, appRec.Body.String())
	}
	var appUA string
	if err := e.pool.QueryRow(
		"SELECT user_agent FROM sessions WHERE user_id = ? ORDER BY id DESC LIMIT 1",
		appUID).Scan(&appUA); err != nil {
		t.Fatalf("读 App 会话行: %v", err)
	}
	if appUA != chUA {
		t.Errorf("App 端点不该采集 CH（UA 应原样），得到 %q", appUA)
	}
}
