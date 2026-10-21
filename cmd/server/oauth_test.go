package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/WXies-Team/auth/internal/auth"
)

// B4 OAuth 跳转授权的路由级用例（真库，无 TEST_MYSQL_DSN 跳过，留 CI）：
// 参数 fail-fast 错误页、未登录托管登录页（tx 续跑）、确认页、发码回跳、
// 换 token 全链路与失败形状。

// oauthConfig 给 calorie-diary 开通客户端，回 client_id 与一次性 secret。
// 用 svc 业务层直调（管理端 HTTP 形状另有 TestOAuthAdminRouteShape 覆盖）：
// AdminConfigureOAuth 的 Caller 只用于审计归属，落一行 super 用户取 uid 即可。
func oauthConfig(t *testing.T, e *routeEnv) (clientID, secret string) {
	t.Helper()
	uid := seedUser(t, e, "oauth-route-super@example.com", "secret123", "super")
	actor := auth.Caller{UID: uid, Email: "oauth-route-super@example.com"}
	res, err := e.svc.AdminConfigureOAuth(actor, auth.AdminScope{Super: true}, "calorie-diary",
		auth.AdminOAuthInput{RedirectUris: []string{"https://app.example.com/cb"}})
	if err != nil {
		t.Fatalf("开通 OAuth 客户端: %v", err)
	}
	return res.ClientID, res.Secret
}

// oauthPKCE 返回 (verifier, challenge)。
func oauthPKCE(t *testing.T) (string, string) {
	t.Helper()
	// 43 位 base64url（RFC 7636 下限）
	verifier := strings.Repeat("v", 43)
	sum := sha256HexForTest(verifier)
	return verifier, sum
}

// drainOAuthBucket 清空 OAuth 两个限流桶（矩阵测试同 IP 十几次请求会打满 15/分）。
func drainOAuthBucket() {
	limiter.mu.Lock()
	for k := range limiter.windows {
		if strings.HasPrefix(k, "oauth-") {
			delete(limiter.windows, k)
		}
	}
	limiter.mu.Unlock()
}

func TestOAuthAuthorizeFailFastErrorPages(t *testing.T) {
	e := newRouteEnv(t)
	clientID, _ := oauthConfig(t, e)
	verifier, challenge := oauthPKCE(t)
	_ = verifier

	for _, tc := range []struct {
		name, query string
		want        string
	}{
		{"未登记 client_id", "response_type=code&client_id=nope&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb&state=s&code_challenge=" + challenge + "&code_challenge_method=S256",
			"应用未登记"},
		{"回跳地址未登记", "response_type=code&client_id=" + clientID + "&redirect_uri=https%3A%2F%2Fevil.example.com%2Fcb&state=s&code_challenge=" + challenge + "&code_challenge_method=S256",
			"回跳地址未登记"},
		{"缺 PKCE", "response_type=code&client_id=" + clientID + "&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb&state=s",
			"code_challenge"},
		{"缺 state", "response_type=code&client_id=" + clientID + "&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb&code_challenge=" + challenge + "&code_challenge_method=S256",
			"state"},
		{"非 code 的 response_type", "response_type=token&client_id=" + clientID + "&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb&state=s&code_challenge=" + challenge + "&code_challenge_method=S256",
			"response_type"},
		{"method 非 S256", "response_type=code&client_id=" + clientID + "&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb&state=s&code_challenge=" + challenge + "&code_challenge_method=plain",
			"code_challenge"},
	} {
		drainOAuthBucket()
		rec := e.do(t, "GET", "/oauth/authorize?"+tc.query, "", nil)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s 应 400 错误页，得到 %d", tc.name, rec.Code)
		}
		body := rec.Body.String()
		if !strings.Contains(body, tc.want) {
			t.Errorf("%s 错误页应含 %q，得到 %.200s", tc.name, tc.want, body)
		}
		if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
			t.Errorf("%s 应回 HTML 错误页，得到 %q", tc.name, ct)
		}
		// 未登记/回跳不匹配的错误页不回显请求里的恶意地址全串
		if tc.name == "回跳地址未登记" && strings.Contains(body, "evil.example.com") {
			t.Error("回跳地址未登记的错误页不该回显请求里的完整地址")
		}
	}
}

func TestOAuthFullFlowViaRoutes(t *testing.T) {
	e := newRouteEnv(t)
	clientID, secret := oauthConfig(t, e)
	verifier, challenge := oauthPKCE(t)
	seedUser(t, e, "oauth-route-user@example.com", "secret123", "user")

	authorizeURL := "/oauth/authorize?response_type=code&client_id=" + clientID +
		"&redirect_uri=" + url.QueryEscape("https://app.example.com/cb") +
		"&state=st-1&code_challenge=" + challenge + "&code_challenge_method=S256"

	// ① 未登录：302 托管登录页，tx 随 URL 带上
	drainOAuthBucket()
	rec := e.do(t, "GET", authorizeURL, "", nil)
	if rec.Code != http.StatusFound {
		t.Fatalf("未登录应 302 登录页，得到 %d %s", rec.Code, rec.Body.String())
	}
	loc := rec.Header().Get("Location")
	if !strings.HasPrefix(loc, "/web/login?tx=") {
		t.Fatalf("应 302 到 /web/login?tx=…，得到 %q", loc)
	}
	tx := strings.TrimPrefix(loc, "/web/login?tx=")

	// ② 登录后续跑：带 cookie 打 resume → 确认页
	drainOAuthBucket()
	drainLoginBucket()
	sess, csrf := loginCookie(t, e, "oauth-route-user@example.com", "secret123")
	resume := e.do(t, "GET", "/oauth/resume?tx="+url.QueryEscape(tx), "", func(r *http.Request) {
		r.AddCookie(sess)
		r.AddCookie(csrf)
	})
	if resume.Code != http.StatusOK {
		t.Fatalf("resume 应 200 确认页，得到 %d %s", resume.Code, resume.Body.String())
	}
	page := resume.Body.String()
	for _, want := range []string{"热量日记", "app.example.com", "oauth-route-user@example.com", "继续", "取消"} {
		if !strings.Contains(page, want) {
			t.Errorf("确认页缺 %q", want)
		}
	}

	// ③ 确认 allow：302 回跳带 code+state（Origin 与 httptest 的 Host 同域，
	// 否则 originGuard 会挡——它比的是 Origin 与 r.Host）
	drainOAuthBucket()
	confirm := e.do(t, "POST", "/oauth/authorize/confirm", "tx="+url.QueryEscape(tx)+"&decision=allow",
		func(r *http.Request) {
			r.AddCookie(sess)
			r.AddCookie(csrf)
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r.Header.Set("Origin", "http://example.com")
		})
	if confirm.Code != http.StatusFound {
		t.Fatalf("确认应 302 回跳，得到 %d %s", confirm.Code, confirm.Body.String())
	}
	back := confirm.Header().Get("Location")
	if !strings.HasPrefix(back, "https://app.example.com/cb?") || !strings.Contains(back, "state=st-1") {
		t.Fatalf("回跳地址不对: %q", back)
	}
	parsed, _ := url.Parse(back)
	code := parsed.Query().Get("code")
	if code == "" {
		t.Fatalf("回跳缺 code: %q", back)
	}

	// ④ 换 token（form 形态）：200 回 JWT
	drainOAuthBucket()
	tokenRec := e.do(t, "POST", "/oauth/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"https://app.example.com/cb"},
		"client_id":     {clientID},
		"client_secret": {secret},
		"code_verifier": {verifier},
	}.Encode(), func(r *http.Request) {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	})
	if tokenRec.Code != http.StatusOK {
		t.Fatalf("换 token 应 200，得到 %d %s", tokenRec.Code, tokenRec.Body.String())
	}
	var res auth.OAuthTokenResult
	if err := json.Unmarshal(tokenRec.Body.Bytes(), &res); err != nil {
		t.Fatalf("解析 token 回执: %v (%s)", err, tokenRec.Body.String())
	}
	if got := keysOf(t, tokenRec.Body.Bytes()); got != "access_token,email,expires_in,token_type,uid" {
		t.Errorf("token 回执形状不对: %s", got)
	}
	if res.TokenType != "Bearer" || res.AccessToken == "" || res.UID == 0 {
		t.Errorf("token 回执内容不对: %+v", res)
	}
	caller, err := e.svc.ValidUserID("Bearer " + res.AccessToken)
	if err != nil || caller.App != "calorie-diary" {
		t.Errorf("签出的 JWT 应过校验且 aud=calorie-diary，得到 %+v err=%v", caller, err)
	}

	// ⑤ 复用 code：expired_token（OAuth 形状）
	drainOAuthBucket()
	reuse := e.do(t, "POST", "/oauth/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {"https://app.example.com/cb"}, "client_id": {clientID},
		"client_secret": {secret}, "code_verifier": {verifier},
	}.Encode(), func(r *http.Request) {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	})
	if reuse.Code != http.StatusBadRequest {
		t.Errorf("复用 code 应 400，得到 %d", reuse.Code)
	}
	var oe struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(reuse.Body.Bytes(), &oe); err != nil || oe.Error != "expired_token" {
		t.Errorf("复用应回 error=expired_token，得到 %s err=%v", reuse.Body.String(), err)
	}
}

// 确认页取消：302 回跳 error=access_denied + 原 state。
func TestOAuthConfirmDenyViaRoute(t *testing.T) {
	e := newRouteEnv(t)
	clientID, _ := oauthConfig(t, e)
	_, challenge := oauthPKCE(t)
	seedUser(t, e, "oauth-deny-user@example.com", "secret123", "user")

	drainOAuthBucket()
	rec := e.do(t, "GET", "/oauth/authorize?response_type=code&client_id="+clientID+
		"&redirect_uri="+url.QueryEscape("https://app.example.com/cb")+
		"&state=st-d&code_challenge="+challenge+"&code_challenge_method=S256", "", nil)
	tx := strings.TrimPrefix(rec.Header().Get("Location"), "/web/login?tx=")

	drainOAuthBucket()
	drainLoginBucket()
	sess, csrf := loginCookie(t, e, "oauth-deny-user@example.com", "secret123")
	// resume 绑定 uid
	if r := e.do(t, "GET", "/oauth/resume?tx="+url.QueryEscape(tx), "", func(req *http.Request) {
		req.AddCookie(sess)
		req.AddCookie(csrf)
	}); r.Code != http.StatusOK {
		t.Fatalf("resume 应 200，得到 %d", r.Code)
	}
	drainOAuthBucket()
	confirm := e.do(t, "POST", "/oauth/authorize/confirm", "tx="+url.QueryEscape(tx)+"&decision=deny",
		func(r *http.Request) {
			r.AddCookie(sess)
			r.AddCookie(csrf)
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r.Header.Set("Origin", "http://example.com")
		})
	if confirm.Code != http.StatusFound {
		t.Fatalf("取消应 302 回跳，得到 %d %s", confirm.Code, confirm.Body.String())
	}
	back := confirm.Header().Get("Location")
	if !strings.Contains(back, "error=access_denied") || !strings.Contains(back, "state=st-d") {
		t.Errorf("取消回跳应带 error=access_denied 与原 state，得到 %q", back)
	}
}

// token 端点的失败形状（OAuth §5.2 {error,error_description}）。
func TestOAuthTokenErrorShapes(t *testing.T) {
	e := newRouteEnv(t)
	clientID, secret := oauthConfig(t, e)
	verifier, _ := oauthPKCE(t)

	post := func(body string) (int, string) {
		drainOAuthBucket()
		rec := e.do(t, "POST", "/oauth/token", body, func(r *http.Request) {
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		})
		var oe struct {
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &oe)
		return rec.Code, rec.Body.String()
	}
	// 错 secret → 401 invalid_client
	code, body := post(url.Values{"grant_type": {"authorization_code"}, "code": {"x"},
		"redirect_uri": {"u"}, "client_id": {clientID}, "client_secret": {"wrong"},
		"code_verifier": {verifier}}.Encode())
	if code != http.StatusUnauthorized || !strings.Contains(body, "invalid_client") {
		t.Errorf("错 secret 应 401 invalid_client，得到 %d %s", code, body)
	}
	// 未登记 client → 401 invalid_client（不泄露存在性）
	code, body = post(url.Values{"grant_type": {"authorization_code"}, "code": {"x"},
		"redirect_uri": {"u"}, "client_id": {"nope"}, "client_secret": {"x"},
		"code_verifier": {verifier}}.Encode())
	if code != http.StatusUnauthorized || !strings.Contains(body, "invalid_client") {
		t.Errorf("未登记 client 应 401 invalid_client，得到 %d %s", code, body)
	}
	// 不存在的 code → 400 expired_token
	code, body = post(url.Values{"grant_type": {"authorization_code"}, "code": {"nope"},
		"redirect_uri": {"u"}, "client_id": {clientID}, "client_secret": {secret},
		"code_verifier": {verifier}}.Encode())
	if code != http.StatusBadRequest || !strings.Contains(body, "expired_token") {
		t.Errorf("不存在的 code 应 400 expired_token，得到 %d %s", code, body)
	}
	// 非法 grant_type → 400 unsupported_grant_type
	code, body = post(url.Values{"grant_type": {"password"}, "code": {"x"},
		"redirect_uri": {"u"}, "client_id": {clientID}, "client_secret": {secret},
		"code_verifier": {verifier}}.Encode())
	if code != http.StatusBadRequest || !strings.Contains(body, "unsupported_grant_type") {
		t.Errorf("非法 grant_type 应 400 unsupported_grant_type，得到 %d %s", code, body)
	}
}

// 管理端 HTTP 形状：POST /admin/projects/{app}/oauth 回 {app,clientId,redirectUris,secret}；
// GET /admin/projects 的项目带 clientId；权限闸四道（cookie-only / role / MFA / reauth）。
func TestOAuthAdminRouteShape(t *testing.T) {
	e := newRouteEnv(t)
	super := makeActor(t, e, "oa-super", "super", nil)

	rec := e.do(t, "POST", "/admin/projects/calorie-diary/oauth",
		`{"redirectUris":["https://app.example.com/cb"],"rotateSecret":true}`,
		super.withCSRF)
	if rec.Code != http.StatusOK {
		t.Fatalf("super 开通应 200，得到 %d %s", rec.Code, rec.Body.String())
	}
	var res struct {
		App          string   `json:"app"`
		ClientID     string   `json:"clientId"`
		RedirectURIs []string `json:"redirectUris"`
		Secret       string   `json:"secret"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("解析回执: %v (%s)", err, rec.Body.String())
	}
	if got := keysOf(t, rec.Body.Bytes()); got != "app,clientId,redirectUris,secret" {
		t.Errorf("开通回执形状不对: %s", got)
	}
	if res.App != "calorie-diary" || res.ClientID == "" || res.Secret == "" || len(res.RedirectURIs) != 1 {
		t.Errorf("开通回执内容不对: %+v", res)
	}

	// GET /admin/projects 带 clientId
	drainOAuthBucket()
	list := e.do(t, "GET", "/admin/projects", "", super.cookieOnly)
	if list.Code != http.StatusOK {
		t.Fatalf("列项目应 200，得到 %d", list.Code)
	}
	var page struct {
		Projects []struct {
			App      string `json:"app"`
			ClientID string `json:"clientId"`
		} `json:"projects"`
	}
	if err := json.Unmarshal(list.Body.Bytes(), &page); err != nil {
		t.Fatalf("解析列表: %v", err)
	}
	var found bool
	for _, p := range page.Projects {
		if p.App == "calorie-diary" {
			found = true
			if p.ClientID != res.ClientID {
				t.Errorf("列表 clientId 应与开通一致，得到 %q", p.ClientID)
			}
		}
		if p.App == "expense-diary" && p.ClientID != "" {
			t.Errorf("未开通项目的 clientId 应为空串，得到 %q", p.ClientID)
		}
	}
	if !found {
		t.Fatal("列表里应有 calorie-diary")
	}

	// 非登录态（无 cookie）401；普通用户 403
	plain := makeActor(t, e, "oa-plain", "user", nil)
	if rec := e.do(t, "POST", "/admin/projects/calorie-diary/oauth",
		`{"redirectUris":["https://x.example.com/cb"]}`, plain.withCSRF); rec.Code != http.StatusForbidden {
		t.Errorf("普通用户应 403，得到 %d", rec.Code)
	}
	// app-admin 越权（无该 scope）403
	appAdmin := makeActor(t, e, "oa-appadmin", "admin", []string{"expense-diary"})
	if rec := e.do(t, "POST", "/admin/projects/calorie-diary/oauth",
		`{"redirectUris":["https://x.example.com/cb"]}`, appAdmin.withCSRF); rec.Code != http.StatusForbidden {
		t.Errorf("app-admin 越权应 403，得到 %d", rec.Code)
	}
	// 非法回跳地址 400
	if rec := e.do(t, "POST", "/admin/projects/calorie-diary/oauth",
		`{"redirectUris":["not-a-url"]}`, super.withCSRF); rec.Code != http.StatusBadRequest {
		t.Errorf("非法回跳地址应 400，得到 %d", rec.Code)
	}
	// 空清单 400
	if rec := e.do(t, "POST", "/admin/projects/calorie-diary/oauth",
		`{"redirectUris":[]}`, super.withCSRF); rec.Code != http.StatusBadRequest {
		t.Errorf("空回跳清单应 400，得到 %d", rec.Code)
	}
}

// sha256HexForTest 在路由测试包里复刻业务层的 S256：base64url(sha256(verifier))。
func sha256HexForTest(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
