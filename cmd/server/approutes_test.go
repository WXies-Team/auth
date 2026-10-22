package main

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/WXies-Team/auth/internal/auth"
	"github.com/WXies-Team/auth/internal/webauthntest"
	"github.com/pquerna/otp/totp"
)

// C 批的路由层契约：三条登录路（passkey finish / 密码两步）按请求里的 app 分流——
// App 支回 {token,email} 里的 token 是**业务 JWT** 且一枚 cookie 都不发，web 支
// 逐字节回到既往（双 cookie、会话 token，JWT 语义不许混进来）。

// fromIP 换一个来源 IP 再发：limiter 是包级共享的，各用例挤同一个 web-login(15/分)
// 桶会把无关用例打成 429。198.51.100.x 不在默认受信代理段（环回+内网），clientIP
// 取 RemoteAddr，正好一用例一键。
func fromIP(ip string) func(*http.Request) {
	return func(r *http.Request) { r.RemoteAddr = ip + ":43210" }
}

// tokenOf 从 {token,email} 回执里取 token 并要求形状齐整。
func tokenOf(t *testing.T, body []byte) string {
	t.Helper()
	var resp authResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("回执不是 JSON: %v (%s)", err, body)
	}
	if resp.Token == "" || resp.Email == "" {
		t.Fatalf("回执缺 token/email: %s", body)
	}
	return resp.Token
}

// authResponse 是 {token,email} 回执的本地写法（cmd/server 的路由测试不与
// internal/auth 共享测试辅助，各写各的更直白）。
type authResponse struct {
	Token string `json:"token"`
	Email string `json:"email"`
}

// verifyByApp 打一次 /internal/verify（日记服务 withUID 的入口），环回来源才放行。
func verifyByApp(t *testing.T, e *routeEnv, token, app string) *http.Response {
	t.Helper()
	rec := e.do(t, "POST", "/internal/verify", `{"app":"`+app+`"}`, func(r *http.Request) {
		r.RemoteAddr = "127.0.0.1:51234"
		r.Header.Set("Authorization", "Bearer "+token)
	})
	return rec.Result()
}

// 密码登录（无 2FA）：带 app 回 JWT + 无 cookie + verify 通过 + 设备列表看得到；
// 白名单外 400；不带 app 是 web 支——双 cookie 在、token 不是 JWT、verify 拒。
func TestAppPasswordLoginRouteReturnsJWT(t *testing.T) {
	e := newRouteEnv(t)
	seedUser(t, e, "app-route@example.com", "secret123", "user")

	rec := e.do(t, "POST", "/web/login/password",
		`{"email":"app-route@example.com","password":"secret123","app":"calorie-diary"}`,
		fromIP("198.51.100.21"))
	if rec.Code != http.StatusOK {
		t.Fatalf("App 密码登录应 200，得到 %d（%s）", rec.Code, rec.Body.String())
	}
	if got := keysOf(t, rec.Body.Bytes()); got != "deletePendingCancelled,email,mustChangePassword,token" {
		t.Errorf("回执应与 AuthResponse 同形，得到 %s", got)
	}
	if cookies := rec.Result().Cookies(); len(cookies) != 0 {
		t.Errorf("App 支不该下发任何 cookie，得到 %v", cookies)
	}
	jwt := tokenOf(t, rec.Body.Bytes())
	if strings.Count(jwt, ".") != 2 {
		t.Fatalf("App 支的 token 应是三段式 JWT，得到 %q", jwt)
	}
	res := verifyByApp(t, e, jwt, "calorie-diary")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("JWT 应过 /internal/verify，得到 %d", res.StatusCode)
	}

	// 白名单外 400（App 名是客户端 bug，先于凭据校验）
	bad := e.do(t, "POST", "/web/login/password",
		`{"email":"app-route@example.com","password":"secret123","app":"evil-app"}`,
		fromIP("198.51.100.22"))
	if bad.Code != http.StatusBadRequest {
		t.Errorf("白名单外的 app 应 400，得到 %d（%s）", bad.Code, bad.Body.String())
	}

	// App 会话出现在 GET /api/sessions（与网页会话同一张表，可被踢）
	sessions := e.do(t, "GET", "/api/sessions", "", func(r *http.Request) {
		fromIP("198.51.100.23")(r)
		r.Header.Set("Authorization", "Bearer "+jwt)
	})
	if sessions.Code != http.StatusOK {
		t.Fatalf("设备列表应 200，得到 %d（%s）", sessions.Code, sessions.Body.String())
	}
	// 回执是 {sessions:[...]} 信封（设备列表端点与网页端同款；裸数组是旧形状，
	// 已在 TestLegacySessionsResponseShape 钉过信封本身）
	// 设备 id 是 63 位雪花、以十进制字符串输出（SessionInfo.ID；浏览器 JS 只有 53 位
	// 精度，数值会抹圆，故协议层用字符串）。此处只需「行的 app 归属」，id 照 string 解析。
	var sessBody struct {
		Sessions []struct {
			ID  string `json:"id"`
			App string `json:"app"`
		} `json:"sessions"`
	}
	if err := json.Unmarshal(sessions.Body.Bytes(), &sessBody); err != nil {
		t.Fatalf("解析设备列表: %v (%s)", err, sessions.Body.String())
	}
	appRow := false
	for _, it := range sessBody.Sessions {
		if it.App == "calorie-diary" {
			appRow = true
		}
	}
	if !appRow {
		t.Errorf("App 会话应出现在列表里，得到 %+v", sessBody.Sessions)
	}

	// web 回归：不带 app → 双 cookie、会话 token（非 JWT）、verify 不认
	web := e.do(t, "POST", "/web/login/password",
		`{"email":"app-route@example.com","password":"secret123"}`,
		fromIP("198.51.100.24"))
	if web.Code != http.StatusOK {
		t.Fatalf("web 密码登录应 200，得到 %d（%s）", web.Code, web.Body.String())
	}
	if got := keysOf(t, web.Body.Bytes()); got != "deletePendingCancelled,email,mustChangePassword,token" {
		t.Errorf("web 回执形状应保持不变，得到 %s", got)
	}
	jar := map[string]*http.Cookie{}
	for _, c := range web.Result().Cookies() {
		jar[c.Name] = c
	}
	if jar[auth.WebCookieName] == nil || jar[auth.WebCSRFCookieName] == nil {
		t.Fatalf("web 支必须签两枚 cookie，得到 %v", jar)
	}
	// M2：web 回体 token 恒空串（形状仍是 {token,email}），凭据只在 HttpOnly cookie
	webResp := authResponse{}
	if err := json.Unmarshal(web.Body.Bytes(), &webResp); err != nil {
		t.Fatalf("web 回执解析: %v（%s）", err, web.Body.String())
	}
	if webResp.Token != "" {
		t.Errorf("web 回体 token 必须恒空（凭据只在 cookie），得到 %q", webResp.Token)
	}
	if webResp.Email != "app-route@example.com" {
		t.Errorf("web 回体 email 应照回，得到 %q", webResp.Email)
	}
	if res := verifyByApp(t, e, "", "calorie-diary"); res.StatusCode != http.StatusUnauthorized {
		t.Errorf("空 token 不该过 /internal/verify，得到 %d", res.StatusCode)
	}
}

// 两步登录的编排两端：第一步把 app 写进 login_states，第二步按它发 JWT、
// 回执仍然 {token,email} 且不下发 cookie。
func TestTwoStepLoginRouteCarriesApp(t *testing.T) {
	e := newRouteEnv(t)
	seedUser(t, e, "app-2fa-route@example.com", "secret123", "user")
	// 绑定 TOTP 走业务层（绑定链路另有 totp_test 覆盖；这里只测编排两端）
	jwt, err := e.svc.Login("app-2fa-route@example.com", "secret123", "calorie-diary", auth.SessionMeta{})
	if err != nil {
		t.Fatalf("取 JWT: %v", err)
	}
	caller, err := e.svc.ValidUserID("Bearer " + jwt.Token)
	if err != nil {
		t.Fatalf("取身份: %v", err)
	}
	setup, err := e.svc.SetupTOTP(caller)
	if err != nil {
		t.Fatalf("setup totp: %v", err)
	}
	if _, err := e.svc.EnableTOTP(caller, totpCode(t, setup.Secret, 0)); err != nil {
		t.Fatalf("enable totp: %v", err)
	}

	step1 := e.do(t, "POST", "/web/login/password",
		`{"email":"app-2fa-route@example.com","password":"secret123","app":"expense-diary"}`,
		fromIP("198.51.100.31"))
	if step1.Code != http.StatusOK {
		t.Fatalf("第一步应 200，得到 %d（%s）", step1.Code, step1.Body.String())
	}
	if got := keysOf(t, step1.Body.Bytes()); got != "loginToken,methods,status" {
		t.Errorf("中间态回执形状应不变，得到 %s", got)
	}
	if cookies := step1.Result().Cookies(); len(cookies) != 0 {
		t.Errorf("中间态也不该下发 cookie，得到 %v", cookies)
	}
	var pending struct {
		Status     string   `json:"status"`
		LoginToken string   `json:"loginToken"`
		Methods    []string `json:"methods"`
	}
	if err := json.Unmarshal(step1.Body.Bytes(), &pending); err != nil {
		t.Fatalf("解析中间态回执: %v", err)
	}
	if pending.Status != "2fa_required" || pending.LoginToken == "" {
		t.Fatalf("应进两步: %+v", pending)
	}
	// app 随中间态落库，第二步据此决定发什么（表里当下只有这一条在途中间态）
	var label string
	if err := e.pool.QueryRow(
		"SELECT app FROM login_states WHERE user_id = (SELECT id FROM users WHERE email = ?)",
		"app-2fa-route@example.com").Scan(&label); err != nil {
		t.Fatalf("查中间态 app: %v", err)
	}
	if label != "expense-diary" {
		t.Errorf("login_states.app 应带住 expense-diary，得到 %q", label)
	}

	step2 := e.do(t, "POST", "/web/login/totp",
		`{"loginToken":"`+pending.LoginToken+`","code":"`+totpCode(t, setup.Secret, 30*time.Second)+`"}`,
		fromIP("198.51.100.32"))
	if step2.Code != http.StatusOK {
		t.Fatalf("第二步应 200，得到 %d（%s）", step2.Code, step2.Body.String())
	}
	if got := keysOf(t, step2.Body.Bytes()); got != "deletePendingCancelled,email,mustChangePassword,token" {
		t.Errorf("第二步回执应与 AuthResponse 同形，得到 %s", got)
	}
	if cookies := step2.Result().Cookies(); len(cookies) != 0 {
		t.Errorf("App 支第二步不该下发 cookie，得到 %v", cookies)
	}
	token := tokenOf(t, step2.Body.Bytes())
	if res := verifyByApp(t, e, token, "expense-diary"); res.StatusCode != http.StatusOK {
		t.Errorf("两步登录换出的 JWT 应过 verify，得到 %d", res.StatusCode)
	}
	if res := verifyByApp(t, e, token, "calorie-diary"); res.StatusCode != http.StatusUnauthorized {
		t.Errorf("aud 不匹配的下游不该认，得到 %d", res.StatusCode)
	}
}

// passkey 登录 finish：App 支按**已上线客户端的形态**发（response 是 JSON 字符串、
// 带 app）→ JWT + 无 cookie + verify 通过；web 支对象形态 → 双 cookie + 会话 token；
// 白名单外 400。
func TestPasskeyLoginFinishRouteAppAndWeb(t *testing.T) {
	e := newRouteEnv(t)
	uid := seedUser(t, e, "pk-route@example.com", "secret123", "user")
	au, err := webauthntest.New()
	if err != nil {
		t.Fatalf("造合成 passkey: %v", err)
	}
	seedPasskey(t, e, uid, au)

	// ---- App 支：字符串形态 response + app ----
	id1, challenge1 := passkeyLoginOptions(t, e, "198.51.100.41")
	assertion, err := au.StringifiedAssertion(challenge1, uid)
	if err != nil {
		t.Fatalf("造字符串形态断言: %v", err)
	}
	rec := e.do(t, "POST", "/webauthn/login/finish",
		`{"ceremonyId":`+strconv.FormatInt(id1, 10)+`,"response":`+string(assertion)+`,"app":"calorie-diary"}`,
		fromIP("198.51.100.41"))
	if rec.Code != http.StatusOK {
		t.Fatalf("App passkey 登录应 200，得到 %d（%s）", rec.Code, rec.Body.String())
	}
	if got := keysOf(t, rec.Body.Bytes()); got != "deletePendingCancelled,email,mustChangePassword,token" {
		t.Errorf("回执应与 AuthResponse 同形，得到 %s", got)
	}
	if cookies := rec.Result().Cookies(); len(cookies) != 0 {
		t.Errorf("App 支不该下发 cookie，得到 %v", cookies)
	}
	jwt := tokenOf(t, rec.Body.Bytes())
	if strings.Count(jwt, ".") != 2 {
		t.Fatalf("App 支的 token 应是三段式 JWT，得到 %q", jwt)
	}
	if res := verifyByApp(t, e, jwt, "calorie-diary"); res.StatusCode != http.StatusOK {
		t.Errorf("passkey 签的 JWT 应过 verify，得到 %d", res.StatusCode)
	}

	// ---- web 支：对象形态 response、无 app ----
	id2, challenge2 := passkeyLoginOptions(t, e, "198.51.100.42")
	obj, err := au.Assertion(challenge2, uid)
	if err != nil {
		t.Fatalf("造对象形态断言: %v", err)
	}
	web := e.do(t, "POST", "/webauthn/login/finish",
		`{"ceremonyId":`+strconv.FormatInt(id2, 10)+`,"response":`+string(obj)+`}`,
		fromIP("198.51.100.42"))
	if web.Code != http.StatusOK {
		t.Fatalf("web passkey 登录应 200，得到 %d（%s）", web.Code, web.Body.String())
	}
	jar := map[string]*http.Cookie{}
	for _, c := range web.Result().Cookies() {
		jar[c.Name] = c
	}
	if jar[auth.WebCookieName] == nil || jar[auth.WebCSRFCookieName] == nil {
		t.Fatalf("web 支必须签两枚 cookie，得到 %v", jar)
	}
	// M2：web 支回体 token 恒空串，凭据只在 cookie
	webResp := authResponse{}
	if err := json.Unmarshal(web.Body.Bytes(), &webResp); err != nil {
		t.Fatalf("web 回执解析: %v（%s）", err, web.Body.String())
	}
	if webResp.Token != "" {
		t.Errorf("web 回体 token 必须恒空（凭据只在 cookie），得到 %q", webResp.Token)
	}
	if res := verifyByApp(t, e, "", "calorie-diary"); res.StatusCode != http.StatusUnauthorized {
		t.Errorf("空 token 不该过 verify，得到 %d", res.StatusCode)
	}

	// ---- 白名单外 400（app 校验在仪式之前，垃圾 ceremonyId 也先报 400）----
	bad := e.do(t, "POST", "/webauthn/login/finish",
		`{"ceremonyId":1,"response":"{}","app":"evil-app"}`, fromIP("198.51.100.43"))
	if bad.Code != http.StatusBadRequest {
		t.Errorf("白名单外的 app 应 400，得到 %d（%s）", bad.Code, bad.Body.String())
	}
}

// 重新验证的 Passkey 路（弹框「Passkey / 两步验证码二选一」的前者，sudo mode）：
// 正路验过刷本会话 reauth_at；仪式行绑 uid（别人的 ceremonyId 消费不动）、单次
// 消费（重放 404）、没 Passkey 的账号 400 提示改走验证码。
func TestPasskeyReauthRoute(t *testing.T) {
	e := newRouteEnv(t)
	uid := seedUser(t, e, "pk-reauth@example.com", "secret123", "user")
	au, err := webauthntest.New()
	if err != nil {
		t.Fatalf("造合成 passkey: %v", err)
	}
	seedPasskey(t, e, uid, au)
	sess, csrf := loginCookie(t, e, "pk-reauth@example.com", "secret123")
	withCSRF := func(r *http.Request) {
		r.AddCookie(sess)
		r.AddCookie(csrf)
		r.Header.Set("X-CSRF-Token", csrf.Value)
	}

	// ① 窗已过期 → 选项 + 断言 finish → 200 且本会话 reauth_at 被刷新
	staleReauth(t, e)
	id, challenge := reauthPasskeyOptions(t, e, withCSRF)
	obj, err := au.Assertion(challenge, uid)
	if err != nil {
		t.Fatalf("造断言: %v", err)
	}
	rec := e.do(t, "POST", "/web/reauth/webauthn/finish",
		`{"ceremonyId":`+strconv.FormatInt(id, 10)+`,"response":`+string(obj)+`}`, withCSRF)
	if rec.Code != http.StatusOK {
		t.Fatalf("passkey 重新验证应 200，得到 %d（%s）", rec.Code, rec.Body.String())
	}
	var reauthAt sql.NullInt64
	if err := e.pool.QueryRow(
		"SELECT reauth_at FROM sessions WHERE user_id = ? AND app = 'web' AND revoked_at IS NULL", uid,
	).Scan(&reauthAt); err != nil || !reauthAt.Valid {
		t.Errorf("验过应刷新本会话 reauth_at，得到 %v（err=%v）", reauthAt, err)
	}

	// ② 同一 ceremonyId 重放：单次消费，404（行已在 ① 删掉，签名再合法也进不了门）
	replayObj, err := au.Assertion(challenge, uid)
	if err != nil {
		t.Fatalf("造重放断言: %v", err)
	}
	replay := e.do(t, "POST", "/web/reauth/webauthn/finish",
		`{"ceremonyId":`+strconv.FormatInt(id, 10)+`,"response":`+string(replayObj)+`}`, withCSRF)
	if replay.Code != http.StatusNotFound {
		t.Errorf("重放同一仪式应 404，得到 %d（%s）", replay.Code, replay.Body.String())
	}

	// ③ 别人的 ceremonyId 消费不动：B 拿 A 的仪式行 finish → 404（行绑 uid）
	uidB := seedUser(t, e, "pk-reauth-b@example.com", "secret123", "user")
	auB, err := webauthntest.New()
	if err != nil {
		t.Fatalf("造 B 合成 passkey: %v", err)
	}
	seedPasskey(t, e, uidB, auB)
	sessB, csrfB := loginCookie(t, e, "pk-reauth-b@example.com", "secret123")
	withCSRFB := func(r *http.Request) {
		r.AddCookie(sessB)
		r.AddCookie(csrfB)
		r.Header.Set("X-CSRF-Token", csrfB.Value)
	}
	idA, challengeA := reauthPasskeyOptions(t, e, withCSRF)
	assertionB, err := auB.Assertion(challengeA, uidB)
	if err != nil {
		t.Fatalf("造 B 断言: %v", err)
	}
	cross := e.do(t, "POST", "/web/reauth/webauthn/finish",
		`{"ceremonyId":`+strconv.FormatInt(idA, 10)+`,"response":`+string(assertionB)+`}`, withCSRFB)
	if cross.Code != http.StatusNotFound {
		t.Errorf("消费他人仪式应 404，得到 %d（%s）", cross.Code, cross.Body.String())
	}

	// ④ 没 Passkey 的账号发起 → 400 且指路验证码（能力探测之外的服务端兜底）
	seedUser(t, e, "pk-reauth-none@example.com", "secret123", "user")
	sessC, csrfC := loginCookie(t, e, "pk-reauth-none@example.com", "secret123")
	none := e.do(t, "POST", "/web/reauth/webauthn/options", `{}`, func(r *http.Request) {
		r.AddCookie(sessC)
		r.AddCookie(csrfC)
		r.Header.Set("X-CSRF-Token", csrfC.Value)
	})
	if none.Code != http.StatusBadRequest || !strings.Contains(none.Body.String(), "验证码") {
		t.Errorf("无 Passkey 发起应 400 并指路验证码，得到 %d（%s）", none.Code, none.Body.String())
	}
}

// reauthPasskeyOptions 在带 cookie/CSRF 的前提下发起一次重新验证仪式，
// 回 ceremonyId 与 challenge（与 passkeyLoginOptions 同一回执形状）。
func reauthPasskeyOptions(t *testing.T, e *routeEnv, mutate func(*http.Request)) (id int64, challenge string) {
	t.Helper()
	rec := e.do(t, "POST", "/web/reauth/webauthn/options", `{}`, mutate)
	if rec.Code != http.StatusOK {
		t.Fatalf("取重新验证选项应 200，得到 %d（%s）", rec.Code, rec.Body.String())
	}
	var opt struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
		CeremonyID int64 `json:"ceremonyId"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &opt); err != nil {
		t.Fatalf("解析选项回执: %v（%s）", err, rec.Body)
	}
	if opt.CeremonyID == 0 || opt.PublicKey.Challenge == "" {
		t.Fatalf("选项回执缺 ceremonyId/challenge: %s", rec.Body)
	}
	return opt.CeremonyID, opt.PublicKey.Challenge
}

// passkeyLoginOptions 发一次 /webauthn/login/options，回 ceremonyId 与 challenge
//（challenge 是 base64url 字符串，合成断言要原样带回 clientData）。
func passkeyLoginOptions(t *testing.T, e *routeEnv, ip string) (id int64, challenge string) {
	t.Helper()
	rec := e.do(t, "POST", "/webauthn/login/options", `{}`, fromIP(ip))
	if rec.Code != http.StatusOK {
		t.Fatalf("取登录选项应 200，得到 %d（%s）", rec.Code, rec.Body.String())
	}
	var opt struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
		CeremonyID int64 `json:"ceremonyId"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &opt); err != nil {
		t.Fatalf("解析选项回执: %v（%s）", err, rec.Body)
	}
	if opt.CeremonyID == 0 || opt.PublicKey.Challenge == "" {
		t.Fatalf("选项回执缺 ceremonyId/challenge: %s", rec.Body)
	}
	return opt.CeremonyID, opt.PublicKey.Challenge
}

// seedPasskey 直接落一行凭证（路由测试不跑注册仪式；落库列与 insertCredential 同源）。
func seedPasskey(t *testing.T, e *routeEnv, uid int64, au *webauthntest.Authenticator) {
	t.Helper()
	if _, err := e.pool.Exec(
		`INSERT INTO passkeys
		 (id, user_id, name, credential_id, rp_id, public_key, sign_count, transports, aaguid,
		  backup_eligible, backup_state, created_at)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
		time.Now().UnixNano(), uid, "测试通行密钥",
		base64.RawURLEncoding.EncodeToString(au.Credential.ID), webauthntest.RPID,
		au.Credential.PublicKey, 0, "internal", "", 0, 0, time.Now().UnixMilli()); err != nil {
		t.Fatalf("落凭证: %v", err)
	}
}

// totpCode 生成 offset 之后那一步的 TOTP 码（Enable 用当下的码，第二步要换一步进）。
func totpCode(t *testing.T, secret string, offset time.Duration) string {
	t.Helper()
	code, err := totp.GenerateCode(secret, time.Now().Add(offset))
	if err != nil {
		t.Fatalf("生成 TOTP 码: %v", err)
	}
	return code
}
