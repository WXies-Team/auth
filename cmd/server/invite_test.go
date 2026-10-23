package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/WXies-Team/auth/internal/auth"
	"github.com/WXies-Team/auth/internal/config"
)

// B9 的路由级用例：四道闸 + scope 收权过完之后的请求/回执形状，以及接受页
//（GET 表单 / POST 提交 → 302 + 种 cookie）打在真 handler 上的行为。
// 真库依赖同 newRouteEnv：无 TEST_MYSQL_DSN 跳过，真跑留 CI。

// drainInviteBucket 清空 web-invite 限流桶：GET 接受页与 POST 提交共用 15/分/IP，
// 测试 IP 全包共享——与 drainLoginBucket 同款思路，不清理会互相踩。
func drainInviteBucket() {
	limiter.mu.Lock()
	for k := range limiter.windows {
		if strings.HasPrefix(k, "web-invite:") {
			delete(limiter.windows, k)
		}
	}
	limiter.mu.Unlock()
}

// 无 DB 的路由装配守卫：ServeMux 的模式冲突在注册那一刻就 panic（进程起不来），
// 而正常装配只发生在 newRouteEnv（真库，缺 DSN 即跳过）。这里用零值 Service 把
// **全部模式挂一遍**，让 B9 新增的字面量段（/admin/users/invite、
// /admin/users/invite/{id}/resend|revoke、/admin/users/bulk、/web/invite）与既有
// 的 /admin/users/{uid}/* 通配模式共存关系在没有数据库时也被钉住。
func TestRegisterRoutesWithoutConflict(t *testing.T) {
	mux := http.NewServeMux()
	registerRoutes(mux, &auth.Service{}, config.New(nil), nil)
	// 走到这里就说明没有模式冲突（冲突在 mux.Handle 处直接 panic，到不了这里）
}

// seedInviteRow 直接落一行邀请并回明文 token。路由测试的 svc 没接 mailer，而明文
// token 只在创建那刻进邮件——这里按 invite.go 的落库形态自算 sha256 种 hash，
// 等价于「管理员已经发过邀请」的起点。
func seedInviteRow(t *testing.T, e *routeEnv, email, app string, token string, expiresAt int64) int64 {
	t.Helper()
	sum := sha256.Sum256([]byte(token))
	id := time.Now().UnixNano()/1000 + uidSeq.Add(1)
	if _, err := e.pool.Exec(
		"INSERT INTO user_invites (id, email, app, invited_by, token_hash, created_at, expires_at) VALUES (?,?,?,?,?,?,?)",
		id, email, app, 1, fmt.Sprintf("%x", sum), time.Now().UnixMilli(), expiresAt); err != nil {
		t.Fatalf("种邀请行: %v", err)
	}
	return id
}

// 管理端邀请四端点：回执形状、四态、查重 400、越权 403、非管理员 403。
func TestAdminInviteRoutes(t *testing.T) {
	drainInviteBucket()
	t.Cleanup(drainInviteBucket)
	e := newRouteEnv(t)
	super := makeActor(t, e, "inv-super", "super", nil)
	appAdmin := makeActor(t, e, "inv-one", "admin", []string{"calorie-diary"})
	plain := makeActor(t, e, "inv-plain", "user", nil)

	// 创建 → {ok,expiresAt}
	rec := e.do(t, "POST", "/admin/users/invite",
		`{"email":"route-invitee@example.com","app":"calorie-diary"}`, super.withCSRF)
	if rec.Code != http.StatusOK {
		t.Fatalf("super 创建邀请应 200，得到 %d %s", rec.Code, rec.Body.String())
	}
	if got := keysOf(t, rec.Body.Bytes()); got != "expiresAt,ok" {
		t.Errorf("创建回执形状应恰为 expiresAt,ok，得到 %s", got)
	}
	var created struct {
		OK        bool  `json:"ok"`
		ExpiresAt int64 `json:"expiresAt"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil || !created.OK ||
		created.ExpiresAt < time.Now().UnixMilli() {
		t.Errorf("创建回执内容不对: ok=%v exp=%d err=%v", created.OK, created.ExpiresAt, err)
	}

	// 查重：同邮箱待接受 → 400 {message}
	rec = e.do(t, "POST", "/admin/users/invite",
		`{"email":"route-invitee@example.com"}`, super.withCSRF)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "待接受") {
		t.Errorf("同邮箱重复邀请应 400 且点名待接受，得到 %d %s", rec.Code, rec.Body.String())
	}
	if got := keysOf(t, rec.Body.Bytes()); got != "message" {
		t.Errorf("错误回执形状应恰为 message，得到 %s", got)
	}

	// 列表 → {invites:[...]}，四态与 id 的字符串口径
	rec = e.do(t, "GET", "/admin/users/invites", "", super.cookieOnly)
	if rec.Code != http.StatusOK {
		t.Fatalf("列邀请应 200，得到 %d %s", rec.Code, rec.Body.String())
	}
	if got := keysOf(t, rec.Body.Bytes()); got != "invites" {
		t.Errorf("列表回执形状应恰为 invites，得到 %s", got)
	}
	var list struct {
		Invites []struct {
			ID        string `json:"id"`
			Email     string `json:"email"`
			App       string `json:"app"`
			CreatedAt int64  `json:"createdAt"`
			ExpiresAt int64  `json:"expiresAt"`
			State     string `json:"state"`
		} `json:"invites"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil || len(list.Invites) != 1 {
		t.Fatalf("应恰 1 条邀请: %v (%s)", err, rec.Body.String())
	}
	it := list.Invites[0]
	if it.State != "pending" || it.Email != "route-invitee@example.com" || it.App != "calorie-diary" {
		t.Errorf("邀请行不对: %+v", it)
	}
	if it.ID == "" || it.CreatedAt == 0 || it.ExpiresAt == 0 {
		t.Errorf("时间戳与 id 都该给全: %+v", it)
	}

	// 重发 → {ok:true}；撤销 → {ok:true}；重复撤销幂等 → {ok:true}
	rec = e.do(t, "POST", "/admin/users/invite/"+it.ID+"/resend", `{}`, super.withCSRF)
	if rec.Code != http.StatusOK || keysOf(t, rec.Body.Bytes()) != "ok" {
		t.Errorf("重发应 200 {ok}，得到 %d %s", rec.Code, rec.Body.String())
	}
	rec = e.do(t, "POST", "/admin/users/invite/"+it.ID+"/revoke", `{}`, super.withCSRF)
	if rec.Code != http.StatusOK || keysOf(t, rec.Body.Bytes()) != "ok" {
		t.Errorf("撤销应 200 {ok}，得到 %d %s", rec.Code, rec.Body.String())
	}
	rec = e.do(t, "POST", "/admin/users/invite/"+it.ID+"/revoke", `{}`, super.withCSRF)
	if rec.Code != http.StatusOK {
		t.Errorf("重复撤销应幂等 200，得到 %d %s", rec.Code, rec.Body.String())
	}
	// 撤销后再重发 → 400（应重新发起）
	rec = e.do(t, "POST", "/admin/users/invite/"+it.ID+"/resend", `{}`, super.withCSRF)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("已撤销的邀请重发应 400，得到 %d %s", rec.Code, rec.Body.String())
	}

	// 权限：app-admin 带授权 app → 200；越权 app → 403；空 app → 403；普通用户 → 403
	rec = e.do(t, "POST", "/admin/users/invite",
		`{"email":"route-scope@example.com","app":"calorie-diary"}`, appAdmin.withCSRF)
	if rec.Code != http.StatusOK {
		t.Errorf("app-admin 邀请授权项目应 200，得到 %d %s", rec.Code, rec.Body.String())
	}
	rec = e.do(t, "POST", "/admin/users/invite",
		`{"email":"route-out@example.com","app":"expense-diary"}`, appAdmin.withCSRF)
	if rec.Code != http.StatusForbidden {
		t.Errorf("越权项目应 403，得到 %d %s", rec.Code, rec.Body.String())
	}
	rec = e.do(t, "POST", "/admin/users/invite",
		`{"email":"route-noscope@example.com"}`, appAdmin.withCSRF)
	if rec.Code != http.StatusForbidden {
		t.Errorf("app-admin 空 app 应 403，得到 %d %s", rec.Code, rec.Body.String())
	}
	rec = e.do(t, "POST", "/admin/users/invite",
		`{"email":"route-plain@example.com"}`, plain.withCSRF)
	if rec.Code != http.StatusForbidden {
		t.Errorf("普通用户应 403（后台闸），得到 %d %s", rec.Code, rec.Body.String())
	}

	// 列表收权：app-admin 只见自己 app 的邀请
	rec = e.do(t, "GET", "/admin/users/invites", "", appAdmin.cookieOnly)
	if rec.Code != http.StatusOK {
		t.Fatalf("app-admin 列邀请应 200，得到 %d %s", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("解析列表: %v", err)
	}
	for _, inv := range list.Invites {
		if inv.App != "calorie-diary" {
			t.Errorf("app-admin 不该见到 %q 的邀请: %+v", inv.App, inv)
		}
	}
}

// 批量端点：形状（批次号 + 汇总 + 逐项）、入参 400、越权项逐项失败不整批报错。
func TestAdminBulkRoute(t *testing.T) {
	e := newRouteEnv(t)
	super := makeActor(t, e, "bulk-super", "super", nil)
	v1 := seedUser(t, e, "bulk-r1@example.com", "secret123", "user")
	v2 := seedUser(t, e, "bulk-r2@example.com", "secret123", "user")

	// 非法 kind → 400 {message}
	rec := e.do(t, "POST", "/admin/users/bulk", `{"kind":"wipe","uids":[1]}`, super.withCSRF)
	if rec.Code != http.StatusBadRequest || keysOf(t, rec.Body.Bytes()) != "message" {
		t.Errorf("非法 kind 应 400 {message}，得到 %d %s", rec.Code, rec.Body.String())
	}
	// 空选择 → 400
	rec = e.do(t, "POST", "/admin/users/bulk", `{"kind":"ban","uids":[]}`, super.withCSRF)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "请先选择") {
		t.Errorf("空选择应 400，得到 %d %s", rec.Code, rec.Body.String())
	}

	// 封禁两人的形状：batchId + kind + total/succeeded/failed + items（逐项 ok/message）
	rec = e.do(t, "POST", "/admin/users/bulk",
		fmt.Sprintf(`{"kind":"ban","uids":[%d,%d],"app":"calorie-diary","reason":"路由测试"}`, v1, v2),
		super.withCSRF)
	if rec.Code != http.StatusOK {
		t.Fatalf("super 批量封禁应 200，得到 %d %s", rec.Code, rec.Body.String())
	}
	if got := keysOf(t, rec.Body.Bytes()); got != "batchId,failed,items,kind,succeeded,total" {
		t.Errorf("批量回执形状应恰为 batchId,failed,items,kind,succeeded,total，得到 %s", got)
	}
	var res struct {
		BatchID   string `json:"batchId"`
		Kind      string `json:"kind"`
		Total     int    `json:"total"`
		Succeeded int    `json:"succeeded"`
		Failed    int    `json:"failed"`
		Items     []struct {
			UID     int64  `json:"uid"`
			OK      bool   `json:"ok"`
			Message string `json:"message"`
		} `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("解析批量回执: %v", err)
	}
	if res.BatchID == "" || res.Kind != "ban" || res.Total != 2 || res.Succeeded != 2 || res.Failed != 0 {
		t.Errorf("批量回执内容不对: %+v", res)
	}
	if len(res.Items) != 2 || !res.Items[0].OK {
		t.Errorf("逐项结果应齐: %+v", res.Items)
	}
	// items 只有 uid/ok/message（临时密码等凭证绝不进批量回执）
	for _, raw := range []string{"temporaryPassword", "password"} {
		if strings.Contains(rec.Body.String(), raw) {
			t.Errorf("批量回执不该出现 %q: %s", raw, rec.Body.String())
		}
	}
	// 封禁行确实落库
	var bans int
	if err := e.pool.QueryRow("SELECT COUNT(*) FROM user_bans WHERE app = 'calorie-diary'").Scan(&bans); err != nil || bans != 2 {
		t.Errorf("应落 2 条封禁行，得到 %d（%v）", bans, err)
	}
	// 解封同端点（kind=unban）→ 2/2
	rec = e.do(t, "POST", "/admin/users/bulk",
		fmt.Sprintf(`{"kind":"unban","uids":[%d,%d],"app":"calorie-diary"}`, v1, v2), super.withCSRF)
	if rec.Code != http.StatusOK {
		t.Fatalf("批量解封应 200，得到 %d %s", rec.Code, rec.Body.String())
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &res)
	if res.Succeeded != 2 {
		t.Errorf("解封应 2/2，得到 %+v", res)
	}

	// 越权项：普通用户 → 后台闸 403（连端点都进不去）
	plain := makeActor(t, e, "bulk-plain", "user", nil)
	rec = e.do(t, "POST", "/admin/users/bulk", `{"kind":"ban","uids":[1],"app":"*"}`, plain.withCSRF)
	if rec.Code != http.StatusForbidden {
		t.Errorf("普通用户应 403，得到 %d %s", rec.Code, rec.Body.String())
	}
}

// 接受页：GET 表单双变体（有效渲染 / 无效 400 错误变体）、POST 提交建号 +
// 种 cookie + 302 进控制台（自动登录），以及弱密码打回原表单。
func TestInviteAcceptPageRoutes(t *testing.T) {
	drainInviteBucket()
	t.Cleanup(drainInviteBucket)
	e := newRouteEnv(t)

	// 无效 token：壳照发（M4 切流后 token 校验在 SPA 内做），POST 才是权威闸
	rec := e.do(t, "GET", "/web/invite?token=definitely-bogus", "", nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "/wasm/authweb.js") {
		t.Fatalf("邀请页应下发 SPA 壳，得到 %d %s", rec.Code, rec.Body.String())
	}

	// 有效 token → 同一 SPA 壳（表单/校验都在 SPA 里）
	token := "route-accept-" + fmt.Sprint(time.Now().UnixNano())
	seedInviteRow(t, e, "route-accept@example.com", "calorie-diary", token,
		time.Now().Add(time.Hour).UnixMilli())
	rec = e.do(t, "GET", "/web/invite?token="+url.QueryEscape(token), "", nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "/wasm/authweb.js") {
		t.Fatalf("邀请页应下发 SPA 壳，得到 %d %s", rec.Code, rec.Body.String())
	}

	// 弱密码 POST → 400 且回到表单（就地报错，不踢去错误变体）
	form := "token=" + url.QueryEscape(token) + "&password=123&nickname=%E5%B0%8F%E9%82%80"
	rec = e.do(t, "POST", "/web/invite", form, func(r *http.Request) {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	})
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "message") {
		t.Fatalf("弱密码应 400 + JSON 错误，得到 %d %s", rec.Code, rec.Body.String())
	}

	// 正确密码 POST → 302 /web/console + 种双 cookie（自动登录）
	form = "token=" + url.QueryEscape(token) + "&password=secret123&nickname=%E5%B0%8F%E9%82%80"
	rec = e.do(t, "POST", "/web/invite", form, func(r *http.Request) {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	})
	if rec.Code != http.StatusFound {
		t.Fatalf("接受成功应 302 进控制台，得到 %d %s", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); loc != "/web/console" {
		t.Errorf("应 302 到 /web/console，得到 %q", loc)
	}
	var sess, csrf *http.Cookie
	for _, c := range rec.Result().Cookies() {
		switch c.Name {
		case "__Host-auth_web":
			sess = c
		case "__Host-auth_web_csrf":
			csrf = c
		}
	}
	if sess == nil || sess.Value == "" || !sess.HttpOnly || !sess.Secure {
		t.Errorf("应种 HttpOnly+Secure 的会话 cookie，得到 %+v", sess)
	}
	if csrf == nil || csrf.Value == "" || csrf.HttpOnly {
		t.Errorf("CSRF cookie 应可读（非 HttpOnly），得到 %+v", csrf)
	}

	// 账号已建 + 邀请单次消费（同一 token 再提交 → 400 错误变体）
	var n int
	if err := e.pool.QueryRow("SELECT COUNT(*) FROM users WHERE email = 'route-accept@example.com'").Scan(&n); err != nil || n != 1 {
		t.Errorf("接受后应恰建 1 个号，得到 %d（%v）", n, err)
	}
	var accepted int
	_ = e.pool.QueryRow("SELECT COUNT(*) FROM user_invites WHERE email = 'route-accept@example.com' AND accepted_at > 0").
		Scan(&accepted)
	if accepted != 1 {
		t.Errorf("邀请行应被置为已接受，得到 %d", accepted)
	}
	// 拿种下的 cookie 直接进控制台 = 自动登录真的成立
	page := e.do(t, "GET", "/web/console", "", func(r *http.Request) {
		r.AddCookie(sess)
		r.AddCookie(csrf)
	})
	if page.Code != http.StatusOK {
		t.Errorf("种下的会话应进得了控制台，得到 %d", page.Code)
	}

	// 同一 token 再接受 → 400 且是错误变体（单次消费）
	rec = e.do(t, "POST", "/web/invite", form, func(r *http.Request) {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	})
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "已被接受") {
		t.Errorf("重放应 400 + JSON 错误，得到 %d %s", rec.Code, rec.Body.String())
	}
}
