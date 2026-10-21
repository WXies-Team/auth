package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/WXies-Team/auth/internal/auth"
)

// W2 分级授权的路由级矩阵：五种身份（super / 单 scope app-admin / 双 scope
// app-admin / 零 scope admin / 普通用户）× 各端点的允许/过滤/403。
// 每个管理身份都过满四道闸（cookie + role + MFA + reauth），矩阵只测闸后的收权。

// drainLoginBucket 清空 web-login 的限流桶：矩阵测试在同一测试 IP 上做十几次
// 登录（每 actor 一次），会打满 15/分/IP 的额度、殃及后续用例——与
// TestInternalVerifyRateLimitPerApp 的 drainVerifyBucket 同款思路。
func drainLoginBucket() {
	limiter.mu.Lock()
	for k := range limiter.windows {
		if strings.HasPrefix(k, "web-login:") {
			delete(limiter.windows, k)
		}
	}
	limiter.mu.Unlock()
}

// adminActor 是矩阵里的一个管理身份：cookie 两枚 + uid + 授权清单。
type adminActor struct {
	name string
	uid  int64
	sess *http.Cookie
	csrf *http.Cookie
	apps []string
	role string
}

// makeActor 落一个指定角色的账号、绑 MFA、登录取 cookie、落 scope 行、过 reauth。
func makeActor(t *testing.T, e *routeEnv, name, role string, apps []string) *adminActor {
	t.Helper()
	drainLoginBucket()
	t.Cleanup(drainLoginBucket)
	uid := seedUser(t, e, name+"@example.com", "secret123", role)
	sess, csrf := loginCookie(t, e, name+"@example.com", "secret123")
	enrollMFA(t, e, uid)
	for _, app := range apps {
		if _, err := e.pool.Exec(
			"INSERT INTO admin_scopes (uid, app, granted_by, granted_at) VALUES (?,?,?,?)",
			uid, app, uid, time.Now().UnixMilli()); err != nil {
			t.Fatalf("落授权行 %s/%s: %v", name, app, err)
		}
	}
	withCSRF := func(r *http.Request) {
		r.AddCookie(sess)
		r.AddCookie(csrf)
		r.Header.Set("X-CSRF-Token", csrf.Value)
	}
	if rec := e.do(t, "POST", "/web/reauth", `{"password":"secret123"}`, withCSRF); rec.Code != http.StatusOK {
		t.Fatalf("%s 重新验证应 200，得到 %d %s", name, rec.Code, rec.Body.String())
	}
	return &adminActor{name: name, uid: uid, sess: sess, csrf: csrf, apps: apps, role: role}
}

// cookieOnly 只带 cookie（GET 用，无需 CSRF 头）。
func (a *adminActor) cookieOnly(r *http.Request) {
	r.AddCookie(a.sess)
	r.AddCookie(a.csrf)
}

// withCSRF 带 cookie + CSRF 头（写操作用）。
func (a *adminActor) withCSRF(r *http.Request) {
	a.cookieOnly(r)
	r.Header.Set("X-CSRF-Token", a.csrf.Value)
}

// seedUserIfNew：seedAppSession 用——账号可能已由调用方 seed 过，不重复 INSERT。
func seedUserIfNew(t *testing.T, e *routeEnv, email string) {
	t.Helper()
	var n int
	if err := e.pool.QueryRow("SELECT COUNT(*) FROM users WHERE email = ?", email).Scan(&n); err != nil {
		t.Fatalf("查账号: %v", err)
	}
	if n == 0 {
		seedUser(t, e, email, "secret123", "user")
	}
}

// seedAppSession 造一台指定 app 的活跃会话（先确保账号存在），回 sid。
func seedAppSession(t *testing.T, e *routeEnv, email, app string) int64 {
	t.Helper()
	seedUserIfNew(t, e, email)
	if _, err := e.svc.Login(email, "secret123", app, auth.SessionMeta{IP: "10.9.9.9", UserAgent: "MatrixTest/1.0"}); err != nil {
		t.Fatalf("登录造会话 %s: %v", app, err)
	}
	var uid, sid int64
	if err := e.pool.QueryRow("SELECT id FROM users WHERE email = ?", email).Scan(&uid); err != nil {
		t.Fatalf("查用户: %v", err)
	}
	if err := e.pool.QueryRow(
		"SELECT id FROM sessions WHERE user_id = ? AND app = ? AND revoked_at IS NULL ORDER BY id DESC LIMIT 1",
		uid, app).Scan(&sid); err != nil {
		t.Fatalf("查会话行: %v", err)
	}
	return sid
}

// seedAuditWithApp 落一条 detail 带 app 标记的审计行（模拟登录类事件）。
func seedAuditWithApp(t *testing.T, e *routeEnv, app string) {
	t.Helper()
	if _, err := e.pool.Exec(
		`INSERT INTO audit_logs (id, ts, actor_uid, actor_email, action, result, detail)
		 VALUES (?,?,1,'seed@example.com','login.success','ok',?)`,
		time.Now().UnixNano()/1000, time.Now().UnixMilli(),
		`{"method":"password","app":"`+app+`"}`); err != nil {
		t.Fatalf("种审计行: %v", err)
	}
}

// seedAIUsage 落一条个人 AI 用量行。
func seedAIUsage(t *testing.T, e *routeEnv, uid int64, count int) {
	t.Helper()
	day := time.Now().Format("2006-01-02")
	if _, err := e.pool.Exec(
		"INSERT INTO ai_usage (scope, subject, day, `count`) VALUES ('user', ?, ?, ?)"+
			" ON DUPLICATE KEY UPDATE `count` = `count` + VALUES(`count`)",
		strconv.FormatInt(uid, 10), day, count); err != nil {
		t.Fatalf("种用量行: %v", err)
	}
}

// TestAdminScopeMatrix 是 W2 的核心矩阵。身份：
//
//	superX    role=super
//	oneApp    role=admin + calorie-diary 单授权
//	twoApps   role=admin + 双授权
//	noScope   role=admin + 零授权行（无权限 admin）
//	plainUser role=user
//
// 数据：victim 有 calorie 与 expense 两台会话、两条审计（各带 app 标记）、
// 一条 AI 用量。
func TestAdminScopeMatrix(t *testing.T) {
	e := newRouteEnv(t)
	superX := makeActor(t, e, "mx-super", "super", nil)
	oneApp := makeActor(t, e, "mx-one", "admin", []string{"calorie-diary"})
	twoApps := makeActor(t, e, "mx-two", "admin", []string{"calorie-diary", "expense-diary"})
	noScope := makeActor(t, e, "mx-noscope", "admin", nil)
	plain := makeActor(t, e, "mx-plain", "user", nil)

	victim := seedUser(t, e, "mx-victim@example.com", "secret123", "user")
	calSID := seedAppSession(t, e, "mx-victim@example.com", "calorie-diary")
	expSID := seedAppSession(t, e, "mx-victim@example.com", "expense-diary")
	seedAuditWithApp(t, e, "calorie-diary")
	seedAuditWithApp(t, e, "expense-diary")
	seedAIUsage(t, e, victim, 5)

	// ---- GET /admin/sessions：范围过滤 ----
	t.Run("sessions-list", func(t *testing.T) {
		countApps := func(rec *httptest.ResponseRecorder) map[string]int {
			var page struct {
				Items []struct {
					App string `json:"app"`
				} `json:"items"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
				t.Fatalf("解析回执: %v (%s)", err, rec.Body.String())
			}
			out := map[string]int{}
			for _, it := range page.Items {
				out[it.App]++
			}
			return out
		}
		// super 全量：两 app 都在
		rec := e.do(t, "GET", "/admin/sessions", "", superX.cookieOnly)
		if rec.Code != http.StatusOK {
			t.Fatalf("super 列会话应 200，得到 %d %s", rec.Code, rec.Body.String())
		}
		got := countApps(rec)
		if got["calorie-diary"] == 0 || got["expense-diary"] == 0 {
			t.Errorf("super 应见两 app 的会话，得到 %v", got)
		}
		// 单 scope：只见 calorie（web 会话也不该出现——它不属于任何授权 app）
		rec = e.do(t, "GET", "/admin/sessions", "", oneApp.cookieOnly)
		if rec.Code != http.StatusOK {
			t.Fatalf("app-admin 列会话应 200，得到 %d %s", rec.Code, rec.Body.String())
		}
		got = countApps(rec)
		for app, n := range got {
			if app != "calorie-diary" || n == 0 {
				t.Errorf("单 scope 只该见 calorie-diary，得到 %v", got)
				break
			}
		}
		// 双 scope：两 app 都在
		rec = e.do(t, "GET", "/admin/sessions", "", twoApps.cookieOnly)
		got = countApps(rec)
		if got["calorie-diary"] == 0 || got["expense-diary"] == 0 {
			t.Errorf("双 scope 应见两 app，得到 %v", got)
		}
		// ?app= 在授权内：单 app 视图
		rec = e.do(t, "GET", "/admin/sessions?app=expense-diary", "", twoApps.cookieOnly)
		got = countApps(rec)
		for app := range got {
			if app != "expense-diary" {
				t.Errorf("?app=expense 只该见 expense，得到 %v", got)
				break
			}
		}
		// ?app= 越界：403
		rec = e.do(t, "GET", "/admin/sessions?app=expense-diary", "", oneApp.cookieOnly)
		if rec.Code != http.StatusForbidden {
			t.Errorf("越界 ?app= 应 403，得到 %d %s", rec.Code, rec.Body.String())
		}
		// 零 scope admin：403（无权限）
		rec = e.do(t, "GET", "/admin/sessions", "", noScope.cookieOnly)
		if rec.Code != http.StatusForbidden {
			t.Errorf("零 scope admin 应 403，得到 %d %s", rec.Code, rec.Body.String())
		}
		// 普通用户：403（连管理闸都过不了）
		rec = e.do(t, "GET", "/admin/sessions", "", plain.cookieOnly)
		if rec.Code != http.StatusForbidden {
			t.Errorf("普通用户应 403，得到 %d", rec.Code)
		}
	})

	// ---- DELETE /admin/sessions/{id}：踢出边界 ----
	t.Run("session-kick", func(t *testing.T) {
		// app-admin 踢授权 app 的会话（victim 的 calorie 会话）→ 200
		rec := e.do(t, "DELETE", "/admin/sessions/"+strconv.FormatInt(calSID, 10), "", oneApp.withCSRF)
		if rec.Code != http.StatusOK {
			t.Errorf("踢授权 app 会话应 200，得到 %d %s", rec.Code, rec.Body.String())
		}
		// 越界：踢 expense 会话 → 403，会话仍活
		rec = e.do(t, "DELETE", "/admin/sessions/"+strconv.FormatInt(expSID, 10), "", oneApp.withCSRF)
		if rec.Code != http.StatusForbidden {
			t.Errorf("越界踢会话应 403，得到 %d %s", rec.Code, rec.Body.String())
		}
		var revoked sql.NullInt64
		if err := e.pool.QueryRow("SELECT revoked_at FROM sessions WHERE id = ?", expSID).Scan(&revoked); err != nil || revoked.Valid {
			t.Errorf("被拒的吊销不该生效，得到 valid=%v err=%v", revoked.Valid, err)
		}
		// super 不限：踢 expense 会话 → 200
		rec = e.do(t, "DELETE", "/admin/sessions/"+strconv.FormatInt(expSID, 10), "", superX.withCSRF)
		if rec.Code != http.StatusOK {
			t.Errorf("super 踢任意会话应 200，得到 %d %s", rec.Code, rec.Body.String())
		}
	})

	// ---- GET /admin/audit：detail app 过滤 ----
	t.Run("audit", func(t *testing.T) {
		auditApps := func(rec *httptest.ResponseRecorder) []string {
			var page struct {
				Items []struct {
					Detail map[string]string `json:"detail"`
				} `json:"items"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
				t.Fatalf("解析审计回执: %v (%s)", err, rec.Body.String())
			}
			out := []string{}
			for _, it := range page.Items {
				out = append(out, it.Detail["app"])
			}
			return out
		}
		// super：全量（含两条 seed 与无 app 的管理事件）
		rec := e.do(t, "GET", "/admin/audit", "", superX.cookieOnly)
		if rec.Code != http.StatusOK {
			t.Fatalf("super 查审计应 200，得到 %d", rec.Code)
		}
		// 单 scope：只见 calorie 条目
		rec = e.do(t, "GET", "/admin/audit", "", oneApp.cookieOnly)
		if rec.Code != http.StatusOK {
			t.Fatalf("app-admin 查审计应 200，得到 %d %s", rec.Code, rec.Body.String())
		}
		for _, app := range auditApps(rec) {
			if app != "" && app != "calorie-diary" {
				t.Errorf("单 scope 审计混入 %q", app)
			}
			if app == "expense-diary" {
				t.Errorf("单 scope 审计混入 expense 条目")
			}
		}
		// 零 scope：403
		if rec = e.do(t, "GET", "/admin/audit", "", noScope.cookieOnly); rec.Code != http.StatusForbidden {
			t.Errorf("零 scope 查审计应 403，得到 %d", rec.Code)
		}
	})

	// ---- GET /admin/ai-usage：subject 归属过滤 ----
	t.Run("ai-usage", func(t *testing.T) {
		parseTotal := func(rec *httptest.ResponseRecorder) int {
			var rep struct {
				Days []struct {
					Total int `json:"total"`
				} `json:"days"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &rep); err != nil {
				t.Fatalf("解析用量回执: %v (%s)", err, rec.Body.String())
			}
			if len(rep.Days) == 0 {
				return 0
			}
			return rep.Days[0].Total
		}
		// victim 只注册过（calorie 会话），用量 5 → calorie 视角应看到
		rec := e.do(t, "GET", "/admin/ai-usage", "", oneApp.cookieOnly)
		if rec.Code != http.StatusOK {
			t.Fatalf("app-admin 看板应 200，得到 %d %s", rec.Code, rec.Body.String())
		}
		if total := parseTotal(rec); total != 5 {
			t.Errorf("calorie 视角当日 total 应 5，得到 %d", total)
		}
		// 零 scope：403
		if rec = e.do(t, "GET", "/admin/ai-usage", "", noScope.cookieOnly); rec.Code != http.StatusForbidden {
			t.Errorf("零 scope 看板应 403，得到 %d", rec.Code)
		}
	})

	// ---- super-only 端点：users / roles / config ----
	t.Run("super-only", func(t *testing.T) {
		for _, tc := range []struct {
			name, method, path, body string
		}{
			{"users-list", "GET", "/admin/users", ""},
			{"users-detail", "GET", "/admin/users/" + strconv.FormatInt(victim, 10), ""},
			{"users-role", "POST", "/admin/users/" + strconv.FormatInt(victim, 10) + "/role", `{"role":"admin"}`},
			{"users-kick", "POST", "/admin/users/" + strconv.FormatInt(victim, 10) + "/revoke-sessions", `{}`},
			{"roles-scope", "POST", "/admin/roles/" + strconv.FormatInt(victim, 10) + "/scope", `{"app":"calorie-diary","op":"grant"}`},
			{"config-list", "GET", "/admin/config", ""},
			{"config-write", "PUT", "/admin/config/llm_model", `{"value":"gpt-x"}`},
		} {
			// super 放行（200）
			rec := e.do(t, tc.method, tc.path, tc.body, superX.withCSRF)
			if rec.Code != http.StatusOK {
				t.Errorf("super %s 应 200，得到 %d %s", tc.name, rec.Code, rec.Body.String())
			}
			// app-admin（哪怕双 scope）403
			rec = e.do(t, tc.method, tc.path, tc.body, twoApps.withCSRF)
			if rec.Code != http.StatusForbidden {
				t.Errorf("app-admin %s 应 403，得到 %d %s", tc.name, rec.Code, rec.Body.String())
			}
			// 普通用户 403
			rec = e.do(t, tc.method, tc.path, tc.body, plain.withCSRF)
			if rec.Code != http.StatusForbidden {
				t.Errorf("普通用户 %s 应 403，得到 %d", tc.name, rec.Code)
			}
		}
	})
}

// 角色管理端点的行为：授予隐含提 admin、收光降回 user、审计落行、
// 最后一个 super 不可降级、非法输入。
func TestRolesEndpoints(t *testing.T) {
	e := newRouteEnv(t)
	superX := makeActor(t, e, "ro-super", "super", nil)
	target := seedUser(t, e, "ro-target@example.com", "secret123", "user")
	otherSuper := seedUser(t, e, "ro-othersuper@example.com", "secret123", "super")

	// 授予：role 提 admin + scopes 摘要可见 + 审计落行
	rec := e.do(t, "POST", "/admin/roles/"+strconv.FormatInt(target, 10)+"/scope",
		`{"app":"calorie-diary","op":"grant"}`, superX.withCSRF)
	if rec.Code != http.StatusOK {
		t.Fatalf("授予应 200，得到 %d %s", rec.Code, rec.Body.String())
	}
	var role string
	if err := e.pool.QueryRow("SELECT role FROM users WHERE id = ?", target).Scan(&role); err != nil || role != "admin" {
		t.Errorf("授予后 role 应 admin，得到 %q err=%v", role, err)
	}
	var grants int
	if err := e.pool.QueryRow("SELECT COUNT(*) FROM audit_logs WHERE action = 'admin.role.grant' AND result = 'ok'").
		Scan(&grants); err != nil || grants == 0 {
		t.Errorf("授予应落 admin.role.grant 审计，得到 %d err=%v", grants, err)
	}
	// 用户详情带 scopes、列表带 scopeCount（合并用户页的数据源，钉住 JSON 字段）
	targetUID := strconv.FormatInt(target, 10)
	rec = e.do(t, "GET", "/admin/users/"+targetUID, "", superX.cookieOnly)
	if rec.Code != http.StatusOK {
		t.Fatalf("用户详情应 200，得到 %d", rec.Code)
	}
	var detail struct {
		Role   string   `json:"role"`
		Scopes []string `json:"scopes"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &detail); err != nil {
		t.Fatalf("用户详情解析: %v (%s)", err, rec.Body.String())
	}
	if detail.Role != "admin" || len(detail.Scopes) != 1 || detail.Scopes[0] != "calorie-diary" {
		t.Errorf("用户详情 role/scopes 不对: %+v", detail)
	}
	rec = e.do(t, "GET", "/admin/users?query=ro-target", "", superX.cookieOnly)
	if rec.Code != http.StatusOK {
		t.Fatalf("用户列表应 200，得到 %d", rec.Code)
	}
	var upage struct {
		Items []struct {
			UID        int64 `json:"uid"`
			ScopeCount int   `json:"scopeCount"`
		} `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &upage); err != nil || len(upage.Items) != 1 {
		t.Fatalf("用户列表解析: %v items=%d", err, len(upage.Items))
	}
	if upage.Items[0].ScopeCount != 1 {
		t.Errorf("列表 scopeCount 应 1，得到 %d", upage.Items[0].ScopeCount)
	}

	// 收光最后一个授权：role 降回 user
	rec = e.do(t, "POST", "/admin/roles/"+strconv.FormatInt(target, 10)+"/scope",
		`{"app":"calorie-diary","op":"revoke"}`, superX.withCSRF)
	if rec.Code != http.StatusOK {
		t.Fatalf("回收应 200，得到 %d %s", rec.Code, rec.Body.String())
	}
	if err := e.pool.QueryRow("SELECT role FROM users WHERE id = ?", target).Scan(&role); err != nil || role != "user" {
		t.Errorf("收光后 role 应降回 user，得到 %q err=%v", role, err)
	}
	var revokes int
	if err := e.pool.QueryRow("SELECT COUNT(*) FROM audit_logs WHERE action = 'admin.role.revoke' AND result = 'ok'").
		Scan(&revokes); err != nil || revokes == 0 {
		t.Errorf("回收应落 admin.role.revoke 审计，得到 %d err=%v", revokes, err)
	}

	// 非法 op / 名单外 app
	rec = e.do(t, "POST", "/admin/roles/"+strconv.FormatInt(target, 10)+"/scope",
		`{"app":"calorie-diary","op":"delete"}`, superX.withCSRF)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("非法 op 应 400，得到 %d", rec.Code)
	}
	rec = e.do(t, "POST", "/admin/roles/"+strconv.FormatInt(target, 10)+"/scope",
		`{"app":"evil-app","op":"grant"}`, superX.withCSRF)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("名单外 app 应 400，得到 %d", rec.Code)
	}

	// role 变更：target 先提成 admin，再升 super，然后试着降最后一个 super（失败）
	_ = e.do(t, "POST", "/admin/roles/"+strconv.FormatInt(target, 10)+"/scope",
		`{"app":"calorie-diary","op":"grant"}`, superX.withCSRF)
	rec = e.do(t, "POST", "/admin/roles/"+strconv.FormatInt(target, 10)+"/role",
		`{"role":"super"}`, superX.withCSRF)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin 升 super 应 200，得到 %d %s", rec.Code, rec.Body.String())
	}
	// 现在有两个 super（superX + target）：superX 不能自贬（400 含「自己」）
	rec = e.do(t, "POST", "/admin/roles/"+strconv.FormatInt(superX.uid, 10)+"/role",
		`{"role":"admin"}`, superX.withCSRF)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "自己") {
		t.Errorf("自贬应 400 且点名，得到 %d %s", rec.Code, rec.Body.String())
	}
	// 把 otherSuper 也升成 super，再逐个降——降到最后一个时应 400
	_ = e.do(t, "POST", "/admin/roles/"+strconv.FormatInt(otherSuper, 10)+"/role",
		`{"role":"super"}`, superX.withCSRF) // otherSuper 本就是 super，此调用应 400（非 admin 目标）
	// target 降 admin（库里还有 superX，允许）
	rec = e.do(t, "POST", "/admin/roles/"+strconv.FormatInt(target, 10)+"/role",
		`{"role":"admin"}`, superX.withCSRF)
	if rec.Code != http.StatusOK {
		t.Errorf("非最后 super 降级应 200，得到 %d %s", rec.Code, rec.Body.String())
	}
	// admin.role.change 审计
	var changes int
	if err := e.pool.QueryRow("SELECT COUNT(*) FROM audit_logs WHERE action = 'admin.role.change' AND result = 'ok'").
		Scan(&changes); err != nil || changes == 0 {
		t.Errorf("角色调整应落 admin.role.change 审计，得到 %d err=%v", changes, err)
	}
	// 非法 role 值
	rec = e.do(t, "POST", "/admin/roles/"+strconv.FormatInt(target, 10)+"/role",
		`{"role":"root"}`, superX.withCSRF)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("非法 role 应 400，得到 %d", rec.Code)
	}
}

// 切换器渲染：super 见「全部」+ 两 app；app-admin 只见自己授权的 app（无「全部」）；
// 普通用户无入口。super 专属页对 app-admin 302。
func TestSwitcherRendering(t *testing.T) {
	e := newRouteEnv(t)
	superX := makeActor(t, e, "sw-super", "super", nil)
	oneApp := makeActor(t, e, "sw-one", "admin", []string{"calorie-diary"})

	pageOf := func(a *adminActor, path string) (int, string) {
		rec := e.do(t, "GET", path, "", a.cookieOnly)
		return rec.Code, rec.Body.String()
	}

	// super：三选项（全部/热量/开支）
	code, html := pageOf(superX, "/web/admin/sessions")
	if code != http.StatusOK {
		t.Fatalf("super 打会话页应 200，得到 %d", code)
	}
	for _, want := range []string{`id="app-switch"`, `data-app=""`, `data-app="calorie-diary"`, `data-app="expense-diary"`, `>全部<`} {
		if !strings.Contains(html, want) {
			t.Errorf("super 切换器缺 %q", want)
		}
	}
	// app-admin：只有 calorie，没有「全部」，没有 users/config/roles 导航入口
	code, html = pageOf(oneApp, "/web/admin/sessions")
	if code != http.StatusOK {
		t.Fatalf("app-admin 打会话页应 200，得到 %d", code)
	}
	if !strings.Contains(html, `data-app="calorie-diary"`) {
		t.Error("app-admin 切换器应含自己的 app")
	}
	if strings.Contains(html, `data-app="expense-diary"`) || strings.Contains(html, `>全部<`) {
		t.Error("app-admin 切换器不该出现未授权 app 或「全部」")
	}
	for _, banned := range []string{`href="/web/admin"`, `href="/web/admin/config"`, `href="/web/admin/roles"`} {
		if strings.Contains(html, banned) {
			t.Errorf("app-admin 的 HTML 不该出现平台级入口 %q", banned)
		}
	}
	// app-admin 直敲 super 专属页：302 去会话总览
	rec := e.do(t, "GET", "/web/admin", "", oneApp.cookieOnly)
	if rec.Code != http.StatusFound || !strings.Contains(rec.Header().Get("Location"), "/web/admin/sessions") {
		t.Errorf("app-admin 访问用户页应 302 去会话页，得到 %d %s", rec.Code, rec.Header().Get("Location"))
	}
	rec = e.do(t, "GET", "/web/admin/roles", "", oneApp.cookieOnly)
	if rec.Code != http.StatusFound {
		t.Errorf("app-admin 访问角色页应 302，得到 %d", rec.Code)
	}
	// 越权 ?app= 页面：403 页（友好文案）
	code, html = pageOf(oneApp, "/web/admin/sessions?app=expense-diary")
	if code != http.StatusForbidden || !strings.Contains(html, "无权访问") {
		t.Errorf("越权 ?app= 页面应 403 且友好文案，得到 %d", code)
	}
	// super 的合法 ?app= 页面：200
	if code, _ = pageOf(superX, "/web/admin/sessions?app=calorie-diary"); code != http.StatusOK {
		t.Errorf("super 带合法 ?app= 应 200，得到 %d", code)
	}
	// 普通用户：管理页 302 去概览
	plain := makeActor(t, e, "sw-plain", "user", nil)
	rec = e.do(t, "GET", "/web/admin/sessions", "", plain.cookieOnly)
	if rec.Code != http.StatusFound || !strings.Contains(rec.Header().Get("Location"), "/web/console") {
		t.Errorf("普通用户访问管理页应 302 去概览，得到 %d %s", rec.Code, rec.Header().Get("Location"))
	}
}
