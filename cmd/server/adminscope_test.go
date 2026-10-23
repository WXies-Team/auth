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
	return makeActorEmail(t, e, name, name+"@example.com", role, apps)
}

// makeActorEmail 同 makeActor 但邮箱显式给出——根收口（W7-2）的用例需要
// RootSuperEmail 账号，推导邮箱凑不出这个地址。
func makeActorEmail(t *testing.T, e *routeEnv, name, email, role string, apps []string) *adminActor {
	t.Helper()
	drainLoginBucket()
	t.Cleanup(drainLoginBucket)
	uid := seedUser(t, e, email, "secret123", role)
	sess, csrf := loginCookie(t, e, email, "secret123")
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
		// 回执的天序列字段是 count（total 是旧名）且按日期**升序**：最旧一天在
		// [0]、today 收尾。图表按 date key 取数、顺序无关，但把 [0] 当今天就会错
		//——字段名与顺序口径在此钉死，顺带钉默认窗口 30 天。
		parseToday := func(rec *httptest.ResponseRecorder) int {
			var rep struct {
				Days []struct {
					Date  string `json:"date"`
					Count int    `json:"count"`
				} `json:"days"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &rep); err != nil {
				t.Fatalf("解析用量回执: %v (%s)", err, rec.Body.String())
			}
			if len(rep.Days) != 30 {
				t.Fatalf("默认窗口应 30 天，得到 %d", len(rep.Days))
			}
			now := time.Now()
			var today int
			for i, d := range rep.Days {
				want := now.AddDate(0, 0, -(len(rep.Days) - 1 - i)).Format("2006-01-02")
				if d.Date != want {
					t.Fatalf("days[%d] 应为 %s（升序、收尾今天），得到 %s", i, want, d.Date)
				}
				if d.Date == now.Format("2006-01-02") {
					today = d.Count
				}
			}
			return today
		}
		// victim 只注册过（calorie 会话），用量 5 → calorie 视角应看到
		rec := e.do(t, "GET", "/admin/ai-usage", "", oneApp.cookieOnly)
		if rec.Code != http.StatusOK {
			t.Fatalf("app-admin 看板应 200，得到 %d %s", rec.Code, rec.Body.String())
		}
		if total := parseToday(rec); total != 5 {
			t.Errorf("calorie 视角当日 count 应 5，得到 %d", total)
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
// 非法输入；角色调整唯一入口是 POST /admin/users/{uid}/role，涉 super 的
// 授予/回收收口根 su（W7-2，非根 super 一律 403）。
func TestRolesEndpoints(t *testing.T) {
	e := newRouteEnv(t)
	superX := makeActor(t, e, "ro-super", "super", nil)
	root := makeActorEmail(t, e, "ro-root", auth.RootSuperEmail, "super", nil)
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

	// role 变更走唯一入口 POST /admin/users/{uid}/role（旧 /admin/roles/{uid}/role
	// 与 PATCH /admin/users/{uid} 已并入删除）。涉 super 的授予/回收收口根 su（W7-2）。
	_ = e.do(t, "POST", "/admin/roles/"+strconv.FormatInt(target, 10)+"/scope",
		`{"app":"calorie-diary","op":"grant"}`, superX.withCSRF)
	// 非根 super 授他人 super → 403（只有根 su 能给 super）
	rec = e.do(t, "POST", "/admin/users/"+strconv.FormatInt(target, 10)+"/role",
		`{"role":"super"}`, superX.withCSRF)
	if rec.Code != http.StatusForbidden {
		t.Errorf("非根 super 授他人 super 应 403，得到 %d %s", rec.Code, rec.Body.String())
	}
	// 根 su 把 admin 升 super → 200
	rec = e.do(t, "POST", "/admin/users/"+strconv.FormatInt(target, 10)+"/role",
		`{"role":"super"}`, root.withCSRF)
	if rec.Code != http.StatusOK {
		t.Fatalf("根 su 给 admin 升 super 应 200，得到 %d %s", rec.Code, rec.Body.String())
	}
	// 自贬一律 400 且点名（先于 super 收口判定表态）
	rec = e.do(t, "POST", "/admin/users/"+strconv.FormatInt(superX.uid, 10)+"/role",
		`{"role":"admin"}`, superX.withCSRF)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "自己") {
		t.Errorf("自贬应 400 且点名，得到 %d %s", rec.Code, rec.Body.String())
	}
	// otherSuper 已是 super：根 su 重复授 super 幂等 200（不写不报错）
	rec = e.do(t, "POST", "/admin/users/"+strconv.FormatInt(otherSuper, 10)+"/role",
		`{"role":"super"}`, root.withCSRF)
	if rec.Code != http.StatusOK {
		t.Errorf("重复授 super 应幂等 200，得到 %d %s", rec.Code, rec.Body.String())
	}
	// target 降 admin（库里还有其它 super，允许）
	rec = e.do(t, "POST", "/admin/users/"+strconv.FormatInt(target, 10)+"/role",
		`{"role":"admin"}`, root.withCSRF)
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
	rec = e.do(t, "POST", "/admin/users/"+strconv.FormatInt(target, 10)+"/role",
		`{"role":"root"}`, root.withCSRF)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("非法 role 应 400，得到 %d", rec.Code)
	}
}

// 管理页门禁（M4 SPA 切流后页面层只剩门禁）：super 通行；app-admin 被 super 专属页
// 302 去会话总览；普通用户一律 302 去概览。（旧「服务端渲染切换器/越权 ?app= 403 页」
// 已随模板前端移除：数据端点的授权闸照旧现查，页面壳不含任何数据。）
func TestSwitcherRendering(t *testing.T) {
	e := newRouteEnv(t)
	superX := makeActor(t, e, "sw-super", "super", nil)
	oneApp := makeActor(t, e, "sw-one", "admin", []string{"calorie-diary"})

	if rec := e.do(t, "GET", "/web/admin", "", superX.cookieOnly); rec.Code != http.StatusOK {
		t.Errorf("super 打用户页应 200，得到 %d", rec.Code)
	}
	// app-admin：普通管理页 200，super 专属页（用户/配置）302 去会话总览
	if rec := e.do(t, "GET", "/web/admin/sessions", "", oneApp.cookieOnly); rec.Code != http.StatusOK {
		t.Errorf("app-admin 打会话总览应 200，得到 %d", rec.Code)
	}
	for _, path := range []string{"/web/admin", "/web/admin/config"} {
		rec := e.do(t, "GET", path, "", oneApp.cookieOnly)
		if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/web/admin/sessions" {
			t.Errorf("app-admin 访问 super 专属页 %s 应 302 去会话总览，得到 %d %q", path, rec.Code, rec.Header().Get("Location"))
		}
	}
	// 普通用户：管理页 302 去概览
	plain := makeActor(t, e, "sw-plain", "user", nil)
	rec := e.do(t, "GET", "/web/admin/sessions", "", plain.cookieOnly)
	if rec.Code != http.StatusFound || !strings.Contains(rec.Header().Get("Location"), "/web/console") {
		t.Errorf("普通用户访问管理页应 302 去概览，得到 %d %s", rec.Code, rec.Header().Get("Location"))
	}
}

// B5 路由级：管理员换邮 / 重置资料两个新端点 + 用户列表/详情的资料字段。
// 矩阵入口（403/404）在业务层用例里钉（TestAdminChangeEmailPermissions），这里只钉
// 路由挂载、回执形状与新字段的 JSON 名。
func TestAdminEmailAndProfileRoutes(t *testing.T) {
	e := newRouteEnv(t)
	superX := makeActor(t, e, "b5-route-super", "super", nil)
	oneApp := makeActor(t, e, "b5-route-one", "admin", []string{"calorie-diary"})

	target := seedUser(t, e, "b5-route-target@example.com", "secret123", "user")
	seedAppSession(t, e, "b5-route-target@example.com", "calorie-diary")
	// 种一行档案（昵称 + 色 + 头像），列表/详情回执都要带
	if _, err := e.pool.Exec(
		"INSERT INTO user_profile (user_id, nickname, avatar_color, avatar_image, updated_at) VALUES (?,?,?,?,?)",
		target, "路由测试昵称", 3, "YWJjZGVm", time.Now().UnixMilli()); err != nil {
		t.Fatalf("种档案行: %v", err)
	}

	// 换邮：super 成功 → {ok:true} 且库中邮箱已变、审计落行
	uid := strconv.FormatInt(target, 10)
	rec := e.do(t, "POST", "/admin/users/"+uid+"/email",
		`{"email":"b5-route-new@example.com","reason":"路由测试"}`, superX.withCSRF)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"ok":true`) {
		t.Fatalf("换邮应 200 {ok:true}，得到 %d %s", rec.Code, rec.Body.String())
	}
	var gotEmail string
	if err := e.pool.QueryRow("SELECT email FROM users WHERE id = ?", target).Scan(&gotEmail); err != nil ||
		gotEmail != "b5-route-new@example.com" {
		t.Errorf("库中邮箱应更新，得到 %q err=%v", gotEmail, err)
	}
	var auditN int
	_ = e.pool.QueryRow("SELECT COUNT(*) FROM audit_logs WHERE action = 'user.email_change' AND result = 'ok'").Scan(&auditN)
	if auditN == 0 {
		t.Error("换邮应落 user.email_change 审计")
	}
	// 未变化 → 400
	rec = e.do(t, "POST", "/admin/users/"+uid+"/email",
		`{"email":"b5-route-new@example.com"}`, superX.withCSRF)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("同邮箱应 400，得到 %d %s", rec.Code, rec.Body.String())
	}
	// app-admin 无会话目标 → 403（矩阵口径在路由层同样成立：这里目标有 calorie 会话，
	// 换成越界目标测 403；此处先验本目标放行）
	rec = e.do(t, "POST", "/admin/users/"+uid+"/email",
		`{"email":"b5-route-appadmin@example.com"}`, oneApp.withCSRF)
	if rec.Code != http.StatusOK {
		t.Errorf("有会话目标的 app-admin 换邮应 200，得到 %d %s", rec.Code, rec.Body.String())
	}

	// 重置资料：全否 → 400；头像+昵称 → 200 且档案回默认
	rec = e.do(t, "POST", "/admin/users/"+uid+"/profile-reset", `{}`, superX.withCSRF)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("全否应 400，得到 %d %s", rec.Code, rec.Body.String())
	}
	rec = e.do(t, "POST", "/admin/users/"+uid+"/profile-reset",
		`{"avatar":true,"nickname":true}`, superX.withCSRF)
	if rec.Code != http.StatusOK {
		t.Fatalf("重置资料应 200，得到 %d %s", rec.Code, rec.Body.String())
	}
	var nick string
	var color int
	var avatar sql.NullString
	// 重置按 UPDATE 语义走（清列不删行）：能查到行本身就是「行仍在」的断言
	if err := e.pool.QueryRow("SELECT nickname, avatar_color, avatar_image FROM user_profile WHERE user_id = ?",
		target).Scan(&nick, &color, &avatar); err != nil || nick != "" || color != 0 || avatar.Valid {
		t.Errorf("重置后档案应清空，得到 nick=%q color=%d avatar.Valid=%v err=%v", nick, color, avatar.Valid, err)
	}

	// 用户列表 / 详情的资料字段（B5 JSON 契约）
	// 重新种回档案（重置是 UPDATE 留行，行还在——只能 UPDATE 不能 INSERT 同 PK）
	if _, err := e.pool.Exec(
		"UPDATE user_profile SET nickname = ?, avatar_color = ?, avatar_image = ?, updated_at = ? WHERE user_id = ?",
		"路由测试昵称", 3, "YWJjZGVm", time.Now().UnixMilli(), target); err != nil {
		t.Fatalf("回种档案行: %v", err)
	}
	// 按当前邮箱检索（用例上文的管理员换邮已把该用户邮箱改成 b5-route-appadmin@…，
	// 旧邮箱片段查不到行）。列表/详情都带 nickname/avatarColor/hasAvatar，详情多带全量图。
	rec = e.do(t, "GET", "/admin/users?query=b5-route-appadmin", "", superX.cookieOnly)
	var upage struct {
		Items []struct {
			Nickname    string `json:"nickname"`
			AvatarColor int    `json:"avatarColor"`
			HasAvatar   bool   `json:"hasAvatar"`
		} `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &upage); err != nil || len(upage.Items) != 1 {
		t.Fatalf("用户列表解析: %v items=%d (%s)", err, len(upage.Items), rec.Body.String())
	}
	it := upage.Items[0]
	if it.Nickname != "路由测试昵称" || it.AvatarColor != 3 || !it.HasAvatar {
		t.Errorf("列表资料字段不对: %+v", it)
	}
	rec = e.do(t, "GET", "/admin/users/"+uid, "", superX.cookieOnly)
	var detail struct {
		Nickname    string `json:"nickname"`
		AvatarColor int    `json:"avatarColor"`
		HasAvatar   bool   `json:"hasAvatar"`
		AvatarImage string `json:"avatarImage"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &detail); err != nil {
		t.Fatalf("详情解析: %v (%s)", err, rec.Body.String())
	}
	if detail.Nickname != "路由测试昵称" || detail.AvatarColor != 3 || !detail.HasAvatar || detail.AvatarImage != "YWJjZGVm" {
		t.Errorf("详情资料字段不对: %+v", detail)
	}
}
