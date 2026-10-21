package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/WXies-Team/auth/internal/protocol"
)

// doAI 打一个 /internal/ai/* 端点（环回来源 + 内部凭据头，与日记服务同款调用形态）。
func (e *routeEnv) doAI(t *testing.T, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	return e.do(t, "POST", path, body, func(r *http.Request) {
		r.RemoteAddr = "127.0.0.1:51234"
		r.Header.Set("X-Internal-Token", hookTokenForTest)
	})
}

// hookTokenForTest 与 newRouteEnv 种进 app_config 的 hook_token 对应（M3 的凭据闸）。
const hookTokenForTest = "route-test-hook-token"

// 种限额键：config.Store 有 10s 缓存，但每个 routeEnv 新建 Store，首轮读即取到。
func seedAIConfig(t *testing.T, e *routeEnv, kv map[string]string) {
	t.Helper()
	for k, v := range kv {
		if _, err := e.pool.Exec(
			"INSERT INTO app_config (`key`, `value`) VALUES (?,?) ON DUPLICATE KEY UPDATE `value` = VALUES(`value`)",
			k, v); err != nil {
			t.Fatalf("种限额键 %s: %v", k, err)
		}
	}
}

func aiCheck(t *testing.T, e *routeEnv, app string, uid int64) *httptest.ResponseRecorder {
	t.Helper()
	return e.doAI(t, "/internal/ai/check",
		`{"app":"`+app+`","uid":`+strconv.FormatInt(uid, 10)+`}`)
}

// 端到端主链路：check 占槽 → consume 入账回执 → release 归还；跨 App 合一。
func TestAIRouteCheckConsumeRelease(t *testing.T) {
	e := newRouteEnv(t)
	uid := int64(7654321)

	rec := aiCheck(t, e, "calorie-diary", uid)
	if rec.Code != http.StatusOK {
		t.Fatalf("check 应 200，得到 %d（%s）", rec.Code, rec.Body.String())
	}
	if got := keysOf(t, rec.Body.Bytes()); got != "ok" {
		t.Errorf("check 回执形状应恰为 ok，得到 %s", got)
	}

	// consume：入账 1（文字）→ 回执 dailyUser/dailyGlobal 即库内计数
	rec = e.doAI(t, "/internal/ai/consume", `{"app":"calorie-diary","uid":`+strconv.FormatInt(uid, 10)+`,"weight":1}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("consume 应 200，得到 %d（%s）", rec.Code, rec.Body.String())
	}
	var out protocol.AIConsumeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("consume 回执解析: %v", err)
	}
	if out.DailyUser != 1 || out.DailyGlobal != 1 {
		t.Errorf("首账回执应 1/1，得到 %d/%d", out.DailyUser, out.DailyGlobal)
	}
	// 跨 App 相加：同一 uid 在另一个 App 再记 2（图片折算）
	rec = e.doAI(t, "/internal/ai/consume", `{"app":"expense-diary","uid":`+strconv.FormatInt(uid, 10)+`,"weight":2}`)
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("consume 回执解析: %v", err)
	}
	if out.DailyUser != 3 || out.DailyGlobal != 3 {
		t.Errorf("跨 App 相加回执应 3/3，得到 %d/%d", out.DailyUser, out.DailyGlobal)
	}

	// release：幂等（再 release 一次也算成功）
	for i := 0; i < 2; i++ {
		rec = e.doAI(t, "/internal/ai/release", `{"app":"calorie-diary","uid":`+strconv.FormatInt(uid, 10)+`}`)
		if rec.Code != http.StatusOK {
			t.Fatalf("release 应 200 幂等，得到 %d（%s）", rec.Code, rec.Body.String())
		}
		if got := keysOf(t, rec.Body.Bytes()); got != "ok" {
			t.Errorf("release 回执形状应恰为 ok，得到 %s", got)
		}
	}

	// 看板一致性：consume 回执 == 看板查询的库内计数（同源同数）
	var userCount, globalCount int
	if err := e.pool.QueryRow("SELECT `count` FROM ai_usage WHERE scope='user' AND subject=? AND day=?",
		strconv.FormatInt(uid, 10), time.Now().Format("2006-01-02")).Scan(&userCount); err != nil {
		t.Fatalf("读个人计数: %v", err)
	}
	if err := e.pool.QueryRow("SELECT `count` FROM ai_usage WHERE scope='global' AND subject='' AND day=?",
		time.Now().Format("2006-01-02")).Scan(&globalCount); err != nil {
		t.Fatalf("读全站计数: %v", err)
	}
	if userCount != out.DailyUser || globalCount != out.DailyGlobal {
		t.Errorf("库内计数应与回执一致：%d/%d vs %d/%d", userCount, globalCount, out.DailyUser, out.DailyGlobal)
	}
	// 管理后台看板读同一张表同一口径：today=scope='user' 的当日合计，
	// 全站合计走 global 行（与 consume 回执同源同数）
	report, err := e.svc.AdminAIUsage(1, nil)
	if err != nil {
		t.Fatalf("查看板: %v", err)
	}
	if report.Today != userCount || report.Global == nil || report.Global.Used != globalCount {
		t.Errorf("看板今日个人/全站合计应 %d/%d，得到 today=%d global=%+v",
			userCount, globalCount, report.Today, report.Global)
	}
}

// 429 文案与 Retry-After 逐字沿用日记侧；并发按 uid 跨 App 合一。
func TestAIRouteConcurrencySharedAcrossApps(t *testing.T) {
	e := newRouteEnv(t)
	seedAIConfig(t, e, map[string]string{"ai_concurrency": "1"})
	uid := int64(7654001)

	if rec := aiCheck(t, e, "calorie-diary", uid); rec.Code != http.StatusOK {
		t.Fatalf("首槽应 200，得到 %d（%s）", rec.Code, rec.Body.String())
	}
	// 同 uid 换 App 也占同一个池（统一口径：跨 App 合一）
	rec := aiCheck(t, e, "expense-diary", uid)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("占满应 429，得到 %d（%s）", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Retry-After"); got != "30" {
		t.Errorf("并发拒应 Retry-After 30，得到 %s", got)
	}
	var apiErr protocol.ApiError
	if err := json.Unmarshal(rec.Body.Bytes(), &apiErr); err != nil {
		t.Fatalf("429 体解析: %v", err)
	}
	if apiErr.Message != "操作过于频繁，请稍后再试" {
		t.Errorf("并发拒文案应逐字沿用日记侧，得到 %q", apiErr.Message)
	}
	// release 后放行
	if rec := e.doAI(t, "/internal/ai/release", `{"app":"expense-diary","uid":`+strconv.FormatInt(uid, 10)+`}`); rec.Code != http.StatusOK {
		t.Fatalf("release 应 200，得到 %d", rec.Code)
	}
	if rec := aiCheck(t, e, "calorie-diary", uid); rec.Code != http.StatusOK {
		t.Errorf("释放后应放行，得到 %d（%s）", rec.Code, rec.Body.String())
	}
	// 另一个 uid 不受影响
	if rec := aiCheck(t, e, "calorie-diary", 7654002); rec.Code != http.StatusOK {
		t.Errorf("并发按 uid，他人不该被挤兑，得到 %d", rec.Code)
	}
}

// 速率闸按 uid 跨 App 合一，429 文案 Retry-After 30。
func TestAIRouteRateSharedAcrossApps(t *testing.T) {
	e := newRouteEnv(t)
	seedAIConfig(t, e, map[string]string{"ai_rate_per_minute": "2"})
	uid := int64(7654003)

	if rec := aiCheck(t, e, "calorie-diary", uid); rec.Code != http.StatusOK {
		t.Fatalf("第 1 次应 200，得到 %d", rec.Code)
	}
	if rec := aiCheck(t, e, "expense-diary", uid); rec.Code != http.StatusOK {
		t.Fatalf("第 2 次应 200（跨 App 共用同一桶），得到 %d", rec.Code)
	}
	rec := aiCheck(t, e, "calorie-diary", uid)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("第 3 次应 429，得到 %d（%s）", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Retry-After"); got != "30" {
		t.Errorf("速率拒应 Retry-After 30，得到 %s", got)
	}
	var apiErr protocol.ApiError
	_ = json.Unmarshal(rec.Body.Bytes(), &apiErr)
	if apiErr.Message != "操作过于频繁，请稍后再试" {
		t.Errorf("速率拒文案应逐字沿用日记侧，得到 %q", apiErr.Message)
	}
}

// 日额度两层在路由层的 429 文案与 Retry-After 3600。
func TestAIRouteDailyQuotaMessages(t *testing.T) {
	e := newRouteEnv(t)
	day := time.Now().Format("2006-01-02")

	// user 层达标
	if _, err := e.pool.Exec(
		"INSERT INTO ai_usage (scope, subject, day, `count`) VALUES ('user','7654004',?,500)", day); err != nil {
		t.Fatalf("造满额行: %v", err)
	}
	rec := aiCheck(t, e, "calorie-diary", 7654004)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("user 达标应 429，得到 %d（%s）", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Retry-After"); got != "3600" {
		t.Errorf("日额拒应 Retry-After 3600，得到 %s", got)
	}
	var apiErr protocol.ApiError
	_ = json.Unmarshal(rec.Body.Bytes(), &apiErr)
	if apiErr.Message != "今日识别次数已用完，明天再来" {
		t.Errorf("日额拒文案应逐字沿用日记侧，得到 %q", apiErr.Message)
	}

	// global 层达标（user 层未达）
	if _, err := e.pool.Exec(
		"INSERT INTO ai_usage (scope, subject, day, `count`) VALUES ('global','',?,5000)", day); err != nil {
		t.Fatalf("造满额 global 行: %v", err)
	}
	rec = aiCheck(t, e, "expense-diary", 7654005)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("global 达标应 429，得到 %d（%s）", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Retry-After"); got != "3600" {
		t.Errorf("全站拒应 Retry-After 3600，得到 %s", got)
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &apiErr)
	if apiErr.Message != "今日识别服务已达上限，请明天再试" {
		t.Errorf("全站拒文案应逐字沿用日记侧，得到 %q", apiErr.Message)
	}
}

// 入参闸：未知 app / uid 出号段 / weight<1 / 坏 JSON 都 400；非环回来源 403。
func TestAIRouteValidation(t *testing.T) {
	e := newRouteEnv(t)

	for _, tc := range []struct {
		name, path, body string
	}{
		{"未知 app", "/internal/ai/check", `{"app":"other-app","uid":7654321}`},
		{"uid 出号段", "/internal/ai/check", `{"app":"calorie-diary","uid":42}`},
		{"坏 JSON", "/internal/ai/check", `{"app":`},
		{"consume weight 0", "/internal/ai/consume", `{"app":"calorie-diary","uid":7654321,"weight":0}`},
		{"consume 未知 app", "/internal/ai/consume", `{"app":"x","uid":7654321,"weight":1}`},
		{"release 未知 app", "/internal/ai/release", `{"app":"x","uid":7654321}`},
	} {
		if rec := e.doAI(t, tc.path, tc.body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s 应 400，得到 %d（%s）", tc.name, rec.Code, rec.Body.String())
		}
	}
	// 非环回来源 403（loopbackOnly，与既有 /internal/* 同款）
	if rec := e.do(t, "POST", "/internal/ai/check", `{"app":"calorie-diary","uid":7654321}`, nil); rec.Code != http.StatusForbidden {
		t.Errorf("公网来源应 403，得到 %d", rec.Code)
	}
}

// M3：三端点强制 X-Internal-Token（hook_token）——带头对得上放行、错头 401、
// 缺头 401、键没配（空配置）恒 401 且不碰业务。
func TestAIRouteInternalTokenGate(t *testing.T) {
	const body = `{"app":"calorie-diary","uid":7654901}`
	e := newRouteEnv(t)

	// 带头且对得上 → 放行（真闸门路径，不是一路 401 的假绿）
	if rec := e.doAI(t, "/internal/ai/check", body); rec.Code != http.StatusOK {
		t.Fatalf("带头对得上应 200，得到 %d（%s）", rec.Code, rec.Body.String())
	}
	// 错头 → 401，且不进闸门（没占并发槽、没记账）
	wrong := func(r *http.Request) {
		r.RemoteAddr = "127.0.0.1:51234"
		r.Header.Set("X-Internal-Token", "not-the-hook-token")
	}
	if rec := e.do(t, "POST", "/internal/ai/check", body, wrong); rec.Code != http.StatusUnauthorized {
		t.Errorf("错头应 401，得到 %d（%s）", rec.Code, rec.Body.String())
	}
	// 缺头 → 401（三个端点都挂同一道闸）
	for _, path := range []string{"/internal/ai/check", "/internal/ai/consume", "/internal/ai/release"} {
		rec := e.do(t, "POST", path, body, func(r *http.Request) { r.RemoteAddr = "127.0.0.1:51234" })
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("缺头打 %s 应 401，得到 %d（%s）", path, rec.Code, rec.Body.String())
		}
	}
	var users int
	if err := e.pool.QueryRow("SELECT COUNT(*) FROM users WHERE id = 7654901").Scan(&users); err != nil || users != 0 {
		t.Errorf("401 不该碰业务行，得到 users=%d err=%v", users, err)
	}

	// 键没配 = 空配置恒 401（哪怕带头的内容恰好是空串也进不来）
	e2 := newRouteEnv(t)
	if _, err := e2.pool.Exec("DELETE FROM app_config WHERE `key` = 'hook_token'"); err != nil {
		t.Fatalf("删内部令牌键: %v", err)
	}
	if rec := e2.doAI(t, "/internal/ai/check", body); rec.Code != http.StatusUnauthorized {
		t.Errorf("空配置应恒 401，得到 %d（%s）", rec.Code, rec.Body.String())
	}
}
