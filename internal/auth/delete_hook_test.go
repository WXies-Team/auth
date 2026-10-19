package auth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// 注销的三道闸：密码错时**一个钩子都不打**；钩子失败时 auth 行一字不删；
// 钩子全成功（缺键的 App 视为跳过）才走既有删除事务。
func TestDeleteAccountGatedByHooks(t *testing.T) {
	svc, mailer := newTestService(t)
	reg := registerViaCode(t, svc, mailer, "hookdel@example.com", "secret123")
	caller, err := svc.ValidUserID("Bearer " + reg.Token)
	if err != nil {
		t.Fatalf("校验失败: %v", err)
	}

	var okSrv hookServer
	ok := httptest.NewServer(&okSrv)
	defer ok.Close()
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer bad.Close()

	users := func() int {
		var n int
		if err := svc.pool.QueryRow("SELECT COUNT(*) FROM users").Scan(&n); err != nil {
			t.Fatalf("数用户行: %v", err)
		}
		return n
	}

	// 1. 密码错 → 400，业务数据还在，钩子一次都不许打
	svc.hooks = NewHooks(lookupOf(map[string]string{
		HookTokenKey:         "tok",
		"hook_calorie_diary": ok.URL,
	}))
	if code, _ := httpMsg(svc.DeleteAccount(caller.UID, "wrong")); code != 400 {
		t.Errorf("密码错应 400，得到 %d", code)
	}
	if okSrv.count() != 0 {
		t.Errorf("密码错时不该调钩子（会误删用户在日记里的数据），得到 %d 次", okSrv.count())
	}
	if users() != 1 {
		t.Error("密码错不该删账号")
	}

	// 2. 钩子失败 → 503 中止，auth 行还在、会话仍然有效
	svc.hooks = NewHooks(lookupOf(map[string]string{
		HookTokenKey:         "tok",
		"hook_calorie_diary": bad.URL,
	}))
	err = svc.DeleteAccount(caller.UID, "secret123")
	if code, msg := httpMsg(err); code != 503 || !strings.Contains(msg, "稍后重试") {
		t.Errorf("钩子失败应中止并回 503，得到 %d %q", code, msg)
	}
	if users() != 1 {
		t.Error("钩子失败时 auth 行一个字都不能删")
	}
	if _, err := svc.ValidUserID("Bearer " + reg.Token); err != nil {
		t.Errorf("注销被中止后会话应保持有效: %v", err)
	}

	// 3. 钩子成功（expense 键缺失 → 跳过）→ 账号与验证码记录都删掉
	svc.hooks = NewHooks(lookupOf(map[string]string{
		HookTokenKey:         "tok",
		"hook_calorie_diary": ok.URL,
	}))
	if err := svc.DeleteAccount(caller.UID, "secret123"); err != nil {
		t.Fatalf("钩子通过后注销应成功: %v", err)
	}
	if okSrv.count() != 1 {
		t.Errorf("只有第 3 步真正打了钩子，得到 %d 次", okSrv.count())
	}
	if users() != 0 {
		t.Error("注销成功后账号应被删除")
	}
	if _, err := svc.ValidUserID("Bearer " + reg.Token); err == nil {
		t.Error("注销后原 token 应失效")
	}
}
