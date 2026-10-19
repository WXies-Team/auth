package auth

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// hookServer 是日记侧 /internal/delete-user 的替身：记住收到的请求并按需回指定状态码。
type hookServer struct {
	mu     sync.Mutex
	hits   int
	bearer string
	path   string
	method string
	body   string
}

func (h *hookServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	h.mu.Lock()
	h.hits++
	h.bearer = r.Header.Get("Authorization")
	h.path = r.URL.Path
	h.method = r.Method
	h.body = string(body)
	h.mu.Unlock()
	w.WriteHeader(http.StatusOK)
}

// snapshot 取一份无锁的观察结果（hookServer 含互斥锁，整结构拷贝会被 vet 拦下）。
func (h *hookServer) snapshot() (hits int, method, path, bearer, body string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.hits, h.method, h.path, h.bearer, h.body
}

func (h *hookServer) count() int {
	hits, _, _, _, _ := h.snapshot()
	return hits
}

// lookupOf 把键值表适配成 ConfigFunc（测试里的 app_config）。
func lookupOf(kv map[string]string) ConfigFunc {
	return func(k string) (string, error) { return kv[k], nil }
}

// 三态之一：两个 App 都配了地址 → 逐个调用、Bearer 与 uid 都要对，整体放行。
func TestHooksSuccessCallsEveryApp(t *testing.T) {
	var calorie, expense hookServer
	cal := httptest.NewServer(&calorie)
	defer cal.Close()
	exp := httptest.NewServer(&expense)
	defer exp.Close()

	h := NewHooks(lookupOf(map[string]string{
		HookTokenKey:         "shared-secret",
		"hook_calorie_diary": cal.URL + "/internal/delete-user",
		"hook_expense_diary": exp.URL + "/internal/delete-user",
	}))
	const uid = int64(123456789012345678)
	if err := h.BeforeDelete(uid, "u@example.com"); err != nil {
		t.Fatalf("两个钩子都成功应放行，得到 %v", err)
	}
	for name, srv := range map[string]*hookServer{"calorie": &calorie, "expense": &expense} {
		hits, method, path, bearer, body := srv.snapshot()
		if hits != 1 {
			t.Errorf("%s 应被调用 1 次，得到 %d 次", name, hits)
		}
		if method != http.MethodPost || path != "/internal/delete-user" {
			t.Errorf("%s 请求形状不对: %s %s", name, method, path)
		}
		if bearer != "Bearer shared-secret" {
			t.Errorf("%s Bearer 错误: %q", name, bearer)
		}
		// uid 是 63 位雪花整数：进 body 必须还是整数文本，过一遍 float64 就花位了
		if body != `{"uid":123456789012345678}` {
			t.Errorf("%s body 错误: %s", name, body)
		}
	}
}

// 三态之二：键缺失 → 跳过该 App（不打网络、不报错）——测试与开发态就是这个形态。
func TestHooksMissingKeySkips(t *testing.T) {
	// 一个 App 配地址、另一个键不存在：配了的照调，没配的静默跳过
	var calorie hookServer
	cal := httptest.NewServer(&calorie)
	defer cal.Close()

	h := NewHooks(lookupOf(map[string]string{
		HookTokenKey:         "shared-secret",
		"hook_calorie_diary": cal.URL,
		// hook_expense_diary 缺键
	}))
	if err := h.BeforeDelete(42, "u@example.com"); err != nil {
		t.Fatalf("缺键应跳过而不是报错，得到 %v", err)
	}
	if calorie.count() != 1 {
		t.Errorf("配了地址的 App 应被调用，得到 %d 次", calorie.count())
	}

	// 三个键全缺：注销照样放行（auth 侧自己删自己的）
	empty := NewHooks(lookupOf(map[string]string{}))
	if err := empty.BeforeDelete(42, "u@example.com"); err != nil {
		t.Errorf("三键全缺应放行，得到 %v", err)
	}
}

// 三态之三：键存在但调用失败 → 整个注销中止（503），后续 App 不再被调。
func TestHooksFailureAborts(t *testing.T) {
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer bad.Close()

	// 第一个 App 就失败，第二个只该被跳过（中止 = 不再往下调）
	var expense hookServer
	exp := httptest.NewServer(&expense)
	defer exp.Close()

	h := NewHooks(lookupOf(map[string]string{
		HookTokenKey:         "shared-secret",
		"hook_calorie_diary": bad.URL,
		"hook_expense_diary": exp.URL,
	}))
	err := h.BeforeDelete(7, "u@example.com")
	if code, msg := httpMsg(err); code != 503 || !strings.Contains(msg, "稍后重试") {
		t.Errorf("钩子非 200 应中止并回 503「…稍后重试」，得到 %d %q", code, msg)
	}
	if expense.count() != 0 {
		t.Errorf("前一个 App 已失败，后续钩子不该再调，得到 %d 次", expense.count())
	}

	// 连接错（地址指着一个没人听的端口）同样是中止
	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	deadURL := dead.URL
	dead.Close()
	h = NewHooks(lookupOf(map[string]string{
		HookTokenKey:         "shared-secret",
		"hook_calorie_diary": deadURL,
	}))
	if code, _ := httpMsg(h.BeforeDelete(7, "u@example.com")); code != 503 {
		t.Errorf("连接错应中止并回 503，得到 %d", code)
	}

	// 读配置键的数据库错误也不能当成「没配」跳过——那会造孤儿数据
	failing := NewHooks(func(string) (string, error) { return "", errDBBoom })
	if code, _ := httpMsg(failing.BeforeDelete(7, "u@example.com")); code != 503 {
		t.Errorf("读键失败应回 503 中止，得到 %d", code)
	}
}

var errDBBoom = &HTTPError{503, "服务暂时不可用，请稍后重试"}
