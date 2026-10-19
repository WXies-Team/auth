package auth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"
)

// ConfigFunc 读一个 app_config 键：键不存在或值为空返回 ("", nil)，
// 真错误返回 err——对应 [config.Store.Require] 的口径，测试里用假实现注入。
type ConfigFunc func(key string) (string, error)

// HookTokenKey 是注销钩子与 /internal/users/ensure 共用的 bearer 配置键
// （路由层鉴权也要读它，故导出）；两个日记侧的钩子端点用同一个值校验请求头。
const HookTokenKey = "hook_token"

// 注销钩子的两个 App 键：值是该 App 的 /internal/delete-user 地址。键名用下划线
// （app_config 的既有习惯），与 JWT aud 的连字符写法（calorie-diary）不是一回事，
// 所以逐个列全、不做字符串替换。
var hookApps = []struct {
	app string
	key string
}{
	{"calorie-diary", "hook_calorie_diary"},
	{"expense-diary", "hook_expense_diary"},
}

// hookTimeout 是单个钩子端点的调用上限。注销请求的 WriteTimeout 是 60 秒，
// 两个 App 各 5 秒仍在预算内；不设超时的话对端挂起不响应会把注销拖到服务端超时。
const hookTimeout = 5 * time.Second

// Hooks 在注销账号前调用各日记服务的 /internal/delete-user，让业务数据由业务方自己清。
type Hooks struct {
	require ConfigFunc
	client  *http.Client
}

// NewHooks 用 app_config 读取器构造钩子集合；client 超时固定 hookTimeout。
func NewHooks(require ConfigFunc) *Hooks {
	return &Hooks{
		require: require,
		client: &http.Client{
			Timeout: hookTimeout,
			// 30x 不跟随：钩子端点回重定向说明配错了地址，跟着跳可能把 Bearer
			// 带去别的主机，按「非 200 即失败」处理更安全
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

// BeforeDelete 按配置逐个调用日记服务的注销钩子，全部成功才放行 auth 侧的删除。
//
//   - **键不存在/值为空 → 跳过该 App 并 Warn**：测试与开发态不配钩子，
//     注销只清本服务自己的数据（既有测试正是这个形态）；
//   - **键存在但调用失败（连接错、超时、非 200）→ 整个注销中止**，回 503 让用户
//     稍后重试：反过来先删 auth 行，业务侧就再没有机会按 uid 找到这些数据了；
//   - 读键时的数据库错误也按中止处理——读失败不等于「没配」，把抖动当成跳过
//     同样会造孤儿数据。
//
// 每个 App 一条结果日志（uid + app + 状态码，邮箱脱敏），逐个调用、逐个记。
func (h *Hooks) BeforeDelete(uid int64, email string) error {
	token, err := h.require(HookTokenKey)
	if err != nil {
		return fmt.Errorf("读 %s: %w", HookTokenKey, err)
	}
	for _, app := range hookApps {
		url, err := h.require(app.key)
		if err != nil {
			return fmt.Errorf("读 %s: %w", app.key, err)
		}
		if url == "" {
			slog.Warn("注销钩子未配置，跳过该 App 的业务数据清理", "app", app.app, "uid", uid)
			continue
		}
		// status 为 0 表示对端没给响应（连接错/超时），错误串里带着根因
		status, err := h.post(url, token, uid)
		if err != nil {
			slog.Error("注销钩子调用失败，注销中止", "uid", uid, "app", app.app,
				"status", status, "email", maskEmail(email), "err", err)
			return &HTTPError{503, "注销失败，请稍后重试"}
		}
		slog.Info("注销钩子已调用", "uid", uid, "app", app.app,
			"status", status, "email", maskEmail(email))
	}
	return nil
}

// post 往一个钩子端点发 {"uid":<users.id>}，200 即成功——端点幂等（删 0 行也算成功），
// 所以不解析响应体，对端回了什么都不影响判定。
func (h *Hooks) post(url, token string, uid int64) (int, error) {
	body, err := json.Marshal(struct {
		UID int64 `json:"uid"`
	}{UID: uid})
	if err != nil {
		return 0, fmt.Errorf("编码 uid: %w", err)
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return 0, fmt.Errorf("构造请求: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := h.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	// 读掉一点响应体才好复用连接；钩子只回小 JSON，读 4KB 足够
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, fmt.Errorf("对端回 %d", resp.StatusCode)
	}
	return resp.StatusCode, nil
}
