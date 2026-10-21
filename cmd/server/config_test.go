package main

// /internal/config 的路由级用例（真库）：凭据闸三态、白名单 400、缺键省略、值与库一致。
// 防护口径与 /internal/ai/* 逐字相同（loopbackOnly + X-Internal-Token），所以断言也同构。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// configDispatchKeys 是端点认的四个 app_config 键，顺序即回执键名排序后的顺序
//（keysOf 按字典序拼）：llmApiKey, llmBaseUrl, llmModel, pushAdminToken ——
// 改契约必须同时改这里与 handler。FCM 两键已退出本端点（见 config.go 头注释）。
const configAllKeys = "llmApiKey,llmBaseUrl,llmModel,pushAdminToken"

// seedConfigKeys 种 app_config（与 seedAIConfig 同款 upsert；config.Store 每个
// routeEnv 新建，首轮读才填缓存，种在请求之前就一定读得到）。
func seedConfigKeys(t *testing.T, e *routeEnv, kv map[string]string) {
	t.Helper()
	for k, v := range kv {
		if _, err := e.pool.Exec(
			"INSERT INTO app_config (`key`, `value`) VALUES (?,?) ON DUPLICATE KEY UPDATE `value` = VALUES(`value`)",
			k, v); err != nil {
			t.Fatalf("种配置键 %s: %v", k, err)
		}
	}
}

// doConfig 打一次 POST /internal/config（默认环回 + 正确的 X-Internal-Token）。
func doConfig(t *testing.T, e *routeEnv, body string, mutate func(*http.Request)) *httptest.ResponseRecorder {
	t.Helper()
	return e.do(t, "POST", "/internal/config", body, func(r *http.Request) {
		r.RemoteAddr = "127.0.0.1:51234"
		r.Header.Set("X-Internal-Token", hookTokenForTest)
		if mutate != nil {
			mutate(r)
		}
	})
}

// 凭据闸三态（带头 / 错头 / 缺头）+ 环回守卫 + 键没配恒 401。
func TestInternalConfigRouteGate(t *testing.T) {
	e := newRouteEnv(t)

	// 带头且对得上 → 放行（库里一个配置键都没种，回执是空对象但状态码 200）
	rec := doConfig(t, e, `{"app":"calorie-diary"}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("带头对得上应 200，得到 %d（%s）", rec.Code, rec.Body.String())
	}
	if got := rec.Body.String(); got != "{}\n" && got != "{}" {
		t.Errorf("四个键全缺时应回空对象，得到 %s", rec.Body.String())
	}

	// 错头 → 401
	rec = doConfig(t, e, `{"app":"calorie-diary"}`, func(r *http.Request) {
		r.Header.Set("X-Internal-Token", "not-the-hook-token")
	})
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("错头应 401，得到 %d（%s）", rec.Code, rec.Body.String())
	}

	// 缺头 → 401
	rec = doConfig(t, e, `{"app":"calorie-diary"}`, func(r *http.Request) {
		r.Header.Del("X-Internal-Token")
	})
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("缺头应 401，得到 %d（%s）", rec.Code, rec.Body.String())
	}

	// 环回守卫在最外层：公网来源带着对的 token 也 403
	rec = doConfig(t, e, `{"app":"calorie-diary"}`, func(r *http.Request) {
		r.RemoteAddr = "203.0.113.9:41234"
	})
	if rec.Code != http.StatusForbidden {
		t.Errorf("非环回来源应 403，得到 %d（%s）", rec.Code, rec.Body.String())
	}

	// hook_token 键没配 = 空配置恒 401（哪怕带头内容恰好是空串也进不来）
	e2 := newRouteEnv(t)
	if _, err := e2.pool.Exec("DELETE FROM app_config WHERE `key` = 'hook_token'"); err != nil {
		t.Fatalf("删内部令牌键: %v", err)
	}
	rec = doConfig(t, e2, `{"app":"calorie-diary"}`, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("空配置应恒 401，得到 %d（%s）", rec.Code, rec.Body.String())
	}
}

// 白名单外的 app（含缺省空串）一律 400：借不到别家的 LLM key 与推送令牌。
func TestInternalConfigRejectsUnknownApp(t *testing.T) {
	e := newRouteEnv(t)
	seedConfigKeys(t, e, map[string]string{"llm_api_key": "sk-should-not-leak"})
	for _, body := range []string{
		`{"app":"evil-app"}`,
		`{}`,
		`{"app":""}`,
		`{"app":"admin"}`,
	} {
		rec := doConfig(t, e, body, nil)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("body=%s 应 400，得到 %d（%s）", body, rec.Code, rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), "sk-should-not-leak") {
			t.Errorf("400 不该带任何配置值: %s", rec.Body.String())
		}
	}
}

// 缺键省略：只有两个键在库里，回执就只有那两个字段——字段整体缺席，不是空串。
func TestInternalConfigOmitsMissingKeys(t *testing.T) {
	e := newRouteEnv(t)
	seedConfigKeys(t, e, map[string]string{
		"llm_model":        "gpt-x",
		"push_admin_token": "push-tok-1",
		// llm_api_key / llm_base_url 故意不种
	})
	rec := doConfig(t, e, `{"app":"expense-diary"}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("应 200，得到 %d（%s）", rec.Code, rec.Body.String())
	}
	if got := keysOf(t, rec.Body.Bytes()); got != "llmModel,pushAdminToken" {
		t.Errorf("缺键应整字段省略，回执形状应为 llmModel,pushAdminToken，得到 %s（%s）",
			got, rec.Body.String())
	}
	var resp map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("回执不是 JSON 对象: %v", err)
	}
	if resp["llmModel"] != "gpt-x" || resp["pushAdminToken"] != "push-tok-1" {
		t.Errorf("有键就该原样回值，得到 %v", resp)
	}
}

// 值与库一致：四个键全种，回执逐键等于 **app_config 里的原值**（现读口径，
// 不做任何改写/裁剪/脱敏——这个端点本来就是给同机调用方分发凭据的）。
func TestInternalConfigValuesMatchDB(t *testing.T) {
	e := newRouteEnv(t)
	want := map[string]string{
		"llm_api_key":      "llm-key-abc",
		"llm_base_url":     "https://llm.example.com/v1",
		"llm_model":        "model-x",
		"push_admin_token": "push-secret-7",
	}
	seedConfigKeys(t, e, want)

	rec := doConfig(t, e, `{"app":"calorie-diary"}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("应 200，得到 %d（%s）", rec.Code, rec.Body.String())
	}
	if got := keysOf(t, rec.Body.Bytes()); got != configAllKeys {
		t.Errorf("四个键齐全时回执形状应为 %s，得到 %s", configAllKeys, got)
	}
	var resp map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("回执不是 JSON 对象: %v", err)
	}
	// 逐键回读库，回执与**库里的字节**逐字相等（不拿 seedMap 当真值，
	// 这样 upsert 走样、列被截断都会被抓到）
	for k, seeded := range want {
		var inDB string
		if err := e.pool.QueryRow("SELECT `value` FROM app_config WHERE `key` = ?", k).Scan(&inDB); err != nil {
			t.Fatalf("回读 %s: %v", k, err)
		}
		if inDB != seeded {
			t.Fatalf("测试前置走样：%s 库里是 %q，seed 是 %q", k, inDB, seeded)
		}
		field, ok := jsonKeyFor(k)
		if !ok {
			t.Fatalf("键 %s 没有对应的回执字段", k)
		}
		if resp[field] != inDB {
			t.Errorf("%s：回执 %q != 库 %q", field, resp[field], inDB)
		}
	}
}

// jsonKeyFor 把 app_config 键映射到回执字段名（与 handler 一一对应）。
func jsonKeyFor(key string) (string, bool) {
	m := map[string]string{
		"llm_api_key":      "llmApiKey",
		"llm_base_url":     "llmBaseUrl",
		"llm_model":        "llmModel",
		"push_admin_token": "pushAdminToken",
	}
	v, ok := m[key]
	return v, ok
}
