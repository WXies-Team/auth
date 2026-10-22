package main

// UA Client Hints 采集的路由层用例。**不碰数据库**——无 TEST_MYSQL_DSN 的 CI 也
// 照常跑（建会话链的真库断言另在 routes_test.go 的 TestWebLoginStoresClientHintSuffix）。
//
// 采集链：/web 页面响应带 Accept-CH（internal/ui.Render 收口）→ 浏览器在本站
// 后续请求自动带上 Sec-CH-UA-Platform / Sec-CH-UA-Model → web 登录路的
// webSessMeta 读头进 SessionMeta → 建会话时并进 user_agent（auth.uaWithCH）。

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/WXies-Team/auth/internal/auth"
)

// webSessMeta 从请求头取 Client Hints 两头（原头值不清——清理在 auth.uaWithCH，
// 业务层收什么由业务层定）；缺席 = 空串：Firefox/Safari 不发 CH、或浏览器还没过
// Accept-CH opt-in，存储串因此不加后缀、设备名回退 UA 解析，零回归。
func TestWebSessMetaReadsClientHintHeaders(t *testing.T) {
	req := httptest.NewRequest("POST", "/web/login/password", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Linux; Android 10; K) Chrome/120 Mobile Safari/537.36")
	req.Header.Set("Sec-CH-UA-Platform", `"Android"`)
	req.Header.Set("Sec-CH-UA-Model", `"Pixel 5"`)
	m := webSessMeta(req)
	if m.CHPlatform != `"Android"` || m.CHModel != `"Pixel 5"` {
		t.Errorf("webSessMeta 应原头取回 CH 两头，得到 %q / %q", m.CHPlatform, m.CHModel)
	}
	if !strings.Contains(m.UserAgent, "Chrome/120") {
		t.Errorf("UA 应照 sessMeta 口径取原文，得到 %q", m.UserAgent)
	}
	// 无 CH 头 → 空串（零回归）
	empty := webSessMeta(httptest.NewRequest("POST", "/web/login/password", nil))
	if empty.CHPlatform != "" || empty.CHModel != "" {
		t.Errorf("无 CH 头应得空串，得到 %q / %q", empty.CHPlatform, empty.CHModel)
	}
	// sessMeta（App 端点 /auth/* 与审计走它）不填 CH——App UA 不受影响
	app := sessMeta(httptest.NewRequest("POST", "/auth/login", nil))
	if app.CHPlatform != "" || app.CHModel != "" {
		t.Errorf("sessMeta 不该填 CH 字段，得到 %q / %q", app.CHPlatform, app.CHModel)
	}
}

// /web 页面响应带 Accept-CH opt-in：零值 Service 装配页面路由（gatePublic 页无
// cookie 即渲染，不碰库），GET /web/login 打在真 handler 上断言响应头。
func TestWebPagesOptIntoClientHints(t *testing.T) {
	mux := http.NewServeMux()
	registerPageRoutes(mux, &auth.Service{})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("GET", "/web/login", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /web/login 应 200，得到 %d", rec.Code)
	}
	if got := rec.Header().Get("Accept-CH"); got != "Sec-CH-UA-Platform, Sec-CH-UA-Model" {
		t.Errorf("/web/login 响应应带 Accept-CH: Sec-CH-UA-Platform, Sec-CH-UA-Model，得到 %q", got)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Errorf("登录页应是 HTML 响应，Content-Type 得到 %q", ct)
	}
}
