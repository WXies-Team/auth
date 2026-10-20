package main

// favicon 三件套与根路径重定向的挂载用例。**不碰数据库**——无 TEST_MYSQL_DSN 的
// CI 也照常跑（与真库路由用例分文件，避免整组被 Skip）。

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func staticDo(t *testing.T, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	mux := http.NewServeMux()
	registerStaticRoutes(mux)
	mux.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
	return rec
}

// 三件套各自的 Content-Type 与魔数：路由挂上了、字节随二进制在、类型不冒名。
func TestStaticAssetsServed(t *testing.T) {
	cases := []struct {
		path, ctype string
		magic       []byte
	}{
		{"/favicon.ico", "image/x-icon", []byte{0x00, 0x00, 0x01, 0x00}}, // ICO 常驻头
		{"/favicon.svg", "image/svg+xml; charset=utf-8", []byte("<svg")},
		{"/apple-touch-icon.png", "image/png", []byte("\x89PNG\r\n\x1a\n")},
	}
	for _, c := range cases {
		rec := staticDo(t, c.path)
		if rec.Code != http.StatusOK {
			t.Errorf("GET %s 应 200，得到 %d", c.path, rec.Code)
			continue
		}
		if got := rec.Header().Get("Content-Type"); got != c.ctype {
			t.Errorf("%s Content-Type 应为 %q，得到 %q", c.path, c.ctype, got)
		}
		if !bytes.HasPrefix(rec.Body.Bytes(), c.magic) {
			t.Errorf("%s 的字节不是预期格式，开头 %q", c.path, rec.Body.Bytes())
		}
		if !strings.Contains(rec.Header().Get("Cache-Control"), "max-age=") {
			t.Errorf("%s 应带长缓存头，得到 %q", c.path, rec.Header().Get("Cache-Control"))
		}
		if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s 缺 nosniff 头", c.path)
		}
	}
	// 名单外的静态名不冒充资产
	if rec := staticDo(t, "/favicon.png"); rec.Code != http.StatusNotFound {
		t.Errorf("未登记的静态名应 404，得到 %d", rec.Code)
	}
}

// 根路径 302 → /web/login（现状 404）；但**不做全站兜底**——打错的 API 路径仍 404。
func TestRootRedirectsToLogin(t *testing.T) {
	rec := staticDo(t, "/")
	if rec.Code != http.StatusFound {
		t.Fatalf("GET / 应 302，得到 %d（%s）", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); loc != "/web/login" {
		t.Errorf("GET / 应跳 /web/login，得到 %q", loc)
	}
	if rec := staticDo(t, "/api/nope"); rec.Code != http.StatusNotFound {
		t.Errorf("打错的 API 路径必须 404（不能被 / 的重定向吞掉），得到 %d", rec.Code)
	}
	if rec := staticDo(t, "/web/login/"); rec.Code != http.StatusNotFound {
		t.Errorf("/web/login/ 这类未登记路径应 404，得到 %d", rec.Code)
	}
}
