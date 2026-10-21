package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"
	"testing"
)

// W3 头像真图端点（GET /admin/users/{uid}/avatar）的路由级用例（真库）：
// 无图 404、有图 200 + 嗅探 Content-Type + 弱缓存（max-age=300 + ETag）、
// 条件请求 304、字节原样、非管理员 403。
func TestAdminUserAvatarRoute(t *testing.T) {
	e := newRouteEnv(t)
	adm := makeActor(t, e, "avatar-admin", "super", nil)
	target := seedUser(t, e, "avatar-target@example.com", "secret123", "user")
	uid := strconv.FormatInt(target, 10)
	path := "/admin/users/" + uid + "/avatar"

	// 无图：404（前端 <img onerror> 据此回退色块+首字）
	if rec := e.do(t, "GET", path, "", adm.cookieOnly); rec.Code != http.StatusNotFound {
		t.Fatalf("无头像应回 404，得到 %d %s", rec.Code, rec.Body.String())
	}

	// 目标用户经真实档案链路（PUT /api/profile）落一张头像：
	// JPEG 前缀字节 + 文本体，够 DetectContentType 嗅出 image/jpeg
	jpeg := append([]byte{0xFF, 0xD8, 0xFF, 0xE0}, []byte("fake-jpeg-avatar-bytes")...)
	b64 := base64.StdEncoding.EncodeToString(jpeg)
	tgtSess, tgtCSRF := loginCookie(t, e, "avatar-target@example.com", "secret123")
	withTgt := func(r *http.Request) {
		r.AddCookie(tgtSess)
		r.AddCookie(tgtCSRF)
		r.Header.Set("X-CSRF-Token", tgtCSRF.Value)
	}
	rec := e.do(t, "PUT", "/api/profile",
		`{"nickname":"","avatarColor":0,"avatarImage":"`+b64+`"}`, withTgt)
	if rec.Code != http.StatusOK {
		t.Fatalf("落头像应 200，得到 %d %s", rec.Code, rec.Body.String())
	}

	// 管理员取图：200 + image/jpeg + 弱缓存 + ETag，字节原样
	rec = e.do(t, "GET", path, "", adm.cookieOnly)
	if rec.Code != http.StatusOK {
		t.Fatalf("有头像应 200，得到 %d %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "image/jpeg" {
		t.Errorf("Content-Type 应 image/jpeg（按字节嗅探），得到 %q", ct)
	}
	if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "max-age=300") {
		t.Errorf("应带弱缓存 max-age=300，得到 %q", cc)
	}
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("取图响应应带 X-Content-Type-Options: nosniff")
	}
	sum := sha256.Sum256(jpeg)
	wantETag := `"` + hex.EncodeToString(sum[:]) + `"`
	if got := rec.Header().Get("ETag"); got != wantETag {
		t.Errorf("ETag 应是 sha256(字节)，得到 %q 想要 %q", got, wantETag)
	}
	if string(rec.Body.Bytes()) != string(jpeg) {
		t.Error("回执字节应与档案头像解码结果一致")
	}

	// 条件请求：If-None-Match 命中回 304（无正文）
	rec304 := e.do(t, "GET", path, "", func(r *http.Request) {
		adm.cookieOnly(r)
		r.Header.Set("If-None-Match", wantETag)
	})
	if rec304.Code != http.StatusNotModified {
		t.Errorf("If-None-Match 命中应 304，得到 %d", rec304.Code)
	}
	if rec304.Body.Len() != 0 {
		t.Error("304 不该带正文")
	}

	// 非管理员拿不到（四道闸的 role 关）：403
	stranger := seedUser(t, e, "avatar-stranger@example.com", "secret123", "user")
	strSess, _ := loginCookie(t, e, "avatar-stranger@example.com", "secret123")
	if rec := e.do(t, "GET", "/admin/users/"+strconv.FormatInt(stranger, 10)+"/avatar", "",
		func(r *http.Request) { r.AddCookie(strSess) }); rec.Code != http.StatusForbidden {
		t.Errorf("普通用户应 403，得到 %d", rec.Code)
	}

	// 坏 uid：400（pathInt64 收口，不落库）
	if rec := e.do(t, "GET", "/admin/users/abc/avatar", "", adm.cookieOnly); rec.Code != http.StatusBadRequest {
		t.Errorf("非数字 uid 应 400，得到 %d", rec.Code)
	}
}
