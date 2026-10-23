package ui

import (
	"strings"
	"testing"
)

// 静态资产清单与品牌 logo 注册（favicon 三件套 + /brand/* 逐名可取、类型正确）。
func TestStaticAssetRegistry(t *testing.T) {
	names := StaticNames()
	if len(names) != len(staticTypes) {
		t.Fatalf("StaticNames 应与清单同长，得到 %v", names)
	}
	for _, n := range names {
		if !strings.HasSuffix(n, ".ico") && !strings.HasSuffix(n, ".svg") && !strings.HasSuffix(n, ".png") {
			t.Errorf("意外的静态资产名 %q", n)
		}
	}
	if _, ctype, ok := Static("favicon.ico"); !ok || !strings.Contains(ctype, "image/x-icon") {
		t.Errorf("favicon.ico 应可取且类型正确，得到 ctype=%q ok=%v", ctype, ok)
	}
	if _, _, ok := Static("nope.xyz"); ok {
		t.Error("清单外的静态资产不该命中")
	}
	if len(brandFiles) == 0 {
		t.Fatal("品牌 logo 应已登记")
	}
	if _, ctype, ok := BrandStatic("auth-v1.png"); !ok || ctype != "image/png" {
		t.Errorf("auth-v1.png 应可取，得到 ctype=%q ok=%v", ctype, ok)
	}
	if _, _, ok := BrandStatic("../evil"); ok {
		t.Error("越界品牌名不该命中")
	}
}

// SPA 壳零外链（零外部依赖规矩）+ 关键结构齐备：viewport-fit、color-scheme、
// 同源脚本 /wasm/authweb.js、画布底色防白闪。
func TestSPAIndexNoExternalResourcesAndShape(t *testing.T) {
	html := SPAIndex("登录")
	for _, bad := range []string{"http://", "https://", "//cdn"} {
		if strings.Contains(html, bad) {
			t.Errorf("SPA 壳出现外链引用 %q", bad)
		}
	}
	for _, want := range []string{
		"<title>登录 · Auth</title",
		`name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover"`,
		`name="color-scheme" content="light dark"`,
		`src="/wasm/authweb.js"`,
		"background:#F7F7F7",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("SPA 壳缺 %q", want)
		}
	}
}

// wasm 产物已内嵌（占位 .keep 之外应有真文件；CI 跑过 gradle 后本地同理）。
// 零外链口径看**加载行为**：产物里不许出现外链资源加载（src/href 指向 http）；
// webpack 产物内的 kotl.in 帮助链接是错误提示文案里的惰性字符串，不产生请求。
func TestWasmAssetsEmbedded(t *testing.T) {
	data, ctype, cache, ok := WasmAsset("authweb.js")
	if !ok {
		// 本地没跑 gradle 时只有 .keep——跳过而非失败；CI 的 build-server.sh 必产真文件
		t.Skip("wasm 产物未嵌入（本地未跑 gradlew wasmJsBrowserDistribution）")
	}
	js := string(data)
	for _, bad := range []string{`src="http`, `src='http`, `href="http`} {
		if strings.Contains(js, bad) {
			t.Errorf("authweb.js 出现外链资源加载 %q（零外部依赖规矩）", bad)
		}
	}
	if ctype != "text/javascript; charset=utf-8" && ctype != "application/javascript" {
		t.Errorf("authweb.js 的 Content-Type 不对：%q", ctype)
	}
	if cache != "no-cache" {
		t.Errorf("authweb.js 应 no-cache，得到 %q", cache)
	}
	if _, _, _, ok := WasmAsset("../go.mod"); ok {
		t.Error("路径穿越名不该命中")
	}
}

// 项目注册表：两 app 齐全、定序稳定（slug→展示名唯一出口）。
func TestRegistry(t *testing.T) {
	reg := Registry()
	if len(reg) != 2 || reg[0].Key != "calorie-diary" || reg[1].Key != "expense-diary" {
		t.Fatalf("注册表应为两个日记 App 且定序稳定，得到 %+v", reg)
	}
	if AppLabel("calorie-diary") != "热量日记" || AppLabel("nope") != "nope" || AppLabel("") != "" {
		t.Error("AppLabel 的映射/回退口径不对")
	}
}

// 授权页双变体：确认页带 hidden tx + decision 双提交与回跳域名；错误页整卡替换
// 并指路控制台；注入内容 HTML 转义（防钓鱼文案注入）。
func TestAuthorizePageVariants(t *testing.T) {
	var b strings.Builder
	err := AuthorizePage(&b, OAuthView{
		Tx: "tx.abc", AppName: "热量日记", RedirectHost: "www.example.com", Email: "a@b.c",
	})
	if err != nil {
		t.Fatalf("渲染确认页: %v", err)
	}
	html := b.String()
	for _, want := range []string{
		`授权登录「热量日记」`, "a@b.c", "www.example.com",
		`name="tx" value="tx.abc"`, `value="allow"`, `value="deny"`, `/oauth/authorize/confirm`,
	} {
		if !strings.Contains(html, want) {
			t.Errorf("确认页缺 %q", want)
		}
	}

	b.Reset()
	if err := AuthorizePage(&b, OAuthView{ErrorTitle: "无法继续授权", ErrorMessage: "项目不在名单内"}); err != nil {
		t.Fatalf("渲染错误页: %v", err)
	}
	html = b.String()
	for _, want := range []string{"无法继续授权", "项目不在名单内", `/web/console`} {
		if !strings.Contains(html, want) {
			t.Errorf("错误页缺 %q", want)
		}
	}
	if strings.Contains(html, `name="tx"`) {
		t.Error("错误页不该出现确认表单")
	}

	b.Reset()
	if err := AuthorizePage(&b, OAuthView{AppName: `<script>alert(1)</script>`}); err != nil {
		t.Fatalf("渲染: %v", err)
	}
	if strings.Contains(b.String(), "<script>alert(1)</script>") {
		t.Error("AppName 注入未被转义")
	}
}
