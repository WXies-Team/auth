package ui

import (
	"regexp"
	"strings"
	"testing"
)

// 所有页面共用 layout 骨架：<head> 必须带三件套 link 与 theme-color，
// 顶栏品牌区挂 favicon.svg（透明底 + #3482FF 裸蓝 fingerprint，与站点 favicon 同源）。
func TestLayoutHeadHasIconLinks(t *testing.T) {
	raw, err := files.ReadFile("templates/layout.html")
	if err != nil {
		t.Fatalf("读页面骨架: %v", err)
	}
	head := string(raw)
	for _, want := range []string{
		`<link rel="icon" href="/favicon.svg" type="image/svg+xml">`,
		`<link rel="icon" href="/favicon.ico" sizes="48x48">`,
		`<link rel="apple-touch-icon" href="/apple-touch-icon.png">`,
		`<meta name="theme-color" content="#3482FF">`,
		`<img src="/favicon.svg" alt="" width="24" height="24">`,
	} {
		if !strings.Contains(head, want) {
			t.Errorf("layout <head> 缺 %s", want)
		}
	}
	// 装饰性图片 alt 必须为空串：紧随其后的品牌名文字才是给读屏的
	if !strings.Contains(head, `class="brand-mark" aria-hidden="true"><img src="/favicon.svg" alt=""`) {
		t.Error("顶栏品牌图标应是 aria-hidden 包裹的空 alt 装饰图")
	}
}

// 静态资产清单三件齐全、可按名取到，且 Content-Type 不缺。
func TestStaticAssetRegistry(t *testing.T) {
	want := []string{"apple-touch-icon.png", "favicon.ico", "favicon.svg"}
	got := StaticNames()
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("静态清单应为 %v（定序），得到 %v", want, got)
	}
	for _, name := range want {
		data, ctype, ok := Static(name)
		if !ok {
			t.Errorf("Static(%q) 未命中", name)
			continue
		}
		if len(data) == 0 || ctype == "" {
			t.Errorf("Static(%q) 内容或类型为空", name)
		}
	}
	if _, _, ok := Static("nope.png"); ok {
		t.Error("名单外的静态名不该命中")
	}
}

// 页面模板一个不缺：路由层登记了 11 个页面，模板缺一个就启动即炸（ui.go 的
// Has 会被 cmd/server 逐个查），这里在包内先钉住数量与关键页。
func TestPageTemplatesPresent(t *testing.T) {
	for _, name := range []string{"login", "console", "admin-config", "admin-ai"} {
		if !Has(name) {
			t.Errorf("页面模板缺失: %s", name)
		}
	}
	if Has("not-a-page") {
		t.Error("未知页名不该命中")
	}
}

// cssRule 取一条以行首选择器开头的规则体（含大括号）。要求行首是为了不被
// `.btn .ico` 这类更长的选择器抢匹配。
func cssRule(css, selector string) (string, bool) {
	i := strings.Index(css, "\n"+selector+" ")
	if i < 0 {
		return "", false
	}
	open := strings.Index(css[i:], "{")
	if open < 0 {
		return "", false
	}
	start := i + open
	end := strings.Index(css[start:], "}")
	if end < 0 {
		return "", false
	}
	return css[start : start+end], true
}

// 品牌区两处（顶栏 `.brand` 与登录页 `.brand-lg`）**同源同款 = favicon.svg 的裸蓝
// 矢量**；全站不得残留任何带底的 logo 图；图标与文字的垂直居中要有双保险
//（flex 的 align-items:center 是主保险，inline 盒子的 vertical-align:middle 是兜底）。
func TestBrandMarksShareFaviconAndCenter(t *testing.T) {
	// 1. 两处品牌区都用同一个 favicon.svg
	for _, tpl := range []string{"templates/layout.html", "templates/login.html"} {
		raw, err := files.ReadFile(tpl)
		if err != nil {
			t.Fatalf("读 %s: %v", tpl, err)
		}
		if !strings.Contains(string(raw), `src="/favicon.svg"`) {
			t.Errorf("%s 的品牌区应引用 /favicon.svg（与站点 favicon 同源），实际没有", tpl)
		}
	}

	// 2. 全模板扫 <img>：src 只允许 /favicon.svg（二维码那张是运行时注入、本身无 src）
	entries, err := files.ReadDir("templates")
	if err != nil {
		t.Fatalf("列模板: %v", err)
	}
	imgTag := regexp.MustCompile(`<img\b[^>]*>`)
	imgSrc := regexp.MustCompile(`\bsrc="([^"]*)"`)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".html") {
			continue
		}
		raw, err := files.ReadFile("templates/" + e.Name())
		if err != nil {
			t.Fatalf("读 %s: %v", e.Name(), err)
		}
		for _, tag := range imgTag.FindAllString(string(raw), -1) {
			m := imgSrc.FindStringSubmatch(tag)
			if m == nil {
				continue // 运行时才补 src（二维码）
			}
			if m[1] != "/favicon.svg" {
				t.Errorf("%s 里有非 favicon 的图片引用 %q——品牌图必须统一成裸蓝矢量，不许带底",
					e.Name(), m[1])
			}
		}
	}

	// 3. 样式：双保险齐备
	cssBytes, err := files.ReadFile("style.css")
	if err != nil {
		t.Fatalf("读 style.css: %v", err)
	}
	css := string(cssBytes)
	if strings.Contains(css, "background-image") {
		t.Error("style.css 不该有 background-image（品牌图标走 <img>，不用底图）")
	}
	for _, want := range []struct{ selector, frag string }{
		{".brand", "align-items: center"},
		{".brand", "vertical-align: middle"},
		{".brand-mark", "align-items: center"},
		{".brand-mark", "vertical-align: middle"},
		{".ico", "vertical-align: middle"},
		{".brand-lg", "align-items: center"},
		{".brand-lg", "justify-content: center"},
	} {
		rule, ok := cssRule(css, want.selector)
		if !ok {
			t.Errorf("style.css 缺规则 %s", want.selector)
			continue
		}
		if !strings.Contains(rule, want.frag) {
			t.Errorf("%s 规则缺 %q（图标与文字垂直居中的保险）：\n%s", want.selector, want.frag, rule)
		}
	}
	// 品牌图标必须是显式尺寸的 <img>，加载前不抖版面
	layout, _ := files.ReadFile("templates/layout.html")
	if !strings.Contains(string(layout), `<img src="/favicon.svg" alt="" width="24" height="24">`) {
		t.Error("顶栏品牌图标应是 alt=\"\" + 显式 24×24 的 img")
	}
	login, _ := files.ReadFile("templates/login.html")
	if !strings.Contains(string(login), `<img class="ico" src="/favicon.svg" alt="" width="28" height="28">`) {
		t.Error("登录页大品牌区应是 alt=\"\" + 显式 28×28 的 img（与顶栏同源）")
	}
}
