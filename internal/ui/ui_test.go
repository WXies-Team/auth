package ui

import (
	"strings"
	"testing"
)

// 所有页面共用 layout 骨架：<head> 必须带三件套 link 与 theme-color，
// 顶栏品牌区挂 favicon.svg（与两 App 启动图标同源的超椭圆渐变指纹图）。
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
