// Package ui 是新版 Kotlin/Wasm 前端（web/ 工程）的伺服层：SPA 宿主页、wasm
// 产物访问、站点静态资产（favicon/品牌 logo）与项目注册表。
//
// 旧的服务端模板前端（templates/ + style.css + app.js）已在 M4 切流时整体移除：
// /web/* 页面壳一律输出 [SPAIndex]，数据由 SPA 经 JSON API 自取。
package ui

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"io"
	"sort"
	"strings"
)

// static/* 是随二进制内嵌的站点静态资产（favicon 三件套 + 品牌邮件 logo）。
//
//go:embed static/*
var files embed.FS

// ClientHintsHeader 是 UA Client Hints 采集的 opt-in（页面壳响应头）。
// 丢了它设备名回退 UA 解析、登录提醒指纹分不出新设备——见 AGENTS 坑位。
const ClientHintsHeader = "Sec-CH-UA-Platform, Sec-CH-UA-Model"

// staticTypes 是站点静态资产清单（favicon 三件套，由 scripts/genicons 生成）：
// 文件名 → Content-Type。路由层按这份清单逐个挂 `GET /<name>`，清单改这里即可。
var staticTypes = map[string]string{
	"favicon.ico":          "image/x-icon",
	"favicon.svg":          "image/svg+xml; charset=utf-8",
	"apple-touch-icon.png": "image/png",
}

var staticFiles = map[string][]byte{}

// brandFiles 是 /brand/ 下的品牌 logo 资产（scripts/genicons 生成、随二进制内嵌）：
// 文件名 → 内容。init 里现读 embed 目录登记，缺品牌资产就在启动时炸。
var brandFiles = map[string][]byte{}

// brandContentType 按扩展名给 /brand/ 资产定 Content-Type（清单式，不猜）。
func brandContentType(name string) string {
	switch {
	case strings.HasSuffix(name, ".png"):
		return "image/png"
	case strings.HasSuffix(name, ".svg"):
		return "image/svg+xml; charset=utf-8"
	default:
		return "application/octet-stream"
	}
}

func init() {
	// 静态资产随二进制一起打包（零外链口径）：缺一个就在启动时炸
	for name := range staticTypes {
		data, err := files.ReadFile("static/" + name)
		if err != nil {
			panic(fmt.Errorf("读静态资产 %s: %w", name, err))
		}
		staticFiles[name] = data
	}

	// 品牌邮件 logo（/brand/<slug>-v1.png + 矢量源 <slug>.svg）：邮件以绝对 URL 引用
	//（见 internal/auth 的 brand.logoURL），这里登记成可挂载的静态资产。
	brandEntries, berr := files.ReadDir("static/brand")
	if berr != nil {
		panic(fmt.Errorf("列品牌 logo: %w", berr))
	}
	for _, e := range brandEntries {
		if e.IsDir() {
			continue
		}
		data, err := files.ReadFile("static/brand/" + e.Name())
		if err != nil {
			panic(fmt.Errorf("读品牌 logo %s: %w", e.Name(), err))
		}
		brandFiles[e.Name()] = data
	}
	if len(brandFiles) == 0 {
		panic("ui: static/brand/ 下没有品牌 logo——先跑 go run ./scripts/genicons")
	}
}

// StaticNames 返回静态资产名清单（路由层逐个挂载用）。
func StaticNames() []string {
	names := make([]string, 0, len(staticTypes))
	for name := range staticTypes {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Static 按名取静态资产内容与 Content-Type。
func Static(name string) ([]byte, string, bool) {
	ctype, ok := staticTypes[name]
	if !ok {
		return nil, "", false
	}
	return staticFiles[name], ctype, true
}

// BrandStatic 按名取品牌 logo 内容与 Content-Type。
func BrandStatic(name string) ([]byte, string, bool) {
	data, ok := brandFiles[name]
	if !ok {
		return nil, "", false
	}
	return data, brandContentType(name), true
}

// knownApps 是项目切换器/授权页的展示名（与 auth.allowedApps 同源的两 app；
// 新应用加这里 + allowedApps 两处）。定序即展示序。前端不存第二份清单。
var knownApps = []struct{ key, label string }{
	{"calorie-diary", "热量日记"},
	{"expense-diary", "开支日记"},
}

// AppLabel 返回项目 slug 的展示名：未知 slug 回原串，'' 回 ""。
func AppLabel(key string) string {
	for _, a := range knownApps {
		if a.key == key {
			return a.label
		}
	}
	return key
}

// RegistryApp 是 GET /web/registry 回执的一条记录。
type RegistryApp struct {
	Key   string `json:"key"`
	Label string `json:"label"`
}

// Registry 是 SPA 的 slug→展示名清单——注册表仍然只有 knownApps 一份。
func Registry() []RegistryApp {
	out := make([]RegistryApp, 0, len(knownApps))
	for _, a := range knownApps {
		out = append(out, RegistryApp{Key: a.key, Label: a.label})
	}
	return out
}

// SPAIndex 渲染 Kotlin/Wasm 前端（web/ 工程）的宿主页。全部同源零外链：脚本走
// /wasm/authweb.js，由它拉起 ComposeViewport 画整页；title 是各路由的固定常量，
// 无用户输入，直接拼接安全。背景色先给画布色，避免 wasm 启动前白闪。
func SPAIndex(title string) string {
	return `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="color-scheme" content="light dark">
<meta name="theme-color" content="#3482FF">
<title>` + title + ` · Auth</title>
<style>html,body{margin:0;padding:0;height:100%;background:#F7F7F7;color-scheme:light dark}@media(prefers-color-scheme:dark){html,body{background:#000}}</style>
</head>
<body>
<script src="/wasm/authweb.js"></script>
</body>
</html>
`
}

// OAuthView 是授权确认/错误页的渲染上下文（cmd/server 的 oauth.go 填）。
type OAuthView struct {
	Tx            string
	AppName       string
	RedirectHost  string
	Email         string
	ErrorTitle    string
	ErrorMessage  string
}

// authorizePageTmpl 是授权页（独立成页、零 JS、零外链）：确认/错误同一张卡片
// 语言。样式内联最小集——这页是 OAuth 回跳链路上的活口，不随 SPA 走。
var authorizePageTmpl = template.Must(template.New("authorize").Parse(`<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>授权登录 · Auth</title>
<style>
html,body{margin:0;height:100%;background:#F7F7F7;color-scheme:light dark;font-family:"MiSans",-apple-system,"PingFang SC","Microsoft YaHei",sans-serif}
@media(prefers-color-scheme:dark){body{background:#000}}
.shell{max-width:420px;margin:0 auto;padding:48px 16px}
.brand{text-align:center;font-size:22px;margin-bottom:16px}
.card{background:#fff;border-radius:24px;padding:24px;box-shadow:inset 0 0 0 1px #ECECEC}
@media(prefers-color-scheme:dark){.card{background:#242424;box-shadow:inset 0 0 0 1px #393939}}
h2{font-size:17px;font-weight:500;margin:0}
p{margin:6px 0;font-size:14px}
.dim{color:rgba(0,0,0,.6)}@media(prefers-color-scheme:dark){.dim{color:rgba(255,255,255,.6)}}
.box{background:#EAF2FF;color:#3482FF;border-radius:16px;padding:12px 14px;font-size:14px;margin-top:12px}
@media(prefers-color-scheme:dark){.box{background:#2B3B54;color:#F2F2F2}}
.hint{color:rgba(0,0,0,.5);font-size:13px;margin-top:10px}
@media(prefers-color-scheme:dark){.hint{color:rgba(255,255,255,.5)}}
button,.btn{display:block;width:100%;margin-top:10px;padding:11px;border:0;border-radius:16px;font-size:15px;cursor:pointer;text-align:center;text-decoration:none;color:inherit}
.primary{background:#3482FF;color:#fff}
.sub{background:#F0F0F0;color:#303030}
@media(prefers-color-scheme:dark){.sub{background:#434343;color:#F2F2F2}}
</style>
</head>
<body>
<div class="shell">
  <div class="brand">🔐 Auth</div>
  {{if .ErrorTitle}}
  <div class="card">
    <h2>{{.ErrorTitle}}</h2>
    <p class="dim">{{.ErrorMessage}}</p>
    <a class="btn primary" href="/web/console">回到控制台</a>
  </div>
  {{else}}
  <div class="card">
    <h2>授权登录「{{.AppName}}」</h2>
    <p class="dim">当前账号：{{.Email}}</p>
    <p class="box">登录到「{{.AppName}}」后，它将获得你的账号标识与邮箱。</p>
    <p class="hint">回跳地址：{{.RedirectHost}}</p>
    <form method="post" action="/oauth/authorize/confirm">
      <input type="hidden" name="tx" value="{{.Tx}}">
      <button type="submit" class="primary" name="decision" value="allow">继续</button>
      <button type="submit" class="sub" name="decision" value="deny">取消</button>
    </form>
  </div>
  {{end}}
</div>
</body>
</html>
`))

// AuthorizePage 渲染授权确认/错误页（w 写出完整 HTML）。
func AuthorizePage(w io.Writer, v OAuthView) error {
	var buf bytes.Buffer
	if err := authorizePageTmpl.Execute(&buf, v); err != nil {
		return fmt.Errorf("渲染授权页: %w", err)
	}
	_, err := w.Write(buf.Bytes())
	return err
}
