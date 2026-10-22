package ui

import (
	"embed"
	"mime"
	"path"
	"strings"
)

// wasm 前端产物（Kotlin/Wasm，web/ 工程经 ci/build-server.sh 构建后拷入）。
// 占位 .keep 保证没跑过 Gradle 的本地 go build 也能编过——伺服层对缺失文件回 404。
//
//go:embed all:wasm
var wasmFS embed.FS

// WasmAsset 按名取嵌入的前端产物：authweb.js 与内容哈希 wasm 分片互相引用、
// 文件名随内容变，因此按名透传伺服而不是写死清单。
// 返回 Content-Type 与 Cache-Control（入口 js 内容常换走 no-cache；其余按
// 内容哈希名走 immutable 长缓存）。
func WasmAsset(name string) (data []byte, contentType, cacheControl string, ok bool) {
	if name == "" || strings.Contains(name, "..") || strings.HasPrefix(name, "/") {
		return nil, "", "", false
	}
	b, err := wasmFS.ReadFile("wasm/" + name)
	if err != nil {
		return nil, "", "", false
	}
	ctype := mime.TypeByExtension(path.Ext(name))
	if ctype == "" {
		ctype = "application/octet-stream"
	}
	cache := "public, max-age=31536000, immutable"
	if name == "authweb.js" {
		cache = "no-cache"
	}
	return b, ctype, cache, true
}
