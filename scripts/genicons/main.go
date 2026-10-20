package main

// Command genicons 生成本仓全部品牌图形资产（一次性画、可随时重生）：
//
//	internal/mail/icons/{calorie-diary,expense-diary,auth}.png  三品牌邮件内嵌图（192px = 96@2x）
//	internal/ui/static/apple-touch-icon.png                     180px（满幅方形，iOS 自套超椭圆蒙版）
//	internal/ui/static/favicon.ico                              16/32/48 三档
//	internal/ui/static/favicon.svg                              96px 超椭圆 path 近似
//
// 用法（仓库根目录）：
//
//	go run ./scripts/genicons          # 写文件
//	go run ./scripts/genicons -check   # 只校验磁盘与本程序输出一致（CI/测试用）
//
// 字形取自 lucide-static v0.462.0（ISC）：热量日记 = flame、开支日记 = receipt、
// Auth = fingerprint——与 internal/ui/icons.go 同一版，图标与页面内联 SVG 同源。

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// flame / receipt 取自 lucide-static v0.462.0（ISC 许可，图标沿用仓库
// 「零 CDN、矢量内联」口径）；fingerprint 与 internal/ui/icons.go 逐字一致。
var (
	flamePaths = []string{
		"M8.5 14.5A2.5 2.5 0 0 0 11 12c0-1.38-.5-2-1-3-1.072-2.143-.224-4.054 2-6 .5 2.5 2 4.9 4 6.5 2 1.6 3 3.5 3 5.5a7 7 0 1 1-14 0c0-1.153.433-2.294 1-3a2.5 2.5 0 0 0 2.5 2.5z",
	}
	receiptPaths = []string{
		"M4 2v20l2-1 2 1 2-1 2 1 2-1 2 1 2-1 2 1V2l-2 1-2-1-2 1-2-1-2 1-2-1-2 1Z",
		"M16 8h-6a2 2 0 1 0 0 4h4a2 2 0 1 1 0 4H8",
		"M12 17.5v-11",
	}
	fingerprintPaths = []string{
		"M12 10a2 2 0 0 0-2 2c0 1.02-.1 2.51-.26 4",
		"M14 13.12c0 2.38 0 6.38-1 8.88",
		"M17.29 21.02c.12-.6.43-2.3.5-3.02",
		"M2 12a10 10 0 0 1 18-6",
		"M2 16h.01",
		"M21.8 16c.2-2 .131-5.354 0-6",
		"M5 19.5C5.5 18 6 15 6 12a6 6 0 0 1 .34-2",
		"M8.65 22c.21-.66.45-1.32.57-2",
		"M9 6.8a6 6 0 0 1 9 5.2v2",
	}
)

// fileOut 是一份待写资产：rel 相对仓库根。
type fileOut struct {
	rel  string
	data []byte
}

// generate 产出全部资产（纯函数：给 -check 与测试比对用）。
func generate() ([]fileOut, error) {
	var out []fileOut

	// 邮件内嵌图：96px@2x = 192px，透明边距 0（超椭圆即图形边界）
	mailIcons := map[string][]string{
		"calorie-diary": flamePaths,
		"expense-diary": receiptPaths,
		"auth":          fingerprintPaths,
	}
	for _, name := range []string{"calorie-diary", "expense-diary", "auth"} {
		png, err := encodePNG(iconSpec{size: 192, cutCorners: true, boxFrac: 0.6, paths: mailIcons[name]})
		if err != nil {
			return nil, fmt.Errorf("画 %s 邮件图标: %w", name, err)
		}
		out = append(out, fileOut{"internal/mail/icons/" + name + ".png", png})
	}

	// apple-touch-icon：满幅方形——iOS 会自己套超椭圆蒙版，切了角会在蒙版外留黑边
	apple, err := encodePNG(iconSpec{size: 180, cutCorners: false, boxFrac: 0.6, paths: fingerprintPaths})
	if err != nil {
		return nil, fmt.Errorf("画 apple-touch-icon: %w", err)
	}
	out = append(out, fileOut{"internal/ui/static/apple-touch-icon.png", apple})

	ico, err := encodeICO([]int{16, 32, 48}, 0.6, fingerprintPaths)
	if err != nil {
		return nil, fmt.Errorf("画 favicon.ico: %w", err)
	}
	out = append(out, fileOut{"internal/ui/static/favicon.ico", ico})

	svg, err := faviconSVG(96, fingerprintPaths)
	if err != nil {
		return nil, fmt.Errorf("画 favicon.svg: %w", err)
	}
	out = append(out, fileOut{"internal/ui/static/favicon.svg", []byte(svg)})

	return out, nil
}

func main() {
	dir := flag.String("dir", ".", "仓库根目录")
	check := flag.Bool("check", false, "只校验磁盘文件与生成结果一致，不写文件")
	flag.Parse()

	files, err := generate()
	if err != nil {
		fmt.Fprintf(os.Stderr, "genicons: %v\n", err)
		os.Exit(1)
	}
	var stale []string
	for _, f := range files {
		path := filepath.Join(*dir, f.rel)
		if *check {
			got, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(got, f.data) {
				stale = append(stale, f.rel)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			fmt.Fprintf(os.Stderr, "genicons: 建目录: %v\n", err)
			os.Exit(1)
		}
		if err := os.WriteFile(path, f.data, 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "genicons: 写 %s: %v\n", path, err)
			os.Exit(1)
		}
		fmt.Println("写入", f.rel)
	}
	if *check && len(stale) > 0 {
		fmt.Fprintf(os.Stderr, "genicons: 以下资产与生成器输出不一致（跑 go run ./scripts/genicons 重生）:\n  %s\n", strings.Join(stale, "\n  "))
		os.Exit(1)
	}
}
