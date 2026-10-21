package main

// Command genicons 生成本仓全部图形资产（一次性画、可随时重生）。两种画法：
//
//	品牌画法（纯色 miuix 品牌蓝 #3482FF 实底 + 白色矢量，squircle 外形）
//	  internal/ui/static/brand/<slug>-v1.png  三品牌邮件 logo（128px = 64@2x，单版本；
//	                                          邮件以 https://auth.horatio.cn/brand/ 引用）
//	  internal/ui/static/brand/<slug>.svg     同款矢量源（squircle 用采样折线逼近）
//	站点画法（**透明底 + miuix 蓝 #3482FF 描边本体**，2026-10-20 作者拍板）
//	  internal/ui/static/apple-touch-icon.png                     180px（iOS 主屏会给透明图标垫黑底）
//	  internal/ui/static/favicon.ico                              16/32/48 三档
//	  internal/ui/static/favicon.svg                              96px，纯蓝描边 glyph
//
// 用法（仓库根目录）：
//
//	go run ./scripts/genicons          # 写文件
//	go run ./scripts/genicons -check   # 只校验磁盘与本程序输出一致（CI/测试用）
//
// 字形取自 lucide-static v0.462.0（ISC）：热量日记 = flame、开支日记 = receipt、
// Auth = shield 素盾（2026-10-21 全渠道统一：favicon 三件套与品牌邮件 logo 同出一份
// shield path data——旧 hexagon（站点位）与 users（品牌位）一并让位）。

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// flame / receipt / shield 取自 lucide-static v0.462.0（ISC 许可，图标沿用仓库
// 「零 CDN、矢量内联」口径），path data 与 lucide 官方源逐字一致。
var (
	flamePaths = []string{
		"M8.5 14.5A2.5 2.5 0 0 0 11 12c0-1.38-.5-2-1-3-1.072-2.143-.224-4.054 2-6 .5 2.5 2 4.9 4 6.5 2 1.6 3 3.5 3 5.5a7 7 0 1 1-14 0c0-1.153.433-2.294 1-3a2.5 2.5 0 0 0 2.5 2.5z",
	}
	receiptPaths = []string{
		"M4 2v20l2-1 2 1 2-1 2 1 2-1 2 1 2-1 2 1V2l-2 1-2-1-2 1-2-1-2 1-2-1-2 1Z",
		"M16 8h-6a2 2 0 1 0 0 4h4a2 2 0 1 1 0 4H8",
		"M12 17.5v-11",
	}
	// shieldPaths 是 Auth 的**唯一品牌字形**（素盾）：favicon.svg / favicon.ico /
	// apple-touch-icon.png 与品牌邮件 logo（brand/auth）全部共用这一份。path data 与
	// lucide 官方 icons/shield.svg 逐字一致（= internal/ui/icons.go "shield-check"
	// 的盾体 path，功能位盾形与品牌位同源）。
	shieldPaths = []string{
		"M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z",
	}
)

// brandGlyphs 是三品牌 logo 的字形（键 = 文件名 slug）。auth = shield 素盾，与站点
// favicon 三件套**同一份 path data**——全渠道一个图形（gen_test 有同源断言钉死）。
var brandGlyphs = map[string][]string{
	"calorie-diary": flamePaths,
	"expense-diary": receiptPaths,
	"auth":          shieldPaths,
}

// brandLabels 是 logo 的 alt/title 文案（与 auth 品牌注册表的 name 同值）。
var brandLabels = map[string]string{
	"calorie-diary": "热量日记",
	"expense-diary": "开支日记",
	"auth":          "Auth",
}

// fileOut 是一份待写资产：rel 相对仓库根。
type fileOut struct {
	rel  string
	data []byte
}

// generate 产出全部资产（纯函数：给 -check 与测试比对用）。
func generate() ([]fileOut, error) {
	var out []fileOut

	// 品牌邮件 logo：64px 设计尺寸 @2x = 128px，超椭圆切角 + 纯色 #3482FF 实底 +
	// 白字形（字形外包盒占 76% ≈ 四周 12% 内边距）。矢量源同款（squircle 用采样折线逼近）。
	for _, name := range []string{"calorie-diary", "expense-diary", "auth"} {
		png, err := encodePNG(iconSpec{size: 128, cutCorners: true, boxFrac: 0.76, paths: brandGlyphs[name]})
		if err != nil {
			return nil, fmt.Errorf("画 %s 品牌 logo: %w", name, err)
		}
		out = append(out, fileOut{"internal/ui/static/brand/" + name + "-v1.png", png})
		svg, err := brandSVG(64, brandLabels[name], brandGlyphs[name])
		if err != nil {
			return nil, fmt.Errorf("画 %s 品牌 logo 矢量源: %w", name, err)
		}
		out = append(out, fileOut{"internal/ui/static/brand/" + name + ".svg", []byte(svg)})
	}

	// apple-touch-icon：与 favicon 同款**透明底 + #3482FF 蓝 glyph**（2026-10-20 作者
	// 拍板）。满幅不切角——iOS 主屏自己套超椭圆蒙版；**iOS 会给透明图标垫黑底**
	//（平台行为），嫌黑再议。
	apple, err := encodePNG(iconSpec{size: 180, boxFrac: 0.6, paths: shieldPaths, transparentBlue: true})
	if err != nil {
		return nil, fmt.Errorf("画 apple-touch-icon: %w", err)
	}
	out = append(out, fileOut{"internal/ui/static/apple-touch-icon.png", apple})

	ico, err := encodeICO([]int{16, 32, 48}, 0.6, shieldPaths)
	if err != nil {
		return nil, fmt.Errorf("画 favicon.ico: %w", err)
	}
	out = append(out, fileOut{"internal/ui/static/favicon.ico", ico})

	svg, err := faviconSVG(96, shieldPaths)
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
