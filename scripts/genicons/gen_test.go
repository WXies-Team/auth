package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"image"
	"image/png" // 解码入库 PNG 做像素级断言
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 生成器必须与入库的资产字节一致：任何人改了字形/配色但忘了重生，这里先红。
//（regenerate 是纯函数，PNG 编码无时间戳——同一份输入恒同一份字节。）
func TestGeneratedAssetsInSync(t *testing.T) {
	files, err := generate()
	if err != nil {
		t.Fatalf("生成资产: %v", err)
	}
	if len(files) != 6 {
		t.Fatalf("资产清单应为 6 份（3 邮件图标 + apple-touch + ico + svg），得到 %d", len(files))
	}
	for _, f := range files {
		got, err := os.ReadFile(filepath.Join("..", "..", f.rel))
		if err != nil {
			t.Errorf("缺资产 %s: %v（跑 go run ./scripts/genicons 重生）", f.rel, err)
			continue
		}
		if !bytes.Equal(got, f.data) {
			t.Errorf("%s 与生成器输出不一致（跑 go run ./scripts/genicons 重生）", f.rel)
		}
	}
}

// 三个邮件图标的 Content-ID 名必须与 internal/mail 的内嵌注册表口径一致
//（cid = 文件名 + "-icon"）——文件名拼错会让邮件里出现裂图。
func TestMailIconFilenamesMatchCIDConvention(t *testing.T) {
	want := map[string]bool{"calorie-diary.png": true, "expense-diary.png": true, "auth.png": true}
	files, err := generate()
	if err != nil {
		t.Fatalf("生成资产: %v", err)
	}
	got := map[string]bool{}
	for _, f := range files {
		if dir, name := filepath.Split(f.rel); dir == "internal/mail/icons/" {
			got[name] = true
		}
	}
	for name := range want {
		if !got[name] {
			t.Errorf("缺邮件图标 %s", name)
		}
	}
	if len(got) != len(want) {
		t.Errorf("邮件图标应恰为 %v，得到 %v", want, got)
	}
}

// readAsset 读入库资产（相对仓库根）。
func readAsset(t *testing.T, rel string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", rel))
	if err != nil {
		t.Fatalf("缺资产 %s: %v（跑 go run ./scripts/genicons 重生）", rel, err)
	}
	return data
}

// px 取像素的 8bit RGBA。png.Decode 对带 alpha 的图回 *image.NRGBA，其 At().RGBA()
// 是**预乘**值——AA 边缘像素会被算成异色，所以先走非预乘的类型断言。
func px(img image.Image, x, y int) (r, g, b, a uint8) {
	switch c := img.(type) {
	case *image.NRGBA:
		v := c.NRGBAAt(x, y)
		return v.R, v.G, v.B, v.A
	case *image.RGBA:
		v := c.RGBAAt(x, y)
		return v.R, v.G, v.B, v.A
	}
	cr, cg, cb, ca := img.At(x, y).RGBA()
	if ca == 0 {
		return 0, 0, 0, 0
	}
	// 反预乘：r8 = (cr/ca) * 255（cr、ca 同为 16bit 定点，比值即 0~1）
	return uint8(uint64(cr) * 255 / uint64(ca)),
		uint8(uint64(cg) * 255 / uint64(ca)),
		uint8(uint64(cb) * 255 / uint64(ca)),
		uint8(ca >> 8)
}

// 站点 favicon 三件套（2026-10-20 作者拍板）：**透明底 + miuix 蓝 #3482FF 的描边本体**，
// 不带任何背景；邮件 CID 图标（2026-10-20 重做拍板）：**纯色 #3482FF 实底**（不许渐变）
// + 白色矢量，squircle 外形不变。
func TestFaviconTransparentBlueAndMailIconsUnchanged(t *testing.T) {
	// ---- favicon.svg：纯蓝描边，无渐变、无底 ----
	svg := string(readAsset(t, "internal/ui/static/favicon.svg"))
	if !strings.Contains(svg, `stroke="#3482FF"`) {
		t.Error("favicon.svg 应是 #3482FF 描边")
	}
	if !strings.Contains(svg, `fill="none"`) {
		t.Error("favicon.svg 字形应 fill=none（只有描边）")
	}
	for _, bad := range []string{"linearGradient", "url(#", `fill="#`, "FF4D95", "2B6DE8"} {
		if strings.Contains(svg, bad) {
			t.Errorf("favicon.svg 不该带底/渐变，却含 %q", bad)
		}
	}

	// ---- apple-touch-icon.png：四角透明、不透明像素全是 miuix 蓝 ----
	apple, err := png.Decode(bytes.NewReader(readAsset(t, "internal/ui/static/apple-touch-icon.png")))
	if err != nil {
		t.Fatalf("解码 apple-touch-icon: %v", err)
	}
	if r, g, b, a := px(apple, 0, 0); a != 0 {
		t.Errorf("apple-touch-icon 四角应透明（iOS 会自己套蒙版），得到 %v%v%v/%v", r, g, b, a)
	}
	var opaque, offBlue int
	for y := 0; y < apple.Bounds().Dy(); y++ {
		for x := 0; x < apple.Bounds().Dx(); x++ {
			r, g, b, a := px(apple, x, y)
			if a == 0 {
				continue
			}
			opaque++
			if r != 0x34 || g != 0x82 || b != 0xFF {
				offBlue++
			}
		}
	}
	if opaque == 0 {
		t.Error("apple-touch-icon 没有字形")
	}
	if offBlue != 0 {
		t.Errorf("apple-touch-icon 应只有 #3482FF 一种字形色，有 %d 个异色像素（背景必须透明而不是白/粉底）", offBlue)
	}

	// ---- favicon.ico：16/32/48 三条 32bpp 条目，角落 alpha=0 且 AND 掩码置位 ----
	ico := readAsset(t, "internal/ui/static/favicon.ico")
	if len(ico) < 6 || binary.LittleEndian.Uint16(ico[2:4]) != 1 {
		t.Fatalf("favicon.ico 头不对: %x", ico[:min(6, len(ico))])
	}
	count := int(binary.LittleEndian.Uint16(ico[4:6]))
	if count != 3 {
		t.Fatalf("favicon.ico 应有 3 档，得到 %d", count)
	}
	sizes := map[int]bool{}
	for i := 0; i < count; i++ {
		ent := ico[6+16*i : 6+16*(i+1)]
		w, h := int(ent[0]), int(ent[1])
		if w == 0 {
			w = 256
		}
		if h == 0 {
			h = 256
		}
		sizes[w] = true
		if bpp := binary.LittleEndian.Uint16(ent[6:8]); bpp != 32 {
			t.Errorf("%dpx 条目应为 32bpp，得到 %d", w, bpp)
		}
		size := int(binary.LittleEndian.Uint32(ent[8:12]))
		off := int(binary.LittleEndian.Uint32(ent[12:16]))
		if off+size > len(ico) {
			t.Fatalf("%dpx 条目越界", w)
		}
		bmp := ico[off : off+size]
		// 位图像素：40 字节头后第一行 = 图像最底行，角落是背景 → alpha 必须 0
		if a := bmp[40+3]; a != 0 {
			t.Errorf("%dpx 条目角落 alpha 应为 0（透明底），得到 %d", w, a)
		}
		// AND 掩码紧随像素区，位=1 表示透明：只看掩码的老客户端也得读出透明
		mask := 40 + w*h*4
		if mask >= len(bmp) || bmp[mask]&0x80 == 0 {
			t.Errorf("%dpx 条目的 AND 掩码未把背景置为透明", w)
		}
	}
	for _, want := range []int{16, 32, 48} {
		if !sizes[want] {
			t.Errorf("favicon.ico 缺 %dpx 档", want)
		}
	}

	// ---- 邮件 CID 图标：纯色 #3482FF 实底（**零渐变**）+ 白矢量 + 超椭圆切角 ----
	for _, name := range []string{"calorie-diary", "expense-diary", "auth"} {
		img, err := png.Decode(bytes.NewReader(readAsset(t, "internal/mail/icons/"+name+".png")))
		if err != nil {
			t.Fatalf("解码 %s.png: %v", name, err)
		}
		// ① 四角是超椭圆切角（透明）
		for _, c := range [][2]int{{0, 0}, {191, 0}, {0, 191}, {191, 191}} {
			if a := pxAtAlpha(img, c[0], c[1]); a != 0 {
				t.Errorf("%s 邮件图标角 (%d,%d) 应透明（超椭圆切角），得到 alpha=%d", name, c[0], c[1], a)
			}
		}
		// ② 采样点逐点断言：上/下/左/右四边中点都在字形外包盒之外，必须是
		//    **不透明的 #3482FF 实底**——顶底同色即证明没有任何竖直渐变
		for _, p := range [][2]int{{96, 8}, {96, 184}, {8, 96}, {184, 96}} {
			r, g, b, a := px(img, p[0], p[1])
			if a != 255 || r != 0x34 || g != 0x82 || b != 0xFF {
				t.Errorf("%s 邮件图标 (%d,%d) 应为纯色 #3482FF 实底，得到 rgba(%d,%d,%d,%d)",
					name, p[0], p[1], r, g, b, a)
			}
		}
		// ③ 全图逐像素：底与字形都只能是「蓝或白」——两个端点的 B 通道都是 0xFF，
		//    任何渐变色（品红 b=149、渐变蓝底 b=232）都会在这里露馅
		var solid, whiteGlyph, bad int
		var badSample string
		for y := 0; y < img.Bounds().Dy(); y++ {
			for x := 0; x < img.Bounds().Dx(); x++ {
				r, g, b, a := px(img, x, y)
				if a == 0 {
					continue
				}
				if b != 0xFF || r < 0x34 || g < 0x82 {
					bad++
					if badSample == "" {
						badSample = fmt.Sprintf("(%d,%d) rgba(%d,%d,%d,%d)", x, y, r, g, b, a)
					}
					continue
				}
				if a == 255 && r == 0x34 && g == 0x82 {
					solid++
				}
				if a == 255 && r > 245 && g > 245 {
					whiteGlyph++
				}
			}
		}
		if bad != 0 {
			t.Errorf("%s 有 %d 个非「纯蓝/白」像素（首例 %s）——底必须是纯色 #3482FF 实底，不许渐变",
				name, bad, badSample)
		}
		if solid == 0 {
			t.Errorf("%s 缺不透明实底像素", name)
		}
		if whiteGlyph == 0 {
			t.Errorf("%s 缺白色矢量前景", name)
		}
	}
}

// glyphMask 把字形（白或蓝）的全不透明像素拍成位图，用于跨画法比对几何。
func glyphMask(img image.Image, white bool) []bool {
	w, h := img.Bounds().Dx(), img.Bounds().Dy()
	m := make([]bool, w*h)
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			r, g, b, a := px(img, x, y)
			hit := white && a == 255 && r > 245 && g > 245 && b > 245
			if !white {
				hit = a == 255 && r == 0x34 && g == 0x82 && b == 0xFF
			}
			if hit {
				m[y*w+x] = true
			}
		}
	}
	return m
}

// 字形口径（全渠道统一）：auth 品牌 = **hexagon**（与站点 favicon 同字形，2026-10-20
// 换装：曾用 fingerprint，与 passkey 功能图标撞脸），flame/receipt 只属于两个日记品牌。
// 比对方式：邮件图（品牌画法）与同一套路径现渲染的站点画法，**字形掩码必须逐像素一致**
// ——映射被改错立刻红。
func TestMailIconGlyphMapping(t *testing.T) {
	cases := []struct {
		file  string
		paths []string
	}{
		{"calorie-diary", flamePaths},
		{"expense-diary", receiptPaths},
		{"auth", hexagonPaths},
	}
	for _, c := range cases {
		img, err := png.Decode(bytes.NewReader(readAsset(t, "internal/mail/icons/"+c.file+".png")))
		if err != nil {
			t.Fatalf("解码 %s.png: %v", c.file, err)
		}
		ref, err := renderIcon(iconSpec{size: 192, boxFrac: 0.6, paths: c.paths, transparentBlue: true})
		if err != nil {
			t.Fatalf("渲染参照字形: %v", err)
		}
		got, want := glyphMask(img, true), glyphMask(ref, false)
		if len(got) != len(want) {
			t.Fatalf("%s 尺寸与参照不一致", c.file)
		}
		diff := 0
		for i := range got {
			if got[i] != want[i] {
				diff++
			}
		}
		if diff != 0 {
			t.Errorf("%s.png 的字形与参照路径不一致（%d 像素差）——品牌→字形映射被改错了", c.file, diff)
		}
	}
}

func pxAtAlpha(img image.Image, x, y int) uint8 {
	_, _, _, a := px(img, x, y)
	return a
}
