package main

import (
	"bytes"
	"encoding/binary"
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
// 不带任何背景；邮件 CID 图标**不受影响**，仍是蓝渐变超椭圆底 + 白色矢量。
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

	// ---- 邮件 CID 图标不受影响：超椭圆切角 + 品牌粉起点渐变 + 白矢量 ----
	for _, name := range []string{"calorie-diary", "expense-diary", "auth"} {
		img, err := png.Decode(bytes.NewReader(readAsset(t, "internal/mail/icons/"+name+".png")))
		if err != nil {
			t.Fatalf("解码 %s.png: %v", name, err)
		}
		if a := pxAtAlpha(img, 0, 0); a != 0 {
			t.Errorf("%s 邮件图标四角应为超椭圆切角（透明），得到 alpha=%d", name, a)
		}
		// 顶部中列是渐变起点（字形最高点在其下方），应为品牌粉
		r, g, b, _ := px(img, 96, 8)
		if !(r > 235 && g < 110 && b > 130 && b < 185) {
			t.Errorf("%s 邮件图标顶部应是品牌粉 #FF4D95，得到 rgb(%d,%d,%d)", name, r, g, b)
		}
		// 底部中列是渐变终点（蓝）
		r, g, b, _ = px(img, 96, 184)
		if !(r < 80 && g > 85 && g < 130 && b > 210) {
			t.Errorf("%s 邮件图标底部应是品牌蓝 #2B6DE8，得到 rgb(%d,%d,%d)", name, r, g, b)
		}
		// 白色矢量存在
		white := 0
		for y := 0; y < img.Bounds().Dy(); y++ {
			for x := 0; x < img.Bounds().Dx(); x++ {
				r, g, b, a := px(img, x, y)
				if a == 255 && r > 245 && g > 245 && b > 245 {
					white++
				}
			}
		}
		if white == 0 {
			t.Errorf("%s 邮件图标缺白色矢量前景", name)
		}
	}
}

func pxAtAlpha(img image.Image, x, y int) uint8 {
	_, _, _, a := px(img, x, y)
	return a
}
