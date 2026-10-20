package main

// 图标光栅化与序列化：超椭圆底 + 竖直渐变 + 白色描边字形。
//
// 配色与形状照「两 App 启动图标」的定案：竖直渐变 #FF4D95FF → #FF2B6DE8
//（8 位串按 RRGGBBAA 读：顶粉不透明、底蓝 E8），lucide 白色矢量前景，
// iOS 超椭圆（squircle）圆角。**统一渲染成不透明**：apple-touch-icon 的半透明
// 会被 iOS 压成黑底、邮件与网页底色也不可控，E8 与 FF 的可见差只有约 3% 亮度。
//
// 自带一个小光栅器的原因：图标要在仓库里可复现地重生（scripts/genicons 一键出全部
// 资产），不引入任何外部绘图库——Go 标准库画不了路径描边，而图标只有「超椭圆填充 +
// 折线圆头描边」两种几何，9 点超采样足够。

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"math"
	"strings"
)

var (
	gradTop    = color.RGBA{R: 0xFF, G: 0x4D, B: 0x95, A: 0xFF}
	gradBottom = color.RGBA{R: 0x2B, G: 0x6D, B: 0xE8, A: 0xFF}
	white      = color.RGBA{R: 0xFF, G: 0xFF, B: 0xFF, A: 0xFF}
)

const (
	squircleN = 5.0 // 超椭圆指数：|u|^n+|v|^n ≤ 1；n=5 是 iOS 连续圆角的常用近似
	subSamples = 3  // 每边 3 个子采样（每像素 9 点）——超椭圆与描边边缘的抗锯齿
)

// iconSpec 一枚图标的绘制参数。boxFrac 是字形外包盒占画布的比例（不含描边宽）。
type iconSpec struct {
	size       int
	cutCorners bool // false = 满幅方形（apple-touch-icon：iOS 自己套超椭圆蒙版）
	boxFrac    float64
	paths      []string
}

// transformFor 把字形外包盒缩放居中到 size×size 画布，返回 (scale, tx, ty)。
// 按字形实际外包盒归一化（而不是按 24 的 viewBox）——火焰、收据、指纹三者的
// 有效图形大小不同，不归一化会一枚大一枚小。
func transformFor(size, boxFrac float64, segs []seg) (s, tx, ty float64) {
	min, max := bboxOf(segs)
	w, h := max.x-min.x, max.y-min.y
	if w <= 0 || h <= 0 {
		w, h = 24, 24
	}
	d := math.Max(w, h)
	s = boxFrac * size / d
	return s, (size - w*s)/2 - min.x*s, (size - h*s)/2 - min.y*s
}

// strokePx 是描边在像素空间的宽度：小尺寸要**光学加粗**——16px 下按 5% 只有 0.8px，
// 等于把指纹糊成灰点。
func strokePxFor(size int) float64 {
	return math.Max(float64(size)*0.05, 1.35)
}

type pseg struct {
	a, b             pt
	minx, miny, maxx, maxy float64
}

func toPixel(segs []seg, s, tx, ty float64) []pseg {
	out := make([]pseg, len(segs))
	for i, g := range segs {
		a := pt{g.a.x*s + tx, g.a.y*s + ty}
		b := pt{g.b.x*s + tx, g.b.y*s + ty}
		out[i] = pseg{
			a: a, b: b,
			minx: math.Min(a.x, b.x), maxx: math.Max(a.x, b.x),
			miny: math.Min(a.y, b.y), maxy: math.Max(a.y, b.y),
		}
	}
	return out
}

// distToSeg 点到线段距离；零长度线段退化成点距（lucide 的圆点靠这个成形）。
func distToSeg(px, py float64, s pseg) float64 {
	dx, dy := s.b.x-s.a.x, s.b.y-s.a.y
	dd := dx*dx + dy*dy
	t := 0.0
	if dd > 0 {
		t = ((px-s.a.x)*dx + (py-s.a.y)*dy) / dd
		if t < 0 {
			t = 0
		} else if t > 1 {
			t = 1
		}
	}
	cx, cy := s.a.x+t*dx, s.a.y+t*dy
	return math.Hypot(px-cx, py-cy)
}

func onStroke(ps []pseg, px, py, hw float64) bool {
	for _, s := range ps {
		if px < s.minx-hw || px > s.maxx+hw || py < s.miny-hw || py > s.maxy+hw {
			continue
		}
		if distToSeg(px, py, s) <= hw {
			return true
		}
	}
	return false
}

// superellipseInside 判定点是否在超椭圆内（u、v 是 [-1,1] 的归一化坐标）。
func superellipseInside(u, v float64) bool {
	return math.Pow(math.Abs(u), squircleN)+math.Pow(math.Abs(v), squircleN) <= 1
}

func lerpColor(a, b color.RGBA, t float64) color.RGBA {
	return color.RGBA{
		R: uint8(float64(a.R) + (float64(b.R)-float64(a.R))*t + 0.5),
		G: uint8(float64(a.G) + (float64(b.G)-float64(a.G))*t + 0.5),
		B: uint8(float64(a.B) + (float64(b.B)-float64(a.B))*t + 0.5),
		A: 255,
	}
}

// renderIcon 画一枚图标并回 RGBA（A 恒为 255：切角处是完全透明，不是半透明）。
func renderIcon(spec iconSpec) (*image.RGBA, error) {
	var all []seg
	for _, d := range spec.paths {
		got, err := flatten(d)
		if err != nil {
			return nil, err
		}
		all = append(all, got...)
	}
	if len(all) == 0 {
		return nil, fmt.Errorf("字形路径为空")
	}
	s, tx, ty := transformFor(float64(spec.size), spec.boxFrac, all)
	ps := toPixel(all, s, tx, ty)
	hw := strokePxFor(spec.size) / 2

	img := image.NewRGBA(image.Rect(0, 0, spec.size, spec.size))
	half := float64(spec.size) / 2
	step := 1.0 / subSamples
	for y := 0; y < spec.size; y++ {
		for x := 0; x < spec.size; x++ {
			var inside, stroke int
			for sy := 0; sy < subSamples; sy++ {
				oy := (float64(sy) + step) / subSamples
				for sx := 0; sx < subSamples; sx++ {
					ox := (float64(sx) + step) / subSamples
					px := float64(x) + ox
					py := float64(y) + oy
					if spec.cutCorners && !superellipseInside((px-half)/half, (py-half)/half) {
						continue
					}
					inside++
					if onStroke(ps, px, py, hw) {
						stroke++
					}
				}
			}
			if inside == 0 {
				continue
			}
			gt := (float64(y) + 0.5) / float64(spec.size) // 渐变取色行（竖直渐变只看 y）
			base := lerpColor(gradTop, gradBottom, gt)
			c := base
			if stroke > 0 {
				c = lerpColor(base, white, float64(stroke)/float64(inside))
			}
			c.A = uint8(float64(inside)/float64(subSamples*subSamples)*255 + 0.5)
			img.SetRGBA(x, y, c)
		}
	}
	return img, nil
}

// encodePNG 渲染并编码。
func encodePNG(spec iconSpec) ([]byte, error) {
	img, err := renderIcon(spec)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// superellipsePath 用折线逼近超椭圆，产出 SVG path d（favicon.svg 的圆角底）。
func superellipsePath(size float64, n int) string {
	a := size / 2
	var b strings.Builder
	for i := 0; i < n; i++ {
		t := 2 * math.Pi * float64(i) / float64(n)
		c, s := math.Cos(t), math.Sin(t)
		x := a + math.Copysign(math.Pow(math.Abs(c), 2/squircleN)*a, c)
		y := a + math.Copysign(math.Pow(math.Abs(s), 2/squircleN)*a, s)
		if i == 0 {
			fmt.Fprintf(&b, "M%.2f %.2f", x, y)
		} else {
			fmt.Fprintf(&b, "L%.2f %.2f", x, y)
		}
	}
	b.WriteString("Z")
	return b.String()
}

// faviconSVG 生成 favicon.svg：同款超椭圆渐变底 + 白色 fingerprint 矢量
//（矢量直接用 lucide 原始 path data，缩放交给 transform）。
func faviconSVG(size float64, paths []string) (string, error) {
	var all []seg
	for _, d := range paths {
		got, err := flatten(d)
		if err != nil {
			return "", err
		}
		all = append(all, got...)
	}
	s, tx, ty := transformFor(size, 0.6, all)
	var b strings.Builder
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %g %g" width="%g" height="%g" role="img" aria-label="Auth">
<title>Auth</title>
<defs><linearGradient id="bg" x1="0" y1="0" x2="0" y2="1">
<stop offset="0" stop-color="%s"/><stop offset="1" stop-color="%s"/>
</linearGradient></defs>
<path fill="url(#bg)" d="%s"/>
<g transform="translate(%.3f %.3f) scale(%.5f)" fill="none" stroke="#FFFFFF" stroke-width="%.3f" stroke-linecap="round" stroke-linejoin="round">
`, size, size, size, size, cssColor(gradTop), cssColor(gradBottom), superellipsePath(size, 160), tx, ty, s, strokePxFor(int(size))/2/s)
	for _, d := range paths {
		fmt.Fprintf(&b, "<path d=\"%s\"/>\n", d)
	}
	b.WriteString("</g>\n</svg>\n")
	return b.String(), nil
}

func cssColor(c color.RGBA) string {
	return fmt.Sprintf("#%02X%02X%02X", c.R, c.G, c.B)
}

// encodeICO 打一个 32bpp BMP 条目式 ICO（16/32/48 三档）。位图条目比 PNG-in-ICO
// 兼容面大（老 Windows 的缩略图与某些浏览器只认位图条目）；32bpp 的 alpha 通道
// Vista+ 就被采纳，AND 掩码留全 0 即「全部不透明」。
func encodeICO(sizes []int, boxFrac float64, paths []string) ([]byte, error) {
	type entry struct {
		size   int
		bmp    []byte
	}
	var entries []entry
	for _, sz := range sizes {
		img, err := renderIcon(iconSpec{size: sz, cutCorners: true, boxFrac: boxFrac, paths: paths})
		if err != nil {
			return nil, err
		}
		entries = append(entries, entry{sz, bmpEntry(img)})
	}
	var buf bytes.Buffer
	binary.Write(&buf, binary.LittleEndian, uint16(0)) // reserved
	binary.Write(&buf, binary.LittleEndian, uint16(1)) // type: icon
	binary.Write(&buf, binary.LittleEndian, uint16(len(entries)))
	offset := 6 + 16*len(entries)
	for _, e := range entries {
		w := uint8(e.size)
		if e.size >= 256 {
			w = 0
		}
		buf.WriteByte(w)
		buf.WriteByte(w) // 宽高：0 表示 256
		buf.WriteByte(0) // 调色板色数
		buf.WriteByte(0) // 保留
		binary.Write(&buf, binary.LittleEndian, uint16(1))  // planes
		binary.Write(&buf, binary.LittleEndian, uint16(32)) // bitcount
		binary.Write(&buf, binary.LittleEndian, uint32(len(e.bmp)))
		binary.Write(&buf, binary.LittleEndian, uint32(offset))
		offset += len(e.bmp)
	}
	for _, e := range entries {
		buf.Write(e.bmp)
	}
	return buf.Bytes(), nil
}

// bmpEntry 把图像编成 ICO 的位图条目：40 字节 BITMAPINFOHEADER（高度 ×2 因为
// XOR 与 AND 两张图叠放）+ BGRA 自下而上像素行 + 全 0 的 AND 掩码。
func bmpEntry(img *image.RGBA) []byte {
	w, h := img.Rect.Dx(), img.Rect.Dy()
	andStride := ((w + 31) / 32) * 4
	data := make([]byte, 40+w*h*4+andStride*h)
	binary.LittleEndian.PutUint32(data[0:], 40)
	binary.LittleEndian.PutUint32(data[4:], uint32(w))
	binary.LittleEndian.PutUint32(data[8:], uint32(h*2))
	binary.LittleEndian.PutUint16(data[12:], 1)  // planes
	binary.LittleEndian.PutUint16(data[14:], 32) // bitcount
	binary.LittleEndian.PutUint32(data[16:], 0)  // BI_RGB
	binary.LittleEndian.PutUint32(data[20:], uint32(w*h*4+andStride*h))
	i := 40
	for y := h - 1; y >= 0; y-- { // 自下而上
		for x := 0; x < w; x++ {
			c := img.RGBAAt(x, y)
			data[i] = c.B
			data[i+1] = c.G
			data[i+2] = c.R
			data[i+3] = c.A
			i += 4
		}
	}
	// AND 掩码留全 0（32bpp 下 alpha 说了算）
	return data
}
