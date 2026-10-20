package main

// SVG path 展平：把 lucide 的 path data 拆成折线段，供光栅描边用。
//
// 只需要「点到线段距离」这一种几何查询（圆头描边 = 距离 ≤ 半宽），所以直线直接成段，
// 贝塞尔与圆弧按固定步长采样成折线——步长只影响曲线的光滑度，不影响语义。
// 支持的命令：M/L/H/V/C/S/Q/T/A/Z（含小写相对形式），其余一律报错（宁可生成失败，
// 也不悄悄画错图形）。

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

// pt 是 24×24 viewBox（或像素空间）里的一个点。
type pt struct{ x, y float64 }

// seg 是一条线段；零长度线段合法（lucide 的 `h.01` 圆点就靠它 + 圆头描边成点）。
type seg struct{ a, b pt }

// curveSteps 是贝塞尔曲线的采样段数。24 段在 192px 画布上（步长 ≈2px）看不出折角。
const curveSteps = 24

// flatten 展平一段 path data；任何不认识的命令都会返回错误。
func flatten(d string) ([]seg, error) {
	p := &parser{d: d}
	if err := p.run(); err != nil {
		return nil, fmt.Errorf("解析路径 %q: %w", d, err)
	}
	return p.segs, nil
}

type parser struct {
	d     string
	i     int
	segs  []seg
	cur   pt // 当前点
	start pt // 子路径起点（Z 回到这里）
	prevC pt // 上一段三次曲线的第二控制点（S 的反射源）
	prevQ pt // 上一段二次曲线的控制点（T 的反射源）
	haveC bool
	haveQ bool
}

func isSpaceB(c byte) bool { return c == ' ' || c == '\t' || c == '\r' || c == '\n' }

func (p *parser) skip() {
	for p.i < len(p.d) && (isSpaceB(p.d[p.i]) || p.d[p.i] == ',') {
		p.i++
	}
}

// atCommand 表示「当前参数列表读完了」：要么到头，要么遇到了下一个命令字母。
func (p *parser) atCommand() bool {
	p.skip()
	if p.i >= len(p.d) {
		return true
	}
	c := p.d[p.i]
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
}

// num 读一个数字：支持负号、小数与指数（lucide 的 d 里有 -2.143 这类串）。
func (p *parser) num() (float64, error) {
	p.skip()
	if p.i >= len(p.d) {
		return 0, fmt.Errorf("参数不足")
	}
	start := p.i
	if p.d[p.i] == '-' || p.d[p.i] == '+' {
		p.i++
	}
	// 数字之间可以无分隔符紧挨（SVG path data 的常态，如 "-1.153.433" 是
	// -1.153 与 .433 两个数、"1-2" 是 1 与 -2）：一个数里只允许一个点，
	// 遇到第二个点就断开交给下一次读。
	seenDot := false
	for p.i < len(p.d) {
		c := p.d[p.i]
		if c >= '0' && c <= '9' {
			p.i++
			continue
		}
		if c == '.' {
			if seenDot {
				break
			}
			seenDot = true
			p.i++
			continue
		}
		if (c == 'e' || c == 'E') && p.i+1 < len(p.d) {
			n := p.d[p.i+1]
			if (n >= '0' && n <= '9') || n == '+' || n == '-' {
				p.i += 2
				continue
			}
		}
		break
	}
	v, err := strconv.ParseFloat(p.d[start:p.i], 64)
	if err != nil {
		return 0, fmt.Errorf("非法数字 %q", p.d[start:p.i])
	}
	return v, nil
}

func (p *parser) run() error {
	for {
		p.skip()
		if p.i >= len(p.d) {
			return nil
		}
		c := p.d[p.i]
		if !strings.ContainsRune("MmLlHhVvCcSsQqTtAaZz", rune(c)) {
			return fmt.Errorf("不支持的路径命令 %q", c)
		}
		p.i++
		if err := p.cmd(c); err != nil {
			return err
		}
	}
}

// abs 把（可能相对的）坐标换成绝对坐标，参照点是当前点。
func (p *parser) abs(x, y float64, rel bool) pt {
	if rel {
		return pt{p.cur.x + x, p.cur.y + y}
	}
	return pt{x, y}
}

func (p *parser) lineTo(e pt) {
	p.segs = append(p.segs, seg{p.cur, e})
}

func (p *parser) curveTo(fn func(float64) pt) {
	prev := p.cur
	for i := 1; i <= curveSteps; i++ {
		q := fn(float64(i) / curveSteps)
		p.segs = append(p.segs, seg{prev, q})
		prev = q
	}
}

func (p *parser) quadTo(c, e pt) {
	p0 := p.cur
	p.curveTo(func(t float64) pt {
		u := 1 - t
		return pt{
			x: u*u*p0.x + 2*u*t*c.x + t*t*e.x,
			y: u*u*p0.y + 2*u*t*c.y + t*t*e.y,
		}
	})
}

func (p *parser) cubicTo(c1, c2, e pt) {
	p0 := p.cur
	p.curveTo(func(t float64) pt {
		u := 1 - t
		return pt{
			x: u*u*u*p0.x + 3*u*u*t*c1.x + 3*u*t*t*c2.x + t*t*t*e.x,
			y: u*u*u*p0.y + 3*u*u*t*c1.y + 3*u*t*t*c2.y + t*t*t*e.y,
		}
	})
}

// cmd 读完一个命令的**一次**参数并落段；参数可重复出现（如 `l 1 1 2 2`），
// 读完一组后若后面还是数字就继续读，直到遇见下一个命令字母或字符串结尾。
func (p *parser) cmd(c byte) error {
	rel := c >= 'a'
	up := c
	if rel {
		up = c - 32
	}
	mode := up
	for {
		switch mode {
		case 'M', 'L':
			x, err := p.num()
			if err != nil {
				return err
			}
			y, err := p.num()
			if err != nil {
				return err
			}
			e := p.abs(x, y, rel)
			if mode == 'M' {
				p.cur, p.start = e, e
				p.haveC, p.haveQ = false, false
				mode = 'L' // moveto 之后的隐式坐标对都是 lineto
			} else {
				p.lineTo(e)
				p.cur = e
				p.haveC, p.haveQ = false, false
			}
		case 'H':
			x, err := p.num()
			if err != nil {
				return err
			}
			e := p.abs(x, p.cur.y, false)
			if rel {
				e = pt{p.cur.x + x, p.cur.y}
			}
			p.lineTo(e)
			p.cur = e
			p.haveC, p.haveQ = false, false
		case 'V':
			y, err := p.num()
			if err != nil {
				return err
			}
			e := pt{p.cur.x, y}
			if rel {
				e = pt{p.cur.x, p.cur.y + y}
			}
			p.lineTo(e)
			p.cur = e
			p.haveC, p.haveQ = false, false
		case 'C', 'S':
			var c1 pt
			if mode == 'C' {
				x1, err := p.num()
				if err != nil {
					return err
				}
				y1, err := p.num()
				if err != nil {
					return err
				}
				c1 = p.abs(x1, y1, rel)
			} else if p.haveC {
				c1 = pt{2*p.cur.x - p.prevC.x, 2*p.cur.y - p.prevC.y}
			} else {
				c1 = p.cur
			}
			x2, err := p.num()
			if err != nil {
				return err
			}
			y2, err := p.num()
			if err != nil {
				return err
			}
			x, err := p.num()
			if err != nil {
				return err
			}
			y, err := p.num()
			if err != nil {
				return err
			}
			c2 := p.abs(x2, y2, rel)
			e := p.abs(x, y, rel)
			p.cubicTo(c1, c2, e)
			p.cur, p.prevC, p.haveC, p.haveQ = e, c2, true, false
		case 'Q', 'T':
			var c1 pt
			if mode == 'Q' {
				x1, err := p.num()
				if err != nil {
					return err
				}
				y1, err := p.num()
				if err != nil {
					return err
				}
				c1 = p.abs(x1, y1, rel)
			} else if p.haveQ {
				c1 = pt{2*p.cur.x - p.prevQ.x, 2*p.cur.y - p.prevQ.y}
			} else {
				c1 = p.cur
			}
			x, err := p.num()
			if err != nil {
				return err
			}
			y, err := p.num()
			if err != nil {
				return err
			}
			e := p.abs(x, y, rel)
			p.quadTo(c1, e)
			p.cur, p.prevQ, p.haveQ, p.haveC = e, c1, true, false
		case 'A':
			rx, err := p.num()
			if err != nil {
				return err
			}
			ry, err := p.num()
			if err != nil {
				return err
			}
			rot, err := p.num()
			if err != nil {
				return err
			}
			large, err := p.num()
			if err != nil {
				return err
			}
			sweep, err := p.num()
			if err != nil {
				return err
			}
			x, err := p.num()
			if err != nil {
				return err
			}
			y, err := p.num()
			if err != nil {
				return err
			}
			e := p.abs(x, y, rel)
			if rx == 0 || ry == 0 {
				p.lineTo(e) // 半径为 0 的弧按规范退化成直线
			} else {
				as, err := arcSegs(p.cur, e, rx, ry, rot, large != 0, sweep != 0)
				if err != nil {
					return err
				}
				p.segs = append(p.segs, as...)
			}
			p.cur = e
			p.haveC, p.haveQ = false, false
		case 'Z':
			p.lineTo(p.start)
			p.cur = p.start
			return nil
		default:
			return fmt.Errorf("不支持的路径命令 %q", c)
		}
		if p.atCommand() {
			return nil
		}
	}
}

// arcSegs 把椭圆弧按「端点 → 圆心参数化」的标准算法换算后采样成折线
//（SVG Implementation Notes F.6.5 全套）。
func arcSegs(p0, p1 pt, rx, ry, rotDeg float64, large, sweep bool) ([]seg, error) {
	phi := rotDeg * math.Pi / 180
	cosP, sinP := math.Cos(phi), math.Sin(phi)
	dx := (p0.x - p1.x) / 2
	dy := (p0.y - p1.y) / 2
	x1p := cosP*dx + sinP*dy
	y1p := -sinP*dx + cosP*dy
	rx, ry = math.Abs(rx), math.Abs(ry)
	// 半径不够大就整体放大（规范 F.6.6），否则开方出 NaN
	lam := x1p*x1p/(rx*rx) + y1p*y1p/(ry*ry)
	if lam > 1 {
		s := math.Sqrt(lam)
		rx *= s
		ry *= s
	}
	sign := 1.0
	if large == sweep {
		sign = -1
	}
	num := rx*rx*ry*ry - rx*rx*y1p*y1p - ry*ry*x1p*x1p
	den := rx*rx*y1p*y1p + ry*ry*x1p*x1p
	if den == 0 {
		return nil, fmt.Errorf("退化的椭圆弧")
	}
	coef := sign * math.Sqrt(math.Max(0, num/den))
	cxp := coef * rx * y1p / ry
	cyp := -coef * ry * x1p / rx
	cx := cosP*cxp - sinP*cyp + (p0.x+p1.x)/2
	cy := sinP*cxp + cosP*cyp + (p0.y+p1.y)/2

	angle := func(ux, uy, vx, vy float64) float64 {
		return math.Atan2(ux*vy-uy*vx, ux*vx+uy*vy)
	}
	theta1 := angle(1, 0, (x1p-cxp)/rx, (y1p-cyp)/ry)
	dtheta := angle((x1p-cxp)/rx, (y1p-cyp)/ry, (-x1p-cxp)/rx, (-y1p-cyp)/ry)
	if !sweep && dtheta > 0 {
		dtheta -= 2 * math.Pi
	}
	if sweep && dtheta < 0 {
		dtheta += 2 * math.Pi
	}
	// 5° 一步：192px 画布上弧长步长 <1px，肉眼与实心弧无差
	steps := int(math.Ceil(math.Abs(dtheta) / (math.Pi / 36)))
	if steps < 2 {
		steps = 2
	}
	at := func(t float64) pt {
		x := rx * math.Cos(t)
		y := ry * math.Sin(t)
		return pt{cosP*x - sinP*y + cx, sinP*x + cosP*y + cy}
	}
	var out []seg
	prev := p0
	for i := 1; i <= steps; i++ {
		q := at(theta1 + dtheta*float64(i)/float64(steps))
		out = append(out, seg{prev, q})
		prev = q
	}
	// 起止点用精确端点覆盖浮点误差
	out[0].a = p0
	out[len(out)-1].b = p1
	return out, nil
}

// bboxOf 取折线外包盒（两端点即可：线段的极值一定在端点上）。
func bboxOf(segs []seg) (min, max pt) {
	if len(segs) == 0 {
		return pt{}, pt{24, 24}
	}
	min, max = segs[0].a, segs[0].a
	consider := func(p pt) {
		if p.x < min.x {
			min.x = p.x
		}
		if p.y < min.y {
			min.y = p.y
		}
		if p.x > max.x {
			max.x = p.x
		}
		if p.y > max.y {
			max.y = p.y
		}
	}
	for _, s := range segs {
		consider(s.a)
		consider(s.b)
	}
	return min, max
}
