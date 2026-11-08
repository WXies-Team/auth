// Package geoip 把 IP 解析成「省 市」级归属地，用于会话/设备列表的「大致位置」。
//
// 数据是 **ip2region v2 的离线 xdb**（Apache-2.0 / MIT，中国数据精确到城市），
// 随二进制内嵌——本服务不向外发任何地理查询请求：IP 属于个人数据，会话页面每次
// 刷新都打第三方 API 既慢又把用户 IP 散给外部服务。查询走内存二分，10 微秒级。
//
// 双栈：v4 库 11 MB、v6 库 36 MB，都随二进制内嵌。按地址族各查各的库，
// 不拿 v4 段去凑 v6 地址。
//
// 数据更新：替换本目录的 ip2region_v4.xdb 后重新发版——和 favicon/品牌图标同一套
// 「资产随二进制走」的口径。上游：https://github.com/lionsoul2014/ip2region
package geoip

import (
	_ "embed"
	"net"
	"strings"
	"sync"

	"github.com/lionsoul2014/ip2region/binding/golang/xdb"
)

//go:embed ip2region_v4.xdb
var dbV4 []byte

//go:embed ip2region_v6.xdb
var dbV6 []byte

var (
	once sync.Once
	v4   *xdb.Searcher
	v6   *xdb.Searcher
)

// initSearchers 按地址族各建一个内存查询器（整库驻留，查询无磁盘 IO）。
// 任一族建失败就保持 nil——Region 返回空串，页面不显示归属地，绝不影响会话页本身。
func initSearchers() {
	if v, err := xdb.VersionFromName("v4"); err == nil {
		if s, err := xdb.NewWithBuffer(v, dbV4); err == nil {
			v4 = s
		}
	}
	if v, err := xdb.VersionFromName("v6"); err == nil {
		if s, err := xdb.NewWithBuffer(v, dbV6); err == nil {
			v6 = s
		}
	}
}

// Region 返回「省 市」形式的归属地（如「江苏 南京」）；查不到、内网地址或
// IP 非法时返回空串。调用方拿到空串就不渲染该段，不做任何猜测。
func Region(ip string) string {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return ""
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ""
	}
	// 内网/回环/链路本地/未指定：归属地无意义，硬查会给出误导性的结果
	if parsed.IsLoopback() || parsed.IsPrivate() || parsed.IsLinkLocalUnicast() ||
		parsed.IsUnspecified() || parsed.IsMulticast() {
		return ""
	}
	once.Do(initSearchers)
	searcher := v6
	if parsed.To4() != nil {
		searcher = v4
	}
	if searcher == nil {
		return ""
	}
	raw, err := searcher.Search(ip)
	if err != nil || raw == "" {
		return ""
	}
	return formatRegion(raw)
}

// formatRegion 把 ip2region 的 `国家|省份|城市|ISP|ISO` 收成给人看的两段。
//
// 三条收敛规则，都是「宁可少说，不说错」：
//   - 「0」是上游的「无此项」占位，丢弃；
//   - 「Reserved」是保留段（TEST-NET 等）的占位词，同样丢弃——直接渲染会得到
//     「Reserved Reserved」这种比不显示更糟的结果（实测 192.0.2.1 就是这样）；
//   - 国内地址省掉「中国」前缀，且相邻重复项（直辖市常见的 北京市|北京市）只留一份。
func formatRegion(raw string) string {
	fields := strings.Split(raw, "|")
	get := func(i int) string {
		if i >= len(fields) {
			return ""
		}
		v := strings.TrimSpace(fields[i])
		if v == "0" || strings.EqualFold(v, "reserved") {
			return ""
		}
		return v
	}
	country, province, city := get(0), get(1), get(2)

	parts := make([]string, 0, 3)
	if country != "" && country != "中国" && country != "China" {
		parts = append(parts, country)
	}
	for _, v := range []string{province, city} {
		if v == "" {
			continue
		}
		if len(parts) > 0 && parts[len(parts)-1] == v {
			continue // 相邻重名（北京市|北京市）只留一份
		}
		parts = append(parts, v)
	}
	return strings.Join(parts, " ")
}
