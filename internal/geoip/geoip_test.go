package geoip

import "testing"

// 归属地是「展示信息」，错了比没有更糟：内网/回环/非法/ IPv6 一律空串，
// 真实公网 IP 才给结果。这条钉住「不猜」的口径。
func TestRegionNeverGuesses(t *testing.T) {
	for _, ip := range []string{
		"", "127.0.0.1", "10.1.2.3", "192.168.1.1", "172.16.0.1",
		"::1", "fe80::1", "not-an-ip",   // 回环/链路本地/非法
		// TEST-NET 保留段：上游标 Reserved，曾被渲染成「Reserved Reserved」
		"192.0.2.1", "198.51.100.7", "203.0.113.9",
	} {
		if got := Region(ip); got != "" {
			t.Errorf("Region(%q) 应为空串（不猜），得到 %q", ip, got)
		}
	}
}

// 真实公网地址应能解析出中文归属地（数据库随二进制内嵌，测试不依赖网络）。
func TestRegionPublicCN(t *testing.T) {
	got := Region("114.114.114.114")
	if got == "" {
		t.Fatal("公共 DNS 114.114.114.114 应能解析出归属地")
	}
	if !containsAny(got, "江苏", "南京", "中国") {
		t.Errorf("归属地看起来不对：%q", got)
	}
}

// IPv6 走 v6 库（与 v4 分开），能解析出省市——双栈都要有归属地。
func TestRegionPublicV6(t *testing.T) {
	got := Region("2400:3200::1")
	if got == "" {
		t.Fatal("IPv6 2400:3200::1（阿里公共 DNS）应能解析出归属地")
	}
	if !containsAny(got, "浙江", "杭州") {
		t.Errorf("IPv6 归属地看起来不对：%q", got)
	}
}

// formatRegion 的收敛规则：丢 0 占位、国内省掉「中国」、省市重名只留一份。
func TestFormatRegion(t *testing.T) {
	cases := map[string]string{
		"中国|江苏省|南京市|0|CN":  "江苏省 南京市",
		"中国|北京市|北京市|0|CN":  "北京市",
		"美国|加利福尼亚州|洛杉矶|0|US": "美国 加利福尼亚州 洛杉矶",
		"0|0|0|0|0":            "",
		"中国|0|0|0|CN":         "",
		"Reserved|Reserved|0|0|ZZ": "",
		"Reserved|0|0|0|ZZ":        "",
	}
	for in, want := range cases {
		if got := formatRegion(in); got != want {
			t.Errorf("formatRegion(%q) = %q, want %q", in, got, want)
		}
	}
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if len(sub) > 0 && contains(s, sub) {
			return true
		}
	}
	return false
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
