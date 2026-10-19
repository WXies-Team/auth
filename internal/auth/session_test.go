package auth

import (
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/WXies-Team/auth/internal/protocol"
)

// 设备标签三态：认出机型给「系统 · 机型」，认出浏览器给「浏览器 · 系统」，
// 都认不出就存 UA 原文截断——列表宁可给一串可辨认的 UA，也不要空着一列。
func TestSessionDeviceLabel(t *testing.T) {
	cases := []struct{ ua, want string }{
		{"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
			"Android · Pixel 8"},
		{"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			"Chrome · Linux"},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.6099.129",
			"Edge · Windows"},
		{"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
			"Safari · macOS"},
		{"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
			"iOS · iPhone"},
		{"curl/8.4.0", "curl/8.4.0"}, // 认不出 → 原文
		{"", "未知设备"},
	}
	for _, c := range cases {
		if got := shortDevice(c.ua); got != c.want {
			t.Errorf("shortDevice(%q) = %q，应为 %q", c.ua, got, c.want)
		}
	}
	// 认不出且超长的 UA 要截到 191 字（device 是 VARCHAR(191)），按 **rune** 切——
	// 按字节切会把多字节字符切半个，列表里就出现乱码
	if got := shortDevice(strings.Repeat("超", 400)); len([]rune(got)) != 191 {
		t.Errorf("超长 UA 应截到 191 字，得到 %d 字", len([]rune(got)))
	}
}

// 会话生命周期：登录建行 → 列表含 current 与解析出的设备标签 → 踢目标（被踢 401、
// 其它仍 200）→ revoke-others 只剩 current → 踢自己幂等 → logout 两层一起吊销。
func TestSessionLifecycle(t *testing.T) {
	svc, mailer := newTestService(t)
	const androidUA = "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36"
	const windowsUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

	// 下面三个闭包都要用 uid：先声明、拿到第一个会话后回填（Go 的作用域从声明处起算）
	var callerUID int64
	list := func(currentSID int64) []protocol.SessionInfo {
		t.Helper()
		items, err := svc.ListSessions(callerUID, currentSID)
		if err != nil {
			t.Fatalf("取设备列表失败: %v", err)
		}
		return items
	}
	verifyOK := func(tok, tag string) {
		t.Helper()
		if _, err := svc.Verify("Bearer "+tok, "calorie-diary"); err != nil {
			t.Errorf("%s 的 token 应通过 verify，得到 %v", tag, err)
		}
	}
	verifyDead := func(tok, tag string) {
		t.Helper()
		_, err := svc.Verify("Bearer "+tok, "calorie-diary")
		if code, msg := httpMsg(err); code != 401 {
			t.Errorf("%s 的 token 应被 verify 判 401，得到 %d %q", tag, code, msg)
		}
	}

	// 设备 A：注册即登录
	reg := registerViaCode(t, svc, mailer, "sess@example.com", "secret123")
	cA, err := svc.ValidUserID("Bearer " + reg.Token)
	if err != nil {
		t.Fatalf("注册 token 校验失败: %v", err)
	}
	callerUID = cA.UID

	// 设备 B：密码登录，UA 带机型 → 设备标签按 UA 解析，IP 按 clientIP 口径记
	respB, err := svc.Login("sess@example.com", "secret123", "calorie-diary",
		SessionMeta{IP: "10.0.0.7", UserAgent: androidUA})
	if err != nil {
		t.Fatalf("登录失败: %v", err)
	}
	cB, err := svc.ValidUserID("Bearer " + respB.Token)
	if err != nil {
		t.Fatalf("B 的 token 校验失败: %v", err)
	}
	if cB.SID == cA.SID || cB.SID == 0 {
		t.Fatalf("每次登录应各建一个会话: A=%d B=%d", cA.SID, cB.SID)
	}

	// 列表：两台、current 只标本次这台、设备与 IP 落对、刚用过的排最前
	items := list(cB.SID)
	if len(items) != 2 {
		t.Fatalf("应有 2 台活跃设备，得到 %d", len(items))
	}
	var currents int
	for _, it := range items {
		if it.Current {
			currents++
		}
		if it.App != "calorie-diary" {
			t.Errorf("会话 %d 的 app 应为 calorie-diary，得到 %q", it.ID, it.App)
		}
		if it.CreatedAt <= 0 || it.LastSeenAt <= 0 {
			t.Errorf("会话 %d 的时间戳应为毫秒正整数，得到 created=%d seen=%d",
				it.ID, it.CreatedAt, it.LastSeenAt)
		}
		if it.ID == cB.SID {
			if it.Device != "Android · Pixel 8" {
				t.Errorf("B 的设备标签应按 UA 解析成 %q，得到 %q", "Android · Pixel 8", it.Device)
			}
			if it.IP != "10.0.0.7" {
				t.Errorf("B 的 IP 应为 10.0.0.7，得到 %q", it.IP)
			}
		}
	}
	if currents != 1 {
		t.Errorf("current 应恰好标 1 台，得到 %d", currents)
	}
	if items[0].ID != cB.SID {
		t.Errorf("列表应按活跃时间倒序，首项应是刚登录的 B（%d），得到 %d", cB.SID, items[0].ID)
	}
	verifyOK(reg.Token, "A")
	verifyOK(respB.Token, "B")

	// 踢 A：被踢 token 在 verify 与 auth 端点都当场失效，B 不受影响
	if err := svc.RevokeSession(callerUID, cA.SID); err != nil {
		t.Fatalf("踢 A 失败: %v", err)
	}
	verifyDead(reg.Token, "A")
	_, authErr := svc.ValidUserID("Bearer " + reg.Token)
	if code, _ := httpMsg(authErr); code != 401 {
		t.Errorf("被踢 token 不该再过 auth 端点，得到 %d", code)
	}
	verifyOK(respB.Token, "B")
	if items := list(cB.SID); len(items) != 1 || items[0].ID != cB.SID {
		t.Errorf("踢掉 A 后列表应只剩 B，得到 %+v", items)
	}

	// revoke-others：只动会话层，当前 token 照用
	respC, err := svc.Login("sess@example.com", "secret123", "calorie-diary",
		SessionMeta{IP: "10.0.0.9", UserAgent: windowsUA})
	if err != nil {
		t.Fatalf("登录第三台失败: %v", err)
	}
	cC, err := svc.ValidUserID("Bearer " + respC.Token)
	if err != nil {
		t.Fatalf("C 的 token 校验失败: %v", err)
	}
	if err := svc.RevokeOtherSessions(callerUID, cB.SID); err != nil {
		t.Fatalf("退出其它设备失败: %v", err)
	}
	verifyDead(respC.Token, "C")
	verifyOK(respB.Token, "B（当前设备）")
	if items := list(cB.SID); len(items) != 1 || items[0].ID != cB.SID {
		t.Errorf("revoke-others 后应只剩 current，得到 %+v", items)
	}
	if cC.SID == cB.SID {
		t.Error("C 与 B 不该共用会话 id")
	}

	// 别人的会话与不存在的 id 同回 404（不给存在性探针），踢自己幂等
	other := registerViaCode(t, svc, mailer, "other-sess@example.com", "secret123")
	cO, err := svc.ValidUserID("Bearer " + other.Token)
	if err != nil {
		t.Fatalf("另一账号校验失败: %v", err)
	}
	if code, _ := httpMsg(svc.RevokeSession(cO.UID, cB.SID)); code != 404 {
		t.Errorf("踢别人的会话应 404，得到 %d", code)
	}
	if code, _ := httpMsg(svc.RevokeSession(callerUID, 1234567890123456789)); code != 404 {
		t.Errorf("不存在的会话应 404，得到 %d", code)
	}
	verifyOK(respB.Token, "B（被别人踢未遂）")
	if err := svc.RevokeSession(callerUID, cB.SID); err != nil {
		t.Fatalf("踢自己失败: %v", err)
	}
	if err := svc.RevokeSession(callerUID, cB.SID); err != nil {
		t.Errorf("重复踢应幂等 200，得到 %v", err)
	}
	verifyDead(respB.Token, "B")

	// logout：token 层与会话层一起吊销，不留活死行
	respD, err := svc.Login("sess@example.com", "secret123", "calorie-diary", testMeta)
	if err != nil {
		t.Fatalf("登录第四台失败: %v", err)
	}
	verifyOK(respD.Token, "D")
	if err := svc.Logout(callerUID); err != nil {
		t.Fatalf("登出失败: %v", err)
	}
	verifyDead(respD.Token, "D")
	var active int
	if err := svc.pool.QueryRow(
		"SELECT COUNT(*) FROM sessions WHERE user_id = ? AND revoked_at IS NULL", callerUID).
		Scan(&active); err != nil || active != 0 {
		t.Errorf("登出后不该剩活跃会话，得到 %d (err=%v)", active, err)
	}
	if items := list(cB.SID); len(items) != 0 {
		t.Errorf("登出后列表应为空，得到 %+v", items)
	}
}

// 会话表上线前签发的 token 没有 sid：verify 与 auth 端点一律 401，逼客户端重登
// （作者定案：切换后全部重登、线上存量为 0，不为它们留兼容分支）。
// ver 取 1 与刚注册的版本一致，确保 401 来自缺 sid 而不是版本对不上。
func TestTokenWithoutSIDIsRejected(t *testing.T) {
	svc, mailer := newTestService(t)
	reg := registerViaCode(t, svc, mailer, "legacy@example.com", "secret123")
	caller, err := svc.ValidUserID("Bearer " + reg.Token)
	if err != nil {
		t.Fatalf("注册 token 校验失败: %v", err)
	}
	verifyOKNow := func(tok, tag string) {
		t.Helper()
		if _, err := svc.Verify("Bearer "+tok, "calorie-diary"); err != nil {
			t.Fatalf("%s: 新 token 应通过 verify: %v", tag, err)
		}
	}
	verifyOKNow(reg.Token, "带 sid 的新 token")

	// 形状 = 切换前签的 token：uid/ver/aud/iss/exp 齐全，唯独没有 sid
	legacy := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"aud":   "calorie-diary",
		"iss":   issuer,
		"uid":   caller.UID,
		"email": caller.Email,
		"ver":   1,
		"exp":   time.Now().Add(time.Hour).Unix(),
	})
	tok, err := legacy.SignedString([]byte(testSecret))
	if err != nil {
		t.Fatalf("签 legacy token: %v", err)
	}

	_, verifyErr := svc.Verify("Bearer "+tok, "calorie-diary")
	if code, msg := httpMsg(verifyErr); code != 401 {
		t.Errorf("无 sid 的 token 应被 verify 判 401，得到 %d %q", code, msg)
	}
	_, authErr := svc.ValidUserID("Bearer " + tok)
	if code, _ := httpMsg(authErr); code != 401 {
		t.Errorf("无 sid 的 token 应被 auth 端点判 401，得到 %d", code)
	}
}
