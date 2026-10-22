package auth

import (
	"database/sql"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/WXies-Team/auth/internal/protocol"
)

// 设备标签四态：App 规范 UA 出机型、浏览器 UA 出「系统 · 机型」/「浏览器 · 系统」、
// 都认不出（脚本、残缺 UA、裸 ktor/okhttp 这类库名）统一「未知设备」——
// 原文仍在 user_agent 列，绝不把库名当设备名显示。
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
		// App 规范 UA（产品名/版本 + 平台段）→ 友好机型，不带「系统 · 」前缀
		{"calorie-diary/1.2.3 (Android; Pixel 8)", "Pixel 8"},
		{"expense-diary/2.0.1 (iOS; iPhone 15 Pro)", "iPhone 15 Pro"},
		{"calorie-diary/1.0 (Android)", "Android"},
		// 品牌+型号的含空格机型：括号段第 2 段整段是机型，按空格再切会把品牌切掉
		{"calorie-diary/1.2.3 (Android; Xiaomi 23127PN0CC)", "Xiaomi 23127PN0CC"},
		// 浏览器 UA 带含空格机型：Mozilla 挡板让 parseAppUA 不接手，走 classifyUA 出
		//「系统 · 机型」而不是裸机型
		{"Mozilla/5.0 (Linux; Android 14; Xiaomi 23127PN0CC) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
			"Android · Xiaomi 23127PN0CC"},
		// 裸库名 UA（无平台段 / 头部不是产品名版本）与脚本 UA：未知设备，不存原文；
		// ktor-client/2.0 是存量行 device 列里的真实坏快照原文，钉住现算不吃它
		{"curl/8.4.0", "未知设备"},
		{"okhttp/4.12.0", "未知设备"},
		{"ktor-client/2.0", "未知设备"},
		{"Ktor client/2.0", "未知设备"},
		{"", "未知设备"},
	}
	for _, c := range cases {
		if got := shortDevice(c.ua); got != c.want {
			t.Errorf("shortDevice(%q) = %q，应为 %q", c.ua, got, c.want)
		}
	}
	// 认不出的超长 UA 落「未知设备」（不截原文进设备列）；截 rune 的能力仍要保住
	//（user_agent 列按 512 字截断用同一个函数，按**字节**切会把多字节字符切半个）
	if got := shortDevice(strings.Repeat("超", 400)); got != "未知设备" {
		t.Errorf("认不出的超长 UA 应回「未知设备」，得到 %q", got)
	}
	if got := truncateRunes(strings.Repeat("超", 600), 512); len([]rune(got)) != 512 {
		t.Errorf("user_agent 截断应按 rune 切到 512 字，得到 %d 字", len([]rune(got)))
	}
}

// UA Client Hints 后缀（web 登录采集的浏览器机型）：有后缀且有机型 → 「平台 · 机型」；
// 无后缀（存量行 / App 行）、残缺后缀（标记后没分号、两段全空）一律剥掉标记走既有
// 解析——零回归。缩水 UA（机型抹成 K）是 CH 机型真正补位的场景。
func TestShortDeviceClientHintsSuffix(t *testing.T) {
	reducedUA := "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36"
	cases := []struct{ ua, want string }{
		// 有后缀：CH 机型优先——UA 里机型已缩水成 K，CH 是唯一真实机型
		{reducedUA + " | CH:Android;Pixel 5", "Android · Pixel 5"},
		// 机型在、平台缺省：只出机型
		{reducedUA + " | CH:;Pixel 5", "Pixel 5"},
		// 残缺后缀：没有分号 / 标记后全空 → 剥掉标记，走既有 UA 解析
		{reducedUA + " | CH:Android", "Android · K"},
		{reducedUA + " | CH:", "Android · K"},
		{reducedUA + " | CH:;", "Android · K"},
		// 无后缀：既有口径一字不变（老行、App 行）
		{reducedUA, "Android · K"},
		{"calorie-diary/1.2.3 (Android; Pixel 8)", "Pixel 8"},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.6099.129",
			"Edge · Windows"},
		{"", "未知设备"},
	}
	for _, c := range cases {
		if got := shortDevice(c.ua); got != c.want {
			t.Errorf("shortDevice(%q) = %q，应为 %q", c.ua, got, c.want)
		}
	}
}

// uaWithCH 是存储串的拼接口径：无 CH / 空 model（桌面 Chrome 的 `Sec-CH-UA-Model:
// ""`）不加后缀；头值是结构化 quoted-string，去引号且剔掉 | ; 分隔符与控制字符
//（分隔符是解析边界，留着等于把 splitCH 交给客户端摆布）；超长 base 先按
// 512-后缀长度截断再拼，后缀一定落进 512 字内。
func TestSessionMetaUAWithCH(t *testing.T) {
	ua := "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	if got := (SessionMeta{UserAgent: ua}).uaWithCH(); got != ua {
		t.Errorf("无 CH 不该加后缀，得到 %q", got)
	}
	if got := (SessionMeta{UserAgent: ua, CHPlatform: `"Windows"`, CHModel: `""`}).uaWithCH(); got != ua {
		t.Errorf("空 model 不该加后缀，得到 %q", got)
	}
	if got, want := (SessionMeta{UserAgent: ua, CHPlatform: `"Android"`, CHModel: `"Pixel 5"`}).uaWithCH(),
		ua+" | CH:Android;Pixel 5"; got != want {
		t.Errorf("带 CH 的存储串应为 %q，得到 %q", want, got)
	}
	if got, want := (SessionMeta{UserAgent: ua, CHModel: "A|B;C\x00"}).uaWithCH(), ua+" | CH:;ABC"; got != want {
		t.Errorf("CH 值里的分隔符/控制字符应被剔除，得到 %q", got)
	}
	// 超长 base：截断不许把尾部后缀切掉，且 base 段恰为 512-后缀长度
	long := strings.Repeat("超", 600)
	suffix := " | CH:Android;Pixel 5"
	got := (SessionMeta{UserAgent: long, CHPlatform: `"Android"`, CHModel: `"Pixel 5"`}).uaWithCH()
	if r := []rune(got); len(r) != 512 {
		t.Errorf("存储串应含后缀恰为 512 字，得到 %d 字", len(r))
	}
	if !strings.HasSuffix(got, suffix) {
		t.Errorf("截断不该把 CH 后缀切掉，串尾为 %q", got[len(got)-len(suffix):])
	}
	if base, _, _, _ := splitCH(got); base != string([]rune(long)[:512-len([]rune(suffix))]) {
		t.Errorf("base 应恰截到 512-后缀长度，得到 %d 字", len([]rune(base)))
	}
}

// sidStr 把 int64 的 sid 换成列表回执里的十进制字符串形态（本批起 SessionInfo.ID
// 一律以字符串输出，避免 63 位雪花被浏览器 JSON.parse 抹圆）。
func sidStr(id int64) string { return strconv.FormatInt(id, 10) }

// 存量行自愈：老服务端时期认不出库名 UA，device 列快照存了 UA 原文
//（ktor-client/2.0）。展示改为读取时按 user_agent 现算后，同一行在用户端
// ListSessions 与管理端 AdminListSessions 都回现算结果；device 列本身不动
//（零迁移，历史快照/排障照旧）。
func TestSessionDeviceLabelHealsLegacyRows(t *testing.T) {
	svc, _ := newTestService(t)
	const legacyUA = "ktor-client/2.0"
	const appUA = "calorie-diary/1.2.3 (Android; Xiaomi 23127PN0CC)"
	const uid = int64(8801234)
	now := time.Now().UnixMilli()
	if _, err := svc.pool.Exec(
		"INSERT INTO users (id, email, created_at, token_version) VALUES (?,?,?,1)", uid, "sess-heal@example.com", now); err != nil {
		t.Fatalf("落用户: %v", err)
	}
	// 两行的 device 列都是「坏快照」（存 UA 原文），user_agent 才是现算的输入
	rows := []struct {
		id int64
		ua string
	}{
		{now + 1, legacyUA},
		{now + 2, appUA},
	}
	for _, r := range rows {
		if _, err := svc.pool.Exec(
			"INSERT INTO sessions (id, user_id, app, device, ip, user_agent, created_at, last_seen_at)"+
				" VALUES (?,?,?,?,?,?,?,?)",
			r.id, uid, "calorie-diary", legacyUA, "127.0.0.1", r.ua, now, now); err != nil {
			t.Fatalf("落会话: %v", err)
		}
	}
	want := map[string]string{
		sidStr(now + 1): "未知设备",              // 库名 UA 现算不出设备
		sidStr(now + 2): "Xiaomi 23127PN0CC", // 品牌 + 含空格型号整段为机型
	}
	items, err := svc.ListSessions(uid, 0, nil)
	if err != nil || len(items) != 2 {
		t.Fatalf("取设备列表: %v（%d 行）", err, len(items))
	}
	for _, it := range items {
		if it.Device != want[it.ID] {
			t.Errorf("用户端会话 %s 的展示设备应为 %q（按 user_agent 现算），得到 %q",
				it.ID, want[it.ID], it.Device)
		}
	}
	admin, _, _, err := svc.AdminListSessions(uid, nil, "", 10, 0)
	if err != nil || len(admin) != 2 {
		t.Fatalf("管理端取会话: %v（%d 行）", err, len(admin))
	}
	for _, it := range admin {
		if it.Device != want[it.ID] {
			t.Errorf("管理端会话 %s 的展示设备应为 %q（与用户端同源现算），得到 %q",
				it.ID, want[it.ID], it.Device)
		}
	}
	// 读不写：device 列的坏快照原样保留（历史快照/排障，零迁移）
	var stored string
	if err := svc.pool.QueryRow("SELECT device FROM sessions WHERE id = ?", now+1).Scan(&stored); err != nil {
		t.Fatalf("读 device 快照列: %v", err)
	}
	if stored != legacyUA {
		t.Errorf("device 快照列不该被展示逻辑改写，得到 %q", stored)
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
		items, err := svc.ListSessions(callerUID, currentSID, nil)
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
			t.Errorf("会话 %s 的 app 应为 calorie-diary，得到 %q", it.ID, it.App)
		}
		if it.CreatedAt <= 0 || it.LastSeenAt <= 0 {
			t.Errorf("会话 %s 的时间戳应为毫秒正整数，得到 created=%d seen=%d",
				it.ID, it.CreatedAt, it.LastSeenAt)
		}
		if it.ID == sidStr(cB.SID) {
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
	if items[0].ID != sidStr(cB.SID) {
		t.Errorf("列表应按活跃时间倒序，首项应是刚登录的 B（%s），得到 %s", sidStr(cB.SID), items[0].ID)
	}
	verifyOK(reg.Token, "A")
	verifyOK(respB.Token, "B")

	// 踢 A：被踢 token 在 verify 与 auth 端点都当场失效，B 不受影响
	if err := svc.RevokeSession(callerUID, cA.SID, nil); err != nil {
		t.Fatalf("踢 A 失败: %v", err)
	}
	verifyDead(reg.Token, "A")
	_, authErr := svc.ValidUserID("Bearer " + reg.Token)
	if code, _ := httpMsg(authErr); code != 401 {
		t.Errorf("被踢 token 不该再过 auth 端点，得到 %d", code)
	}
	verifyOK(respB.Token, "B")
	if items := list(cB.SID); len(items) != 1 || items[0].ID != sidStr(cB.SID) {
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
	if err := svc.RevokeOtherSessions(callerUID, cB.SID, nil); err != nil {
		t.Fatalf("退出其它设备失败: %v", err)
	}
	verifyDead(respC.Token, "C")
	verifyOK(respB.Token, "B（当前设备）")
	if items := list(cB.SID); len(items) != 1 || items[0].ID != sidStr(cB.SID) {
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
	if code, _ := httpMsg(svc.RevokeSession(cO.UID, cB.SID, nil)); code != 404 {
		t.Errorf("踢别人的会话应 404，得到 %d", code)
	}
	if code, _ := httpMsg(svc.RevokeSession(callerUID, 1234567890123456789, nil)); code != 404 {
		t.Errorf("不存在的会话应 404，得到 %d", code)
	}
	verifyOK(respB.Token, "B（被别人踢未遂）")
	if err := svc.RevokeSession(callerUID, cB.SID, nil); err != nil {
		t.Fatalf("踢自己失败: %v", err)
	}
	if err := svc.RevokeSession(callerUID, cB.SID, nil); err != nil {
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

// 会话作用域与批量退出（本批拍板）：apps 非空（Bearer 侧 = 自己 app 的会话）只
// 见/只踢自己 app 的行，apps=nil（cookie 侧）是全景；超范围与查无此行同 404；
// 批量退出整批校验、任一不合法整体 404、回执是实际踢掉的台数。
func TestSessionScopeAndBatchRevoke(t *testing.T) {
	svc, mailer := newTestService(t)
	reg := registerViaCode(t, svc, mailer, "scope-sess@example.com", "secret123") // calorie 会话
	c, err := svc.ValidUserID("Bearer " + reg.Token)
	if err != nil {
		t.Fatalf("解析会话: %v", err)
	}
	respE, err := svc.Login("scope-sess@example.com", "secret123", "expense-diary", testMeta)
	if err != nil {
		t.Fatalf("expense 登录: %v", err)
	}
	cE, err := svc.ValidUserID("Bearer " + respE.Token)
	if err != nil {
		t.Fatalf("解析 expense 会话: %v", err)
	}
	ws, err := svc.CreateWebSession(c.UID, SessionMeta{IP: "10.0.0.1", UserAgent: "Mozilla/5.0 test"})
	if err != nil {
		t.Fatalf("建 web 会话: %v", err)
	}

	calOnly := []string{"calorie-diary"}
	// Bearer（aud=calorie-diary）视角：只看得见自己 app 的一条
	items, err := svc.ListSessions(c.UID, c.SID, calOnly)
	if err != nil || len(items) != 1 || items[0].App != "calorie-diary" {
		t.Fatalf("calorie 视角应只见 1 条，得到 %+v err=%v", items, err)
	}
	if items[0].ID != sidStr(c.SID) || !items[0].Current {
		t.Errorf("ID 应是十进制字符串且 current 标本机，得到 %+v", items[0])
	}
	// cookie 侧（apps=nil）：三条全景
	all, err := svc.ListSessions(c.UID, 0, nil)
	if err != nil || len(all) != 3 {
		t.Fatalf("全景应 3 条，得到 %d err=%v", len(all), err)
	}
	// 超范围踢 expense 会话 → 404，会话仍活
	if code, msg := httpMsg(svc.RevokeSession(c.UID, cE.SID, calOnly)); code != 404 {
		t.Errorf("超范围踢应 404，得到 %d %q", code, msg)
	}
	var alive sql.NullInt64
	if err := svc.pool.QueryRow("SELECT revoked_at FROM sessions WHERE id = ?", cE.SID).Scan(&alive); err != nil || alive.Valid {
		t.Errorf("被拒的吊销不该生效，得到 valid=%v err=%v", alive.Valid, err)
	}
	// 全景视角踢同一条 → 成功
	if err := svc.RevokeSession(c.UID, cE.SID, nil); err != nil {
		t.Errorf("全景踢应成功: %v", err)
	}

	// 批量退出：calorie + web 一起走，回执 2
	n, err := svc.RevokeSessions(c.UID, []int64{c.SID, ws.SID}, nil)
	if err != nil || n != 2 {
		t.Fatalf("批量退出应踢 2 条，得到 n=%d err=%v", n, err)
	}
	// 两条都当场失效
	if _, err := svc.ValidUserID("Bearer " + reg.Token); err == nil {
		t.Error("被批量退出的 token 应 401")
	}
	if _, err := svc.ValidWebSession(ws.Token); err == nil {
		t.Error("被批量退出的 web 会话应 401")
	}

	// 整批校验：混入他人的会话 → 404 且一条都不踢（先补两条活的）
	resp2, err := svc.Login("scope-sess@example.com", "secret123", "calorie-diary", testMeta)
	if err != nil {
		t.Fatalf("再登录: %v", err)
	}
	c2, err := svc.ValidUserID("Bearer " + resp2.Token)
	if err != nil {
		t.Fatalf("解析新会话: %v", err)
	}
	other := registerViaCode(t, svc, mailer, "scope-other@example.com", "secret123")
	cO, err := svc.ValidUserID("Bearer " + other.Token)
	if err != nil {
		t.Fatalf("解析他人会话: %v", err)
	}
	_, batchErr := svc.RevokeSessions(c.UID, []int64{c2.SID, cO.SID}, nil)
	if code, _ := httpMsg(batchErr); code != 404 {
		t.Errorf("混入他人会话应整体 404，得到 %d", code)
	}
	var rest int
	if err := svc.pool.QueryRow(
		"SELECT COUNT(*) FROM sessions WHERE user_id = ? AND revoked_at IS NULL", c.UID).Scan(&rest); err != nil || rest != 1 {
		t.Errorf("整体被拒时不该踢掉任何会话，得到 %d err=%v", rest, err)
	}
	// 空数组 / 超上限都是 400（带下一步文案）
	_, emptyErr := svc.RevokeSessions(c.UID, nil, nil)
	if code, msg := httpMsg(emptyErr); code != 400 || !strings.Contains(msg, "勾选") {
		t.Errorf("空数组应 400 且点名勾选，得到 %d %q", code, msg)
	}
	ids := make([]int64, maxRevokeBatch+1)
	for i := range ids {
		ids[i] = int64(i + 1)
	}
	_, capErr := svc.RevokeSessions(c.UID, ids, nil)
	if code, _ := httpMsg(capErr); code != 400 {
		t.Errorf("超上限应 400，得到 %d", code)
	}
}
