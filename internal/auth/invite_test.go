package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// B9 邀请建号的用例：纯判定（本机真跑）+ 真库端到端（无 TEST_MYSQL_DSN 跳过，
// 与本仓其它真库用例同策略）。

// ---- 纯单测（无 DB）----

// 四态派生矩阵：接受 > 撤销 > 过期 > 待接受的判定序是契约——accepted/revoked 是
// 不可逆事实，先于时间判定；时间边界用「now > expires_at」（等于不算过期）。
func TestInviteStateMatrix(t *testing.T) {
	const (
		past   = int64(1000)
		future = int64(3000)
		now    = int64(2000)
	)
	cases := []struct {
		name                       string
		acceptedAt, revokedAt      int64
		expiresAt, now             int64
		want                       string
	}{
		{"待接受", 0, 0, future, now, "pending"},
		{"已过期", 0, 0, past, now, "expired"},
		{"到期边界仍算待接受", 0, 0, now, now, "pending"},
		{"已接受", future, 0, past, now, "accepted"},
		{"已撤销", 0, future, past, now, "revoked"},
		{"接受压过撤销", future, future, past, now, "accepted"},
		{"撤销压过过期", 0, future, past, now, "revoked"},
		{"未过期且已撤销", 0, future, future, now, "revoked"},
	}
	for _, c := range cases {
		if got := inviteState(c.acceptedAt, c.revokedAt, c.expiresAt, c.now); got != c.want {
			t.Errorf("%s：inviteState 应为 %q，得到 %q", c.name, c.want, got)
		}
	}
}

// token 的落库形态钉死：32 字节 CSPRNG → base64url 串，库里存**原样 SHA-256 的
// 小写 hex**（无盐、无迭代——与验证码同款 sha256Hex）。改成加盐/换算法会让
// 线上已发的邀请链接静默全部失效，所以这里打独立实现对拍 + 已知向量。
func TestInviteTokenHashIsPlainSHA256(t *testing.T) {
	// 已知向量：sha256("test") 的标准 hex，钉「小写 hex、无前缀、无换行」
	if got := sha256Hex("test"); got != "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" {
		t.Fatalf("sha256Hex 形态变了（影响验证码与邀请 token 的存量行）: %s", got)
	}
	for i := 0; i < 20; i++ {
		token, err := randomToken(inviteTokenBytes)
		if err != nil {
			t.Fatalf("生成 token: %v", err)
		}
		if len(token) < 40 {
			t.Errorf("32 字节的 base64url 串不该短于 40 字符，得到 %q", token)
		}
		if strings.ContainsAny(token, "+/=") {
			t.Errorf("token 必须是 base64url（链接里不能出现 + / =）: %q", token)
		}
		sum := sha256.Sum256([]byte(token))
		want := hex.EncodeToString(sum[:])
		if got := sha256Hex(token); got != want {
			t.Fatalf("邀请 token 的哈希应是对拍的裸 SHA-256：得到 %s，应为 %s", got, want)
		}
		if h := sha256Hex(token); len(h) != 64 {
			t.Errorf("哈希应恒 64 字符 hex，得到 %d", len(h))
		}
	}
	// 不同 token 不同哈希（32 字节随机数没有碰撞空间，这里钉的是「没做截断」）
	if sha256Hex("aaa") == sha256Hex("aab") {
		t.Error("不同输入不该得到相同哈希")
	}
}

// 空/空白 token 在**碰库之前**就被 400 拒掉（InviteLookup 走零值 Service 即可验证
// 这条早返回——它不落审计、不触 pool；顺带钉住错误是「链接不完整」而不是 500）。
func TestInviteLookupRejectsEmptyTokenWithoutDB(t *testing.T) {
	var s Service
	for _, tok := range []string{"", "   ", "\t\n"} {
		_, err := s.InviteLookup(tok)
		code, msg := httpMsg(err)
		if code != 400 || !strings.Contains(msg, "邀请链接不完整") {
			t.Errorf("空白 token 应 400「邀请链接不完整」，得到 code=%d msg=%q", code, msg)
		}
	}
}

// ---- 真库端到端（无 TEST_MYSQL_DSN 跳过）----

// inviteTokenIn 从记录器里的**最后一封**邀请信抠出明文 token（明文只在创建/重发
// 那一刻进邮件——这正是「库里只有哈希」的反面证据链）。
var inviteURLRe = regexp.MustCompile(`/web/invite\?token=([A-Za-z0-9_-]+)`)

func inviteTokenIn(t *testing.T, m *recordMailer) string {
	t.Helper()
	if len(m.sent) == 0 {
		t.Fatal("没有发出任何邮件")
	}
	last := m.sent[len(m.sent)-1]
	hit := inviteURLRe.FindStringSubmatch(last.html)
	if hit == nil {
		t.Fatalf("邀请邮件里找不到邀请链接（to=%s subject=%s）: %s", last.to, last.subject, last.html)
	}
	return hit[1]
}

// 建 → 查重 → 列表四态 → 重发旧失效 → 撤销幂等 → 过期判定 → 接受建号+自动登录。
func TestInviteEndToEnd(t *testing.T) {
	svc, mailer := newTestService(t)
	super := seedAdminUser(t, svc, mailer, "inv-super@example.com", adminRoleSuper)
	scope := AdminScope{Super: true}

	// ---- 创建：邮箱归一化、24h 有效期、信发到目标邮箱、库里只落哈希 ----
	before := time.Now().UnixMilli()
	expiresAt, err := svc.AdminCreateInvite(super, scope, "  Invitee@Example.COM ", "calorie-diary")
	if err != nil {
		t.Fatalf("创建邀请: %v", err)
	}
	if expiresAt < before+(24*time.Hour-time.Minute).Milliseconds() || expiresAt > time.Now().UnixMilli()+(24*time.Hour+time.Minute).Milliseconds() {
		t.Errorf("有效期应是创建起 24 小时，得到 %d", expiresAt)
	}
	if mailer.to != "invitee@example.com" || !strings.Contains(mailer.subject, "账号邀请") {
		t.Errorf("邀请信应收件归一化、主题带「账号邀请」，得到 to=%q subject=%q", mailer.to, mailer.subject)
	}
	token := inviteTokenIn(t, mailer)
	var stored string
	if err := svc.pool.QueryRow("SELECT token_hash FROM user_invites WHERE email = ?",
		"invitee@example.com").Scan(&stored); err != nil {
		t.Fatalf("查邀请行: %v", err)
	}
	sum := sha256.Sum256([]byte(token))
	if stored != hex.EncodeToString(sum[:]) {
		t.Errorf("库里应存 token 的裸 SHA-256，得到 %s", stored)
	}
	var plainHits int
	_ = svc.pool.QueryRow("SELECT COUNT(*) FROM user_invites WHERE token_hash = ?", token).Scan(&plainHits)
	if plainHits != 0 {
		t.Error("明文 token 不该出现在库里")
	}

	// ---- 查重：同邮箱待接受 400；已注册邮箱 400 ----
	_, err = svc.AdminCreateInvite(super, scope, "invitee@example.com", "calorie-diary")
	if code, msg := httpMsg(err); code != 400 || !strings.Contains(msg, "待接受") {
		t.Errorf("同邮箱待接受邀请应 400，得到 code=%d msg=%q", code, msg)
	}
	registerViaCode(t, svc, mailer, "taken@example.com", "secret123")
	_, err = svc.AdminCreateInvite(super, scope, "taken@example.com", "")
	if code, msg := httpMsg(err); code != 400 || !strings.Contains(msg, "已注册") {
		t.Errorf("已注册邮箱应 400「该邮箱已注册」，得到 code=%d msg=%q", code, msg)
	}

	// ---- 列表：字段与四态（此时 pending）----
	list, err := svc.AdminListInvites(scope, "")
	if err != nil {
		t.Fatalf("列邀请: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("应恰有 1 条邀请，得到 %d", len(list))
	}
	it := list[0]
	if it.Email != "invitee@example.com" || it.App != "calorie-diary" || it.State != "pending" {
		t.Errorf("邀请行不对: %+v", it)
	}
	if it.ID == "" || it.ExpiresAt != expiresAt {
		t.Errorf("id 应是十进制串、expiresAt 应回原值，得到 id=%q exp=%d", it.ID, it.ExpiresAt)
	}
	if _, err := strconv.ParseInt(it.ID, 10, 64); err != nil {
		t.Errorf("邀请 id 应能按十进制解析（JS 安全的字符串口径）: %v", err)
	}
	// query 过滤（邮箱片段）
	fl, err := svc.AdminListInvites(scope, "invitee")
	if err != nil || len(fl) != 1 {
		t.Errorf("query=invitee 应命中 1 条，得到 %d（%v）", len(fl), err)
	}
	fl, err = svc.AdminListInvites(scope, "nobody@example.com")
	if err != nil || len(fl) != 0 {
		t.Errorf("不匹配的 query 应回空，得到 %d（%v）", len(fl), err)
	}

	// ---- 无效 token：404（不给存在性线索的文案口径） ----
	_, err = svc.InviteLookup("not-a-real-token")
	if code, msg := httpMsg(err); code != 404 || !strings.Contains(msg, "邀请链接无效") {
		t.Errorf("乱写 token 应 404，得到 code=%d msg=%q", code, msg)
	}

	// ---- 过期：改列 → 列表 expired、Lookup 400；重发把它救活（新 token、续 24h） ----
	inviteID, _ := strconv.ParseInt(it.ID, 10, 64)
	if _, err := svc.pool.Exec("UPDATE user_invites SET expires_at = ? WHERE id = ?",
		time.Now().Add(-time.Minute).UnixMilli(), inviteID); err != nil {
		t.Fatalf("种过期: %v", err)
	}
	list, _ = svc.AdminListInvites(scope, "")
	if list[0].State != "expired" {
		t.Errorf("过了 expires_at 应派生 expired，得到 %q", list[0].State)
	}
	_, err = svc.InviteLookup(token)
	if code, msg := httpMsg(err); code != 400 || !strings.Contains(msg, "已过期") {
		t.Errorf("过期 token 应 400「已过期」，得到 code=%d msg=%q", code, msg)
	}
	if err := svc.AdminResendInvite(super, scope, inviteID); err != nil {
		t.Fatalf("重发过期邀请: %v", err)
	}
	resendToken := inviteTokenIn(t, mailer)
	if resendToken == token {
		t.Fatal("重发必须换新 token")
	}
	if _, err := svc.InviteLookup(token); err == nil {
		t.Error("旧 token 应随重发即刻失效")
	}
	if _, err := svc.InviteLookup(resendToken); err != nil {
		t.Errorf("新 token 应可用: %v", err)
	}
	list, _ = svc.AdminListInvites(scope, "")
	if list[0].State != "pending" {
		t.Errorf("重发后应回到 pending，得到 %q", list[0].State)
	}

	// ---- 撤销：幂等 + 400 口径 ----
	if err := svc.AdminRevokeInvite(super, scope, inviteID); err != nil {
		t.Fatalf("撤销邀请: %v", err)
	}
	if err := svc.AdminRevokeInvite(super, scope, inviteID); err != nil {
		t.Errorf("重复撤销应幂等: %v", err)
	}
	list, _ = svc.AdminListInvites(scope, "")
	if list[0].State != "revoked" {
		t.Errorf("撤销后应派生 revoked，得到 %q", list[0].State)
	}
	_, err = svc.InviteLookup(resendToken)
	if code, msg := httpMsg(err); code != 400 || !strings.Contains(msg, "已被撤销") {
		t.Errorf("已撤销的 token 应 400「该邀请已被撤销」，得到 code=%d msg=%q", code, msg)
	}
	if err := svc.AdminResendInvite(super, scope, inviteID); err == nil {
		t.Error("已撤销的邀请重发应 400（应重新发起）")
	}

	// ---- 接受：受限项目 → 建号 + project_access + 自动登录 + 单次消费 ----
	if err := svc.AdminSetRestricted(super, scope, "calorie-diary", true); err != nil {
		t.Fatalf("开项目限制: %v", err)
	}
	if _, err := svc.AdminCreateInvite(super, scope, "acceptee@example.com", "calorie-diary"); err != nil {
		t.Fatalf("创建接受用邀请: %v", err)
	}
	acceptToken := inviteTokenIn(t, mailer)
	res, err := svc.AcceptInvite(acceptToken, "secret123", "小邀", testMeta)
	if err != nil {
		t.Fatalf("接受邀请: %v", err)
	}
	if res.Session == nil || res.Session.Token == "" {
		t.Fatal("接受邀请应直接建 web 会话（自动登录）")
	}
	wc, err := svc.ValidWebSession(res.Session.Token)
	if err != nil || wc.Email != "acceptee@example.com" {
		t.Errorf("种下的会话应可直接进控制台：caller=%+v err=%v", wc, err)
	}
	var uid int64
	if err := svc.pool.QueryRow("SELECT id FROM users WHERE email = 'acceptee@example.com'").Scan(&uid); err != nil {
		t.Fatalf("接受后应建号: %v", err)
	}
	// 受限项目：project_access 落行（放行名单要的正是这行）
	var acc int
	if err := svc.pool.QueryRow("SELECT COUNT(*) FROM project_access WHERE app = 'calorie-diary' AND uid = ?",
		uid).Scan(&acc); err != nil || acc != 1 {
		t.Errorf("受限项目接受应自动加入 project_access，得到 acc=%d err=%v", acc, err)
	}
	// 昵称落档案
	var nick string
	_ = svc.pool.QueryRow("SELECT nickname FROM user_profile WHERE user_id = ?", uid).Scan(&nick)
	if nick != "小邀" {
		t.Errorf("昵称应落 user_profile，得到 %q", nick)
	}
	// 单次消费：同一 token 再接受 400
	if _, err := svc.AcceptInvite(acceptToken, "secret123", "", testMeta); err == nil {
		t.Error("邀请只能被接受一次")
	}
	list, _ = svc.AdminListInvites(AdminScope{Super: true}, "acceptee")
	if len(list) != 1 || list[0].State != "accepted" {
		t.Errorf("接受后列表应是 accepted，得到 %+v", list)
	}
	// 已接受的邀请不可撤销/重发
	acceptID, _ := strconv.ParseInt(list[0].ID, 10, 64)
	if err := svc.AdminRevokeInvite(super, scope, acceptID); err == nil {
		t.Error("已接受的邀请撤销应 400")
	}
	if err := svc.AdminResendInvite(super, scope, acceptID); err == nil {
		t.Error("已接受的邀请重发应 400")
	}

	// ---- 审计：四个事件落行，token 绝不进 detail ----
	for _, action := range []string{AuditUserInvite, AuditUserInviteResend, AuditUserInviteRevoke, AuditUserInviteAccept} {
		var n int
		if err := svc.pool.QueryRow("SELECT COUNT(*) FROM audit_logs WHERE action = ?", action).Scan(&n); err != nil || n == 0 {
			t.Errorf("审计缺 %s 行（n=%d err=%v）", action, n, err)
		}
	}
	var detail string
	if err := svc.pool.QueryRow("SELECT detail FROM audit_logs WHERE action = ? ORDER BY id LIMIT 1",
		AuditUserInvite).Scan(&detail); err == nil {
		for _, leak := range []string{token, resendToken, acceptToken} {
			if leak != "" && strings.Contains(detail, leak) {
				t.Errorf("审计 detail 不该出现 token: %s", detail)
			}
		}
	}
}

// 权限矩阵：super 可空 app / 任意白名单 app；app-admin 必带授权 app（空 → 403、
// 越权 → 403）；未知 slug 400、非法邮箱 400；列表按 scope 收权。
func TestInvitePermissionMatrix(t *testing.T) {
	svc, mailer := newTestService(t)
	super := seedAdminUser(t, svc, mailer, "invp-super@example.com", adminRoleSuper)
	appAdmin := seedAdminUser(t, svc, mailer, "invp-one@example.com", adminRoleAdmin)
	if err := svc.AdminSetScope(super, appAdmin.UID, "calorie-diary", true); err != nil {
		t.Fatalf("授 scope: %v", err)
	}
	appScope := AdminScope{Apps: []string{"calorie-diary"}}

	// app-admin 带授权 app：允许（空 app = 账号级邀请，只属平台管理员）
	if _, err := svc.AdminCreateInvite(appAdmin, appScope, "p-ok@example.com", "calorie-diary"); err != nil {
		t.Errorf("app-admin 邀请授权项目应成功: %v", err)
	}
	// 越权项目 → 403
	_, err := svc.AdminCreateInvite(appAdmin, appScope, "p-out@example.com", "expense-diary")
	if code, msg := httpMsg(err); code != 403 || !strings.Contains(msg, "管理权限") {
		t.Errorf("越权项目应 403，得到 code=%d msg=%q", code, msg)
	}
	// 空 app → 403（账号级邀请只属 super）
	_, err = svc.AdminCreateInvite(appAdmin, appScope, "p-none@example.com", "")
	if code, _ := httpMsg(err); code != 403 {
		t.Errorf("app-admin 空 app 应 403，得到 code=%d", code)
	}
	// 未知 slug → 400（super 也一样，先于 scope 判定）
	_, err = svc.AdminCreateInvite(super, AdminScope{Super: true}, "p-bad@example.com", "not-an-app")
	if code, msg := httpMsg(err); code != 400 || !strings.Contains(msg, "未知项目") {
		t.Errorf("未知项目应 400，得到 code=%d msg=%q", code, msg)
	}
	// 非法邮箱 → 400
	_, err = svc.AdminCreateInvite(super, AdminScope{Super: true}, "not-an-email", "")
	if code, _ := httpMsg(err); code != 400 {
		t.Errorf("非法邮箱应 400，得到 code=%d", code)
	}

	// 列表收权：app-admin 只见自己 app；零 scope admin 回空；super 全量
	if _, err := svc.AdminCreateInvite(super, AdminScope{Super: true}, "p-exp@example.com", "expense-diary"); err != nil {
		t.Fatalf("super 邀请 expense: %v", err)
	}
	one, err := svc.AdminListInvites(appScope, "")
	if err != nil || len(one) != 1 || one[0].App != "calorie-diary" {
		t.Errorf("app-admin 应只见 calorie 的邀请，得到 %+v（%v）", one, err)
	}
	all, err := svc.AdminListInvites(AdminScope{Super: true}, "")
	if err != nil || len(all) != 2 {
		t.Errorf("super 应见全部 2 条，得到 %d（%v）", len(all), err)
	}
	none, err := svc.AdminListInvites(AdminScope{}, "")
	if err != nil || len(none) != 0 {
		t.Errorf("零 scope admin 应回空列表，得到 %d（%v）", len(none), err)
	}
}
