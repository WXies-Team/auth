package auth

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/bwmarrin/snowflake"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"

	"github.com/WXies-Team/auth/internal/db"
)

const testSecret = "test-secret-do-not-use-in-prod-0123456789"

// recordMailer 记住最后一封信：真库测试**绝不能真发信**，但「验证码确实进了邮件正文」
// 这条链要验到——所以从正文里把码抠出来继续走注册。
// sent 留全量（改邮箱要断言新旧两封通知信都在，只留最后一封看不到旧邮箱那封）。
type mailRec struct{ to, subject, html string }

type recordMailer struct {
	to, subject, html string
	sent              []mailRec
}

func (m *recordMailer) Send(_ context.Context, to, subject, html string) error {
	m.to, m.subject, m.html = to, subject, html
	m.sent = append(m.sent, mailRec{to, subject, html})
	return nil
}

// newTestService 真库端到端：没有 TEST_MYSQL_DSN 就跳过（与 db 包同策略）。
// 这些断言逐条对着行为契约写——客户端依赖的行为，改了就会让老版本 App 登录不上。
func newTestService(t *testing.T) (*Service, *recordMailer) {
	t.Helper()
	dsn := os.Getenv("TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("未设置 TEST_MYSQL_DSN，跳过 auth 真库测试")
	}
	pool, err := db.Open(dsn)
	if err != nil {
		t.Fatalf("连接测试库: %v", err)
	}
	t.Cleanup(func() { _ = pool.Close() })
	if err := db.EnsureSchema(pool); err != nil {
		t.Fatalf("建表: %v", err)
	}
	// 每次跑清干净：测试库专用，绝不碰生产
	for _, table := range []string{"users", "otp_codes"} {
		if _, err := pool.Exec("DELETE FROM " + table); err != nil {
			t.Fatalf("清空 %s: %v", table, err)
		}
	}
	m := &recordMailer{}
	svc, err := NewService(pool, testSecret, m)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc, m
}

// registerViaCode 走真实链路：发码 → 从邮件正文取码 → 注册。
// 绕过发码直接塞一个码进去，测的就不是注册流程了。
func registerViaCode(t *testing.T, svc *Service, m *recordMailer, email, password string) *Response {
	t.Helper()
	if err := svc.SendCode(email, PurposeRegister); err != nil {
		t.Fatalf("发码失败: %v", err)
	}
	code := codeIn(t, m)
	resp, err := svc.Register(email, password, code, "calorie-diary")
	if err != nil {
		t.Fatalf("注册失败: %v", err)
	}
	return resp
}

// codeIn 从 mailer 记下的正文里取 6 位码（模板里没有别的 6 位数字）。
func codeIn(t *testing.T, m *recordMailer) string {
	t.Helper()
	code := regexp.MustCompile(`\d{6}`).FindString(m.html)
	if len(code) != 6 {
		t.Fatalf("邮件正文里找不到 6 位验证码: %s", m.html)
	}
	return code
}

func httpMsg(err error) (int, string) {
	var he *HTTPError
	if errors.As(err, &he) {
		return he.Code, he.Message
	}
	return 0, ""
}

// tokenClaimUID 直接读 JWT payload 里的 uid（json.Number，无损），用于断言
//「claims 里的雪花 id 与库里的 id 一字不差」。
func tokenClaimUID(t *testing.T, token string) int64 {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token 形状不对: %s", token)
	}
	payload, err := jwt.NewParser().DecodeSegment(parts[1])
	if err != nil {
		t.Fatalf("解码 payload: %v", err)
	}
	var claims struct {
		UID json.Number `json:"uid"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("解析 payload: %v", err)
	}
	uid, err := claims.UID.Int64()
	if err != nil {
		t.Fatalf("uid 不是整数（走了 float64？）: %v", err)
	}
	return uid
}

func TestRegisterLoginLogout(t *testing.T) {
	svc, mailer := newTestService(t)

	// 邮箱归一化：大写输入应存小写、返回小写。注册前必须先发码——验证码是注册的前置。
	reg := registerViaCode(t, svc, mailer, "  USER@Example.COM ", "secret123")
	if reg.Email != "user@example.com" {
		t.Errorf("邮箱未归一化，得到 %q", reg.Email)
	}
	if reg.Token == "" {
		t.Fatal("注册应直接返回可用 token（注册即登录）")
	}
	// 雪花 id 契约：claims.uid == 会话 uid == 库里的 users.id，且是超过 2^53 的
	// 大整数（float64 装不下——谁把 claims 解成 float64 谁就会拿到花位的 uid）
	claimUID := tokenClaimUID(t, reg.Token)
	if claimUID <= 1<<53 {
		t.Errorf("雪花 id 应超过 2^53，得到 %d——node/epoch 配置漂了", claimUID)
	}
	uid, err := svc.ValidUserID("Bearer " + reg.Token)
	if err != nil {
		t.Fatalf("有效 token 应通过校验: %v", err)
	}
	if uid.UID != claimUID {
		t.Errorf("claims.uid 与校验结果不一致: %d vs %d", claimUID, uid.UID)
	}
	var dbID int64
	if err := svc.pool.QueryRow("SELECT id FROM users WHERE email = 'user@example.com'").Scan(&dbID); err != nil || dbID != claimUID {
		t.Errorf("库里的 id 应与 claims 一致: db=%d claim=%d err=%v", dbID, claimUID, err)
	}

	// 不带验证码的注册必须被拒（强制验证码）
	_, eNoCode := svc.Register("fresh@example.com", "secret123", "", "calorie-diary")
	if code, msg := httpMsg(eNoCode); code != 400 || !strings.Contains(msg, "请先获取") {
		t.Errorf("无验证码注册应 400「请先获取验证码」，得到 %d %q", code, msg)
	}

	// 重复注册：400 且文案直白——查重在验证码之前
	_, err = svc.Register("user@example.com", "secret123", "", "calorie-diary")
	if code, msg := httpMsg(err); code != 400 || !strings.Contains(msg, "已注册") {
		t.Errorf("重复注册应 400「该邮箱已注册，请直接登录」，得到 %d %q", code, msg)
	}

	// 校验规则（邮箱格式与密码长度都在验证码之前，报错顺序一致）
	_, eMail := svc.Register("not-an-email", "secret123", "", "calorie-diary")
	if code, _ := httpMsg(eMail); code != 400 {
		t.Errorf("非法邮箱应 400，得到 %d", code)
	}
	_, eShort := svc.Register("a@b.com", "12345", "", "calorie-diary")
	if code, msg := httpMsg(eShort); code != 400 || !strings.Contains(msg, "至少8位") {
		t.Errorf("密码不足 8 位应 400 并提示现规则，得到 %d %q", code, msg)
	}

	// 登录：正常成功
	if _, err = svc.Login("USER@EXAMPLE.COM", "secret123", "calorie-diary"); err != nil {
		t.Errorf("登录失败: %v", err)
	}
	// 登录：邮箱不存在与密码错必须**同一句话**（否则可枚举注册过的邮箱）
	_, e1 := svc.Login("nobody@example.com", "secret123", "calorie-diary")
	_, e2 := svc.Login("user@example.com", "wrong-pass", "calorie-diary")
	c1, m1 := httpMsg(e1)
	c2, m2 := httpMsg(e2)
	if c1 != 401 || c2 != 401 {
		t.Errorf("凭据错误应 401，得到 %d / %d", c1, c2)
	}
	if m1 != m2 {
		t.Errorf("邮箱不存在与密码错误文案必须一致（防枚举）：%q vs %q", m1, m2)
	}
}

// aud 白名单：登录请求声明的应用决定 token 的 aud，白名单外一律拒（400，
// 这是客户端 bug 不是凭据问题）；不同应用签发的 token aud 各自正确。
func TestAppWhitelist(t *testing.T) {
	svc, mailer := newTestService(t)
	registerViaCode(t, svc, mailer, "app@example.com", "secret123")

	if err := validateApp("calorie-diary"); err != nil {
		t.Errorf("calorie-diary 应在白名单: %v", err)
	}
	if err := validateApp("expense-diary"); err != nil {
		t.Errorf("expense-diary 应在白名单: %v", err)
	}
	for _, bad := range []string{"", "evil-app", "CALORIE-DIARY"} {
		if err := validateApp(bad); err == nil {
			t.Errorf("%q 不该过白名单", bad)
		}
	}
	// 登录声明未知应用 → 400
	_, err := svc.Login("app@example.com", "secret123", "evil-app")
	if code, _ := httpMsg(err); code != 400 {
		t.Errorf("未知 app 登录应 400，得到 %d", code)
	}
	// expense-diary 登录成功且 aud=expense-diary
	resp, err := svc.Login("app@example.com", "secret123", "expense-diary")
	if err != nil {
		t.Fatalf("expense-diary 登录失败: %v", err)
	}
	claims := jwt.MapClaims{}
	if _, err := jwt.ParseWithClaims(resp.Token, claims, func(j *jwt.Token) (any, error) {
		return []byte(testSecret), nil
	}); err != nil {
		t.Fatalf("token 解析失败: %v", err)
	}
	aud, _ := claims.GetAudience()
	if len(aud) == 0 || aud[0] != "expense-diary" {
		t.Errorf("aud 应为 expense-diary，得到 %v", aud)
	}
}

func TestJWTClaimsAndRevocation(t *testing.T) {
	svc, mailer := newTestService(t)

	reg := registerViaCode(t, svc, mailer, "jwt@example.com", "secret123")

	claims := jwt.MapClaims{}
	parsed, err := jwt.ParseWithClaims(reg.Token, claims, func(j *jwt.Token) (any, error) {
		return []byte(testSecret), nil
	})
	if err != nil || !parsed.Valid {
		t.Fatalf("token 解析失败: %v", err)
	}
	aud, _ := claims.GetAudience()
	if len(aud) == 0 || aud[0] != "calorie-diary" {
		t.Errorf("aud 应为 calorie-diary，得到 %v", aud)
	}
	iss, _ := claims.GetIssuer()
	if iss != issuer {
		t.Errorf("iss 应为 %q，得到 %q", issuer, iss)
	}
	if claims["email"] != "jwt@example.com" {
		t.Errorf("email claim 错误: %v", claims["email"])
	}
	if ver, _ := claimInt64(claims, "ver"); ver != 1 {
		t.Errorf("ver 应为 1，得到 %v", claims["ver"])
	}

	// logout 后旧 token 必须失效——靠 ver 变化，不比对就等于没吊销
	caller, err := svc.ValidUserID("Bearer " + reg.Token)
	if err != nil {
		t.Fatalf("有效 token 应通过校验: %v", err)
	}
	if err := svc.Logout(caller.UID); err != nil {
		t.Fatalf("logout 失败: %v", err)
	}
	if _, err := svc.ValidUserID("Bearer " + reg.Token); err == nil {
		t.Error("登出后旧 token 仍可用——吊销没生效")
	}
	// 空 token 与篡改过的 token 都要 401
	if _, err := svc.ValidUserID(""); err == nil {
		t.Error("空 token 应 401")
	}
	if _, err := svc.ValidUserID("Bearer " + reg.Token + "x"); err == nil {
		t.Error("篡改过的 token 应 401")
	}
	// 拿别的密钥签的 token（伪造/旧密钥）必须 401
	forged := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"aud": "calorie-diary", "iss": issuer, "uid": caller.UID,
		"email": "jwt@example.com", "ver": 1, "exp": time.Now().Add(time.Hour).Unix(),
	})
	forgedTok, _ := forged.SignedString([]byte("some-other-secret-at-least-32-bytes-long!"))
	if _, err := svc.ValidUserID("Bearer " + forgedTok); err == nil {
		t.Error("异密钥签名的 token 应 401")
	}
	// 白名单外的 aud（哪怕签名正确）也进不了登录端点
	weird := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"aud": "evil-app", "iss": issuer, "uid": caller.UID,
		"email": "jwt@example.com", "ver": 1, "exp": time.Now().Add(time.Hour).Unix(),
	})
	weirdTok, _ := weird.SignedString([]byte(testSecret))
	if _, err := svc.ValidUserID("Bearer " + weirdTok); err == nil {
		t.Error("白名单外 aud 的 token 应 401")
	}
}

// /internal/verify 的边界：aud 必须与期望应用**精确**匹配——A 应用的 token 不能
// 被 B 应用的中间件接受；吊销后的 token 同样 401。
func TestVerifyAudienceBoundary(t *testing.T) {
	svc, mailer := newTestService(t)
	reg := registerViaCode(t, svc, mailer, "verify@example.com", "secret123")

	res, err := svc.Verify("Bearer "+reg.Token, "calorie-diary")
	if err != nil {
		t.Fatalf("期望应用匹配应通过: %v", err)
	}
	if res.UID == 0 || res.Email != "verify@example.com" || res.App != "calorie-diary" {
		t.Errorf("回执错误: %+v", res)
	}

	if _, err := svc.Verify("Bearer "+reg.Token, "expense-diary"); err == nil {
		t.Error("换期望 aud 必须 401（权限边界）")
	}
	if _, err := svc.Verify("Bearer "+reg.Token, "evil-app"); err == nil {
		t.Error("未知期望 aud 必须 401")
	}
	if _, err := svc.Verify("", "calorie-diary"); err == nil {
		t.Error("空 token 应 401")
	}

	caller, err := svc.ValidUserID("Bearer " + reg.Token)
	if err != nil {
		t.Fatalf("校验失败: %v", err)
	}
	if err := svc.Logout(caller.UID); err != nil {
		t.Fatalf("logout 失败: %v", err)
	}
	if _, err := svc.Verify("Bearer "+reg.Token, "calorie-diary"); err == nil {
		t.Error("吊销后的 token 在 /internal/verify 也必须 401")
	}
}

func TestChangePasswordRevokesOldSession(t *testing.T) {
	svc, mailer := newTestService(t)

	reg := registerViaCode(t, svc, mailer, "pw@example.com", "secret123")
	caller, err := svc.ValidUserID("Bearer " + reg.Token)
	if err != nil {
		t.Fatalf("校验失败: %v", err)
	}

	// 旧密码错 → 400
	_, eOld := svc.ChangePassword(caller, "wrong-old", "newsecret1")
	if code, _ := httpMsg(eOld); code != 400 {
		t.Errorf("原密码错误应 400，得到 %d", code)
	}
	// 改密成功 → 返回新 token，且**旧 token 立即失效**、新 token aud 沿用
	next, err := svc.ChangePassword(caller, "secret123", "newsecret1")
	if err != nil {
		t.Fatalf("改密失败: %v", err)
	}
	if _, err := svc.ValidUserID("Bearer " + reg.Token); err == nil {
		t.Error("改密后旧 token 应失效")
	}
	reissued, err := svc.ValidUserID("Bearer " + next.Token)
	if err != nil {
		t.Errorf("改密返回的新 token 应可用: %v", err)
	}
	if reissued.App != "calorie-diary" || reissued.UID != caller.UID {
		t.Errorf("重发 token 应沿用会话身份: %+v", reissued)
	}
	// 新密码登录成功、旧密码失败
	if _, err := svc.Login("pw@example.com", "newsecret1", "calorie-diary"); err != nil {
		t.Errorf("新密码登录失败: %v", err)
	}
	if _, err := svc.Login("pw@example.com", "secret123", "calorie-diary"); err == nil {
		t.Error("旧密码不应再能登录")
	}
}

// 验证码版改密全流程：发码进绑定邮箱 → 弱密码/错码不改 → 对码改密并吊销旧会话、
// 新 token 无缝续用 → 码用后即焚。
func TestChangePasswordByCode(t *testing.T) {
	svc, mailer := newTestService(t)
	reg := registerViaCode(t, svc, mailer, "chg@example.com", "secret123")
	caller, err := svc.ValidUserID("Bearer " + reg.Token)
	if err != nil {
		t.Fatalf("校验失败: %v", err)
	}

	// 收件人必须是 token 绑定的邮箱，主题必须是修改密码场景
	if err := svc.SendChangeCode(caller.UID); err != nil {
		t.Fatalf("发码失败: %v", err)
	}
	if mailer.to != "chg@example.com" {
		t.Errorf("验证码必须发给绑定邮箱，得到 %q", mailer.to)
	}
	if !strings.Contains(mailer.subject, "修改密码") {
		t.Errorf("主题应是修改密码场景，得到 %q", mailer.subject)
	}
	code := codeIn(t, mailer)

	// 弱密码 → 拒，且**不消耗码**（强度校验在验码之前）
	if _, err := svc.ChangePasswordByCode(caller, code, "short"); err == nil {
		t.Error("弱密码应被拒")
	}
	// 错码 → 不改密码，原密码照常能登录
	wrong := "000000"
	if wrong == code {
		wrong = "999999"
	}
	if _, err := svc.ChangePasswordByCode(caller, wrong, "newsecret1"); err == nil {
		t.Fatal("错码不该改密")
	}
	if _, err := svc.Login("chg@example.com", "secret123", "calorie-diary"); err != nil {
		t.Errorf("错码失败后原密码应仍可用: %v", err)
	}
	// 对码 → 改密成功，旧 token 当场失效、返回的新 token 可用
	next, err := svc.ChangePasswordByCode(caller, code, "newsecret1")
	if err != nil {
		t.Fatalf("改密失败: %v", err)
	}
	if _, err := svc.ValidUserID("Bearer " + reg.Token); err == nil {
		t.Error("改密后旧 token 应失效")
	}
	if _, err := svc.ValidUserID("Bearer " + next.Token); err != nil {
		t.Errorf("改密返回的新 token 应可用: %v", err)
	}
	if _, err := svc.Login("chg@example.com", "newsecret1", "calorie-diary"); err != nil {
		t.Errorf("新密码登录失败: %v", err)
	}
	// 码是一次性的：用过就不能再改
	if _, err := svc.ChangePasswordByCode(caller, code, "again123"); err == nil {
		t.Error("用过的验证码不能复用")
	}
}

// 注销：只删本服务数据（users 行 + 验证码行）；密码错什么都不删；
// 原 token 随账号一起失效。
func TestDeleteAccountRemovesData(t *testing.T) {
	svc, mailer := newTestService(t)

	reg := registerViaCode(t, svc, mailer, "del@example.com", "secret123")
	caller, err := svc.ValidUserID("Bearer " + reg.Token)
	if err != nil {
		t.Fatalf("校验失败: %v", err)
	}
	// 造几行验证码记录（发码流程正常会留下的东西）
	if _, err := svc.otps.issue(PurposeLogin, "del@example.com"); err != nil {
		t.Fatalf("造 otp 数据失败: %v", err)
	}

	// 密码错 → 400 且**什么都不删**
	eDel := svc.DeleteAccount(caller.UID, "wrong")
	if code, _ := httpMsg(eDel); code != 400 {
		t.Errorf("密码错误应 400，得到 %d", code)
	}
	var kept int
	if err := svc.pool.QueryRow("SELECT COUNT(*) FROM users").Scan(&kept); err != nil || kept != 1 {
		t.Errorf("密码错误时不该删数据，得到 %d (err=%v)", kept, err)
	}

	// 正确密码 → 账号与验证码记录都没了
	if err := svc.DeleteAccount(caller.UID, "secret123"); err != nil {
		t.Fatalf("注销失败: %v", err)
	}
	var users, otps int
	_ = svc.pool.QueryRow("SELECT COUNT(*) FROM users").Scan(&users)
	_ = svc.pool.QueryRow("SELECT COUNT(*) FROM otp_codes WHERE email = 'del@example.com'").Scan(&otps)
	if users != 0 || otps != 0 {
		t.Errorf("注销后应清空账号与验证码记录，得到 users=%d otps=%d", users, otps)
	}
	// 原 token 随账号一起失效
	if _, err := svc.ValidUserID("Bearer " + reg.Token); err == nil {
		t.Error("注销后原 token 应失效")
	}
}

// P2-10 的前置条件：dummy 哈希必须是**可解析的 cost12**，且比对真的要烧一轮 CPU。
// 被换成坏串 → 解析报错；被换成低 cost → 比真实登录快，反而成了新的计时侧信道。
func TestDummyPasswordHashIsPrecomputedCost12(t *testing.T) {
	cost, err := bcrypt.Cost([]byte(dummyPasswordHash))
	if err != nil {
		t.Fatalf("dummy 哈希解析不了（不是合法 bcrypt）: %v", err)
	}
	if cost != bcryptCost {
		t.Errorf("dummy 哈希 cost = %d，必须与真实登录一致（%d）", cost, bcryptCost)
	}

	start := time.Now()
	err = bcrypt.CompareHashAndPassword([]byte(dummyPasswordHash), []byte("not-the-password"))
	elapsed := time.Since(start)
	if err == nil {
		t.Error("dummy 哈希绝不能匹配任何密码——它不是可用凭据")
	}
	// cost12 一轮比对是百毫秒级；低于 50ms 说明这轮 bcrypt 根本没跑起来
	if elapsed < 50*time.Millisecond {
		t.Errorf("dummy 比对只花了 %v，拉平时延的目的没达成", elapsed)
	}
}

// 找回密码全流程：发码 → 错码不改、对码改 → 旧会话当场吊销、旧密码失效。
func TestResetPasswordRevokesSessions(t *testing.T) {
	svc, mailer := newTestService(t)
	reg := registerViaCode(t, svc, mailer, "reset@example.com", "secret123")

	// 用途分流：未注册邮箱不给找回码、已注册邮箱不给注册码（文案都直白）
	if err := svc.SendCode("nobody@example.com", PurposeReset); err == nil {
		t.Error("未注册邮箱发找回码应被拒")
	}
	if err := svc.SendCode("reset@example.com", PurposeRegister); err == nil {
		t.Error("已注册邮箱不该再收到注册码")
	}

	if err := svc.SendCode("reset@example.com", PurposeReset); err != nil {
		t.Fatalf("发码失败: %v", err)
	}
	if mailer.to != "reset@example.com" {
		t.Errorf("验证码必须发给本人，得到 %q", mailer.to)
	}
	if !strings.Contains(mailer.subject, "找回密码") {
		t.Errorf("主题应是找回密码场景，得到 %q", mailer.subject)
	}
	code := codeIn(t, mailer)
	wrong := "000000"
	if wrong == code {
		wrong = "999999"
	}

	// 错码：不改密码，原密码照常能登录
	if err := svc.ResetPassword("reset@example.com", wrong, "newsecret1"); err == nil {
		t.Fatal("错码不该重置密码")
	}
	if _, err := svc.Login("reset@example.com", "secret123", "calorie-diary"); err != nil {
		t.Errorf("错码失败后原密码应仍可用: %v", err)
	}

	// 对码：重置成功，且旧 token 立即失效（token_version+1）
	if err := svc.ResetPassword("reset@example.com", code, "newsecret1"); err != nil {
		t.Fatalf("重置失败: %v", err)
	}
	if _, err := svc.ValidUserID("Bearer " + reg.Token); err == nil {
		t.Error("重置密码后旧 token 必须失效")
	}
	if _, err := svc.Login("reset@example.com", "newsecret1", "calorie-diary"); err != nil {
		t.Errorf("新密码应可登录: %v", err)
	}
	if _, err := svc.Login("reset@example.com", "secret123", "calorie-diary"); err == nil {
		t.Error("旧密码不该还能登录")
	}
	// 码是一次性的：同一张码不能改两次密码
	if err := svc.ResetPassword("reset@example.com", code, "again123"); err == nil {
		t.Error("用过的验证码不能复用")
	}
}

type failMailer struct{}

func (failMailer) Send(context.Context, string, string, string) error { return errors.New("graph boom") }

// 发信失败必须**回滚冷却**：码已生成但信没发出去时若不作废，用户要白等 60 秒。
func TestSendCodeFailureRollsBackCooldown(t *testing.T) {
	svc, _ := newTestService(t)
	good := svc.mailer
	svc.mailer = failMailer{}

	err := svc.SendCode("bounce@example.com", PurposeRegister)
	if code, msg := httpMsg(err); code != 503 || !strings.Contains(msg, "稍后重试") {
		t.Fatalf("发信失败应 503 白话，得到 %d %q", code, msg)
	}
	svc.mailer = good
	if err := svc.SendCode("bounce@example.com", PurposeRegister); err != nil {
		t.Errorf("发信失败后应能立刻重试（冷却已回滚），得到: %v", err)
	}
}

// 邮箱验证码登录：登录码换 token；未注册、跨用途码、过期全被拒；
// 签发不动 token_version（与 Login 同语义：只签发、不吊销别的会话）。
func TestLoginByEmailCode(t *testing.T) {
	svc, mailer := newTestService(t)
	registerViaCode(t, svc, mailer, "login@example.com", "secret123")

	// 未注册：先于验码返回可执行文案——「验证码已过期」不是用户能执行的下一步
	_, err := svc.LoginByEmailCode("nobody@example.com", "123456", "calorie-diary")
	if code, msg := httpMsg(err); code != 400 || !strings.Contains(msg, "邮箱未注册，请先注册") {
		t.Errorf("未注册应 400「邮箱未注册，请先注册」，得到 %d %q", code, msg)
	}

	// 跨用途：找回密码的码不能拿来登录（purpose 进 key，五种码互不串用）
	if err := svc.SendCode("login@example.com", PurposeReset); err != nil {
		t.Fatalf("发找回码失败: %v", err)
	}
	if _, err := svc.LoginByEmailCode("login@example.com", codeIn(t, mailer), "calorie-diary"); err == nil {
		t.Error("找回密码码不该能登录")
	}

	// 正常登录
	if err := svc.SendCode("login@example.com", PurposeLogin); err != nil {
		t.Fatalf("发登录码失败: %v", err)
	}
	code := codeIn(t, mailer)
	resp, err := svc.LoginByEmailCode("login@example.com", code, "calorie-diary")
	if err != nil {
		t.Fatalf("验证码登录失败: %v", err)
	}
	if resp.Email != "login@example.com" || resp.Token == "" {
		t.Errorf("应返回 token 与邮箱，得到 %+v", resp)
	}
	if _, err := svc.ValidUserID("Bearer " + resp.Token); err != nil {
		t.Errorf("登录码签发的 token 应可用: %v", err)
	}
	// 用后即焚：同一个码不能再登第二次
	if _, err := svc.LoginByEmailCode("login@example.com", code, "calorie-diary"); err == nil {
		t.Error("登录码是一次性的，用过必须作废")
	}
}

// 改绑邮箱全流程：占用查重 / 与当前相同 / 密码错 / 码过期全拒 → 成功改绑、
// 现会话不吊销（不 bump token_version）、新旧邮箱各收一封通知信。
func TestChangeEmailFlow(t *testing.T) {
	svc, mailer := newTestService(t)
	reg := registerViaCode(t, svc, mailer, "old@example.com", "secret123")
	caller, err := svc.ValidUserID("Bearer " + reg.Token)
	if err != nil {
		t.Fatalf("校验失败: %v", err)
	}
	registerViaCode(t, svc, mailer, "taken@example.com", "secret123")

	// 占用查重：发码阶段就挡，不烧信
	err = svc.SendChangeEmailCode(caller.UID, "taken@example.com")
	if code, msg := httpMsg(err); code != 400 || !strings.Contains(msg, "该邮箱已被其他账号使用") {
		t.Errorf("被占用邮箱应 400「该邮箱已被其他账号使用」，得到 %d %q", code, msg)
	}
	// 与当前邮箱相同
	err = svc.SendChangeEmailCode(caller.UID, "old@example.com")
	if code, msg := httpMsg(err); code != 400 || !strings.Contains(msg, "相同") {
		t.Errorf("同邮箱应 400「新邮箱与当前邮箱相同」，得到 %d %q", code, msg)
	}

	// 发码到新邮箱：主题是「修改邮箱」验证码信
	if err := svc.SendChangeEmailCode(caller.UID, "new@example.com"); err != nil {
		t.Fatalf("改邮箱发码失败: %v", err)
	}
	if mailer.subject != "【Horatio 账号】修改邮箱验证码" {
		t.Errorf("发码信主题不对: %q", mailer.subject)
	}
	code1 := codeIn(t, mailer)

	// 密码错 → 400「原密码不正确」（与原密码改密同一口径），且**码不被消耗**
	err = svc.ChangeEmail(caller.UID, "wrong-pass", "new@example.com", code1)
	if code, msg := httpMsg(err); code != 400 || !strings.Contains(msg, "原密码不正确") {
		t.Errorf("密码错应 400「原密码不正确」，得到 %d %q", code, msg)
	}

	// 成功路径：上一步密码错没烧掉这个码
	if err := svc.ChangeEmail(caller.UID, "secret123", "new@example.com", code1); err != nil {
		t.Fatalf("改绑失败: %v", err)
	}
	var got string
	if err := svc.pool.QueryRow("SELECT email FROM users WHERE id = ?", caller.UID).Scan(&got); err != nil ||
		got != "new@example.com" {
		t.Errorf("users.email 应更新为 new@example.com，得到 %q (err=%v)", got, err)
	}
	if _, err := svc.ValidUserID("Bearer " + reg.Token); err != nil {
		t.Errorf("改邮箱不该吊销现会话（不 bump token_version）: %v", err)
	}

	// 两封通知信：旧邮箱收到「已更换」、新邮箱收到「已绑定」，正文都点名两个邮箱
	var noticeOld, noticeNew bool
	for _, m := range mailer.sent {
		if m.to == "old@example.com" && m.subject == "【Horatio 账号】绑定邮箱已更换" &&
			strings.Contains(m.html, "new@example.com") {
			noticeOld = true
		}
		if m.to == "new@example.com" && m.subject == "【Horatio 账号】新邮箱已绑定" &&
			strings.Contains(m.html, "old@example.com") {
			noticeNew = true
		}
	}
	if !noticeOld || !noticeNew {
		t.Errorf("新旧邮箱各应收到一封通知信，得到 旧=%v 新=%v", noticeOld, noticeNew)
	}
}

// 雪花 id：node 1 固定、单调递增、互不重复、超 2^53（客户端与 /internal/verify
// 的调用方都要能无损传输这些 id）。
func TestSnowflakeIDs(t *testing.T) {
	node, err := snowflake.NewNode(nodeID)
	if err != nil {
		t.Fatalf("雪花节点初始化失败: %v", err)
	}
	prev := node.Generate()
	for i := 0; i < 1000; i++ {
		cur := node.Generate()
		if cur <= prev {
			t.Fatalf("雪花 id 必须严格递增: %d 后出了 %d", prev, cur)
		}
		prev = cur
	}
	if int64(prev) <= 1<<53 {
		t.Errorf("雪花 id 应超过 2^53，得到 %d", int64(prev))
	}
}
