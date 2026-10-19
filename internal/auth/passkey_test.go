package auth

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// newPasskeyUser 注册账号并回它的 Caller（Passkey 用例都要一个登录态身份）。
func newPasskeyUser(t *testing.T, svc *Service, mailer *recordMailer, email string) Caller {
	t.Helper()
	reg := registerViaCode(t, svc, mailer, email, "secret123")
	c, err := svc.ValidUserID("Bearer " + reg.Token)
	if err != nil {
		t.Fatalf("注册 token 校验失败: %v", err)
	}
	return c
}

// 仪式中间态的单次性：finish 无论成败都把行消费掉——同一个 ceremonyId 第二次来
// 一律 404（重放是最省事的绕过姿势，不给「失败后还能再试」的余地）。
func TestPasskeyCeremonySingleUse(t *testing.T) {
	svc, mailer := newTestService(t)
	c := newPasskeyUser(t, svc, mailer, "pk-single@example.com")

	creation, id, err := svc.BeginPasskeyRegistration(c)
	if err != nil {
		t.Fatalf("发起注册仪式: %v", err)
	}
	if creation == nil || len(creation.Response.Challenge) == 0 || id <= 0 {
		t.Fatalf("应同时回 CredentialCreation 与 ceremonyId，得到 %+v / %d", creation, id)
	}
	var kind string
	var owner int64
	if err := svc.pool.QueryRow("SELECT kind, user_id FROM webauthn_challenges WHERE id = ?", id).
		Scan(&kind, &owner); err != nil || kind != PasskeyCeremonyRegister || owner != c.UID {
		t.Errorf("仪式行应落库且绑发起者: kind=%q owner=%d err=%v", kind, owner, err)
	}

	// 塞垃圾响应体：库解析失败回 400，但**行已被消费**
	_, cerr := svc.FinishPasskeyRegistration(c, id, []byte(`{}`), SessionMeta{UserAgent: "Chrome"})
	if code, _ := httpMsg(cerr); code != 400 {
		t.Errorf("垃圾响应应 400，得到 %d %v", code, cerr)
	}
	// 重放同一 ceremonyId → 404
	_, cerr = svc.FinishPasskeyRegistration(c, id, []byte(`{}`), SessionMeta{UserAgent: "Chrome"})
	if code, _ := httpMsg(cerr); code != 404 {
		t.Errorf("重放 ceremonyId 应 404，得到 %d %v", code, cerr)
	}

	// 过期后同样 404（提前把 expires_at 拨回去，免得测试真等 5 分钟）
	_, id2, err := svc.BeginPasskeyRegistration(c)
	if err != nil {
		t.Fatalf("第二次发起: %v", err)
	}
	if _, err := svc.pool.Exec("UPDATE webauthn_challenges SET expires_at = ? WHERE id = ?",
		time.Now().Add(-time.Minute).UnixMilli(), id2); err != nil {
		t.Fatalf("拨过期: %v", err)
	}
	_, cerr = svc.FinishPasskeyRegistration(c, id2, []byte(`{}`), SessionMeta{UserAgent: "Chrome"})
	if code, _ := httpMsg(cerr); code != 404 {
		t.Errorf("过期仪式应 404，得到 %d %v", code, cerr)
	}
}

// register 仪式绑发起者：别人的 ceremonyId 一律 404，且**不能替我消费掉**——
// 发起者自己再 finish 仍走得到校验（回 400 而非 404）。
func TestPasskeyCeremonyOwnedByCaller(t *testing.T) {
	svc, mailer := newTestService(t)
	alice := newPasskeyUser(t, svc, mailer, "pk-alice@example.com")
	bob := newPasskeyUser(t, svc, mailer, "pk-bob@example.com")

	_, id, err := svc.BeginPasskeyRegistration(alice)
	if err != nil {
		t.Fatalf("发起: %v", err)
	}
	_, cerr := svc.FinishPasskeyRegistration(bob, id, []byte(`{}`), SessionMeta{})
	if code, _ := httpMsg(cerr); code != 404 {
		t.Errorf("别人的 ceremonyId 应 404，得到 %d %v", code, cerr)
	}
	_, cerr = svc.FinishPasskeyRegistration(alice, id, []byte(`{}`), SessionMeta{})
	if code, _ := httpMsg(cerr); code != 400 {
		t.Errorf("发起者本人应走到校验（400），得到 %d %v", code, cerr)
	}
}

// userHandle ↔ uid：8 字节大端往返无损，长度不对 / 最高位为 1 的垃圾一律报错
//（discoverable 登录靠它反查账号，错位就是把 passkey 认给别人）。
func TestUserHandleRoundTrip(t *testing.T) {
	for _, uid := range []int64{1, 1<<53 + 7, 2112093138515398659, 1<<63 - 1} {
		got, err := uidFromWebAuthnID(webAuthnID(uid))
		if err != nil || got != uid {
			t.Errorf("uid %d 往返失败: got=%d err=%v", uid, got, err)
		}
	}
	if _, err := uidFromWebAuthnID([]byte{1, 2, 3}); err == nil {
		t.Error("长度不对的 userHandle 应报错")
	}
	// 最高位为 1：解出来会是负数（不是合法雪花 uid），必须拦
	neg := []byte{0xff, 0, 0, 0, 0, 0, 0, 1}
	if _, err := uidFromWebAuthnID(neg); err == nil {
		t.Error("负数 uid 形态应报错")
	}
}

// 登录仪式：discoverable 行的 user_id 必须为空，过期同样 404。
func TestPasskeyLoginCeremonyShape(t *testing.T) {
	svc, _ := newTestService(t)
	assertion, id, err := svc.BeginPasskeyLogin()
	if err != nil {
		t.Fatalf("发起登录仪式: %v", err)
	}
	if assertion == nil || len(assertion.Response.Challenge) == 0 {
		t.Fatal("应回 CredentialAssertion")
	}
	var userNull interface{}
	if err := svc.pool.QueryRow("SELECT user_id FROM webauthn_challenges WHERE id = ?", id).Scan(&userNull); err != nil {
		t.Fatalf("查登录仪式行: %v", err)
	}
	if userNull != nil {
		t.Errorf("discoverable 行的 user_id 应为 NULL，得到 %v", userNull)
	}
	if _, err := svc.pool.Exec("UPDATE webauthn_challenges SET expires_at = ? WHERE id = ?",
		time.Now().Add(-time.Minute).UnixMilli(), id); err != nil {
		t.Fatalf("拨过期: %v", err)
	}
	_, _, _, cerr := svc.FinishPasskeyLogin(id, []byte(`{}`))
	if code, _ := httpMsg(cerr); code != 404 {
		t.Errorf("过期登录仪式应 404，得到 %d %v", code, cerr)
	}
}

// 凭证落库 + 登录回写：字段映射无损、sign_count 每次前进都写回、
// 计数器不前进时**记告警但仍写**（同步型 passkey 常报 0，拒绝会误杀）。
func TestPasskeyCredentialStorageAndSignCount(t *testing.T) {
	svc, mailer := newTestService(t)
	c := newPasskeyUser(t, svc, mailer, "pk-store@example.com")

	cred := &webauthn.Credential{
		ID:        []byte("credential-bytes-01"),
		PublicKey: []byte{0xa5, 0x01, 0x02, 0x03},
		Flags:     webauthn.CredentialFlags{BackupEligible: true, BackupState: true},
	}
	cred.Authenticator.SignCount = 7
	cred.Authenticator.AAGUID = []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	cred.Transport = []protocol.AuthenticatorTransport{"internal", "hybrid"}

	id, err := svc.insertCredential(c.UID, "我的通行密钥", cred)
	if err != nil {
		t.Fatalf("落凭证: %v", err)
	}
	got, err := svc.loadCredentials(c.UID)
	if err != nil || len(got) != 1 {
		t.Fatalf("读凭证: %v (n=%d)", err, len(got))
	}
	if string(got[0].ID) != string(cred.ID) || string(got[0].PublicKey) != string(cred.PublicKey) ||
		got[0].Authenticator.SignCount != 7 || !got[0].Flags.BackupEligible || !got[0].Flags.BackupState {
		t.Errorf("字段映射有损: %+v", got[0])
	}
	if len(got[0].Transport) != 2 || got[0].Transport[1] != "hybrid" {
		t.Errorf("transports 应往返成两段，得到 %+v", got[0].Transport)
	}

	// 计数器前进：写回新值
	next := *cred
	next.Authenticator.SignCount = 9
	if err := svc.recordCredentialUse(c.UID, &next); err != nil {
		t.Fatalf("回写: %v", err)
	}
	var stored int64
	if err := svc.pool.QueryRow("SELECT sign_count FROM passkeys WHERE id = ?", id).Scan(&stored); err != nil || stored != 9 {
		t.Errorf("sign_count 应写回 9，得到 %d err=%v", stored, err)
	}
	// 计数器不前进（旧值非 0）：**仍写回**，只是告警——拒绝会误杀同步型 passkey
	clone := *cred
	clone.Authenticator.SignCount = 4
	if err := svc.recordCredentialUse(c.UID, &clone); err != nil {
		t.Fatalf("回写克隆形态: %v", err)
	}
	if err := svc.pool.QueryRow("SELECT sign_count FROM passkeys WHERE id = ?", id).Scan(&stored); err != nil || stored != 4 {
		t.Errorf("计数器不前进时也应写回新值（只告警），得到 %d err=%v", stored, err)
	}

	// 同一把 credential_id 再绑一次 → 409
	_, cerr := svc.insertCredential(c.UID, "重复", cred)
	if code, _ := httpMsg(cerr); code != 409 {
		t.Errorf("credential_id 冲突应 409，得到 %d %v", code, cerr)
	}

	// 列表 + current 标记（本会话登录用的那把才亮）
	svc.markPasskeyLogin(987654321098765, base64.RawURLEncoding.EncodeToString(cred.ID))
	list, err := svc.ListPasskeys(c.UID, 987654321098765)
	if err != nil || len(list) != 1 {
		t.Fatalf("列表: %v (n=%d)", err, len(list))
	}
	if !list[0].Current || list[0].ID != id || list[0].Name != "我的通行密钥" {
		t.Errorf("列表字段/current 不对: %+v", list[0])
	}
}

// 改名：只动名字；不存在的 id 回 404；空名拒绝。
func TestRenamePasskey(t *testing.T) {
	svc, mailer := newTestService(t)
	c := newPasskeyUser(t, svc, mailer, "pk-rename@example.com")
	id, err := svc.insertCredential(c.UID, "旧名", &webauthn.Credential{ID: []byte("cred-rename"), PublicKey: []byte{1}})
	if err != nil {
		t.Fatalf("落凭证: %v", err)
	}
	if err := svc.RenamePasskey(c.UID, id, "  新的名字  "); err != nil {
		t.Fatalf("改名: %v", err)
	}
	var name string
	if err := svc.pool.QueryRow("SELECT name FROM passkeys WHERE id = ?", id).Scan(&name); err != nil || name != "新的名字" {
		t.Errorf("名字应 trim 后落库，得到 %q err=%v", name, err)
	}
	if err := svc.RenamePasskey(c.UID, id, "   "); err == nil {
		t.Error("空名应拒绝")
	}
	cerr := svc.RenamePasskey(c.UID, 1234567890123456789, "x")
	if code, _ := httpMsg(cerr); code != 404 {
		t.Errorf("不存在的 id 应 404，得到 %d", code)
	}
}

// 删除守卫：最后一种登录方式（无密码 + 无两步验证 + 只剩这一把 passkey）必须留住。
func TestDeletePasskeyGuardsLastLoginMethod(t *testing.T) {
	svc, mailer := newTestService(t)

	// 形态一：有密码（正常注册账号）→ 可以删
	withPwd := newPasskeyUser(t, svc, mailer, "pk-haspwd@example.com")
	idA, err := svc.insertCredential(withPwd.UID, "A", &webauthn.Credential{ID: []byte("cred-a"), PublicKey: []byte{1}})
	if err != nil {
		t.Fatalf("落凭证: %v", err)
	}
	if err := svc.DeletePasskey(withPwd.UID, idA); err != nil {
		t.Errorf("有密码的账号应能删 passkey: %v", err)
	}

	// 形态二：无密码无 2FA、只剩这一把 → 400（保住至少一种登录方式）
	noPwd := newPasskeyUser(t, svc, mailer, "pk-nopwd@example.com")
	if _, err := svc.pool.Exec("UPDATE users SET password_hash = NULL WHERE id = ?", noPwd.UID); err != nil {
		t.Fatalf("去掉密码: %v", err)
	}
	idB, err := svc.insertCredential(noPwd.UID, "B", &webauthn.Credential{ID: []byte("cred-b"), PublicKey: []byte{1}})
	if err != nil {
		t.Fatalf("落凭证: %v", err)
	}
	err = svc.DeletePasskey(noPwd.UID, idB)
	if err == nil || !strings.Contains(err.Error(), "最后一种登录方式") {
		t.Errorf("应拒绝并说明原因，得到 %v", err)
	}
	var still int
	if err := svc.pool.QueryRow("SELECT COUNT(*) FROM passkeys WHERE id = ?", idB).Scan(&still); err != nil || still != 1 {
		t.Errorf("被守卫拦下时凭证必须还在，得到 n=%d err=%v", still, err)
	}

	// 形态三：同账号开了两步验证 → 解锁，可删。守卫只看 enabled 这一位，这里直接置位
	//（验码链路另有 totp_test 覆盖，不必在本用例里再跑一遍）
	if _, err := svc.SetupTOTP(noPwd); err != nil {
		t.Fatalf("setup totp: %v", err)
	}
	if _, err := svc.pool.Exec("UPDATE totp_factors SET enabled = 1, confirmed_at = ? WHERE user_id = ?",
		time.Now().UnixMilli(), noPwd.UID); err != nil {
		t.Fatalf("置 enabled: %v", err)
	}
	if err := svc.DeletePasskey(noPwd.UID, idB); err != nil {
		t.Errorf("有两步验证兜底时应能删: %v", err)
	}
	// 不属于自己的 id → 404（与不存在同形，不给存在性探针）
	cerr := svc.DeletePasskey(withPwd.UID, 999999999999999999)
	if code, _ := httpMsg(cerr); code != 404 {
		t.Errorf("别人的/不存在的凭证应 404，得到 %d", code)
	}
}
