package auth

import (
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

// newTOTPUser 注册一个账号并回它的 Caller（TOTP 用例都要一个带邮箱的会话身份）。
func newTOTPUser(t *testing.T, svc *Service, mailer *recordMailer, email string) Caller {
	t.Helper()
	reg := registerViaCode(t, svc, mailer, email, "secret123")
	c, err := svc.ValidUserID("Bearer " + reg.Token)
	if err != nil {
		t.Fatalf("注册 token 校验失败: %v", err)
	}
	return c
}

// codeAt 取 secret 在 now+offset 时刻的码。用它代替 time.Sleep 模拟「下一个步进」：
// 验证窗是 ±1 步进，直接生成未来步进的码即可让用例秒级跑完，不用真等 30 秒。
func codeAt(t *testing.T, secret string, offset time.Duration) string {
	t.Helper()
	code, err := totp.GenerateCode(secret, time.Now().Add(offset))
	if err != nil {
		t.Fatalf("生成 TOTP 码: %v", err)
	}
	return code
}

// currentCode 取该 secret 的当下码（与用户手机上看到的一致）。
func currentCode(t *testing.T, secret string) string {
	t.Helper()
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("生成 TOTP 码: %v", err)
	}
	return code
}

// 先验后启：setup 只落 pending（状态恒未开启），验过一次码才启用并一次性交出
// 10 个恢复码；启用所用的那个码随后不能再验（同步进重放拒）。
func TestTOTPSetupEnableAndReplayRejected(t *testing.T) {
	svc, mailer := newTestService(t)
	c := newTOTPUser(t, svc, mailer, "totp-basic@example.com")

	st, err := svc.TOTPStatus(c.UID)
	if err != nil || st.Enabled {
		t.Fatalf("初始应未开启: %+v err=%v", st, err)
	}

	setup, err := svc.SetupTOTP(c)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	if setup.Secret == "" || !strings.HasPrefix(setup.OTPAuthURI, "otpauth://totp/") {
		t.Errorf("setup 应回 secret 与 otpauth URI，得到 %+v", setup)
	}
	if !strings.HasPrefix(setup.QRDataURI, "data:image/png;base64,") {
		t.Errorf("二维码应是内联 data URI（零外链），得到 %.30s", setup.QRDataURI)
	}
	st, err = svc.TOTPStatus(c.UID)
	if err != nil || st.Enabled {
		t.Errorf("setup 之后仍应未开启（先验后启）: %+v err=%v", st, err)
	}
	// 明文 secret 不进库：库里是 AES-GCM 密文
	var blob []byte
	if err := svc.pool.QueryRow("SELECT secret_cipher FROM totp_factors WHERE user_id = ?", c.UID).Scan(&blob); err != nil {
		t.Fatalf("查密文: %v", err)
	}
	if strings.Contains(string(blob), setup.Secret) {
		t.Error("secret 明文出现在库里——加密没生效")
	}
	if _, err := svc.openSecret(blob); err != nil {
		t.Errorf("密文应能用服务端密钥解开: %v", err)
	}

	// 错码不启用
	if _, err := svc.EnableTOTP(c, "000000"); err == nil {
		t.Error("错码不该启用")
	}
	codes, err := svc.EnableTOTP(c, currentCode(t, setup.Secret))
	if err != nil {
		t.Fatalf("enable: %v", err)
	}
	if len(codes) != recoveryCodeCount {
		t.Errorf("应回 %d 个恢复码，得到 %d", recoveryCodeCount, len(codes))
	}
	for _, rc := range codes {
		if parts := strings.Split(rc, "-"); len(parts) != 4 || len(rc) != 19 {
			t.Errorf("恢复码格式应 XXXX-XXXX-XXXX-XXXX，得到 %q", rc)
		}
	}
	seen := map[string]bool{}
	for _, rc := range codes {
		if seen[rc] {
			t.Errorf("恢复码重复: %q", rc)
		}
		seen[rc] = true
	}
	st, err = svc.TOTPStatus(c.UID)
	if err != nil || !st.Enabled || st.CreatedAt <= 0 {
		t.Errorf("enable 后应开启且带启用时间: %+v err=%v", st, err)
	}

	// 同步进重放：启用时用过的那个码不能再验（ASVS 6.5.1 一次一用）
	enableCode := currentCode(t, setup.Secret)
	if ok, err := svc.VerifyTOTPCode(c.UID, enableCode); ok || err != nil {
		t.Errorf("启用用过的码应被同步进重放挡下，得到 ok=%v err=%v", ok, err)
	}
	// 下一个步进的全新码应通过（按未来步进生成，用例不必真等 30 秒）
	next := codeAt(t, setup.Secret, 30*time.Second)
	if ok, err := svc.VerifyTOTPCode(c.UID, next); !ok || err != nil {
		t.Errorf("新码应通过: ok=%v err=%v", ok, err)
	}
	if ok, err := svc.VerifyTOTPCode(c.UID, "123456"); ok || err != nil {
		t.Errorf("错码应不通过: ok=%v err=%v", ok, err)
	}
}

// 重置流程的安全前提：setup 一个新 secret 不能顺手废掉受害者手上那台验证器——
// 旧 secret 与 enabled 必须保持到新码在 enable 里被验过为止。
func TestTOTPResetKeepsOldUntilNewVerified(t *testing.T) {
	svc, mailer := newTestService(t)
	c := newTOTPUser(t, svc, mailer, "totp-reset@example.com")

	first, err := svc.SetupTOTP(c)
	if err != nil {
		t.Fatalf("首次 setup: %v", err)
	}
	if _, err := svc.EnableTOTP(c, currentCode(t, first.Secret)); err != nil {
		t.Fatalf("首次 enable: %v", err)
	}

	second, err := svc.SetupTOTP(c)
	if err != nil {
		t.Fatalf("重置 setup: %v", err)
	}
	if second.Secret == first.Secret {
		t.Fatal("重置应换一个新 secret")
	}
	st, _ := svc.TOTPStatus(c.UID)
	if !st.Enabled {
		t.Error("重置 setup 期间旧 TOTP 必须保持 enabled")
	}
	// 旧验证器照常能过（登录侧验的是 Secret 段）。用下一个步进的码：启用那一步
	// 已经把当步进记进重放账，同一个码再拿来验会被自己的防重放挡下
	oldCode := codeAt(t, first.Secret, 30*time.Second)
	if ok, _ := svc.VerifyTOTPCode(c.UID, oldCode); !ok {
		t.Error("重置期间旧 secret 应仍可用")
	}
	// 新码 enable 成功 → 换代：旧码当场作废
	if _, err := svc.EnableTOTP(c, currentCode(t, second.Secret)); err != nil {
		t.Fatalf("重置 enable: %v", err)
	}
	if ok, _ := svc.VerifyTOTPCode(c.UID, oldCode); ok {
		t.Error("换代后旧 secret 应作废")
	}
}

// 恢复码：单次使用、用掉即废、整组换新后旧组全失效。
func TestRecoveryCodesSingleUseAndRegeneration(t *testing.T) {
	svc, mailer := newTestService(t)
	c := newTOTPUser(t, svc, mailer, "totp-recovery@example.com")

	setup, err := svc.SetupTOTP(c)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	codes, err := svc.EnableTOTP(c, currentCode(t, setup.Secret))
	if err != nil {
		t.Fatalf("enable: %v", err)
	}
	// 连字符、空白、大小写都归一化（手抄不算错）
	used, err := svc.consumeRecoveryCode(c.UID, "  "+codes[0]+" ", SessionMeta{})
	if err != nil || !used {
		t.Fatalf("首个恢复码应可用: used=%v err=%v", used, err)
	}
	if used, _ := svc.consumeRecoveryCode(c.UID, codes[0], SessionMeta{}); used {
		t.Error("恢复码只能用一次")
	}
	if used, _ := svc.consumeRecoveryCode(c.UID, "AAAA-BBBB-CCCC-DDDD", SessionMeta{}); used {
		t.Error("乱造的码不该命中")
	}

	// 换新：验一个没用过的 TOTP 码 → 新组 10 个、旧组即废
	fresh := codeAt(t, setup.Secret, 30*time.Second)
	next, err := svc.RegenerateRecoveryCodes(c, fresh)
	if err != nil {
		t.Fatalf("换发恢复码: %v", err)
	}
	if len(next) != recoveryCodeCount {
		t.Errorf("换发应回 %d 个，得到 %d", recoveryCodeCount, len(next))
	}
	for _, rc := range codes[1:] {
		if used, _ := svc.consumeRecoveryCode(c.UID, rc, SessionMeta{}); used {
			t.Errorf("旧组恢复码在换发后必须作废: %q", rc)
		}
	}
	if used, _ := svc.consumeRecoveryCode(c.UID, next[0], SessionMeta{}); !used {
		t.Error("新组首个恢复码应可用")
	}
}

// 关闭两步验证：恢复码可解（丢了手机的收尾通道），关掉后因子与恢复码一起删。
func TestDisableTOTPWithRecoveryCode(t *testing.T) {
	svc, mailer := newTestService(t)
	c := newTOTPUser(t, svc, mailer, "totp-disable@example.com")

	setup, err := svc.SetupTOTP(c)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	codes, err := svc.EnableTOTP(c, currentCode(t, setup.Secret))
	if err != nil {
		t.Fatalf("enable: %v", err)
	}
	if err := svc.DisableTOTP(c, codes[3]); err != nil {
		t.Fatalf("用恢复码关闭: %v", err)
	}
	st, _ := svc.TOTPStatus(c.UID)
	if st.Enabled || st.CreatedAt != 0 {
		t.Errorf("关闭后应完全没因子，得到 %+v", st)
	}
	var n int
	if err := svc.pool.QueryRow("SELECT COUNT(*) FROM recovery_codes WHERE user_id = ?", c.UID).Scan(&n); err != nil || n != 0 {
		t.Errorf("恢复码应随解绑清空，得到 n=%d err=%v", n, err)
	}
	// 已关闭就别再关（幂等性提示，不是静默成功）
	if err := svc.DisableTOTP(c, codes[0]); err == nil {
		t.Error("已关闭时再关应回 400")
	}
}

// m1 回归：TOTP 重放闸是**原子**的——并发提交同一个当前码，只允许一个通过。
// 旧实现「SELECT 看 last_used → UPDATE 覆盖写」两步之间有窗口，并发同码可双双放行。
func TestVerifyTOTPConcurrentSameCodeSingleUse(t *testing.T) {
	svc, mailer := newTestService(t)
	c := newTOTPUser(t, svc, mailer, "totp-race@example.com")
	setup, err := svc.SetupTOTP(c)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	if _, err := svc.EnableTOTP(c, currentCode(t, setup.Secret)); err != nil {
		t.Fatalf("enable: %v", err)
	}
	// 用下一个步进的码（enable 已把当步进记进重放账）
	code := codeAt(t, setup.Secret, 30*time.Second)

	const n = 8
	var wg sync.WaitGroup
	var oks atomic.Int64
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if ok, err := svc.VerifyTOTPCode(c.UID, code); ok && err == nil {
				oks.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if oks.Load() != 1 {
		t.Errorf("并发同码应只放行 1 次，得到 %d 次", oks.Load())
	}
}

// AES-GCM 往返与「密钥对不上就解不开」——TOTP secret 只能存原值，加密是它唯一的遮挡。
func TestSecretCipherRoundTrip(t *testing.T) {
	svc, _ := newTestService(t)
	const secret = "JBSWY3DPEHPK3PXP"
	blob, err := svc.sealSecret(secret)
	if err != nil {
		t.Fatalf("加密: %v", err)
	}
	got, err := svc.openSecret(blob)
	if err != nil || got != secret {
		t.Errorf("往返应无损: got=%q err=%v", got, err)
	}
	// 换一把密钥（模拟 TOTP_ENC_KEY 轮换）：解不开，而不是解出垃圾
	other := &Service{totpKey: []byte(strings.Repeat("z", 32))}
	if _, err := other.openSecret(blob); err == nil {
		t.Error("密钥不同必须解不开")
	}
}
