package auth

import (
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// otpGate（冷却 + 两级日限额）的纯判定测试：这三条闸只要有一条失守，
// 验证码就挡不住轰炸。
func TestOTPCooldownAndDailyLimit(t *testing.T) {
	now := time.Now()

	// 无在途码、额度充足 → 放行
	if err := otpGate(now, time.Time{}, 0, 0); err != nil {
		t.Errorf("空闲状态应放行，得到 %v", err)
	}
	// 冷却：59 秒拒、60 秒放（按「上一次发出」算）
	if err := otpGate(now, now.Add(-59*time.Second), 0, 0); err == nil {
		t.Error("60 秒内重复发送应被拒")
	} else if code, _ := httpMsg(err); code != 429 {
		t.Errorf("冷却应 429，得到 %d", code)
	}
	if err := otpGate(now, now.Add(-otpCooldown), 0, 0); err != nil {
		t.Errorf("冷却刚过应放行，得到 %v", err)
	}
	// 每用途每日 10 条：第 11 条拒
	if err := otpGate(now, time.Time{}, otpDailyLimit, 0); err == nil {
		t.Error("当日超过 10 条应被拒")
	} else if code, _ := httpMsg(err); code != 429 {
		t.Errorf("日额度应 429，得到 %d", code)
	}
	// 收件人跨用途总闸：15 条拒，且**优先于冷却**——总闸满了连提示都不该轮到冷却
	if err := otpGate(now, now, 0, recipientDailyCap); err == nil {
		t.Error("收件人日总闸应拒")
	} else if msg := err.Error(); !strings.Contains(msg, "已达上限") {
		t.Errorf("总闸文案应是「已达上限」，得到 %q", msg)
	}
}

// 码必须是密码学随机：可预测的验证码等于没有。
func TestRandomCodeIsSixDigits(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		c, err := randomCode()
		if err != nil {
			t.Fatalf("生成失败: %v", err)
		}
		if len(c) != otpDigits {
			t.Fatalf("长度应 6，得到 %q", c)
		}
		for _, r := range c {
			if r < '0' || r > '9' {
				t.Fatalf("必须纯数字，得到 %q", c)
			}
		}
		seen[c] = true
	}
	// 200 次里出现重复是正常的（生日碰撞），但全塌成同一个值必是坏的随机源
	if len(seen) < 100 {
		t.Errorf("200 次只出了 %d 个不同的码，随机性可疑", len(seen))
	}
}

// 库里不落明文码：sha256 十六进制、64 位、确定性。
func TestSha256HexFormat(t *testing.T) {
	h := sha256Hex("123456")
	if len(h) != 64 {
		t.Fatalf("sha256 十六进制应 64 字符，得到 %d", len(h))
	}
	for _, r := range h {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			t.Fatalf("应是小写十六进制，得到 %q", h)
		}
	}
	if h != sha256Hex("123456") || h == sha256Hex("123457") {
		t.Error("同一码应同一散列，不同码应不同散列")
	}
}

// 日志里的邮箱必须脱敏：本地名遮掉、域名保留（域名是排障线索，全文邮箱是 PII）。
func TestMaskEmail(t *testing.T) {
	cases := map[string]string{
		"user@example.com": "u***@example.com",
		"ab@example.com":  "a***@example.com",
		"no-at-sign":      "***",
		"@example.com":    "***",
	}
	for in, want := range cases {
		if got := maskEmail(in); got != want {
			t.Errorf("maskEmail(%q) = %q，应为 %q", in, got, want)
		}
	}
	// 中文本地名按 **rune** 取首字，不能按字节切半个汉字
	if got := maskEmail("张三@例子.cn"); got != "张***@例子.cn" {
		t.Errorf("多字节本地名脱敏错了: %q", got)
	}
}

// 邮件模板的硬约束：验证码与有效期在正文里、暗色模式覆盖在、
// 不过 AA 的低对比度灰（#8a8a8e≈3.6:1 / #a1a1a6≈2.6:1）不许出现。
// 字阶照 miuix 定案：标题 20 / 正文 16 / 验证码 32 / 页脚与元信息 13，小于 13 不许出现。
func TestCodeEmailTemplateKeepsContract(t *testing.T) {
	subject, html := codeEmail(brandFor(""), "注册", "123456")
	if subject != "【Auth】注册验证码" {
		t.Errorf("主题格式变了: %q", subject)
	}
	for _, want := range []string{"123456", "5 分钟内有效", "prefers-color-scheme",
		"role=\"presentation\"", "max-width:600px", "继续注册"} {
		if !strings.Contains(html, want) {
			t.Errorf("正文缺 %q", want)
		}
	}
	for _, bad := range []string{"#8a8a8e", "#a1a1a6", "font-size:12px", "font-size:11px", "font-size:10px"} {
		if strings.Contains(html, bad) {
			t.Errorf("低对比度灰/小于 10pt 的字阶 %s 不该进模板", bad)
		}
	}
}

// 改绑邮箱的通知信（旧/新各一封）：主题与正文说清发生了什么 + 非本人操作的下一步；
// 邮箱进正文前必须转义（正则不拦 <>）。
func TestChangeEmailNoticeEmail(t *testing.T) {
	subject, body := changeEmailNoticeEmail(brandFor(""), false, "old@example.com", "new@example.com")
	if subject != "【Auth】绑定邮箱已更换" {
		t.Errorf("旧邮箱信主题变了: %q", subject)
	}
	for _, want := range []string{"old@example.com", "new@example.com", "绑定邮箱已更换",
		"找回密码", "prefers-color-scheme", `role="presentation"`, "max-width:600px"} {
		if !strings.Contains(body, want) {
			t.Errorf("旧邮箱信缺 %q", want)
		}
	}

	subject, body = changeEmailNoticeEmail(brandFor(""), true, "old@example.com", "new@example.com")
	if subject != "【Auth】新邮箱已绑定" {
		t.Errorf("新邮箱信主题变了: %q", subject)
	}
	for _, want := range []string{"new@example.com", "新邮箱已绑定", "验证码会发到这里"} {
		if !strings.Contains(body, want) {
			t.Errorf("新邮箱信缺 %q", want)
		}
	}

	// 注入面：邮箱里的 < > 必须被转义，不能原样进 HTML
	_, body = changeEmailNoticeEmail(brandFor(""), true, `a<b>@x.com`, "n@y.com")
	if strings.Contains(body, "<b>") || !strings.Contains(body, "&lt;b&gt;") {
		t.Errorf("邮箱未转义，存在 HTML 注入面: %s", body)
	}
}

// 真库语义：生命周期（发→猜→对）、错 5 次作废、跨用途隔离、发信失败回滚冷却。
// 没有 TEST_MYSQL_DSN 时整组跳过（与 auth 包真库测试同策略）。
func TestOTPStoreLifecycle(t *testing.T) {
	svc, _ := newTestService(t)
	s := svc.otps
	ctx := "a@b.com"

	// 没发过就提交：说「请先获取」而不是「验证码错误」——用户该知道自己没点发送
	if err := s.verify(PurposeRegister, ctx, ""); err == nil ||
		!strings.Contains(err.Error(), "请先获取") {
		t.Errorf("空码应提示先获取，得到 %v", err)
	}

	code, err := s.issue(PurposeRegister, ctx)
	if err != nil {
		t.Fatalf("发码失败: %v", err)
	}
	// 冷却：60 秒内重复发送被拒
	if _, err := s.issue(PurposeRegister, ctx); err == nil {
		t.Fatal("60 秒内重复发送应被拒")
	} else if c, _ := httpMsg(err); c != 429 {
		t.Errorf("冷却应 429，得到 %d", c)
	}

	// 错码：400 且只说「错误」，不透露还剩几次
	guess := "000000"
	if guess == code {
		guess = "000001"
	}
	if err := s.verify(PurposeRegister, ctx, guess); err == nil ||
		!strings.Contains(err.Error(), "验证码错误") {
		t.Errorf("错码应报验证码错误，得到 %v", err)
	}

	// 对码：通过，且**用后即焚**——同一个码不能再提交第二次
	if err := s.verify(PurposeRegister, ctx, code); err != nil {
		t.Fatalf("正确码应通过: %v", err)
	}
	if err := s.verify(PurposeRegister, ctx, code); err == nil {
		t.Error("验证码是一次性的，用过之后不能复用")
	}

	// 用掉一代后冷却即刻解除（用后即焚的另一半：不用白等 60 秒）
	if _, err := s.issue(PurposeRegister, ctx); err != nil {
		t.Errorf("用掉一代后应能立刻再发: %v", err)
	}

	// 跨用途隔离：注册码不能在登录流程用。先烧掉上面"立刻再发"留下的活跃注册代——
	// 否则注册行还在，拿登录码来撞得到的是「验证码错误」（行在、码不匹配）而非
	//「过期」（该 purpose 无行）；两种都是拒绝，但这条钉的是 purpose 分键语义。
	s.revoke(PurposeRegister, ctx)
	loginCode, err := s.issue(PurposeLogin, ctx)
	if err != nil {
		t.Fatalf("发登录码失败: %v", err)
	}
	if err := s.verify(PurposeRegister, ctx, loginCode); err == nil ||
		!strings.Contains(err.Error(), "过期") {
		t.Errorf("登录码不该在注册流程可用，得到 %v", err)
	}
	if err := s.verify(PurposeLogin, ctx, loginCode); err != nil {
		t.Errorf("登录码应在本流程可用: %v", err)
	}

	// 错 5 次作废：随后正确码也进不来
	code2, err := s.issue(PurposeReset, ctx)
	if err != nil {
		t.Fatalf("发找回码失败: %v", err)
	}
	wrong := "000000"
	if wrong == code2 {
		wrong = "000001"
	}
	for i := 0; i < otpMaxTries; i++ {
		if err := s.verify(PurposeReset, ctx, wrong); err == nil {
			t.Fatalf("第 %d 次错码不该通过", i+1)
		}
	}
	if err := s.verify(PurposeReset, ctx, code2); err == nil {
		t.Error("试错用尽后正确码也不该再通过——否则试错上限形同虚设")
	}

	// 撤销 = 发信失败时的回滚：码不能留在活跃集里，否则用户要白等 60 秒冷却
	if _, err := s.issue(PurposeChange, ctx); err != nil {
		t.Fatalf("发修改密码码失败: %v", err)
	}
	s.revoke(PurposeChange, ctx)
	if _, err := s.issue(PurposeChange, ctx); err != nil {
		t.Errorf("撤销后应能立刻重发: %v", err)
	}
}

// 并发语义（真库）：冷却、用后即焚、5 次作废三条闸都不能被同批并发穿透——
// 读-判-写之间的窗口补齐后，这三种并发都只能各成一次。
func TestOTPStoreConcurrency(t *testing.T) {
	svc, _ := newTestService(t)
	s := svc.otps
	const n = 8

	// 并发发码：冷却窗口内只允许 1 个成功，其余必须吃 429 冷却
	t.Run("发码冷却挡并发", func(t *testing.T) {
		email := "race-issue@example.com"
		var wg sync.WaitGroup
		var oks atomic.Int64
		start := make(chan struct{})
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				if _, err := s.issue(PurposeRegister, email); err == nil {
					oks.Add(1)
				} else if c, _ := httpMsg(err); c != 429 {
					t.Errorf("并发发码的失败应是 429 冷却，得到 %v", err)
				}
			}()
		}
		close(start)
		wg.Wait()
		if oks.Load() != 1 {
			t.Errorf("并发发码应只成功 1 个，得到 %d", oks.Load())
		}
	})

	// 并发提交同一个正确码：用后即焚只放行一次
	t.Run("验码一次性挡并发", func(t *testing.T) {
		email := "race-verify@example.com"
		code, err := s.issue(PurposeLogin, email)
		if err != nil {
			t.Fatalf("发码失败: %v", err)
		}
		var wg sync.WaitGroup
		var oks atomic.Int64
		start := make(chan struct{})
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				if err := s.verify(PurposeLogin, email, code); err == nil {
					oks.Add(1)
				}
			}()
		}
		close(start)
		wg.Wait()
		if oks.Load() != 1 {
			t.Errorf("同一码并发提交应只成功 1 次，得到 %d", oks.Load())
		}
	})

	// 并发错码：5 次作废不被穿透——N 个错码并发提交后，正确码也必须进不来
	t.Run("错5次作废挡并发", func(t *testing.T) {
		email := "race-attempts@example.com"
		code, err := s.issue(PurposeReset, email)
		if err != nil {
			t.Fatalf("发码失败: %v", err)
		}
		wrong := "000000"
		if wrong == code {
			wrong = "000001"
		}
		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				if err := s.verify(PurposeReset, email, wrong); err == nil {
					t.Error("错码不该通过")
				}
			}()
		}
		close(start)
		wg.Wait()
		if err := s.verify(PurposeReset, email, code); err == nil {
			t.Error("并发错码打满试错上限后，正确码也不该再通过")
		}
	})
}
