package auth

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

// ---- PKCE（RFC 7636）纯单测：本机真跑，不碰库 ----

// RFC 7636 附录 B 的官方向量：verifier → S256 challenge 一字不差。
func TestPKCES256Vector(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	want := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	if got := pkceS256(verifier); got != want {
		t.Errorf("S256 向量不匹配：得到 %q，期望 %q", got, want)
	}
}

func TestPKCEValueOK(t *testing.T) {
	valid := base64.RawURLEncoding.EncodeToString(make([]byte, 32)) // 43 位 base64url
	if len(valid) != 43 {
		t.Fatalf("43 字节的 base64url 应是 43 字符，得到 %d", len(valid))
	}
	for _, tc := range []struct {
		name, v string
		ok      bool
	}{
		{"43 位下限", valid, true},
		{"128 位上限", strings.Repeat("a", 128), true},
		{"42 位过短", strings.Repeat("a", 42), false},
		{"129 位过长", strings.Repeat("a", 129), false},
		{"空串", "", false},
		{"带填充 =", valid + "=", false},
		{"带标准 base64 的 +", strings.Repeat("a", 42) + "+", false},
		{"带 /", strings.Repeat("a", 42) + "/", false},
		{"带点（非 unreserved）", strings.Repeat("a", 42) + ".", false},
		{"带波浪线", strings.Repeat("a", 42) + "~", false},
	} {
		if got := pkceValueOK(tc.v); got != tc.ok {
			t.Errorf("%s：期望 ok=%v，得到 %v", tc.name, tc.ok, got)
		}
	}
}

// S256 比对：verifier 算出的 challenge 必须与授权请求存的一字不差；
// 错 verifier（哪怕同长度同字符集）恒不匹配。
func TestPKCEChallengeCompare(t *testing.T) {
	right := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	wrong := "AbjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	if pkceS256(right) == pkceS256(wrong) {
		t.Fatal("不同 verifier 不该算出同一 challenge")
	}
	if pkceS256(right) != pkceS256(right) {
		t.Fatal("同一 verifier 的 challenge 应稳定")
	}
}

// ---- redirect_uri 精确匹配（RFC 9700）：前缀攻击 / 子域 / query 变体全拒 ----

func TestOAuthRedirectExactMatch(t *testing.T) {
	registered := []string{"https://a.com/cb", "https://a.com/other?x=1"}
	allowed := func(u string) bool { return oauthRedirectAllowed(registered, u) }
	for _, tc := range []struct {
		name, uri string
		ok        bool
	}{
		{"逐字命中", "https://a.com/cb", true},
		{"带 query 的变体", "https://a.com/cb?evil=1", false},
		{"路径穿越变体", "https://a.com/cb/../evil", false},
		{"尾斜杠变体", "https://a.com/cb/", false},
		{"子域变体", "https://sub.a.com/cb", false},
		{"大小写变体（host）", "https://A.com/cb", false},
		{"同前缀不同路径", "https://a.com/cbevil", false},
		{"带 userinfo", "https://evil.com@a.com/cb", false},
		{"带 fragment", "https://a.com/cb#frag", false},
		{"http 降级", "http://a.com/cb", false},
		{"query 变体命中登记的第二条", "https://a.com/other?x=1", true},
	} {
		if got := allowed(tc.uri); got != tc.ok {
			t.Errorf("%s（%s）：期望 allowed=%v，得到 %v", tc.name, tc.uri, tc.ok, got)
		}
	}
}

// ---- secret 恒时比对：错 secret 拒、未签发（空 hash）恒拒 ----

func TestOAuthSecretMatches(t *testing.T) {
	const secret = "s3cret-value-abcdefghijklmnopqrstuv"
	hash := sha256Hex(secret)
	if !oauthSecretMatches(hash, secret) {
		t.Error("正确 secret 应命中")
	}
	if oauthSecretMatches(hash, secret+"x") {
		t.Error("错 secret 应被拒")
	}
	if oauthSecretMatches(hash, "") {
		t.Error("空 secret 应被拒")
	}
	if oauthSecretMatches("", secret) {
		t.Error("空 hash（未签发过 secret）应恒拒")
	}
	if oauthSecretMatches(hash, secret[:len(secret)-1]) {
		t.Error("截断的 secret 应被拒")
	}
}

// ---- 回跳地址登记校验 ----

func TestValidateOAuthRedirects(t *testing.T) {
	if _, err := validateOAuthRedirects([]string{"https://a.com/cb"}); err != nil {
		t.Errorf("合法地址应通过，得到 %v", err)
	}
	for _, tc := range []struct {
		name string
		uris []string
	}{
		{"空清单", nil},
		{"全是空串", []string{"", "  "}},
		{"超 10 条", func() []string {
			out := make([]string, 11)
			for i := range out {
				out[i] = "https://a.com/cb" + string(rune('a'+i))
			}
			return out
		}()},
		{"无 scheme", []string{"a.com/cb"}},
		{"非 http(s)", []string{"ftp://a.com/cb"}},
		{"无 host", []string{"https://"}},
		{"带 userinfo", []string{"https://user@a.com/cb"}},
		{"带 fragment", []string{"https://a.com/cb#x"}},
		{"超长", []string{"https://a.com/" + strings.Repeat("a", maxOAuthRedirectLen)}},
	} {
		if _, err := validateOAuthRedirects(tc.uris); err == nil {
			t.Errorf("%s：应被拒但通过了", tc.name)
		}
	}
	// 去重：重复条目折叠后仍合法
	deduped, err := validateOAuthRedirects([]string{"https://a.com/cb", "https://a.com/cb", " https://a.com/cb "})
	if err != nil || len(deduped) != 1 {
		t.Errorf("重复条目应去重成 1 条，得到 %v err=%v", deduped, err)
	}
}

// ---- 内存授权事务 / 授权码：单次 + 过期 ----

func TestOAuthStoreTxSingleUseAndTTL(t *testing.T) {
	o := newOAuthStore()
	o.putTx("tx1", &oauthTx{App: "calorie-diary", State: "st", UID: 7})

	// 读不消耗（确认页可能刷新重渲染）
	if got := o.tx("tx1"); got == nil || got.UID != 7 {
		t.Fatal("tx 应可重复读取且保留 uid 绑定")
	}
	if o.tx("nope") != nil {
		t.Error("不存在的 tx 应回 nil")
	}
	// 取出即消耗
	if got := o.takeTx("tx1"); got == nil || got.App != "calorie-diary" {
		t.Fatal("takeTx 应返回事务本体")
	}
	if o.takeTx("tx1") != nil || o.tx("tx1") != nil {
		t.Error("tx 消耗后不该再被取出（单次）")
	}
	// 过期：写入后把 CreatedAt 拨老（putTx 恒写 now，测试要造过期行只能直接拨）
	o.putTx("tx2", &oauthTx{App: "calorie-diary"})
	o.mu.Lock()
	o.txs["tx2"].CreatedAt = time.Now().Add(-oauthTxTTL - time.Second)
	o.mu.Unlock()
	if o.tx("tx2") != nil || o.takeTx("tx2") != nil {
		t.Error("过期 tx 应不可用")
	}
}

func TestOAuthStoreCodeSingleUseAndTTL(t *testing.T) {
	o := newOAuthStore()
	o.putCode("c1", &oauthCode{UID: 42, App: "expense-diary", Exp: time.Now().Add(oauthCodeTTL)})
	// 过期码：写入时不擦、取出时判死
	o.putCode("dead", &oauthCode{UID: 42, Exp: time.Now().Add(-time.Second)})

	if got := o.takeCode("c1"); got == nil || got.UID != 42 || got.App != "expense-diary" {
		t.Fatal("takeCode 应回授权码本体")
	}
	if o.takeCode("c1") != nil {
		t.Error("授权码取出即失效（复用应失败）")
	}
	if o.takeCode("dead") != nil {
		t.Error("过期授权码应不可用")
	}
	if o.takeCode("nope") != nil {
		t.Error("不存在的授权码应回 nil")
	}
}

// bindTx 只在行还在时生效；消耗后绑定无效。
func TestOAuthStoreBindTx(t *testing.T) {
	o := newOAuthStore()
	o.putTx("tx", &oauthTx{App: "calorie-diary"})
	o.bindTx("tx", 99)
	if got := o.tx("tx"); got == nil || got.UID != 99 {
		t.Fatal("bindTx 应写入 uid")
	}
	o.takeTx("tx")
	o.bindTx("tx", 100) // no-op，不 panic
}

// buildOAuthRedirect：在已登记地址上追加 code/error 与 state，保留原有 query。
func TestBuildOAuthRedirect(t *testing.T) {
	got, err := buildOAuthRedirect("https://a.com/cb?keep=1",
		map[string][]string{"code": {"abc"}, "state": {"s1"}})
	if err != nil {
		t.Fatalf("构建回跳: %v", err)
	}
	if !strings.HasPrefix(got, "https://a.com/cb?") ||
		!strings.Contains(got, "code=abc") || !strings.Contains(got, "state=s1") ||
		!strings.Contains(got, "keep=1") {
		t.Errorf("回跳 URL 应带 code/state 且保留原 query，得到 %q", got)
	}
	got, err = buildOAuthRedirect("https://a.com/cb",
		map[string][]string{"error": {"access_denied"}, "state": {"s2"}})
	if err != nil || !strings.Contains(got, "error=access_denied") || !strings.Contains(got, "state=s2") {
		t.Errorf("deny 回跳应带 error=access_denied，得到 %q err=%v", got, err)
	}
}
