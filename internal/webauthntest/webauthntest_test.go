package webauthntest

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
)

// 合成数据自己先过一遍库的解析：公钥能按 COSE 解出 Ed25519、断言能按
// CredentialAssertionResponse 解出四段（id/rawId 一致、challenge 与 userHandle 对）。
// 挂在这里而不是等真库用例：编码错一位（CBOR 键序、flags、counter）在无 DB 的
// 这一层就报，定位比「passkey 登录 400」近得多。
func TestSyntheticCredentialParses(t *testing.T) {
	a, err := New()
	if err != nil {
		t.Fatalf("造合成 passkey: %v", err)
	}
	key, err := webauthncose.ParsePublicKey(a.Credential.PublicKey)
	if err != nil {
		t.Fatalf("COSE 公钥解析失败（手拼的 CBOR 键序/长度不对）: %v", err)
	}
	if _, ok := key.(webauthncose.OKPPublicKeyData); !ok {
		t.Errorf("公钥应解析成 OKP(Ed25519)，得到 %T", key)
	}

	const challenge = "Y2hhbGxlbmdlLXRlc3Q"
	const uid = 1234567
	raw, err := a.Assertion(challenge, uid)
	if err != nil {
		t.Fatalf("造断言: %v", err)
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(raw)
	if err != nil {
		t.Fatalf("断言解析失败: %v", err)
	}
	if parsed.Response.CollectedClientData.Challenge != challenge {
		t.Errorf("challenge 应原样带回，得到 %q", parsed.Response.CollectedClientData.Challenge)
	}
	if parsed.Response.CollectedClientData.Origin != Origin {
		t.Errorf("origin 应为 %q，得到 %q", Origin, parsed.Response.CollectedClientData.Origin)
	}
	wantHandle := UserHandle(uid)
	if string(parsed.Response.UserHandle) != string(wantHandle) {
		t.Errorf("userHandle 应是 uid 的 8 字节大端，得到 %x", parsed.Response.UserHandle)
	}
	if base64.RawURLEncoding.EncodeToString(parsed.RawID) != parsed.ID {
		t.Error("id 与 rawId 必须是同一串的两种写法")
	}
	if !parsed.Response.AuthenticatorData.Flags.HasUserPresent() ||
		!parsed.Response.AuthenticatorData.Flags.HasUserVerified() {
		t.Errorf("flags 应带 UP|UV，得到 %#x", parsed.Response.AuthenticatorData.Flags)
	}

	// App 形态：整体是 JSON 字符串，解一层必须回到同一份对象字节
	stringified, err := a.StringifiedAssertion(challenge, uid)
	if err != nil {
		t.Fatalf("造字符串形态断言: %v", err)
	}
	var asString string
	if err := json.Unmarshal(stringified, &asString); err != nil {
		t.Fatalf("App 形态应是 JSON 字符串: %v", err)
	}
	if asString != string(raw) {
		t.Error("字符串形态应与对象形态逐字节同源")
	}
}
