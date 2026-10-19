// Package webauthntest 合成一把能通过 go-webauthn 校验的 passkey 与它的登录断言——
// 真库用例既不引浏览器也不碰平台 Credential Manager（规格 A3 的测试基建口径：
// 「WebAuthn 测试用库 protocol 层构造」），只拼出库认的形态。
//
// 仅供测试使用：产出的凭证/断言只在本仓的真库用例里落 rows 与打路由，
// 不参与任何生产路径。
package webauthntest

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// RPID 是合成断言要对上的 RP 分区（与 internal/auth 的 passkeyRPID 同值：
// 那边不导出，这里按规格 A1.1 的定案再写一遍，改 RP 的规格变更要两处一起动）。
const RPID = "horatio.cn"

// Origin 是合成断言用的 web origin——与网页端一致，落在测试形态
// NewWebAuthn(nil) 的 RPOrigins（https://auth.horatio.cn）里。
const Origin = "https://auth.horatio.cn"

// Authenticator 是一把合成的 passkey：Ed25519 密钥对 + 随机 credential id。
type Authenticator struct {
	// Credential 是可直接落 passkeys 行的形态（ID 原始字节、COSE 公钥、flags、
	// sign_count 起 0、transports=internal）——落库那一列列名各测试自己写 SQL，
	// 本包不碰 database/sql。
	Credential *webauthn.Credential
	priv       ed25519.PrivateKey
}

// New 造一把新 passkey。每次调用一把不同的 credential id，测试之间不会撞 UNIQUE。
func New() (*Authenticator, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("生成 Ed25519 密钥对: %w", err)
	}
	id := make([]byte, 32)
	if _, err := rand.Read(id); err != nil {
		return nil, fmt.Errorf("生成 credential id: %w", err)
	}
	cred := &webauthn.Credential{
		ID:        id,
		PublicKey: cosePublicKeyEd25519(pub),
		Transport: []protocol.AuthenticatorTransport{"internal"},
		// BE/BS 都为 0：断言侧的 flags 必须与落库值一致（库校验 BE 不变量），
		// 两边都关最省事，也不必为合成数据造备份态。
		Flags: webauthn.CredentialFlags{},
	}
	return &Authenticator{Credential: cred, priv: priv}, nil
}

// UserHandle 把 uid 编成 8 字节大端（不足 8 字节前补零）——与 internal/auth 的
// WebAuthnID 同一口径：discoverable 登录靠 userHandle 反查账号，错位就认错人。
func UserHandle(uid int64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(uid))
	return b
}

// Assertion 造一条 discoverable 登录断言（**对象形态**，网页端就是这么发的）：
//
//	clientData 带仪式 challenge 与 web origin、crossOrigin=false；
//	authData  = rpIdHash ‖ flags(UP|UV) ‖ counter(1)——counter 比落库的 0 前进，
//	            免得克隆判定（新 ≤ 旧且旧非 0）平白告警；
//	signature = Ed25519(authData ‖ sha256(clientData))，userHandle = uid 的 8 字节大端。
func (a *Authenticator) Assertion(challenge string, uid int64) ([]byte, error) {
	clientData, err := json.Marshal(map[string]any{
		"type":        protocol.AssertCeremony,
		"challenge":   challenge,
		"origin":      Origin,
		"crossOrigin": false,
	})
	if err != nil {
		return nil, fmt.Errorf("序列化 clientData: %w", err)
	}
	rpHash := sha256.Sum256([]byte(RPID))
	authData := make([]byte, 0, 37)
	authData = append(authData, rpHash[:]...)
	authData = append(authData, 0x05)      // UP(0x01) | UV(0x04)，AT/ED 都为 0
	authData = append(authData, 0, 0, 0, 1) // counter = 1（大端）

	clientHash := sha256.Sum256(clientData)
	sigInput := make([]byte, 0, len(authData)+len(clientHash))
	sigInput = append(sigInput, authData...)
	sigInput = append(sigInput, clientHash[:]...)
	sig := ed25519.Sign(a.priv, sigInput)

	b64 := base64.RawURLEncoding
	id := b64.EncodeToString(a.Credential.ID)
	return json.Marshal(map[string]any{
		"id":     id,
		"rawId":  id,
		"type":   string(protocol.PublicKeyCredentialType),
		"clientExtensionResults": map[string]any{},
		"response": map[string]any{
			"clientDataJSON":     b64.EncodeToString(clientData),
			"authenticatorData": b64.EncodeToString(authData),
			"signature":          b64.EncodeToString(sig),
			"userHandle":         b64.EncodeToString(UserHandle(uid)),
		},
	})
}

// StringifiedAssertion 把断言再 JSON 编码一层：日记 App 发的是 Credential Manager 的
// authenticationResponseJson，字段值是**字符串**（WebAuthDtos.kt 的 response: String），
// 与网页端的对象形态并存，服务端两形态都收（见 cmd/server/web.go 的 credentialJSON）。
func (a *Authenticator) StringifiedAssertion(challenge string, uid int64) (json.RawMessage, error) {
	raw, err := a.Assertion(challenge, uid)
	if err != nil {
		return nil, err
	}
	return json.Marshal(string(raw))
}

// cosePublicKeyEd25519 手拼 COSE_Key：map(4) {1: OKP(1), 3: EdDSA(-8),
// -1: Ed25519(6), -2: 32 字节公钥}。键按 RFC 8949 确定性编码的顺序排列
//（0x01 < 0x03 < 0x20 < 0x21）——为一条测试数据引 CBOR 依赖不值得。
func cosePublicKeyEd25519(pub ed25519.PublicKey) []byte {
	out := []byte{0xa4, 0x01, 0x01, 0x03, 0x27, 0x20, 0x06, 0x21, 0x58, 0x20}
	return append(out, pub...)
}
