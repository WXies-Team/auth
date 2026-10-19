package auth

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// Passkey（WebAuthn）的口径，逐条对齐规格 A1.1：
//
//	RP ID = horatio.cn（auth.horatio.cn 的 eTLD+1）——两个子域与两个日记 App 共用
//	同一批 passkey，不必做 Related Origin Requests（只在跨 eTLD+1 时才需要）。
//	仪式中间态 SessionData 整体 JSON 落库，5 分钟过期、用后即焚；
//	凭证按 credential_id UNIQUE + rp_id 列分区；每次登录回写 sign_count。
const (
	// passkeyRPID 是凭证的 RP 分区键。凭证必须按 RP 存——另一 RP 的行不能拿来
	// 认这里的登录，这是 WebAuthn 的硬规则，不是本仓的偏好。
	passkeyRPID = "horatio.cn"
	// challengeTTL 对齐邮箱验证码的 5 分钟：仪式是「扫码/弹窗」这一下，久等无益。
	challengeTTL = 5 * time.Minute
	// PasskeyCeremonyRegister / Login 是 webauthn_challenges.kind 的两值。
	PasskeyCeremonyRegister = "register"
	PasskeyCeremonyLogin    = "login"
)

// PasskeyInfo 是 /api/passkeys 的一条记录。
type PasskeyInfo struct {
	ID         int64  `json:"id"`
	Name       string `json:"name"`
	CreatedAt  int64  `json:"createdAt"`
	LastUsedAt int64  `json:"lastUsedAt"`
	Current    bool   `json:"current"`
}

// NewWebAuthn 组装 RP 实例，配置逐字段按规格 A1.1。
//
// opaqueOrigins 是 Android 原生仪式的 `android:apk-key-hash:<证书指纹>` 清单
//（app_config 键 webauthn_opaque_origins，逗号分隔，指纹由 App 侧提供后灌库）：
// 没配时网页端照常可用，只是两个日记 App 的原生仪式会被 origin 校验挡下——
// 那是「配置还没到位」的可诊断状态，不是崩溃。
func NewWebAuthn(opaqueOrigins []string) (*webauthn.WebAuthn, error) {
	cfg := &webauthn.Config{
		RPID:            passkeyRPID,
		RPDisplayName:   "Auth",
		RPOrigins:       []string{"https://auth.horatio.cn"},
		RPOpaqueOrigins: opaqueOrigins,
		// v0.18.2 的常量名：PreferNoAttestation（= attestation:none）。
		// 与 VerificationRequired / ResidentKeyRequirementRequired 组成消费级 passkey
		// 的标准组合：不要 attestation 报告、但强制用户在场验证 + discoverable 凭证。
		AttestationPreference: protocol.PreferNoAttestation,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementRequired, // discoverable 登录的前提
			UserVerification: protocol.VerificationRequired,
		},
		Timeouts: webauthn.TimeoutsConfig{
			Login:        webauthn.TimeoutConfig{Enforce: true},
			Registration: webauthn.TimeoutConfig{Enforce: true},
		},
	}
	return webauthn.New(cfg)
}

// ---- User 适配层 ----

// passkeyUser 把本仓的 users 行适配成库的 User 接口。
//
// WebAuthnID 取**雪花 uid 的 8 字节大端**：稳定（邮箱可改）、可逆（discoverable
// 登录靠 userHandle 反查账号）、≤64 字节上限。不用邮箱——改绑邮箱会让
// userHandle 与账号错位，passkey 归属就断了。
type passkeyUser struct {
	svc   *Service
	uid   int64
	email string
	creds []webauthn.Credential
}

func (u *passkeyUser) WebAuthnID() []byte { return webAuthnID(u.uid) }
func (u *passkeyUser) WebAuthnName() string {
	return u.email
}
func (u *passkeyUser) WebAuthnDisplayName() string {
	// 显示名只给认证器的选人 UI 看：邮箱比「Auth 用户」更能让人认出这是谁的账号
	return u.email
}
func (u *passkeyUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

// webAuthnID 把 uid 编成 8 字节大端（不足 8 字节前补零，uid 恒正、恒 ≤64 位）。
func webAuthnID(uid int64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(uid))
	return b
}

// uidFromWebAuthnID 是 webAuthnID 的逆：长度不对或溢出有符号位都按「查无此账号」报，
// 交给上层回 404——拿垃圾 userHandle 不该变成 500。
func uidFromWebAuthnID(b []byte) (int64, error) {
	if len(b) != 8 {
		return 0, fmt.Errorf("userHandle 长度 %d 非法", len(b))
	}
	v := binary.BigEndian.Uint64(b)
	if v&(1<<63) != 0 {
		return 0, errors.New("userHandle 不是合法 uid")
	}
	return int64(v), nil
}

// passkeyUserFor 装配用户（邮箱 + 该 RP 下的全部凭证）。
func (s *Service) passkeyUserFor(uid int64) (*passkeyUser, error) {
	var email string
	err := s.pool.QueryRowContext(context.Background(), "SELECT email FROM users WHERE id = ?", uid).Scan(&email)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, unauthorized("登录已过期，请重新登录")
	}
	if err != nil {
		return nil, fmt.Errorf("查用户: %w", err)
	}
	creds, err := s.loadCredentials(uid)
	if err != nil {
		return nil, err
	}
	return &passkeyUser{svc: s, uid: uid, email: email, creds: creds}, nil
}

// ---- 仪式中间态 ----

// saveChallenge 把 SessionData 整体 JSON 落库（库规定唯一持久化形态），回 ceremonyId。
// JSON 而非手拼字段：SessionData.Extensions 的序列化形态随库版本漂移，pin 死版本 +
// 整体存取，升级时旧行一起清（见风险清单第 4 条）。
func (s *Service) saveChallenge(kind string, userID *int64, sd *webauthn.SessionData) (int64, error) {
	raw, err := json.Marshal(sd)
	if err != nil {
		return 0, fmt.Errorf("序列化仪式数据: %w", err)
	}
	now := time.Now()
	id := s.ids.Generate().Int64()
	if _, err := s.pool.ExecContext(context.Background(),
		`INSERT INTO webauthn_challenges (id, kind, user_id, session_data, expires_at, created_at)
		 VALUES (?,?,?,?,?,?)`,
		id, kind, userID, string(raw), now.Add(challengeTTL).UnixMilli(), now.UnixMilli()); err != nil {
		return 0, fmt.Errorf("落仪式中间态: %w", err)
	}
	// 顺手清过期行（表常年只有个位数行，全表删可忽略）
	_, _ = s.pool.ExecContext(context.Background(),
		"DELETE FROM webauthn_challenges WHERE expires_at < ?", now.Add(-challengeTTL).UnixMilli())
	return id, nil
}

// takeChallenge 取出并**立刻删行**：单次性由删除保证，成功失败都已消费
//（「失败可以再试一次」的余地不给——重放同一 ceremonyId 是最常见的绕过姿势）。
// 缺行、过期、kind 或 uid 不对，统一回 404（不区分，免得当探针）。
func (s *Service) takeChallenge(ceremonyID int64, kind string, uid int64) (*webauthn.SessionData, error) {
	ctx := context.Background()
	tx, err := s.pool.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("开事务: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var raw string
	var owner sql.NullInt64
	var expires int64
	err = tx.QueryRowContext(ctx,
		"SELECT session_data, user_id, expires_at FROM webauthn_challenges WHERE id = ? AND kind = ? FOR UPDATE",
		ceremonyID, kind).Scan(&raw, &owner, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, &HTTPError{404, "验证请求已过期，请重新发起"}
	}
	if err != nil {
		return nil, fmt.Errorf("查仪式中间态: %w", err)
	}
	// register 仪式必须绑发起者；login（discoverable）行的 user_id 为 NULL，
	// 不参与比对——认人靠 userHandle 反查，不靠建仪式时猜
	if kind == PasskeyCeremonyRegister && (!owner.Valid || owner.Int64 != uid) {
		return nil, &HTTPError{404, "验证请求已过期，请重新发起"}
	}
	if time.Now().UnixMilli() > expires {
		return nil, &HTTPError{404, "验证请求已过期，请重新发起"}
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM webauthn_challenges WHERE id = ?", ceremonyID); err != nil {
		return nil, fmt.Errorf("消费仪式中间态: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("提交消费: %w", err)
	}
	var sd webauthn.SessionData
	if err := json.Unmarshal([]byte(raw), &sd); err != nil {
		return nil, fmt.Errorf("解析仪式数据: %w", err)
	}
	return &sd, nil
}

// synthRequest 给库构造一个只带浏览器响应体的 *http.Request：库的 Finish* 按
// 「body 就是 PublicKeyCredential JSON」解析，而我们的端点还要从同一个 body 里
// 取 ceremonyId，解一次再还给它——用原始字节重新包一个请求，不碰已消费的流。
func synthRequest(body []byte) *http.Request {
	return &http.Request{
		Method: http.MethodPost,
		Header: http.Header{"Content-Type": []string{"application/json"}},
		Body:   io.NopCloser(bytes.NewReader(body)),
	}
}

// ---- 注册 ----

// BeginPasskeyRegistration 发起注册仪式：回库的 CredentialCreation 与 ceremonyId。
func (s *Service) BeginPasskeyRegistration(c Caller) (*protocol.CredentialCreation, int64, error) {
	if s.wa == nil {
		return nil, 0, &HTTPError{503, "Passkey 服务暂不可用，请稍后重试"}
	}
	user, err := s.passkeyUserFor(c.UID)
	if err != nil {
		return nil, 0, err
	}
	creation, sd, err := s.wa.BeginRegistration(user)
	if err != nil {
		return nil, 0, fmt.Errorf("发起注册仪式: %w", err)
	}
	id, err := s.saveChallenge(PasskeyCeremonyRegister, &c.UID, sd)
	if err != nil {
		return nil, 0, err
	}
	return creation, id, nil
}

// FinishPasskeyRegistration 校验注册回执并落凭证行。
// 默认名按发起请求的 UA 推断（shortDevice：Chrome · Linux 之类）——用户不必先想名字，
// 之后随时在列表里改。
func (s *Service) FinishPasskeyRegistration(c Caller, ceremonyID int64, body []byte, meta SessionMeta) (*PasskeyInfo, error) {
	if s.wa == nil {
		return nil, &HTTPError{503, "Passkey 服务暂不可用，请稍后重试"}
	}
	sd, err := s.takeChallenge(ceremonyID, PasskeyCeremonyRegister, c.UID)
	if err != nil {
		return nil, err
	}
	user, err := s.passkeyUserFor(c.UID)
	if err != nil {
		return nil, err
	}
	cred, err := s.wa.FinishRegistration(user, *sd, synthRequest(body))
	if err != nil {
		slog.Warn("passkey 注册仪式失败", "uid", c.UID, "err", err)
		return nil, &HTTPError{400, "Passkey 注册未通过校验，请重试"}
	}
	name := shortDevice(meta.UserAgent)
	id, err := s.insertCredential(c.UID, name, cred)
	if err != nil {
		return nil, err
	}
	return &PasskeyInfo{ID: id, Name: name, CreatedAt: time.Now().UnixMilli(), LastUsedAt: 0}, nil
}

// ---- 登录 ----

// BeginPasskeyLogin 发起 discoverable 登录：allowCredentials 留空 + UV required，
// 让系统弹「用通行密钥登录」而不是先要账号。
func (s *Service) BeginPasskeyLogin() (*protocol.CredentialAssertion, int64, error) {
	if s.wa == nil {
		return nil, 0, &HTTPError{503, "Passkey 服务暂不可用，请稍后重试"}
	}
	assertion, sd, err := s.wa.BeginDiscoverableLogin()
	if err != nil {
		return nil, 0, fmt.Errorf("发起登录仪式: %w", err)
	}
	id, err := s.saveChallenge(PasskeyCeremonyLogin, nil, sd)
	if err != nil {
		return nil, 0, err
	}
	return assertion, id, nil
}

// FinishPasskeyLogin 校验登录回执：userHandle（=uid 8 字节大端）反查账号，
// 回写 sign_count 与 backup_state，交调用方去建会话。
//
// sign_count 克隆判定：新值 ≤ 旧值且旧值非 0 时**记告警不拒绝**——同步型 passkey
// 常年报 0，拒绝会误杀主流的手机通行密钥（业界通行做法，残余风险已声明）。
func (s *Service) FinishPasskeyLogin(ceremonyID int64, body []byte) (int64, string, string, error) {
	if s.wa == nil {
		return 0, "", "", &HTTPError{503, "Passkey 服务暂不可用，请稍后重试"}
	}
	sd, err := s.takeChallenge(ceremonyID, PasskeyCeremonyLogin, 0)
	if err != nil {
		return 0, "", "", err
	}
	handler := func(rawID, userHandle []byte) (webauthn.User, error) {
		uid, err := uidFromWebAuthnID(userHandle)
		if err != nil {
			return nil, err
		}
		return s.passkeyUserFor(uid)
	}
	user, cred, err := s.wa.FinishPasskeyLogin(handler, *sd, synthRequest(body))
	if err != nil {
		slog.Warn("passkey 登录仪式失败", "err", err)
		return 0, "", "", &HTTPError{400, "Passkey 验证失败，请重试"}
	}
	pu, ok := user.(*passkeyUser)
	if !ok {
		return 0, "", "", &HTTPError{400, "Passkey 验证失败，请重试"}
	}
	if err := s.recordCredentialUse(pu.uid, cred); err != nil {
		// 回写失败不拦登录：登录已经成立，丢的只是一次计数
		slog.Warn("回写 passkey 使用记录失败", "uid", pu.uid, "err", err)
	}
	return pu.uid, pu.email, base64.RawURLEncoding.EncodeToString(cred.ID), nil
}

// recordCredentialUse 回写 sign_count / backup_state / last_used_at，并做克隆告警。
func (s *Service) recordCredentialUse(uid int64, cred *webauthn.Credential) error {
	credID := base64.RawURLEncoding.EncodeToString(cred.ID)
	var oldCount int64
	err := s.pool.QueryRowContext(context.Background(),
		"SELECT sign_count FROM passkeys WHERE credential_id = ? AND user_id = ? AND rp_id = ?",
		credID, uid, passkeyRPID).Scan(&oldCount)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("查凭证计数: 凭证不存在")
	}
	if err != nil {
		return fmt.Errorf("查凭证计数: %w", err)
	}
	newCount := int64(cred.Authenticator.SignCount)
	if newCount <= oldCount && oldCount != 0 {
		slog.Warn("passkey 计数器未前进，可能是克隆或同步型实现",
			"uid", uid, "old", oldCount, "new", newCount)
	}
	_, err = s.pool.ExecContext(context.Background(),
		`UPDATE passkeys SET sign_count = ?, backup_state = ?, last_used_at = ?
		 WHERE credential_id = ? AND user_id = ?`,
		newCount, boolInt(cred.Flags.BackupState), time.Now().UnixMilli(), credID, uid)
	if err != nil {
		return fmt.Errorf("回写凭证: %w", err)
	}
	return nil
}

// ---- 列表 / 改名 / 删除 ----

// ListPasskeys 回当前账号的全部凭证；current 标出**本会话登录用的那把**。
func (s *Service) ListPasskeys(uid, currentSID int64) ([]PasskeyInfo, error) {
	rows, err := s.pool.QueryContext(context.Background(),
		`SELECT id, name, created_at, last_used_at FROM passkeys
		 WHERE user_id = ? AND rp_id = ? ORDER BY created_at DESC, id DESC`, uid, passkeyRPID)
	if err != nil {
		return nil, fmt.Errorf("查 passkey 列表: %w", err)
	}
	defer func() { _ = rows.Close() }()
	current := s.credentialOfSession(currentSID)
	out := make([]PasskeyInfo, 0, 4)
	for rows.Next() {
		var it PasskeyInfo
		var lastUsed sql.NullInt64
		if err := rows.Scan(&it.ID, &it.Name, &it.CreatedAt, &lastUsed); err != nil {
			return nil, fmt.Errorf("读 passkey 行: %w", err)
		}
		if lastUsed.Valid {
			it.LastUsedAt = lastUsed.Int64
		}
		out = append(out, it)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("遍历 passkey: %w", err)
	}
	if current != "" {
		for i := range out {
			if cred, err := s.credentialIDFor(out[i].ID); err == nil && cred == current {
				out[i].Current = true
			}
		}
	}
	return out, nil
}

// RenamePasskey 只改名字：名字是纯展示字段，动它不碰凭证与仪式。
func (s *Service) RenamePasskey(uid, id int64, name string) error {
	name = truncateRunes(strings.TrimSpace(name), 64)
	if name == "" {
		return badRequest("名称不能为空")
	}
	res, err := s.pool.ExecContext(context.Background(),
		"UPDATE passkeys SET name = ? WHERE id = ? AND user_id = ? AND rp_id = ?",
		name, id, uid, passkeyRPID)
	if err != nil {
		return fmt.Errorf("改名: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return &HTTPError{404, "该 Passkey 不存在"}
	}
	return nil
}

// DeletePasskey 删凭证。守卫：**至少保留一种登录方式**——若这是最后一把 passkey
// 且账号既无密码也没开两步验证，拒绝（恢复手段不得弱于常规登录，OWASP MFA CS）。
func (s *Service) DeletePasskey(uid, id int64) error {
	ctx := context.Background()
	var rp string
	err := s.pool.QueryRowContext(ctx,
		"SELECT rp_id FROM passkeys WHERE id = ? AND user_id = ?", id, uid).Scan(&rp)
	if errors.Is(err, sql.ErrNoRows) {
		return &HTTPError{404, "该 Passkey 不存在"}
	}
	if err != nil {
		return fmt.Errorf("查 passkey: %w", err)
	}

	var total int
	if err := s.pool.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM passkeys WHERE user_id = ? AND rp_id = ?", uid, passkeyRPID).Scan(&total); err != nil {
		return fmt.Errorf("数 passkey: %w", err)
	}
	if total <= 1 {
		var pw sql.NullString
		var totp int
		if err := s.pool.QueryRowContext(ctx, "SELECT password_hash FROM users WHERE id = ?", uid).Scan(&pw); err != nil {
			return fmt.Errorf("查密码: %w", err)
		}
		if err := s.pool.QueryRowContext(ctx,
			"SELECT COUNT(*) FROM totp_factors WHERE user_id = ? AND enabled = 1", uid).Scan(&totp); err != nil {
			return fmt.Errorf("查两步验证: %w", err)
		}
		hasPassword := pw.Valid && strings.TrimSpace(pw.String) != ""
		if !hasPassword && totp == 0 {
			return badRequest("这是最后一种登录方式，删除后将无法登录：请先设置密码或开启两步验证")
		}
	}
	if _, err := s.pool.ExecContext(ctx,
		"DELETE FROM passkeys WHERE id = ? AND user_id = ? AND rp_id = ?", id, uid, passkeyRPID); err != nil {
		return fmt.Errorf("删除 passkey: %w", err)
	}
	return nil
}

// ---- 凭证存取 ----

// insertCredential 落一行凭证。credential_id 撞 UNIQUE（同一把 passkey 重复绑定）
// 翻成 409——用户重试「添加」时手里那把已经绑过了，回 409 比 500 更可执行。
func (s *Service) insertCredential(uid int64, name string, cred *webauthn.Credential) (int64, error) {
	id := s.ids.Generate().Int64()
	transports := make([]string, 0, len(cred.Transport))
	for _, t := range cred.Transport {
		transports = append(transports, string(t))
	}
	var aaguid string
	if len(cred.Authenticator.AAGUID) > 0 {
		aaguid = hex.EncodeToString(cred.Authenticator.AAGUID)
	}
	_, err := s.pool.ExecContext(context.Background(),
		`INSERT INTO passkeys
		 (id, user_id, name, credential_id, rp_id, public_key, sign_count, transports, aaguid,
		  backup_eligible, backup_state, created_at)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
		id, uid, truncateRunes(strings.TrimSpace(name), 64),
		base64.RawURLEncoding.EncodeToString(cred.ID), passkeyRPID, cred.PublicKey,
		int64(cred.Authenticator.SignCount), strings.Join(transports, ","), aaguid,
		boolInt(cred.Flags.BackupEligible), boolInt(cred.Flags.BackupState), time.Now().UnixMilli())
	if err != nil {
		// 1062 = Duplicate entry（uq_passkeys_cred）
		if strings.Contains(err.Error(), "Duplicate entry") {
			return 0, &HTTPError{409, "这把 Passkey 已经绑定过了，无需重复添加"}
		}
		return 0, fmt.Errorf("落 passkey: %w", err)
	}
	return id, nil
}

// loadCredentials 读该用户在 passkeyRPID 下的全部凭证，映射回库的 Credential 形态。
// rp_id 必须进 WHERE——另一 RP 的行在这里一律不算数（credentials MUST be
// partitioned by RP ID）。
func (s *Service) loadCredentials(uid int64) ([]webauthn.Credential, error) {
	rows, err := s.pool.QueryContext(context.Background(),
		`SELECT credential_id, public_key, sign_count, transports, aaguid, backup_eligible, backup_state
		 FROM passkeys WHERE user_id = ? AND rp_id = ?`, uid, passkeyRPID)
	if err != nil {
		return nil, fmt.Errorf("查凭证: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := make([]webauthn.Credential, 0, 4)
	for rows.Next() {
		var (
			credID, transports, aaguid string
			pk                         []byte
			signCount                  int64
			be, bs                     int
		)
		if err := rows.Scan(&credID, &pk, &signCount, &transports, &aaguid, &be, &bs); err != nil {
			return nil, fmt.Errorf("读凭证行: %w", err)
		}
		rawID, err := base64.RawURLEncoding.DecodeString(credID)
		if err != nil {
			return nil, fmt.Errorf("解 credential_id: %w", err)
		}
		cred := webauthn.Credential{
			ID:        rawID,
			PublicKey: pk,
			Flags: webauthn.CredentialFlags{
				BackupEligible: be == 1,
				BackupState:    bs == 1,
			},
		}
		cred.Authenticator.SignCount = uint32(signCount)
		if aaguid != "" {
			if decoded, err := hex.DecodeString(aaguid); err == nil {
				cred.Authenticator.AAGUID = decoded
			}
		}
		for _, t := range strings.Split(transports, ",") {
			if t = strings.TrimSpace(t); t != "" {
				cred.Transport = append(cred.Transport, protocol.AuthenticatorTransport(t))
			}
		}
		out = append(out, cred)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("遍历凭证: %w", err)
	}
	return out, nil
}

// credentialIDFor 把列表行的 id 换成 credential_id（current 标记要比对它）。
func (s *Service) credentialIDFor(passkeyID int64) (string, error) {
	var cred string
	err := s.pool.QueryRowContext(context.Background(),
		"SELECT credential_id FROM passkeys WHERE id = ?", passkeyID).Scan(&cred)
	return cred, err
}

// ---- 「本会话用哪把 Passkey 登录」的进程内记录 ----
//
// 只为列表页 current 标记服务，丢了最多是少一行高亮——会话与凭证本体都在库里。
// 单实例假设与限流层一致（仓 AGENTS 已声明），重启即清。
func (s *Service) markPasskeyLogin(sid int64, credentialID string) {
	s.credBySIDMu.Lock()
	defer s.credBySIDMu.Unlock()
	if s.credBySID == nil {
		s.credBySID = map[int64]string{}
	}
	s.credBySID[sid] = credentialID
}

func (s *Service) credentialOfSession(sid int64) string {
	s.credBySIDMu.RLock()
	defer s.credBySIDMu.RUnlock()
	return s.credBySID[sid]
}

// boolInt 是 TINYINT 列的写入形态（MySQL 没有原生 bool 参数位）。
func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// parseCeremonyID 把路径里的 ceremonyId 解成 int64（雪花，非法串回 404 而不是 400：
// 这个值只有服务端发过，客户端拿着乱串说明仪式早就丢了）。
func parseCeremonyID(raw string) (int64, error) {
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || id <= 0 {
		return 0, &HTTPError{404, "验证请求已过期，请重新发起"}
	}
	return id, nil
}
