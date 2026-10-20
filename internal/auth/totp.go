package auth

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"image/png"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// TOTP 两步验证的口径（pquerna 官方流程 + OWASP MFA CS）：
//
//	30 秒 · 6 位 · ±1 步进（库默认，即 Google Authenticator 兼容参数）
//	先验后启：setup 只落 pending，enable 验过一次码才 enabled=1
//	同 timestep 不放行第二次（ASVS 6.5.1），恢复码 10 个、单次使用
const (
	// totpIssuer 是二维码里的应用名（Google Authenticator Key Uri Format 的 issuer 字段），
	// 与邮件品牌同口径取中性名 Auth。
	totpIssuer       = "Auth"
	totpPeriod       = 30
	totpMaxLoginTries = 5
	// recoveryCodeCount / 格式：16 位 Crockford 风格（去掉 I L O U，32 字符表）≈ 80 位熵，
	// 分四段连字符便于手抄。恢复码是 TOTP 丢失时的唯一后路，数量对齐主流厂商的量级。
	recoveryCodeCount    = 10
	recoveryCodeSegments = 4
	recoveryCodeSegLen   = 4
	// crockfordAlphabet：排除易混的 I/L/O/U，抄错率低且不影响熵（仍 5 bit/字符）。
	crockfordAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	// recoveryPepperLabel 是从 JWT_SECRET 派生恢复码 HMAC 密钥的域分隔串：
	// 同一个根密钥派出两把互不相干的子密钥，将来一把泄露不牵连另一把。
	recoveryPepperLabel = "recovery-code-pepper|"
	// pendingSecretSep 分隔 secret_cipher 里的「现用 secret」与「待验 pending secret」。
	// 重置流程要求旧 TOTP 在新码验过前照常可用——一行一用户的表结构下，两段塞进
	// 同一列即可，不必为 pending 单开表/列。
	pendingSecretSep = "\x00"
)

// TOTPStatus 是 GET /api/totp 的回执。CreatedAt 对已启用取启用时刻、对 pending 取
// 最近一次 setup——两种状态下「创建时间」指的都是用户看到的那件事。
type TOTPStatus struct {
	Enabled   bool  `json:"enabled"`
	CreatedAt int64 `json:"createdAt"`
}

// TOTPSetup 是 setup 的回执：二维码 data URI、otpauth URI 与明文 secret 三件套
//（Supabase 同做法——扫码之外永远留手输，扫不了码的人也要能绑）。
type TOTPSetup struct {
	Secret     string `json:"secret"`
	OTPAuthURI string `json:"otpauthUri"`
	QRDataURI  string `json:"qrPng"`
}

// totpFactor 是 totp_factors 一行的解码结果。
type totpFactor struct {
	Secret          string
	Pending         string // 非空 = 正在重置，验码目标是它而不是 Secret
	Enabled         bool
	LastUsedStep    int64
	ConfirmedAt     sql.NullInt64
	CreatedAt       int64
}

// sealSecret AES-256-GCM 加密 secret 明文，落库形态 nonce||ciphertext。
// pquerna README 明确要求「store the secret in an encrypted field」——TOTP secret 是
// 验证所需原值，没法像密码那样只存哈希，库被拖走也解不出。
func (s *Service) sealSecret(plain string) ([]byte, error) {
	block, err := aes.NewCipher(s.totpKey)
	if err != nil {
		return nil, fmt.Errorf("初始化 TOTP 加密: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("初始化 GCM: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("生成 nonce: %w", err)
	}
	return gcm.Seal(nonce, nonce, []byte(plain), nil), nil
}

// openSecret 解开 sealSecret 的产物；解不开（密钥换了/行被改）按「没有 TOTP」报错，
// 调用方据此让用户重新绑定——密钥丢失本来就等于已绑用户的 TOTP 全作废（部署文档口径）。
func (s *Service) openSecret(blob []byte) (string, error) {
	block, err := aes.NewCipher(s.totpKey)
	if err != nil {
		return "", fmt.Errorf("初始化 TOTP 加密: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("初始化 GCM: %w", err)
	}
	if len(blob) < gcm.NonceSize() {
		return "", errors.New("TOTP 密文过短")
	}
	plain, err := gcm.Open(nil, blob[:gcm.NonceSize()], blob[gcm.NonceSize():], nil)
	if err != nil {
		return "", errors.New("TOTP 密文解开失败")
	}
	return string(plain), nil
}

// loadFactor 取该用户的 TOTP 行（没有行 = 未绑定）。
func (s *Service) loadFactor(uid int64) (*totpFactor, error) {
	var (
		blob            []byte
		enabled         int
		step, confirmed sql.NullInt64
		createdAt       int64
	)
	err := s.pool.QueryRowContext(context.Background(),
		"SELECT secret_cipher, enabled, last_used_timestep, created_at, confirmed_at FROM totp_factors WHERE user_id = ?", uid).
		Scan(&blob, &enabled, &step, &createdAt, &confirmed)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("查 TOTP 因子: %w", err)
	}
	plain, err := s.openSecret(blob)
	if err != nil {
		return nil, err
	}
	f := &totpFactor{
		Enabled:      enabled == 1,
		LastUsedStep: step.Int64,
		ConfirmedAt:  confirmed,
		CreatedAt:    createdAt,
	}
	secret, pending, _ := strings.Cut(plain, pendingSecretSep)
	f.Secret, f.Pending = secret, pending
	return f, nil
}

// TOTPStatus 回绑定状态（GET /api/totp）。
func (s *Service) TOTPStatus(uid int64) (TOTPStatus, error) {
	f, err := s.loadFactor(uid)
	if err != nil {
		return TOTPStatus{}, err
	}
	if f == nil {
		return TOTPStatus{}, nil
	}
	st := TOTPStatus{Enabled: f.Enabled, CreatedAt: f.CreatedAt}
	if f.Enabled && f.ConfirmedAt.Valid {
		st.CreatedAt = f.ConfirmedAt.Int64
	}
	return st, nil
}

// SetupTOTP 生成 secret 并落 pending（enabled=0），回二维码 + 手输密钥。
//
// 已绑定时按**重置流程**走：新 secret 只作为 pending 进来，旧 secret 与 enabled
// 原样保留——发起 setup 的人哪怕是一时被冒用，也废不掉受害者手上那台验证器，
// 直到新码在 enable 里被验过（A1.2 第 3 步）。
func (s *Service) SetupTOTP(c Caller) (setup *TOTPSetup, err error) {
	defer func() {
		// setup 只是 pending：没启用前它不是安全能力的变化，但它是「有人在动
		// 两步验证」的信号，成败都记
		s.Audit(AuditEvent{
			Action: AuditTOTPSetup, OK: err == nil, ActorUID: uidPtr(c.UID),
			ActorEmail: maskEmail(c.Email), Meta: c.Meta,
		})
	}()
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      totpIssuer,
		AccountName: c.Email,
	})
	if err != nil {
		return nil, fmt.Errorf("生成 TOTP 密钥: %w", err)
	}
	secret := key.Secret()

	f, err := s.loadFactor(c.UID)
	if err != nil {
		return nil, err
	}
	plain := secret
	if f != nil && f.Enabled {
		// 保留现用 secret，新 secret 排在分隔符后等验
		plain = f.Secret + pendingSecretSep + secret
	}
	cipherText, err := s.sealSecret(plain)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	if f == nil {
		if _, err := s.pool.ExecContext(ctx,
			`INSERT INTO totp_factors (user_id, secret_cipher, enabled, last_used_timestep, created_at)
			 VALUES (?,?,0,0,?)`, c.UID, cipherText, time.Now().UnixMilli()); err != nil {
			return nil, fmt.Errorf("落 TOTP 因子: %w", err)
		}
	} else {
		if _, err := s.pool.ExecContext(ctx,
			"UPDATE totp_factors SET secret_cipher = ? WHERE user_id = ?", cipherText, c.UID); err != nil {
			return nil, fmt.Errorf("更新 TOTP 因子: %w", err)
		}
	}

	// 二维码：库自带 key.Image（内部 boombuler/barcode），出 PNG 后转 data URI——
	// 零额外 QR 依赖、零外链
	pngBytes, err := keyImage(key)
	if err != nil {
		return nil, err
	}
	return &TOTPSetup{
		Secret:     secret,
		OTPAuthURI: key.URL(),
		QRDataURI:  "data:image/png;base64," + base64.StdEncoding.EncodeToString(pngBytes),
	}, nil
}

// keyImage 把 otp.Key 画成 240×240 的 PNG。
func keyImage(key *otp.Key) ([]byte, error) {
	img, err := key.Image(240, 240)
	if err != nil {
		return nil, fmt.Errorf("生成二维码: %w", err)
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, fmt.Errorf("编码二维码: %w", err)
	}
	return buf.Bytes(), nil
}

// EnableTOTP 验一次码才启用（先验后启），同事务生成 10 个恢复码——
// 两步不同批的话，「已启用但没有恢复码」的中间态会让 TOTP 一丢就锁死账号。
func (s *Service) EnableTOTP(c Caller, code string) (codes []string, err error) {
	defer func() {
		if err == nil {
			// 启用与恢复码生成是同一批动作的两件事，各记一条（规格 A2.2「审计×2」）
			s.Audit(AuditEvent{
				Action: AuditTOTPEnable, OK: true, ActorUID: uidPtr(c.UID),
				ActorEmail: maskEmail(c.Email), Meta: c.Meta,
			})
			s.Audit(AuditEvent{
				Action: AuditRecoveryGen, OK: true, ActorUID: uidPtr(c.UID),
				ActorEmail: maskEmail(c.Email), Meta: c.Meta,
				Detail: map[string]string{"reason": "enable"},
			})
		}
	}()
	if strings.TrimSpace(code) == "" {
		return nil, badRequest("请输入验证码")
	}
	f, err := s.loadFactor(c.UID)
	if err != nil {
		return nil, err
	}
	if f == nil {
		return nil, badRequest("请先开始两步验证设置")
	}
	target := f.Secret
	if f.Pending != "" {
		// 重置流程：验的是新 secret，旧 secret 仍能用到 enable 成功为止
		target = f.Pending
	}
	// 验的是**新 secret**（首次 setup 时就是 secret 本身），不比 last_used_timestep：
	// 那一列跟的是现用 secret 的重放账，pending 是没用过的新码，拿旧账去卡只会把
	//「同一窗口内登录过再启用」误杀。验过立刻把命中步进记上，enable 码自己不能重放。
	step, ok := s.verifyTOTPAt(target, code, 0)
	if !ok {
		return nil, badRequest("验证码错误，请重新输入")
	}

	// 启用 = 换代：pending 顶掉旧 secret（没有 pending 就是首次启用）
	secret := target
	cipherText, err := s.sealSecret(secret)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	codes, err = generateRecoveryCodes()
	if err != nil {
		return nil, err
	}
	pepper := s.recoveryPepper

	tx, err := s.pool.BeginTx(context.Background(), nil)
	if err != nil {
		return nil, fmt.Errorf("开事务: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(context.Background(),
		`UPDATE totp_factors SET secret_cipher = ?, enabled = 1, last_used_timestep = ?, confirmed_at = ?
		 WHERE user_id = ?`, cipherText, step, now.UnixMilli(), c.UID); err != nil {
		return nil, fmt.Errorf("启用 TOTP: %w", err)
	}
	// 旧恢复码整组作废：新码表接替，留着旧的等于多一份没主的后门
	if _, err := tx.ExecContext(context.Background(),
		"DELETE FROM recovery_codes WHERE user_id = ?", c.UID); err != nil {
		return nil, fmt.Errorf("清空旧恢复码: %w", err)
	}
	for _, rc := range codes {
		if _, err := tx.ExecContext(context.Background(),
			"INSERT INTO recovery_codes (user_id, code_hash, used, created_at) VALUES (?, ?, 0, ?)",
			c.UID, hashRecoveryCode(pepper, normalizeRecoveryCode(rc)), now.UnixMilli()); err != nil {
			return nil, fmt.Errorf("落恢复码: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("提交启用: %w", err)
	}
	return codes, nil
}

// DisableTOTP 关闭两步验证：当前 TOTP 码或恢复码任一可解（TOTP 手机丢了就靠
// 恢复码收尾，堵死「丢了手机+没恢复码」之外的任何死锁）。解绑同时删恢复码，
// 并吊销其它会话——因子变了，别让旧设备继续挂着（ASVS 7.4.3）。
func (s *Service) DisableTOTP(c Caller, code string) (err error) {
	defer func() {
		s.Audit(AuditEvent{
			Action: AuditTOTPDisable, OK: err == nil, ActorUID: uidPtr(c.UID),
			ActorEmail: maskEmail(c.Email), Meta: c.Meta,
		})
	}()
	if strings.TrimSpace(code) == "" {
		return badRequest("请输入验证码")
	}
	f, err := s.loadFactor(c.UID)
	if err != nil {
		return err
	}
	if f == nil || !f.Enabled {
		return badRequest("两步验证尚未开启")
	}
	used, err := s.consumeRecoveryCode(c.UID, c.Email, code, c.Meta)
	if err != nil {
		return err
	}
	if !used {
		step, ok := s.verifyTOTPAt(f.Secret, code, f.LastUsedStep)
		if !ok {
			return badRequest("验证码错误，请重新输入")
		}
		// 记下命中步进：解绑用过的码，不能再拿来换发恢复码
		if _, err := s.pool.ExecContext(context.Background(),
			"UPDATE totp_factors SET last_used_timestep = ? WHERE user_id = ?", step, c.UID); err != nil {
			return fmt.Errorf("记录 TOTP timestep: %w", err)
		}
	}
	tx, err := s.pool.BeginTx(context.Background(), nil)
	if err != nil {
		return fmt.Errorf("开事务: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(context.Background(),
		"DELETE FROM totp_factors WHERE user_id = ?", c.UID); err != nil {
		return fmt.Errorf("删除 TOTP 因子: %w", err)
	}
	if _, err := tx.ExecContext(context.Background(),
		"DELETE FROM recovery_codes WHERE user_id = ?", c.UID); err != nil {
		return fmt.Errorf("删除恢复码: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("提交关闭: %w", err)
	}
	return s.RevokeOtherSessions(c.UID, c.SID)
}

// RegenerateRecoveryCodes 换发恢复码：验 TOTP 或任一旧恢复码，整组换新、旧组即废。
func (s *Service) RegenerateRecoveryCodes(c Caller, code string) (codes []string, err error) {
	defer func() {
		// 换发即整组作废，是安全事件：成功必记（失败由调用方的 4xx 体现）
		if err == nil {
			s.Audit(AuditEvent{
				Action: AuditRecoveryGen, OK: true, ActorUID: uidPtr(c.UID),
				ActorEmail: maskEmail(c.Email), Meta: c.Meta,
				Detail: map[string]string{"reason": "regenerate"},
			})
		}
	}()
	if strings.TrimSpace(code) == "" {
		return nil, badRequest("请输入验证码")
	}
	f, err := s.loadFactor(c.UID)
	if err != nil {
		return nil, err
	}
	if f == nil || !f.Enabled {
		return nil, badRequest("两步验证尚未开启")
	}
	used, err := s.consumeRecoveryCode(c.UID, c.Email, code, c.Meta)
	if err != nil {
		return nil, err
	}
	if !used {
		step, ok := s.verifyTOTPAt(f.Secret, code, f.LastUsedStep)
		if !ok {
			return nil, badRequest("验证码错误，请重新输入")
		}
		if _, err := s.pool.ExecContext(context.Background(),
			"UPDATE totp_factors SET last_used_timestep = ? WHERE user_id = ?", step, c.UID); err != nil {
			return nil, fmt.Errorf("记录 TOTP timestep: %w", err)
		}
	}
	codes, err = generateRecoveryCodes()
	if err != nil {
		return nil, err
	}
	tx, err := s.pool.BeginTx(context.Background(), nil)
	if err != nil {
		return nil, fmt.Errorf("开事务: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(context.Background(),
		"DELETE FROM recovery_codes WHERE user_id = ?", c.UID); err != nil {
		return nil, fmt.Errorf("清空旧恢复码: %w", err)
	}
	now := time.Now().UnixMilli()
	for _, rc := range codes {
		if _, err := tx.ExecContext(context.Background(),
			"INSERT INTO recovery_codes (user_id, code_hash, used, created_at) VALUES (?, ?, 0, ?)",
			c.UID, hashRecoveryCode(s.recoveryPepper, normalizeRecoveryCode(rc)), now); err != nil {
			return nil, fmt.Errorf("落恢复码: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("提交换发: %w", err)
	}
	return codes, nil
}

// VerifyTOTPCode 登录侧验码：验过即记 timestep（同 timestep 重放拒）。
// 没绑定 / 未启用一律 false——调用方（登录编排）据此分流，不回原因给端点外。
//
// 重放闸是**一条原子 UPDATE**：`WHERE last_used_timestep < step` 按 RowsAffected
// 判定归属——并发提交同一个码时 InnoDB 行锁让两个事务串行，后者 WHERE 不再命中
//（0 行）自然落败。旧实现「SELECT 看账再 UPDATE 覆盖写」两步之间有窗口，
// 并发同码可双双放行（ASVS 6.5.1「一次一用」失守）。
func (s *Service) VerifyTOTPCode(uid int64, code string) (bool, error) {
	if strings.TrimSpace(code) == "" {
		return false, nil
	}
	f, err := s.loadFactor(uid)
	if err != nil {
		return false, err
	}
	if f == nil || !f.Enabled {
		return false, nil
	}
	// 先按当前账面拒掉重放（快路径，省一次写）；真正的归属判定在下面的原子 UPDATE
	step, ok := s.verifyTOTPAt(f.Secret, code, f.LastUsedStep)
	if !ok {
		return false, nil
	}
	res, err := s.pool.ExecContext(context.Background(),
		"UPDATE totp_factors SET last_used_timestep = ? WHERE user_id = ? AND last_used_timestep < ?",
		step, uid, step)
	if err != nil {
		return false, fmt.Errorf("记录 TOTP timestep: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("读 TOTP 重放闸结果: %w", err)
	}
	// 0 行 = 同步进已被并发对手抢先记账：重放，拒
	return n == 1, nil
}

// verifyTOTPAt 校验码并回**命中的步进序号**（0 = 没通过），附带两条闸：±1 步进
//（库默认的 Google Authenticator 兼容参数）、同步进已用过则拒（抓「录一次码反复放」）。
//
// 不用 totp.ValidateCustom 的 bool——它不告诉你命中的步进，重放就没法按步进挡。
// 这里按相邻三个步进各自**生成**预期码再比对：既拿到精确步进，比较也走常数时间
//（逐字符相等会让「差几位」变成计时信号）。
func (s *Service) verifyTOTPAt(secret, code string, lastStep int64) (int64, bool) {
	code = strings.TrimSpace(code)
	if len(code) != 6 {
		return 0, false
	}
	opts := totp.ValidateOpts{
		Period:    totpPeriod,
		Digits:    otp.DigitsSix,
		Skew:      1,
		Algorithm: otp.AlgorithmSHA1,
	}
	now := time.Now()
	for delta := int64(-1); delta <= 1; delta++ {
		at := now.Add(time.Duration(delta) * totpPeriod * time.Second)
		want, err := totp.GenerateCodeCustom(secret, at, opts)
		if err != nil {
			return 0, false // secret 不是合法 base32（库里坏了）= 不通过
		}
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) != 1 {
			continue
		}
		step := at.Unix() / totpPeriod
		if lastStep != 0 && step <= lastStep {
			return 0, false
		}
		return step, true
	}
	return 0, false
}

// consumeRecoveryCode 尝试消费一个恢复码：命中即置 used=1 并回 true。
// 归一化在服务端做（去空格/连字符、大写）——手抄时多打个空格不该判错。
//
// 只有**命中**才落 recovery.consume 审计：拿乱码试的失败轮次已经在
// login.fail 里计着，逐次记只会让表被爆破尝试灌满。actor 带 uid 与掩码邮箱
//（m5：恢复码消费是安全事件，审计行要能独立归因）。
func (s *Service) consumeRecoveryCode(uid int64, email, code string, meta SessionMeta) (bool, error) {
	norm := normalizeRecoveryCode(code)
	if norm == "" {
		return false, nil
	}
	hash := hashRecoveryCode(s.recoveryPepper, norm)
	res, err := s.pool.ExecContext(context.Background(),
		"UPDATE recovery_codes SET used = 1, used_at = ? WHERE user_id = ? AND code_hash = ? AND used = 0",
		time.Now().UnixMilli(), uid, hash)
	if err != nil {
		return false, fmt.Errorf("消费恢复码: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("读消费结果: %w", err)
	}
	if n == 1 {
		s.Audit(AuditEvent{
			Action: AuditRecoveryUse, OK: true, ActorUID: uidPtr(uid),
			ActorEmail: maskEmail(email), Meta: meta,
		})
	}
	return n == 1, nil
}

// TOTPEnabled 是登录编排要问的一句话（有无启用中的 2FA），与状态端点同源。
func (s *Service) TOTPEnabled(uid int64) (bool, error) {
	var n int
	if err := s.pool.QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM totp_factors WHERE user_id = ? AND enabled = 1", uid).Scan(&n); err != nil {
		return false, fmt.Errorf("查两步验证状态: %w", err)
	}
	return n > 0, nil
}

// generateRecoveryCodes 造 10 个 `XXXX-XXXX-XXXX-XXXX`。
func generateRecoveryCodes() ([]string, error) {
	out := make([]string, 0, recoveryCodeCount)
	for i := 0; i < recoveryCodeCount; i++ {
		raw := make([]byte, recoveryCodeSegments*recoveryCodeSegLen)
		for j := range raw {
			// 每字符单独取随机：免得把整段整数化再取模（边界偏置那套要多写多测）
			n, err := rand.Int(rand.Reader, big.NewInt(int64(len(crockfordAlphabet))))
			if err != nil {
				return nil, fmt.Errorf("生成恢复码: %w", err)
			}
			raw[j] = crockfordAlphabet[n.Int64()]
		}
		var b strings.Builder
		for k, ch := range raw {
			if k > 0 && k%recoveryCodeSegLen == 0 {
				b.WriteByte('-')
			}
			b.WriteByte(byte(ch))
		}
		out = append(out, b.String())
	}
	return out, nil
}

// normalizeRecoveryCode 去掉分隔符与空白、转大写；形态不对回空串。
func normalizeRecoveryCode(code string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(strings.TrimSpace(code)) {
		if r == '-' || r == ' ' {
			continue
		}
		b.WriteRune(r)
	}
	s := b.String()
	if len(s) != recoveryCodeSegments*recoveryCodeSegLen {
		return ""
	}
	for _, r := range s {
		if !strings.ContainsRune(crockfordAlphabet, r) {
			return ""
		}
	}
	return s
}

// hashRecoveryCode 是恢复码的落库形态：HMAC-SHA256(pepper, 归一化码)。
// 口令类查表哈希的口径（ASVS 6.5.2）——pepper 在进程环境里、行被拖走也凑不齐原码。
func hashRecoveryCode(pepper []byte, normalized string) string {
	mac := hmac.New(sha256.New, pepper)
	mac.Write([]byte(normalized))
	return hex.EncodeToString(mac.Sum(nil))
}

// deriveRecoveryPepper 从 JWT_SECRET 派生恢复码 HMAC 密钥（域分隔，见常量注释）。
func deriveRecoveryPepper(jwtSecret string) []byte {
	sum := sha256.Sum256([]byte(recoveryPepperLabel + jwtSecret))
	return sum[:]
}

// requireTOTPEncKey 读并规范化 TOTP 加密密钥：接受 32 字节裸值，或 supervisord
// 环境里惯用的 64 位 hex 表示（=32 字节，可读且无 ini 转义风险——生产即此形态，
// 曾因直接裸转致 aes 报 invalid key size 64、2FA 开启恒 500）。其余形态一律拒启
//（与 JWT_SECRET 同口径——坏密钥等于没加密，而 TOTP secret 只能存原值）。
// 丢失该密钥 = 已绑用户的 TOTP 全部作废（只剩恢复码），运维要单独备份它。
func requireTOTPEncKey() ([]byte, error) {
	key := os.Getenv("TOTP_ENC_KEY")
	if len(key) == 64 && isHexStr(key) {
		b, err := hex.DecodeString(key)
		if err != nil || len(b) != 32 {
			return nil, errors.New("TOTP_ENC_KEY 为 64 位但非合法 hex，检查 supervisord 的 environment")
		}
		return b, nil
	}
	if len(key) == 32 {
		return []byte(key), nil
	}
	return nil, errors.New("TOTP_ENC_KEY 必须是 32 字节裸值或 64 位 hex（=32 字节），检查 supervisord 的 environment")
}

func isHexStr(s string) bool {
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}
