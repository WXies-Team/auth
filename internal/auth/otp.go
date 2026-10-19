package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// 验证码口径（对齐行业惯例与客户端 60 秒倒计时，与热量日记服务逐条一致）：
//
//	6 位数字 · 5 分钟过期 · 同邮箱 60 秒冷却 + 每日 10 条 · 错 5 次作废 · 用后即焚
//
// 与旧实现（进程内存 map）的唯一差异是**落库**：重启不再丢码，冷却与限额跨重启
// 仍然有效；语义靠 otp_codes 表复刻，见 schema.sql 的 used 列说明。
const (
	otpTTL        = 5 * time.Minute
	otpCooldown   = time.Minute
	otpDailyLimit = 10
	otpMaxTries   = 5
	otpDigits     = 6
	// recipientDailyCap：单个收件邮箱跨用途的每日总闸。取 15——正常用户一天最多
	// 注册+找回+登录+改密+改邮各一两次，15 远高于真实用量、又把轰炸面压到可忽略。
	// 五条发码路各自 10 条/日、IP 层 5/分挡不住分布式来源，合计约 40~50 封/日/目标
	// 邮箱的轰炸面由它兜底。
	recipientDailyCap = 15
	// otpRetention：验证码行的保留时长。超过 7 天的行不参与任何闸门判定
	//（每日计数只看当天），纯粹是隐私残留，发码时顺手清。
	otpRetention = 7 * 24 * time.Hour
)

// 验证码用途；文案与校验目标都按它分流。
//
// register/reset/login 走**无登录态**的 /auth/send-code（白名单，非白名单直接 400，
// 客户端只认 CodePurpose 的三值）；change 只经 authed 的 /auth/send-change-code 签发、
// email_change 只经 authed 的 /auth/send-change-email-code 签发——收件人由 uid
// 查库决定、客户端传不了，码才不会变成轰炸任意邮箱的工具。五条路共用同一套
// 冷却、日限额与 5 分钟有效期；purpose 进查询维度，五者的码互不串用。
const (
	PurposeRegister    = "register"
	PurposeReset       = "reset"
	PurposeLogin       = "login"
	PurposeChange      = "change"
	PurposeChangeEmail = "email_change"
)

// otpStore 把验证码落在 otp_codes 表。单实例假设与限流层一致（进程内滑动窗口
// 限流同样是单实例口径），但验证码本身跨重启有效。
type otpStore struct {
	pool *sql.DB
}

// otpGate 是冷却与两级日限额的**纯判定**（可脱离数据库单测）。
//
// lastSent 为零值表示该邮箱+用途当前没有在途验证码（不存在冷却）；
// dayCount 是该 (email, purpose) 今天仍活跃的码数（用后即焚的语义：用掉一代就清零，
// 与旧内存实现「verify 删除条目后计数归零」一致）；recipientCount 是该收件邮箱
// 今天发出的**全部**码数（跨用途总闸，用掉的也计数）。
func otpGate(now time.Time, lastSent time.Time, dayCount, recipientCount int) error {
	if recipientCount >= recipientDailyCap {
		return &HTTPError{429, "今日验证码发送次数已达上限，请明天再试"}
	}
	// 冷却按「上一次发出」算：失败的发送会被 revoke 掉，不会白烧 60 秒
	if !lastSent.IsZero() && now.Sub(lastSent) < otpCooldown {
		return &HTTPError{429, "发送过于频繁，请60秒后再试"}
	}
	if dayCount >= otpDailyLimit {
		return &HTTPError{429, "今日验证码发送次数已达上限，请明天再试"}
	}
	return nil
}

// dayStart 是 now 所在**本地日**的零点毫秒时间戳。与旧内存实现按本地日
//（"2006-01-02"）计数同口径；服务器与 DSN 都按本地时区跑，跨天即重置。
func dayStart(now time.Time) int64 {
	y, m, d := now.Date()
	return time.Date(y, m, d, 0, 0, 0, 0, now.Location()).UnixMilli()
}

// issue 生成并落库一条验证码。冷却与日限额在这里挡，**发信之前**就挡。
func (s *otpStore) issue(purpose, email string) (string, error) {
	code, err := randomCode()
	if err != nil {
		return "", err
	}
	ctx := context.Background()
	now := time.Now()

	// 只看活跃行（used=0）：作废代不构成冷却，也不占日额度——用后即焚的语义
	// 就是「烧掉一代后可以立刻再要一个」
	var lastSent sql.NullInt64
	err = s.pool.QueryRowContext(ctx,
		"SELECT last_sent_at FROM otp_codes WHERE email = ? AND purpose = ? AND used = 0 ORDER BY id DESC LIMIT 1",
		email, purpose).Scan(&lastSent)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("查验证码冷却: %w", err)
	}
	var dayCount, recipientCount int
	if err := s.pool.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM otp_codes WHERE email = ? AND purpose = ? AND used = 0 AND created_at >= ?",
		email, purpose, dayStart(now)).Scan(&dayCount); err != nil {
		return "", fmt.Errorf("查验证码日限额: %w", err)
	}
	// 总闸数「今天发过的全部码」，含已用掉/已作废的——否则反复「发码→用码」
	// 就能把 15 条总闸刷没
	if err := s.pool.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM otp_codes WHERE email = ? AND created_at >= ?",
		email, dayStart(now)).Scan(&recipientCount); err != nil {
		return "", fmt.Errorf("查收件人日总闸: %w", err)
	}

	var sentAt time.Time
	if lastSent.Valid {
		sentAt = time.UnixMilli(lastSent.Int64)
	}
	if err := otpGate(now, sentAt, dayCount, recipientCount); err != nil {
		return "", err
	}

	if _, err := s.pool.ExecContext(ctx,
		`INSERT INTO otp_codes (email, purpose, code_hash, expires_at, attempts, used, created_at, last_sent_at)
		 VALUES (?, ?, ?, ?, 0, 0, ?, ?)`,
		email, purpose, sha256Hex(code), now.Add(otpTTL).UnixMilli(), now.UnixMilli(), now.UnixMilli()); err != nil {
		return "", fmt.Errorf("落库验证码: %w", err)
	}
	// 过期行清理：表常年只有几十~几百行，全表扫可忽略；失败不挡发码
	_, _ = s.pool.ExecContext(ctx, "DELETE FROM otp_codes WHERE created_at < ?", now.Add(-otpRetention).UnixMilli())
	return code, nil
}

// verify 校验并**用后即焚**（一次性的码不能再用第二次）。文案区分两种失败：
// 没发过/过期/试错太多 → 一句「过期」，输错 → 「验证码错误」，避免把
//「还有几次机会」这类可被利用的信息说出去。
func (s *otpStore) verify(purpose, email, code string) error {
	if len(code) == 0 {
		return badRequest("请先获取验证码")
	}
	ctx := context.Background()
	now := time.Now()

	var (
		id        int64
		stored    string
		expiresAt int64
		attempts  int
	)
	err := s.pool.QueryRowContext(ctx,
		"SELECT id, code_hash, expires_at, attempts FROM otp_codes WHERE email = ? AND purpose = ? AND used = 0 ORDER BY id DESC LIMIT 1",
		email, purpose).Scan(&id, &stored, &expiresAt, &attempts)
	if errors.Is(err, sql.ErrNoRows) {
		return badRequest("验证码已过期，请重新获取")
	}
	if err != nil {
		return fmt.Errorf("查验证码: %w", err)
	}
	// 作废整代（同 email+purpose 的全部活跃行）：库里同代可能有多行（发过多次），
	// 只废最新一行挡不住拿旧码来试——旧内存实现一个 key 只有一条，语义天然如此
	burnGeneration := func() {
		_, _ = s.pool.ExecContext(ctx,
			"UPDATE otp_codes SET used = 1 WHERE email = ? AND purpose = ? AND used = 0", email, purpose)
	}
	if now.UnixMilli() > expiresAt || attempts >= otpMaxTries {
		burnGeneration()
		return badRequest("验证码已过期，请重新获取")
	}
	if subtle.ConstantTimeCompare([]byte(stored), []byte(sha256Hex(code))) != 1 {
		_, _ = s.pool.ExecContext(ctx, "UPDATE otp_codes SET attempts = attempts + 1 WHERE id = ?", id)
		if attempts+1 >= otpMaxTries {
			burnGeneration()
		}
		return badRequest("验证码错误，请重新输入")
	}
	burnGeneration()
	return nil
}

// revoke 作废刚生成的码——只在「码已生成但信没发出去」时用，否则用户要白等
// 60 秒冷却。清理失败只记在返回值之外无从表达：撤销是尽力而为，最坏是多等 60 秒。
func (s *otpStore) revoke(purpose, email string) {
	_, _ = s.pool.ExecContext(context.Background(),
		"UPDATE otp_codes SET used = 1 WHERE email = ? AND purpose = ? AND used = 0", email, purpose)
}

// randomCode 用 crypto/rand 取 [0,1000000) 再左补零成 6 位（不能用 math/rand：码可被
// 预测就等于没有验证码）。
func randomCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return "", fmt.Errorf("生成验证码: %w", err)
	}
	return fmt.Sprintf("%0*d", otpDigits, n.Int64()), nil
}
