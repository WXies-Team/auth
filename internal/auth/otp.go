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
	// 注册+找回+登录+两步验证+改密+改邮各一两次，15 远高于真实用量、又把轰炸面压到
	// 可忽略。六条发码路各自 10 条/日、IP 层 5/分挡不住分布式来源，合计约 50~60 封
	// /日/目标邮箱的轰炸面由它兜底。
	recipientDailyCap = 15
	// otpRetention：验证码行的保留时长。超过 7 天的行不参与任何闸门判定
	//（每日计数只看当天），纯粹是隐私残留，发码时顺手清。
	otpRetention = 7 * 24 * time.Hour
)

// 验证码用途；文案与校验目标都按它分流。
//
// register/reset/login/login_2fa/delete 走**无登录态**的 /auth/send-code（白名单，
// 非白名单直接 400；日记客户端与 web 登录第二步都认 CodePurpose 的常量集，
// login_2fa 是两步验证第二步的邮箱码（web 与日记 App 对称可用），delete 是注销申请
// 的确认码（W3：老客户端不传照常工作））；change 只经 authed 的 /auth/send-change-code 签发、
// email_change 只经 authed 的 /auth/send-change-email-code 签发——收件人由 uid
// 查库决定、客户端传不了，码才不会变成轰炸任意邮箱的工具。七条路共用同一套
// 冷却、日限额与 5 分钟有效期；purpose 进查询维度，七者的码互不串用。
//
// login_2fa（登录两步验证）与 login（邮箱验证码登录）刻意分开：两种码的语义、
// 校验时机与错码文案都不同（前者是 2FA 第二因子，验它要绑 login state 并共享
// 5 次烧毁计数），混在一个 purpose 里既串计数也串文案。
const (
	PurposeRegister    = "register"
	PurposeReset       = "reset"
	PurposeLogin       = "login"
	PurposeLogin2FA    = "login_2fa"
	PurposeChange      = "change"
	PurposeChangeEmail = "email_change"
	// PurposeDelete 是注销申请的确认码（W3 七天宽限期的入口闸）：6 位/5 分钟/
	// 既有冷却与日限，不加任何特殊 TTL——宽限期本身记在 users.pending_delete_at 上。
	PurposeDelete = "delete"
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
//
// uid 是发码时的账号归属：0 = 匿名发码（register/reset/login/login_2fa/delete，
// /auth/send-code 无登录态），非 0 = 登录态发码（change / email_change）。它进
// otp_codes.uid 列：验码按它做归属校验（只看自己那代的码），管理员换邮也按它
// 烧在途的自助改邮码（见 AdminChangeEmail 的防覆盖竞态）。
//
// 三条闸的读与 INSERT 之间包一把**按邮箱的 MySQL 命名锁**（GET_LOCK）：同邮箱的
// 并发发码在此串行化，冷却/日限额不会被同批并发穿透。
// 没用事务 + SELECT … FOR UPDATE 做这件事：该邮箱还没发过码时（发码的主场景）
// 锁定读拿的是间隙锁，间隙锁彼此兼容、两边的 INSERT 又互相等待对方的间隙锁，
// 首发并发就是一把死锁；GET_LOCK 是会话级互斥，没有这个坑。
// 锁只护 issue 自身的读-判-写窗口；verify/revoke 的烧代只会把闸门变松（作废代
// 本就立刻释放冷却），不需要同一把锁。
func (s *otpStore) issue(uid int64, purpose, email string) (string, error) {
	code, err := randomCode()
	if err != nil {
		return "", err
	}
	ctx := context.Background()
	now := time.Now()

	// 持锁段走独立方法：RELEASE 的 defer 在它返回时就跑，锁先于外层清理释放——
	// 清理要走 pool（可能需要池里空出的新连接），占着锁等池就是拿「锁等连接、
	// 连接等锁」把自己挂死（并发测试实测过：8 条池连接全被占满时清理语句
	// 永远等不到连接，持锁者释放不了锁）。
	code, err = s.issueLocked(uid, purpose, email, code, now, ctx)
	if err != nil {
		return "", err
	}
	// 过期行清理：表常年只有几十~几百行，全表扫可忽略；失败不挡发码
	_, _ = s.pool.ExecContext(ctx, "DELETE FROM otp_codes WHERE created_at < ?", now.Add(-otpRetention).UnixMilli())
	// 审计行的 90 天保留期同样挂在发码路径上清（规格 A1.4：不引入后台 goroutine，
	// 借高频且已有的清理点顺手做）
	cleanAuditLogs(s.pool)
	// AI 用量行的 90 天保留期同批清（n4）：看板只读近 30 天，过期行只剩对账价值
	cleanAIUsage(s.pool)
	// 会话僵尸行同批清（n6）：撤销/绝对过期满 30 天才删，回看窗内留着
	cleanDeadSessions(s.pool)
	return code, nil
}

// issueLocked 是 issue 的持锁段：全程只用一条钉住的连接（GET_LOCK 挂在会话上，
// 中途换连接锁就丢了），闸门判定与 INSERT 都在这条连接上；返回前锁必已释放。
func (s *otpStore) issueLocked(uid int64, purpose, email, code string, now time.Time, ctx context.Context) (string, error) {
	conn, err := s.pool.Conn(ctx)
	if err != nil {
		return "", fmt.Errorf("取数据库连接: %w", err)
	}
	// 先 Close 的 defer 后执行：锁先释放、连接后归还，顺序不能反
	defer func() { _ = conn.Close() }()
	// 锁名是服务级全局的且限 64 字符：用邮箱 sha256 的前 32 位做定长名，裸邮箱
	// 超长会被 MySQL 截断出撞锁。取不到锁（对端 5 秒不放）直接报错让上层回
	//「稍后重试」的通用文案——拿不到锁多半是库出了问题，硬发只会把闸门穿掉。
	// 锁挂在会话连接上，RELEASE 必须落在同一连接（所以整个持锁段都用 conn）。
	lockName := "auth_otp_" + sha256Hex(email)[:32]
	var got sql.NullInt64
	if err := conn.QueryRowContext(ctx, "SELECT GET_LOCK(?, 5)", lockName).Scan(&got); err != nil {
		return "", fmt.Errorf("取发码锁: %w", err)
	}
	if !got.Valid || got.Int64 != 1 {
		return "", fmt.Errorf("取发码锁超时: %s", lockName)
	}
	defer func() { _, _ = conn.ExecContext(ctx, "SELECT RELEASE_LOCK(?)", lockName) }()

	// 只看活跃行（used=0）：作废代不构成冷却，也不占日额度——用后即焚的语义
	// 就是「烧掉一代后可以立刻再要一个」
	var lastSent sql.NullInt64
	err = conn.QueryRowContext(ctx,
		"SELECT last_sent_at FROM otp_codes WHERE email = ? AND purpose = ? AND used = 0 ORDER BY id DESC LIMIT 1",
		email, purpose).Scan(&lastSent)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("查验证码冷却: %w", err)
	}
	var dayCount, recipientCount int
	if err := conn.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM otp_codes WHERE email = ? AND purpose = ? AND used = 0 AND created_at >= ?",
		email, purpose, dayStart(now)).Scan(&dayCount); err != nil {
		return "", fmt.Errorf("查验证码日限额: %w", err)
	}
	// 总闸数「今天发过的全部码」，含已用掉/已作废的——否则反复「发码→用码」
	// 就能把 15 条总闸刷没
	if err := conn.QueryRowContext(ctx,
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

	if _, err := conn.ExecContext(ctx,
		`INSERT INTO otp_codes (email, purpose, code_hash, expires_at, attempts, used, created_at, last_sent_at, uid)
		 VALUES (?, ?, ?, ?, 0, 0, ?, ?, ?)`,
		email, purpose, sha256Hex(code), now.Add(otpTTL).UnixMilli(), now.UnixMilli(), now.UnixMilli(), uid); err != nil {
		return "", fmt.Errorf("落库验证码: %w", err)
	}
	return code, nil
}

// verify 校验并**用后即焚**（一次性的码不能再用第二次）。文案区分两种失败：
// 没发过/过期/试错太多 → 一句「过期」，输错 → 「验证码错误」，避免把
//「还有几次机会」这类可被利用的信息说出去。
//
// uid 是**发码时写入的归属**（见 issue）：查询与烧代都按 uid 收口——发码时是 0
// 就验 0（匿名五用途），是真实 uid 就验同一 uid（change / email_change）。这是
// 归属校验：两个账号可以同时申请改成同一个空闲地址，A 不能拿 B 那代的码；码只
// 对发出它的那一代生效，查无行与错 uid 同报「过期」，不泄露归属信息。
//
// 整段包进事务并给命中的码行加锁（FOR UPDATE）：试错次数的读-判-写之间不再有
// 并发窗口——同码的并发提交在这里串行化，「错 5 次作废」不会被同批并发穿透，
// 用后即焚的烧代对并发提交也只放行一次。
func (s *otpStore) verify(uid int64, purpose, email, code string) error {
	if len(code) == 0 {
		return badRequest("请先获取验证码")
	}
	ctx := context.Background()
	now := time.Now()

	tx, err := s.pool.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("开事务: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var (
		id        int64
		stored    string
		expiresAt int64
		attempts  int
	)
	err = tx.QueryRowContext(ctx,
		"SELECT id, code_hash, expires_at, attempts FROM otp_codes WHERE email = ? AND purpose = ? AND uid = ? AND used = 0 ORDER BY id DESC LIMIT 1 FOR UPDATE",
		email, purpose, uid).Scan(&id, &stored, &expiresAt, &attempts)
	if errors.Is(err, sql.ErrNoRows) {
		return badRequest("验证码已过期，请重新获取")
	}
	if err != nil {
		return fmt.Errorf("查验证码: %w", err)
	}
	// 作废整代（同 email+purpose+uid 的全部活跃行）：库里同代可能有多行（发过多次），
	// 只废最新一行挡不住拿旧码来试——旧内存实现一个 key 只有一条，语义天然如此
	burnGeneration := func() {
		_, _ = tx.ExecContext(ctx,
			"UPDATE otp_codes SET used = 1 WHERE email = ? AND purpose = ? AND uid = ? AND used = 0", email, purpose, uid)
	}
	if now.UnixMilli() > expiresAt || attempts >= otpMaxTries {
		burnGeneration()
		_ = tx.Commit()
		return badRequest("验证码已过期，请重新获取")
	}
	if subtle.ConstantTimeCompare([]byte(stored), []byte(sha256Hex(code))) != 1 {
		_, _ = tx.ExecContext(ctx, "UPDATE otp_codes SET attempts = attempts + 1 WHERE id = ?", id)
		if attempts+1 >= otpMaxTries {
			burnGeneration()
		}
		_ = tx.Commit()
		return badRequest("验证码错误，请重新输入")
	}
	burnGeneration()
	return tx.Commit()
}

// revoke 作废刚生成的码——只在「码已生成但信没发出去」时用，否则用户要白等
// 60 秒冷却。uid 同 issue：只废发出时归属该账号的那代，不误伤同地址别人的在途码。
// 清理失败只记在返回值之外无从表达：撤销是尽力而为，最坏是多等 60 秒。
func (s *otpStore) revoke(uid int64, purpose, email string) {
	_, _ = s.pool.ExecContext(context.Background(),
		"UPDATE otp_codes SET used = 1 WHERE email = ? AND purpose = ? AND uid = ? AND used = 0", email, purpose, uid)
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
