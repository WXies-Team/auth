package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// W3 注销七天宽限（B1 合并批次）：
//
//	POST /auth/delete 校验注册邮箱 + purpose=delete 验证码 → **不删任何东西**：
//	置 users.pending_delete_at、token_version+1（杀全部会话含当前）、发注销确认信
//	（含撤销链接）→ 审计 account.delete_requested；
//	撤销三路：撤销页 POST、登录即撤销（loginGate）、到期不清（无法撤销）；
//	到期执行：进程内清扫 goroutine（每小时 + 启动即跑）逐个走**既有注销管线**。
const (
	// deleteGrace 是注销宽限期：pending_delete_at 起 7 天后执行（登录/撤销都按它判到期）。
	deleteGrace = 7 * 24 * time.Hour
	// pendingDeleteSweepInterval 是到期清扫的周期。单实例假设与进程内限流一致；
	// 周期到点前到期的行最迟晚一个周期执行（登录侧的同步兜底见 loginGate）。
	pendingDeleteSweepInterval = time.Hour
	// deleteCancelPurpose 是撤销链接 JWT 的专用 purpose claim——与登录 JWT 的
	// aud/sid 体系互不相通：撤销 token 冒充不了登录凭据（缺 aud/sid），
	// 登录 JWT 也冒充不了撤销凭据（缺 purpose）。
	deleteCancelPurpose = "delete_cancel"
	// deleteCancelURL 是撤销链接的落点（模板里的常量串，token 由服务端拼接）。
	deleteCancelURL = siteBase + "/web/delete-cancel?token="
)

// RequestAccountDeletion 是 POST /auth/delete 的业务实现（契约 2 新 body：{email, code}）。
//
// 校验顺序：邮箱格式 → **email == 本人注册邮箱**（改名/换号场景下不让验证码被
// 用到别的收件箱上）→ purpose=delete 验证码（走既有 OTP 闸：烧码 / 5 错烧 / 参数化）。
// 全过才置 pending——一步删除都不执行，数据还在、7 天内随时可撤。
//
// token_version+1 + 会话吊销在**同一事务**里（与 Logout 同款两层同进同退）：
// 注销申请一落库，包括当前设备在内的全部会话当场下线——申请注销的设备也不例外，
// 回执 {ok:true} 照发（响应不依赖会话还活着）。
func (s *Service) RequestAccountDeletion(c Caller, rawEmail, code string) (err error) {
	defer func() {
		s.Audit(AuditEvent{
			Action: AuditDeleteRequested, OK: err == nil, ActorUID: uidPtr(c.UID),
			ActorEmail: maskEmail(c.Email), Meta: c.Meta,
		})
	}()
	registered, _, err := s.loadUserAuth(c.UID)
	if err != nil {
		return err
	}
	email := normalizeEmail(rawEmail)
	if err := validateEmail(email); err != nil {
		return err
	}
	if email != registered {
		return badRequest("注销邮箱与当前账号不一致，请使用注册邮箱")
	}
	// 码按注册邮箱验（与上面的比对同源，这里两者相等）；注销确认码走匿名
	// SendCode（uid=0），验按 0 收口——归属已由上面的「email == 注册邮箱」挡
	if err := s.otps.verify(0, PurposeDelete, registered, code); err != nil {
		return err
	}
	if err := s.markPendingDelete(c.UID); err != nil {
		return err
	}
	// 确认信尽力而为（best-effort）：pending 已落库，信没发出去用户仍可登录即撤销；
	// 把已完成的申请回滚成 500 只会让用户对着烧掉的验证码白等 60 秒冷却。
	token, terr := s.createDeleteCancelToken(c.UID)
	if terr != nil {
		slog.Error("生成注销撤销链接失败（用户仍可登录撤销）", "uid", c.UID, "err", terr)
	} else {
		s.sendDeleteRequestEmail(registered, token, time.Now().Add(deleteGrace))
	}
	return nil
}

// markPendingDelete 置 pending + token_version+1 + 吊销全部会话（含当前），
// 一个事务提交（半吊子状态 = token 死了行还活着 / pending 没落却已登出）。
func (s *Service) markPendingDelete(uid int64) error {
	ctx := context.Background()
	tx, err := s.pool.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("开事务: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx,
		"UPDATE users SET pending_delete_at = ?, token_version = token_version + 1 WHERE id = ?",
		time.Now().UnixMilli(), uid); err != nil {
		return fmt.Errorf("登记注销申请: %w", err)
	}
	if err := revokeUserSessions(ctx, tx, uid, 0, nil); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("提交注销申请: %w", err)
	}
	return nil
}

// createDeleteCancelToken 签撤销链接的 JWT：HS256、iss=auth、purpose=delete_cancel、
// exp=+7 天（与宽限期同长——链接活过宽限也没意义）。
func (s *Service) createDeleteCancelToken(uid int64) (string, error) {
	claims := jwt.MapClaims{
		"purpose": deleteCancelPurpose,
		"iss":     issuer,
		"uid":     uid,
		"exp":     time.Now().Add(deleteGrace).Unix(),
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(s.secret))
	if err != nil {
		return "", fmt.Errorf("签发注销撤销链接: %w", err)
	}
	return signed, nil
}

// parseDeleteCancelToken 验签撤销链接并回 uid。签名 / 过期 / purpose 不对回同一句
// 400——不给「哪一步错了」的探针面，页面侧渲染同一张友好错误页。
func (s *Service) parseDeleteCancelToken(token string) (int64, error) {
	claims := jwt.MapClaims{}
	parsed, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("意外的签名算法 %v", t.Header["alg"])
		}
		return []byte(s.secret), nil
	},
		jwt.WithValidMethods([]string{"HS256"}),
		jwt.WithIssuer(issuer),
		jwt.WithExpirationRequired(),
		jwt.WithJSONNumber(),
	)
	if err != nil || !parsed.Valid {
		return 0, badRequest("撤销链接无效或已过期，请重新登录后再试")
	}
	if purpose, _ := claims["purpose"].(string); purpose != deleteCancelPurpose {
		return 0, badRequest("撤销链接无效或已过期，请重新登录后再试")
	}
	uid, ok := claimInt64(claims, "uid")
	if !ok || uid <= 0 {
		return 0, badRequest("撤销链接无效或已过期，请重新登录后再试")
	}
	return uid, nil
}

// pendingDeleteState 读一笔待执行注销的状态：(pending_at, email)。
// pending_at 为 0 = 没有申请；err 仅在库错误时非 nil（账号不存在按「无申请」处理——
// 撤销一个已注销的账号没有可报的错，页面回友好错误页即可）。
func (s *Service) pendingDeleteState(uid int64) (int64, string, error) {
	var (
		pending int64
		email   string
	)
	err := s.pool.QueryRowContext(context.Background(),
		"SELECT pending_delete_at, email FROM users WHERE id = ?", uid).Scan(&pending, &email)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, "", nil
	}
	if err != nil {
		return 0, "", fmt.Errorf("查注销申请: %w", err)
	}
	return pending, email, nil
}

// CheckDeleteCancel 是撤销**确认页**（GET /web/delete-cancel）的校验：
// 验签 → 有 pending 且未到期，任一不满足回 400 让页面渲染友好错误页。
// 与 CancelDelete 同一套判定（页面与提交不会各说各话），但不写任何数据。
func (s *Service) CheckDeleteCancel(token string) error {
	_, _, err := s.checkCancelEligible(token)
	return err
}

// checkCancelEligible 验签 + 判宽限，回 (uid, registered_email)；不满足回 400。
func (s *Service) checkCancelEligible(token string) (int64, string, error) {
	uid, err := s.parseDeleteCancelToken(token)
	if err != nil {
		return 0, "", err
	}
	pending, email, err := s.pendingDeleteState(uid)
	if err != nil {
		return 0, "", err
	}
	switch {
	case pending == 0:
		return 0, "", badRequest("当前没有待执行的注销申请")
	case time.Now().UnixMilli() > pending+deleteGrace.Milliseconds():
		return 0, "", badRequest("注销申请已过期，无法撤销")
	}
	return uid, email, nil
}

// CancelDelete 是撤销提交（POST /web/delete-cancel）：验签 + 有 pending 且未到期 →
// 清 pending、发「注销已撤销」信、审计 account.delete_cancelled。**不放在 withUID
// 后面**（已登出用户也要能撤），token 即凭证、不可猜。
func (s *Service) CancelDelete(token string) (err error) {
	uid, email, err := s.checkCancelEligible(token)
	if err != nil {
		return err
	}
	if err := s.cancelPendingDelete(uid, email, SessionMeta{}); err != nil {
		return err
	}
	return nil
}

// cancelPendingDelete 清 pending + 发撤销信 + 审计（登录即撤销与撤销页共用一处，
// 两路的审计/邮件不会漂）。WHERE 带 pending>0 守卫：并发双清只算一次（幂等）。
func (s *Service) cancelPendingDelete(uid int64, email string, meta SessionMeta) error {
	res, err := s.pool.ExecContext(context.Background(),
		"UPDATE users SET pending_delete_at = 0 WHERE id = ? AND pending_delete_at > 0", uid)
	if err != nil {
		return fmt.Errorf("撤销注销申请: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		// 并发撤销（双路登录/登录+撤销页同瞬）已被另一路赢下：列只清一次，
		// 审计与「已撤销」信同样只属于赢家，否则副作用会重复
		return nil
	}
	s.Audit(AuditEvent{
		Action: AuditDeleteCancelled, OK: true, ActorUID: uidPtr(uid),
		ActorEmail: maskEmail(email), Meta: meta,
	})
	s.sendDeleteCancelledEmail(email)
	return nil
}

// finishDelete 执行到期注销的完整收尾：既有注销管线（purgeAccount）+ 「注销已完成」
// 信 + 审计沿用 AuditAccountDelete。清扫 goroutine 与登录侧的到期兜底共用一处，
// 两条执行路径的信与审计口径一致。
func (s *Service) finishDelete(uid int64, email string, meta SessionMeta) error {
	if err := s.purgeAccount(uid, email); err != nil {
		return err
	}
	s.Audit(AuditEvent{
		Action: AuditAccountDelete, OK: true, ActorUID: uidPtr(uid),
		ActorEmail: maskEmail(email), Meta: meta,
	})
	s.sendDeleteDoneEmail(email)
	return nil
}

// purgeAccount 是注销的**钩子 + 清库主体**（自原 DeleteAccount 抽出，W3 要求可复用）：
// 先让两个日记服务清各自的业务数据（钩子全成功才动本服务的行，见 [Hooks]），
// 再删本服务持有的数据。语义与抽出前逐字一致——钩子幂等可重入，重试即救济。
//
// 按 uid 存的表全部同批清：除既有清单外补 **user_bans / project_access**（W2/W5 新表）——
// 留着它们，uid 被复用时前任的封禁与项目名单会落到新人头上。
func (s *Service) purgeAccount(userID int64, email string) error {
	if s.hooks != nil {
		if err := s.hooks.BeforeDelete(userID, email); err != nil {
			return err
		}
	}

	tx, err := s.pool.BeginTx(context.Background(), nil)
	if err != nil {
		return fmt.Errorf("开事务: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// 验证码行按邮箱清：账号没了还留着验证码记录，既是隐私残留，
	// 也拦不住同邮箱重新注册后被旧计数误伤
	if _, err := tx.ExecContext(context.Background(),
		"DELETE FROM otp_codes WHERE email = ?", email); err != nil {
		return fmt.Errorf("清空验证码记录: %w", err)
	}
	// 会话行按 uid 清：账号都删了，设备列表的行只剩隐私残留，没人再踢得掉它们
	if _, err := tx.ExecContext(context.Background(),
		"DELETE FROM sessions WHERE user_id = ?", userID); err != nil {
		return fmt.Errorf("清空登录会话: %w", err)
	}
	// Web 管理台的四张按 uid 存的表同批清（passkey / TOTP / 恢复码 / 仪式中间态），
	// 外加两步登录的中间态——它们是 5 分钟的在途凭证，账号没了还挂着就是一张废票。
	// user_profile 也在列：档案归身份提供方，账号删了还留着昵称/头像就是隐私残留
	//（日记侧的对应资料行由注销钩子清，本服务这行只能在这里删）。
	for _, table := range []string{"passkeys", "totp_factors", "recovery_codes", "webauthn_challenges", "login_states", "user_profile"} {
		if _, err := tx.ExecContext(context.Background(),
			"DELETE FROM "+table+" WHERE user_id = ?", userID); err != nil {
			return fmt.Errorf("清空 %s: %w", table, err)
		}
	}
	// 同列名 uid 的三张表单独清：授权 / 项目名单 / 封禁指向已注销账号既无意义
	// 也是残留（uid 复用时会把前任的权限与处罚送给人）。
	for _, table := range []string{"admin_scopes", "project_access", "user_bans"} {
		if _, err := tx.ExecContext(context.Background(),
			"DELETE FROM "+table+" WHERE uid = ?", userID); err != nil {
			return fmt.Errorf("清空 %s: %w", table, err)
		}
	}
	// m14：个人 AI 用量行同批清（scope='user' AND subject=uid）——隐私残留 +
	// 防日后 uid 复用时把前任的用量算到新人头上。global 行与迁移映射表行**保留**：
	// 它们不指向任何个人（global 是全站日计数，映射表是合并对账的守卫键）。
	// subject 存的是 7 位随机 uid 的十进制串（ai_usage 口径，见 internal/ai 包注释）。
	if _, err := tx.ExecContext(context.Background(),
		"DELETE FROM ai_usage WHERE scope = 'user' AND subject = ?", fmt.Sprintf("%d", userID)); err != nil {
		return fmt.Errorf("清空 AI 用量: %w", err)
	}
	// 审计行**留着但匿名化**：删掉它等于给「注销自己账号就能抹掉操作痕迹」开后门，
	// 事件本身要继续对得起 ASVS V16；邮箱清空后行里只剩 uid，账号已不存在。
	if _, err := tx.ExecContext(context.Background(),
		"UPDATE audit_logs SET actor_email = '' WHERE actor_uid = ?", userID); err != nil {
		return fmt.Errorf("匿名化审计: %w", err)
	}
	if _, err := tx.ExecContext(context.Background(),
		"DELETE FROM users WHERE id = ?", userID); err != nil {
		return fmt.Errorf("删除账号: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("提交注销: %w", err)
	}
	slog.Info("账号已注销", "uid", userID, "email", maskEmail(email))
	return nil
}

// RunPendingDeleteSweeper 是到期注销的进程内清扫（W3）：启动立即跑一遍，
// 之后每 deleteSweepInterval 一轮，直到 ctx 取消（main 的优雅关闭信号）。
// 单实例假设——与进程内限流同一部署形态，不引入跨实例协调。
func (s *Service) RunPendingDeleteSweeper(ctx context.Context) {
	s.sweepPendingDeletes()
	ticker := time.NewTicker(pendingDeleteSweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.sweepPendingDeletes()
		}
	}
}

// sweepPendingDeletes 执行一轮清扫：pending 非 0 且已满 7 天的行逐个走 finishDelete。
// **先把行读完再逐个执行**（不在持有 rows 时打钩子/事务，8 条池连接经不起长占）；
// 多行失败互不影响，slog 带 uid。
func (s *Service) sweepPendingDeletes() {
	ctx := context.Background()
	cutoff := time.Now().Add(-deleteGrace).UnixMilli()
	rows, err := s.pool.QueryContext(ctx,
		"SELECT id, email FROM users WHERE pending_delete_at > 0 AND pending_delete_at <= ?", cutoff)
	if err != nil {
		slog.Error("扫描到期注销申请失败", "err", err)
		return
	}
	type dueRow struct {
		uid   int64
		email string
	}
	var due []dueRow
	for rows.Next() {
		var d dueRow
		if err := rows.Scan(&d.uid, &d.email); err != nil {
			slog.Error("读到期注销行失败", "err", err)
			_ = rows.Close()
			return
		}
		due = append(due, d)
	}
	if err := rows.Err(); err != nil {
		slog.Error("遍历到期注销行失败", "err", err)
	}
	_ = rows.Close()
	for _, d := range due {
		if err := s.finishDelete(d.uid, d.email, SessionMeta{}); err != nil {
			slog.Error("到期注销执行失败（其余行继续）", "uid", d.uid, "err", err)
		}
	}
}

// ---- 三封注销信（发送器缺席只记不发：route 测试不接 mailer）----

func (s *Service) sendDeleteRequestEmail(email, cancelToken string, dueAt time.Time) {
	if s.mailer == nil {
		return
	}
	b := brandFor("")
	subject, htmlBody, text := deleteRequestEmail(b, deleteCancelURL+cancelToken, dueAt)
	if err := s.mailer.Send(context.Background(), b.name, email, subject, htmlBody, text); err != nil {
		mailLog(err, PurposeDelete, email)
	}
}

func (s *Service) sendDeleteCancelledEmail(email string) {
	if s.mailer == nil {
		return
	}
	b := brandFor("")
	subject, htmlBody, text := deleteCancelledEmail(b)
	if err := s.mailer.Send(context.Background(), b.name, email, subject, htmlBody, text); err != nil {
		mailLog(err, "delete_cancel", email)
	}
}

func (s *Service) sendDeleteDoneEmail(email string) {
	if s.mailer == nil {
		return
	}
	b := brandFor("")
	subject, htmlBody, text := deleteDoneEmail(b)
	if err := s.mailer.Send(context.Background(), b.name, email, subject, htmlBody, text); err != nil {
		mailLog(err, "delete_done", email)
	}
}
