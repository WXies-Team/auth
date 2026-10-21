package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
)

// B9 管理端邀请建号：管理员发一封带链接的邀请信，收件人点开设置密码即完成建号
//（链接只有目标邮箱的持有者收得到，邮箱因此视为已验证——不叠邮箱验证码）。
//
// 口径（调研定案，邀请链接流为主）：
//   - token 32 字节 CSPRNG，库里**只存 sha256**（明文只在创建/重发那一刻进邮件），
//     24 小时过期；重发换新 token，旧 token 即刻失效；
//   - 状态不存列，由 accepted_at / revoked_at / expires_at 三个时间戳派生四态
//     （inviteState）；
//   - 接受 = 建号 + 单次消费（条件 UPDATE 防并发双开）+ 自动登录（web cookie 会话，
//     与 completeLogin 的 web 支同款）；**不**自动开 2FA，login_notify 走列默认值
//     （DEFAULT 1，见 db.extraColumns）；
//   - 邀请带 app 且该项目已开登录白名单时，接受即自动加入 project_access（正是
//     放行名单要的行）；项目开放则不做授权动作。
//
// 权限（与其它管理动作同一套闸）：super 可不带 app 或带任意白名单 app；app-admin
// 必带其 scopes 内的 app（空 app / 越权 → 403，未知 slug → 400，adminTargetScope）。
const (
	inviteTTL        = 24 * time.Hour
	inviteTokenBytes = 32
)

// AdminInvite 是邀请列表的一行（GET /admin/users/invites）。
// ID 是雪花 id 的**十进制串**（63 位过不了 JS 的 53 位精度，与会话 id 同口径）。
// State 是 inviteState 的派生值，不落库。
type AdminInvite struct {
	ID        string `json:"id"`
	Email     string `json:"email"`
	App       string `json:"app"`
	CreatedAt int64  `json:"createdAt"`
	ExpiresAt int64  `json:"expiresAt"`
	State     string `json:"state"` // pending | accepted | revoked | expired
}

// inviteState 从三个时间戳派生四态（纯函数：接受 > 撤销 > 过期 > 待接受）。
// 判定序与调研定案逐字一致——accepted/revoked 是不可逆事实，先于时间判定。
func inviteState(acceptedAt, revokedAt, expiresAt, now int64) string {
	switch {
	case acceptedAt > 0:
		return "accepted"
	case revokedAt > 0:
		return "revoked"
	case now > expiresAt:
		return "expired"
	default:
		return "pending"
	}
}

// inviteRow 是 user_invites 一行的读出结果（内部流转，不进回执）。
type inviteRow struct {
	id         int64
	email      string
	app        string
	invitedBy  int64
	acceptedAt int64
	revokedAt  int64
	expiresAt  int64
}

// ---- 管理端三动作 ----

// AdminCreateInvite 创建邀请并把链接信发给目标邮箱（POST /admin/users/invite）。
// 回执 expiresAt 供前端 toast 说清「什么时候之前有效」。
//
// 两道查重：① 邮箱已有活跃账号 → 400 该邮箱已注册；② 同邮箱有未过期待接受邀请
// → 400 该邮箱已有待接受的邀请，请先撤销或重发（Clerk 同邮箱重复邀请失败口径）。
// 审计 user.invite（detail: email 掩码 + app，token 绝不进审计）。
func (s *Service) AdminCreateInvite(actor Caller, scope AdminScope, rawEmail, app string) (expiresAt int64, err error) {
	defer func() {
		s.Audit(AuditEvent{
			Action: AuditUserInvite, OK: err == nil, ActorUID: uidPtr(actor.UID),
			ActorEmail: maskEmail(actor.Email), Meta: actor.Meta,
			Detail: map[string]string{"email": maskEmail(normalizeEmail(rawEmail)), "app": app},
		})
	}()
	// 项目边界：空 app = 账号级邀请，仅平台管理员（adminTargetScope 对非 super 的
	// 空串恒 403）；给了就必须在白名单（400）且在操作者 scopes 内（403）。
	if app != "" && !allowedApps[app] {
		return 0, badRequest("未知项目，请重新选择后重试")
	}
	if err = adminTargetScope(scope, app); err != nil {
		return 0, err
	}
	email := normalizeEmail(rawEmail)
	if verr := validateEmail(email); verr != nil {
		return 0, verr
	}
	exists, xerr := s.userExists(email)
	if xerr != nil {
		return 0, xerr
	}
	if exists {
		return 0, badRequest("该邮箱已注册")
	}
	var dup int
	if qerr := s.pool.QueryRowContext(context.Background(),
		"SELECT EXISTS(SELECT 1 FROM user_invites WHERE email = ? AND accepted_at = 0 AND revoked_at = 0 AND expires_at > ?)",
		email, time.Now().UnixMilli()).Scan(&dup); qerr != nil {
		return 0, fmt.Errorf("查邀请: %w", qerr)
	}
	if dup == 1 {
		return 0, badRequest("该邮箱已有待接受的邀请，请先撤销或重发")
	}
	token, terr := randomToken(inviteTokenBytes)
	if terr != nil {
		return 0, terr
	}
	now := time.Now().UnixMilli()
	expiresAt = now + inviteTTL.Milliseconds()
	if _, err = s.pool.ExecContext(context.Background(),
		"INSERT INTO user_invites (id, email, app, invited_by, token_hash, created_at, expires_at) VALUES (?,?,?,?,?,?,?)",
		s.ids.Generate().Int64(), email, app, actor.UID, sha256Hex(token), now, expiresAt); err != nil {
		return 0, fmt.Errorf("创建邀请: %w", err)
	}
	// 邀请信尽力而为：邀请行已落库，管理员可在列表里重发——一封信投递失败
	// 不该把已建的邀请翻成 500（与密码重置通知同口径）
	s.sendInviteEmail(app, email, token, time.UnixMilli(expiresAt))
	return expiresAt, nil
}

// AdminListInvites 列邀请（su 全量、app-admin 仅其 app；零 scope admin 回空列表）。
// query 是邮箱片段（LIKE），与用户列表的邮箱搜索同口径。
func (s *Service) AdminListInvites(scope AdminScope, query string) ([]AdminInvite, error) {
	cond := " WHERE 1=1"
	var args []any
	if !scope.Super {
		if len(scope.Apps) == 0 {
			return []AdminInvite{}, nil
		}
		cond += " AND app IN (" + placeholders(len(scope.Apps)) + ")"
		for _, a := range scope.Apps {
			args = append(args, a)
		}
	}
	if q := strings.TrimSpace(query); q != "" {
		cond += " AND email LIKE ?"
		args = append(args, "%"+q+"%")
	}
	// 待接受排最前（accepted_at <> 0 是 MySQL 的布尔排序：0 在前）——管理台先看
	// 还能动手的行，接受/撤销/过期的沉底。
	rows, err := s.pool.QueryContext(context.Background(),
		"SELECT id, email, app, created_at, expires_at, accepted_at, revoked_at FROM user_invites"+
			cond+" ORDER BY accepted_at <> 0, created_at DESC, id DESC", args...)
	if err != nil {
		return nil, fmt.Errorf("查邀请: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := make([]AdminInvite, 0, 16)
	now := time.Now().UnixMilli()
	for rows.Next() {
		var (
			it                    AdminInvite
			id                    int64
			acceptedAt, revokedAt int64
		)
		if err := rows.Scan(&id, &it.Email, &it.App, &it.CreatedAt, &it.ExpiresAt,
			&acceptedAt, &revokedAt); err != nil {
			return nil, fmt.Errorf("读邀请行: %w", err)
		}
		it.ID = strconv.FormatInt(id, 10)
		it.State = inviteState(acceptedAt, revokedAt, it.ExpiresAt, now)
		out = append(out, it)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("遍历邀请: %w", err)
	}
	return out, nil
}

// AdminResendInvite 重发邀请（新 token 换旧、续 24h、重发邮件）。
// 已接受 → 400（账号已存在，重发只会指向死路）；已撤销 → 400（应重新发起）。
// 审计 user.invite_resend（detail: email 掩码 + app + invite id）。
func (s *Service) AdminResendInvite(actor Caller, scope AdminScope, id int64) (err error) {
	var row inviteRow
	defer func() {
		s.Audit(AuditEvent{
			Action: AuditUserInviteResend, OK: err == nil, ActorUID: uidPtr(actor.UID),
			ActorEmail: maskEmail(actor.Email), Meta: actor.Meta,
			Detail: map[string]string{"email": maskEmail(row.email), "app": row.app,
				"invite": strconv.FormatInt(id, 10)},
		})
	}()
	if row, err = s.adminInviteRow(scope, id); err != nil {
		return err
	}
	if row.acceptedAt > 0 {
		return badRequest("该邀请已被接受，无需重发")
	}
	if row.revokedAt > 0 {
		return badRequest("该邀请已撤销，请重新发起邀请")
	}
	token, terr := randomToken(inviteTokenBytes)
	if terr != nil {
		return terr
	}
	now := time.Now().UnixMilli()
	expires := now + inviteTTL.Milliseconds()
	// WHERE 带 accepted_at=0：与「接受」并发时只有一边生效——接受先落库的话这里
	// 0 行命中，不会给一个已消费的邀请续命。
	if _, err = s.pool.ExecContext(context.Background(),
		"UPDATE user_invites SET token_hash = ?, created_at = ?, expires_at = ? WHERE id = ? AND accepted_at = 0",
		sha256Hex(token), now, expires, id); err != nil {
		return fmt.Errorf("重发邀请: %w", err)
	}
	s.sendInviteEmail(row.app, row.email, token, time.UnixMilli(expires))
	return nil
}

// AdminRevokeInvite 撤销邀请（置 revoked_at，幂等：已撤销再撤回 ok）。
// 已接受 → 400（账号已建，撤销只会在名单上留一条自相矛盾的行）。
// 审计 user.invite_revoke（detail: email 掩码 + app + invite id）。
func (s *Service) AdminRevokeInvite(actor Caller, scope AdminScope, id int64) (err error) {
	var row inviteRow
	defer func() {
		s.Audit(AuditEvent{
			Action: AuditUserInviteRevoke, OK: err == nil, ActorUID: uidPtr(actor.UID),
			ActorEmail: maskEmail(actor.Email), Meta: actor.Meta,
			Detail: map[string]string{"email": maskEmail(row.email), "app": row.app,
				"invite": strconv.FormatInt(id, 10)},
		})
	}()
	if row, err = s.adminInviteRow(scope, id); err != nil {
		return err
	}
	if row.acceptedAt > 0 {
		return badRequest("该邀请已被接受，无法撤销")
	}
	if row.revokedAt > 0 {
		return nil // 幂等
	}
	// 条件 UPDATE 带 accepted_at=0：与「接受」并发时只有一边生效
	if _, err = s.pool.ExecContext(context.Background(),
		"UPDATE user_invites SET revoked_at = ? WHERE id = ? AND accepted_at = 0",
		time.Now().UnixMilli(), id); err != nil {
		return fmt.Errorf("撤销邀请: %w", err)
	}
	return nil
}

// adminInviteRow 取一行邀请并过 app-admin 的项目边界：查无 → 404；目标 app 不在
// scopes 内（含 app='' 的账号级邀请）→ 403。super 全通。
func (s *Service) adminInviteRow(scope AdminScope, id int64) (inviteRow, error) {
	var r inviteRow
	err := s.pool.QueryRowContext(context.Background(),
		"SELECT email, app, accepted_at, revoked_at FROM user_invites WHERE id = ?", id).
		Scan(&r.email, &r.app, &r.acceptedAt, &r.revokedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return r, &HTTPError{404, "该邀请不存在，请刷新列表后重试"}
	}
	if err != nil {
		return r, fmt.Errorf("查邀请: %w", err)
	}
	r.id = id
	if scerr := adminTargetScope(scope, r.app); scerr != nil {
		return r, scerr
	}
	return r, nil
}

// ---- 公开接受流 ----

// InvitePublic 是接受页（GET /web/invite）验过 token 后的展示信息。
// App 为 '' = 账号级邀请（不限项目）。
type InvitePublic struct {
	Email string
	App   string
}

// InviteLookup 验邀请 token（公开端点，无登录态）：哈希点查 + 四态判定，通过才回
// 展示信息。无效 / 已接受 / 已撤销 / 过期各有各的一句话（错误 = 出错 + 下一步），
// 不区分「token 是乱写的」与「被重发换掉的旧 token」——都不给存在性线索。
func (s *Service) InviteLookup(token string) (*InvitePublic, error) {
	row, err := s.inviteByToken(token)
	if err != nil {
		return nil, err
	}
	return &InvitePublic{Email: row.email, App: row.app}, nil
}

// inviteByToken 按明文 token 点查并做四态判定（Lookup 与 Accept 共用一处，
// 两条路的拒绝口径不会各说各话）。
func (s *Service) inviteByToken(token string) (*inviteRow, error) {
	if strings.TrimSpace(token) == "" {
		return nil, badRequest("邀请链接不完整，请从邀请邮件重新打开")
	}
	var r inviteRow
	err := s.pool.QueryRowContext(context.Background(),
		"SELECT id, email, app, invited_by, accepted_at, revoked_at, expires_at FROM user_invites WHERE token_hash = ?",
		sha256Hex(token)).Scan(&r.id, &r.email, &r.app, &r.invitedBy, &r.acceptedAt, &r.revokedAt, &r.expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, &HTTPError{404, "邀请链接无效，请联系邀请人重新发送"}
	}
	if err != nil {
		return nil, fmt.Errorf("查邀请: %w", err)
	}
	switch inviteState(r.acceptedAt, r.revokedAt, r.expiresAt, time.Now().UnixMilli()) {
	case "accepted":
		return nil, badRequest("该邀请已被接受；如未注册成功请联系邀请人重新发送")
	case "revoked":
		return nil, badRequest("该邀请已被撤销，请联系邀请人重新发送")
	case "expired":
		return nil, badRequest("邀请链接已过期（24 小时内有效），请联系邀请人重新发送")
	}
	return &r, nil
}

// InviteAcceptResult 是接受邀请的回执：账号已建、web 会话已成立（路由层据此签
// cookie，把用户直接送进控制台）。
type InviteAcceptResult struct {
	Email   string
	Session *WebSession
}

// AcceptInvite 接受邀请并自动登录（POST /web/invite）：
//
//	校验：token 四态（inviteByToken）→ 密码规则（validatePassword）→ 昵称规则
//	      （validateProfile 的 nickname 一栏，可空）；
//	行为：单次消费（条件 UPDATE）+ 建号（uid 走 newUserID 的 7 位随机号段）+
//	      可选昵称落 user_profile + 受限项目自动加 project_access + 建 web 会话，
//	      **全部同批事务**（与 Register 同款：不留「已消费邀请却没账号」的半截态）；
//	不自动开 2FA；login_notify 走列默认值（开）；
//	审计 user.invite_accept（detail: app + invite id；只记成功——失败尝试留在
//	invite 行的状态里，token 是 32 字节随机，爆破无收益也无从聚合）。
func (s *Service) AcceptInvite(token, password, nickname string, meta SessionMeta) (*InviteAcceptResult, error) {
	row, err := s.inviteByToken(token)
	if err != nil {
		return nil, err
	}
	if err := validatePassword(password); err != nil {
		return nil, err
	}
	nick, _, _, perr := validateProfile(nickname, 0, nil)
	if perr != nil {
		return nil, perr
	}
	// bcrypt 放到所有校验之后：前面失败时不必白烧一次百毫秒的 cost12
	hashed, err := hash(password)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	tx, err := s.pool.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("开事务: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now().UnixMilli()
	// 单次消费：条件带 accepted_at=0 与未过期两道，RowsAffected≠1 = 并发双开里
	// 落败的一边（账号那边此时已建好，绝不再开第二个）。
	cp, err := tx.ExecContext(ctx,
		"UPDATE user_invites SET accepted_at = ? WHERE id = ? AND accepted_at = 0 AND revoked_at = 0 AND expires_at > ?",
		now, row.id, now)
	if err != nil {
		return nil, fmt.Errorf("消费邀请: %w", err)
	}
	if n, _ := cp.RowsAffected(); n != 1 {
		return nil, badRequest("邀请链接已失效，请联系邀请人重新发送")
	}
	uid, err := newUserID(randUserID, func(id int64) error {
		_, e := tx.ExecContext(ctx,
			"INSERT INTO users (id, email, password_hash, created_at, token_version) VALUES (?, ?, ?, ?, 1)",
			id, row.email, hashed, now)
		return e
	})
	if err != nil {
		// 接受与自助注册 / 管理员改邮的并发撞库：uq_users_email 挡住，翻译成人话
		//（与 Register 同口径，顺带把含邮箱的 MySQL 错误串挡在日志外）。
		var me *mysql.MySQLError
		if errors.As(err, &me) && me.Number == 1062 {
			return nil, badRequest("该邮箱已注册，请直接登录")
		}
		return nil, fmt.Errorf("创建用户: %w", err)
	}
	if nick != "" {
		if _, err = tx.ExecContext(ctx,
			"INSERT INTO user_profile (user_id, nickname, avatar_color, updated_at) VALUES (?,?,0,?)",
			uid, nick, now); err != nil {
			return nil, fmt.Errorf("写用户档案: %w", err)
		}
	}
	// 邀请带项目且该项目已开登录白名单 → 自动加入放行名单。开放项目不落行：
	// 名单只对受限项目有意义，白加一行只会在项目访问页多出一条迷惑记录。
	if row.app != "" {
		var restricted int
		scanErr := tx.QueryRowContext(ctx,
			"SELECT restricted FROM project_policy WHERE app = ?", row.app).Scan(&restricted)
		if scanErr != nil && !errors.Is(scanErr, sql.ErrNoRows) {
			return nil, fmt.Errorf("查项目限制: %w", scanErr)
		}
		if restricted == 1 {
			if _, err = tx.ExecContext(ctx,
				"INSERT IGNORE INTO project_access (app, uid, granted_by, created_at) VALUES (?,?,?,?)",
				row.app, uid, row.invitedBy, now); err != nil {
				return nil, fmt.Errorf("加入项目名单: %w", err)
			}
		}
	}
	ws, err := s.createWebSessionOn(tx, uid, meta)
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, fmt.Errorf("提交接受邀请: %w", err)
	}
	// 建号前刚亲手设过密码 = 强认证：打 reauth 窗，进控制台后的敏感操作不必再逼一遍
	_ = s.MarkReauth(ws.SID)
	s.Audit(AuditEvent{
		Action: AuditUserInviteAccept, OK: true, ActorUID: uidPtr(uid),
		ActorEmail: maskEmail(row.email), Meta: meta,
		Detail: map[string]string{"app": row.app, "invite": strconv.FormatInt(row.id, 10)},
	})
	return &InviteAcceptResult{Email: row.email, Session: ws}, nil
}

// sendInviteEmail 投邀请链接信。品牌按邀请 app（无 app = 中性 Auth）——
// 收件人看到的是自己被邀请加入的那个项目的名头。
func (s *Service) sendInviteEmail(app, email, token string, expiresAt time.Time) {
	if s.mailer == nil {
		return
	}
	b := brandFor(app)
	subject, htmlBody, text := inviteEmail(b, siteBase+"/web/invite?token="+token, expiresAt)
	if err := s.mailer.Send(context.Background(), b.name, email, subject, htmlBody, text); err != nil {
		mailLog(err, "user_invite", email)
	}
}
