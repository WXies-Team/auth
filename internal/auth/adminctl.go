package auth

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
	"unicode"

	"github.com/go-sql-driver/mysql"
)

// W1/W2/W5 的管理操作（管理员重置密码 / 封禁 / 项目名单与限制）。
// 授权判定的公共段（404、根收口、scope 越权）在 gate.go 的 adminTarget /
// adminTargetScope；本文件只做各端点专属的参数校验、数据操作与审计。

// knownAppOrder 是项目展示序（allowedApps 的定序视图）：Go map 遍历无序，
// 后台项目列表每请求要稳定排序。**新增应用时与 allowedApps 一起加**
//（TestKnownAppOrderMatchesWhitelist 对拍漂移）。
var knownAppOrder = []string{"calorie-diary", "expense-diary"}

// appName 取项目展示名：走品牌注册表（与 internal/ui 的 knownApps 同键，
// TestBrandForSelection 钉住 brands ↔ allowedApps 同步）。未登记回 slug 兜底。
func appName(app string) string {
	if b, ok := brands[app]; ok {
		return b.name
	}
	return app
}

// ---- W1 管理员重置密码 ----

// AdminPasswordReset 是 POST /admin/users/{uid}/password 的入参（契约 6）。
// BatchID 是 B9 批量操作的批次号：单发恒空；批量时由 AdminBulk 填，随审计 detail
// 落库——逐用户事件与 admin.bulk_action 总账靠它关联，**不进回执**。
type AdminPasswordReset struct {
	Mode        string // "generate"（16 位强随机）| "manual"（管理员手输）
	Password    string // mode=manual 时的临时密码；generate 忽略
	ForceChange bool   // password_must_change 置 1（用户下次登录必须改密）/ 0
	Notify      bool   // 给用户发「密码重置通知」（含临时密码本体）
	Reason      string // 备注：只进审计 detail
	BatchID     string // 批量操作批次号（单发为空）
}

const (
	tempPasswordLen = 16
	tempPWUpper     = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	tempPWLower     = "abcdefghijklmnopqrstuvwxyz"
	tempPWDigits    = "0123456789"
)

// generateTempPassword 生成 16 位强随机临时密码：大小写字母与数字**各至少一位**，
// 其余从全集取，最后 crypto/rand 洗牌。不能用 math/rand——可预测等于没重置。
func generateTempPassword() (string, error) {
	pick := func(set string) (byte, error) {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(set))))
		if err != nil {
			return 0, err
		}
		return set[n.Int64()], nil
	}
	buf := make([]byte, 0, tempPasswordLen)
	for _, set := range []string{tempPWUpper, tempPWLower, tempPWDigits} {
		c, err := pick(set)
		if err != nil {
			return "", fmt.Errorf("生成临时密码: %w", err)
		}
		buf = append(buf, c)
	}
	all := tempPWUpper + tempPWLower + tempPWDigits
	for len(buf) < tempPasswordLen {
		c, err := pick(all)
		if err != nil {
			return "", fmt.Errorf("生成临时密码: %w", err)
		}
		buf = append(buf, c)
	}
	for i := len(buf) - 1; i > 0; i-- {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return "", fmt.Errorf("生成临时密码: %w", err)
		}
		j := int(n.Int64())
		buf[i], buf[j] = buf[j], buf[i]
	}
	return string(buf), nil
}

// validateManualPassword 校验管理员手输的临时密码（契约 6 的 400 口径）：
// 空 → 400；不足 8 位 / 超 72 字节复用 validatePassword 的现规则；
// **单一字符类**（纯小写、纯大写、纯数字、纯符号）算弱 → 400。
func validateManualPassword(p string) error {
	if strings.TrimSpace(p) == "" {
		return badRequest("请输入要设置的密码，或改用自动生成")
	}
	if err := validatePassword(p); err != nil {
		return err
	}
	var lower, upper, digit, other bool
	for _, r := range p {
		switch {
		case unicode.IsUpper(r):
			upper = true
		case unicode.IsLower(r):
			lower = true
		case unicode.IsDigit(r):
			digit = true
		default:
			other = true
		}
	}
	classes := 0
	for _, has := range []bool{lower, upper, digit, other} {
		if has {
			classes++
		}
	}
	if classes < 2 {
		return badRequest("密码不能是单一类型字符（如纯字母或纯数字），请混合字母与数字后重试")
	}
	return nil
}

// AdminResetPassword 执行管理员重置（W1）：
//
//	权限：su 对任何人；app-admin 只能对「当前在任一其授权项目下有活跃会话」的用户
//	      （无 → 403 你没有该用户的管理权限）；目标是根 su 账号时仅根本人（adminTarget）。
//	行为：写新 hash、password_must_change 按 forceChange 置位、token_version+1 且
//	      吊销全部既有会话；回执的临时密码**只在这里出现一次**（不进日志、不进审计）。
//	审计：password.reset（detail: mode / forceChange / notify / reason，不记密码）。
func (s *Service) AdminResetPassword(actor Caller, scope AdminScope, targetUID int64, in AdminPasswordReset) (tmp string, err error) {
	defer func() {
		detail := map[string]string{
			"mode": in.Mode, "forceChange": boolWord(in.ForceChange), "notify": boolWord(in.Notify),
		}
		if strings.TrimSpace(in.Reason) != "" {
			detail["reason"] = in.Reason
		}
		s.Audit(AuditEvent{
			Action: AuditPasswordReset, OK: err == nil, ActorUID: uidPtr(actor.UID),
			ActorEmail: maskEmail(actor.Email), TargetUID: uidPtr(targetUID), Meta: actor.Meta,
			Detail: withBatchID(detail, in.BatchID),
		})
	}()
	switch in.Mode {
	case "generate":
		if tmp, err = generateTempPassword(); err != nil {
			return "", err
		}
	case "manual":
		if err = validateManualPassword(in.Password); err != nil {
			return "", err
		}
		tmp = in.Password
	default:
		return "", badRequest("mode 只能是 generate 或 manual，请重新选择后重试")
	}
	// 目标存在（404）与根收口（403）——先于 session 查询表态
	email, err := s.adminTarget(actor, targetUID)
	if err != nil {
		return "", err
	}
	// app-admin：目标必须在任一授权项目下有活跃会话（W1 权限口径）
	if !scope.Super {
		ok, cerr := s.targetHasScopedSession(targetUID, scope.Apps)
		if cerr != nil {
			return "", cerr
		}
		if !ok {
			return "", &HTTPError{403, "你没有该用户的管理权限"}
		}
	}
	hashed, err := hash(tmp)
	if err != nil {
		return "", err
	}
	forceFlag := 0
	if in.ForceChange {
		forceFlag = 1
	}
	ctx := context.Background()
	tx, err := s.pool.BeginTx(ctx, nil)
	if err != nil {
		return "", fmt.Errorf("开事务: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err = tx.ExecContext(ctx,
		"UPDATE users SET password_hash = ?, token_version = token_version + 1, password_must_change = ? WHERE id = ?",
		hashed, forceFlag, targetUID); err != nil {
		return "", fmt.Errorf("重置密码: %w", err)
	}
	if err = revokeUserSessions(ctx, tx, targetUID, 0, nil); err != nil {
		return "", err
	}
	if err = tx.Commit(); err != nil {
		return "", fmt.Errorf("提交重置: %w", err)
	}
	// 通知信尽力而为：临时密码已回执给管理员，信没发出去不该把重置翻成 500
	if in.Notify {
		s.sendPasswordResetNotice(email, tmp)
	}
	return tmp, nil
}

// targetHasScopedSession 判「目标在任一授权项目下有活跃会话」（W1 的 app-admin 闸）。
// apps 为空（零 scope admin）恒 false——没有项目就没有可管的用户。
func (s *Service) targetHasScopedSession(uid int64, apps []string) (bool, error) {
	if len(apps) == 0 {
		return false, nil
	}
	args := make([]any, 0, len(apps)+1)
	args = append(args, uid)
	for _, a := range apps {
		args = append(args, a)
	}
	var ok int
	err := s.pool.QueryRowContext(context.Background(),
		"SELECT EXISTS(SELECT 1 FROM sessions WHERE user_id = ? AND revoked_at IS NULL AND app IN ("+
			placeholders(len(apps))+"))", args...).Scan(&ok)
	if err != nil {
		return false, fmt.Errorf("查目标会话: %w", err)
	}
	return ok == 1, nil
}

// sendPasswordResetNotice 发「密码重置通知」（W8 第 1 封，含临时密码本体——
// 用户已拍板两者都发）。品牌恒中性 Auth；失败只记日志。
func (s *Service) sendPasswordResetNotice(email, temporary string) {
	if s.mailer == nil {
		return
	}
	b := brandFor("")
	subject, htmlBody, text := passwordResetNoticeEmail(b, temporary)
	if err := s.mailer.Send(context.Background(), b.name, email, subject, htmlBody, text); err != nil {
		mailLog(err, "password_reset_notice", email)
	}
}

// ---- W1 管理员更换邮箱 ----

// AdminEmailChange 是 POST /admin/users/{uid}/email 的入参（B5 契约）。
type AdminEmailChange struct {
	Email  string // 新邮箱（归一化 + 格式 + 查重都在业务层）
	Reason string // 备注：只进审计 detail
}

// AdminChangeEmail 执行管理员更换邮箱（B5，Okta Admin Console 口径）：
//
//	权限：与 AdminResetPassword 逐字同矩阵——su 对任何人；目标是根 su 仅根本人；
//	      app-admin 只能对「当前在任一其授权项目下有活跃会话」的用户
//	      （无 → 403 你没有该用户的管理权限）。
//	校验：邮箱格式（validateEmail）；与原邮箱相同 → 400 邮箱未变化；
//	      已被其它账号占用 → 400 该邮箱已被其它账号使用（撞库唯一性）。
//	行为：直接 UPDATE users.email，**不 bump token_version**（uid 是权威标识，
//	      会话全部保留——与自助改绑同口径）；顺手烧掉该用户全部进行中的自助改邮验证码
//	      （按 uid 烧 purpose=email_change 的在途码，防「管理员改完用户又拿旧码
//	      改回去」的覆盖竞态——码按用户申请的目标地址存，只按新旧邮箱匹配会漏）。
//	通知：新旧邮箱**都必发**管理员措辞的警报/指引信（无勾选，安全网）。
//	审计：user.email_change（detail 只带 newEmail / oldEmail / reason 三键，邮箱掩码）。
func (s *Service) AdminChangeEmail(actor Caller, scope AdminScope, targetUID int64, in AdminEmailChange) (err error) {
	var oldEmail string
	defer func() {
		detail := map[string]string{"newEmail": maskEmail(normalizeEmail(in.Email))}
		if oldEmail != "" {
			detail["oldEmail"] = maskEmail(oldEmail)
		}
		if strings.TrimSpace(in.Reason) != "" {
			detail["reason"] = in.Reason
		}
		s.Audit(AuditEvent{
			Action: AuditUserEmailChange, OK: err == nil, ActorUID: uidPtr(actor.UID),
			ActorEmail: maskEmail(actor.Email), TargetUID: uidPtr(targetUID), Meta: actor.Meta,
			Detail: detail,
		})
	}()
	email := normalizeEmail(in.Email)
	if verr := validateEmail(email); verr != nil {
		return verr
	}
	// 目标存在（404）与根收口（403）——先于其它校验表态；回执里的旧邮箱是后续判定的底稿
	oldEmail, err = s.adminTarget(actor, targetUID)
	if err != nil {
		return err
	}
	// app-admin：目标必须在任一授权项目下有活跃会话（与 AdminResetPassword 同一矩阵）
	if !scope.Super {
		ok, cerr := s.targetHasScopedSession(targetUID, scope.Apps)
		if cerr != nil {
			return cerr
		}
		if !ok {
			return &HTTPError{403, "你没有该用户的管理权限"}
		}
	}
	if email == normalizeEmail(oldEmail) {
		return badRequest("邮箱未变化")
	}
	exists, xerr := s.userExists(email)
	if xerr != nil {
		return xerr
	}
	if exists {
		return badRequest("该邮箱已被其它账号使用")
	}
	ctx := context.Background()
	tx, err := s.pool.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("开事务: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err = tx.ExecContext(ctx,
		"UPDATE users SET email = ? WHERE id = ?", email, targetUID); err != nil {
		// 并发下另一个账号先占了这个邮箱：uq_users_email 挡住，翻译成同一句人话
		var me *mysql.MySQLError
		if errors.As(err, &me) && me.Number == 1062 {
			return badRequest("该邮箱已被其它账号使用")
		}
		return fmt.Errorf("更换邮箱: %w", err)
	}
	// 清掉在途的自助改邮验证码（FX5）：改邮码按**用户申请的目标地址**存（见
	// SendChangeEmailCode），既不在改后邮箱也不在旧邮箱名下——按邮箱匹配会漏掉
	//「申请改成第三地址」的在途码，用户一提交就把管理员的结果覆盖回去。按 uid
	// 烧该用户全部 email_change 在途码才封死这条覆盖竞态；也不能反过来按邮箱
	// 烧：那会误伤恰好申请改成这两个地址的**其他**账号的在途码。
	if _, derr := tx.ExecContext(ctx,
		"UPDATE otp_codes SET used = 1 WHERE uid = ? AND purpose = ? AND used = 0",
		targetUID, PurposeChangeEmail); derr != nil {
		return fmt.Errorf("清自助改邮验证码: %w", derr)
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("提交更换邮箱: %w", err)
	}
	// 通知信尽力而为：改绑已完成，信没发出去不该翻成 500（与改密通知同口径）
	s.notifyAdminEmailChanged(oldEmail, email)
	return nil
}

// notifyAdminEmailChanged 管理员改邮后的两封通知信（旧、新邮箱各一封，必发）。
// 品牌恒中性 Auth（账号级操作，subject 前缀【Auth】）；失败只记日志。
func (s *Service) notifyAdminEmailChanged(oldEmail, newEmail string) {
	if s.mailer == nil {
		return
	}
	b := brandFor("")
	for _, to := range []struct {
		addr  string
		toNew bool
	}{{oldEmail, false}, {newEmail, true}} {
		subject, htmlBody, text := adminChangeEmailNoticeEmail(b, to.toNew, oldEmail, newEmail)
		if err := s.mailer.Send(context.Background(), b.name, to.addr, subject, htmlBody, text); err != nil {
			mailLog(err, "admin_email_change_notice", to.addr)
		}
	}
}

// ---- W3 管理员重置资料 ----

// AdminProfileReset 是 POST /admin/users/{uid}/profile-reset 的入参（B5 契约）。
type AdminProfileReset struct {
	Avatar   bool // 清 avatarImage + avatarColor（回退色块+首字）
	Nickname bool // 清 nickname（回退邮箱前缀）
}

// AdminResetProfile 执行管理员重置资料（B5）：
//
//	权限：与 AdminChangeEmail / AdminResetPassword 同一矩阵（su / 根收口 / app-admin
//	      需目标在任一授权项目下有活跃会话）。
//	行为：至少勾一项（全否 → 400）；按项清 user_profile 的列——avatar=true 清
//	      avatarImage 与 avatarColor（回退到「色块+首字」，color 归 0 取色板首位），
//	      nickname=true 清 nickname（回退邮箱前缀）。无档案行时为幂等 no-op。
//	      **不动 users 表、不吊销会话**——资料重置不是凭证变更。
//	审计：user.profile_reset（detail 只带 cleared：avatar,nickname 清单 + reason）。
func (s *Service) AdminResetProfile(actor Caller, scope AdminScope, targetUID int64, in AdminProfileReset) (err error) {
	defer func() {
		cleared := make([]string, 0, 2)
		if in.Avatar {
			cleared = append(cleared, "avatar")
		}
		if in.Nickname {
			cleared = append(cleared, "nickname")
		}
		s.Audit(AuditEvent{
			Action: AuditUserProfileReset, OK: err == nil, ActorUID: uidPtr(actor.UID),
			ActorEmail: maskEmail(actor.Email), TargetUID: uidPtr(targetUID), Meta: actor.Meta,
			Detail: map[string]string{"cleared": strings.Join(cleared, ",")},
		})
	}()
	if !in.Avatar && !in.Nickname {
		return badRequest("请至少选择要重置的一项（头像或昵称）")
	}
	if _, err = s.adminTarget(actor, targetUID); err != nil {
		return err
	}
	if !scope.Super {
		ok, cerr := s.targetHasScopedSession(targetUID, scope.Apps)
		if cerr != nil {
			return cerr
		}
		if !ok {
			return &HTTPError{403, "你没有该用户的管理权限"}
		}
	}
	// 逐项生成 SET 子句：无档案行时 UPDATE 命中 0 行 = 幂等 no-op（从未设置过
	// 档案的账号本就回退在默认态，重置它无事可做）。
	sets := make([]string, 0, 2)
	args := make([]any, 0, 3)
	if in.Avatar {
		sets = append(sets, "avatar_image = NULL", "avatar_color = 0")
	}
	if in.Nickname {
		sets = append(sets, "nickname = ''")
	}
	sets = append(sets, "updated_at = ?")
	args = append(args, time.Now().UnixMilli(), targetUID)
	if _, err = s.pool.ExecContext(context.Background(),
		"UPDATE user_profile SET "+strings.Join(sets, ", ")+" WHERE user_id = ?", args...); err != nil {
		return fmt.Errorf("重置资料: %w", err)
	}
	return nil
}

// ---- W2 封禁 ----

// AdminBanInput 是封禁端点入参（契约 6）。BatchID 见 AdminPasswordReset.BatchID。
type AdminBanInput struct {
	App     string // '*' = 全站；否则项目 slug（白名单内）
	Until   int64  // 0 = 永久；否则**未来**的毫秒时间戳
	Reason  string
	BatchID string // 批量操作批次号（单发为空）
}

// AdminBan 封禁一个用户（W2）：upsert user_bans（重复封禁 = 覆盖），
// 写入后**立即吊销范围内全部会话**（'*' → 全部；具体 app → 该 app 会话），
// **不 bump token_version**（只杀范围内会话，范围外项目的 token 不受牵连）。
// 400：slug 不在白名单 / admin 传 '*' / until 已过去；403 越权；404 目标不存在。
// 审计 user.ban（detail: app / until / reason）。
func (s *Service) AdminBan(actor Caller, scope AdminScope, targetUID int64, in AdminBanInput) (err error) {
	defer func() {
		s.Audit(AuditEvent{
			Action: AuditUserBan, OK: err == nil, ActorUID: uidPtr(actor.UID),
			ActorEmail: maskEmail(actor.Email), TargetUID: uidPtr(targetUID), Meta: actor.Meta,
			Detail: withBatchID(map[string]string{
				"app": in.App, "until": untilStr(in.Until), "reason": in.Reason}, in.BatchID),
		})
	}()
	if in.App != "*" && !allowedApps[in.App] {
		return badRequest("未知项目，请重新选择后重试")
	}
	if in.App == "*" && !scope.Super {
		return badRequest("全站封禁仅平台管理员可操作，请改为具体项目后重试")
	}
	if in.Until != 0 && in.Until <= time.Now().UnixMilli() {
		return badRequest("解除时间必须晚于当前时间，请重新选择")
	}
	if err = adminTargetScope(scope, in.App); err != nil {
		return err
	}
	if _, err = s.adminTarget(actor, targetUID); err != nil {
		return err
	}
	ctx := context.Background()
	if _, err = s.pool.ExecContext(ctx,
		`INSERT INTO user_bans (uid, app, until_ms, reason, banned_by, created_at)
		 VALUES (?,?,?,?,?,?)
		 ON DUPLICATE KEY UPDATE until_ms = VALUES(until_ms), reason = VALUES(reason),
		                         banned_by = VALUES(banned_by), created_at = VALUES(created_at)`,
		targetUID, in.App, in.Until, truncateRunes(in.Reason, 255), actor.UID, time.Now().UnixMilli()); err != nil {
		return fmt.Errorf("写封禁: %w", err)
	}
	// 立即下线范围内会话：'*' → apps=nil 不限（该用户全部），具体项目 → 只杀该 app
	var apps []string
	if in.App != "*" {
		apps = []string{in.App}
	}
	if err = revokeUserSessions(ctx, s.pool, targetUID, 0, apps); err != nil {
		return err
	}
	return nil
}

// AdminUnban 解除封禁（W2）：删行（幂等——行不在也回 ok）+ 审计 user.unban。
// 参数与越权校验和 AdminBan 同一套（400/403/404 同序同由）。
// batchID 是 B9 批量操作的批次号（单发传空串），只进审计 detail。
func (s *Service) AdminUnban(actor Caller, scope AdminScope, targetUID int64, app, batchID string) (err error) {
	defer func() {
		s.Audit(AuditEvent{
			Action: AuditUserUnban, OK: err == nil, ActorUID: uidPtr(actor.UID),
			ActorEmail: maskEmail(actor.Email), TargetUID: uidPtr(targetUID), Meta: actor.Meta,
			Detail: withBatchID(map[string]string{"app": app}, batchID),
		})
	}()
	if app != "*" && !allowedApps[app] {
		return badRequest("未知项目，请重新选择后重试")
	}
	if app == "*" && !scope.Super {
		return badRequest("全站封禁仅平台管理员可操作，请改为具体项目后重试")
	}
	if err = adminTargetScope(scope, app); err != nil {
		return err
	}
	if _, err = s.adminTarget(actor, targetUID); err != nil {
		return err
	}
	if _, err = s.pool.ExecContext(context.Background(),
		"DELETE FROM user_bans WHERE uid = ? AND app = ?", targetUID, app); err != nil {
		return fmt.Errorf("解除封禁: %w", err)
	}
	return nil
}

// ---- W5 项目登录白名单 ----

// AdminProjectMember 是受邀名单的一行。
type AdminProjectMember struct {
	UID   int64  `json:"uid"`
	Email string `json:"email"`
}

// AdminProject 是 GET /admin/projects 的一条（回执由路由层包进 {projects:[...]}）。
// ClientID 是该项目的 OAuth client_id（空串 = 未开通，前端据此渲染空态）；
// RedirectURIs 是已登记的回跳地址（未开通时为 null）。
type AdminProject struct {
	App          string               `json:"app"`
	Name         string               `json:"name"`
	Restricted   bool                 `json:"restricted"`
	Members      []AdminProjectMember `json:"members"`
	ClientID     string               `json:"clientId"`
	RedirectURIs []string             `json:"redirectUris"`
}

// AdminListProjects 列项目与名单（契约 6）：super = 全部 knownApps，
// app-admin = 仅其 admin_scopes 项目（零 scope 回空列表，页面空态说明）。
// restricted 直查 project_policy（不进 app_config 缓存）。
func (s *Service) AdminListProjects(scope AdminScope) ([]AdminProject, error) {
	ctx := context.Background()
	out := make([]AdminProject, 0, len(knownAppOrder))
	for _, app := range knownAppOrder {
		if !scope.Super && !containsStr(scope.Apps, app) {
			continue
		}
		p := AdminProject{
			App: app, Name: appName(app),
			Members: make([]AdminProjectMember, 0, 4),
		}
		var restricted int
		err := s.pool.QueryRowContext(ctx,
			"SELECT restricted FROM project_policy WHERE app = ?", app).Scan(&restricted)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("查项目限制: %w", err)
		}
		p.Restricted = restricted == 1

		rows, err := s.pool.QueryContext(ctx,
			"SELECT pa.uid, u.email FROM project_access pa JOIN users u ON u.id = pa.uid"+
				" WHERE pa.app = ? ORDER BY pa.created_at, pa.uid", app)
		if err != nil {
			return nil, fmt.Errorf("查项目名单: %w", err)
		}
		for rows.Next() {
			var m AdminProjectMember
			if err := rows.Scan(&m.UID, &m.Email); err != nil {
				_ = rows.Close()
				return nil, fmt.Errorf("读项目名单: %w", err)
			}
			p.Members = append(p.Members, m)
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("遍历项目名单: %w", err)
		}
		_ = rows.Close()
		// OAuth 客户端登记（B4）：有则带 clientId/redirectUris，空 = 未开通
		p.ClientID, p.RedirectURIs = s.OAuthClientIDFor(app)
		out = append(out, p)
	}
	return out, nil
}

// uidByEmail 按注册邮箱取 uid（access 端点的邮箱 → 账号解析）。
// 格式错 400；查无 404（「邮箱不存在」，契约 6 的 404 语义）。
func (s *Service) uidByEmail(rawEmail string) (int64, error) {
	email := normalizeEmail(rawEmail)
	if err := validateEmail(email); err != nil {
		return 0, err
	}
	var uid int64
	err := s.pool.QueryRowContext(context.Background(),
		"SELECT id FROM users WHERE email = ?", email).Scan(&uid)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, &HTTPError{404, "该用户不存在，请刷新用户列表后重试"}
	}
	if err != nil {
		return 0, fmt.Errorf("查用户: %w", err)
	}
	return uid, nil
}

// AdminGrantAccess 把用户加入项目受邀名单（POST /admin/projects/{app}/access）：
// 404 邮箱不存在 / 403 越权 / 已在名单幂等 ok。放行不吊销会话（它是开权限，不是收权限）。
// 审计 project.access_grant（detail: app；target_uid 带被加的人）。
func (s *Service) AdminGrantAccess(actor Caller, scope AdminScope, app, rawEmail string) (err error) {
	var target int64
	defer func() {
		s.Audit(AuditEvent{
			Action: AuditProjectAccessGrant, OK: err == nil, ActorUID: uidPtr(actor.UID),
			ActorEmail: maskEmail(actor.Email), TargetUID: uidPtr(target), Meta: actor.Meta,
			Detail: map[string]string{"app": app},
		})
	}()
	if !allowedApps[app] {
		return badRequest("未知项目，请重新选择后重试")
	}
	if err = adminTargetScope(scope, app); err != nil {
		return err
	}
	target, err = s.uidByEmail(rawEmail)
	if err != nil {
		return err
	}
	if _, err = s.pool.ExecContext(context.Background(),
		"INSERT IGNORE INTO project_access (app, uid, granted_by, created_at) VALUES (?,?,?,?)",
		app, target, actor.UID, time.Now().UnixMilli()); err != nil {
		return fmt.Errorf("加入项目名单: %w", err)
	}
	return nil
}

// AdminRevokeAccess 把用户移出项目受邀名单（DELETE /admin/projects/{app}/access）：
// **幂等**——邮箱查无或不在名单都回 ok（只把「移除」当无事发生）；找到人则删行并
// **吊销其该 app 的全部会话**（W5：从名单移除成员即下线）。格式错仍 400。
// 审计 project.access_revoke。
func (s *Service) AdminRevokeAccess(actor Caller, scope AdminScope, app, rawEmail string) (err error) {
	var target int64
	defer func() {
		s.Audit(AuditEvent{
			Action: AuditProjectAccessRevoke, OK: err == nil, ActorUID: uidPtr(actor.UID),
			ActorEmail: maskEmail(actor.Email), TargetUID: uidPtr(target), Meta: actor.Meta,
			Detail: map[string]string{"app": app},
		})
	}()
	if !allowedApps[app] {
		return badRequest("未知项目，请重新选择后重试")
	}
	if err = adminTargetScope(scope, app); err != nil {
		return err
	}
	uid, uerr := s.uidByEmail(rawEmail)
	if uerr != nil {
		// 404（邮箱查无）= 幂等无事可做：没有这个人就没有要移除的行与会话。
		// 其它错误（格式 400 / DB 错）照抛。
		var he *HTTPError
		if errors.As(uerr, &he) && he.Code == 404 {
			return nil
		}
		return uerr
	}
	target = uid
	if _, err = s.pool.ExecContext(context.Background(),
		"DELETE FROM project_access WHERE app = ? AND uid = ?", app, uid); err != nil {
		return fmt.Errorf("移出项目名单: %w", err)
	}
	if err = revokeUserSessions(context.Background(), s.pool, uid, 0, []string{app}); err != nil {
		return err
	}
	return nil
}

// AdminSetRestricted 开关项目登录白名单（POST /admin/projects/{app}/restrict）：
// upsert project_policy（直查直写，不进缓存）。**开限制时扫一遍**吊销该 app 下
// 不合规用户（非 super、不在名单、非该项目 admin）的会话；关限制不吊销。
// 审计 project.restrict_on / project.restrict_off（detail: app）。
func (s *Service) AdminSetRestricted(actor Caller, scope AdminScope, app string, restricted bool) (err error) {
	action := AuditProjectRestrictOff
	if restricted {
		action = AuditProjectRestrictOn
	}
	defer func() {
		s.Audit(AuditEvent{
			Action: action, OK: err == nil, ActorUID: uidPtr(actor.UID),
			ActorEmail: maskEmail(actor.Email), Meta: actor.Meta,
			Detail: map[string]string{"app": app},
		})
	}()
	if !allowedApps[app] {
		return badRequest("未知项目，请重新选择后重试")
	}
	if err = adminTargetScope(scope, app); err != nil {
		return err
	}
	flag := 0
	if restricted {
		flag = 1
	}
	ctx := context.Background()
	if _, err = s.pool.ExecContext(ctx,
		`INSERT INTO project_policy (app, restricted, updated_by, updated_at) VALUES (?,?,?,?)
		 ON DUPLICATE KEY UPDATE restricted = VALUES(restricted),
		                         updated_by = VALUES(updated_by), updated_at = VALUES(updated_at)`,
		app, flag, actor.UID, time.Now().UnixMilli()); err != nil {
		return fmt.Errorf("写项目限制: %w", err)
	}
	if !restricted {
		return nil
	}
	// 开限制即清场：不在白名单（super / 在册 / 该项目 admin）的活跃会话当场吊销。
	// 子查询不引用 sessions，不撞 MySQL 的「同表不能出现在 UPDATE 的子查询」限制。
	if _, err = s.pool.ExecContext(ctx,
		`UPDATE sessions SET revoked_at = ?
		 WHERE app = ? AND revoked_at IS NULL AND user_id NOT IN (
		   SELECT id FROM users WHERE role = ?
		   UNION SELECT uid FROM project_access WHERE app = ?
		   UNION SELECT uid FROM admin_scopes WHERE app = ?)`,
		time.Now().UnixMilli(), app, adminRoleSuper, app, app); err != nil {
		return fmt.Errorf("吊销不合规会话: %w", err)
	}
	return nil
}
