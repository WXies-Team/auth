package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/WXies-Team/auth/internal/protocol"
)

// 管理后台的口径（规格 A2.5）：
//
//	授权判定在路由层（requireAdmin 每请求现查 + 强制 MFA + reauth 2 小时窗），
//	本文件只管数据操作与「管理动作必记审计」；
//	配置中心**写而不显**：secret 键只回 configured + 末 4 位，改动只记 key。
const (
	// adminRoleUser / adminRoleAdmin 是 users.role 的两值（deny-by-default：新用户恒 user）。
	adminRoleUser  = "user"
	adminRoleAdmin = "admin"

	// adminMaxPage 是后台列表的页大小上限；默认页 20，一页放得下且不用懒加载。
	adminMaxPage = 100
	// adminMaxConfigValue 是单个配置值的字节数上限：app_config.value 是 TEXT，
	// 放开到 64KB 等于给「手滑粘了一整个文件」留门，4KB 覆盖真实密钥与地址绰绰有余。
	adminMaxConfigValue = 4096
)

// RootSuperEmail 是**根平台管理员**的钉死邮箱。super 的授予与回收只认这一个身份
//（见 AdminSetRole）——改这个值等于移交根权限，**改需慎重**：动它之前确认新邮箱
// 的持有者身份，且库里至少还有一个有效 super。
const RootSuperEmail = "horatioxs@outlook.com"

// AdminUser 是后台用户列表/详情的一行。
type AdminUser struct {
	UID          int64  `json:"uid"`
	Email        string `json:"email"`
	Role         string `json:"role"`
	CreatedAt    int64  `json:"createdAt"`
	TotpEnabled  bool   `json:"totpEnabled"`
	PasskeyCount int    `json:"passkeyCount"`
	// ScopeCount 是该用户持有的应用授权行数（admin_scopes）：普通用户恒 0，
	// app-admin 一眼能看出他管几个项目。按 uid IN 批量回填，不做 N+1。
	ScopeCount int `json:"scopeCount"`
}

// AdminUserDetail 是用户详情：加凭证摘要、应用授权清单与活跃会话，够管理员判断
//「要不要踢、该不该给权限」，不回任何口令散列。
type AdminUserDetail struct {
	AdminUser
	HasPassword bool                   `json:"hasPassword"`
	Scopes      []string               `json:"scopes"`
	Sessions    []protocol.SessionInfo `json:"sessions"`
	Passkeys    []PasskeyInfo          `json:"passkeys"`
}

// AdminSession 是全站会话总览的一行（比用户自己的设备列表多出 uid/email）。
// ID 同 SessionInfo：**十进制字符串**输出（63 位雪花过不了浏览器 JSON.parse 的
// 53 位精度，路径里的会话 id 也按字符串传）。
type AdminSession struct {
	ID         string `json:"id"`
	UID        int64  `json:"uid"`
	Email      string `json:"email"`
	App        string `json:"app"`
	Device     string `json:"device"`
	IP         string `json:"ip"`
	CreatedAt  int64  `json:"createdAt"`
	LastSeenAt int64  `json:"lastSeenAt"`
}

// ConfigItem 是配置中心的一条：secret 只回 configured + 末 4 位 hint，
// 非 secret 回全文（value）。hint 只对 secret 有值。
type ConfigItem struct {
	Key        string `json:"key"`
	Secret     bool   `json:"secret"`
	Configured bool   `json:"configured"`
	Value      string `json:"value,omitempty"`
	Hint       string `json:"hint,omitempty"`
}

// AIUsageDayTotal 是一天的用量（date = YYYY-MM-DD，count = 当日次数）。
// days 数组按**日期升序**铺满整个查询窗口、没用量的日期补 0——折线图要有连续的
// 时间轴，前端不必自己补齐（0 次是事实，不是造数）。
type AIUsageDayTotal struct {
	Date  string `json:"date"`
	Count int    `json:"count"`
}

// AIUsageGlobal 是全站当日用量与全站日限额（ai_daily_global）。用的是
// scope='global' 那一行——限额闸看的就是它，与看板同源同数。
type AIUsageGlobal struct {
	Used  int `json:"used"`
	Limit int `json:"limit"`
}

// AIUsageUserRow 是看板 per-user 的一行：today / range / share 三个用量视角，
// 加 limitToday（per-user 每日限额）——前端拿它与 today 直拼「剩 x/limit」进度条，
// 不必自己算。share 是**区间口径**：该用户区间用量 / 全站区间合计（0..1 比例）。
type AIUsageUserRow struct {
	UID        int64   `json:"uid"`
	Email      string  `json:"email"`
	Today      int     `json:"today"`
	Range      int     `json:"range"`
	Share      float64 `json:"share"`
	LimitToday int     `json:"limitToday"`
}

// AIUsageOverview 是 GET /admin/ai-usage（不带 uid）的回执。
//
//	today / yesterday / activeToday（今日有用量的人数）/ days / users 全部按
//	**user 层计数**聚合：super 视角 = 全站用户合计，app-admin 视角 = 授权项目
//	用户集合计；global 行是跨项目数据，app-admin 视角为 null（收权隐藏）；
//	defaultsUsed = 四档限额里还在走默认值的档数（0 = 全部显式配置过）。
type AIUsageOverview struct {
	Today        int               `json:"today"`
	Yesterday    int               `json:"yesterday"`
	ActiveToday  int               `json:"activeToday"`
	Global       *AIUsageGlobal    `json:"global"`
	DefaultsUsed int               `json:"defaultsUsed"`
	Days         []AIUsageDayTotal `json:"days"`
	Users        []AIUsageUserRow  `json:"users"`
}

// AIUsageUserDetail 是 GET /admin/ai-usage?days=N&uid=X 的钻取回执。
type AIUsageUserDetail struct {
	UID        int64             `json:"uid"`
	Email      string            `json:"email"`
	Today      int               `json:"today"`
	Days       []AIUsageDayTotal `json:"days"`
	LimitToday int               `json:"limitToday"`
}

// ---- 用户查询 ----

// AdminSearchUsers 按邮箱片段或精确 uid 搜用户，倒序分页。
// query 为空 = 列全部（后台首页的默认形态）。
func (s *Service) AdminSearchUsers(query string, limit, offset int) ([]AdminUser, int, error) {
	limit, offset = clampPage(limit, offset)
	const cols = "SELECT id, email, role, created_at FROM users"
	var (
		args []any
		cond string
	)
	if q := strings.TrimSpace(query); q != "" {
		// 纯数字（**全串校验**）按 uid 精确匹配（uid 是对外可见的标识），其余按
		// 邮箱片段 LIKE。fmt.Sscan 会把 "123abc" 按前缀解成 123——带字母的片段
		// 因此错走 uid 精确路、查无此行；strconv.ParseInt 全串不合格即回落 LIKE。
		// 片段里统配符转义交给 MySQL 的默认行为——查询来自管理员自己的输入，
		// 不构成注入面（参数全部占位符）。
		if _, err := strconv.ParseInt(q, 10, 64); err == nil {
			cond = " WHERE id = ?"
			args = append(args, q)
		} else {
			cond = " WHERE email LIKE ?"
			args = append(args, "%"+q+"%")
		}
	}
	var total int
	if err := s.pool.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM users"+cond, args...).
		Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("数用户: %w", err)
	}
	listArgs := append(append([]any{}, args...), limit, offset)
	rows, err := s.pool.QueryContext(context.Background(),
		cols+cond+" ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?", listArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("查用户: %w", err)
	}
	defer func() { _ = rows.Close() }()

	base := make([]AdminUser, 0, limit)
	for rows.Next() {
		var u AdminUser
		if err := rows.Scan(&u.UID, &u.Email, &u.Role, &u.CreatedAt); err != nil {
			return nil, 0, fmt.Errorf("读用户行: %w", err)
		}
		base = append(base, u)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("遍历用户: %w", err)
	}
	if err := s.fillUserSummaries(base); err != nil {
		return nil, 0, err
	}
	return base, total, nil
}

// fillUserSummaries 给一批用户补 TOTP / passkey / 应用授权摘要。全部按 uid IN
// 批量查，避免「每行两次查询」把列表页打成 N+1。
func (s *Service) fillUserSummaries(users []AdminUser) error {
	if len(users) == 0 {
		return nil
	}
	ids := make([]any, 0, len(users))
	placeholders := make([]string, 0, len(users))
	for _, u := range users {
		ids = append(ids, u.UID)
		placeholders = append(placeholders, "?")
	}
	rows, err := s.pool.QueryContext(context.Background(),
		"SELECT user_id, COUNT(*) FROM totp_factors WHERE enabled = 1 AND user_id IN ("+strings.Join(placeholders, ",")+") GROUP BY user_id",
		ids...)
	if err != nil {
		return fmt.Errorf("查两步验证: %w", err)
	}
	defer func() { _ = rows.Close() }()
	enabled := map[int64]bool{}
	for rows.Next() {
		var uid int64
		var n int
		if err := rows.Scan(&uid, &n); err != nil {
			return fmt.Errorf("读两步验证: %w", err)
		}
		enabled[uid] = n > 0
	}
	if err := rows.Err(); err != nil {
		return err
	}

	rows2, err := s.pool.QueryContext(context.Background(),
		"SELECT user_id, COUNT(*) FROM passkeys WHERE rp_id = ? AND user_id IN ("+strings.Join(placeholders, ",")+") GROUP BY user_id",
		append([]any{passkeyRPID}, ids...)...)
	if err != nil {
		return fmt.Errorf("查 passkey: %w", err)
	}
	defer func() { _ = rows2.Close() }()
	counts := map[int64]int{}
	for rows2.Next() {
		var uid int64
		var n int
		if err := rows2.Scan(&uid, &n); err != nil {
			return fmt.Errorf("读 passkey: %w", err)
		}
		counts[uid] = n
	}
	if err := rows2.Err(); err != nil {
		return err
	}
	for i := range users {
		users[i].TotpEnabled = enabled[users[i].UID]
		users[i].PasskeyCount = counts[users[i].UID]
	}

	rows3, err := s.pool.QueryContext(context.Background(),
		"SELECT uid, COUNT(*) FROM admin_scopes WHERE uid IN ("+strings.Join(placeholders, ",")+") GROUP BY uid",
		ids...)
	if err != nil {
		return fmt.Errorf("查应用授权数: %w", err)
	}
	defer func() { _ = rows3.Close() }()
	scopeCounts := map[int64]int{}
	for rows3.Next() {
		var uid int64
		var n int
		if err := rows3.Scan(&uid, &n); err != nil {
			return fmt.Errorf("读应用授权数: %w", err)
		}
		scopeCounts[uid] = n
	}
	if err := rows3.Err(); err != nil {
		return err
	}
	for i := range users {
		users[i].ScopeCount = scopeCounts[users[i].UID]
	}
	return nil
}

// AdminUserDetail 取单个用户的详情：身份 + 凭证摘要 + 应用授权 + 活跃会话 + passkey
// 列表。查无此 uid 回 404（与「不存在」同形，不区分）。
func (s *Service) AdminUserDetail(uid int64) (*AdminUserDetail, error) {
	var (
		u        AdminUser
		password sql.NullString
	)
	err := s.pool.QueryRowContext(context.Background(),
		"SELECT id, email, role, created_at, password_hash FROM users WHERE id = ?", uid).
		Scan(&u.UID, &u.Email, &u.Role, &u.CreatedAt, &password)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, &HTTPError{404, "该用户不存在，请刷新用户列表后重试"}
	}
	if err != nil {
		return nil, fmt.Errorf("查用户: %w", err)
	}
	batch := []AdminUser{u}
	if err := s.fillUserSummaries(batch); err != nil {
		return nil, err
	}
	detail := &AdminUserDetail{AdminUser: batch[0], HasPassword: password.Valid && strings.TrimSpace(password.String) != ""}

	// 应用授权清单（app slug 数组）：与列表页的 scopeCount 同源，详情页给全量
	scopes, err := s.AdminScopes(uid)
	if err != nil {
		return nil, err
	}
	detail.Scopes = scopes

	// 用户详情是 super 的全量视角（详情页含跨 app 的会话与凭证），不传 app 过滤
	sessions, _, _, err := s.AdminListSessions(uid, nil, "", adminMaxPage, 0)
	if err != nil {
		return nil, err
	}
	detail.Sessions = make([]protocol.SessionInfo, 0, len(sessions))
	for _, it := range sessions {
		detail.Sessions = append(detail.Sessions, protocol.SessionInfo{
			ID: it.ID, App: it.App, Device: it.Device, IP: it.IP,
			CreatedAt: it.CreatedAt, LastSeenAt: it.LastSeenAt,
			Current: false, // 后台视角没有「本机」概念
		})
	}
	passkeys, err := s.ListPasskeys(uid, 0)
	if err != nil {
		return nil, err
	}
	detail.Passkeys = passkeys
	return detail, nil
}

// AdminSetRole 是**唯一**的角色调整入口（POST /admin/users/{uid}/role，本批把
// PATCH /admin/users/{uid} 与 POST /admin/roles/{uid}/role 两个旧端点合并到这里）：
// role 取 user | admin | super 三值。授权规则 = W2 的「只能授予低于自己」再加根 su 收口：
//
//	只有根 su（RootSuperEmail，钉死邮箱）能把任何人设为 / 取消 super；
//	其余 su 只能设 user | admin；
//	app-admin（role=admin）无任何角色修改权——路由层 requireSuper 挡在业务之前。
//
// 既有守卫全部保留：① 不能改自己的角色（一次误操作就可能把所有人锁在门外）；
// ② 降级最后一个 super 拒绝（库里一个 super 都不剩，授予/回收/配置从此无人能做）；
// ③ 目标不存在 404；④ 已是目标角色则幂等返回、不写库。降回 user 时清掉
// admin_scopes 行，防止残留授权在下次提权时意外复活。
//
// 审计沿用两个现状事件名：涉及 super 的调整（设为或取消 super）落
// admin.role.change，其余落 admin.user.role_change——审计下拉与既有取证口径不变。
func (s *Service) AdminSetRole(actor Caller, targetUID int64, role string) (err error) {
	action := AuditAdminRole
	defer func() {
		s.Audit(AuditEvent{
			Action: action, OK: err == nil, ActorUID: uidPtr(actor.UID),
			ActorEmail: maskEmail(actor.Email), TargetUID: uidPtr(targetUID), Meta: actor.Meta,
			Detail: map[string]string{"role": role},
		})
	}()
	if role != adminRoleUser && role != adminRoleAdmin && role != adminRoleSuper {
		return badRequest("角色只能是 user、admin 或 super，请重新选择后重试")
	}
	if targetUID == actor.UID {
		return badRequest("不能修改自己的角色，请让另一位平台管理员操作")
	}
	var current string
	scanErr := s.pool.QueryRowContext(context.Background(),
		"SELECT role FROM users WHERE id = ?", targetUID).Scan(&current)
	if errors.Is(scanErr, sql.ErrNoRows) {
		return &HTTPError{404, "该用户不存在，请刷新用户列表后重试"}
	}
	if scanErr != nil {
		return fmt.Errorf("查目标用户: %w", scanErr)
	}
	// super 的授予与回收收进根 su：涉 super 的调整（无论升降）非根 su 一律 403，
	// 且审计落到 admin.role.change 这个「平台角色调整」事件上
	if role == adminRoleSuper || IsSuperRole(current) {
		action = AuditRoleChange
		if !isRootSuper(actor) {
			return &HTTPError{403, "只有根管理员可以授予或取消 super 角色"}
		}
	}
	if current == role {
		return nil // 幂等：已是目标角色，不写不报错
	}
	if IsSuperRole(current) && role != adminRoleSuper {
		var supers int
		if err := s.pool.QueryRowContext(context.Background(),
			"SELECT COUNT(*) FROM users WHERE role = ?", adminRoleSuper).Scan(&supers); err != nil {
			return fmt.Errorf("数平台管理员: %w", err)
		}
		if supers <= 1 {
			return badRequest("不能降级最后一个平台管理员，之后将无人能管理本服务")
		}
	}
	if _, err := s.pool.ExecContext(context.Background(),
		"UPDATE users SET role = ? WHERE id = ?", role, targetUID); err != nil {
		return fmt.Errorf("改角色: %w", err)
	}
	if role == adminRoleUser {
		// 降回普通用户即清授权行：残留行会在下次提权时把旧 app 权限意外带回来
		if _, err := s.pool.ExecContext(context.Background(),
			"DELETE FROM admin_scopes WHERE uid = ?", targetUID); err != nil {
			return fmt.Errorf("清应用授权: %w", err)
		}
	}
	return nil
}

// isRootSuper 判定操作者是不是根 su：比对当前邮箱（大小写归一）。管理端点只收
// cookie 会话，邮箱每次请求从 users 表现查——不存在「JWT 里的旧邮箱」误判的窗口。
func isRootSuper(actor Caller) bool {
	return strings.EqualFold(strings.TrimSpace(actor.Email), RootSuperEmail)
}

// ---- 会话总览 ----

// AdminListSessions 列活跃会话；uid > 0 时只看该用户；apps 非空时只回这些
// app 的行（app-admin 的数据边界——sessions.app 列天然承载归属，过滤成本一次
// 条件而已），空 = 不限（super 的全量视图）。
//
// query 是搜索框的**服务端**口径（A4#3）：纯数字按 uid 精确匹配，其余按邮箱片段
// LIKE，与 AdminSearchUsers 同一套分流——在前端拿到的本页数据上本地过滤会漏掉
// 本页之外的用户。total 是同条件下的会话条数（分页按会话 offset 走），totalUsers
// 是同条件下去重后的用户数（会话总览的表格一行一位用户，页码文案按用户数说）。
func (s *Service) AdminListSessions(uid int64, apps []string, query string, limit, offset int) ([]AdminSession, int, int, error) {
	limit, offset = clampPage(limit, offset)
	cond := " WHERE s.revoked_at IS NULL"
	args := []any{}
	if uid > 0 {
		cond += " AND s.user_id = ?"
		args = append(args, uid)
	}
	if len(apps) > 0 {
		cond += " AND s.app IN (" + placeholders(len(apps)) + ")"
		for _, a := range apps {
			args = append(args, a)
		}
	}
	if q := strings.TrimSpace(query); q != "" {
		// 与 AdminSearchUsers 同款全串校验：带字母的片段回落邮箱 LIKE，
		// 不被 Sscan 按前缀解成 uid（"123abc" 不该命中 uid=123）
		if _, err := strconv.ParseInt(q, 10, 64); err == nil {
			cond += " AND s.user_id = ?"
			args = append(args, q)
		} else {
			cond += " AND u.email LIKE ?"
			args = append(args, "%"+q+"%")
		}
	}
	// count 与 list 必须吃同一个 from：query 的邮箱条件在 users 侧，少了 join 数不对
	from := " FROM sessions s JOIN users u ON u.id = s.user_id" + cond
	var total, totalUsers int
	if err := s.pool.QueryRowContext(context.Background(),
		"SELECT COUNT(*)"+from, args...).Scan(&total); err != nil {
		return nil, 0, 0, fmt.Errorf("数会话: %w", err)
	}
	if err := s.pool.QueryRowContext(context.Background(),
		"SELECT COUNT(DISTINCT s.user_id)"+from, args...).Scan(&totalUsers); err != nil {
		return nil, 0, 0, fmt.Errorf("数会话用户: %w", err)
	}
	listArgs := append(append([]any{}, args...), limit, offset)
	rows, err := s.pool.QueryContext(context.Background(),
		"SELECT s.id, s.user_id, u.email, s.app, s.device, s.ip, s.created_at, s.last_seen_at"+
			from+" ORDER BY s.last_seen_at DESC, s.id DESC LIMIT ? OFFSET ?", listArgs...)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("查会话: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := make([]AdminSession, 0, limit)
	for rows.Next() {
		var it AdminSession
		var id int64
		if err := rows.Scan(&id, &it.UID, &it.Email, &it.App, &it.Device, &it.IP,
			&it.CreatedAt, &it.LastSeenAt); err != nil {
			return nil, 0, 0, fmt.Errorf("读会话行: %w", err)
		}
		it.ID = strconv.FormatInt(id, 10)
		out = append(out, it)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, 0, fmt.Errorf("遍历会话: %w", err)
	}
	return out, total, totalUsers, nil
}

// AdminRevokeSession 吊销**任意**会话（幂等：不存在的 id 也回成功——管理员点两下
// 不该看到 404）。owner 只为了审计里能带 target_uid。
//
// apps 非空时是 app-admin 的收权边界：目标会话的 app 不在授权清单内一律 403
//（不能踢别的 app 的会话）；空 = 不限（super）。越界尝试照记审计（fail）。
func (s *Service) AdminRevokeSession(actor Caller, sid int64, apps []string) (err error) {
	var owner sql.NullInt64
	var sessApp string
	appErr := s.pool.QueryRowContext(context.Background(),
		"SELECT user_id, app FROM sessions WHERE id = ?", sid).Scan(&owner, &sessApp)
	defer func() {
		s.Audit(AuditEvent{
			Action: AuditAdminSession, OK: err == nil, ActorUID: uidPtr(actor.UID),
			ActorEmail: maskEmail(actor.Email), TargetUID: uidPtr(owner.Int64), Meta: actor.Meta,
			Detail: map[string]string{"session": fmt.Sprint(sid)},
		})
	}()
	// 查无此行（含 appErr=ErrNoRows）维持幂等成功语义：不存在的会话没有可越界的
	// app，下面的 UPDATE 也是 0 行命中
	if appErr == nil && len(apps) > 0 && !containsStr(apps, sessApp) {
		err = &HTTPError{403, "没有该项目的管理权限，请联系平台管理员开通"}
		return err
	}
	if _, err = s.pool.ExecContext(context.Background(),
		"UPDATE sessions SET revoked_at = ? WHERE id = ?", time.Now().UnixMilli(), sid); err != nil {
		return fmt.Errorf("吊销会话: %w", err)
	}
	return nil
}

// AdminRevokeUserSessions 吊销某个用户的全部会话（ASVS 7.4.5：出事就把人踢干净）。
// 只动会话层：每个 token 都带 sid，行被吊销即当场失效，不必碰 token_version。
func (s *Service) AdminRevokeUserSessions(actor Caller, targetUID int64) (err error) {
	defer func() {
		s.Audit(AuditEvent{
			Action: AuditAdminUserKick, OK: err == nil, ActorUID: uidPtr(actor.UID),
			ActorEmail: maskEmail(actor.Email), TargetUID: uidPtr(targetUID), Meta: actor.Meta,
		})
	}()
	if err = revokeUserSessions(context.Background(), s.pool, targetUID, 0, nil); err != nil {
		return err
	}
	return nil
}

// ---- 配置中心 ----

// adminConfigPrefixes 是配置中心的白名单前缀（规格 A2.5 逐字）。
// 非白名单键一律 404：后台不该变成「能改库里任意键」的口子。
// fcm* 前缀已随 FCM 凭据退出分发端点一并移除（见 cmd/server/config.go 头注释）：
// 库里的 fcm_* 旧键不再出现在配置中心，也不可再编辑。
var adminConfigPrefixes = []string{"mail_", "hook_", "llm_", "ai_"}

// isSecretConfigKey 判定「只显示末 4 位」的键：名字里带凭据语义的一律算。
// 判不出来宁可当 secret（多遮一次不亏，漏遮一次是泄密）。
func isSecretConfigKey(key string) bool {
	lower := strings.ToLower(key)
	for _, marker := range []string{"secret", "token", "password", "_key", "apikey", "credential"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func allowedConfigKey(key string) bool {
	for _, prefix := range adminConfigPrefixes {
		if strings.HasPrefix(key, prefix) {
			return true
		}
	}
	return false
}

// AdminListConfig 列白名单配置：读**库里现值**（不走 config.Store 的 10 秒缓存，
// 否则刚写的值读回旧的，管理员会以为没保存）。
func (s *Service) AdminListConfig() ([]ConfigItem, error) {
	rows, err := s.pool.QueryContext(context.Background(),
		"SELECT `key`, `value` FROM app_config ORDER BY `key`")
	if err != nil {
		return nil, fmt.Errorf("查配置: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := make([]ConfigItem, 0, 32)
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			return nil, fmt.Errorf("读配置行: %w", err)
		}
		if !allowedConfigKey(key) {
			continue
		}
		item := ConfigItem{Key: key, Secret: isSecretConfigKey(key), Configured: strings.TrimSpace(value) != ""}
		if item.Secret {
			// 只回末 4 位：够管理员辨认「配的是哪把钥匙」，凑不出原值
			trimmed := strings.TrimSpace(value)
			if len(trimmed) >= 4 {
				item.Hint = trimmed[len(trimmed)-4:]
			}
		} else if item.Configured {
			item.Value = value
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("遍历配置: %w", err)
	}
	return out, nil
}

// adminMaxConfigKeyLen 是配置键的长度上限：app_config.key 是 VARCHAR(64)，
// 超长会被 MySQL 截断落库（写进去的键与请求的键不是同一个），在入口就拒。
const adminMaxConfigKeyLen = 64

// configKeyCharset 限定配置键字符集：字母数字与下划线。键会出现在日志、审计
// detail 与后台页面里，放开点/横线/空白/非 ASCII 只会养出一堆「看着像注入面」
// 的脏键（现有键 mail_*/hook_*/llm_*/ai_* 全部合规）。
var configKeyCharset = regexp.MustCompile(`^[A-Za-z0-9_]+$`)

// aiUsageMergedAtKey 是合并标记键：由一次性 AI 用量合并迁移写入（迁移已完成，
// 脚本已移除），**是防全站 AI 计数翻倍的唯一护栏**（见仓 AGENTS）。配置中心对它只读。
const aiUsageMergedAtKey = "ai_usage_merged_at"

// AdminSetConfig 写一个白名单键：空串 = 删键（「清空提交=不改、单独清除按钮」
// 是前端约定，服务端只认「value 为空即清除」这一条）。审计只记 key 与旧值是否
// 已配置——**值本身永远不进审计表**。
//
// 三道写入闸（m6/m7）：① key ≤64 字符且只含 [A-Za-z0-9_]；② ai_* 键的值必须是
// 正整数（四档限额按非正整数解析会静默回默认值，写错的管理员会以为改生效了）；
// ③ ai_usage_merged_at 只读——删掉它再跑迁移脚本会把全站 AI 计数翻倍。
func (s *Service) AdminSetConfig(actor Caller, key, value string) (err error) {
	var before bool
	defer func() {
		s.Audit(AuditEvent{
			Action: AuditAdminConfig, OK: err == nil, ActorUID: uidPtr(actor.UID),
			ActorEmail: maskEmail(actor.Email), Meta: actor.Meta,
			Detail: map[string]string{
				"key":              key,
				"configuredBefore": boolWord(before),
			},
		})
	}()
	if len(key) == 0 || len(key) > adminMaxConfigKeyLen || !configKeyCharset.MatchString(key) {
		return badRequest(fmt.Sprintf("配置键格式不正确：仅限字母、数字、下划线，最长 %d 字符", adminMaxConfigKeyLen))
	}
	if key == aiUsageMergedAtKey {
		return badRequest("此键由迁移脚本写入，不可在后台编辑，请勿重复执行迁移脚本")
	}
	if !allowedConfigKey(key) {
		return &HTTPError{404, "该配置键不在可编辑范围内，请确认键名后重试"}
	}
	if len(value) > adminMaxConfigValue {
		return badRequest(fmt.Sprintf("配置值过长（最多 %d 字节），请精简后重试", adminMaxConfigValue))
	}
	if strings.HasPrefix(key, "ai_") && strings.TrimSpace(value) != "" {
		if _, err := parseIntConfig(value); err != nil {
			return badRequest("AI 限额配置值必须是正整数，请修改后重试")
		}
	}
	// 先读旧态（给审计用），失败不挡写入
	var old string
	if err := s.pool.QueryRowContext(context.Background(),
		"SELECT `value` FROM app_config WHERE `key` = ?", key).Scan(&old); err == nil {
		before = strings.TrimSpace(old) != ""
	}

	ctx := context.Background()
	if strings.TrimSpace(value) == "" {
		if _, err = s.pool.ExecContext(ctx, "DELETE FROM app_config WHERE `key` = ?", key); err != nil {
			return fmt.Errorf("清除配置: %w", err)
		}
		return nil
	}
	// 非 secret 键不允许写进「看起来像凭据」的值…… 不做这条：同一个键在不同
	// 部署里含义不同，服务端只管遮蔽与白名单，语义判断留给管理员自己。
	if _, err = s.pool.ExecContext(ctx,
		"INSERT INTO app_config (`key`, `value`) VALUES (?,?) ON DUPLICATE KEY UPDATE `value` = VALUES(`value`)",
		key, value); err != nil {
		return fmt.Errorf("写配置: %w", err)
	}
	return nil
}

// ---- AI 用量看板 ----

// aiQuotaKeys 是四档限额的配置键与默认值（与 calorie 侧 quota.go 逐字一致——
// 迁入 auth 后零改表零改名）。
var aiQuotaKeys = []struct {
	key string
	def int
}{
	{"ai_rate_per_minute", 20},
	{"ai_concurrency", 8},
	{"ai_daily_per_user", 500},
	{"ai_daily_global", 5000},
}

// clampAIDays 把看板的窗口天数收进合法区间：默认 30 天，上限 90（更大的窗口
// 也只是全表扫，给前端一个能预期的量）。
func clampAIDays(days int) int {
	if days <= 0 {
		return 30
	}
	if days > 90 {
		return 90
	}
	return days
}

// aiUsageDayTotals 把按天的 map 铺成**升序、补零**的整窗序列。
func aiUsageDayTotals(days int, now time.Time, perDay map[string]int) []AIUsageDayTotal {
	out := make([]AIUsageDayTotal, 0, days)
	for i := days - 1; i >= 0; i-- {
		date := now.AddDate(0, 0, -i).Format("2006-01-02")
		out = append(out, AIUsageDayTotal{Date: date, Count: perDay[date]})
	}
	return out
}

// aiLimitValues 是四档限额的现值与「走默认值的档数」：任一键缺失或写成非正整数
// 都按默认计一档——看板要能一眼看出「限额还有几档没配」。
type aiLimitValues struct {
	dailyPerUser int
	dailyGlobal  int
	defaultsUsed int
}

func (s *Service) aiLimitValues() (aiLimitValues, error) {
	out := aiLimitValues{}
	values := map[string]string{}
	rows, err := s.pool.QueryContext(context.Background(),
		"SELECT `key`, `value` FROM app_config WHERE `key` IN (?,?,?,?)",
		aiQuotaKeys[0].key, aiQuotaKeys[1].key, aiQuotaKeys[2].key, aiQuotaKeys[3].key)
	if err != nil {
		return out, fmt.Errorf("查限额配置: %w", err)
	}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			_ = rows.Close()
			return out, fmt.Errorf("读限额配置: %w", err)
		}
		values[k] = v
	}
	_ = rows.Close()
	if err := rows.Err(); err != nil {
		return out, fmt.Errorf("遍历限额配置: %w", err)
	}
	for _, k := range aiQuotaKeys {
		raw, ok := values[k.key]
		v := k.def
		if !ok || strings.TrimSpace(raw) == "" {
			out.defaultsUsed++
		} else if parsed, err := parseIntConfig(raw); err == nil && parsed > 0 {
			v = parsed
		} else {
			// 配置写了个非数字：按默认计，这一档也算「没配」
			out.defaultsUsed++
		}
		switch k.key {
		case "ai_daily_per_user":
			out.dailyPerUser = v
		case "ai_daily_global":
			out.dailyGlobal = v
		}
	}
	return out, nil
}

// AdminAIUsage 聚合近 N 天的 AI 用量（GET /admin/ai-usage?days=N），口径见
// AIUsageOverview 的注释。表里没用量时回补零的整窗 days 与空 users——不做任何造数。
//
// apps 非空 = app-admin 视角。ai_usage **没有 app 维度**（列只有
// scope/subject/day/count，见 schema.sql），诚实可行的过滤口径是「subject 归属
// 该 app 的用户」：subject（uid 十进制串）∈ 在该 app 有会话行的用户集合。两点
// 如实声明：① sessions 行在注销后即删、死会话保留 30 天（cleanup.go），新近
// 才流失的用户可能短暂落出视图——现状数据结构下没有更准的归属源；②
// scope='global' 的行是全站跨 app 合计，属跨项目数据，对 app-admin 一律隐藏。
// 限额是全站配置，两档视角都显示（app-admin 的「限额视图」是需求明列的）。
func (s *Service) AdminAIUsage(days int, apps []string) (*AIUsageOverview, error) {
	days = clampAIDays(days)
	now := time.Now()
	today := now.Format("2006-01-02")
	yesterday := now.AddDate(0, 0, -1).Format("2006-01-02")
	since := now.AddDate(0, 0, -(days - 1)).Format("2006-01-02")

	cond := ""
	args := []any{since}
	if len(apps) > 0 {
		cond = " AND CAST(a.subject AS UNSIGNED) IN" +
			" (SELECT user_id FROM sessions WHERE app IN (" + placeholders(len(apps)) + "))"
		for _, a := range apps {
			args = append(args, a)
		}
	}
	rows, err := s.pool.QueryContext(context.Background(),
		"SELECT a.day, a.subject, a.`count`, u.email FROM ai_usage a"+
			" LEFT JOIN users u ON u.id = CAST(a.subject AS UNSIGNED)"+
			" WHERE a.scope = 'user' AND a.day >= ?"+cond+" ORDER BY a.day ASC", args...)
	if err != nil {
		return nil, fmt.Errorf("查用量: %w", err)
	}
	defer func() { _ = rows.Close() }()

	perDay := map[string]int{}
	perUser := map[int64]*AIUsageUserRow{}
	for rows.Next() {
		var day, subject string
		var count int
		var email sql.NullString
		if err := rows.Scan(&day, &subject, &count, &email); err != nil {
			return nil, fmt.Errorf("读用量行: %w", err)
		}
		uid, convErr := strconv.ParseInt(subject, 10, 64)
		if convErr != nil {
			continue // subject 不是 uid 的脏行不进 per-user（也不该存在）
		}
		perDay[day] += count
		row := perUser[uid]
		if row == nil {
			row = &AIUsageUserRow{UID: uid, Email: email.String}
			perUser[uid] = row
		}
		row.Range += count
		if day == today {
			row.Today += count
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("遍历用量: %w", err)
	}

	limits, err := s.aiLimitValues()
	if err != nil {
		return nil, err
	}
	overview := &AIUsageOverview{
		Today:        perDay[today],
		Yesterday:    perDay[yesterday],
		DefaultsUsed: limits.defaultsUsed,
		Days:         aiUsageDayTotals(days, now, perDay),
		Users:        make([]AIUsageUserRow, 0, len(perUser)),
	}
	totalRange := 0
	for _, u := range perUser {
		totalRange += u.Range
		if u.Today > 0 {
			overview.ActiveToday++
		}
	}
	for _, u := range perUser {
		if totalRange > 0 {
			// share = 该用户区间用量 / 全部用户区间用量之和，留 4 位小数够排展示
			u.Share = math.Round(float64(u.Range)/float64(totalRange)*10000) / 10000
		}
		u.LimitToday = limits.dailyPerUser
		overview.Users = append(overview.Users, *u)
	}
	// users 按区间用量降序（同量再按今日、uid 定序，保证翻页/刷新稳定）
	sort.Slice(overview.Users, func(i, j int) bool {
		a, b := overview.Users[i], overview.Users[j]
		if a.Range != b.Range {
			return a.Range > b.Range
		}
		if a.Today != b.Today {
			return a.Today > b.Today
		}
		return a.UID < b.UID
	})

	// 全站行：限额闸比对的就是它；app-admin 视角藏起来（跨项目数据）
	if len(apps) == 0 {
		var used int
		if err := s.pool.QueryRowContext(context.Background(),
			"SELECT `count` FROM ai_usage WHERE scope = 'global' AND subject = '' AND day = ?",
			today).Scan(&used); err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("查全站当日用量: %w", err)
		}
		overview.Global = &AIUsageGlobal{Used: used, Limit: limits.dailyGlobal}
	}
	return overview, nil
}

// AdminAIUsageUser 钻取单个用户近 N 天的用量（GET /admin/ai-usage?days=N&uid=X）。
// apps 非空 = app-admin 视角：目标用户必须在授权项目的用户集内，否则与「查无此人」
// 同回 404——不给「这个 uid 存不存在 / 是谁的人」的存在性探针。
func (s *Service) AdminAIUsageUser(days int, apps []string, uid int64) (*AIUsageUserDetail, error) {
	days = clampAIDays(days)
	now := time.Now()
	today := now.Format("2006-01-02")

	// 身份 + 可见性一次问清：LEFT JOIN 顺带回邮箱，行缺失 = 不存在 / 不在范围内
	cond := ""
	args := []any{uid}
	if len(apps) > 0 {
		cond = " AND EXISTS (SELECT 1 FROM sessions s WHERE s.user_id = u.id AND s.app IN (" + placeholders(len(apps)) + "))"
		for _, a := range apps {
			args = append(args, a)
		}
	}
	var email sql.NullString
	err := s.pool.QueryRowContext(context.Background(),
		"SELECT u.email FROM users u WHERE u.id = ?"+cond, args...).Scan(&email)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, &HTTPError{404, "该用户不存在，请刷新用户列表后重试"}
	}
	if err != nil {
		return nil, fmt.Errorf("查用户: %w", err)
	}

	rows, err := s.pool.QueryContext(context.Background(),
		"SELECT day, `count` FROM ai_usage WHERE scope = 'user' AND subject = ? AND day >= ? ORDER BY day ASC",
		strconv.FormatInt(uid, 10), now.AddDate(0, 0, -(days-1)).Format("2006-01-02"))
	if err != nil {
		return nil, fmt.Errorf("查用户用量: %w", err)
	}
	defer func() { _ = rows.Close() }()
	perDay := map[string]int{}
	for rows.Next() {
		var day string
		var count int
		if err := rows.Scan(&day, &count); err != nil {
			return nil, fmt.Errorf("读用户用量行: %w", err)
		}
		perDay[day] += count
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("遍历用户用量: %w", err)
	}

	limits, err := s.aiLimitValues()
	if err != nil {
		return nil, err
	}
	return &AIUsageUserDetail{
		UID:        uid,
		Email:      email.String,
		Today:      perDay[today],
		Days:       aiUsageDayTotals(days, now, perDay),
		LimitToday: limits.dailyPerUser,
	}, nil
}

// HasPassword 回账号是否设过密码（overview 页与后台详情共用一句判定：
// NULL 与空串都算「没密码」，那正是纯验证码并入账号的形态）。
func (s *Service) HasPassword(uid int64) (bool, error) {
	var pw sql.NullString
	err := s.pool.QueryRowContext(context.Background(),
		"SELECT password_hash FROM users WHERE id = ?", uid).Scan(&pw)
	if errors.Is(err, sql.ErrNoRows) {
		return false, unauthorized("登录已过期，请重新登录")
	}
	if err != nil {
		return false, fmt.Errorf("查密码状态: %w", err)
	}
	return pw.Valid && strings.TrimSpace(pw.String) != "", nil
}

// HasMFA 是管理后台「强制 MFA」的判定：绑了 TOTP 或至少一把 passkey。
func (s *Service) HasMFA(uid int64) (bool, error) {
	var totp, passkeys int
	if err := s.pool.QueryRowContext(context.Background(),
		"SELECT (SELECT COUNT(*) FROM totp_factors WHERE user_id = ? AND enabled = 1),"+
			"(SELECT COUNT(*) FROM passkeys WHERE user_id = ? AND rp_id = ?)",
		uid, uid, passkeyRPID).Scan(&totp, &passkeys); err != nil {
		return false, fmt.Errorf("查 MFA 状态: %w", err)
	}
	return totp > 0 || passkeys > 0, nil
}

// clampPage 把分页参数收到合法区间：页大小 1..adminMaxPage（默认 20），
// offset 不为负、上限挡住「无脑翻到底」。
func clampPage(limit, offset int) (int, int) {
	if limit <= 0 {
		limit = 20
	}
	if limit > adminMaxPage {
		limit = adminMaxPage
	}
	if offset < 0 || offset > AuditOffsetCap {
		offset = 0
	}
	return limit, offset
}

// parseIntConfig 解数字型配置（限额用），非正整数视为解析失败。
// strconv.ParseInt 全串校验——fmt.Sscan 会把 "12abc"、"1.5" 这类脏值按前缀
// 解成 12 / 1 放行，写错的配置就静默生效了。
func parseIntConfig(raw string) (int, error) {
	n, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if err != nil || n <= 0 || n > int64(math.MaxInt32) {
		return 0, fmt.Errorf("非正整数")
	}
	return int(n), nil
}

// boolWord 把布尔转成审计 detail 里的 "true"/"false"（detail 是 map[string]string，
// 混类型 map 会让序列化结果不可预期）。
func boolWord(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
