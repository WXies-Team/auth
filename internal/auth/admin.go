package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/WXies-Team/auth/internal/protocol"
)

// 管理后台的口径（规格 A2.5）：
//
//	授权判定在路由层（requireAdmin 每请求现查 + 强制 MFA + reauth 15 分钟窗），
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

// AdminUser 是后台用户列表/详情的一行。
type AdminUser struct {
	UID          int64  `json:"uid"`
	Email        string `json:"email"`
	Role         string `json:"role"`
	CreatedAt    int64  `json:"createdAt"`
	TotpEnabled  bool   `json:"totpEnabled"`
	PasskeyCount int    `json:"passkeyCount"`
}

// AdminUserDetail 是用户详情：加凭证摘要与活跃会话，够管理员判断「要不要踢、
// 该不该给权限」，不回任何口令散列。
type AdminUserDetail struct {
	AdminUser
	HasPassword bool                   `json:"hasPassword"`
	Sessions    []protocol.SessionInfo `json:"sessions"`
	Passkeys    []PasskeyInfo          `json:"passkeys"`
}

// AdminSession 是全站会话总览的一行（比用户自己的设备列表多出 uid/email）。
type AdminSession struct {
	ID         int64  `json:"id"`
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

// AIUsageSubject 是用量看板一天内的一个统计对象（uid 或 global）。
type AIUsageSubject struct {
	Subject string `json:"subject"`
	Count   int    `json:"count"`
}

// AIUsageDay 是一天的聚合（字段名对齐规格 A2.5：单日 Top10 记 byUserTop10）。
type AIUsageDay struct {
	Day       string           `json:"day"`
	Total     int              `json:"total"`
	ByUserTop []AIUsageSubject `json:"byUserTop10"`
}

// AIQuota 是四档限额的当前值与「是否来自配置」。
type AIQuota struct {
	PerMinute    int  `json:"perMinute"`
	Concurrency  int  `json:"concurrency"`
	DailyPerUser int  `json:"dailyPerUser"`
	DailyGlobal  int  `json:"dailyGlobal"`
	Configured   bool `json:"configured"`
}

// AIUsageReport 是看板回执：days 为空 = 表里还没有用量（页面回「暂无记录」）。
type AIUsageReport struct {
	Days  []AIUsageDay `json:"days"`
	Quota AIQuota      `json:"quota"`
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
		// 纯数字按 uid 精确匹配（uid 是对外可见的标识），其余按邮箱片段 LIKE。
		// 片段里统配符转义交给 MySQL 的默认行为——查询来自管理员自己的输入，
		// 不构成注入面（参数全部占位符）。
		if _, err := fmt.Sscan(q, new(int64)); err == nil {
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
	if err := s.fillUserFactors(base); err != nil {
		return nil, 0, err
	}
	return base, total, nil
}

// fillUserFactors 给一批用户补 TOTP/passkey 摘要。按 uid IN 批量查，避免
// 「每行两次查询」把列表页打成 N+1。
func (s *Service) fillUserFactors(users []AdminUser) error {
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
	return nil
}

// AdminUserDetail 取单个用户的详情：身份 + 凭证摘要 + 活跃会话 + passkey 列表。
// 查无此 uid 回 404（与「不存在」同形，不区分）。
func (s *Service) AdminUserDetail(uid int64) (*AdminUserDetail, error) {
	var (
		u        AdminUser
		password sql.NullString
	)
	err := s.pool.QueryRowContext(context.Background(),
		"SELECT id, email, role, created_at, password_hash FROM users WHERE id = ?", uid).
		Scan(&u.UID, &u.Email, &u.Role, &u.CreatedAt, &password)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, &HTTPError{404, "该用户不存在"}
	}
	if err != nil {
		return nil, fmt.Errorf("查用户: %w", err)
	}
	batch := []AdminUser{u}
	if err := s.fillUserFactors(batch); err != nil {
		return nil, err
	}
	detail := &AdminUserDetail{AdminUser: batch[0], HasPassword: password.Valid && strings.TrimSpace(password.String) != ""}

	sessions, _, err := s.AdminListSessions(uid, adminMaxPage, 0)
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

// AdminSetRole 改角色。
//
// 两条守卫：① 不能降级自己（否则一次误操作就把所有人都锁在门外）；
// ② 角色只认 user/admin 两值——库里多一个没实现过的值等于多一种未知权限。
func (s *Service) AdminSetRole(actor Caller, targetUID int64, role string) (err error) {
	defer func() {
		s.Audit(AuditEvent{
			Action: AuditAdminRole, OK: err == nil, ActorUID: uidPtr(actor.UID),
			ActorEmail: maskEmail(actor.Email), TargetUID: uidPtr(targetUID), Meta: actor.Meta,
			Detail: map[string]string{"role": role},
		})
	}()
	if role != adminRoleUser && role != adminRoleAdmin {
		return badRequest("角色只能是 user 或 admin")
	}
	if targetUID == actor.UID && role != adminRoleAdmin {
		return badRequest("不能取消自己的管理员身份")
	}
	var exists int
	if err := s.pool.QueryRowContext(context.Background(),
		"SELECT EXISTS(SELECT 1 FROM users WHERE id = ?)", targetUID).Scan(&exists); err != nil {
		return fmt.Errorf("查目标用户: %w", err)
	}
	if exists == 0 {
		return &HTTPError{404, "该用户不存在"}
	}
	if _, err := s.pool.ExecContext(context.Background(),
		"UPDATE users SET role = ? WHERE id = ?", role, targetUID); err != nil {
		return fmt.Errorf("改角色: %w", err)
	}
	return nil
}

// ---- 会话总览 ----

// AdminListSessions 列活跃会话；uid > 0 时只看该用户。
func (s *Service) AdminListSessions(uid int64, limit, offset int) ([]AdminSession, int, error) {
	limit, offset = clampPage(limit, offset)
	cond := " WHERE s.revoked_at IS NULL"
	args := []any{}
	if uid > 0 {
		cond += " AND s.user_id = ?"
		args = append(args, uid)
	}
	var total int
	if err := s.pool.QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM sessions s"+cond, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("数会话: %w", err)
	}
	listArgs := append(append([]any{}, args...), limit, offset)
	rows, err := s.pool.QueryContext(context.Background(),
		"SELECT s.id, s.user_id, u.email, s.app, s.device, s.ip, s.created_at, s.last_seen_at"+
			" FROM sessions s JOIN users u ON u.id = s.user_id"+cond+
			" ORDER BY s.last_seen_at DESC, s.id DESC LIMIT ? OFFSET ?", listArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("查会话: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := make([]AdminSession, 0, limit)
	for rows.Next() {
		var it AdminSession
		if err := rows.Scan(&it.ID, &it.UID, &it.Email, &it.App, &it.Device, &it.IP,
			&it.CreatedAt, &it.LastSeenAt); err != nil {
			return nil, 0, fmt.Errorf("读会话行: %w", err)
		}
		out = append(out, it)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("遍历会话: %w", err)
	}
	return out, total, nil
}

// AdminRevokeSession 吊销**任意**会话（幂等：不存在的 id 也回成功——管理员点两下
// 不该看到 404）。owner 只为了审计里能带 target_uid。
func (s *Service) AdminRevokeSession(actor Caller, sid int64) (err error) {
	var owner sql.NullInt64
	_ = s.pool.QueryRowContext(context.Background(), "SELECT user_id FROM sessions WHERE id = ?", sid).Scan(&owner)
	defer func() {
		s.Audit(AuditEvent{
			Action: AuditAdminSession, OK: err == nil, ActorUID: uidPtr(actor.UID),
			ActorEmail: maskEmail(actor.Email), TargetUID: uidPtr(owner.Int64), Meta: actor.Meta,
			Detail: map[string]string{"session": fmt.Sprint(sid)},
		})
	}()
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
	if err = revokeUserSessions(context.Background(), s.pool, targetUID, 0); err != nil {
		return err
	}
	return nil
}

// ---- 配置中心 ----

// adminConfigPrefixes 是配置中心的白名单前缀（规格 A2.5 逐字）。
// 非白名单键一律 404：后台不该变成「能改库里任意键」的口子。
var adminConfigPrefixes = []string{"mail_", "hook_", "llm_", "fcm", "ai_"}

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
// 的脏键（现有键 mail_*/hook_*/llm_*/fcm*/ai_* 全部合规）。
var configKeyCharset = regexp.MustCompile(`^[A-Za-z0-9_]+$`)

// aiUsageMergedAtKey 是合并标记键：由 scripts/migrate-ai-usage-to-auth.sh 写入，
// **是防全站 AI 计数翻倍的唯一护栏**（见仓 AGENTS）。配置中心对它只读。
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
		return badRequest("此键由迁移脚本写入，不可编辑")
	}
	if !allowedConfigKey(key) {
		return &HTTPError{404, "未知配置键"}
	}
	if len(value) > adminMaxConfigValue {
		return badRequest(fmt.Sprintf("配置值过长（最多 %d 字节）", adminMaxConfigValue))
	}
	if strings.HasPrefix(key, "ai_") && strings.TrimSpace(value) != "" {
		if _, err := parseIntConfig(value); err != nil {
			return badRequest("AI 限额配置值必须是正整数")
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

// AdminAIUsage 聚合近 N 天的 AI 用量与四档限额现值。
// 表为空回 days=[]（页面显示「暂无记录」）——不做任何造数。
func (s *Service) AdminAIUsage(days int) (*AIUsageReport, error) {
	if days <= 0 {
		days = 30
	}
	if days > 90 {
		days = 90
	}
	since := time.Now().AddDate(0, 0, -(days - 1)).Format("2006-01-02")
	rows, err := s.pool.QueryContext(context.Background(),
		"SELECT day, subject, count FROM ai_usage WHERE day >= ? ORDER BY day DESC, count DESC", since)
	if err != nil {
		return nil, fmt.Errorf("查用量: %w", err)
	}
	defer func() { _ = rows.Close() }()

	report := &AIUsageReport{Days: []AIUsageDay{}}
	index := map[string]int{}
	for rows.Next() {
		var day, subject string
		var count int
		if err := rows.Scan(&day, &subject, &count); err != nil {
			return nil, fmt.Errorf("读用量行: %w", err)
		}
		i, ok := index[day]
		if !ok {
			report.Days = append(report.Days, AIUsageDay{Day: day, ByUserTop: []AIUsageSubject{}})
			i = len(report.Days) - 1
			index[day] = i
		}
		report.Days[i].Total += count
		// 天内 Top10：查询已按 count 倒序，只管截断
		if len(report.Days[i].ByUserTop) < 10 {
			report.Days[i].ByUserTop = append(report.Days[i].ByUserTop, AIUsageSubject{Subject: subject, Count: count})
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("遍历用量: %w", err)
	}

	// 限额现值：任一键缺失即 configured=false（缺失的那几项按默认值展示）
	q := AIQuota{Configured: true}
	values := map[string]string{}
	rows2, err := s.pool.QueryContext(context.Background(),
		"SELECT `key`, `value` FROM app_config WHERE `key` IN (?,?,?,?)",
		aiQuotaKeys[0].key, aiQuotaKeys[1].key, aiQuotaKeys[2].key, aiQuotaKeys[3].key)
	if err != nil {
		return nil, fmt.Errorf("查限额配置: %w", err)
	}
	for rows2.Next() {
		var k, v string
		if err := rows2.Scan(&k, &v); err != nil {
			_ = rows2.Close()
			return nil, fmt.Errorf("读限额配置: %w", err)
		}
		values[k] = v
	}
	_ = rows2.Close()
	if err := rows2.Err(); err != nil {
		return nil, fmt.Errorf("遍历限额配置: %w", err)
	}
	for _, k := range aiQuotaKeys {
		raw, ok := values[k.key]
		v := k.def
		if !ok || strings.TrimSpace(raw) == "" {
			q.Configured = false
		} else if parsed, err := parseIntConfig(raw); err == nil && parsed > 0 {
			v = parsed
		} else {
			// 配置写了个非数字：按默认展示，但整组不算「已配置」
			q.Configured = false
		}
		switch k.key {
		case "ai_rate_per_minute":
			q.PerMinute = v
		case "ai_concurrency":
			q.Concurrency = v
		case "ai_daily_per_user":
			q.DailyPerUser = v
		case "ai_daily_global":
			q.DailyGlobal = v
		}
	}
	report.Quota = q
	return report, nil
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
