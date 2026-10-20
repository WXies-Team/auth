package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// W2 分级授权的口径（作者定稿 + 业界 scoped-RBAC 精简版）：
//
//	super    平台管理员：管所有 app/网页——角色授予、全局配置中心、注销用户、跨 app 全部数据；
//	app-admin 按 app 授权：只管**该 app 范围内**的数据（会话踢出 / AI 用量 / 相关审计），
//	           不能碰用户目录、角色、注销、全局配置、跨 app 数据。
//
//	有效 app-admin = role='admin' 且持有 ≥1 条 admin_scopes 行（无行 = 无权限，
//	页面只见空态说明）；role='super' 绕过 scope 全量通行。一人管多个项目 = 多行叠加。
//	授予规则按业界「只能授予低于自己」：只有 super 能授予/回收 app-admin 与 super，
//	app-admin 无任何授予权（新端点全部 super-only，路由层把闸）。
//	scope 解析每请求查库（每请求两行成本可接受，与「撤销当场生效」同款理由，
//	不做进程缓存——token_version 从不缓存的同一条规矩）。
const (
	// adminRoleSuper 是平台管理员（users.role 的第三个值；VARCHAR(16) 值域演进，
	// 无 DDL——列宽与类型不变，纯值域扩展）。
	adminRoleSuper = "super"
)

// IsAdminRole 判定「进得了管理后台」：admin 与 super 都算。
// 与 internal/ui 的 IsAdminRole 同口径（模板层放行的按钮，数据层一定挡得住），
// 两处值域由 TestIsAdminRole / ui 的 TestTopbarAccountAndAdminEntry 分别钉住。
func IsAdminRole(role string) bool { return role == adminRoleAdmin || role == adminRoleSuper }

// IsSuperRole 判定平台管理员（绕过 scope、可授予角色）。
func IsSuperRole(role string) bool { return role == adminRoleSuper }

// AdminScopes 查一个 uid 的 app 授权清单（app-admin 的数据过滤范围）。
// super 的调用方不该走到这里（路由层已按 role 分流）；查错上报、查无回空切片。
func (s *Service) AdminScopes(uid int64) ([]string, error) {
	rows, err := s.pool.QueryContext(context.Background(),
		"SELECT app FROM admin_scopes WHERE uid = ? ORDER BY app", uid)
	if err != nil {
		return nil, fmt.Errorf("查应用授权: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := make([]string, 0, 2)
	for rows.Next() {
		var app string
		if err := rows.Scan(&app); err != nil {
			return nil, fmt.Errorf("读授权行: %w", err)
		}
		out = append(out, app)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("遍历授权行: %w", err)
	}
	return out, nil
}

// AdminRoleUser 是角色管理页（GET /admin/roles）的一行：身份 + 角色 + 授权摘要。
type AdminRoleUser struct {
	UID    int64    `json:"uid"`
	Email  string   `json:"email"`
	Role   string   `json:"role"`
	Scopes []string `json:"scopes"`
}

// AdminListRoles 列用户与角色/授权摘要（检索口径与 AdminSearchUsers 一致：
// 空查询列全部、纯数字按 uid 精确、其余按邮箱片段）。scopes 按 uid IN 批量回填，
// 不做 N+1。
func (s *Service) AdminListRoles(query string, limit, offset int) ([]AdminRoleUser, int, error) {
	users, total, err := s.AdminSearchUsers(query, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	out := make([]AdminRoleUser, 0, len(users))
	for _, u := range users {
		out = append(out, AdminRoleUser{UID: u.UID, Email: u.Email, Role: u.Role, Scopes: []string{}})
	}
	if len(out) == 0 {
		return out, total, nil
	}
	ids := make([]any, 0, len(out))
	holders := make([]string, 0, len(out))
	for _, u := range out {
		ids = append(ids, u.UID)
		holders = append(holders, "?")
	}
	rows, err := s.pool.QueryContext(context.Background(),
		"SELECT uid, app FROM admin_scopes WHERE uid IN ("+strings.Join(holders, ",")+") ORDER BY app", ids...)
	if err != nil {
		return nil, 0, fmt.Errorf("查授权摘要: %w", err)
	}
	defer func() { _ = rows.Close() }()
	byUID := map[int64]int{}
	for i, u := range out {
		byUID[u.UID] = i
	}
	for rows.Next() {
		var uid int64
		var app string
		if err := rows.Scan(&uid, &app); err != nil {
			return nil, 0, fmt.Errorf("读授权摘要行: %w", err)
		}
		if i, ok := byUID[uid]; ok {
			out[i].Scopes = append(out[i].Scopes, app)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("遍历授权摘要: %w", err)
	}
	return out, total, nil
}

// AdminSetScope 授予（grant）或回收（revoke）一个 app-admin 的应用授权。
//
// 授予隐含把 role 提为 admin（scope 行是有效性的来源，role 是门槛——两者都要在位）；
// 回收到 0 行时把 role 降回 user：**定案是降**——role='admin' 零 scope 是无权限的
// 空壳，留着只会让角色目录里长期挂着「admin 但什么都不管」的误导态，降回 user
// 让角色与实际权限一致（重新授予时再自动提回来，无信息损失）。
// 目标是 super 时拒（super 绕过 scope 全量通行，授予无意义只会造出误导性摘要）。
func (s *Service) AdminSetScope(actor Caller, targetUID int64, app string, grant bool) (err error) {
	action := AuditRoleRevoke
	if grant {
		action = AuditRoleGrant
	}
	defer func() {
		s.Audit(AuditEvent{
			Action: action, OK: err == nil, ActorUID: uidPtr(actor.UID),
			ActorEmail: maskEmail(actor.Email), TargetUID: uidPtr(targetUID), Meta: actor.Meta,
			Detail: map[string]string{"app": app},
		})
	}()
	if !allowedApps[app] {
		return badRequest("未知应用")
	}
	var role string
	scanErr := s.pool.QueryRowContext(context.Background(),
		"SELECT role FROM users WHERE id = ?", targetUID).Scan(&role)
	if errors.Is(scanErr, sql.ErrNoRows) {
		return &HTTPError{404, "该用户不存在"}
	}
	if scanErr != nil {
		return fmt.Errorf("查目标用户: %w", scanErr)
	}
	if IsSuperRole(role) {
		return badRequest("平台管理员无需按应用授权")
	}

	tx, err := s.pool.BeginTx(context.Background(), nil)
	if err != nil {
		return fmt.Errorf("开事务: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if grant {
		if _, err := tx.ExecContext(context.Background(),
			"INSERT IGNORE INTO admin_scopes (uid, app, granted_by, granted_at) VALUES (?,?,?,?)",
			targetUID, app, actor.UID, time.Now().UnixMilli()); err != nil {
			return fmt.Errorf("授予应用: %w", err)
		}
		if role == adminRoleUser {
			if _, err := tx.ExecContext(context.Background(),
				"UPDATE users SET role = ? WHERE id = ?", adminRoleAdmin, targetUID); err != nil {
				return fmt.Errorf("提升为管理员: %w", err)
			}
		}
	} else {
		if _, err := tx.ExecContext(context.Background(),
			"DELETE FROM admin_scopes WHERE uid = ? AND app = ?", targetUID, app); err != nil {
			return fmt.Errorf("回收应用: %w", err)
		}
		var rest int
		if err := tx.QueryRowContext(context.Background(),
			"SELECT COUNT(*) FROM admin_scopes WHERE uid = ?", targetUID).Scan(&rest); err != nil {
			return fmt.Errorf("数剩余授权: %w", err)
		}
		if rest == 0 && role == adminRoleAdmin {
			if _, err := tx.ExecContext(context.Background(),
				"UPDATE users SET role = ? WHERE id = ?", adminRoleUser, targetUID); err != nil {
				return fmt.Errorf("降回普通用户: %w", err)
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("提交授权变更: %w", err)
	}
	return nil
}

// AdminChangeRole 调整平台角色（POST /admin/roles/{uid}/role）：**仅 admin↔super 之间**。
// 普通用户的提权走 AdminSetScope 的隐含提升（先有授权才有角色），这里不收 user——
// 「仅 super↔admin 间调整」是定稿语义。
//
// 两道守卫：① 不能调整自己（防自贬把平台锁死，也防误操作清空最后一个 super——
// 最后一道锁在 ②）；② 降级 super→admin 时目标必须不是最后一个 super
//（库里一个 super 都不剩，授予/回收/配置从此无人能做，平台锁死）。
func (s *Service) AdminChangeRole(actor Caller, targetUID int64, role string) (err error) {
	defer func() {
		s.Audit(AuditEvent{
			Action: AuditRoleChange, OK: err == nil, ActorUID: uidPtr(actor.UID),
			ActorEmail: maskEmail(actor.Email), TargetUID: uidPtr(targetUID), Meta: actor.Meta,
			Detail: map[string]string{"role": role},
		})
	}()
	if role != adminRoleAdmin && role != adminRoleSuper {
		return badRequest("角色只能是 admin 或 super")
	}
	if targetUID == actor.UID {
		return badRequest("不能调整自己的平台角色")
	}
	var current string
	scanErr := s.pool.QueryRowContext(context.Background(),
		"SELECT role FROM users WHERE id = ?", targetUID).Scan(&current)
	if errors.Is(scanErr, sql.ErrNoRows) {
		return &HTTPError{404, "该用户不存在"}
	}
	if scanErr != nil {
		return fmt.Errorf("查目标用户: %w", scanErr)
	}
	if current != adminRoleAdmin && current != adminRoleSuper {
		return badRequest("该用户不是管理员，请先授予应用授权")
	}
	if current == role {
		return nil // 幂等：已是目标角色，不写不报错
	}
	if IsSuperRole(current) && role == adminRoleAdmin {
		var supers int
		if err := s.pool.QueryRowContext(context.Background(),
			"SELECT COUNT(*) FROM users WHERE role = ?", adminRoleSuper).Scan(&supers); err != nil {
			return fmt.Errorf("数平台管理员: %w", err)
		}
		if supers <= 1 {
			return badRequest("不能降级最后一个平台管理员")
		}
	}
	if _, err := s.pool.ExecContext(context.Background(),
		"UPDATE users SET role = ? WHERE id = ?", role, targetUID); err != nil {
		return fmt.Errorf("改角色: %w", err)
	}
	return nil
}

// placeholders 生成 n 个 SQL 占位符（"?,?,?"）。调用方保证 n > 0（循环拼 IN 条件
// 的位置都是 len(apps) > 0 的分支）。
func placeholders(n int) string {
	return strings.TrimSuffix(strings.Repeat("?,", n), ",")
}

// containsStr 是 []string 的线性查找（清单最多两个 app，建 map 纯属浪费）。
func containsStr(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}
