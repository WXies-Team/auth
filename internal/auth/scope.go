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
//	授予规则按业界「只能授予低于自己」：app-admin 的授予/回收任一 super 都可做
//	（POST /admin/roles/{uid}/scope），super 角色本身的授予/回收只认根 su
//	（见 admin.go 的 RootSuperEmail / AdminSetRole）；app-admin 无任何授予权
//	（新端点全部 super-only，路由层把闸）。
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
		return badRequest("未知项目，请重新选择后重试")
	}
	var role string
	scanErr := s.pool.QueryRowContext(context.Background(),
		"SELECT role FROM users WHERE id = ?", targetUID).Scan(&role)
	if errors.Is(scanErr, sql.ErrNoRows) {
		return &HTTPError{404, "该用户不存在，请刷新用户列表后重试"}
	}
	if scanErr != nil {
		return fmt.Errorf("查目标用户: %w", scanErr)
	}
	if IsSuperRole(role) {
		return badRequest("平台管理员的权限覆盖全部项目，无需按项目授权")
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
