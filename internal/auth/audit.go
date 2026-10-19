package auth

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"
)

// 审计日志的口径（规格 A1.4，ASVS V16.2/V16.3）：
//
//	认证成败全记（含用了哪种因子）、授权失败、配置改动必记；
//	actor_email 存掩码、detail 只放非密钥的结构化信息——表本身不能变成泄密面；
//	只增不改不删，保留 90 天（清理挂发码路径，见 otp.go 的 issue）。
const (
	// login 的成功/失败在 action 上分流（规格事件清单原文），其余动作用 result 列。
	AuditLogin = "login"

	// 其余事件名（route 层与业务层共用，避免各处写字面量漂移）
	AuditRegister       = "register"
	AuditLogout         = "logout"
	AuditPasswordChange = "password.change"
	AuditPasswordReset  = "password.reset"
	AuditEmailChange    = "email.change"
	AuditAccountDelete  = "account.delete"
	AuditSessionKick    = "session.kick"
	AuditPasskeyCreate  = "passkey.create"
	AuditPasskeyRename  = "passkey.rename"
	AuditPasskeyDelete  = "passkey.delete"
	AuditTOTPSetup      = "totp.setup"
	AuditTOTPEnable     = "totp.enable"
	AuditTOTPDisable    = "totp.disable"
	AuditRecoveryGen    = "recovery.generate"
	AuditRecoveryUse    = "recovery.consume"
	AuditReauth         = "reauth"
	AuditAdminRole      = "admin.user.role_change"
	AuditAdminUserKick  = "admin.user.session_revoke"
	AuditAdminSession   = "admin.session.revoke"
	AuditAdminConfig    = "admin.config.set"
	AuditAdminAuditView = "admin.audit.view"

	// auditRetention：审计行保留 90 天。更久的对个人账号服务没有决策价值，
	// 只剩隐私暴露面（ASVS V16.1 要求定义保留期）。
	auditRetention = 90 * 24 * time.Hour
)

// AuditEvent 是一条待落库的审计记录。
//
// Action 是事件名；OK 决定 result 列（login 事件同时改写成 login.success /
// login.fail，对齐规格的事件清单）。ActorUID 为 nil 表示匿名事件（注册、
// 未登录的登录失败）。Detail 的值必须是**非密钥**的展示性信息——测试里有
// 白盒断言钉住「密码 / secret 不得出现在 detail」。
type AuditEvent struct {
	Action     string
	OK         bool
	ActorUID   *int64
	ActorEmail string
	TargetUID  *int64
	Meta       SessionMeta
	Detail     map[string]string
}

// Audit 落一条审计。**尽力而为**：写失败只记日志、绝不影响业务回执——
// 审计是旁路观察者，不能把「改密成功」变成 500。
func (s *Service) Audit(e AuditEvent) {
	action, result := e.Action, "ok"
	if !e.OK {
		result = "fail"
	}
	if e.Action == AuditLogin {
		if e.OK {
			action = "login.success"
		} else {
			action = "login.fail"
		}
	}
	var detailJSON string
	if len(e.Detail) > 0 {
		b, err := json.Marshal(e.Detail)
		if err != nil {
			slog.Warn("审计 detail 序列化失败，按无 detail 记", "action", action, "err", err)
		} else {
			detailJSON = string(b)
		}
	}
	_, err := s.pool.ExecContext(context.Background(),
		`INSERT INTO audit_logs
		 (id, ts, actor_uid, actor_email, action, result, target_uid, ip, user_agent, detail)
		 VALUES (?,?,?,?,?,?,?,?,?,?)`,
		s.ids.Generate().Int64(), time.Now().UnixMilli(),
		e.ActorUID, e.ActorEmail, action, result, e.TargetUID,
		e.Meta.IP, truncateRunes(e.Meta.UserAgent, 512), detailJSON)
	if err != nil {
		// 审计写不进必须响：静默丢弃等于给「出事查不到」埋雷
		slog.Error("写审计日志失败", "action", action, "result", result, "err", err)
	}
}

// AuditFromError 是「拿 err 直接落一条」的便携形态：err==nil 即成功。
func (s *Service) AuditFromError(e AuditEvent, err error) {
	e.OK = err == nil
	s.Audit(e)
}

// uidPtr 把可能为零的 uid 装成审计用的 *int64（0 = 匿名，不落指针）。
func uidPtr(uid int64) *int64 {
	if uid == 0 {
		return nil
	}
	return &uid
}

// AuditList 是管理台审计查询的一行（GET /admin/audit）。
type AuditRow struct {
	ID         int64             `json:"id"`
	TS         int64             `json:"ts"`
	ActorUID   int64             `json:"actorUid"`
	ActorEmail string            `json:"actorEmail"`
	Action     string            `json:"action"`
	Result     string            `json:"result"`
	TargetUID  int64             `json:"targetUid"`
	IP         string            `json:"ip"`
	UserAgent  string            `json:"userAgent"`
	Detail     map[string]string `json:"detail,omitempty"`
}

// AuditQuery 是审计查询条件（route 层从 query 参数填好再传）。
type AuditQuery struct {
	Action string
	Actor  int64 // 0 = 不限
	Target int64 // 0 = 不限
	From   int64 // 毫秒，0 = 不限
	To     int64
	Limit  int
	Offset int
}

// AuditLimit / AuditOffsetCap：审计查询的页大小与翻页上限。50 是管理台一页
// 放得下的量；偏移上限挡住「无脑翻到表底」把连接池拖住。
const (
	AuditLimit    = 50
	AuditOffsetCap = 100000
)

// QueryAudit 倒序分页查审计。条件全部可选，按 (ts, id) 倒序保证翻页稳定。
func (s *Service) QueryAudit(q AuditQuery) ([]AuditRow, int, error) {
	limit := q.Limit
	if limit <= 0 || limit > AuditLimit {
		limit = AuditLimit
	}
	offset := q.Offset
	if offset < 0 || offset > AuditOffsetCap {
		offset = 0
	}

	// 条件逐个拼：参数全走占位符，绝不字符串拼值进 SQL
	const base = " FROM audit_logs WHERE 1=1"
	var (
		args []any
		cond string
	)
	if q.Action != "" {
		cond += " AND action = ?"
		args = append(args, q.Action)
	}
	if q.Actor > 0 {
		cond += " AND actor_uid = ?"
		args = append(args, q.Actor)
	}
	if q.Target > 0 {
		cond += " AND target_uid = ?"
		args = append(args, q.Target)
	}
	if q.From > 0 {
		cond += " AND ts >= ?"
		args = append(args, q.From)
	}
	if q.To > 0 {
		cond += " AND ts <= ?"
		args = append(args, q.To)
	}

	var total int
	if err := s.pool.QueryRowContext(context.Background(), "SELECT COUNT(*)"+base+cond, args...).
		Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("数审计行: %w", err)
	}

	listArgs := append(append([]any{}, args...), limit, offset)
	rows, err := s.pool.QueryContext(context.Background(),
		"SELECT id, ts, actor_uid, actor_email, action, result, target_uid, ip, user_agent, detail"+
			base+cond+" ORDER BY ts DESC, id DESC LIMIT ? OFFSET ?", listArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("查审计: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := make([]AuditRow, 0, limit)
	for rows.Next() {
		var (
			it       AuditRow
			actorUID sql.NullInt64
			target   sql.NullInt64
			detail   []byte
		)
		if err := rows.Scan(&it.ID, &it.TS, &actorUID, &it.ActorEmail, &it.Action, &it.Result,
			&target, &it.IP, &it.UserAgent, &detail); err != nil {
			return nil, 0, fmt.Errorf("读审计行: %w", err)
		}
		it.ActorUID, it.TargetUID = actorUID.Int64, target.Int64
		if len(detail) > 0 {
			// detail 解不动就留空：坏行不该让整页查询 500
			_ = json.Unmarshal(detail, &it.Detail)
		}
		out = append(out, it)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("遍历审计: %w", err)
	}
	return out, total, nil
}

// CleanAuditLogs 删掉超过保留期的审计行。挂发码路径（otp.go issue）周期性调用，
// 与 otp_codes 的过期清理同一套模式——不引入后台 goroutine，免得多一个永不退出的
// 循环与它自己的测试面。
func (s *Service) CleanAuditLogs() { cleanAuditLogs(s.pool) }

// cleanAuditLogs 按保留期删过期审计行（Service 方法与 otp 发码路径共用同一实现）。
func cleanAuditLogs(pool *sql.DB) {
	if _, err := pool.ExecContext(context.Background(),
		"DELETE FROM audit_logs WHERE ts < ?", time.Now().Add(-auditRetention).UnixMilli()); err != nil {
		slog.Warn("清理过期审计行失败（下次发码再试）", "err", err)
	}
}
