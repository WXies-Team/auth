package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"time"
)

// 登录与 /internal/verify 共用的账号态闸（W2 封禁 / W5 项目登录白名单）。
//
// 判定顺序钉死（B1 合并批次契约）：**封禁 → 项目白名单**，之后才是注销 pending 与
// mustChange（那两道在 loginGate 里，见 pendingdelete.go）。拦截点只有两处：
//
//	a) 三路登录（密码 / 邮箱码 / Passkey）与 2FA 第二步——都在**凭据验证成功之后、
//	   发 token 之前**（先验凭据后报封禁，防邮箱枚举）；
//	b) /internal/verify —— 会话建好后被封 / 项目开限制的老 token 当场 403。
//
// 封禁写入时已吊销范围内会话（见 AdminBan），所以 verify 这道闸主要接住
// 「吊销竞态里漏掉的会话」与 app 范围之外没被吊销的行。

// denyReason 判定 uid 在 app 语境下能否登录 / 通过 verify：任一命中回 403，
// 全部放行回 nil。app 为空串（web 流程 / 控制台）时只判全站封禁（'*'）——
// 项目维度的封禁与白名单只对具体项目会话有意义。
//
// DB 抖动一律 503 而不是放行：把抖动当「没封」等于给封禁开一个故障窗口，
// 口径与 token_version 查库失败一致（503 让客户端按普通失败重试）。
func (s *Service) denyReason(uid int64, app string) error {
	if err := s.denyIfBanned(uid, app); err != nil {
		return err
	}
	return s.denyIfProjectRestricted(uid, app)
}

// denyIfBanned 查 user_bans：'*' 行对所有语境生效，具体项目行只对同 app 生效。
// 读到过期的限时行（until_ms>0 且已过）视为已解封并顺手删行（惰性清扫——
// 不引入定时任务，判定即清理，契约定案）。
func (s *Service) denyIfBanned(uid int64, app string) error {
	ctx := context.Background()
	rows, err := s.pool.QueryContext(ctx,
		"SELECT app, until_ms, reason FROM user_bans WHERE uid = ?", uid)
	if err != nil {
		slog.Error("查封禁行失败", "uid", uid, "err", err)
		return &HTTPError{503, "服务暂时不可用，请稍后重试"}
	}
	defer func() { _ = rows.Close() }()
	now := time.Now().UnixMilli()
	type banRow struct {
		app    string
		until  int64
		reason string
	}
	var hit *banRow
	var stale []string
	for rows.Next() {
		var b banRow
		if err := rows.Scan(&b.app, &b.until, &b.reason); err != nil {
			slog.Error("读封禁行失败", "uid", uid, "err", err)
			return &HTTPError{503, "服务暂时不可用，请稍后重试"}
		}
		if b.until > 0 && now > b.until {
			// 过期行记下惰性删（rows 读完再执行，不在查询中途抢连接）
			stale = append(stale, b.app)
			continue
		}
		if b.app == "*" || (app != "" && b.app == app) {
			c := b
			hit = &c
			// 不 break：同表可能还有第二条命中行（'*' + 具体项目），过期行仍要扫掉
		}
	}
	if err := rows.Err(); err != nil {
		slog.Error("遍历封禁行失败", "uid", uid, "err", err)
		return &HTTPError{503, "服务暂时不可用，请稍后重试"}
	}
	_ = rows.Close()
	for _, bannedApp := range stale {
		// 失败只记日志：判定已按未封处理，删不掉不影响本次结果
		if _, derr := s.pool.ExecContext(ctx,
			"DELETE FROM user_bans WHERE uid = ? AND app = ?", uid, bannedApp); derr != nil {
			slog.Warn("清理过期封禁行失败（不影响本次判定）", "uid", uid, "app", bannedApp, "err", derr)
		}
	}
	if hit == nil {
		return nil
	}
	return &HTTPError{403, banMessage(hit.reason, hit.until)}
}

// banMessage 拼封禁文案（W2 钉死的元素拼装，中文自然语序）：
// 账号已被封禁[：原因][，将于 {yyyy-MM-dd HH:mm} 解除 | ，为永久封禁]。如有疑问请联系管理员。
func banMessage(reason string, until int64) string {
	msg := "账号已被封禁"
	if reason != "" {
		msg += "：" + reason
	}
	if until > 0 {
		msg += "，将于 " + time.UnixMilli(until).Format("2006-01-02 15:04") + " 解除"
	} else {
		msg += "，为永久封禁"
	}
	return msg + "。如有疑问请联系管理员"
}

// denyIfProjectRestricted 判定项目登录白名单（W5，Entra「Assignment required」模式）：
// project_policy.restricted=1 时只放行 super（su 无限制）∨ project_access 在册用户
// ∨ 该项目的 admin_scopes 管理员。restricted 直查表——不进 app_config 的 10s 缓存，
// 开关必须当场生效。非项目语境（app 空 / 未知 slug）直接放行。
func (s *Service) denyIfProjectRestricted(uid int64, app string) error {
	if !allowedApps[app] {
		return nil
	}
	var restricted int
	err := s.pool.QueryRowContext(context.Background(),
		"SELECT restricted FROM project_policy WHERE app = ?", app).Scan(&restricted)
	if errors.Is(err, sql.ErrNoRows) {
		return nil // 没有策略行 = 未开限制（默认开放）
	}
	if err != nil {
		slog.Error("查项目登录限制失败", "app", app, "err", err)
		return &HTTPError{503, "服务暂时不可用，请稍后重试"}
	}
	if restricted == 0 {
		return nil
	}
	var allowed int
	if err := s.pool.QueryRowContext(context.Background(),
		`SELECT (EXISTS(SELECT 1 FROM users WHERE id = ? AND role = ?)
		       OR EXISTS(SELECT 1 FROM project_access WHERE app = ? AND uid = ?)
		       OR EXISTS(SELECT 1 FROM admin_scopes WHERE app = ? AND uid = ?))`,
		uid, adminRoleSuper, app, uid, app, uid).Scan(&allowed); err != nil {
		slog.Error("查项目白名单失败", "app", app, "uid", uid, "err", err)
		return &HTTPError{503, "服务暂时不可用，请稍后重试"}
	}
	if allowed == 1 {
		return nil
	}
	return &HTTPError{403, restrictedMessage(app)}
}

// restrictedMessage 是项目白名单的拒绝文案（带项目名更佳——展示名取品牌注册表，
// 与 allowedApps 同键对拍，不会漂）。
func restrictedMessage(app string) string {
	return "「" + appName(app) + "」项目仅限受邀用户登录，如需访问请联系管理员"
}

// loginGate 是**凭据验证通过之后、发 token 之前**的账号态总闸（顺序钉死）：
// 封禁 → 项目白名单 → 注销 pending（未到期即撤销、到期同步执行注销管线并拒绝登录）
// → 回填 mustChangePassword。返回值直接进登录回执（契约 4）。
//
// err 非 nil 时调用方必须终止登录（会话与 token 都还没建，不会留半截状态）。
func (s *Service) loginGate(uid int64, app string, meta SessionMeta) (mustChange, deleteCancelled bool, err error) {
	if err := s.denyReason(uid, app); err != nil {
		return false, false, err
	}
	ctx := context.Background()
	var (
		email    string
		pending  int64
		mustFlag int
	)
	err = s.pool.QueryRowContext(ctx,
		"SELECT email, pending_delete_at, password_must_change FROM users WHERE id = ?", uid).
		Scan(&email, &pending, &mustFlag)
	if errors.Is(err, sql.ErrNoRows) {
		// 凭据刚验过、行却没了：注销/删号竞态，按会话失效处理
		return false, false, unauthorized("登录已过期，请重新登录")
	}
	if err != nil {
		slog.Error("读账号态失败", "uid", uid, "err", err)
		return false, false, &HTTPError{503, "服务暂时不可用，请稍后重试"}
	}
	if pending > 0 {
		if time.Now().UnixMilli() <= pending+deleteGrace.Milliseconds() {
			// 宽限期内登录 = 撤销注销（W3「登录即撤销」）：清 pending、发信、记审计，
			// 回执 deletePendingCancelled=true 让客户端能提示「已撤销」。
			if err := s.cancelPendingDelete(uid, email, meta); err != nil {
				return false, false, err
			}
			return mustFlag == 1, true, nil
		}
		// 清扫滞后：已到期 → 立即同步执行注销管线，拒绝登录
		if err := s.finishDelete(uid, email, meta); err != nil {
			return false, false, err
		}
		return false, false, &HTTPError{401, "该账号已注销"}
	}
	return mustFlag == 1, false, nil
}

// passwordMustChange 读强制改密位（改密端点的空 oldPassword 通道要用）。
func (s *Service) passwordMustChange(uid int64) (bool, error) {
	var flag int
	err := s.pool.QueryRowContext(context.Background(),
		"SELECT password_must_change FROM users WHERE id = ?", uid).Scan(&flag)
	if errors.Is(err, sql.ErrNoRows) {
		return false, unauthorized("登录已过期，请重新登录")
	}
	if err != nil {
		return false, fmt.Errorf("查改密状态: %w", err)
	}
	return flag == 1, nil
}

// adminTarget 校验「操作者能否管理 targetUID」的第一段（W1/W2 共用）：
// 目标存在（404）+ 目标是根 su 时仅根本人（403），回目标邮箱供后续判定与审计。
//
// 根判定按 uid（W7-2：root 换绑邮箱不再失权）：目标 uid 与启动时缓存的根 uid
// 相等即根；缓存未解析出（空库形态）才回退钉死邮箱比对。
func (s *Service) adminTarget(actor Caller, targetUID int64) (string, error) {
	var email string
	err := s.pool.QueryRowContext(context.Background(),
		"SELECT email FROM users WHERE id = ?", targetUID).Scan(&email)
	if errors.Is(err, sql.ErrNoRows) {
		return "", &HTTPError{404, "该用户不存在，请刷新用户列表后重试"}
	}
	if err != nil {
		return "", fmt.Errorf("查目标用户: %w", err)
	}
	if s.isRootAccount(targetUID, email) && !s.isRootSuper(actor) {
		return "", &HTTPError{403, "只有根管理员可以操作该账号"}
	}
	return email, nil
}

// adminTargetScope 是 app-admin 的项目边界校验（W2 封禁 / W5 项目管理共用）：
// 非 super 且目标项目不在授权清单 → 403。'*'（全站）只属 super，由调用方先行 400。
func adminTargetScope(scope AdminScope, app string) error {
	if scope.Super || containsStr(scope.Apps, app) {
		return nil
	}
	return &HTTPError{403, "没有该项目的管理权限，请联系平台管理员开通"}
}

// AdminScope 是管理端点的授权现场（路由层 adminCtx 透传）：
// Super=平台管理员（此时 Apps 恒 nil）；Apps=app-admin 的 admin_scopes 清单（每请求现查，
// 撤销 scope 当场生效）。业务层不再二次查 role——与 AdminRevokeSession 信任入参 apps
// 同一口径。
type AdminScope struct {
	Super bool
	Apps  []string
}

// untilStr 把封禁解除时刻转成审计 detail 用的十进制串（0=永久原样落 "0"）。
func untilStr(until int64) string { return strconv.FormatInt(until, 10) }
