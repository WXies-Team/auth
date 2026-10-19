package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/WXies-Team/auth/internal/protocol"
)

// SessionMeta 是一次登录请求的来源信息：ip 进列表（限流口径同一个 clientIP），
// User-Agent 用来解析设备标签。由路由层从 *http.Request 取，业务层不碰 HTTP。
type SessionMeta struct {
	IP        string
	UserAgent string
}

// sessionTouchInterval 是 last_seen_at 的回写节流：verify 是每个业务请求的必经点，
// 不节流就是每请求一次 UPDATE，把一个展示字段变成写放大。
const sessionTouchInterval = time.Minute

// execer 让会话吊销既能用 *sql.DB（单条语句）也能用 *sql.Tx（与 token_version+1
// 同批提交）——Logout 两个动作必须一起成一起败。
type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// createSession 落一行登录会话并返回雪花 sid，token 用它签进 claims。
// 建行失败就不发 token：没有 sid 的 token 过不了校验，发出去也是废的。
func (s *Service) createSession(userID int64, app string, meta SessionMeta) (int64, error) {
	return s.createSessionOn(s.pool, userID, app, meta)
}

// createSessionOn 在给定执行器上建会话。**Register 用事务执行器**：用户行与会话行
// 必须同批提交，分开写的话会话插入一失败就留下一个「已注册但拿不到 token」的账号，
// 用户重试只会看到「该邮箱已注册」。
func (s *Service) createSessionOn(ex execer, userID int64, app string, meta SessionMeta) (int64, error) {
	now := time.Now().UnixMilli()
	sid := s.ids.Generate().Int64()
	if _, err := ex.ExecContext(context.Background(),
		"INSERT INTO sessions (id, user_id, app, device, ip, user_agent, created_at, last_seen_at) VALUES (?,?,?,?,?,?,?,?)",
		sid, userID, app, truncateRunes(shortDevice(meta.UserAgent), 191),
		meta.IP, truncateRunes(meta.UserAgent, 512), now, now); err != nil {
		return 0, fmt.Errorf("建登录会话: %w", err)
	}
	return sid, nil
}

// sessionAlive 是所有 token 校验的第三道闸：sid 指向的会话行存在、未吊销、
// 属于该 uid，缺一即失效（查无此行 = 会话被踢或从未建过）。通过后顺带节流回写
// last_seen_at——写失败不拦请求，它只是设备列表的排序字段。
//
// ValidUserID 与 /internal/verify 都走这里：踢一台设备若只影响 verify，被踢的
// token 仍能调改密/注销这类 auth 端点，「踢」就只踢了半边。
func (s *Service) sessionAlive(userID, sid int64) (bool, error) {
	if sid <= 0 {
		return false, nil
	}
	ctx := context.Background()
	var owner, lastSeen int64
	var revokedAt sql.NullInt64
	err := s.pool.QueryRowContext(ctx,
		"SELECT user_id, last_seen_at, revoked_at FROM sessions WHERE id = ?", sid).
		Scan(&owner, &lastSeen, &revokedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("查会话: %w", err)
	}
	if owner != userID || revokedAt.Valid {
		return false, nil
	}
	if now := time.Now().UnixMilli(); now-lastSeen >= sessionTouchInterval.Milliseconds() {
		if _, err := s.pool.ExecContext(ctx,
			"UPDATE sessions SET last_seen_at = ? WHERE id = ? AND revoked_at IS NULL", now, sid); err != nil {
			slog.Warn("回写会话活跃时间失败（不影响请求）", "sid", sid, "err", err)
		}
	}
	return true, nil
}

// ListSessions 回当前用户的全部活跃会话，last_seen_at 倒序（刚用过的设备排最前），
// current 标出发起本请求的那台——客户端据此判断哪些能踢、哪台是自己。
func (s *Service) ListSessions(userID, currentSID int64) ([]protocol.SessionInfo, error) {
	rows, err := s.pool.QueryContext(context.Background(),
		"SELECT id, app, device, ip, created_at, last_seen_at FROM sessions WHERE user_id = ? AND revoked_at IS NULL ORDER BY last_seen_at DESC, id DESC",
		userID)
	if err != nil {
		return nil, fmt.Errorf("查登录会话: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := make([]protocol.SessionInfo, 0, 8)
	for rows.Next() {
		var it protocol.SessionInfo
		if err := rows.Scan(&it.ID, &it.App, &it.Device, &it.IP, &it.CreatedAt, &it.LastSeenAt); err != nil {
			return nil, fmt.Errorf("读登录会话: %w", err)
		}
		it.Current = it.ID == currentSID
		out = append(out, it)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("遍历登录会话: %w", err)
	}
	return out, nil
}

// RevokeSession 踢单台会话。**只能踢自己的**：别人的会话与不存在的 id 回同一个
// 404，不给「这个 id 存不存在」的探针。幂等——自己的已吊销会话再踢一次照样 200，
// 客户端重试不必对错误码分支处理。
func (s *Service) RevokeSession(userID, sid int64) error {
	var owner int64
	err := s.pool.QueryRowContext(context.Background(),
		"SELECT user_id FROM sessions WHERE id = ?", sid).Scan(&owner)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && owner != userID) {
		return &HTTPError{404, "该会话不存在"}
	}
	if err != nil {
		return fmt.Errorf("查会话归属: %w", err)
	}
	if _, err := s.pool.ExecContext(context.Background(),
		"UPDATE sessions SET revoked_at = ? WHERE id = ? AND user_id = ?",
		time.Now().UnixMilli(), sid, userID); err != nil {
		return fmt.Errorf("吊销会话: %w", err)
	}
	return nil
}

// RevokeOtherSessions 撤掉除 keepSID 外的全部会话（「退出其它设备」）。
// **不碰 token_version**：只在会话层动手，当前设备的 token 照用——与踢人同一套语义。
func (s *Service) RevokeOtherSessions(userID, keepSID int64) error {
	return revokeUserSessions(context.Background(), s.pool, userID, keepSID)
}

// revokeUserSessions 吊销该用户全部未吊销会话；keepSID > 0 时保留它自己。
func revokeUserSessions(ctx context.Context, ex execer, userID, keepSID int64) error {
	if _, err := ex.ExecContext(ctx,
		"UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL AND id <> ?",
		time.Now().UnixMilli(), userID, keepSID); err != nil {
		return fmt.Errorf("吊销登录会话: %w", err)
	}
	return nil
}

// shortDevice 把 User-Agent 尽力压成短标签，认不出来就退回 UA 原文截断。
//
// 形态按作者定案：有机型的移动设备出「系统 · 机型」（Android · Pixel 8），
// 桌面出「浏览器 · 系统」（Chrome · Linux）；都认不出（脚本、残缺 UA）就存原文——
// 设备列表宁可给一串可辨认的 UA，也不要空着一列。
func shortDevice(ua string) string {
	if strings.TrimSpace(ua) == "" {
		return "未知设备"
	}
	os, browser, model := classifyUA(ua)
	switch {
	case os != "" && model != "":
		return os + " · " + model
	case browser != "" && os != "":
		return browser + " · " + os
	case os != "":
		return os
	case browser != "":
		return browser
	default:
		return truncateRunes(ua, 191)
	}
}

// classifyUA 从 UA 里分拣出系统、浏览器与机型三个要素（任一可缺省）。
// 顺序要紧：Edge/Opera 的 UA 里都带 Chrome、Android 的 UA 里带 Linux，
// 先认窄的再认宽的，否则一律判成 Chrome / Linux。
func classifyUA(ua string) (osName, browser, model string) {
	switch {
	case strings.Contains(ua, "Android"):
		osName = "Android"
		// 机型在平台段的下一项：(Linux; Android 14; Pixel 8) → Pixel 8
		parts := parenParts(ua)
		for i, p := range parts {
			if strings.HasPrefix(p, "Android") && i+1 < len(parts) {
				model = parts[i+1]
			}
		}
	case strings.Contains(ua, "iPhone") || strings.Contains(ua, "iPad"):
		osName, model = "iOS", strings.TrimSpace(strings.Split(parenGroup(ua), ";")[0])
	case strings.Contains(ua, "CrOS"):
		osName = "ChromeOS"
	case strings.Contains(ua, "Mac OS X") || strings.Contains(ua, "Macintosh"):
		osName = "macOS"
	case strings.Contains(ua, "Windows"):
		osName = "Windows"
	case strings.Contains(ua, "Linux") || strings.Contains(ua, "X11"):
		osName = "Linux"
	}

	switch {
	case strings.Contains(ua, "Edg/") || strings.Contains(ua, "EdgA/") || strings.Contains(ua, "EdgiOS/"):
		browser = "Edge"
	case strings.Contains(ua, "OPR/") || strings.Contains(ua, "Opera") || strings.Contains(ua, "OPiOS/"):
		browser = "Opera"
	case strings.Contains(ua, "SamsungBrowser/"):
		browser = "Samsung Internet"
	case strings.Contains(ua, "Firefox/") || strings.Contains(ua, "FxiOS/"):
		browser = "Firefox"
	case strings.Contains(ua, "Chrome/") || strings.Contains(ua, "CriOS/"):
		browser = "Chrome"
	case strings.Contains(ua, "Safari/") && strings.Contains(ua, "Version/"):
		browser = "Safari"
	}
	return osName, browser, model
}

// parenGroup 取 UA 里第一个圆括号段（UA 规范里的平台段），没有就回空串。
func parenGroup(ua string) string {
	start := strings.IndexByte(ua, '(')
	end := strings.IndexByte(ua, ')')
	if start < 0 || end <= start {
		return ""
	}
	return ua[start+1 : end]
}

// parenParts 把平台段按分号拆开并去空白，如 "Linux; Android 14; Pixel 8" → 三段。
func parenParts(ua string) []string {
	group := parenGroup(ua)
	if group == "" {
		return nil
	}
	raw := strings.Split(group, ";")
	parts := make([]string, 0, len(raw))
	for _, p := range raw {
		parts = append(parts, strings.TrimSpace(p))
	}
	return parts
}

// truncateRunes 按 **rune** 截断：device/user_agent 是 UTF-8 列，按字节切会把
// 多字节字符切半个——列表里就出现乱码。
func truncateRunes(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n])
	}
	return s
}
