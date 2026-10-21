package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
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

// 会话作用域（本批拍板）：会话归属 uid 之外还带一层「可见 app」。
//
//	cookie（网页控制台 / 管理后台）调用者 → apps = nil = 全部 app 的会话；
//	Bearer（JWT aud 或 web 会话 token 的 app='web'）调用者 → 只限自己 app 的会话。
//
// 超范围与查无此行**同回 404**（同一句文案）：不给「这个 id 存不存在 / 属于谁」的
// 存在性探针。路由层据凭据形态填 apps，业务层只认这个参数。

// ListSessions 回当前用户的活跃会话，last_seen_at 倒序（刚用过的设备排最前），
// current 标出发起本请求的那台——客户端据此判断哪些能踢、哪台是自己。
// apps 非空 = 只回这些 app 的行；空 = 不限（见文件顶部的会话作用域注释）。
//
// 展示的 device 是**读取时按 user_agent 现算**（shortDevice），不读 device 列：
// 那列是插入时快照，老服务端时期认不出的库名 UA（ktor-client/2.0）被当设备名
// 存了进去，现算让存量行随解析规则升级自愈，零迁移；列本身保留作历史快照/排障。
//
// ID 以**十进制字符串**回出（见 protocol.SessionInfo 的注释：63 位雪花过不了
// 浏览器 JSON.parse 的 53 位精度）。
func (s *Service) ListSessions(userID, currentSID int64, apps []string) ([]protocol.SessionInfo, error) {
	cond := " WHERE user_id = ? AND revoked_at IS NULL"
	args := []any{userID}
	if len(apps) > 0 {
		cond += " AND app IN (" + placeholders(len(apps)) + ")"
		for _, a := range apps {
			args = append(args, a)
		}
	}
	rows, err := s.pool.QueryContext(context.Background(),
		"SELECT id, app, user_agent, ip, created_at, last_seen_at FROM sessions"+cond+
			" ORDER BY last_seen_at DESC, id DESC", args...)
	if err != nil {
		return nil, fmt.Errorf("查登录会话: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := make([]protocol.SessionInfo, 0, 8)
	for rows.Next() {
		var (
			it protocol.SessionInfo
			id int64
			ua string
		)
		if err := rows.Scan(&id, &it.App, &ua, &it.IP, &it.CreatedAt, &it.LastSeenAt); err != nil {
			return nil, fmt.Errorf("读登录会话: %w", err)
		}
		it.ID = strconv.FormatInt(id, 10)
		it.Device = shortDevice(ua)
		it.Current = id == currentSID
		out = append(out, it)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("遍历登录会话: %w", err)
	}
	return out, nil
}

// RevokeSession 踢单台会话。**只能踢自己的、且在可见范围内**：别人的会话、
// 超出 apps 范围的会话与不存在的 id 回同一个 404，不给「这个 id 存不存在」的探针。
// 幂等——自己的已吊销会话再踢一次照样 200，客户端重试不必对错误码分支处理。
func (s *Service) RevokeSession(userID, sid int64, apps []string) error {
	var owner int64
	var sessApp string
	err := s.pool.QueryRowContext(context.Background(),
		"SELECT user_id, app FROM sessions WHERE id = ?", sid).Scan(&owner, &sessApp)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && (owner != userID || (len(apps) > 0 && !containsStr(apps, sessApp)))) {
		return &HTTPError{404, msgSessionGone}
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

// msgSessionGone 是「查无此行 / 不属于你 / 不在你的可见范围」三态共用的一句话：
// 三者分开说等于把存在性探针白送给调用方。
const msgSessionGone = "该会话不存在或已退出，请刷新设备列表后重试"

// maxRevokeBatch 是批量退出（POST /api/sessions/revoke-many）一次的 id 上限：
// 一条 UPDATE 最多 100 个占位符，超了就是客户端 bug 或恶意灌包。
const maxRevokeBatch = 100

// RevokeSessions 批量踢会话（网页端「退出该设备全部会话」）：先整批校验归属与
// 可见范围，**任一不合法即整体 404**（与单踢同句文案、同一套不泄露存在性口径），
// 再一条 UPDATE 吊销——不会出现「踢了一半」的中间态。回执是实际踢掉的台数
// （已吊销的行不计，重复提交仍回 200）。
func (s *Service) RevokeSessions(userID int64, ids []int64, apps []string) (int, error) {
	if len(ids) == 0 {
		return 0, badRequest("未选择要退出的会话，请先勾选设备")
	}
	if len(ids) > maxRevokeBatch {
		return 0, badRequest(fmt.Sprintf("一次最多退出 %d 个会话，请分批操作", maxRevokeBatch))
	}
	holders := placeholders(len(ids))
	args := make([]any, 0, len(ids))
	for _, id := range ids {
		args = append(args, id)
	}
	rows, err := s.pool.QueryContext(context.Background(),
		"SELECT id, user_id, app FROM sessions WHERE id IN ("+holders+")", args...)
	if err != nil {
		return 0, fmt.Errorf("查待退出会话: %w", err)
	}
	seen := make(map[int64]bool, len(ids))
	var bad bool
	for rows.Next() {
		var (
			id, owner int64
			sessApp   string
		)
		if err := rows.Scan(&id, &owner, &sessApp); err != nil {
			_ = rows.Close()
			return 0, fmt.Errorf("读待退出会话: %w", err)
		}
		seen[id] = true
		if owner != userID || (len(apps) > 0 && !containsStr(apps, sessApp)) {
			bad = true
		}
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return 0, fmt.Errorf("遍历待退出会话: %w", err)
	}
	_ = rows.Close()
	if bad || len(seen) != len(ids) {
		// 缺行（别人会话 / 超范围 / 已被清理）一律 404，与单踢同口径
		return 0, &HTTPError{404, msgSessionGone}
	}
	res, err := s.pool.ExecContext(context.Background(),
		"UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL AND id IN ("+holders+")",
		append([]any{time.Now().UnixMilli(), userID}, args...)...)
	if err != nil {
		return 0, fmt.Errorf("批量吊销会话: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("读批量吊销结果: %w", err)
	}
	return int(n), nil
}

// RevokeOtherSessions 撤掉除 keepSID 外的会话（「退出其它设备」），只动
// **可见范围内**的行（apps 空 = 不限）。**不碰 token_version**：只在会话层动手，
// 当前设备的 token 照用——与踢人同一套语义。
func (s *Service) RevokeOtherSessions(userID, keepSID int64, apps []string) error {
	return revokeUserSessions(context.Background(), s.pool, userID, keepSID, apps)
}

// revokeUserSessions 吊销该用户可见范围内的全部未吊销会话；keepSID > 0 时保留它自己。
func revokeUserSessions(ctx context.Context, ex execer, userID, keepSID int64, apps []string) error {
	cond := ""
	args := []any{time.Now().UnixMilli(), userID, keepSID}
	if len(apps) > 0 {
		cond = " AND app IN (" + placeholders(len(apps)) + ")"
		for _, a := range apps {
			args = append(args, a)
		}
	}
	if _, err := ex.ExecContext(ctx,
		"UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL AND id <> ?"+cond,
		args...); err != nil {
		return fmt.Errorf("吊销登录会话: %w", err)
	}
	return nil
}

// shortDevice 把 User-Agent 压成**设备列表里显示的那一格**。三态定案：
//
//	① App 规范 UA（`calorie-diary/1.2.3 (Android; Pixel 8)`）→ 友好机型（Pixel 8）；
//	② 浏览器 UA → 有机型出「系统 · 机型」（Android · Pixel 8），否则「浏览器 · 系统」；
//	③ 认不出 → 「未知设备」。
//
// 第 ③ 条是本批收紧的：早先认不出就存 UA 原文，于是 Ktor/OkHttp 这类**库名 UA**
// 被当成设备名显示（「ktor-client/2.0」根本不是一台设备）。原文不丢——完整 UA
// 仍按 512 字截断落在 user_agent 列，排障时照查。
//
// 调用口径：**展示时现算**——ListSessions / AdminListSessions 读取时按 user_agent
// 调它（存量行随规则升级自愈，device 列快照不参与展示）；插入时（createSessionOn /
// websession）也调同一个函数落快照，新行两处天然一致。
func shortDevice(ua string) string {
	if strings.TrimSpace(ua) == "" {
		return "未知设备"
	}
	if ok, osName, model := parseAppUA(ua); ok {
		if model != "" {
			return model
		}
		if osName != "" {
			return osName
		}
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
		return "未知设备"
	}
}

// parseAppUA 识别 App 上报的规范 User-Agent：`产品名/版本 (系统; 机型)`。
// 返回 ok 及平台段的系统与机型两段（任一可缺省）。机型段按分号拆，**段内空格
// 保留**——`Xiaomi 23127PN0CC` 整段就是机型，按空格再切会把品牌切掉。
//
// 认定条件（缺一即不是 App UA）：头部必须是 `字母数字连字符/数点版本`，必须带
// 平台段，且 UA 里不能出现 Mozilla——浏览器 UA 的头部同样是 `名字/版本`
//（Mozilla/5.0），不挡它会把整张设备表都判成 App UA。ktor/okhttp 这类库名 UA
// 通常没有平台段，天然落不进来。
func parseAppUA(ua string) (ok bool, osName, model string) {
	if strings.Contains(ua, "Mozilla") {
		return false, "", ""
	}
	head, rest, found := strings.Cut(ua, " ")
	if !found || !strings.Contains(rest, "(") {
		return false, "", ""
	}
	name, ver, hasVer := strings.Cut(head, "/")
	if !hasVer || !allOfRunes(name, uaProductRunes) || !allOfRunes(ver, uaVersionRunes) {
		return false, "", ""
	}
	parts := parenParts(ua)
	if len(parts) == 0 {
		return false, "", ""
	}
	if len(parts) > 1 {
		model = parts[1]
	}
	return true, parts[0], model
}

// uaProductRunes / uaVersionRunes 是 App UA 头部两段的字符集：
// 产品名 = 字母数字与连字符（calorie-diary），版本 = 数字与点（1.2.3）。
func uaProductRunes(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-'
}

func uaVersionRunes(r rune) bool {
	return (r >= '0' && r <= '9') || r == '.'
}

// allOfRunes 判定串里每个字符都过 pred（空串不过——产品名/版本不能为空）。
func allOfRunes(s string, pred func(rune) bool) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !pred(r) {
			return false
		}
	}
	return true
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
