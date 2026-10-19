package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"
)

// Web 会话的两个 cookie 名。__Host- 前缀把 Secure/Path=/ 绑进浏览器（子域伪造与
// HTTPS 降级都写不进来），OWASP Session Management Cheat Sheet 的推荐形态。
// 名字在包里导出：cookie 的读写在路由层，hash 的校验在业务层，两边必须同名。
const (
	WebCookieName     = "__Host-auth_web"
	WebCSRFCookieName = "__Host-auth_web_csrf"
)

const (
	// webAppLabel 是 sessions.app 在 Web 台登录行上的取值——设备页因此能把
	// 网页登录和两个日记 App 的登录分列显示。
	webAppLabel = "web"
	// webTokenBytes 是会话 token 与 CSRF token 的熵：32 字节 CSPRNG（ASVS 7.2.3
	// 要求 ≥128 位），base64url 落 cookie。
	webTokenBytes = 32
	// 空闲 7 天 / 绝对 90 天：个人控制台存的是低敏数据，设备页本身还能踢人自卫。
	// OWASP 的 15~30 分钟参考区间对这个场景过激，属 documented deviation（ASVS 7.1.1）。
	webIdleTTL     = 7 * 24 * time.Hour
	webAbsoluteTTL = 90 * 24 * time.Hour
	// WebCookieMaxAgeSeconds 是会话 cookie 的绝对寿命（与 webAbsoluteTTL 同值的秒数）。
	// 路由层给 Set-Cookie 用——cookie 的读写在 HTTP 层，业务层不碰它。
	WebCookieMaxAgeSeconds = 90 * 24 * 3600
	// ReauthWindow 是「强认证（输密码 / 过 TOTP）」的有效窗：改密、改邮、绑解 2FA、
	// 管理写操作都要求它在 15 分钟内（ASVS V7.5.1）。
	ReauthWindow = 15 * time.Minute
)

// MsgReauthRequired 是 reauth 窗过期时的固定文案。前端据此弹「重新验证」框
//（ApiError 只有 message 一个字段，不能为了机器可读去改它的形状——老客户端在读它）。
const MsgReauthRequired = "需要重新验证身份，请输入密码或验证码"

// WebSession 是一次 Web 登录签发的凭据：两串都只以 sha256 落库，明文只在这一刻
// 回给调用方（cookie 与 /web/session 的 csrfToken）。
type WebSession struct {
	SID       int64
	Token     string
	CSRFToken string
	ExpiresAt time.Time
}

// randomToken 生成 n 字节 CSPRNG 的 base64url 串（URL 安全、无填充）。
// 用 crypto/rand——token 可预测等于没有会话。
func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("生成随机 token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// CreateWebSession 给 Web 台登录建一行会话（app='web'）并返回双 token。
//
// 与两条老登录路的差别只有「多存两列 hash」：id 仍是雪花、device 仍走 shortDevice、
// 踢人与 revoked_at 闸完全复用——网页登录的这行会出现在 App 的设备页里，可被踢。
func (s *Service) CreateWebSession(userID int64, meta SessionMeta) (*WebSession, error) {
	token, err := randomToken(webTokenBytes)
	if err != nil {
		return nil, err
	}
	csrf, err := randomToken(webTokenBytes)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	sid := s.ids.Generate().Int64()
	if _, err := s.pool.ExecContext(context.Background(),
		`INSERT INTO sessions (id, user_id, app, device, ip, user_agent, created_at, last_seen_at, web_token_hash, web_csrf_hash)
		 VALUES (?,?,?,?,?,?,?,?,?,?)`,
		sid, userID, webAppLabel, truncateRunes(shortDevice(meta.UserAgent), 191),
		meta.IP, truncateRunes(meta.UserAgent, 512), now.UnixMilli(), now.UnixMilli(),
		sha256Hex(token), sha256Hex(csrf)); err != nil {
		return nil, fmt.Errorf("建 web 会话: %w", err)
	}
	return &WebSession{SID: sid, Token: token, CSRFToken: csrf, ExpiresAt: now.Add(webAbsoluteTTL)}, nil
}

// WebCaller 是 Web 会话解析结果：内嵌 Caller（业务层照旧用它的 UID/SID），
// 多带两项只有路由层关心的现场——CSRF hash（cookie 请求要对）与「凭 cookie 进来的」
// 标记（Bearer 请求不走 CSRF：跨站脚本设置不了 Authorization，没有可搭的顺风车）。
type WebCaller struct {
	Caller
	CSRFHash  string
	ViaCookie bool
	// Role 是 users.role 的现查结果（web 会话解析时顺带取回，省一次点查）；
	// 管理端点的最终判定仍要再查一次——撤销必须当场生效。
	Role string
}

// ValidWebSession 用会话 cookie 的明文 token 换身份：sha256 点查 → 行活着 →
// 两道超时（空闲 7 天 / 绝对 90 天）→ 节流回写 last_seen_at。
//
// 任一不满足都回 401「登录已过期」——前端据此清状态、跳登录页。
// DB 抖动按 503 报：把一次 MySQL 超时当成会话失效会把人静默踢出控制台。
func (s *Service) ValidWebSession(token string) (WebCaller, error) {
	if token == "" {
		return WebCaller{}, unauthorized("登录已过期，请重新登录")
	}
	ctx := context.Background()
	var (
		sid, uid, createdAt, lastSeen int64
		revokedAt                     sql.NullInt64
		csrfHash, email, role         string
	)
	err := s.pool.QueryRowContext(ctx,
		`SELECT s.id, s.user_id, s.created_at, s.last_seen_at, s.revoked_at, s.web_csrf_hash, u.email, u.role
		 FROM sessions s JOIN users u ON u.id = s.user_id
		 WHERE s.web_token_hash = ?`, sha256Hex(token)).
		Scan(&sid, &uid, &createdAt, &lastSeen, &revokedAt, &csrfHash, &email, &role)
	if errors.Is(err, sql.ErrNoRows) {
		return WebCaller{}, unauthorized("登录已过期，请重新登录")
	}
	if err != nil {
		return WebCaller{}, &HTTPError{503, "服务暂时不可用，请稍后重试"}
	}
	now := time.Now().UnixMilli()
	switch {
	case revokedAt.Valid:
		return WebCaller{}, unauthorized("登录已过期，请重新登录")
	case now-createdAt > webAbsoluteTTL.Milliseconds():
		return WebCaller{}, unauthorized("登录已过期，请重新登录")
	case now-lastSeen > webIdleTTL.Milliseconds():
		// 空闲超时的行不自动吊销：下次登录/踢人照常把它收掉，这里只是不再认它
		return WebCaller{}, unauthorized("登录已过期，请重新登录")
	}
	// 节流回写：与 sessionAlive 同款（60 秒内不重复写），失败不拦请求——它只是
	// 设备页的排序字段
	if now-lastSeen >= sessionTouchInterval.Milliseconds() {
		if _, err := s.pool.ExecContext(ctx,
			"UPDATE sessions SET last_seen_at = ? WHERE id = ? AND revoked_at IS NULL", now, sid); err != nil {
			slog.Warn("回写 web 会话活跃时间失败（不影响请求）", "sid", sid, "err", err)
		}
	}
	return WebCaller{
		Caller:    Caller{UID: uid, Email: email, App: webAppLabel, SID: sid},
		CSRFHash:  csrfHash,
		ViaCookie: true,
		Role:      role,
	}, nil
}

// ValidWebBearer 识别并解析以 Authorization: Bearer 携带的 **web 会话 token**
//（C 批 App 拿到的 {token} 就是它）。JWT 走 ValidUserID、web token 走这里，
// 双凭据互不串用，但两条路各自都要撞 revoked_at 与超时闸。
func (s *Service) ValidWebBearer(header string) (WebCaller, error) {
	raw := bearerLike(header)
	if raw == "" {
		return WebCaller{}, unauthorized("请先登录")
	}
	c, err := s.ValidWebSession(raw)
	if err != nil {
		return WebCaller{}, err
	}
	c.ViaCookie = false
	return c, nil
}

// bearerLike 去掉 "Bearer " 前缀取 token；没这个前缀回空串。
func bearerLike(header string) string {
	if !strings.HasPrefix(header, "Bearer ") {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))
}

// CheckWebCSRF 校验同步器 token：请求头 X-CSRF-Token 的 sha256 要等于本会话存的。
// 常数时间比对（值是等长 64 位 hex，subtle 走满长度）。
func (c WebCaller) CheckCSRF(provided string) bool {
	if c.CSRFHash == "" || provided == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(c.CSRFHash), []byte(sha256Hex(provided))) == 1
}

// MarkReauth 记下「刚刚强认证过」，写在**本会话行**上：换设备、换登录方式都不串。
func (s *Service) MarkReauth(sid int64) error {
	_, err := s.pool.ExecContext(context.Background(),
		"UPDATE sessions SET reauth_at = ? WHERE id = ? AND revoked_at IS NULL", time.Now().UnixMilli(), sid)
	if err != nil {
		return fmt.Errorf("记录强认证时间: %w", err)
	}
	return nil
}

// RequireReauth 强认证窗（15 分钟）内的请求放行，否则 401 + 固定文案，
// 前端弹重新验证框后调 /web/reauth 刷新。
func (s *Service) RequireReauth(sid int64) error {
	var reauth sql.NullInt64
	err := s.pool.QueryRowContext(context.Background(),
		"SELECT reauth_at FROM sessions WHERE id = ? AND revoked_at IS NULL", sid).Scan(&reauth)
	if errors.Is(err, sql.ErrNoRows) {
		return unauthorized("登录已过期，请重新登录")
	}
	if err != nil {
		return &HTTPError{503, "服务暂时不可用，请稍后重试"}
	}
	if !reauth.Valid || time.Now().UnixMilli()-reauth.Int64 > ReauthWindow.Milliseconds() {
		return &HTTPError{401, MsgReauthRequired}
	}
	return nil
}

// Reauth 完成一次强认证并刷新**本会话**的 reauth_at：密码或 TOTP 码二选一。
//
// 密码路复用 checkPassword（与登录同一份凭据判定，含防枚举的恒时假比对），
// 并按 uid 比对而不是邮箱——token 里的邮箱可能已是旧值，uid 才是会话的锚。
// 成败都进审计：这是「持登录态重拿高危操作许可」的动作，被反复尝试值得看见。
func (s *Service) Reauth(c Caller, password, totpCode string) (err error) {
	method := "totp"
	if strings.TrimSpace(password) != "" {
		method = "password"
	}
	defer func() {
		s.Audit(AuditEvent{
			Action: AuditReauth, OK: err == nil, ActorUID: uidPtr(c.UID),
			ActorEmail: maskEmail(c.Email), Meta: c.Meta,
			Detail: map[string]string{"method": method},
		})
	}()
	switch {
	case strings.TrimSpace(password) != "":
		uid, _, err := s.checkPassword(c.Email, password)
		if err != nil {
			return err
		}
		if uid != c.UID {
			// 邮箱对不上说明 token 身份与库不一致（改绑竞态等），按凭据错误处理
			return unauthorized("密码不正确")
		}
	case strings.TrimSpace(totpCode) != "":
		enabled, err := s.TOTPEnabled(c.UID)
		if err != nil {
			return err
		}
		if !enabled {
			return badRequest("两步验证尚未开启，请改用密码验证")
		}
		ok, err := s.VerifyTOTPCode(c.UID, totpCode)
		if err != nil {
			return err
		}
		if !ok {
			return badRequest("验证码错误，请重新输入")
		}
	default:
		return badRequest("请输入密码或验证码")
	}
	return s.MarkReauth(c.SID)
}

// SessionRole 取当前会话用户的 role（管理后台每请求现查，不缓存——与 token_version
// 「吊销从不缓存」同款理由：撤销管理员资格必须当场生效）。
func (s *Service) SessionRole(uid int64) (string, error) {
	var role string
	err := s.pool.QueryRowContext(context.Background(), "SELECT role FROM users WHERE id = ?", uid).Scan(&role)
	if errors.Is(err, sql.ErrNoRows) {
		return "", unauthorized("登录已过期，请重新登录")
	}
	if err != nil {
		return "", &HTTPError{503, "服务暂时不可用，请稍后重试"}
	}
	return role, nil
}
