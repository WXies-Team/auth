package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Web 登录编排的两段式（规格 A1.2 / A2.3）：
//
//	密码验过 → 账号开了 2FA 就只发一张 5 分钟的**单次中间态**（login_states），
//	拿它换 TOTP/恢复码，验过才建会话；没开 2FA 直接建会话。
//	邮箱验证码登录**不叠** TOTP——邮件通道本身就是持有因子（ASVS V6.3.6）。
const (
	loginStateTTL   = 5 * time.Minute
	loginStateFails = 5
)

// WebLoginResult 是 /web/login/* 的业务回执：Session 非 nil 即登录完成
//（路由层据此签双 cookie 并回 {token,email}）；Status 非空即还差一步。
type WebLoginResult struct {
	UID     int64
	Email   string
	Session *WebSession
	// Status 是 "2fa_required" 的机器位；空串 = 已完成
	Status     string
	LoginToken string
	Methods    []string
	// usedMethod 是第二步实际用掉的因子（totp / recovery），给审计落 detail.method 用；
	// 不进响应体——客户端不需要知道自己刚输的是哪种码。
	usedMethod string
}

// resUID / resEmail 从登录回执里取审计要用的身份（失败时回执为 nil → 匿名事件）。
func resUID(res *WebLoginResult) int64 {
	if res == nil {
		return 0
	}
	return res.UID
}

func resEmail(res *WebLoginResult, fallback string) string {
	if res == nil {
		return fallback
	}
	return res.Email
}

// loginStateRow 是 login_states 一行的读出结果。
type loginStateRow struct {
	uid    int64
	method string
}

// WebLoginPassword 密码登录第一步：验密码 → 无 2FA 直接建会话，有 2FA 发中间态。
// 凭据判定复用 checkPassword（与老端点 /auth/login 同一份实现）。
func (s *Service) WebLoginPassword(rawEmail, password string, meta SessionMeta) (res *WebLoginResult, err error) {
	// 登录失败必记（method=password）；**两步中间态不算成功也不算失败**——
	// 密码对了但还没过第二步，真正的结论由 WebLoginTOTP 那条事件给出。
	defer func() {
		if err == nil && (res == nil || res.Session == nil) {
			return
		}
		s.Audit(AuditEvent{
			Action: AuditLogin, OK: err == nil, ActorUID: uidPtr(resUID(res)),
			ActorEmail: maskEmail(normalizeEmail(rawEmail)), Meta: meta,
			Detail: map[string]string{"method": "password"},
		})
	}()
	uid, _, err := s.checkPassword(rawEmail, password)
	if err != nil {
		return nil, err
	}
	email := normalizeEmail(rawEmail)
	enabled, err := s.TOTPEnabled(uid)
	if err != nil {
		return nil, err
	}
	if !enabled {
		ws, err := s.CreateWebSession(uid, meta)
		if err != nil {
			return nil, err
		}
		return &WebLoginResult{UID: uid, Email: email, Session: ws}, nil
	}
	token, err := s.beginLoginState(uid)
	if err != nil {
		return nil, err
	}
	return &WebLoginResult{
		UID:        uid,
		Email:      email,
		Status:     "2fa_required",
		LoginToken: token,
		Methods:    []string{"totp", "recovery"},
	}, nil
}

// WebLoginEmailCode 邮箱验证码登录：一路建到底，**不叠 TOTP**（理由见包注释）。
func (s *Service) WebLoginEmailCode(rawEmail, code string, meta SessionMeta) (res *WebLoginResult, err error) {
	defer func() {
		s.Audit(AuditEvent{
			Action: AuditLogin, OK: err == nil, ActorUID: uidPtr(resUID(res)),
			ActorEmail: maskEmail(normalizeEmail(rawEmail)), Meta: meta,
			Detail: map[string]string{"method": "email_code"},
		})
	}()
	uid, _, email, err := s.checkLoginCode(rawEmail, code)
	if err != nil {
		return nil, err
	}
	ws, err := s.CreateWebSession(uid, meta)
	if err != nil {
		return nil, err
	}
	return &WebLoginResult{UID: uid, Email: email, Session: ws}, nil
}

// WebLoginTOTP 登录第二步：TOTP 码或恢复码任一验过即建会话。
//
// 错码记进 login_state 的 attempts，错 5 次整条烧毁（与邮箱验证码同口径）——
// 中间态是「已知密码」的凭证，必须比普通表单更抗爆破。
func (s *Service) WebLoginTOTP(loginToken, code, recoveryCode string, meta SessionMeta) (res *WebLoginResult, err error) {
	// method 在进分支前就定下来：失败那次也要说清用户输的是哪种码
	method := "totp"
	if strings.TrimSpace(recoveryCode) != "" {
		method = "recovery"
	}
	defer func() {
		// 中间态本身过期/不存在：这不是「输错码」，不进登录失败统计
		if err != nil && strings.Contains(err.Error(), "登录请求已过期") {
			return
		}
		s.Audit(AuditEvent{
			Action: AuditLogin, OK: err == nil, ActorUID: uidPtr(resUID(res)),
			ActorEmail: maskEmail(resEmail(res, "")), Meta: meta,
			Detail: map[string]string{"method": method},
		})
	}()
	st, err := s.peekLoginState(loginToken)
	if err != nil {
		return nil, err
	}
	var ok bool
	if rc := strings.TrimSpace(recoveryCode); rc != "" {
		ok, err = s.consumeRecoveryCode(st.uid, rc, meta)
		if err != nil {
			return nil, err
		}
	} else {
		ok, err = s.VerifyTOTPCode(st.uid, strings.TrimSpace(code))
		if err != nil {
			return nil, err
		}
	}
	if !ok {
		// 计一次失败；第 5 次把中间态烧掉，之后 peek 直接回「已过期」
		if err := s.failLoginState(loginToken); err != nil {
			return nil, err
		}
		return nil, badRequest("验证码错误，请重新输入")
	}
	s.burnLoginState(loginToken)
	var email string
	if err := s.pool.QueryRowContext(context.Background(), "SELECT email FROM users WHERE id = ?", st.uid).
		Scan(&email); err != nil {
		return nil, fmt.Errorf("查用户: %w", err)
	}
	ws, err := s.CreateWebSession(st.uid, meta)
	if err != nil {
		return nil, err
	}
	return &WebLoginResult{UID: st.uid, Email: email, Session: ws, usedMethod: method}, nil
}

// beginLoginState 发一张 5 分钟单次中间态：随机 32 字节明文回前端，
// 库里只存 sha256（与会话 cookie 同款 identifier/verifier 口径）。
func (s *Service) beginLoginState(uid int64) (string, error) {
	token, err := randomToken(webTokenBytes)
	if err != nil {
		return "", err
	}
	now := time.Now()
	if _, err := s.pool.ExecContext(context.Background(),
		`INSERT INTO login_states (token_hash, user_id, method, attempts, expires_at, created_at)
		 VALUES (?,?,?,?,?,?)`,
		sha256Hex(token), uid, "totp", 0, now.Add(loginStateTTL).UnixMilli(), now.UnixMilli()); err != nil {
		return "", fmt.Errorf("落登录中间态: %w", err)
	}
	// 过期行顺手清（表只有「在途两步登录」那么几行）
	_, _ = s.pool.ExecContext(context.Background(),
		"DELETE FROM login_states WHERE expires_at < ?", now.Add(-loginStateTTL).UnixMilli())
	return token, nil
}

// peekLoginState 读中间态（**不消费**：验码可能失败还要重试）。
// 不存在 / 过期一律 400「登录请求已过期」——两者不区分，免得当探针。
func (s *Service) peekLoginState(token string) (loginStateRow, error) {
	if strings.TrimSpace(token) == "" {
		return loginStateRow{}, &HTTPError{400, "登录请求已过期，请重新登录"}
	}
	var row loginStateRow
	var expires int64
	err := s.pool.QueryRowContext(context.Background(),
		"SELECT user_id, method, expires_at FROM login_states WHERE token_hash = ?", sha256Hex(token)).
		Scan(&row.uid, &row.method, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return loginStateRow{}, &HTTPError{400, "登录请求已过期，请重新登录"}
	}
	if err != nil {
		return loginStateRow{}, fmt.Errorf("查登录中间态: %w", err)
	}
	if time.Now().UnixMilli() > expires {
		s.burnLoginState(token)
		return loginStateRow{}, &HTTPError{400, "登录请求已过期，请重新登录"}
	}
	return row, nil
}

// failLoginState 记一次错码；第 loginStateFails 次把整条删掉。
func (s *Service) failLoginState(token string) error {
	_, err := s.pool.ExecContext(context.Background(),
		"UPDATE login_states SET attempts = attempts + 1 WHERE token_hash = ?", sha256Hex(token))
	if err != nil {
		return fmt.Errorf("记录错码: %w", err)
	}
	// 达到上限即烧（WHERE 带条件，避免「先查后删」的竞态窗口）
	if _, err := s.pool.ExecContext(context.Background(),
		"DELETE FROM login_states WHERE token_hash = ? AND attempts >= ?",
		sha256Hex(token), loginStateFails); err != nil {
		return fmt.Errorf("烧毁登录中间态: %w", err)
	}
	return nil
}

// burnLoginState 删行（验码通过后的用后即焚；失败路径不调它，留给 attempts 计数）。
func (s *Service) burnLoginState(token string) {
	_, _ = s.pool.ExecContext(context.Background(),
		"DELETE FROM login_states WHERE token_hash = ?", sha256Hex(token))
}
