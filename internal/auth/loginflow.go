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
//	拿它换 TOTP/恢复码/邮箱验证码，验过才建会话；没开 2FA 直接建会话。
//	邮箱验证码登录**不叠** TOTP——邮件通道本身就是持有因子（ASVS V6.3.6）。
//
// C 批起每条路再分两支（分岔点只有 completeLogin 与中间态的 app 列）：
//
//	app 空   = **web 流程**：会话行 app='web'、签双 cookie，回执与既往逐字节一致；
//	app 非空 = **App 流程**：会话行 app=<白名单应用>、签既有格式 JWT（与 /auth/login
//	          同一 createToken 助手：同 aud 白名单/ver/sid/90 天），不下发 cookie。
const (
	loginStateTTL   = 5 * time.Minute
	loginStateFails = 5
)

// WebLoginResult 是 /web/login/* 与 /webauthn/login/finish 的业务回执：
// Session 或 JWT 任一非空即登录完成（路由层据此签 cookie 或直接回体）；
// 两者都空且 Status 非空 = 还差 2FA 第二步。
type WebLoginResult struct {
	UID     int64
	Email   string
	Session *WebSession
	// App 是本次登录声明的应用：空串 = web 流程；非空 = App 流程（白名单内）。
	// 它同时是路由层的分流开关——App 流程不碰 cookie。
	App string
	// JWT 是 App 流程签给业务侧的 token（web 流程恒空，那时用 Session.Token）。
	JWT string
	// SID 是本回执对应的会话行 id（web 与 App 两路都填）：passkey 登录要用它
	// 记「本会话用哪把凭证」，两支的取法不同所以统一放在这里。
	SID int64
	// Status 是 "2fa_required" 的机器位；空串 = 已完成
	Status     string
	LoginToken string
	Methods    []string
	// MustChangePassword / DeletePendingCancelled 是登录回执的两个账号态位（契约 4）：
	// loginGate 回填，路由层 writeLoginResult 原样落进 AuthResponse（强制改密屏 /
	// 「已撤销注销」提示的依据）。
	MustChangePassword     bool
	DeletePendingCancelled bool
	// usedMethod 是第二步实际用掉的因子（totp / recovery / email_code），给审计落 detail.method 用；
	// 不进响应体——客户端不需要知道自己刚输的是哪种码。
	usedMethod string
}

// resUID 从登录回执里取审计要用的 uid（失败时回执为 nil → 匿名事件）。
func resUID(res *WebLoginResult) int64 {
	if res == nil {
		return 0
	}
	return res.UID
}

// normalizeLoginApp 是三条登录编排入口共用的 app 闸：空串 = web 流程（不签 JWT、
// 走 cookie 会话），给了就必须在 aud 白名单里——外值一律 400（与 /auth/login 的
// validateApp 同一句文案）。校验放在凭据之前：app 写错是客户端 bug，401 会误导排障。
func normalizeLoginApp(app string) (string, error) {
	if app == "" {
		return "", nil
	}
	if err := validateApp(app); err != nil {
		return "", err
	}
	return app, nil
}

// loginStateAppLabel / loginStateApp 只在 SQL 边界上换词汇：业务侧恒用「空串 = web
// 流程」，而 login_states.app 是 NOT NULL DEFAULT 'web'（老行与 web 流程都存 'web'）。
func loginStateAppLabel(app string) string {
	if app == "" {
		return webAppLabel
	}
	return app
}

func loginStateApp(label string) string {
	if label == webAppLabel {
		return ""
	}
	return label
}

// loginStateRow 是 login_states 一行的读出结果。
type loginStateRow struct {
	uid    int64
	method string
	// app 是第一步声明的目标应用（已按 loginStateApp 换回业务词汇：'' = web）。
	app string
}

// completeLogin 把「登录已成立」落成回执，web / App 两支的唯一分岔点。
//
//	web 流程（app 空）：CreateWebSession 建双 token 会话，路由层据此签 cookie；
//	App 流程：createSession 建业务会话行（不写 web_token_hash / web_csrf_hash 两列，
//	          没有 cookie 可校验），再用 createToken 签**既有格式** JWT——不发明第二种
//	          token 形态，/internal/verify 与下游 withUID 一行都不必改。
//
// 两支都打 reauth_at：登录即强认证，passkey 注册那道 Bearer reauth 窗靠它（App 登录
// 拿到的会话行是它唯一的落点）。
//
// **loginGate 在最前面**（凭据已在各调用方验过）：封禁 → 项目白名单 → 注销 pending →
// mustChange，四道按契约顺序在建会话/签 token 之前过完——任一命中这里直接返回，
// 不留半截会话。
func (s *Service) completeLogin(uid int64, email, app string, meta SessionMeta) (*WebLoginResult, error) {
	mustChange, cancelled, err := s.loginGate(uid, app, meta)
	if err != nil {
		return nil, err
	}
	if app == "" {
		ws, err := s.CreateWebSession(uid, meta)
		if err != nil {
			return nil, err
		}
		// 密码/验证码/因子刚验过 = 强认证：给新会话记 reauth_at，接下来 2 小时内的
		// 敏感操作（改密改邮、绑解两步验证、进管理后台）不必再逼用户输一遍。
		_ = s.MarkReauth(ws.SID)
		// 新设备登录提醒（W1）：best-effort，失败只 slog 不拦登录
		s.notifyNewLoginDevice(uid, ws.SID, email, app, meta)
		return &WebLoginResult{
			UID: uid, Email: email, Session: ws, SID: ws.SID,
			MustChangePassword: mustChange, DeletePendingCancelled: cancelled,
		}, nil
	}
	// 兜底：入口处（normalizeLoginApp）已校验过，这里再过一道——app 是 JWT 的 aud，
	// 白名单外的值一个字节都不签。
	if err := validateApp(app); err != nil {
		return nil, err
	}
	sid, err := s.createSession(uid, app, meta)
	if err != nil {
		return nil, err
	}
	ver, err := s.tokenVersion(uid)
	if err != nil {
		return nil, err
	}
	token, err := s.createToken(uid, email, app, ver, sid)
	if err != nil {
		return nil, err
	}
	_ = s.MarkReauth(sid)
	// 新设备登录提醒（W1）：best-effort，失败只 slog 不拦登录
	s.notifyNewLoginDevice(uid, sid, email, app, meta)
	return &WebLoginResult{
		UID: uid, Email: email, App: app, JWT: token, SID: sid,
		MustChangePassword: mustChange, DeletePendingCancelled: cancelled,
	}, nil
}

// WebLoginPassword 密码登录第一步：验密码 → 无 2FA 直接落会话，有 2FA 发中间态。
// 凭据判定复用 checkPassword（与老端点 /auth/login 同一份实现）。
// app 空 = web 流程（cookie 会话），非空 = App 流程（JWT），语义见 completeLogin。
func (s *Service) WebLoginPassword(rawEmail, password string, meta SessionMeta, app string) (res *WebLoginResult, err error) {
	// 登录失败必记（method=password）；**两步中间态不算成功也不算失败**——
	// 密码对了但还没过第二步，真正的结论由 WebLoginTOTP 那条事件给出。
	// defer 先于 app 校验挂上：app 写错同样是一条 login.fail（与 /auth/login 一致），
	// 之后任何返回路径都不必记得补记。
	defer func() {
		if err == nil && (res == nil || (res.Session == nil && res.JWT == "")) {
			return
		}
		detail := map[string]string{"method": "password"}
		if app != "" {
			detail["app"] = app
		}
		s.Audit(AuditEvent{
			Action: AuditLogin, OK: err == nil, ActorUID: uidPtr(resUID(res)),
			ActorEmail: maskEmail(normalizeEmail(rawEmail)), Meta: meta,
			Detail: detail,
		})
	}()
	if app, err = normalizeLoginApp(app); err != nil {
		return nil, err
	}
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
		return s.completeLogin(uid, email, app, meta)
	}
	token, err := s.beginLoginState(uid, app)
	if err != nil {
		return nil, err
	}
	return &WebLoginResult{
		UID:        uid,
		Email:      email,
		App:        app,
		Status:     "2fa_required",
		LoginToken: token,
		Methods:    []string{"totp", "recovery"},
	}, nil
}

// WebLoginEmailCode 邮箱验证码登录：一路建到底，**不叠 TOTP**（理由见包注释）。
// 契约里没有 app（这条路只在 Web 台出现），恒走 web 流程。
//
// 登录闸（loginGate）与 completeLogin 同款前置；且**登录成功打 reauth_at**——
// 与另两条 web 登录路合流（W4 定案：登录成功一律刷新强认证窗，强制改密要过
// reauthThen；早先「邮件通道不算强因子故不合流」的口径由 W1 批推翻）。
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
	// 与另两条 web 登录路合流到 completeLogin（W1 批重构）：loginGate + 建会话 +
	// reauth 收口在那一处，新设备登录提醒的接线点也因此一处覆盖全部登录路径。
	return s.completeLogin(uid, email, "", meta)
}

// WebLoginTOTP 登录第二步：TOTP 码 / 恢复码 / 邮箱验证码任一验过即落会话。
//
// **app 不在请求里**：第一步声明的目标应用随 login_states 带下来（列 app，
// NOT NULL DEFAULT 'web'），第二步据此决定发 web 会话还是业务 JWT——客户端只交
// loginToken，两步之间换不了目标应用。
//
// 因子分流 recoveryCode > emailCode > code：前两个是专用字段（非空即选定该因子），
// code 是兜底的 TOTP 位——客户端一次只交一个因子的值，同时给多个按此优先级取用。
//
// 邮箱码（emailCode，purpose=login_2fa）绑**同一 login state 的 uid/邮箱**，
// otp store 的冷却/每日限额/5 错烧码一条不放松（验证码强度弱于 TOTP，闸门只会更紧，
// 口径同 Entra External ID / Okta 的 email authentication factor）；它的错码与
// TOTP/恢复码**共享 login state 的 5 次烧毁计数**——三选一是三条通道、不是三份额度。
//
// 错码记进 login_state 的 attempts，错 5 次整条烧毁（与邮箱验证码同口径）——
// 中间态是「已知密码」的凭证，必须比普通表单更抗爆破。
func (s *Service) WebLoginTOTP(loginToken, code, recoveryCode, emailCode string, meta SessionMeta) (res *WebLoginResult, err error) {
	// method 在进分支前就定下来：失败那次也要说清用户输的是哪种码
	method := "totp"
	switch {
	case strings.TrimSpace(recoveryCode) != "":
		method = "recovery"
	case strings.TrimSpace(emailCode) != "":
		method = "email_code"
	}
	// actor 在中间态揭开后即回填：失败路径（错码/乱码爆破第二步）同样要能
	// 归因到 uid 与掩码邮箱——旧实现失败时 res=nil，审计 actor 全空
	var actorUID int64
	var actorEmail string
	defer func() {
		// 中间态本身过期/不存在：这不是「输错码」，不进登录失败统计
		if err != nil && strings.Contains(err.Error(), "登录请求已过期") {
			return
		}
		detail := map[string]string{"method": method}
		// 只有走完全程的回执才知道目标应用；失败行维持既有形状（无 app）
		if res != nil && res.App != "" {
			detail["app"] = res.App
		}
		s.Audit(AuditEvent{
			Action: AuditLogin, OK: err == nil, ActorUID: uidPtr(actorUID),
			ActorEmail: actorEmail, Meta: meta,
			Detail: detail,
		})
	}()
	st, err := s.peekLoginState(loginToken)
	if err != nil {
		return nil, err
	}
	actorUID = st.uid
	// 邮箱查一次：审计 actor 的掩码底稿与后面 completeLogin 共用同一行查询
	var email string
	if err := s.pool.QueryRowContext(context.Background(),
		"SELECT email FROM users WHERE id = ?", st.uid).Scan(&email); err != nil {
		return nil, fmt.Errorf("查用户: %w", err)
	}
	actorEmail = maskEmail(email)
	var ok bool
	switch {
	case strings.TrimSpace(recoveryCode) != "":
		// n7：实耗恢复码时中间态的 method 如实改账 'recovery'——beginLoginState
		// 恒写 'totp'，失败重试留下的行、审计回联都该能看出用户当时用的哪种码
		if err := s.setLoginStateMethod(loginToken, "recovery"); err != nil {
			return nil, err
		}
		ok, err = s.consumeRecoveryCode(st.uid, email, strings.TrimSpace(recoveryCode), meta)
		if err != nil {
			return nil, err
		}
	case strings.TrimSpace(emailCode) != "":
		// 两步验证在第一步之后被关掉的窗口：没有第二步可走，指回密码登录
		//（中间态还在，直接报会变成永远过不去的死路）
		enabled, terr := s.TOTPEnabled(st.uid)
		if terr != nil {
			return nil, terr
		}
		if !enabled {
			return nil, badRequest("该账号未开启两步验证，请换用密码登录")
		}
		if err := s.setLoginStateMethod(loginToken, "email_code"); err != nil {
			return nil, err
		}
		// otp 层回自己的文案（错码/过期/请先获取）并管逐码计数；错码另计入
		// login state 的共享烧毁计数——三选一是三条通道、不是三份额度。
		// 两步验证邮箱码走匿名 SendCode（uid=0），验按 0 收口
		if verr := s.otps.verify(0, PurposeLogin2FA, email, strings.TrimSpace(emailCode)); verr != nil {
			if ferr := s.failLoginState(loginToken); ferr != nil {
				return nil, ferr
			}
			return nil, verr
		}
		ok = true
	default:
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
		// 文案按实耗的因子分流：恢复码错了说恢复码，两步验证码错了说验证码
		return nil, badRequest(wrongCodeMsg(method == "recovery", ""))
	}
	s.burnLoginState(loginToken)
	res, err = s.completeLogin(st.uid, email, st.app, meta)
	if err != nil {
		return nil, err
	}
	res.usedMethod = method // 过了 TOTP/恢复码/邮箱码任一关就是强认证（reauth_at 在 completeLogin 里打）
	return res, nil
}

// WebPasskeyLogin 是 /webauthn/login/finish 的业务编排（规格 A2.1，C 批）：
// 仪式校验 → 落会话（web 双 token 会话 / App 的业务会话 + JWT）→ 记「本会话用哪把
// passkey」→ 审计 login.success method=passkey。
//
// response 必须已是**对象字节**：日记 App 发的 authenticationResponseJson 是 JSON
// 字符串，解一层属于传输层的事，在 cmd/server/web.go 的 credentialJSON 里做——
// 业务层只见库认的对象形态。
func (s *Service) WebPasskeyLogin(ceremonyID int64, response []byte, app string, meta SessionMeta) (res *WebLoginResult, err error) {
	// app 先于仪式校验：写错的应用是客户端 bug，且不能让一次失败的请求白白烧掉
	// 单次性的 ceremonyId（重排就得让用户重新掏一次 passkey）。
	target, err := normalizeLoginApp(app)
	if err != nil {
		return nil, err
	}
	uid, email, credID, err := s.FinishPasskeyLogin(ceremonyID, response)
	if err != nil {
		return nil, err
	}
	res, err = s.completeLogin(uid, email, target, meta)
	if err != nil {
		return nil, err
	}
	// discoverable 登录带 UV（设备锁/面容/指纹），按强认证记 reauth_at——已由
	// completeLogin 打在本会话行上（两条支路同口径）。
	s.MarkPasskeyLogin(res.SID, credID)
	detail := map[string]string{"method": "passkey"}
	if target != "" {
		detail["app"] = target
	}
	s.Audit(AuditEvent{
		Action: AuditLogin, OK: true, ActorUID: uidPtr(res.UID), ActorEmail: email,
		Meta:   meta,
		Detail: detail,
	})
	return res, nil
}

// beginLoginState 发一张 5 分钟单次中间态：随机 32 字节明文回前端，
// 库里只存 sha256（与会话 cookie 同款 identifier/verifier 口径）。
// app 存进 login_states.app（空串落 'web'），第二步靠它决定发 web 会话还是 JWT。
func (s *Service) beginLoginState(uid int64, app string) (string, error) {
	token, err := randomToken(webTokenBytes)
	if err != nil {
		return "", err
	}
	now := time.Now()
	if _, err := s.pool.ExecContext(context.Background(),
		`INSERT INTO login_states (token_hash, user_id, method, attempts, expires_at, created_at, app)
		 VALUES (?,?,?,?,?,?,?)`,
		sha256Hex(token), uid, "totp", 0, now.Add(loginStateTTL).UnixMilli(), now.UnixMilli(),
		loginStateAppLabel(app)); err != nil {
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
	var label string
	err := s.pool.QueryRowContext(context.Background(),
		"SELECT user_id, method, app, expires_at FROM login_states WHERE token_hash = ?", sha256Hex(token)).
		Scan(&row.uid, &row.method, &label, &expires)
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
	row.app = loginStateApp(label)
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

// setLoginStateMethod 如实回写第二步实耗的因子（totp / recovery / email_code）。
// beginLoginState 恒写 'totp'（密码路只有 TOTP 一种预告因子），恢复码与邮箱码
// 真的被提交时改账——失败重试留下的行据此能看出爆破走的是哪条通道（n7）。
func (s *Service) setLoginStateMethod(token, method string) error {
	if _, err := s.pool.ExecContext(context.Background(),
		"UPDATE login_states SET method = ? WHERE token_hash = ?", method, sha256Hex(token)); err != nil {
		return fmt.Errorf("记录登录因子: %w", err)
	}
	return nil
}
