// Package protocol 定义与客户端共享的 HTTP 协议。
//
// **auth 各请求/响应的字段名与日记客户端的 AuthDtos.kt 逐字一致**
//（JSON tag 一字不差）：两个日记 App 后续把客户端切到本端点时，改动只需
//「加上 app 字段、换个 base URL」。对拍钉在 protocol_test.go 的
// TestProtocolMatchesDiaryAuthDtos——日记仓是私有仓，CI 无权跨仓读真文件，
// 只能把它 AuthDtos.kt 的字段快照内联钉住；日记侧改字段要同步更新那份快照。
package protocol

import "encoding/json"

// AuthRequest 对应日记客户端的 AuthRequest。
//
// Code 只在**注册**时校验，登录一律忽略——两边共用一个 DTO，老客户端登录不带
// 该字段照常工作；注册不带 = 拒绝（强制验证码）。
//
// App 是本服务新增的字段：登录请求要声明目标应用，作为 JWT aud
//（白名单 calorie-diary / expense-diary，缺失或未知拒绝）。
type AuthRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Code     string `json:"code"`
	App      string `json:"app"`
}

// SendCodeRequest 对应 SendCodeRequest。Purpose 取 auth.PurposeRegister /
// PurposeReset / PurposeLogin（客户端 CodePurpose 三值，服务端白名单同集，其余回 400）。
//
// App 是本服务新增的**可选**字段：决定这封验证码邮件的品牌（空白 = 中性品牌 Auth，
// 预留给将来的 web 账号台；给了就必须在 calorie-diary / expense-diary 白名单，未知值 400）。
// 老客户端不传照常工作——可选字段加进来不会让它们挂掉。
type SendCodeRequest struct {
	Email   string `json:"email"`
	Purpose string `json:"purpose"`
	App     string `json:"app"`
}

// ResetPasswordRequest 对应 ResetPasswordRequest。
type ResetPasswordRequest struct {
	Email    string `json:"email"`
	Code     string `json:"code"`
	Password string `json:"password"`
}

// LoginCodeRequest 对应 LoginCodeRequest：邮箱验证码登录（POST /auth/login-code）。
type LoginCodeRequest struct {
	Email string `json:"email"`
	Code  string `json:"code"`
	App   string `json:"app"`
}

// SendChangeEmailCodeRequest 对应 SendChangeEmailCodeRequest：改邮箱发码
// （authed，POST /auth/send-change-email-code），验证码发到**新**邮箱。
type SendChangeEmailCodeRequest struct {
	Email string `json:"email"`
}

// ChangeEmailRequest 对应 ChangeEmailRequest：改绑邮箱（authed，POST /auth/change-email），
// 当前密码重验 + 新邮箱验证码，成功回 {ok:true}（不吊销会话，见 auth.Service.ChangeEmail）。
type ChangeEmailRequest struct {
	Password string `json:"password"`
	Email    string `json:"email"`
	Code     string `json:"code"`
}

// AuthResponse 对应 AuthResponse。
type AuthResponse struct {
	Token string `json:"token"`
	Email string `json:"email"`
}

// ChangePasswordRequest 对应 ChangePasswordRequest（原密码版改密，老客户端仍走它）。
type ChangePasswordRequest struct {
	OldPassword string `json:"oldPassword"`
	NewPassword string `json:"newPassword"`
}

// ChangePasswordCodeRequest 对应验证码版改密请求。
type ChangePasswordCodeRequest struct {
	Code     string `json:"code"`
	Password string `json:"password"`
}

// DeleteAccountRequest 对应 DeleteAccountRequest。
type DeleteAccountRequest struct {
	Password string `json:"password"`
}

// VerifyRequest 是 POST /internal/verify 的请求体：调用方（日记服务的 withUID
// 中间件）声明自己的应用标识，与 token 的 aud 精确比对。
type VerifyRequest struct {
	App string `json:"app"`
}

// VerifyResponse 是 /internal/verify 的成功回执。
// UID 是 7 位随机整数（2026-10 起，此前为 63 位雪花 uid）：调用方务必用整型字段
// 接收（encoding/json 对 int64 字段直接按数字解析，无损；decode 成 float64 的写法
// 一旦挪去接 sid / 内部 id 这类 63 位值就会丢低位）。
type VerifyResponse struct {
	UID   int64  `json:"uid"`
	Email string `json:"email"`
	App   string `json:"app"`
}

// EnsureUserEntry 是 POST /internal/users/ensure 的单条存量用户（迁移脚本 → 本服务）。
//
// **内部接口，不属于客户端契约**：与上面那些和 calorie-diary 逐字对齐的 /auth/* DTO
// 无关，改字段名不影响任何 App。
//
// PasswordHash 原样落库：旧库已是 bcrypt 串，重算既没必要也需要明文；nil/缺字段/null
// 都落 NULL——纯邮箱验证码登录的账号在旧库就没有密码。
type EnsureUserEntry struct {
	Email        string  `json:"email"`
	PasswordHash *string `json:"password_hash"`
	CreatedAt    int64   `json:"created_at"`
}

// EnsureUserResult 是并入回执：Email 是**归一化后**的邮箱（小写去空格，与落库值一致），
// UID 是 7 位随机整数（此前为 63 位雪花），调用方仍用 int64 接收——同一段代码
// 别按 float64 解 JSON 数字，挪去接 63 位的 sid/内部 id 就丢低位。
type EnsureUserResult struct {
	Email string `json:"email"`
	UID   int64  `json:"uid"`
}

// SessionInfo 是 GET /api/sessions 的一条「已登录设备」（本服务新增的端点，
// 不属于与日记客户端既有 /auth/* 逐字对齐的那批 DTO）。
//
// ID 是 63 位雪花：用 int64 字段接收（decode 成 float64 会丢低位）；
// Current 标出发起本次请求的那台——踢谁都行，踢掉自己等于本地登出。
type SessionInfo struct {
	ID         int64  `json:"id"`
	App        string `json:"app"`
	Device     string `json:"device"`
	IP         string `json:"ip"`
	CreatedAt  int64  `json:"createdAt"`
	LastSeenAt int64  `json:"lastSeenAt"`
	Current    bool   `json:"current"`
}

// ---- Web 自助台 / 管理后台的新端点 DTO ----
//
// 与上面那批「与日记客户端逐字对齐」的 DTO 分开：这些是本服务新增端点的形状，
// 由 Web 页与（C 批）日记 App 的 passkey/2FA 流程读写，改字段不影响老客户端。

// WebLoginRequest 是 POST /web/login/password 的请求体。
//
// App 是可选的：日记 App 走这条路要带上自己的标识（便于审计与将来分流），
// 网页端可以不传——web 会话不签 JWT，没有 aud 参与。
type WebLoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	App      string `json:"app"`
}

// WebLoginCodeRequest 是 POST /web/login/email-code 的请求体。
type WebLoginCodeRequest struct {
	Email string `json:"email"`
	Code  string `json:"code"`
}

// WebLoginTOTPRequest 是 POST /web/login/totp 的请求体：Code 与 RecoveryCode
// 二选一（哪个非空用哪个）。
type WebLoginTOTPRequest struct {
	LoginToken   string `json:"loginToken"`
	Code         string `json:"code"`
	RecoveryCode string `json:"recoveryCode"`
}

// WebLoginPending 是两步登录第一步的回执（与 {token,email} 互斥）。
type WebLoginPending struct {
	Status     string   `json:"status"`
	LoginToken string   `json:"loginToken"`
	Methods    []string `json:"methods"`
}

// WebSessionResponse 是 POST /web/session 的回执：控制台页头与管理后台
// 的入口判定都看它。csrfToken 从可读 cookie 同步回一份（服务端才是准的）。
type WebSessionResponse struct {
	UID          int64  `json:"uid"`
	Email        string `json:"email"`
	Role         string `json:"role"`
	CSRFToken    string `json:"csrfToken"`
	TotpEnabled  bool   `json:"totpEnabled"`
	PasskeyCount int    `json:"passkeyCount"`
	// PasswordSet 是规格 A2.3 字段之外的**附加只读位**：概览页要如实显示
	// 「密码这一行现在是什么状态」，而纯验证码并入的账号本来就没有密码——
	// 加字段不改既有字段，老调用方零影响。
	PasswordSet bool `json:"passwordSet"`
}

// WebReauthRequest 是 POST /web/reauth 的请求体：Password 与 TOTPCode 二选一，
// 都为空则回 400（「重新验证」必须真的验点什么）。
type WebReauthRequest struct {
	Password string `json:"password"`
	TOTPCode string `json:"totpCode"`
}

// PasskeyFinishRequest 是 /webauthn/*/finish 的请求体：ceremonyId 是我们发的，
// response 是浏览器原样回的 PublicKeyCredential JSON（透传给库解析）。
type PasskeyFinishRequest struct {
	CeremonyID int64           `json:"ceremonyId"`
	Response   json.RawMessage `json:"response"`
}

// PasskeyRenameRequest 是 PATCH /api/passkeys/{id} 的请求体。
type PasskeyRenameRequest struct {
	Name string `json:"name"`
}

// CodeRequest 是 /api/totp/setup 之外三个 TOTP 写操作的统一请求体
//（enable / disable / regenerate-recovery-codes 都只要一个码）。
type CodeRequest struct {
	Code string `json:"code"`
}

// RecoveryCodesResponse 是 /api/totp/enable 与 regenerate-recovery-codes 的回执：
// 恢复码**只在这一次响应里出现**，服务端此后只有哈希，忘了就只能换发。
type RecoveryCodesResponse struct {
	RecoveryCodes []string `json:"recoveryCodes"`
}

// ApiError 对应 ApiError：所有非 200 回执的统一响应体。
type ApiError struct {
	Message string `json:"message"`
}
