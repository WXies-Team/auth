// Package protocol 定义与客户端共享的 HTTP 协议。
//
// **auth 各请求/响应的字段名与 calorie-diary 服务端的 /auth/* 逐字一致**
//（JSON tag 一字不差）：两个日记 App 后续把客户端切到本端点时，改动只需
//「加上 app 字段、换个 base URL」。改任何字段名前先对照
// calorie-diary/server/internal/protocol/protocol.go 的 auth 块。
package protocol

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
type SendCodeRequest struct {
	Email   string `json:"email"`
	Purpose string `json:"purpose"`
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
// UID 是 63 位雪花整数：调用方务必用整型字段接收（encoding/json 对 int64 字段
// 直接按数字解析，无损；decode 成 float64 会丢精度）。
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
// UID 是 63 位雪花整数，调用方用 int64 接收（decode 成 float64 会丢低位）。
type EnsureUserResult struct {
	Email string `json:"email"`
	UID   int64  `json:"uid"`
}

// ApiError 对应 ApiError：所有非 200 回执的统一响应体。
type ApiError struct {
	Message string `json:"message"`
}
