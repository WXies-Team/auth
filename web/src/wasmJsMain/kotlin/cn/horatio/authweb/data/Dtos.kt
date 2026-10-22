// HTTP 数据层 DTO：与 Go 侧 internal/protocol/protocol.go 的 JSON tag 逐字对齐。
// 权威来源是协议快照 TestProtocolMatchesDiaryAuthDtos（protocol_test.go）；
// 本文件新增端点的形状以 cmd/server/{routes,web}.go 的回执为准。
//
// 回执形状的两处实测结论（与直觉不同，改前先看源码）：
// - GET /api/sessions 回 {sessions:[...]} 对象信封（routes.go 注释钉死：裸数组
//   在 Kotlin 端反序列化必失败）→ SessionsResponse。
// - GET /api/passkeys 与 GET /web/registry 回**裸数组**（web.go 直接
//   writeJSON(list)）→ 用 Api.get<List<PasskeyInfo>> / List<RegistryApp> 整顶层
//   数组解析，没有信封 DTO。
package cn.horatio.authweb.data

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement

// ---- 登录（/auth/* 老端点 + /web/login/* cookie 流程）----

/** 登录/注册完成回执（AuthResponse，协议顺序钉死）：web 流程 token 恒空串（凭据在 HttpOnly cookie）。 */
@Serializable
data class AuthResponse(
    val token: String = "",
    val email: String = "",
    val mustChangePassword: Boolean = false,
    val deletePendingCancelled: Boolean = false,
)

/** POST /web/login/password。app 缺省 = web cookie 流程；白名单值 = App JWT 流程。 */
@Serializable
data class WebLoginRequest(
    val email: String,
    val password: String = "",
    val app: String = "",
)

/** POST /web/login/email-code（web 两步流第一步之一）。 */
@Serializable
data class WebLoginCodeRequest(val email: String, val code: String)

/** POST /web/login/totp：code / recoveryCode / emailCode 三选一，优先级 recovery > email > code。 */
@Serializable
data class WebLoginTOTPRequest(
    val loginToken: String,
    val code: String = "",
    val recoveryCode: String = "",
    val emailCode: String = "",
)

/** 两步登录第一步回执（与 AuthResponse 互斥）：status=="2fa" 时进第二步。 */
@Serializable
data class WebLoginPending(
    val status: String,
    val loginToken: String,
    val methods: List<String> = emptyList(),
)

// ---- 会话（POST /web/session、/web/reauth*、/web/logout）----

/** POST /web/session 回执：控制台入口判定 + CSRF 令牌回同步（protocol.WebSessionResponse）。 */
@Serializable
data class WebSessionResponse(
    val uid: Long,
    val email: String,
    val role: String,
    val csrfToken: String,
    val totpEnabled: Boolean,
    val passkeyCount: Int,
    val passwordSet: Boolean,
)

/** POST /web/reauth：password / totpCode / recoveryCode 三选一，全空 400。 */
@Serializable
data class WebReauthRequest(
    val password: String = "",
    val totpCode: String = "",
    val recoveryCode: String = "",
)

// ---- Passkey（/webauthn/*、/api/passkeys）----

/**
 * /webauthn/login/finish 与 /web/reauth/webauthn/finish 的请求体：
 * response 是浏览器 PublicKeyCredential 的 JSON（见 WebAuthn.kt 的序列化路径）。
 */
@Serializable
data class PasskeyFinishRequest(
    val ceremonyId: Long,
    val response: JsonElement,
    val app: String = "",
)

/** PATCH /api/passkeys/{id}。 */
@Serializable data class PasskeyRenameRequest(val name: String)

/**
 * /webauthn/register|login|reauth 的 options 回执（ceremonyResponse）：
 * publicKey 是库给浏览器的创建/断言选项整体（内部字段仍是 base64url 字符串）。
 */
@Serializable
data class CeremonyResponse(val publicKey: JsonElement, val ceremonyId: Long)

/** GET /api/passkeys 的一条（auth.PasskeyInfo）；列表本身是裸数组。 */
@Serializable
data class PasskeyInfo(
    val id: Long,
    val name: String,
    val createdAt: Long,
    val lastUsedAt: Long = 0,
    val current: Boolean = false,
)

// ---- 两步验证（/api/totp*）----

/** GET /api/totp 回执（auth.TOTPStatus）：enabled + createdAt（启用时刻或最近 setup 时刻）。 */
@Serializable
data class TotpStatusResponse(val enabled: Boolean = false, val createdAt: Long = 0)

/** POST /api/totp/setup 回执（auth.TOTPSetup）：secret 手输兜底、qrPng 是 data URI 二维码。 */
@Serializable
data class TotpSetupResponse(val secret: String = "", val otpauthUri: String = "", val qrPng: String = "")

/** /api/totp/{enable,disable,regenerate-recovery-codes} 的统一请求体。 */
@Serializable data class CodeRequest(val code: String)

/** enable / regenerate-recovery-codes 的回执：恢复码只在这一次响应里出现。 */
@Serializable data class RecoveryCodesResponse(val recoveryCodes: List<String>)

// ---- 验证码 / 找回与修改（/auth/send-code 等）----

/** POST /auth/send-code：app 可选，只决定邮件品牌（空白 = 中性 Auth）。 */
@Serializable
data class SendCodeRequest(val email: String, val purpose: String, val app: String = "")

/** POST /auth/send-change-code（发码到本人邮箱）与 /auth/send-change-email-code（发到新邮箱）的回执。 */
@Serializable data class SentResponse(val sent: Boolean = true)

@Serializable
data class ResetPasswordRequest(val email: String, val code: String, val password: String)

@Serializable
data class ChangePasswordRequest(val oldPassword: String, val newPassword: String)

@Serializable
data class ChangePasswordCodeRequest(val code: String, val password: String)

/** POST /auth/change-email：password 重验 + 新邮箱验证码，成功回 {ok:true}（会话不吊销）。 */
@Serializable
data class ChangeEmailRequest(val password: String = "", val email: String, val code: String)

/** POST /auth/delete：邮箱验证码确认（老 {password} body 已废，服务端回 400 指引升级）。 */
@Serializable
data class DeleteAccountRequest(val email: String, val code: String)

// ---- 设备/会话管理（GET /api/sessions 等）----

/**
 * 会话列表的一条：id 是 63 位雪花、**十进制字符串**（JSON 数字只有 53 位精度，
 * 抹圆的 id 再踢人会 404）——原样回传，不要转 Long。
 */
@Serializable
data class SessionInfo(
    val id: String,
    val app: String,
    val device: String,
    val ip: String,
    val createdAt: Long,
    val lastSeenAt: Long,
    val current: Boolean = false,
)

/** GET /api/sessions 的对象信封（非裸数组）。 */
@Serializable data class SessionsResponse(val sessions: List<SessionInfo> = emptyList())

/** POST /api/sessions/revoke-many 的请求体（ids 与列表回执同为十进制字符串）。 */
@Serializable data class RevokeManyRequest(val ids: List<String>)

// ---- 档案（/api/profile）----

/** GET /api/profile：avatarImage null = 无头像；updatedAt 毫秒、从未写过为 0。 */
@Serializable
data class ProfileResponse(
    val nickname: String = "",
    val avatarColor: Int = 0,
    val avatarImage: String? = null,
    val updatedAt: Long = 0,
    val loginNotify: Boolean = true,
)

/** PUT /api/profile：三件套全量替换；loginNotify null = 不改值（唯一例外）。 */
@Serializable
data class ProfileUpdateRequest(
    val nickname: String,
    val avatarColor: Int,
    val avatarImage: String? = null,
    val loginNotify: Boolean? = null,
)

// ---- 公开通用 ----

/** GET /web/registry 的一条（ui.RegistryApp）；列表本身是裸数组。 */
@Serializable data class RegistryApp(val key: String, val label: String)

/** 写操作的通用成功回执 {ok:true}。 */
@Serializable data class OkResponse(val ok: Boolean = true)

/** 所有非 2xx 回执的统一体（protocol.ApiError）。 */
@Serializable data class ApiError(val message: String)
