package cn.horatio.authweb.nav

import kotlinx.serialization.Serializable
import top.yukonga.miuix.kmp.nav.core.NavKey

/**
 * auth web 全部路由。与既有 URL 路径一一对应（HistoryBridge 用它做深链）：
 * /web/login、/web/console、/web/sessions、/web/passkeys、/web/security、
 * /web/account、/web/admin、/web/admin/access、/web/admin/sessions、
 * /web/admin/audit、/web/admin/config、/web/admin/ai。
 */
@Serializable
sealed interface Route : NavKey {
    // ---- 公开页（无会话也能进）----
    @Serializable data object Login : Route
    /** OAuth 授权确认页；q 是原始 query 串（client_id/redirect_uri/state 原样带回） */
    @Serializable data class Authorize(val q: String = "") : Route
    /** 接受邀请页；token 缺省 = 从 URL query 现取 */
    @Serializable data class Invite(val token: String = "") : Route
    /** 注销撤销页（邮件里的取消链接） */
    @Serializable data class DeleteCancel(val token: String = "") : Route

    // ---- 控制台 ----
    @Serializable data object Console : Route
    @Serializable data object Sessions : Route
    @Serializable data object Passkeys : Route
    @Serializable data object TwoFactor : Route
    @Serializable data object Account : Route

    // ---- 管理后台 ----
    @Serializable data object AdminUsers : Route
    @Serializable data class AdminUserDetail(val uid: Long) : Route
    @Serializable data object AdminAccess : Route
    @Serializable data object AdminSessions : Route
    @Serializable data class AdminUserSessions(val uid: Long) : Route
    @Serializable data object AdminAudit : Route
    @Serializable data object AdminConfig : Route
    @Serializable data object AdminAi : Route
}
