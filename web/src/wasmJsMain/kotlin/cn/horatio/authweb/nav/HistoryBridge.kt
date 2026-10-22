package cn.horatio.authweb.nav

import kotlinx.browser.window
import org.w3c.dom.events.Event

/**
 * 浏览器 History ↔ NavBackStack 桥（Web 端专属胶水，对应 App 的系统返回手势）。
 *
 * - App→URL：每次程序化入栈后调用 [push]，把栈顶映射成 URL——深链可分享、刷新停在原页。
 * - URL→App：popstate 时把栈对齐到 location 映射出的路由——浏览器后退=返回上一页。
 *   pushState 不触发 popstate，天然无回环；replace/pop 都不发新事件给本桥。
 *
 * URL 与 Route 的映射是唯一真相（[pathOf]/[routeOf]），改路由先改这里。
 */
object HistoryBridge {
    /** 路由 → URL（含 query）。 */
    fun pathOf(route: Route): String = when (route) {
        Route.Login -> "/web/login"
        is Route.Authorize -> "/web/authorize" + route.q.querySuffix()
        is Route.Invite -> "/web/invite" + route.token.querySuffix("token")
        is Route.DeleteCancel -> "/web/delete-cancel" + route.token.querySuffix("token")
        Route.Console -> "/web/console"
        Route.Sessions -> "/web/sessions"
        Route.Passkeys -> "/web/passkeys"
        Route.TwoFactor -> "/web/security"
        Route.Account -> "/web/account"
        Route.AdminUsers -> "/web/admin"
        is Route.AdminUserDetail -> "/web/admin/users/${route.uid}"
        Route.AdminAccess -> "/web/admin/access"
        Route.AdminSessions -> "/web/admin/sessions"
        is Route.AdminUserSessions -> "/web/admin/sessions/${route.uid}"
        Route.AdminAudit -> "/web/admin/audit"
        Route.AdminConfig -> "/web/admin/config"
        Route.AdminAi -> "/web/admin/ai"
    }

    /** URL（pathname + search）→ 路由；不认识的路径回 null（调用方留在原栈）。 */
    fun routeOf(pathname: String, search: String): Route? {
        val query = parseQuery(search)
        return when {
            pathname == "/web/login" -> Route.Login
            pathname == "/web/authorize" -> Route.Authorize(search.removePrefix("?"))
            pathname == "/web/invite" -> Route.Invite(query["token"] ?: "")
            pathname == "/web/delete-cancel" -> Route.DeleteCancel(query["token"] ?: "")
            pathname == "/web/console" -> Route.Console
            pathname == "/web/sessions" -> Route.Sessions
            pathname == "/web/passkeys" -> Route.Passkeys
            pathname == "/web/security" -> Route.TwoFactor
            pathname == "/web/account" -> Route.Account
            pathname == "/web/admin" -> Route.AdminUsers
            pathname.startsWith("/web/admin/users/") ->
                pathname.substringAfterLast("/").toLongOrNull()?.let { Route.AdminUserDetail(it) }
            pathname == "/web/admin/access" -> Route.AdminAccess
            pathname == "/web/admin/sessions" -> Route.AdminSessions
            pathname.startsWith("/web/admin/sessions/") ->
                pathname.substringAfterLast("/").toLongOrNull()?.let { Route.AdminUserSessions(it) }
            pathname == "/web/admin/audit" -> Route.AdminAudit
            pathname == "/web/admin/config" -> Route.AdminConfig
            pathname == "/web/admin/ai" -> Route.AdminAi
            else -> null
        }
    }

    /** 当前地址栏 → 路由（含初始进入与前进方向的 popstate）。 */
    fun currentFromLocation(): Route? = routeOf(window.location.pathname, window.location.search)

    /** 程序化入栈：Navigator.push 之后调用，写一条浏览器历史。 */
    fun push(navigator: Navigator, key: Route) {
        navigator.push(key)
        window.history.pushState(null, "", pathOf(key))
    }

    /** 程序化换顶：不产生历史条目（表单页内状态替换等场景）。 */
    fun replace(navigator: Navigator, key: Route) {
        navigator.replaceAll(key)
        window.history.replaceState(null, "", pathOf(key))
    }

    /** 启动接线：初始 URL replaceState 对齐 + popstate 订阅（只装一次）。 */
    fun attach(navigator: Navigator, initial: Route) {
        window.history.replaceState(null, "", pathOf(initial))
        window.addEventListener("popstate", { _: Event ->
            val route = currentFromLocation() ?: return@addEventListener
            when {
                route in navigator.backStack -> navigator.popUntil { it == route }
                // 前进到陌生深链：单路由成栈（浏览器后退再回来时会命中第一条分支）
                else -> navigator.replaceAll(route)
            }
        })
    }

    private fun String.querySuffix(name: String = "q"): String =
        if (isEmpty()) "" else "?$name=$this"

    /** query 解析：本页只透传 URL-safe 值（邀请/撤销 token 均为 hex/base64url），
     *  不做百分号解码——要传非 URL-safe 值时再引 URLSearchParams。 */
    private fun parseQuery(search: String): Map<String, String> =
        search.removePrefix("?")
            .split("&")
            .filter { it.isNotEmpty() }
            .associate {
                val idx = it.indexOf('=')
                if (idx <= 0) it to ""
                else it.substring(0, idx) to it.substring(idx + 1)
            }
}
