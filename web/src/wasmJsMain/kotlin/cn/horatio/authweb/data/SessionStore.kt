// 会话状态单例：POST /web/session（cmd/server/web.go）的装载与清空。
// 页面通过 isAuthed/isAdmin 做入口判定；csrfToken 同步进 Api 供非 GET 请求附带。
@file:OptIn(kotlin.js.ExperimentalWasmJsInterop::class)

package cn.horatio.authweb.data

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue

object SessionStore {
    /** null = 未登录；装载成功 = cookie 会话有效。 */
    var session: WebSessionResponse? by mutableStateOf(null)

    val isAuthed: Boolean get() = session != null
    val isSuper: Boolean get() = session?.role == "super"
    val isAdmin: Boolean get() = session?.role == "admin" || isSuper

    /**
     * 拉取当前会话：成功 → 装载并把 csrfToken 同步进 [Api]；401 → 清空回 null；
     * 其它错误（网络/5xx）向上抛，调用方自行决定重试或提示。
     */
    suspend fun refresh(): WebSessionResponse? {
        val res = Api.request("POST", "/web/session", "{}")
        if (res.status == 401) {
            clear()
            return null
        }
        val s = res.json<WebSessionResponse>()
        session = s
        Api.csrfToken = s.csrfToken
        return s
    }

    /** 登出或 401 收口：清内存态与 CSRF 令牌（cookie 由 /web/logout 服务端清）。 */
    fun clear() {
        session = null
        Api.csrfToken = ""
    }
}
