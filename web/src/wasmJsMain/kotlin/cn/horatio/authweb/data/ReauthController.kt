// 重新验证（sudo mode）控制器：全局单例，保证同一时刻只有一份弹框流程在飞。
//
// 服务端语义（cmd/server/web.go）：/admin/* 与部分写操作（reauthed）要求 2 小时内
// 强认证，过期回 401「需要重新验证身份」——UI 捕获后调 [ReauthController.ensure]，
// 弹框成功后重放原请求。
//
//   POST /web/reauth                      密码/两步验证码/恢复码三选一
//   POST /web/reauth/webauthn/options     Passkey 断言选项（CeremonyResponse）
//   POST /web/reauth/webauthn/finish      断言结果（PasskeyFinishRequest）
//
// 能力探测：SessionStore.refresh() 一次拿 totpEnabled / passkeyCount / passwordSet，
// UI 据此决定弹框里摆哪几个入口（有 passkey 才给 Passkey 按钮，无密码不给密码框）。
package cn.horatio.authweb.data

import kotlinx.coroutines.CompletableDeferred

object ReauthController {
    /**
     * UI 层注入的弹框流程：内部逐个尝试 [viaPassword] / [viaTotp] / [viaRecovery] /
     * [viaPasskey]，全部失败（含用户取消）回 false。控制器只管并发单例语义。
     */
    var promptFlow: (suspend () -> Boolean)? = null

    /** 在飞的验证流程；所有并发 ensure() 共享同一份结果。 */
    private var reauthJob: CompletableDeferred<Boolean>? = null

    /**
     * 确保已通过强认证：在飞则等待同一份结果；否则启动 [promptFlow]。
     * 成功正常返回；流程失败/未注入时抛 [ApiException](401) 让调用方中止原操作。
     * 无流程在飞时的重复调用会各自启动新弹框——这是刻意的：上一轮已失败，重试是新一轮。
     */
    suspend fun ensure() {
        val job = reauthJob ?: CompletableDeferred<Boolean>().also { fresh ->
            reauthJob = fresh
            // 流程异常也要让并发等待者解脱：completeExceptionally 后 await 会重抛
            val ok = try {
                runPrompt()
            } catch (t: Throwable) {
                fresh.completeExceptionally(t)
                reauthJob = null
                throw t
            }
            fresh.complete(ok)
            reauthJob = null
        }
        if (!job.await()) throw ApiException(401, "需要重新验证身份")
    }

    private suspend fun runPrompt(): Boolean {
        val flow = promptFlow ?: return false
        // 能力探测先行：弹框读 SessionStore.session 决定入口；失败也继续（流程里各 via* 自会报错）
        runCatching { SessionStore.refresh() }
        return flow()
    }

    /** Passkey 路：options → 浏览器断言 → finish。用户取消回 false（不置错误文案）。 */
    suspend fun viaPasskey(): Boolean {
        lastError = null
        return try {
            val ceremony = Api.post<CeremonyResponse>("/web/reauth/webauthn/options")
            val credential = getAssertion(ceremony.publicKey) ?: return false
            Api.post<OkResponse>(
                "/web/reauth/webauthn/finish",
                Api.encode(PasskeyFinishRequest(ceremony.ceremonyId, credential)),
            )
            true
        } catch (e: ApiException) {
            lastError = e.message
            false
        }
    }

    /** 两步验证码路（POST /web/reauth 的 totpCode）。 */
    suspend fun viaTotp(code: String): Boolean = reauth(WebReauthRequest(totpCode = code))

    /** 恢复码路（POST /web/reauth 的 recoveryCode）。 */
    suspend fun viaRecovery(code: String): Boolean = reauth(WebReauthRequest(recoveryCode = code))

    /** 密码路（POST /web/reauth 的 password）。 */
    suspend fun viaPassword(password: String): Boolean = reauth(WebReauthRequest(password = password))

    /** 最近一次失败的错误文案，供弹框就地展示（成功或换入口时置 null）。 */
    var lastError: String? = null
        private set

    private suspend fun reauth(body: WebReauthRequest): Boolean {
        lastError = null
        return try {
            Api.post<OkResponse>("/web/reauth", Api.encode(body))
            true
        } catch (e: ApiException) {
            lastError = e.message
            false
        }
    }
}
