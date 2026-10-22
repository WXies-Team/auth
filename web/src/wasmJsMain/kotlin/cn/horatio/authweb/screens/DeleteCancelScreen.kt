// 公开页 · 注销撤销：行为规格 = 旧 GET /web/delete-cancel 内嵌页（web.go writeDeleteCancelPage，
// 确认卡 + 「撤销注销」→ 成功换「注销已撤销」结果卡；无需登录——token 即凭证）。
// 接口：POST /web/delete-cancel {token}（jsonBody，非表单），成功 {ok:true}，失败 ApiError 一句中文。
@file:OptIn(kotlin.js.ExperimentalWasmJsInterop::class)

package cn.horatio.authweb.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import cn.horatio.authweb.component.buttonColorsPrimaryApp
import cn.horatio.authweb.data.Api
import cn.horatio.authweb.data.OkResponse
import cn.horatio.authweb.nav.LocalNav
import cn.horatio.authweb.nav.Route
import cn.horatio.authweb.theme.OnCardColors
import kotlinx.browser.window
import kotlinx.coroutines.launch
import top.yukonga.miuix.kmp.basic.Button
import top.yukonga.miuix.kmp.basic.Card
import top.yukonga.miuix.kmp.basic.InfiniteProgressIndicator
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.theme.MiuixTheme

/** 当前地址栏 query 里的 token（与 Route.DeleteCancel.token 同源；深链直进时 route 可能没带）。 */
private fun tokenFromLocation(): String =
    window.location.search.removePrefix("?")
        .split("&")
        .firstNotNullOfOrNull {
            val idx = it.indexOf('=')
            if (idx > 0 && it.substring(0, idx) == "token") it.substring(idx + 1) else null
        } ?: ""

@Composable
fun DeleteCancelScreen(token: String = "") {
    val scope = rememberCoroutineScope()
    val nav = LocalNav.current

    val tok = token.ifEmpty { tokenFromLocation() }
    var busy by remember { mutableStateOf(false) }
    var done by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }

    /** 撤销提交：成功换结果卡（旧页同款两态切换）；失败就地一句中文。 */
    fun cancel() {
        if (busy) return
        scope.launch {
            busy = true
            error = null
            try {
                Api.post<OkResponse>("/web/delete-cancel", Api.encode(DeleteCancelRequest(token = tok)))
                done = true
            } catch (e: Exception) {
                error = e.message ?: "撤销失败，请稍后重试"
            } finally {
                busy = false
            }
        }
    }

    PublicPageShell {
        Card(Modifier.fillMaxWidth().padding(top = 20.dp)) {
            Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                if (done) {
                    // 结果卡（旧页 done 分支同款文案）
                    Text(
                        text = "注销已撤销",
                        style = MiuixTheme.textStyles.title2,
                        color = MiuixTheme.colorScheme.onSurface,
                    )
                    Text(
                        text = "你的注销申请已撤销，账号与数据一切如常。",
                        style = MiuixTheme.textStyles.footnote1,
                        color = MiuixTheme.colorScheme.onSurfaceSecondary,
                    )
                    Button(
                        onClick = { nav.push(Route.Login) },
                        modifier = Modifier.fillMaxWidth(),
                        colors = buttonColorsPrimaryApp(),
                    ) {
                        Text(text = "前往登录")
                    }
                } else {
                    Text(
                        text = "注销确认",
                        style = MiuixTheme.textStyles.title2,
                        color = MiuixTheme.colorScheme.onSurface,
                    )
                    Text(
                        text = "你正在撤销此前提交的注销申请。撤销后账号与数据一切如常，随时可以重新登录。",
                        style = MiuixTheme.textStyles.footnote1,
                        color = MiuixTheme.colorScheme.onSurfaceSecondary,
                    )
                    Text(
                        text = "如果不是你本人操作，请撤销后立即修改密码并检查登录设备。",
                        style = MiuixTheme.textStyles.footnote1,
                        color = OnCardColors.danger,
                    )
                    if (tok.isEmpty()) {
                        InlineError(text = "撤销链接不完整，请从注销确认邮件重新打开。")
                        Button(
                            onClick = { nav.push(Route.Login) },
                            modifier = Modifier.fillMaxWidth(),
                            colors = buttonColorsPrimaryApp(),
                        ) {
                            Text(text = "前往登录")
                        }
                    } else {
                        InlineError(text = error)
                        Button(
                            onClick = { cancel() },
                            enabled = !busy,
                            modifier = Modifier.fillMaxWidth(),
                            colors = buttonColorsPrimaryApp(),
                        ) {
                            if (busy) {
                                InfiniteProgressIndicator(color = Color.White, size = 20.dp)
                            } else {
                                Text(text = "撤销注销")
                            }
                        }
                    }
                }
            }
        }
    }
}

/** POST /web/delete-cancel 的请求体（web.go deleteCancelRequest：{token}）。 */
@kotlinx.serialization.Serializable
private data class DeleteCancelRequest(val token: String)
