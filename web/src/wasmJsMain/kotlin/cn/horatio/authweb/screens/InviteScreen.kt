// 公开页 · 接受邀请：行为规格 = 旧 internal/ui/templates/invite.html（服务端渲染含只读邮箱）。
// 后端现状（cmd/server/web.go POST /web/invite）：零 JS 表单端点，字段 token/password/nickname，
// 成功 = 建号 + 种 web cookie + 302 /web/console（AcceptInvite 自动登录）。
// **没有取邀请信息的 JSON 端点**（GET /web/invite 只渲染 HTML）——故本屏不做只读邮箱展示，
// 表单自足；需要的端点形状见交付报告（GET /web/invite/info?token= → {email,appLabel,valid}）。
@file:OptIn(kotlin.js.ExperimentalWasmJsInterop::class)

package cn.horatio.authweb.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import cn.horatio.authweb.component.buttonColorsPrimaryApp
import cn.horatio.authweb.data.Api
import cn.horatio.authweb.data.HttpResponse
import cn.horatio.authweb.data.SessionStore
import cn.horatio.authweb.nav.LocalNav
import cn.horatio.authweb.nav.Route
import cn.horatio.authweb.screens.admin.urlEnc
import cn.horatio.authweb.shell.LocalSnackbarHostState
import kotlin.js.toJsString
import kotlinx.browser.window
import kotlinx.coroutines.await
import kotlinx.coroutines.launch
import org.w3c.fetch.Headers
import org.w3c.fetch.RequestInit
import top.yukonga.miuix.kmp.basic.Button
import top.yukonga.miuix.kmp.basic.Card
import top.yukonga.miuix.kmp.basic.InfiniteProgressIndicator
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.basic.TextField
import top.yukonga.miuix.kmp.theme.MiuixTheme

/** 当前地址栏 query 里的 token（与 Route.Invite.token 同源；深链直进时 route 可能没带）。 */
private fun tokenFromLocation(): String =
    window.location.search.removePrefix("?")
        .split("&")
        .firstNotNullOfOrNull {
            val idx = it.indexOf('=')
            if (idx > 0 && it.substring(0, idx) == "token") it.substring(idx + 1) else null
        } ?: ""

@Composable
fun InviteScreen(token: String = "") {
    val scope = rememberCoroutineScope()
    val nav = LocalNav.current
    val snackbarHostState = LocalSnackbarHostState.current

    val tok = token.ifEmpty { tokenFromLocation() }
    var password by remember { mutableStateOf("") }
    var nickname by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }

    /** 提交（表单编码）：成功 = 服务端已种会话 cookie（302 控制台被 fetch 跟随），刷新后进控制台。 */
    fun submit() {
        if (busy) return
        if (password.length < 8) { error = "密码至少 8 位"; return }
        if (nickname.length > 64) { error = "昵称最多 64 个字"; return }
        scope.launch {
            busy = true
            error = null
            try {
                val res = postInviteForm(tok, password, nickname.trim())
                if (res.status in 200..299) {
                    runCatching { SessionStore.refresh() }
                    snackbarHostState.showSnackbar("注册成功，已自动登录")
                    if (SessionStore.isAuthed) nav.push(Route.Console) else nav.push(Route.Login)
                } else {
                    // 业务打回是 400 + 重渲染的邀请页 HTML（非 JSON）：就地抽错误段落
                    error = inviteHtmlError(res.body) ?: "邀请链接无效或已过期，请联系邀请人重新发送"
                }
            } catch (e: Exception) {
                error = e.message ?: "提交失败，请稍后重试"
            } finally {
                busy = false
            }
        }
    }

    PublicPageShell {
        Card(Modifier.fillMaxWidth().padding(top = 20.dp)) {
            Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(
                    text = "接受邀请",
                    style = MiuixTheme.textStyles.title2,
                    color = MiuixTheme.colorScheme.onSurface,
                )
                if (tok.isEmpty()) {
                    // 链接缺 token：无从提交，给一条出路（旧错误页变体同款文案）
                    Text(
                        text = "邀请链接不完整，请从邀请邮件重新打开。",
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
                        text = "你被邀请注册 Auth 账号；设置密码即可完成注册并自动登录。",
                        style = MiuixTheme.textStyles.footnote1,
                        color = MiuixTheme.colorScheme.onSurfaceSecondary,
                    )
                    TextField(
                        colors = fieldLabelColors(),
                        value = password,
                        onValueChange = { password = it; error = null },
                        enabled = !busy,
                        label = "设置密码（至少 8 位）",
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                        visualTransformation = PasswordVisualTransformation(),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password, imeAction = ImeAction.Next),
                    )
                    TextField(
                        colors = fieldLabelColors(),
                        value = nickname,
                        onValueChange = { nickname = it; error = null },
                        enabled = !busy,
                        label = "昵称（选填）",
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Text, imeAction = ImeAction.Done),
                    )
                    InlineError(text = error)
                    Button(
                        onClick = { submit() },
                        enabled = !busy,
                        modifier = Modifier.fillMaxWidth(),
                        colors = buttonColorsPrimaryApp(),
                    ) {
                        if (busy) {
                            InfiniteProgressIndicator(color = Color.White, size = 20.dp)
                        } else {
                            Text(text = "设置密码并完成注册")
                        }
                    }
                    Text(
                        text = "邀请链接 24 小时内有效，且只能使用一次。",
                        style = MiuixTheme.textStyles.footnote2,
                        color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                    )
                }
            }
        }
    }
}

/**
 * 表单编码 POST /web/invite：数据层（data/Api）只会说 JSON，而本端点是零 JS 表单端点
 * （web.go r.ParseForm 只认 x-www-form-urlencoded），且交付范围不含 data/——故就地一条 fetch。
 * 302 到 /web/console 由浏览器默认跟随，成功判 final 2xx。
 */
private suspend fun postInviteForm(token: String, password: String, nickname: String): HttpResponse {
    val headers = Headers()
    headers.append("Content-Type", "application/x-www-form-urlencoded")
    val body = buildString {
        append("token=").append(urlEnc(token))
        append("&password=").append(urlEnc(password))
        append("&nickname=").append(urlEnc(nickname))
    }
    val res = window.fetch(
        "/web/invite",
        RequestInit(method = "POST", headers = headers, body = body.toJsString()),
    ).await()
    return HttpResponse(res.status.toInt(), res.text().await().toString())
}

/**
 * 从打回的邀请页 HTML 抽一句中文错误：表单重渲染变体在 role="alert" 段落，
 * token 失效的错误卡变体在 dim 段落（ui.go renderInvitePage/renderInviteError 两处模板）。
 */
private fun inviteHtmlError(body: String): String? {
    val alert = Regex("role=\"alert\">([^<]*)<").find(body)?.groupValues?.get(1)
    if (!alert.isNullOrBlank()) return unescapeHtml(alert)
    val dim = Regex("class=\"dim\" style=\"margin-top:8px\">([^<]*)<").find(body)?.groupValues?.get(1)
    return dim?.takeIf { it.isNotBlank() }?.let { unescapeHtml(it) }
}

/** html/template 的四种实体反转义（错误文案里出现即救，不引库）。 */
private fun unescapeHtml(s: String): String = s
    .replace("&lt;", "<")
    .replace("&gt;", ">")
    .replace("&quot;", "\"")
    .replace("&#39;", "'")
    .replace("&amp;", "&")
