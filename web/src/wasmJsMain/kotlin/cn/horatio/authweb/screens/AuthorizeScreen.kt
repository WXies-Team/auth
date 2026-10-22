// 公开页 · OAuth 授权确认：行为规格 = 旧 internal/ui/templates/authorize.html（零 JS 轻确认页）。
//
// 与任务书的一处偏差（以 Go handler 为准，cmd/server/oauth.go oauthConfirm）：
// POST /oauth/authorize/confirm 只收 **tx + decision** 两个表单字段，不收原 query 字段；
// tx 由 GET /oauth/authorize（OAuthBeginAuthorize）落内存事务后随 HTML 确认页下发。
// 当前后端没有「begin 授权事务」的 JSON 端点，故本屏在已登录时先 GET /oauth/authorize?<q>
// （同源、带 cookie）从返回的确认页 HTML 里抽 hidden tx（旧模板同一字段名），确认按钮
// 走**真实表单 POST 提交**（与旧零 JS 页同款）——302 到第三方 redirect_uri 是整页导航，
// fetch 跟不了跨域跳转，表单提交才是该端点的原生语义。需要主控补的 JSON 端点见交付报告。
@file:OptIn(kotlin.js.ExperimentalWasmJsInterop::class)

package cn.horatio.authweb.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.Alignment
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import cn.horatio.authweb.component.TextButton
import cn.horatio.authweb.component.buttonColorsPrimaryApp
import cn.horatio.authweb.data.SessionStore
import cn.horatio.authweb.nav.LocalNav
import cn.horatio.authweb.nav.Route
import cn.horatio.authweb.screens.admin.appLabels
import kotlinx.browser.window
import kotlinx.coroutines.await
import top.yukonga.miuix.kmp.basic.Button
import top.yukonga.miuix.kmp.basic.Card
import top.yukonga.miuix.kmp.basic.CircularProgressIndicator
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.theme.MiuixTheme

@Composable
fun AuthorizeScreen(q: String = "") {
    val nav = LocalNav.current

    // route.q 是原始 query 串（HistoryBridge 直存 search 去「?」）；深链直进时 route 可能没带
    val rawQuery = q.ifEmpty { window.location.search.removePrefix("?") }
    val params = remember(rawQuery) { parseRawQuery(rawQuery) }
    val clientId = params["client_id"] ?: ""
    val redirectHost = remember(params["redirect_uri"]) { hostOf(params["redirect_uri"].orEmpty()) }

    var loaded by remember { mutableStateOf(false) }
    var authed by remember { mutableStateOf(false) }
    var appName by remember { mutableStateOf(clientId) }
    var tx by remember { mutableStateOf("") }
    var beginError by remember { mutableStateOf<String?>(null) }

    LaunchedEffect(Unit) {
        // 项目展示名（注册表 slug→label，进程内缓存）
        appName = appLabels()[clientId] ?: clientId
        val session = runCatching { SessionStore.refresh() }.getOrNull()
        authed = session != null
        if (session != null && clientId.isNotEmpty()) {
            // 取授权事务：后端经 GET /oauth/authorize 落 tx 并渲染确认页；这里只要 hidden tx
            try {
                val res = window.fetch("/oauth/authorize?$rawQuery").await()
                val body = res.text().await().toString()
                if (res.ok) {
                    val found = Regex("name=\"tx\" value=\"([^\"]+)\"").find(body)?.groupValues?.get(1)
                    if (found != null) {
                        tx = found
                    } else {
                        beginError = "无法发起授权，请重新发起后重试"
                    }
                } else {
                    // 错误页变体（authorize.html 双变体）：dim 段落即服务端中文文案
                    beginError = Regex("class=\"dim\" style=\"margin-top:8px\">([^<]*)<")
                        .find(body)?.groupValues?.get(1)?.takeIf { it.isNotBlank() }
                        ?: "无法发起授权，请重新发起后重试"
                }
            } catch (e: Exception) {
                beginError = e.message ?: "无法发起授权，请稍后重试"
            }
        }
        loaded = true
    }

    PublicPageShell {
        Card(Modifier.fillMaxWidth().padding(top = 20.dp)) {
            Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                when {
                    clientId.isEmpty() -> {
                        Text(
                            text = "无法继续授权",
                            style = MiuixTheme.textStyles.title2,
                            color = MiuixTheme.colorScheme.onSurface,
                        )
                        Text(
                            text = "授权请求缺少 client_id 参数，请让应用重新发起授权。",
                            style = MiuixTheme.textStyles.footnote1,
                            color = MiuixTheme.colorScheme.onSurfaceSecondary,
                        )
                        TextButton(
                            text = "回到控制台",
                            onClick = { nav.push(Route.Console) },
                            modifier = Modifier.fillMaxWidth(),
                        )
                    }
                    !loaded -> {
                        Column(Modifier.fillMaxWidth(), horizontalAlignment = Alignment.CenterHorizontally) {
                            CircularProgressIndicator()
                        }
                    }
                    !authed -> {
                        Text(
                            text = "请先登录",
                            style = MiuixTheme.textStyles.title2,
                            color = MiuixTheme.colorScheme.onSurface,
                        )
                        Text(
                            text = "登录后再继续授权「$appName」。",
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
                    }
                    beginError != null -> {
                        Text(
                            text = "无法继续授权",
                            style = MiuixTheme.textStyles.title2,
                            color = MiuixTheme.colorScheme.onSurface,
                        )
                        Text(
                            text = beginError ?: "",
                            style = MiuixTheme.textStyles.footnote1,
                            color = MiuixTheme.colorScheme.onSurfaceSecondary,
                        )
                        TextButton(
                            text = "回到控制台",
                            onClick = { nav.push(Route.Console) },
                            modifier = Modifier.fillMaxWidth(),
                        )
                    }
                    else -> {
                        Text(
                            text = "授权登录「$appName」",
                            style = MiuixTheme.textStyles.title2,
                            color = MiuixTheme.colorScheme.onSurface,
                        )
                        Text(
                            text = "当前账号：${SessionStore.session?.email.orEmpty()}",
                            style = MiuixTheme.textStyles.footnote1,
                            color = MiuixTheme.colorScheme.onSurfaceSecondary,
                        )
                        Text(
                            text = "登录到「$appName」后，它将获得你的账号标识与邮箱。",
                            style = MiuixTheme.textStyles.body2,
                            color = MiuixTheme.colorScheme.onSurface,
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(top = 4.dp),
                        )
                        Text(
                            // 只显示 host：redirect_uri 原值回显会给钓鱼页面当镜子（oauth.go 同口径）
                            text = "回跳地址：${redirectHost.ifEmpty { "（未提供）" }}",
                            style = MiuixTheme.textStyles.footnote1,
                            color = MiuixTheme.colorScheme.onSurfaceSecondary,
                        )
                        Button(
                            onClick = { submitAuthorizeDecision(tx, "allow") },
                            modifier = Modifier.fillMaxWidth().padding(top = 4.dp),
                            colors = buttonColorsPrimaryApp(),
                        ) {
                            Text(text = "继续")
                        }
                        TextButton(
                            text = "取消",
                            onClick = { submitAuthorizeDecision(tx, "deny") },
                            modifier = Modifier.fillMaxWidth(),
                        )
                    }
                }
            }
        }
    }
}

// ---- 原始 query 手写解析（本页只透传 URL-safe 值；redirect_uri 展示前做百分号解码）----

private fun parseRawQuery(raw: String): Map<String, String> =
    raw.removePrefix("?")
        .split("&")
        .filter { it.isNotEmpty() }
        .associate {
            val idx = it.indexOf('=')
            if (idx <= 0) it to ""
            else it.substring(0, idx) to it.substring(idx + 1).percentDecode()
        }

/** 百分号解码（UTF-8 字节聚合后 decodeToString）；无 % 原样返回。 */
private fun String.percentDecode(): String {
    if ('%' !in this) return this
    val out = ArrayList<Byte>(length)
    var i = 0
    while (i < length) {
        val c = this[i]
        if (c == '%' && i + 2 < length) {
            val hi = this[i + 1].digitToHex()
            val lo = this[i + 2].digitToHex()
            if (hi >= 0 && lo >= 0) {
                out.add(((hi shl 4) or lo).toByte())
                i += 3
                continue
            }
        }
        // 非编码字面量：按 UTF-8 收字节（本页输入是 ASCII 与中文邮箱/URI）
        for (b in c.toString().encodeToByteArray()) out.add(b)
        i++
    }
    return out.toByteArray().decodeToString()
}

private fun Char.digitToHex(): Int = when (this) {
    in '0'..'9' -> this - '0'
    in 'a'..'f' -> this - 'a' + 10
    in 'A'..'F' -> this - 'A' + 10
    else -> -1
}

/** 从（已解码的）redirect_uri 取 host：scheme://host/path → host；取不到回原串首段。 */
private fun hostOf(uri: String): String {
    if (uri.isEmpty()) return ""
    val afterScheme = uri.substringAfter("://", uri)
    return afterScheme.substringBefore("/").substringBefore("?").substringBefore("#")
}

/**
 * 确认/取消：真实表单 POST（旧 authorize.html 的零 JS 提交同款）——服务端 302 到
 * 第三方 redirect_uri（带 code 或 error=access_denied），整页导航才能把用户送过去。
 * Kotlin/Wasm 的 String 参数自动转换为 JS string。
 */
@JsFun(
    """
    (tx, decision) => {
      const form = document.createElement('form');
      form.method = 'post';
      form.action = '/oauth/authorize/confirm';
      const add = (name, value) => {
        const input = document.createElement('input');
        input.type = 'hidden';
        input.name = name;
        input.value = String(value);
        form.appendChild(input);
      };
      add('tx', tx);
      add('decision', decision);
      document.body.appendChild(form);
      form.submit();
    }
    """,
)
private external fun submitAuthorizeDecision(tx: String, decision: String)
