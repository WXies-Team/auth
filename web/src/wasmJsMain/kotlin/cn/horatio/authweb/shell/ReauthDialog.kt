// 全局「重新验证身份」弹框（GitHub sudo mode 口径，见 data/ReauthController.kt）。
//
// 生命周期：本组合件把 [ReauthController.promptFlow] 注入成「显示弹框并挂起直到
// 用户完成/取消」的 suspend 实现——CompletableDeferred 承载结果，取消回 false，
// ensure() 侧 await 拿到 false 就抛 401 让原操作中止。
//
// 内容由能力驱动（SessionStore.session 的 passkeyCount / totpEnabled / passwordSet，
// 打开时先 SessionStore.refresh() 兜底一次）：
//   有 Passkey  → 主按钮「使用 Passkey 验证」（viaPasskey，浏览器断言）
//   开了两步验证 → 验证码输入 + 「使用恢复码」互切（viaTotp / viaRecovery）
//   都没有     → 密码框（viaPassword）
package cn.horatio.authweb.shell

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.ui.unit.dp
import cn.horatio.authweb.component.DialogButtonRow
import cn.horatio.authweb.component.TextButton
import cn.horatio.authweb.component.textButtonColorsPrimaryApp
import cn.horatio.authweb.data.ReauthController
import cn.horatio.authweb.data.SessionStore
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.launch
import top.yukonga.miuix.kmp.basic.TextField
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.overlay.OverlayDialog
import top.yukonga.miuix.kmp.theme.MiuixTheme

/** 弹框输入形态：两步验证码 / 恢复码 / 密码。 */
private enum class ReauthMode { Totp, Recovery, Password }

/**
 * 全局重新验证弹框：**挂在 AppRoot 一处**（与 LocalSnackbarHostState 同层），
 * 幂等——没有待处理流程时不渲染任何内容。
 */
@Composable
fun ReauthDialog() {
    val scope = rememberCoroutineScope()

    var show by remember { mutableStateOf(false) }
    var pending by remember { mutableStateOf<CompletableDeferred<Boolean>?>(null) }

    var mode by remember { mutableStateOf(ReauthMode.Totp) }
    var code by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }

    // promptFlow：显示本弹框并挂起，直到完成/取消（取消 → await 拿 false）
    LaunchedEffect(Unit) {
        ReauthController.promptFlow = {
            val gate = CompletableDeferred<Boolean>()
            pending = gate
            code = ""
            password = ""
            error = null
            busy = false
            show = true
            val ok = gate.await()
            show = false
            pending = null
            ok
        }
    }
    DisposableEffect(Unit) {
        onDispose { ReauthController.promptFlow = null }
    }

    // 能力探测：runPrompt 已 refresh 过一次，这里兜底（打开时再刷一次，取最新能力）
    LaunchedEffect(show) {
        if (show) runCatching { SessionStore.refresh() }
    }

    val session = SessionStore.session
    val hasPasskey = (session?.passkeyCount ?: 0) > 0
    val hasTotp = session?.totpEnabled == true
    val hasPassword = session?.passwordSet == true

    // 打开时按能力定初始形态：两步验证优先，其次密码（都没有 → 密码框兜底）
    LaunchedEffect(show) {
        if (show) mode = if (hasTotp) ReauthMode.Totp else ReauthMode.Password
    }

    fun finish(ok: Boolean) {
        pending?.complete(ok)
        pending = null
        show = false
    }

    fun fail(message: String?) {
        error = message ?: "验证失败，请重试"
        busy = false
    }

    if (!show) return

    OverlayDialog(
        show = true,
        onDismissRequest = { if (!busy) finish(false) },
        onDismissFinished = {},
        title = "重新验证身份",
        summary = "为保护账号，敏感操作需要再次确认是你本人。",
    ) {
        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            if (hasPasskey) {
                TextButton(
                    text = if (busy) "等待系统验证…" else "使用 Passkey 验证",
                    enabled = !busy,
                    colors = textButtonColorsPrimaryApp(),
                    modifier = Modifier.fillMaxWidth(),
                    onClick = {
                        if (!busy) {
                            busy = true
                            error = null
                            scope.launch {
                                val ok = ReauthController.viaPasskey()
                                if (ok) {
                                    finish(true)
                                } else {
                                    // 用户在系统弹框里取消：lastError 为空，就地重试不关窗
                                    fail(ReauthController.lastError)
                                }
                            }
                        }
                    },
                )
            }

            when (mode) {
                ReauthMode.Totp -> {
                    TextField(
                        value = code,
                        onValueChange = { code = it },
                        label = "两步验证码（6 位）",
                        singleLine = true,
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                        modifier = Modifier.fillMaxWidth(),
                    )
                    Row2 {
                        TextButton(
                            text = "使用恢复码",
                            onClick = {
                                mode = ReauthMode.Recovery
                                code = ""
                                error = null
                            },
                        )
                        if (hasPassword) {
                            TextButton(
                                text = "改用密码",
                                onClick = {
                                    mode = ReauthMode.Password
                                    password = ""
                                    error = null
                                },
                            )
                        }
                    }
                }
                ReauthMode.Recovery -> {
                    TextField(
                        value = code,
                        onValueChange = { code = it },
                        label = "恢复码（XXXX-XXXX-XXXX-XXXX）",
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                    )
                    Row2 {
                        TextButton(
                            text = "改用两步验证码",
                            onClick = {
                                mode = ReauthMode.Totp
                                code = ""
                                error = null
                            },
                        )
                        if (hasPassword) {
                            TextButton(
                                text = "改用密码",
                                onClick = {
                                    mode = ReauthMode.Password
                                    password = ""
                                    error = null
                                },
                            )
                        }
                    }
                }
                ReauthMode.Password -> {
                    TextField(
                        value = password,
                        onValueChange = { password = it },
                        label = "登录密码",
                        singleLine = true,
                        visualTransformation = PasswordVisualTransformation(),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                        modifier = Modifier.fillMaxWidth(),
                    )
                    if (hasTotp) {
                        Row2 {
                            TextButton(
                                text = "改用两步验证码",
                                onClick = {
                                    mode = ReauthMode.Totp
                                    code = ""
                                    error = null
                                },
                            )
                        }
                    }
                    if (!hasPassword) {
                        Text(
                            text = "该账号未设置密码，请改用 Passkey 或两步验证码。",
                            style = MiuixTheme.textStyles.footnote2,
                            color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                        )
                    }
                }
            }

            error?.let { message ->
                Text(
                    text = message,
                    style = MiuixTheme.textStyles.footnote1,
                    color = MiuixTheme.colorScheme.error,
                    modifier = Modifier.fillMaxWidth(),
                )
            }

            DialogButtonRow(
                confirmText = "验证",
                onConfirm = {
                    if (busy) return@DialogButtonRow
                    when (mode) {
                        ReauthMode.Password -> {
                            if (password.isBlank()) {
                                error = "请输入密码"
                                return@DialogButtonRow
                            }
                        }
                        ReauthMode.Totp -> {
                            if (code.isBlank()) {
                                error = "请输入两步验证码"
                                return@DialogButtonRow
                            }
                        }
                        ReauthMode.Recovery -> {
                            if (code.isBlank()) {
                                error = "请输入恢复码"
                                return@DialogButtonRow
                            }
                        }
                    }
                    busy = true
                    error = null
                    scope.launch {
                        val ok = when (mode) {
                            ReauthMode.Password -> ReauthController.viaPassword(password)
                            ReauthMode.Totp -> ReauthController.viaTotp(code.trim())
                            ReauthMode.Recovery -> ReauthController.viaRecovery(code.trim())
                        }
                        if (ok) {
                            finish(true)
                        } else {
                            fail(ReauthController.lastError)
                        }
                    }
                },
                onCancel = { if (!busy) finish(false) },
                confirmColors = textButtonColorsPrimaryApp(),
            )
        }
    }
}

/** 弹框内的横向小按钮行（切换验证方式用）。 */
@Composable
private fun Row2(content: @Composable androidx.compose.foundation.layout.RowScope.() -> Unit) {
    androidx.compose.foundation.layout.Row(
        Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        content = content,
    )
}
