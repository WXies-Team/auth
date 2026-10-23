// 公开页 · 登录：行为规格 = 旧 internal/ui/templates/login.html + app.js initLogin
// （密码登录含 2FA 单输入三态、邮箱验证码登录、找回密码、强制改密步、Passkey 登录）。
// 接口权威 = cmd/server/web.go 的 /web/login/* 与 /auth/*。公开页无顶栏：直接 Box 布局
//（旧 Minimal 壳同款），不走 ScreenScaffold。
@file:OptIn(kotlin.js.ExperimentalWasmJsInterop::class)

package cn.horatio.authweb.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import cn.horatio.authweb.component.TextButton
import cn.horatio.authweb.component.buttonColorsPrimaryApp
import cn.horatio.authweb.data.Api
import cn.horatio.authweb.data.AuthResponse
import cn.horatio.authweb.data.ChangePasswordRequest
import cn.horatio.authweb.data.CeremonyResponse
import cn.horatio.authweb.data.HttpResponse
import cn.horatio.authweb.data.OkResponse
import cn.horatio.authweb.data.PasskeyFinishRequest
import cn.horatio.authweb.data.ReauthController
import cn.horatio.authweb.data.ResetPasswordRequest
import cn.horatio.authweb.data.SendCodeRequest
import cn.horatio.authweb.data.SentResponse
import cn.horatio.authweb.data.SessionStore
import cn.horatio.authweb.data.WebLoginCodeRequest
import cn.horatio.authweb.data.WebLoginPending
import cn.horatio.authweb.data.WebLoginRequest
import cn.horatio.authweb.data.WebLoginTOTPRequest
import cn.horatio.authweb.data.getAssertion
import cn.horatio.authweb.data.json
import cn.horatio.authweb.icons.AppIcon
import cn.horatio.authweb.nav.LocalNav
import cn.horatio.authweb.nav.Route
import cn.horatio.authweb.shell.LocalSnackbarHostState
import com.composables.icons.lucide.KeyRound
import com.composables.icons.lucide.Lucide
import kotlinx.coroutines.launch
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.jsonObject
import top.yukonga.miuix.kmp.basic.Button
import top.yukonga.miuix.kmp.basic.Card
import top.yukonga.miuix.kmp.basic.InfiniteProgressIndicator
import top.yukonga.miuix.kmp.basic.TabRowDefaults
import top.yukonga.miuix.kmp.basic.TabRowWithContour
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.basic.TextField
import top.yukonga.miuix.kmp.theme.MiuixTheme

/** 登录页三档 tab（旧 login.html 的 tabs）。 */
private enum class LoginTab(val label: String) { PASSWORD("密码登录"), CODE("邮箱验证码"), RESET("找回密码") }

/** 2FA 第二步单输入的三态（旧 app.js makeCodeToggle 同构：验证器码 / 邮箱码 / 恢复码）。 */
private enum class TotpMode { CODE, EMAIL, RECOVERY }

@Composable
fun LoginScreen() {
    val scope = rememberCoroutineScope()
    val nav = LocalNav.current
    val snackbarHostState = LocalSnackbarHostState.current

    // 进屏判已登录（旧 gatePublic 同款语义）：有会话直接进控制台；NavController 无
    // 单路由 replace，按规格退 push。
    LaunchedEffect(Unit) {
        if (runCatching { SessionStore.refresh() }.getOrNull() != null) {
            nav.replaceAll(Route.Console)
        }
    }

    var tab by remember { mutableStateOf(LoginTab.PASSWORD) }
    var busy by remember { mutableStateOf(false) }
    var sending by remember { mutableStateOf(false) }

    // 密码登录 + 2FA 第二步
    var email by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var loginToken by remember { mutableStateOf("") } // 非空 = 已在第二步（服务端 login_states 中间态）
    var enteredPw by remember { mutableStateOf("") } // 第一步确认过的密码，强制改密步作 oldPassword 带上
    var totpMode by remember { mutableStateOf(TotpMode.CODE) }
    var totpValue by remember { mutableStateOf("") }
    var totpEmailSent by remember { mutableStateOf(false) }
    var loginError by remember { mutableStateOf<String?>(null) }
    val totpCooldown = rememberCooldown()

    // 邮箱验证码登录
    var codeEmail by remember { mutableStateOf("") }
    var codeValue by remember { mutableStateOf("") }
    var codeError by remember { mutableStateOf<String?>(null) }
    val codeCooldown = rememberCooldown()

    // 找回密码
    var resetEmail by remember { mutableStateOf("") }
    var resetCode by remember { mutableStateOf("") }
    var resetPassword by remember { mutableStateOf("") }
    var resetError by remember { mutableStateOf<String?>(null) }
    val resetCooldown = rememberCooldown()

    // 强制改密步（登录回执 mustChangePassword=true 时顶替整个卡片，旧 step-force-pw）
    var forceMode by remember { mutableStateOf(false) }
    var forceOldPw by remember { mutableStateOf("") }
    var forceNew by remember { mutableStateOf("") }
    var forceConfirm by remember { mutableStateOf("") }
    var forceError by remember { mutableStateOf<String?>(null) }

    // Passkey
    val supportsPasskey = remember { supportsWebAuthn() }
    var passkeyError by remember { mutableStateOf<String?>(null) }

    fun goConsole() {
        scope.launch {
            runCatching { SessionStore.refresh() }
            nav.replaceAll(Route.Console)
        }
    }

    /** 四条登录路（密码 / 2FA 完成 / 邮箱验证码 / Passkey）的统一收口。 */
    fun finishLogin(res: AuthResponse, oldPw: String) {
        if (res.deletePendingCancelled) {
            scope.launch { snackbarHostState.showSnackbar("已撤销账号注销，账号恢复正常") }
        }
        if (res.mustChangePassword) {
            forceMode = true
            forceOldPw = oldPw
            forceNew = ""
            forceConfirm = ""
            forceError = null
            return
        }
        goConsole()
    }

    /** 密码 tab 提交：无 loginToken 走第一步，有则按当前三态组字段走第二步。 */
    fun submitPassword() {
        if (busy) return
        if (loginToken.isEmpty()) {
            val em = email.trim()
            if (em.isEmpty()) { loginError = "请先填写邮箱"; return }
            if (password.isEmpty()) { loginError = "请输入密码"; return }
            scope.launch {
                busy = true
                loginError = null
                try {
                    val res = Api.request(
                        "POST", "/web/login/password",
                        Api.encode(WebLoginRequest(email = em, password = password)),
                    ).loginOutcome()
                    when (res) {
                        is LoginOutcome.Pending -> {
                            loginToken = res.pending.loginToken
                            enteredPw = password
                            totpMode = TotpMode.CODE
                            totpValue = ""
                            totpEmailSent = false
                        }
                        is LoginOutcome.Done -> finishLogin(res.done, password)
                    }
                } catch (e: Exception) {
                    loginError = e.message ?: "登录失败，请稍后重试"
                } finally {
                    busy = false
                }
            }
        } else {
            val v = totpValue.trim()
            if (v.isEmpty()) {
                loginError = when (totpMode) {
                    TotpMode.CODE -> "请输入两步验证码"
                    TotpMode.EMAIL -> "请输入邮箱验证码"
                    TotpMode.RECOVERY -> "请输入恢复码"
                }
                return
            }
            val body = when (totpMode) {
                TotpMode.CODE -> WebLoginTOTPRequest(loginToken = loginToken, code = v)
                TotpMode.EMAIL -> WebLoginTOTPRequest(loginToken = loginToken, emailCode = v)
                TotpMode.RECOVERY -> WebLoginTOTPRequest(loginToken = loginToken, recoveryCode = v)
            }
            scope.launch {
                busy = true
                loginError = null
                try {
                    val res = Api.request("POST", "/web/login/totp", Api.encode(body)).loginOutcome()
                    if (res is LoginOutcome.Done) finishLogin(res.done, enteredPw)
                } catch (e: Exception) {
                    loginError = e.message ?: "验证失败，请重试"
                    // 只有登录中间态过期才退回第一步——邮箱码自己的「验证码已过期」不能触发
                    if (e.message?.contains("登录请求已过期") == true) {
                        loginToken = ""
                        totpValue = ""
                    }
                } finally {
                    busy = false
                }
            }
        }
    }

    /** 强制改密：oldPassword 空串放行条件 = password_must_change=1 且会话在 reauth 窗内
     *  （登录即 MarkReauth，窗是新鲜的；万一用户在本步停留超 2 小时撞 401，走全局重新验证弹框重试一次）。 */
    fun submitForcePw() {
        if (busy) return
        if (forceNew.length < 8) { forceError = "新密码至少 8 位"; return }
        if (forceNew != forceConfirm) { forceError = "两次输入的新密码不一致"; return }
        suspend fun change() {
            Api.post<AuthResponse>(
                "/auth/change-password",
                Api.encode(ChangePasswordRequest(oldPassword = forceOldPw, newPassword = forceNew)),
            )
        }
        scope.launch {
            busy = true
            forceError = null
            try {
                try {
                    change()
                } catch (e: Exception) {
                    // reauth 窗过期唯一可自救路径：弹框重验后原样重试一次
                    if (e.message?.contains("重新验证") != true) throw e
                    ReauthController.ensure()
                    change()
                }
                scope.launch { snackbarHostState.showSnackbar("密码已更新") }
                goConsole()
            } catch (e: Exception) {
                forceError = e.message ?: "改密失败，请稍后重试"
            } finally {
                busy = false
            }
        }
    }

    /** 邮箱验证码登录 tab 提交。 */
    fun submitCode() {
        if (busy) return
        val em = codeEmail.trim()
        val v = codeValue.trim()
        if (em.isEmpty()) { codeError = "请先填写邮箱"; return }
        if (v.isEmpty()) { codeError = "请输入邮箱验证码"; return }
        scope.launch {
            busy = true
            codeError = null
            try {
                val res = Api.request(
                    "POST", "/web/login/email-code",
                    Api.encode(WebLoginCodeRequest(email = em, code = v)),
                ).loginOutcome()
                if (res is LoginOutcome.Done) finishLogin(res.done, "")
            } catch (e: Exception) {
                codeError = e.message ?: "登录失败，请稍后重试"
            } finally {
                busy = false
            }
        }
    }

    /** 找回密码 tab 提交；成功回密码 tab（邮箱预填），旧 toast 文案走 snackbar。 */
    fun submitReset() {
        if (busy) return
        val em = resetEmail.trim()
        val v = resetCode.trim()
        if (em.isEmpty()) { resetError = "请先填写注册邮箱"; return }
        if (v.isEmpty()) { resetError = "请输入邮箱验证码"; return }
        if (resetPassword.length < 8) { resetError = "新密码至少 8 位"; return }
        scope.launch {
            busy = true
            resetError = null
            try {
                Api.post<OkResponse>(
                    "/auth/reset-password",
                    Api.encode(ResetPasswordRequest(email = em, code = v, password = resetPassword)),
                )
                snackbarHostState.showSnackbar("密码已重置，请用新密码登录")
                tab = LoginTab.PASSWORD
                email = em
                password = ""
                resetCode = ""
                resetPassword = ""
            } catch (e: Exception) {
                resetError = e.message ?: "重置失败，请稍后重试"
            } finally {
                busy = false
            }
        }
    }

    /** Passkey 登录：options → 浏览器断言（用户取消静默收场）→ finish。 */
    fun passkeyLogin() {
        if (busy) return
        scope.launch {
            busy = true
            passkeyError = null
            try {
                val ceremony = Api.post<CeremonyResponse>("/webauthn/login/options", "{}")
                val credential = getAssertion(ceremony.publicKey) ?: return@launch
                val res = Api.request(
                    "POST", "/webauthn/login/finish",
                    Api.encode(PasskeyFinishRequest(ceremonyId = ceremony.ceremonyId, response = credential)),
                ).loginOutcome()
                if (res is LoginOutcome.Done) finishLogin(res.done, "")
            } catch (e: Exception) {
                passkeyError = e.message ?: "Passkey 验证失败，请重试"
            } finally {
                busy = false
            }
        }
    }

    /** 发码（邮箱验证码登录 / 找回密码 / 两步邮箱码共用）：60 秒冷却，成功亮对应提示。 */
    fun sendCode(
        target: String,
        purpose: String,
        cooldown: CooldownState,
        showError: (String) -> Unit,
        onSent: () -> Unit,
    ) {
        if (sending) return
        val em = target.trim()
        if (em.isEmpty()) { showError("请先填写邮箱"); return }
        scope.launch {
            sending = true
            try {
                Api.post<SentResponse>("/auth/send-code", Api.encode(SendCodeRequest(email = em, purpose = purpose)))
                cooldown.start()
                onSent()
                snackbarHostState.showSnackbar("验证码已发送，没收到可查看垃圾箱")
            } catch (e: Exception) {
                showError(e.message ?: "发送失败，请稍后重试")
            } finally {
                sending = false
            }
        }
    }

    PublicPageShell {
        Card(
            Modifier
                .fillMaxWidth()
                .padding(top = 20.dp),
        ) {
                Column(Modifier.padding(12.dp)) {
                    if (forceMode) {
                        // 强制改密步顶替整个卡片（含 tabs 与 Passkey 入口，旧 showForcePassword 同款）
                        Text(
                            text = "请设置新密码",
                            style = MiuixTheme.textStyles.title3,
                            color = MiuixTheme.colorScheme.onSurface,
                        )
                        Text(
                            text = "出于安全考虑，必须设置新密码后才能继续使用。",
                            style = MiuixTheme.textStyles.footnote1,
                            color = MiuixTheme.colorScheme.onSurfaceSecondary,
                            modifier = Modifier.padding(top = 6.dp),
                        )
                        TextField(
                            colors = fieldLabelColors(),
                            value = forceNew,
                            onValueChange = { forceNew = it },
                            enabled = !busy,
                            label = "新密码（至少 8 位）",
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth().padding(top = 12.dp),
                            visualTransformation = PasswordVisualTransformation(),
                            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password, imeAction = ImeAction.Next),
                        )
                        TextField(
                            colors = fieldLabelColors(),
                            value = forceConfirm,
                            onValueChange = { forceConfirm = it },
                            enabled = !busy,
                            label = "确认新密码",
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth().padding(top = 12.dp),
                            visualTransformation = PasswordVisualTransformation(),
                            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password, imeAction = ImeAction.Done),
                        )
                        InlineError(text = forceError, modifier = Modifier.padding(top = 8.dp))
                        Button(
                            onClick = { submitForcePw() },
                            enabled = !busy,
                            modifier = Modifier.fillMaxWidth().padding(top = 12.dp),
                            colors = buttonColorsPrimaryApp(),
                        ) {
                            if (busy) {
                                InfiniteProgressIndicator(color = Color.White, size = 20.dp)
                            } else {
                                Text(text = "设置新密码并继续")
                            }
                        }
                    } else {
                        TabRowWithContour(
                            colors = TabRowDefaults.tabRowColors(),
                            tabs = LoginTab.entries.map { it.label },
                            selectedTabIndex = tab.ordinal,
                            onTabSelected = {
                                tab = LoginTab.entries[it]
                                loginError = null
                                codeError = null
                                resetError = null
                            },
                            modifier = Modifier.fillMaxWidth().padding(bottom = 12.dp),
                        )
                        when (tab) {
                            LoginTab.PASSWORD -> PasswordPane(
                                email = email,
                                onEmailChange = { email = it; loginError = null },
                                password = password,
                                onPasswordChange = { password = it; loginError = null },
                                inTwoFa = loginToken.isNotEmpty(),
                                totpMode = totpMode,
                                totpValue = totpValue,
                                onTotpValueChange = { v ->
                                    totpValue = if (totpMode == TotpMode.RECOVERY) {
                                        v.filter { c -> c.isLetterOrDigit() || c == '-' }.take(24)
                                    } else {
                                        v.filter { c -> c.isDigit() }.take(6)
                                    }
                                },
                                totpEmailSent = totpEmailSent,
                                onSwitchMode = { m ->
                                    totpMode = m
                                    totpValue = ""
                                    loginError = null
                                    totpEmailSent = false
                                },
                                onBackToPassword = {
                                    loginToken = ""
                                    totpValue = ""
                                    loginError = null
                                },
                                onSendEmailCode = {
                                    sendCode(email, "login_2fa", totpCooldown, { loginError = it }) { totpEmailSent = true }
                                },
                                cooldown = totpCooldown,
                                sending = sending,
                                error = loginError,
                                busy = busy,
                                onSubmit = { submitPassword() },
                            )
                            LoginTab.CODE -> CodeLoginPane(
                                email = codeEmail,
                                onEmailChange = { codeEmail = it; codeError = null },
                                code = codeValue,
                                onCodeChange = { codeValue = it.filter { c -> c.isDigit() }.take(6) },
                                onSendCode = {
                                    sendCode(codeEmail, "login", codeCooldown, { codeError = it }) { }
                                },
                                cooldown = codeCooldown,
                                sending = sending,
                                error = codeError,
                                busy = busy,
                                onSubmit = { submitCode() },
                            )
                            LoginTab.RESET -> ResetPane(
                                email = resetEmail,
                                onEmailChange = { resetEmail = it; resetError = null },
                                code = resetCode,
                                onCodeChange = { resetCode = it.filter { c -> c.isDigit() }.take(6) },
                                password = resetPassword,
                                onPasswordChange = { resetPassword = it; resetError = null },
                                onSendCode = {
                                    sendCode(resetEmail, "reset", resetCooldown, { resetError = it }) { }
                                },
                                cooldown = resetCooldown,
                                sending = sending,
                                error = resetError,
                                busy = busy,
                                onSubmit = { submitReset() },
                            )
                        }
                    }
                }
            }

            if (supportsPasskey && !forceMode) {
                Text(
                    text = "或",
                    style = MiuixTheme.textStyles.footnote1,
                    color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                    textAlign = TextAlign.Center,
                    modifier = Modifier.fillMaxWidth().padding(top = 16.dp),
                )
                Button(
                    onClick = { passkeyLogin() },
                    enabled = !busy,
                    modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
                    colors = buttonColorsPrimaryApp(),
                ) {
                    if (busy) {
                        InfiniteProgressIndicator(color = Color.White, size = 20.dp)
                    } else {
                        AppIcon(
                            icon = Lucide.KeyRound,
                            contentDescription = null,
                            tint = Color.White,
                            modifier = Modifier.size(18.dp),
                        )
                        Spacer(Modifier.width(8.dp))
                        Text(text = "使用 Passkey 登录")
                    }
                }
                InlineError(text = passkeyError, modifier = Modifier.padding(top = 8.dp))
            }

            // 页脚一句话（旧 login.html 底部 dim 文案）
            Text(
                text = "统一账号服务：支持密码、邮箱验证码与 Passkey；开启两步验证的账号在密码之后还需一步验证。",
                style = MiuixTheme.textStyles.footnote2,
                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                textAlign = TextAlign.Center,
                modifier = Modifier.fillMaxWidth().padding(top = 20.dp),
            )
    }
}

/**
 * 公开页统一外壳（四屏共用，替代旧 login-shell）：品牌头 + 居中限宽滚动列。
 * 公开页无顶栏、不走 ScreenScaffold；键盘弹出随滚动避让（imePadding）。
 */
@Composable
internal fun PublicPageShell(content: @Composable androidx.compose.foundation.layout.ColumnScope.() -> Unit) {
    Box(
        Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .imePadding(),
        contentAlignment = Alignment.TopCenter,
    ) {
        Column(
            Modifier
                .fillMaxWidth()
                .widthIn(max = 480.dp)
                .padding(horizontal = 16.dp)
                .padding(top = 40.dp, bottom = 24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            // 品牌（旧 brand-lg）
            Text(
                text = "Auth",
                style = MiuixTheme.textStyles.title1,
                color = MiuixTheme.colorScheme.onSurface,
            )
            Text(
                text = "统一账号服务",
                style = MiuixTheme.textStyles.footnote1,
                color = MiuixTheme.colorScheme.onSurfaceSecondary,
                modifier = Modifier.padding(top = 2.dp),
            )
            content()
        }
    }
}

// ---- 密码 tab（含 2FA 第二步）----

@Composable
private fun PasswordPane(
    email: String,
    onEmailChange: (String) -> Unit,
    password: String,
    onPasswordChange: (String) -> Unit,
    inTwoFa: Boolean,
    totpMode: TotpMode,
    totpValue: String,
    onTotpValueChange: (String) -> Unit,
    totpEmailSent: Boolean,
    onSwitchMode: (TotpMode) -> Unit,
    onBackToPassword: () -> Unit,
    onSendEmailCode: () -> Unit,
    cooldown: CooldownState,
    sending: Boolean,
    error: String?,
    busy: Boolean,
    onSubmit: () -> Unit,
) {
    if (!inTwoFa) {
        TextField(
            colors = fieldLabelColors(),
            value = email,
            onValueChange = onEmailChange,
            enabled = !busy,
            label = "邮箱",
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Email, imeAction = ImeAction.Next),
        )
        TextField(
            colors = fieldLabelColors(),
            value = password,
            onValueChange = onPasswordChange,
            enabled = !busy,
            label = "密码",
            singleLine = true,
            modifier = Modifier.fillMaxWidth().padding(top = 12.dp),
            visualTransformation = PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password, imeAction = ImeAction.Done),
        )
    } else {
        Text(
            text = when (totpMode) {
                TotpMode.CODE -> "该账号已开启两步验证：请输入验证器上的 6 位验证码完成登录。"
                TotpMode.EMAIL -> "该账号已开启两步验证：请输入邮箱里的 6 位验证码完成登录。"
                TotpMode.RECOVERY -> "该账号已开启两步验证：请输入一个恢复码完成登录。"
            },
            style = MiuixTheme.textStyles.footnote1,
            color = MiuixTheme.colorScheme.onSurfaceSecondary,
        )
        if (totpMode == TotpMode.EMAIL) {
            Row(
                modifier = Modifier.fillMaxWidth().padding(top = 12.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                TextField(
                    colors = fieldLabelColors(),
                    value = totpValue,
                    onValueChange = onTotpValueChange,
                    enabled = !busy,
                    label = "邮箱验证码（6 位）",
                    singleLine = true,
                    modifier = Modifier.weight(1f),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword, imeAction = ImeAction.Done),
                )
                TextButton(
                    text = when {
                        sending -> "正在发送…"
                        cooldown.running -> "${cooldown.left} 秒后重发"
                        else -> "获取验证码"
                    },
                    enabled = !busy && !sending && !cooldown.running,
                    onClick = onSendEmailCode,
                )
            }
            if (totpEmailSent) {
                Text(
                    text = "验证码已发送到你的邮箱，5 分钟内有效",
                    style = MiuixTheme.textStyles.footnote2,
                    color = MiuixTheme.colorScheme.onSurfaceSecondary,
                    modifier = Modifier.padding(top = 6.dp),
                )
            }
        } else {
            TextField(
                colors = fieldLabelColors(),
                value = totpValue,
                onValueChange = onTotpValueChange,
                enabled = !busy,
                label = if (totpMode == TotpMode.RECOVERY) "恢复码（XXXX-XXXX-XXXX-XXXX）" else "两步验证码（6 位）",
                singleLine = true,
                modifier = Modifier.fillMaxWidth().padding(top = 12.dp),
                // 恢复码是 Crockford 字母数字：数字键盘打不出字母且部分输入法禁粘贴（全仓已知坑）
                keyboardOptions = KeyboardOptions(
                    keyboardType = if (totpMode == TotpMode.RECOVERY) KeyboardType.Text else KeyboardType.NumberPassword,
                    imeAction = ImeAction.Done,
                ),
            )
        }
        Row(
            modifier = Modifier.fillMaxWidth().padding(top = 12.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            when (totpMode) {
                TotpMode.CODE -> {
                    TextButton(text = "没有验证器？获取邮箱验证码", onClick = { onSwitchMode(TotpMode.EMAIL) }, modifier = Modifier.weight(1f))
                    TextButton(text = "使用恢复码", onClick = { onSwitchMode(TotpMode.RECOVERY) }, modifier = Modifier.weight(1f))
                }
                TotpMode.EMAIL -> {
                    TextButton(text = "换回验证器验证码", onClick = { onSwitchMode(TotpMode.CODE) }, modifier = Modifier.weight(1f))
                    TextButton(text = "使用恢复码", onClick = { onSwitchMode(TotpMode.RECOVERY) }, modifier = Modifier.weight(1f))
                }
                TotpMode.RECOVERY -> {
                    TextButton(text = "改用两步验证码", onClick = { onSwitchMode(TotpMode.CODE) }, modifier = Modifier.weight(1f))
                }
            }
        }
        TextButton(
            text = "换用密码登录",
            onClick = onBackToPassword,
            modifier = Modifier.fillMaxWidth().padding(top = 4.dp),
        )
    }
    InlineError(text = error, modifier = Modifier.padding(top = 8.dp))
    Button(
        onClick = onSubmit,
        enabled = !busy,
        modifier = Modifier.fillMaxWidth().padding(top = 12.dp),
        colors = buttonColorsPrimaryApp(),
    ) {
        if (busy) {
            InfiniteProgressIndicator(color = Color.White, size = 20.dp)
        } else {
            Text(text = if (inTwoFa) "完成登录" else "登录")
        }
    }
}

// ---- 邮箱验证码登录 tab ----

@Composable
private fun CodeLoginPane(
    email: String,
    onEmailChange: (String) -> Unit,
    code: String,
    onCodeChange: (String) -> Unit,
    onSendCode: () -> Unit,
    cooldown: CooldownState,
    sending: Boolean,
    error: String?,
    busy: Boolean,
    onSubmit: () -> Unit,
) {
    TextField(
        colors = fieldLabelColors(),
        value = email,
        onValueChange = onEmailChange,
        enabled = !busy,
        label = "邮箱",
        singleLine = true,
        modifier = Modifier.fillMaxWidth(),
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Email, imeAction = ImeAction.Next),
    )
    CodeRow(
        code = code,
        onCodeChange = onCodeChange,
        onSendCode = onSendCode,
        cooldown = cooldown,
        sending = sending,
        enabled = !busy,
    )
    Text(
        text = "验证码 5 分钟内有效；没收到可查看垃圾箱，60 秒后可重新发送。",
        style = MiuixTheme.textStyles.footnote1,
        color = MiuixTheme.colorScheme.onSurfaceSecondary,
        modifier = Modifier.padding(top = 8.dp),
    )
    InlineError(text = error, modifier = Modifier.padding(top = 8.dp))
    Button(
        onClick = onSubmit,
        enabled = !busy,
        modifier = Modifier.fillMaxWidth().padding(top = 12.dp),
        colors = buttonColorsPrimaryApp(),
    ) {
        if (busy) {
            InfiniteProgressIndicator(color = Color.White, size = 20.dp)
        } else {
            Text(text = "登录")
        }
    }
}

// ---- 找回密码 tab ----

@Composable
private fun ResetPane(
    email: String,
    onEmailChange: (String) -> Unit,
    code: String,
    onCodeChange: (String) -> Unit,
    password: String,
    onPasswordChange: (String) -> Unit,
    onSendCode: () -> Unit,
    cooldown: CooldownState,
    sending: Boolean,
    error: String?,
    busy: Boolean,
    onSubmit: () -> Unit,
) {
    TextField(
        colors = fieldLabelColors(),
        value = email,
        onValueChange = onEmailChange,
        enabled = !busy,
        label = "注册邮箱",
        singleLine = true,
        modifier = Modifier.fillMaxWidth(),
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Email, imeAction = ImeAction.Next),
    )
    CodeRow(
        code = code,
        onCodeChange = onCodeChange,
        onSendCode = onSendCode,
        cooldown = cooldown,
        sending = sending,
        enabled = !busy,
    )
    TextField(
        colors = fieldLabelColors(),
        value = password,
        onValueChange = onPasswordChange,
        enabled = !busy,
        label = "新密码（至少 8 位）",
        singleLine = true,
        modifier = Modifier.fillMaxWidth().padding(top = 12.dp),
        visualTransformation = PasswordVisualTransformation(),
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password, imeAction = ImeAction.Done),
    )
    Text(
        text = "重置成功后，其它已登录设备会全部退出。",
        style = MiuixTheme.textStyles.footnote1,
        color = MiuixTheme.colorScheme.onSurfaceSecondary,
        modifier = Modifier.padding(top = 8.dp),
    )
    InlineError(text = error, modifier = Modifier.padding(top = 8.dp))
    Button(
        onClick = onSubmit,
        enabled = !busy,
        modifier = Modifier.fillMaxWidth().padding(top = 12.dp),
        colors = buttonColorsPrimaryApp(),
    ) {
        if (busy) {
            InfiniteProgressIndicator(color = Color.White, size = 20.dp)
        } else {
            Text(text = "重置密码")
        }
    }
}

/** 「验证码 + 获取验证码」一行（登录三处共用；按钮文案与 60s 冷却同旧 app.js cooldown）。 */
@Composable
private fun CodeRow(
    code: String,
    onCodeChange: (String) -> Unit,
    onSendCode: () -> Unit,
    cooldown: CooldownState,
    sending: Boolean,
    enabled: Boolean,
) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(top = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        TextField(
            colors = fieldLabelColors(),
            value = code,
            onValueChange = onCodeChange,
            enabled = enabled && !sending,
            label = "邮箱验证码（6 位）",
            singleLine = true,
            modifier = Modifier.weight(1f),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword, imeAction = ImeAction.Done),
        )
        TextButton(
            text = when {
                sending -> "正在发送…"
                cooldown.running -> "${cooldown.left} 秒后重发"
                else -> "获取验证码"
            },
            enabled = enabled && !sending && !cooldown.running,
            onClick = onSendCode,
        )
    }
}

// ---- 登录回执分流与浏览器探测 ----

/** /web login 系列的两支回执：{status,loginToken,methods} 中间态 vs {token,email,…} 完成态。 */
private sealed interface LoginOutcome {
    data class Done(val done: AuthResponse) : LoginOutcome
    data class Pending(val pending: WebLoginPending) : LoginOutcome
}

/**
 * 2xx 才走到分流（json() 对非 2xx 统一抛 ApiException）：有 loginToken 键即中间态——
 * 不比对 status 字面量（Go 侧现值 "2fa_required"，DTO 注释里的 "2fa" 已过时）。
 */
private fun HttpResponse.loginOutcome(): LoginOutcome {
    val root = json<JsonElement>().jsonObject
    return if ("loginToken" in root) {
        LoginOutcome.Pending(Api.Json.decodeFromJsonElement(WebLoginPending.serializer(), root))
    } else {
        LoginOutcome.Done(Api.Json.decodeFromJsonElement(AuthResponse.serializer(), root))
    }
}

/** 浏览器是否支持 WebAuthn（旧 app.js supportsPasskey 同式：不支持就不摆死按钮）。 */
@JsFun("() => typeof PublicKeyCredential !== 'undefined' && !!navigator.credentials")
private external fun supportsWebAuthn(): Boolean
