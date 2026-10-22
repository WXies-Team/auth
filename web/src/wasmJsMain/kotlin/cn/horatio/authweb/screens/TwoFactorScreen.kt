// 控制台 · 两步验证：行为规格 = 旧前端 internal/ui/templates/security.html + app.js
// initSecurity（未开启三步引导 / 扫码绑定 / 恢复码一次性面板 / 已开启状态与重生成、关闭）。
// setup/enable/disable/regenerate 全是服务端 reauth 闸操作（reauthed），
// 先 ReauthController.ensure() 再发请求；恢复码只在 enable/regenerate 回执里出现一次。
@file:OptIn(kotlin.js.ExperimentalWasmJsInterop::class)

package cn.horatio.authweb.screens

import androidx.compose.foundation.Image
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyListState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import cn.horatio.authweb.component.DialogButtonRow
import cn.horatio.authweb.component.ItemFadeSpec
import cn.horatio.authweb.component.ItemPlacementSpec
import cn.horatio.authweb.component.PrefIcon
import cn.horatio.authweb.component.SmallTitle
import cn.horatio.authweb.component.TextButton
import cn.horatio.authweb.component.buttonColorsPrimaryApp
import cn.horatio.authweb.component.textButtonColorsDanger
import cn.horatio.authweb.component.textButtonColorsPrimaryApp
import cn.horatio.authweb.data.Api
import cn.horatio.authweb.data.CodeRequest
import cn.horatio.authweb.data.OkResponse
import cn.horatio.authweb.data.ReauthController
import cn.horatio.authweb.data.RecoveryCodesResponse
import cn.horatio.authweb.data.SessionStore
import cn.horatio.authweb.data.TotpSetupResponse
import cn.horatio.authweb.data.TotpStatusResponse
import cn.horatio.authweb.shell.LocalSnackbarHostState
import cn.horatio.authweb.shell.ScreenScaffold
import cn.horatio.authweb.shell.adaptiveContentWidth
import cn.horatio.authweb.shell.pageContentPadding
import cn.horatio.authweb.shell.pageScrollModifiers
import com.composables.icons.lucide.Lucide
import com.composables.icons.lucide.Shield
import com.composables.icons.lucide.ShieldCheck
import kotlin.js.JsString
import kotlin.js.toJsString
import kotlinx.coroutines.launch
import top.yukonga.miuix.kmp.basic.BasicComponent
import top.yukonga.miuix.kmp.basic.BasicComponentDefaults
import top.yukonga.miuix.kmp.basic.Button
import top.yukonga.miuix.kmp.basic.Card
import top.yukonga.miuix.kmp.basic.CircularProgressIndicator
import top.yukonga.miuix.kmp.basic.MiuixScrollBehavior
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.basic.TextField
import top.yukonga.miuix.kmp.basic.VerticalScrollBar
import top.yukonga.miuix.kmp.basic.rememberScrollBarAdapter
import top.yukonga.miuix.kmp.overlay.OverlayDialog
import top.yukonga.miuix.kmp.theme.MiuixTheme

/** 页内步骤：未开启（无绑定流程）/ 扫码绑定 / 恢复码一次性展示 / 已开启。 */
private enum class TwoFactorStep { OFF, SETUP, CODES, ON }

/** 通用「要一个码」请求（app.js askCode 同语义）：单输入 + 恢复码切换，回调交出码值。 */
private class AskCodeRequest(
    val title: String,
    val summary: String,
    val danger: Boolean,
    val onDone: (String) -> Unit,
)

@Composable
fun TwoFactorScreen() {
    val scope = rememberCoroutineScope()
    val snackbarHostState = LocalSnackbarHostState.current
    val scrollBehavior = MiuixScrollBehavior()
    val lazyListState = remember { LazyListState() }

    var loaded by remember { mutableStateOf(false) }
    var loadError by remember { mutableStateOf<String?>(null) }
    var enabled by remember { mutableStateOf(false) }
    var createdAt by remember { mutableStateOf(0L) }

    var setup by remember { mutableStateOf<TotpSetupResponse?>(null) }
    var setupCode by remember { mutableStateOf("") }
    var setupError by remember { mutableStateOf<String?>(null) }
    var recoveryCodes by remember { mutableStateOf<List<String>>(emptyList()) }
    var busy by remember { mutableStateOf(false) }
    var actionError by remember { mutableStateOf<String?>(null) }
    var askRequest by remember { mutableStateOf<AskCodeRequest?>(null) }

    suspend fun refresh() {
        try {
            val st = Api.get<TotpStatusResponse>("/api/totp")
            enabled = st.enabled
            createdAt = st.createdAt
            loadError = null
        } catch (e: Exception) {
            loadError = e.message ?: "状态读取失败，请稍后重试"
        }
        loaded = true
    }

    LaunchedEffect(Unit) {
        runCatching { SessionStore.refresh() }
        refresh()
    }

    /** ① 开启：reauth 闸 → setup（只发资料，状态仍算未开启）→ 展示二维码与密钥。 */
    fun startSetup() {
        if (busy) return
        scope.launch {
            busy = true
            actionError = null
            try {
                ReauthController.ensure()
                setup = Api.post<TotpSetupResponse>("/api/totp/setup", "{}")
                setupCode = ""
                setupError = null
            } catch (e: Exception) {
                actionError = e.message ?: "开启失败，请稍后重试"
            } finally {
                busy = false
            }
        }
    }

    /** ③ 确认开启（reauth 闸）：验码通过才 enabled，恢复码只回这一次 → 直接进展示面板。 */
    fun enable() {
        if (busy) return
        val code = setupCode.trim()
        if (code.length != 6) {
            setupError = "请输入 6 位验证码"
            return
        }
        scope.launch {
            busy = true
            setupError = null
            try {
                ReauthController.ensure()
                val res = Api.post<RecoveryCodesResponse>("/api/totp/enable", Api.encode(CodeRequest(code = code)))
                recoveryCodes = res.recoveryCodes
                setup = null
                setupCode = ""
                refresh()
            } catch (e: Exception) {
                setupError = e.message ?: "绑定失败，请确认验证码后重试"
            } finally {
                busy = false
            }
        }
    }

    /** 重生成恢复码（要码）：新组只回这一次，旧组即废。 */
    fun regenerate(code: String) {
        if (busy) return
        scope.launch {
            busy = true
            try {
                ReauthController.ensure()
                val res = Api.post<RecoveryCodesResponse>(
                    "/api/totp/regenerate-recovery-codes",
                    Api.encode(CodeRequest(code = code)),
                )
                recoveryCodes = res.recoveryCodes
                snackbarHostState.showSnackbar("已换发新恢复码，旧码全部作废")
            } catch (e: Exception) {
                snackbarHostState.showSnackbar(e.message ?: "重生成失败，请确认验证码后重试")
            } finally {
                busy = false
            }
        }
    }

    /** 关闭两步验证（要码）：成功回未开启态。 */
    fun disable(code: String) {
        if (busy) return
        scope.launch {
            busy = true
            try {
                ReauthController.ensure()
                Api.post<OkResponse>("/api/totp/disable", Api.encode(CodeRequest(code = code)))
                enabled = false
                createdAt = 0
                snackbarHostState.showSnackbar("两步验证已关闭")
            } catch (e: Exception) {
                snackbarHostState.showSnackbar(e.message ?: "关闭失败，请确认验证码后重试")
            } finally {
                busy = false
            }
        }
    }

    ScreenScaffold(title = "两步验证", scrollBehavior = scrollBehavior) { innerPadding ->
        val contentPadding = pageContentPadding(innerPadding, PaddingValues(0.dp), extraBottom = 16.dp)
        Box(Modifier.fillMaxSize()) {
            LazyColumn(
                state = lazyListState,
                modifier = Modifier
                    .adaptiveContentWidth()
                    .align(Alignment.TopCenter)
                    .pageScrollModifiers(scrollBehavior),
                contentPadding = contentPadding,
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                if (!loaded) {
                    item(key = "loading") {
                        Box(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(vertical = 64.dp)
                                .animateItem(fadeInSpec = ItemFadeSpec, placementSpec = ItemPlacementSpec, fadeOutSpec = ItemFadeSpec),
                            contentAlignment = Alignment.Center,
                        ) {
                            CircularProgressIndicator()
                        }
                    }
                } else {
                    item(key = "body") {
                        Column(Modifier.animateItem(fadeInSpec = ItemFadeSpec, placementSpec = ItemPlacementSpec, fadeOutSpec = ItemFadeSpec)) {
                            if (loadError != null) {
                                InlineError(text = loadError, modifier = Modifier.padding(horizontal = 28.dp))
                            }
                            // 页首状态卡恒在：开/关状态与徽标不跟着换步闪
                            StatusCard(enabled = enabled, createdAt = createdAt)
                            val step = when {
                                recoveryCodes.isNotEmpty() -> TwoFactorStep.CODES
                                setup != null -> TwoFactorStep.SETUP
                                enabled -> TwoFactorStep.ON
                                else -> TwoFactorStep.OFF
                            }
                            when (step) {
                                TwoFactorStep.OFF -> OffSection(busy = busy, onStart = { startSetup() }, error = actionError)
                                TwoFactorStep.SETUP -> SetupSection(
                                    setup = setup,
                                    code = setupCode,
                                    onCodeChange = { setupCode = it.filter { c -> c.isDigit() }.take(6) },
                                    error = setupError,
                                    busy = busy,
                                    onBind = { enable() },
                                    onCancel = {
                                        setup = null
                                        setupCode = ""
                                        setupError = null
                                    },
                                )
                                TwoFactorStep.CODES -> RecoveryCodesSection(
                                    codes = recoveryCodes,
                                    onCopy = {
                                        copyTextToClipboard(recoveryCodes.joinToString("\n").toJsString())
                                        scope.launch { snackbarHostState.showSnackbar("恢复码已复制到剪贴板") }
                                    },
                                    onDownload = {
                                        downloadTextFile(
                                            "auth-recovery-codes.txt".toJsString(),
                                            buildRecoveryCodesFile(recoveryCodes).toJsString(),
                                        )
                                    },
                                    onDone = {
                                        recoveryCodes = emptyList()
                                        scope.launch {
                                            snackbarHostState.showSnackbar("恢复码已保存。离开本页后无法再查看，需要时可重生成。")
                                        }
                                    },
                                )
                                TwoFactorStep.ON -> EnabledSection(
                                    createdAt = createdAt,
                                    onRegenerate = {
                                        askRequest = AskCodeRequest(
                                            title = "重生成恢复码",
                                            summary = "输入当前两步验证码或一个恢复码；旧的恢复码会全部作废。",
                                            danger = false,
                                            onDone = { c -> regenerate(c) },
                                        )
                                    },
                                    onDisable = {
                                        askRequest = AskCodeRequest(
                                            title = "关闭两步验证",
                                            summary = "输入当前两步验证码或一个恢复码；关闭后验证器绑定与全部恢复码失效，登录只需密码，其它设备保持登录状态。",
                                            danger = true,
                                            onDone = { c -> disable(c) },
                                        )
                                    },
                                )
                            }
                        }
                    }
                }
                item(key = "spacer") {
                    Spacer(Modifier.height(16.dp))
                }
            }
            VerticalScrollBar(
                adapter = rememberScrollBarAdapter(lazyListState),
                modifier = Modifier.align(Alignment.CenterEnd).fillMaxHeight(),
                trackPadding = contentPadding,
            )
        }

        AskCodeDialog(
            request = askRequest,
            onDismiss = { askRequest = null },
        )
    }
}

/** 页首状态卡：图标 + 状态一句话 + 开/关徽标；不属于任何一步，换步不闪。 */
@Composable
private fun StatusCard(enabled: Boolean, createdAt: Long) {
    Card(modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp)) {
        BasicComponent(
            title = "两步验证",
            summary = if (enabled) {
                "${fmtTime(createdAt)} 开启 · 登录时除密码外，还需输入身份验证器上的 6 位验证码"
            } else {
                "尚未开启，登录仍只需密码"
            },
            summaryColor = BasicComponentDefaults.summaryColor(
                color = MiuixTheme.colorScheme.onSurfaceSecondary,
            ),
            startAction = { PrefIcon(if (enabled) Lucide.ShieldCheck else Lucide.Shield) },
            endActions = {
                Text(
                    text = if (enabled) "已开启" else "未开启",
                    style = MiuixTheme.textStyles.footnote2,
                    fontWeight = FontWeight.SemiBold,
                    color = if (enabled) {
                        cn.horatio.authweb.theme.OnCardColors.success
                    } else {
                        MiuixTheme.colorScheme.onSurfaceSecondary
                    },
                )
            },
        )
    }
}

/** 未开启态：编号三步卡 + 「开启两步验证」主按钮（旧 totp-off 文案）。 */
@Composable
private fun OffSection(busy: Boolean, onStart: () -> Unit, error: String?) {
    SmallTitle(text = "开启两步验证")
    Card(modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp)) {
        Column(Modifier.padding(12.dp)) {
            Text(
                text = "密码之外再要一个 6 位动态码，账号被撞库也进不来。",
                style = MiuixTheme.textStyles.footnote1,
                color = MiuixTheme.colorScheme.onSurfaceSecondary,
            )
            StepLine(index = 1, text = "开启前需验证身份（当前密码或已有的验证方式）")
            StepLine(index = 2, text = "扫描二维码，或手动输入密钥")
            StepLine(index = 3, text = "输入验证码确认开启")
            InlineError(text = error, modifier = Modifier.padding(top = 8.dp))
            Button(
                onClick = onStart,
                enabled = !busy,
                modifier = Modifier.fillMaxWidth().padding(top = 12.dp),
                colors = buttonColorsPrimaryApp(),
            ) {
                Text(text = "开启两步验证")
            }
        }
    }
}

/** 编号步骤行：①②③ 序号 + 文案。 */
@Composable
private fun StepLine(index: Int, text: String) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            text = "$index.",
            style = MiuixTheme.textStyles.footnote1,
            fontWeight = FontWeight.SemiBold,
            color = MiuixTheme.colorScheme.onSurfaceSecondary,
            modifier = Modifier.widthIn(min = 20.dp),
        )
        Text(
            text = text,
            style = MiuixTheme.textStyles.footnote1,
            color = MiuixTheme.colorScheme.onSurfaceSecondary,
        )
    }
}

/** 绑定态：二维码（≤200dp）+ 手输密钥复制行 + 6 位码输入 + 确认开启/取消。 */
@Composable
private fun SetupSection(
    setup: TotpSetupResponse?,
    code: String,
    onCodeChange: (String) -> Unit,
    error: String?,
    busy: Boolean,
    onBind: () -> Unit,
    onCancel: () -> Unit,
) {
    SmallTitle(text = "绑定验证器")
    Card(modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp)) {
        Column(Modifier.padding(12.dp), horizontalAlignment = Alignment.CenterHorizontally) {
            Text(
                text = "用身份验证器 App 扫描二维码",
                style = MiuixTheme.textStyles.footnote1,
                color = MiuixTheme.colorScheme.onSurfaceSecondary,
            )
            val qr = remember(setup?.qrPng) { setup?.qrPng?.let { dataUriImageBitmap(it) } }
            if (qr != null) {
                Image(
                    bitmap = qr,
                    contentDescription = "两步验证二维码，可用验证器 App 扫描",
                    modifier = Modifier.padding(top = 12.dp).widthIn(max = 200.dp).size(200.dp),
                )
            }
            Text(
                text = "扫不了码？在验证器里手动添加，粘贴这段密钥：",
                style = MiuixTheme.textStyles.footnote1,
                color = MiuixTheme.colorScheme.onSurfaceSecondary,
                modifier = Modifier.fillMaxWidth().padding(top = 12.dp),
            )
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 4.dp)
                    .clickable {
                        val secret = setup?.secret.orEmpty()
                        if (secret.isNotBlank()) {
                            copyTextToClipboard(secret.toJsString())
                        }
                    },
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    text = setup?.secret.orEmpty(),
                    style = MiuixTheme.textStyles.body2,
                    fontWeight = FontWeight.Bold,
                    // 密钥是逐字符抄写型内容：等宽字体占位一致才好对照（恢复码同口径）
                    fontFamily = FontFamily.Monospace,
                    color = MiuixTheme.colorScheme.onSurface,
                    modifier = Modifier.weight(1f),
                )
                TextButton(text = "复制", onClick = {
                    val secret = setup?.secret.orEmpty()
                    if (secret.isNotBlank()) {
                        copyTextToClipboard(secret.toJsString())
                    }
                })
            }
            TextField(
                colors = fieldLabelColors(),
                value = code,
                onValueChange = onCodeChange,
                enabled = !busy,
                label = "输入验证器上的 6 位验证码",
                singleLine = true,
                modifier = Modifier.fillMaxWidth().padding(top = 12.dp),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword, imeAction = ImeAction.Done),
            )
            InlineError(text = error, modifier = Modifier.padding(top = 8.dp))
            Row(
                modifier = Modifier.fillMaxWidth().padding(top = 12.dp),
                horizontalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                Button(
                    onClick = onBind,
                    enabled = !busy,
                    modifier = Modifier.weight(1f),
                    colors = buttonColorsPrimaryApp(),
                ) {
                    Text(text = "确认开启")
                }
                TextButton(
                    text = "取消",
                    onClick = onCancel,
                    modifier = Modifier.weight(1f),
                )
            }
        }
    }
}

/** 恢复码一次性展示面板：两列等宽网格 + 下载 txt / 复制全部 / 我已保存。 */
@Composable
private fun RecoveryCodesSection(
    codes: List<String>,
    onCopy: () -> Unit,
    onDownload: () -> Unit,
    onDone: () -> Unit,
) {
    SmallTitle(text = "恢复码")
    Card(modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp)) {
        Column(Modifier.padding(12.dp)) {
            Text(
                text = "10 个一次性恢复码，验证器不在身边时靠它登录。关闭本页后无法再查看，请先保存。",
                style = MiuixTheme.textStyles.footnote1,
                color = MiuixTheme.colorScheme.onSurfaceSecondary,
            )
            codes.chunked(2).forEachIndexed { rowIdx, pair ->
                Row(
                    modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    pair.forEachIndexed { i, c ->
                        Text(
                            text = "${rowIdx * 2 + i + 1}",
                            style = MiuixTheme.textStyles.footnote2,
                            color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                            textAlign = TextAlign.End,
                            modifier = Modifier.widthIn(min = 20.dp),
                        )
                        Text(
                            text = c,
                            style = MiuixTheme.textStyles.body2,
                            fontWeight = FontWeight.Bold,
                            // 抄写/对照型内容：等宽字体让每个码占位一致
                            fontFamily = FontFamily.Monospace,
                            color = MiuixTheme.colorScheme.onSurface,
                            textAlign = TextAlign.Center,
                            modifier = Modifier.weight(1f),
                        )
                    }
                    if (pair.size == 1) Spacer(Modifier.weight(1f))
                }
            }
            Row(
                modifier = Modifier.fillMaxWidth().padding(top = 12.dp),
                horizontalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                TextButton(text = "下载 txt", onClick = onDownload, modifier = Modifier.weight(1f))
                TextButton(text = "复制全部", onClick = onCopy, modifier = Modifier.weight(1f))
            }
            TextButton(
                text = "我已保存",
                onClick = onDone,
                modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
                colors = textButtonColorsPrimaryApp(),
            )
        }
    }
}

/** 已开启态：状态提示 + 重生成恢复码；关闭走危险区（红字行）。 */
@Composable
private fun EnabledSection(
    createdAt: Long,
    onRegenerate: () -> Unit,
    onDisable: () -> Unit,
) {
    SmallTitle(text = "两步验证已开启")
    Card(modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp)) {
        Column(Modifier.padding(12.dp)) {
            Text(
                text = "开启时间：${fmtTime(createdAt)}",
                style = MiuixTheme.textStyles.footnote1,
                color = MiuixTheme.colorScheme.onSurfaceSecondary,
            )
            Text(
                text = "开启两步验证时已生成 10 个恢复码；剩余数量无法查询，需要时可重新生成。",
                style = MiuixTheme.textStyles.footnote1,
                color = MiuixTheme.colorScheme.onSurfaceSecondary,
                modifier = Modifier.padding(top = 6.dp),
            )
            Row(
                modifier = Modifier.fillMaxWidth().padding(top = 12.dp),
                horizontalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                TextButton(text = "重生成恢复码", onClick = onRegenerate, modifier = Modifier.weight(1f))
                TextButton(
                    text = "关闭两步验证",
                    onClick = onDisable,
                    modifier = Modifier.weight(1f),
                    colors = textButtonColorsDanger(),
                )
            }
            Text(
                text = "重生成：旧的 10 个恢复码全部作废，需要输入当前两步验证码或一个恢复码。",
                style = MiuixTheme.textStyles.footnote1,
                color = MiuixTheme.colorScheme.onSurfaceSecondary,
                modifier = Modifier.padding(top = 8.dp),
            )
            Text(
                text = "关闭：作废验证器绑定与全部恢复码，关闭后登录只需密码，其它设备保持登录状态。",
                style = MiuixTheme.textStyles.footnote1,
                color = MiuixTheme.colorScheme.onSurfaceSecondary,
                modifier = Modifier.padding(top = 6.dp),
            )
        }
    }
}

/**
 * 通用「要一个码」弹层（app.js askCode 同形态）：单输入 + 「使用恢复码」切换。
 * 服务端 code 字段两码通用；恢复码是 Crockford 字母数字（XXXX-XXXX-…），
 * 切换到恢复码必须用文本键盘——数字键盘打不出字母且部分输入法禁粘贴。
 */
@Composable
private fun AskCodeDialog(
    request: AskCodeRequest?,
    onDismiss: () -> Unit,
) {
    var code by remember { mutableStateOf("") }
    var recovery by remember { mutableStateOf(false) }
    OverlayDialog(
        show = request != null,
        title = request?.title ?: "验证身份",
        summary = request?.summary ?: "",
        onDismissRequest = onDismiss,
        onDismissFinished = {
            onDismiss()
            code = ""
            recovery = false
        },
    ) {
        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            TextField(
                colors = fieldLabelColors(),
                value = code,
                onValueChange = {
                    code = if (recovery) {
                        it.filter { c -> c.isLetterOrDigit() || c == '-' }.take(24)
                    } else {
                        it.filter { c -> c.isDigit() }.take(6)
                    }
                },
                label = if (recovery) "恢复码（XXXX-XXXX-XXXX-XXXX）" else "两步验证码（6 位）",
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
                keyboardOptions = KeyboardOptions(
                    keyboardType = if (recovery) KeyboardType.Text else KeyboardType.NumberPassword,
                    imeAction = ImeAction.Done,
                ),
            )
            TextButton(
                text = if (recovery) "改用两步验证码" else "使用恢复码",
                onClick = {
                    recovery = !recovery
                    code = ""
                },
            )
            DialogButtonRow(
                cancelText = "取消",
                onCancel = onDismiss,
                confirmText = "确定",
                onConfirm = {
                    code.trim().takeIf { it.isNotBlank() }?.let { v -> request?.onDone(v) }
                    onDismiss()
                },
                confirmColors = if (request?.danger == true) {
                    textButtonColorsDanger()
                } else {
                    textButtonColorsPrimaryApp()
                },
            )
        }
    }
}

/**
 * 恢复码导出文件正文（结构参考旧 app.js 下载逻辑：服务名 + 账号 + 生成日期 + 说明 + 码列表）——
 * 纯码列表落进密码管理器后没人知道它是谁的。
 */
private fun buildRecoveryCodesFile(codes: List<String>): String = buildString {
    appendLine("Auth 统一账号服务 —— 恢复码")
    appendLine("账号：${SessionStore.session?.email.orEmpty()}")
    appendLine("生成日期：${todayStr()}")
    appendLine()
    appendLine("每个恢复码只能使用一次，用于两步验证开启后验证器不可用时登录。" +
        "使用后即失效；重生成会让全部旧码作废。请离线妥善保存。")
    appendLine()
    codes.forEach(::appendLine)
    appendLine()
}

// ---- 浏览器互操作：剪贴板与 Blob 下载（@JsFun 直连 navigator/DOM，Kotlin 侧只传串）----

/** navigator.clipboard.writeText；非安全上下文/拒绝一律静默（提示由调用方 snackbar 给）。 */
private const val COPY_JS = """
(text) => {
  try {
    navigator.clipboard.writeText(String(text)).catch(() => {});
  } catch (e) { /* 非安全上下文没有 clipboard：静默 */ }
}
"""

@JsFun(COPY_JS)
private external fun copyTextToClipboard(text: JsString)

/** Blob + 临时 <a download> 触发下载（app.js 恢复码下载同配方），用完即回收 ObjectURL。 */
private const val DOWNLOAD_JS = """
(filename, content) => {
  const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
  const a = document.createElement('a');
  const url = URL.createObjectURL(blob);
  a.href = url;
  a.download = String(filename);
  a.click();
  URL.revokeObjectURL(url);
}
"""

@JsFun(DOWNLOAD_JS)
private external fun downloadTextFile(filename: JsString, content: JsString)
