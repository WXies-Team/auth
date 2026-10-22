// 控制台 · 账号：行为规格 = 旧前端 internal/ui/templates/account.html + app.js
// initAccount/initProfile/initLoginNotify（资料 / 改密码两 tab / 改邮箱 / 登录提醒 /
// 注销危险区）。PUT /api/profile 是全量替换语义——持本地档案副本整份提交；
// loginNotify 只能经「GET 整份 → PUT 带显式值」改，直接 PUT {loginNotify} 会清空
// 昵称与头像（旧 initLoginNotify 同款守卫）。
//
// 本文件兼收五屏共用的表单/头像小件（InlineError、fieldLabelColors、色板与墨色、
// base64→ImageBitmap、验证码冷却）：交付范围限定在 screens/ 且只有 DeviceIcon 一个
// common 文件，同包 internal 顶格函数即可跨屏引用。
@file:OptIn(kotlin.js.ExperimentalWasmJsInterop::class)

package cn.horatio.authweb.screens

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.defaultMinSize
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.wrapContentHeight
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyListState
import androidx.compose.foundation.shape.CircleShape
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
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import cn.horatio.authweb.component.DialogButtonRow
import cn.horatio.authweb.component.ItemFadeSpec
import cn.horatio.authweb.component.ItemPlacementSpec
import cn.horatio.authweb.component.PrefIcon
import cn.horatio.authweb.component.SmallTitle
import cn.horatio.authweb.component.TextButton
import cn.horatio.authweb.component.buttonColorsDanger
import cn.horatio.authweb.component.buttonColorsPrimaryApp
import cn.horatio.authweb.component.textButtonColorsDanger
import cn.horatio.authweb.component.textButtonColorsPrimaryApp
import cn.horatio.authweb.data.Api
import cn.horatio.authweb.data.AuthResponse
import cn.horatio.authweb.data.ChangeEmailRequest
import cn.horatio.authweb.data.ChangePasswordCodeRequest
import cn.horatio.authweb.data.ChangePasswordRequest
import cn.horatio.authweb.data.DeleteAccountRequest
import cn.horatio.authweb.data.OkResponse
import cn.horatio.authweb.data.ProfileResponse
import cn.horatio.authweb.data.ProfileUpdateRequest
import cn.horatio.authweb.data.ReauthController
import cn.horatio.authweb.data.SendCodeRequest
import cn.horatio.authweb.data.SentResponse
import cn.horatio.authweb.data.SessionStore
import cn.horatio.authweb.nav.LocalNav
import cn.horatio.authweb.nav.Route
import cn.horatio.authweb.shell.LocalSnackbarHostState
import cn.horatio.authweb.shell.ScreenScaffold
import cn.horatio.authweb.shell.adaptiveContentWidth
import cn.horatio.authweb.shell.pageContentPadding
import cn.horatio.authweb.shell.pageScrollModifiers
import com.composables.icons.lucide.Bell
import com.composables.icons.lucide.Lucide
import kotlin.js.JsString
import kotlin.js.Promise
import kotlinx.coroutines.delay
import kotlinx.coroutines.await
import kotlinx.coroutines.launch
import kotlinx.serialization.Serializable
import kotlin.math.pow
import org.jetbrains.skia.Image as SkiaImage
import androidx.compose.ui.graphics.toComposeImageBitmap
import top.yukonga.miuix.kmp.basic.BasicComponent
import top.yukonga.miuix.kmp.basic.BasicComponentDefaults
import top.yukonga.miuix.kmp.basic.Button
import top.yukonga.miuix.kmp.basic.ButtonDefaults
import top.yukonga.miuix.kmp.basic.Card
import top.yukonga.miuix.kmp.basic.CircularProgressIndicator
import top.yukonga.miuix.kmp.basic.MiuixScrollBehavior
import top.yukonga.miuix.kmp.basic.Switch
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.basic.TextField
import top.yukonga.miuix.kmp.basic.TextFieldColors
import top.yukonga.miuix.kmp.basic.TextFieldDefaults
import top.yukonga.miuix.kmp.basic.VerticalScrollBar
import top.yukonga.miuix.kmp.basic.rememberScrollBarAdapter
import top.yukonga.miuix.kmp.overlay.OverlayDialog
import top.yukonga.miuix.kmp.theme.MiuixTheme

// ---- 五屏共用小件 ----

/** 表单/列表级校验红字：错误贴近问题处、null 不占位（旧 InlineError 同款动效走 Fade）。 */
@Composable
internal fun InlineError(text: String?, modifier: Modifier = Modifier) {
    var lastText by remember { mutableStateOf("") }
    if (text != null) lastText = text
    AnimatedVisibility(visible = text != null) {
        Text(
            text = text ?: lastText,
            style = MiuixTheme.textStyles.body2,
            color = OnCardDanger,
            modifier = modifier,
        )
    }
}

/** 卡内/页面底都可读的错误红（OnCardColors.danger：浅 4.92 / 深 4.64 双底达 AA）。 */
private val OnCardDanger: Color
    @Composable get() = cn.horatio.authweb.theme.OnCardColors.danger

/** 表单字段 label 配色：正常态 onSurfaceSecondary（日记 App 的 fieldLabelColors 同款）；
 *  出错时只把 label 染成错误红、背景与边框仍走 miuix 默认（官方 validation 配方）。 */
@Composable
internal fun fieldLabelColors(hasError: Boolean = false): TextFieldColors =
    if (hasError) {
        TextFieldDefaults.textFieldColors(labelColor = OnCardDanger)
    } else {
        TextFieldDefaults.textFieldColors(labelColor = MiuixTheme.colorScheme.onSurfaceSecondary)
    }

// ---- 头像（色板 / 墨色 / 首字；与旧 app.js avatarHex/avatarInk/initialFor 同式）----

/** 8 色色板：与 internal/ui avatarPalette 及两日记 App AvatarPalette 同值。 */
internal val AvatarPalette: List<Color> = listOf(
    Color(0xFF5B8DEF),
    Color(0xFF7C6AF2),
    Color(0xFFE2556B),
    Color(0xFFFF8A3D),
    Color(0xFF2BB673),
    Color(0xFF14A8A0),
    Color(0xFFE6B422),
    Color(0xFF8B7355),
)

/**
 * 展示色下标（W3 派生）：显式设过的色（>0 且在色板内）原样用；
 * 未设（0/越界）按 uid%8 派生——与 app.js effectiveColor/avatarHex 同式。
 */
internal fun effectiveAvatarColorIndex(index: Int, uid: Long): Int =
    if (index > 0 && index < AvatarPalette.size) index else if (uid > 0) (uid % AvatarPalette.size).toInt() else 0

/**
 * 首字墨色：按 WCAG 相对亮度取白墨/黑墨中对比更高的一支（app.js avatarInk 同式——
 * 白墨对 8 色色板只有 1.92~4.49:1，黑墨全数 ≥4.5）。
 */
internal fun avatarInk(bg: Color): Color {
    fun lin(v: Float): Float = if (v <= 0.04045f) v / 12.92f else ((v + 0.055f) / 1.055f).pow(2.4f)
    val l = 0.2126f * lin(bg.red) + 0.7152f * lin(bg.green) + 0.0722f * lin(bg.blue)
    return if (1.05f / (l + 0.05f) >= (l + 0.05f) / 0.05f) Color.White else Color.Black
}

/** 按码点计长（UTF-16 length 会把 emoji 数成两个）；String.codePointCount 是 JVM API，Wasm 没有。 */
internal fun codePointLength(s: String): Int {
    var count = 0
    var i = 0
    while (i < s.length) {
        val c = s[i]
        i += if (c.isHighSurrogate() && i + 1 < s.length && s[i + 1].isLowSurrogate()) 2 else 1
        count++
    }
    return count
}

/** 首字回退链与服务端 initialFor 同源：昵称首字符 → 邮箱前缀首字符（按码点取，不切代理对）。 */
internal fun avatarInitial(nickname: String, email: String): String {
    val src = nickname.trim().ifEmpty { email.substringBefore('@') }
    val first = src.firstOrNull() ?: return "?"
    val code = if (first.isHighSurrogate() && src.length > 1 && src[1].isLowSurrogate()) {
        0x10000 + ((first.code - 0xD800) shl 10) + (src[1].code - 0xDC00)
    } else {
        first.code
    }
    val text = if (code >= 0x10000) {
        val off = code - 0x10000
        ((0xD800 + (off shr 10)).toChar().toString() + (0xDC00 + (off and 0x3FF)).toChar().toString())
    } else {
        code.toChar().toString()
    }
    return text.uppercase()
}

/** 96dp/56dp 头像块：有图用图（dataURL 裸 base64），无图回退色块+首字（墨色按亮度成对）。 */
@Composable
internal fun AvatarBox(
    color: Color,
    initial: String,
    image: ImageBitmap?,
    size: Dp,
    modifier: Modifier = Modifier,
) {
    Box(
        modifier.size(size).clip(CircleShape).background(color),
        contentAlignment = Alignment.Center,
    ) {
        if (image != null) {
            Image(
                bitmap = image,
                contentDescription = null,
                contentScale = ContentScale.Crop,
                modifier = Modifier.fillMaxSize(),
            )
        } else {
            val fontSize = with(LocalDensity.current) { (size.value * 0.42f).dp.toSp() }
            Text(
                text = initial,
                color = avatarInk(color),
                style = MiuixTheme.textStyles.title2.copy(fontSize = fontSize, fontWeight = FontWeight.SemiBold),
            )
        }
    }
}

// ---- 标准 base64（带 padding，+/ 字母表）→ ImageBitmap：头像与 TOTP 二维码共用 ----

private val B64_STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

/** 标准 base64（可带 whitespace）→ 字节；非法字符抛 IllegalArgumentException。 */
internal fun base64StdDecode(input: String): ByteArray {
    val clean = input.filter { it != '=' && !it.isWhitespace() }
    val out = ByteArray(clean.length * 3 / 4)
    var acc = 0
    var bits = 0
    var o = 0
    for (c in clean) {
        val d = B64_STD.indexOf(c)
        if (d < 0) throw IllegalArgumentException("非法 base64 字符: $c")
        acc = (acc shl 6) or d
        bits += 6
        if (bits >= 8) {
            bits -= 8
            out[o++] = (acc shr bits).toByte()
        }
    }
    return if (o == out.size) out else out.copyOf(o)
}

/** 裸 base64 → ImageBitmap（skiko 解码，PNG/JPEG 都收）；解码失败回 null（前端兜底色块）。 */
internal fun decodeBase64Image(base64: String): ImageBitmap? = try {
    SkiaImage.makeFromEncoded(base64StdDecode(base64)).toComposeImageBitmap()
} catch (_: Throwable) {
    null
}

/** dataURI（`data:image/jpeg;base64,…`）→ ImageBitmap；非 dataURI 或解码失败回 null。 */
internal fun dataUriImageBitmap(dataUri: String): ImageBitmap? {
    val b64 = dataUri.substringAfter("base64,", "").ifBlank { return null }
    return decodeBase64Image(b64)
}

// ---- 验证码发送冷却（60s，app.js cooldown 同款文案「N 秒后重发」）----

internal class CooldownState(private val tick: androidx.compose.runtime.MutableState<Int>) {
    val left: Int get() = tick.value
    val running: Boolean get() = tick.value > 0
    fun start() { tick.value = 60 }
}

@Composable
internal fun rememberCooldown(): CooldownState {
    val state = remember { mutableStateOf(0) }
    LaunchedEffect(state.value) {
        if (state.value > 0) {
            delay(1000)
            state.value -= 1
        }
    }
    return remember(state) { CooldownState(state) }
}

// ---- 账号页 ----

/** POST /auth/send-change-code 同族：发码到**新**邮箱（purpose=email_change），只收邮箱。 */
@Serializable
private data class SendChangeEmailCodeBody(val email: String)

/** 修改密码的两种方式（旧 tabs：原密码 / 验证码）。 */
private enum class PwTab { OLD, CODE }

@Composable
fun AccountScreen() {
    val nav = LocalNav.current
    val scope = rememberCoroutineScope()
    val snackbarHostState = LocalSnackbarHostState.current
    val scrollBehavior = MiuixScrollBehavior()
    val lazyListState = remember { LazyListState() }

    var loaded by remember { mutableStateOf(false) }
    var loadError by remember { mutableStateOf<String?>(null) }
    var profile by remember { mutableStateOf<ProfileResponse?>(null) }
    var meUid by remember { mutableStateOf(0L) }
    var meEmail by remember { mutableStateOf("") }

    // 资料草稿：PUT /api/profile 全量替换，保存时整份提交
    var nickname by remember { mutableStateOf("") }
    var colorIdx by remember { mutableStateOf(0) }
    var avatarB64 by remember { mutableStateOf<String?>(null) }
    var saving by remember { mutableStateOf(false) }
    var profileError by remember { mutableStateOf<String?>(null) }

    // 登录提醒：独立 GET→PUT 显式值流程
    var loginNotify by remember { mutableStateOf(true) }
    var notifyLoaded by remember { mutableStateOf(false) }
    var notifyBusy by remember { mutableStateOf(false) }

    // 修改密码
    var pwTab by remember { mutableStateOf(PwTab.OLD) }
    var pwOld by remember { mutableStateOf("") }
    var pwNew by remember { mutableStateOf("") }
    var pwCode by remember { mutableStateOf("") }
    var pwCodeNew by remember { mutableStateOf("") }
    var pwError by remember { mutableStateOf<String?>(null) }
    var pwBusy by remember { mutableStateOf(false) }
    val pwCooldown = rememberCooldown()

    // 修改邮箱
    var emailNew by remember { mutableStateOf("") }
    var emailCode by remember { mutableStateOf("") }
    var emailPassword by remember { mutableStateOf("") }
    var emailError by remember { mutableStateOf<String?>(null) }
    var emailBusy by remember { mutableStateOf(false) }
    val emailCooldown = rememberCooldown()

    // 注销
    var showDelete by remember { mutableStateOf(false) }
    var deleteEmail by remember { mutableStateOf("") }
    var deleteCode by remember { mutableStateOf("") }
    var deleteError by remember { mutableStateOf<String?>(null) }
    var deleteBusy by remember { mutableStateOf(false) }
    val deleteCooldown = rememberCooldown()

    val nicknameOverlong = codePointLength(nickname.trim()) > 64
    val dirty = profile?.let { p ->
        nickname.trim() != p.nickname ||
            colorIdx != p.avatarColor ||
            (avatarB64 ?: "") != (p.avatarImage ?: "")
    } ?: false

    fun applyProfile(p: ProfileResponse) {
        profile = p
        nickname = p.nickname
        colorIdx = p.avatarColor
        avatarB64 = p.avatarImage
        loginNotify = p.loginNotify
        notifyLoaded = true
    }

    LaunchedEffect(Unit) {
        try {
            runCatching { SessionStore.refresh() }.getOrNull()?.let {
                meUid = it.uid
                meEmail = it.email
            }
            applyProfile(Api.get<ProfileResponse>("/api/profile"))
            loaded = true
        } catch (e: Exception) {
            loadError = e.message ?: "账号信息加载失败，请稍后重试"
            loaded = true
        }
    }

    // 头像换图：文件选择 → canvas 缩图（≤512px 方裁、JPEG 逐档降质、700KB 上限，
    // 与旧 cropAvatar 逐行同式）→ 裸 base64（无 data: 前缀）
    fun pickAvatar() {
        scope.launch {
            val result = pickAndCropAvatar().await().toString()
            when {
                result.isEmpty() -> Unit // 用户取消
                result.startsWith("err:") -> snackbarHostState.showSnackbar(result.removePrefix("err:"))
                else -> avatarB64 = result
            }
        }
    }

    fun saveProfile() {
        if (!dirty || nicknameOverlong || saving) return
        scope.launch {
            saving = true
            try {
                val p = Api.put<ProfileResponse>(
                    "/api/profile",
                    Api.encode(
                        ProfileUpdateRequest(
                            nickname = nickname.trim(),
                            avatarColor = colorIdx,
                            avatarImage = avatarB64 ?: "",
                        ),
                    ),
                )
                applyProfile(p)
                snackbarHostState.showSnackbar("资料已更新")
            } catch (e: Exception) {
                profileError = e.message ?: "保存失败，请稍后重试"
            } finally {
                saving = false
            }
        }
    }

    fun setLoginNotify(want: Boolean) {
        if (!notifyLoaded || notifyBusy) return
        scope.launch {
            notifyBusy = true
            try {
                // PUT 是全量替换：先 GET 整份档案，再带显式 loginNotify 整份 PUT
                val p = Api.get<ProfileResponse>("/api/profile")
                val updated = Api.put<ProfileResponse>(
                    "/api/profile",
                    Api.encode(
                        ProfileUpdateRequest(
                            nickname = p.nickname,
                            avatarColor = p.avatarColor,
                            avatarImage = p.avatarImage ?: "",
                            loginNotify = want,
                        ),
                    ),
                )
                loginNotify = updated.loginNotify
                snackbarHostState.showSnackbar(if (want) "已开启新设备登录提醒" else "已关闭新设备登录提醒")
            } catch (e: Exception) {
                snackbarHostState.showSnackbar(e.message ?: "操作失败，请稍后重试")
            } finally {
                notifyBusy = false
            }
        }
    }

    /** 注销提交：双确认（注册邮箱 + purpose=delete 邮箱验证码），成功即登出回登录页。 */
    fun submitDelete() {
        val email = deleteEmail.trim()
        val code = deleteCode.trim()
        if (email.isEmpty()) {
            deleteError = "请先填写注册邮箱"
            return
        }
        if (code.isEmpty()) {
            deleteError = "请输入邮箱验证码"
            return
        }
        if (deleteBusy) return
        scope.launch {
            deleteBusy = true
            try {
                Api.post<OkResponse>("/auth/delete", Api.encode(DeleteAccountRequest(email = email, code = code)))
                showDelete = false
                // 登出回登录页：会话多半已随注销失效，登不成也不拦跳转
                runCatching { Api.post<OkResponse>("/web/logout", "{}") }
                SessionStore.clear()
                snackbarHostState.showSnackbar("注销已提交，7 天内登录可撤销")
                nav.push(Route.Login)
            } catch (e: Exception) {
                deleteError = e.message
            } finally {
                deleteBusy = false
            }
        }
    }

    ScreenScaffold(title = "账号", scrollBehavior = scrollBehavior) { innerPadding ->
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
                } else if (loadError != null) {
                    item(key = "load-error") {
                        InlineError(text = loadError, modifier = Modifier.padding(horizontal = 28.dp))
                    }
                } else {
                    // ① 账号资料
                    item(key = "profile") {
                        Column(Modifier.animateItem(fadeInSpec = ItemFadeSpec, placementSpec = ItemPlacementSpec, fadeOutSpec = ItemFadeSpec)) {
                            SmallTitle(text = "账号资料")
                            Card(modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp)) {
                                Column(Modifier.padding(16.dp)) {
                                    Row(
                                        verticalAlignment = Alignment.CenterVertically,
                                        horizontalArrangement = Arrangement.spacedBy(16.dp),
                                    ) {
                                        val effective = effectiveAvatarColorIndex(colorIdx, meUid)
                                        AvatarBox(
                                            color = AvatarPalette[effective],
                                            initial = avatarInitial(nickname, meEmail),
                                            image = avatarB64?.takeIf { it.isNotBlank() }?.let { decodeBase64Image(it) },
                                            size = 96.dp,
                                        )
                                        Column(Modifier.weight(1f)) {
                                            Text(
                                                text = "邮箱 $meEmail",
                                                style = MiuixTheme.textStyles.footnote1,
                                                color = MiuixTheme.colorScheme.onSurfaceSecondary,
                                            )
                                            Row(
                                                modifier = Modifier.padding(top = 8.dp),
                                                horizontalArrangement = Arrangement.spacedBy(12.dp),
                                            ) {
                                                TextButton(text = "更换头像", onClick = { pickAvatar() })
                                                if (!avatarB64.isNullOrBlank()) {
                                                    TextButton(
                                                        text = "移除头像",
                                                        onClick = { avatarB64 = null },
                                                        colors = textButtonColorsDanger(),
                                                    )
                                                }
                                            }
                                        }
                                    }
                                    TextField(
                                        colors = fieldLabelColors(hasError = nicknameOverlong),
                                        value = nickname,
                                        onValueChange = { nickname = it },
                                        label = "昵称（最多 64 个字）",
                                        singleLine = true,
                                        modifier = Modifier.fillMaxWidth().padding(top = 16.dp),
                                        keyboardOptions = KeyboardOptions(imeAction = ImeAction.Done),
                                    )
                                    InlineError(
                                        text = if (nicknameOverlong) "昵称最多 64 个字，请精简后重试" else null,
                                        modifier = Modifier.padding(top = 6.dp),
                                    )
                                    // 有自定义头像时收起色板行（底色只在无图时决定首字观感，
                                    // 与旧 W7 同式）；移除头像即恢复，两态永远同步
                                    if (avatarB64.isNullOrBlank()) {
                                        Row(
                                            modifier = Modifier.padding(top = 12.dp),
                                            horizontalArrangement = Arrangement.spacedBy(10.dp),
                                        ) {
                                            val effective = effectiveAvatarColorIndex(colorIdx, meUid)
                                            AvatarPalette.forEachIndexed { i, c ->
                                                val selected = i == effective
                                                Box(
                                                    modifier = Modifier
                                                        .size(32.dp)
                                                        .clip(CircleShape)
                                                        .background(c)
                                                        .then(
                                                            if (selected) {
                                                                Modifier.border(2.dp, MiuixTheme.colorScheme.primary, CircleShape)
                                                            } else {
                                                                Modifier
                                                            },
                                                        )
                                                        .clickable { colorIdx = i },
                                                )
                                            }
                                        }
                                    }
                                    Button(
                                        onClick = { saveProfile() },
                                        enabled = dirty && !nicknameOverlong && !saving,
                                        modifier = Modifier.fillMaxWidth().padding(top = 16.dp),
                                        colors = buttonColorsPrimaryApp(),
                                    ) {
                                        Text(text = "保存")
                                    }
                                    InlineError(text = profileError, modifier = Modifier.padding(top = 8.dp))
                                }
                            }
                        }
                    }

                    // ② 修改密码（两 tab：原密码 / 验证码）
                    item(key = "password") {
                        Column(Modifier.animateItem(fadeInSpec = ItemFadeSpec, placementSpec = ItemPlacementSpec, fadeOutSpec = ItemFadeSpec)) {
                            SmallTitle(text = "修改密码")
                            Card(modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp)) {
                                Column(Modifier.padding(12.dp)) {
                                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                        TextButton(
                                            text = "原密码",
                                            onClick = { pwTab = PwTab.OLD },
                                            modifier = Modifier.weight(1f),
                                            colors = if (pwTab == PwTab.OLD) textButtonColorsPrimaryApp() else ButtonDefaults.textButtonColors(),
                                        )
                                        TextButton(
                                            text = "验证码",
                                            onClick = { pwTab = PwTab.CODE },
                                            modifier = Modifier.weight(1f),
                                            colors = if (pwTab == PwTab.CODE) textButtonColorsPrimaryApp() else ButtonDefaults.textButtonColors(),
                                        )
                                    }
                                    if (pwTab == PwTab.OLD) {
                                        TextField(
                                            colors = fieldLabelColors(),
                                            value = pwOld,
                                            onValueChange = { pwOld = it },
                                            label = "原密码",
                                            singleLine = true,
                                            modifier = Modifier.fillMaxWidth().padding(top = 12.dp),
                                            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password, imeAction = ImeAction.Next),
                                        )
                                        TextField(
                                            colors = fieldLabelColors(),
                                            value = pwNew,
                                            onValueChange = { pwNew = it },
                                            label = "新密码（至少 8 位）",
                                            singleLine = true,
                                            modifier = Modifier.fillMaxWidth().padding(top = 12.dp),
                                            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password, imeAction = ImeAction.Done),
                                        )
                                    } else {
                                        Text(
                                            text = "验证码发到本账号的绑定邮箱。",
                                            style = MiuixTheme.textStyles.footnote1,
                                            color = MiuixTheme.colorScheme.onSurfaceSecondary,
                                            modifier = Modifier.padding(top = 12.dp),
                                        )
                                        Row(
                                            modifier = Modifier.fillMaxWidth().padding(top = 12.dp),
                                            verticalAlignment = Alignment.CenterVertically,
                                        ) {
                                            TextField(
                                                colors = fieldLabelColors(),
                                                value = pwCode,
                                                onValueChange = { pwCode = it.filter { c -> c.isDigit() }.take(6) },
                                                label = "验证码（6 位）",
                                                singleLine = true,
                                                modifier = Modifier.weight(1f),
                                                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword, imeAction = ImeAction.Done),
                                            )
                                            Spacer(Modifier.width(12.dp))
                                            TextButton(
                                                text = if (pwCooldown.running) "${pwCooldown.left} 秒后重发" else "获取验证码",
                                                enabled = !pwCooldown.running && !pwBusy,
                                                onClick = {
                                                    pwError = null
                                                    scope.launch {
                                                        try {
                                                            Api.post<SentResponse>("/auth/send-change-code", "{}")
                                                            pwCooldown.start()
                                                            snackbarHostState.showSnackbar("验证码已发送到绑定邮箱")
                                                        } catch (e: Exception) {
                                                            pwError = e.message
                                                        }
                                                    }
                                                },
                                            )
                                        }
                                        TextField(
                                            colors = fieldLabelColors(),
                                            value = pwCodeNew,
                                            onValueChange = { pwCodeNew = it },
                                            label = "新密码（至少 8 位）",
                                            singleLine = true,
                                            modifier = Modifier.fillMaxWidth().padding(top = 12.dp),
                                            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password, imeAction = ImeAction.Done),
                                        )
                                    }
                                    InlineError(text = pwError, modifier = Modifier.padding(top = 8.dp))
                                    Text(
                                        text = "改密码会把其它设备全部退出，本机保持登录",
                                        style = MiuixTheme.textStyles.footnote1,
                                        color = MiuixTheme.colorScheme.onSurfaceSecondary,
                                        modifier = Modifier.padding(top = 8.dp),
                                    )
                                    Button(
                                        onClick = {
                                            pwError = null
                                            scope.launch {
                                                pwBusy = true
                                                try {
                                                    // 改密是服务端 reauth 闸操作：先过强认证再提交
                                                    ReauthController.ensure()
                                                    if (pwTab == PwTab.OLD) {
                                                        Api.post<AuthResponse>(
                                                            "/auth/change-password",
                                                            Api.encode(ChangePasswordRequest(oldPassword = pwOld, newPassword = pwNew)),
                                                        )
                                                        pwOld = ""
                                                        pwNew = ""
                                                    } else {
                                                        Api.post<AuthResponse>(
                                                            "/auth/change-password-code",
                                                            Api.encode(ChangePasswordCodeRequest(code = pwCode.trim(), password = pwCodeNew)),
                                                        )
                                                        pwCode = ""
                                                        pwCodeNew = ""
                                                    }
                                                    // 会话凭据已换发（Set-Cookie）：重拉会话同步 CSRF 令牌
                                                    runCatching { SessionStore.refresh() }
                                                    snackbarHostState.showSnackbar("密码已修改")
                                                } catch (e: Exception) {
                                                    pwError = e.message
                                                } finally {
                                                    pwBusy = false
                                                }
                                            }
                                        },
                                        enabled = !pwBusy,
                                        modifier = Modifier.fillMaxWidth().padding(top = 12.dp),
                                        colors = buttonColorsPrimaryApp(),
                                    ) {
                                        Text(text = "更新密码")
                                    }
                                }
                            }
                        }
                    }

                    // ③ 修改邮箱
                    item(key = "email") {
                        Column(Modifier.animateItem(fadeInSpec = ItemFadeSpec, placementSpec = ItemPlacementSpec, fadeOutSpec = ItemFadeSpec)) {
                            SmallTitle(text = "修改邮箱")
                            Card(modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp)) {
                                Column(Modifier.padding(12.dp)) {
                                    Text(
                                        text = "验证码发到新邮箱；提交需要当前密码。",
                                        style = MiuixTheme.textStyles.footnote1,
                                        color = MiuixTheme.colorScheme.onSurfaceSecondary,
                                    )
                                    TextField(
                                        colors = fieldLabelColors(),
                                        value = emailNew,
                                        onValueChange = { emailNew = it },
                                        label = "新邮箱",
                                        singleLine = true,
                                        modifier = Modifier.fillMaxWidth().padding(top = 12.dp),
                                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Email, imeAction = ImeAction.Next),
                                    )
                                    Row(
                                        modifier = Modifier.fillMaxWidth().padding(top = 12.dp),
                                        verticalAlignment = Alignment.CenterVertically,
                                    ) {
                                        TextField(
                                            colors = fieldLabelColors(),
                                            value = emailCode,
                                            onValueChange = { emailCode = it.filter { c -> c.isDigit() }.take(6) },
                                            label = "验证码（6 位）",
                                            singleLine = true,
                                            modifier = Modifier.weight(1f),
                                            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword, imeAction = ImeAction.Done),
                                        )
                                        Spacer(Modifier.width(12.dp))
                                        TextButton(
                                            text = if (emailCooldown.running) "${emailCooldown.left} 秒后重发" else "获取验证码",
                                            enabled = !emailCooldown.running && !emailBusy,
                                            onClick = {
                                                emailError = null
                                                val target = emailNew.trim()
                                                if (target.isEmpty()) {
                                                    emailError = "请先填写新邮箱"
                                                    return@TextButton
                                                }
                                                scope.launch {
                                                    try {
                                                        Api.post<SentResponse>(
                                                            "/auth/send-change-email-code",
                                                            Api.encode(SendChangeEmailCodeBody(email = target)),
                                                        )
                                                        emailCooldown.start()
                                                        snackbarHostState.showSnackbar("验证码已发送到新邮箱")
                                                    } catch (e: Exception) {
                                                        emailError = e.message
                                                    }
                                                }
                                            },
                                        )
                                    }
                                    TextField(
                                        colors = fieldLabelColors(),
                                        value = emailPassword,
                                        onValueChange = { emailPassword = it },
                                        label = "当前密码",
                                        singleLine = true,
                                        modifier = Modifier.fillMaxWidth().padding(top = 12.dp),
                                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password, imeAction = ImeAction.Done),
                                    )
                                    InlineError(text = emailError, modifier = Modifier.padding(top = 8.dp))
                                    Button(
                                        onClick = {
                                            emailError = null
                                            scope.launch {
                                                emailBusy = true
                                                try {
                                                    ReauthController.ensure()
                                                    Api.post<OkResponse>(
                                                        "/auth/change-email",
                                                        Api.encode(
                                                            ChangeEmailRequest(
                                                                password = emailPassword,
                                                                email = emailNew.trim(),
                                                                code = emailCode.trim(),
                                                            ),
                                                        ),
                                                    )
                                                    emailCode = ""
                                                    emailPassword = ""
                                                    snackbarHostState.showSnackbar("邮箱已更新，新旧邮箱都收到了通知")
                                                } catch (e: Exception) {
                                                    emailError = e.message
                                                } finally {
                                                    emailBusy = false
                                                }
                                            }
                                        },
                                        enabled = !emailBusy,
                                        modifier = Modifier.fillMaxWidth().padding(top = 12.dp),
                                        colors = buttonColorsPrimaryApp(),
                                    ) {
                                        Text(text = "更新邮箱")
                                    }
                                    Text(
                                        text = "改绑不会退出其它设备，新旧邮箱都会收到通知。",
                                        style = MiuixTheme.textStyles.footnote1,
                                        color = MiuixTheme.colorScheme.onSurfaceSecondary,
                                        modifier = Modifier.padding(top = 8.dp),
                                    )
                                }
                            }
                        }
                    }

                    // ④ 登录提醒（SwitchPreference 形态的开关行）
                    item(key = "notify") {
                        Column(Modifier.animateItem(fadeInSpec = ItemFadeSpec, placementSpec = ItemPlacementSpec, fadeOutSpec = ItemFadeSpec)) {
                            SmallTitle(text = "登录提醒")
                            Card(modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp)) {
                                BasicComponent(
                                    title = "新设备登录提醒",
                                    summary = "在陌生设备上登录时，向绑定邮箱发送提醒邮件。",
                                    summaryColor = BasicComponentDefaults.summaryColor(
                                        color = MiuixTheme.colorScheme.onSurfaceSecondary,
                                    ),
                                    startAction = { PrefIcon(Lucide.Bell) },
                                    endActions = {
                                        Switch(
                                            checked = loginNotify,
                                            onCheckedChange = { setLoginNotify(it) },
                                            enabled = notifyLoaded && !notifyBusy,
                                        )
                                    },
                                )
                            }
                        }
                    }

                    // ⑤ 危险区：注销账号
                    item(key = "delete") {
                        Column(Modifier.animateItem(fadeInSpec = ItemFadeSpec, placementSpec = ItemPlacementSpec, fadeOutSpec = ItemFadeSpec)) {
                            SmallTitle(text = "危险操作")
                            Card(modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp)) {
                                Column(Modifier.padding(12.dp)) {
                                    Text(
                                        text = "注销账号",
                                        style = MiuixTheme.textStyles.title3,
                                        fontWeight = FontWeight.SemiBold,
                                        color = cn.horatio.authweb.theme.OnCardColors.danger,
                                    )
                                    Text(
                                        text = "注销后，你在本服务下接入的所有项目将一并注销，全部项目的数据都会被清空且不可恢复。",
                                        style = MiuixTheme.textStyles.footnote1,
                                        color = MiuixTheme.colorScheme.onSurfaceSecondary,
                                        modifier = Modifier.padding(top = 8.dp),
                                    )
                                    Text(
                                        text = "建议先备份各项目的数据。",
                                        style = MiuixTheme.textStyles.footnote1,
                                        color = MiuixTheme.colorScheme.onSurfaceSecondary,
                                        modifier = Modifier.padding(top = 6.dp),
                                    )
                                    Text(
                                        text = "提交后 7 天内为反悔期：期间重新登录，或点击邮件中的撤销链接，即可取消注销；7 天后将执行注销，数据清空且不可恢复。",
                                        style = MiuixTheme.textStyles.footnote1,
                                        color = MiuixTheme.colorScheme.onSurfaceSecondary,
                                        modifier = Modifier.padding(top = 6.dp),
                                    )
                                    Button(
                                        onClick = {
                                            deleteEmail = meEmail
                                            deleteCode = ""
                                            deleteError = null
                                            showDelete = true
                                        },
                                        modifier = Modifier.fillMaxWidth().padding(top = 12.dp),
                                        colors = buttonColorsDanger(),
                                    ) {
                                        Text(text = "注销账号")
                                    }
                                }
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

        // 注销双确认：注册邮箱 + 邮箱验证码（purpose=delete），7 天反悔期（旧 delete-dialog 文案）
        OverlayDialog(
            show = showDelete,
            title = "确认注销账号",
            summary = "输入注册邮箱与邮箱验证码确认。7 天反悔期内重新登录即可取消。",
            onDismissRequest = { showDelete = false },
            onDismissFinished = { showDelete = false },
        ) {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                TextField(
                    colors = fieldLabelColors(),
                    value = deleteEmail,
                    onValueChange = { deleteEmail = it },
                    label = "注册邮箱",
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Email, imeAction = ImeAction.Next),
                )
                Row(verticalAlignment = Alignment.CenterVertically) {
                    TextField(
                        colors = fieldLabelColors(),
                        value = deleteCode,
                        onValueChange = { deleteCode = it.filter { c -> c.isDigit() }.take(6) },
                        label = "邮箱验证码（6 位）",
                        singleLine = true,
                        modifier = Modifier.weight(1f),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword, imeAction = ImeAction.Done),
                    )
                    Spacer(Modifier.width(12.dp))
                    TextButton(
                        text = if (deleteCooldown.running) "${deleteCooldown.left} 秒后重发" else "获取验证码",
                        enabled = !deleteCooldown.running && !deleteBusy,
                        onClick = {
                            deleteError = null
                            val target = deleteEmail.trim()
                            if (target.isEmpty()) {
                                deleteError = "请先填写注册邮箱"
                                return@TextButton
                            }
                            scope.launch {
                                try {
                                    Api.post<SentResponse>(
                                        "/auth/send-code",
                                        Api.encode(SendCodeRequest(email = target, purpose = "delete")),
                                    )
                                    deleteCooldown.start()
                                    snackbarHostState.showSnackbar("验证码已发送，没收到可查看垃圾箱")
                                } catch (e: Exception) {
                                    deleteError = e.message
                                }
                            }
                        },
                    )
                }
                Text(
                    text = "验证码 5 分钟内有效",
                    style = MiuixTheme.textStyles.footnote1,
                    color = MiuixTheme.colorScheme.onSurfaceSecondary,
                )
                InlineError(text = deleteError)
                DialogButtonRow(
                    cancelText = "取消",
                    onCancel = { showDelete = false },
                    confirmText = "永久注销账号",
                    onConfirm = { submitDelete() },
                    confirmColors = textButtonColorsDanger(),
                )
            }
        }
    }
}

// ---- 头像文件选择 + 缩图（浏览器侧，行为=旧 app.js cropAvatar）----
//
// 输入框由 JS 临时创建并直接 click（Compose/Wasm 没有文件选择器，也不能把 DOM input
// 嵌进布局）；Promise 永不 reject：取消回空串，失败回 "err:<原因>"，成功回**裸 base64**
// （剥 data: 前缀、标准字母表带 padding）——与日记客户端 Base64.NO_WRAP 同形，
// 服务端 maxAvatarImageBytes=700KB 按解码字节卡（base64 长度×3/4 估算即可）。
private const val PICK_CROP_AVATAR_JS = """
() => new Promise((resolve) => {
  const input = document.createElement('input');
  input.type = 'file';
  input.accept = 'image/*';
  input.onchange = async () => {
    const file = input.files && input.files[0];
    if (!file) { resolve(''); return; }
    const AVATAR_MAX_DECODED = 700 * 1024;
    let url = '';
    try {
      url = URL.createObjectURL(file);
      const img = await new Promise((res, rej) => {
        const im = new Image();
        im.onload = () => res(im);
        im.onerror = () => rej(new Error('图片无法解码，请换一张'));
        im.src = url;
      });
      const side = Math.min(img.naturalWidth, img.naturalHeight);
      if (!side) { resolve('err:图片尺寸异常，请换一张'); return; }
      let size = Math.min(side, 512);
      const sx = (img.naturalWidth - side) / 2;
      const sy = (img.naturalHeight - side) / 2;
      let out = '';
      for (let attempt = 0; attempt < 3 && !out; attempt++) {
        const canvas = document.createElement('canvas');
        canvas.width = size;
        canvas.height = size;
        canvas.getContext('2d').drawImage(img, sx, sy, side, side, 0, 0, size, size);
        for (let q = 0.85; q >= 0.3; q -= 0.1) {
          const b64 = canvas.toDataURL('image/jpeg', q).split(',')[1] || '';
          if (Math.floor(b64.length * 3 / 4) <= AVATAR_MAX_DECODED) { out = b64; break; }
        }
        size = Math.floor(size * 0.7);
      }
      resolve(out || 'err:图片过大，请换一张更小的图');
    } catch (e) {
      resolve('err:' + ((e && e.message) || '图片处理失败，请换一张试试'));
    } finally {
      if (url) URL.revokeObjectURL(url);
    }
  };
  input.click();
})
"""

@JsFun(PICK_CROP_AVATAR_JS)
private external fun pickAndCropAvatar(): Promise<JsString>
