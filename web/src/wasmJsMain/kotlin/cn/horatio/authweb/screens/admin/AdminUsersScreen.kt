// 管理后台「用户」屏（super 专属）。
//
// 交付清单只允许各屏文件与 shell/ReauthDialog.kt 落地，因此 screens/admin 包共享的
// DTO、组件与工具也集中在本文件顶部，同包其余各屏直接复用（Kotlin 同包跨文件可见）。
//
// 端点权威是 cmd/server/admin.go：列表 GET /admin/users?query=&limit=&offset=（**不是**
// q），邀请 /admin/users/invite*，批量 POST /admin/users/bulk {kind,uids,app,until,reason}。
package cn.horatio.authweb.screens.admin

import androidx.compose.foundation.background
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyListScope
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.state.ToggleableState
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import cn.horatio.authweb.component.DialogButtonRow
import cn.horatio.authweb.component.TextButton
import cn.horatio.authweb.component.textButtonColorsDanger
import cn.horatio.authweb.component.textButtonColorsPrimaryApp
import cn.horatio.authweb.data.Api
import cn.horatio.authweb.data.ApiException
import cn.horatio.authweb.data.OkResponse
import cn.horatio.authweb.data.RegistryApp
import cn.horatio.authweb.data.ReauthController
import cn.horatio.authweb.data.SessionStore
import cn.horatio.authweb.nav.LocalNav
import cn.horatio.authweb.nav.Route
import cn.horatio.authweb.shell.LocalSnackbarHostState
import cn.horatio.authweb.shell.ScreenScaffold
import cn.horatio.authweb.shell.pageContentPadding
import cn.horatio.authweb.shell.pageScrollModifiers
import cn.horatio.authweb.theme.OnCardColors
import cn.horatio.authweb.theme.StatusColors
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.await
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.datetime.Clock
import kotlinx.datetime.Instant
import kotlinx.datetime.LocalDate
import kotlinx.datetime.LocalDateTime
import kotlinx.datetime.TimeZone
import kotlinx.datetime.atStartOfDayIn
import kotlinx.datetime.toInstant
import kotlinx.datetime.toLocalDateTime
import kotlinx.serialization.Serializable
import top.yukonga.miuix.kmp.basic.ButtonDefaults
import top.yukonga.miuix.kmp.basic.Card
import top.yukonga.miuix.kmp.basic.Checkbox
import top.yukonga.miuix.kmp.basic.MiuixScrollBehavior
import top.yukonga.miuix.kmp.basic.ScrollBehavior
import top.yukonga.miuix.kmp.basic.TextField
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.preference.WindowDropdownPreference
import top.yukonga.miuix.kmp.overlay.OverlayDialog
import top.yukonga.miuix.kmp.theme.MiuixTheme

// ===================== 共享 DTO（回执形状以 Go 源码为准） =====================

/** GET /admin/users 一条（auth.AdminUser）。 */
@Serializable
data class AdminUser(
    val uid: Long = 0,
    val email: String = "",
    val role: String = "user",
    val createdAt: Long = 0,
    val totpEnabled: Boolean = false,
    val passkeyCount: Int = 0,
    val scopeCount: Int = 0,
    val nickname: String = "",
    val avatarColor: Int = 0,
    val hasAvatar: Boolean = false,
)

/** 后台分页统一回执 `page{items,total}`（cmd/server/admin.go 的 page 结构）。 */
@Serializable
data class AdminPage<T>(
    val items: List<T> = emptyList(),
    val total: Int = 0,
)

/** GET /admin/users/invites 的一条（auth.AdminInvite；id 是十进制串）。 */
@Serializable
data class AdminInvite(
    val id: String = "",
    val email: String = "",
    val app: String = "",
    val createdAt: Long = 0,
    val expiresAt: Long = 0,
    val state: String = "pending",
)

@Serializable
data class InvitesResponse(val invites: List<AdminInvite> = emptyList())

@Serializable
data class InviteRequest(val email: String = "", val app: String = "")

@Serializable
data class InviteResult(val ok: Boolean = true, val expiresAt: Long = 0)

/** POST /admin/users/bulk（kind: password_reset | ban | unban）。 */
@Serializable
data class BulkRequest(
    val kind: String = "",
    val uids: List<Long> = emptyList(),
    val app: String = "",
    val until: Long = 0,
    val reason: String = "",
)

@Serializable
data class BulkItemResult(val uid: Long = 0, val ok: Boolean = false, val message: String = "")

@Serializable
data class BulkResult(
    val batchId: String = "",
    val kind: String = "",
    val total: Int = 0,
    val succeeded: Int = 0,
    val failed: Int = 0,
    val items: List<BulkItemResult> = emptyList(),
)

/** GET /admin/projects 的一条（auth.AdminProject；{projects:[...]} 信封见 [ProjectsResponse]）。 */
@Serializable
data class AdminProjectMember(val uid: Long = 0, val email: String = "")

@Serializable
data class AdminProject(
    val app: String = "",
    val name: String = "",
    val restricted: Boolean = false,
    val members: List<AdminProjectMember> = emptyList(),
    val clientId: String = "",
    val redirectUris: List<String>? = null,
)

/** GET /admin/projects 回执（{projects:[...]} 信封）。 */
@Serializable
data class ProjectsResponse(val projects: List<AdminProject> = emptyList())

// ===================== 共享工具 =====================

private fun pad2(n: Int): String = if (n < 10) "0$n" else n.toString()

/** 当前时刻毫秒。kotlinx.datetime 0.8 已把 Clock 移交 stdlib 的 `kotlin.time.Clock`。 */
@OptIn(kotlin.time.ExperimentalTime::class)
internal fun nowMs(): Long = kotlin.time.Clock.System.now().toEpochMilliseconds()

private fun localOf(ms: Long) =
    Instant.fromEpochMilliseconds(ms).toLocalDateTime(TimeZone.currentSystemDefault())

/** 毫秒 → `yyyy-MM-dd HH:mm`（本机时区）；0/负数回「—」。 */
internal fun fmtTime(ms: Long): String {
    if (ms <= 0) return "—"
    val d = localOf(ms)
    return "${d.year}-${pad2(d.monthNumber)}-${pad2(d.dayOfMonth)} ${pad2(d.hour)}:${pad2(d.minute)}"
}

/** 相对时间：刚刚 / N 分钟前 / N 小时前 / N 天前（超过 30 天回落绝对时间）。 */
internal fun relTime(ms: Long): String {
    if (ms <= 0) return "—"
    val min = (nowMs() - ms) / 60_000
    return when {
        min < 1 -> "刚刚"
        min < 60 -> "$min 分钟前"
        min < 60 * 24 -> "${min / 60} 小时前"
        min < 60 * 24 * 30 -> "${min / (60 * 24)} 天前"
        else -> fmtTime(ms)
    }
}

/** 剩余时长（邀请有效期用，向上取整）：N 分钟 / N 小时 / N 天。 */
internal fun remainTime(ms: Long): String {
    if (ms <= 0) return "—"
    val left = (ms - nowMs()).coerceAtLeast(0)
    val min = (left + 59_999) / 60_000
    return when {
        min == 0L -> "不到 1 分钟"
        min < 60 -> "$min 分钟"
        min < 60 * 24 -> "${min / 60} 小时"
        min < 60 * 24 * 30 -> "${min / (60 * 24)} 天"
        else -> fmtTime(ms)
    }
}

/** `yyyy-MM-dd`（本机时区）。 */
internal fun todayStr(): String {
    val d = localOf(nowMs())
    return "${d.year}-${pad2(d.monthNumber)}-${pad2(d.dayOfMonth)}"
}

/** `yyyy-MM-dd` → 当日本地 00:00 毫秒；格式不合法回 null。 */
internal fun dayStartMs(day: String): Long? = try {
    LocalDate.parse(day).atStartOfDayIn(TimeZone.currentSystemDefault()).toEpochMilliseconds()
} catch (_: Exception) {
    null
}

/** `yyyy-MM-dd` → 当日本地 23:59:59 毫秒；格式不合法回 null。 */
internal fun dayEndMs(day: String): Long? = try {
    dayStartMs(day)?.let { it + 24 * 3600 * 1000 - 1 }
} catch (_: Exception) {
    null
}

/** `yyyy-MM-ddTHH:mm`（datetime-local 输入）→ 毫秒；格式不合法回 null。 */
internal fun localDateTimeMs(raw: String): Long? = try {
    LocalDateTime.parse(raw).toInstant(TimeZone.currentSystemDefault()).toEpochMilliseconds()
} catch (_: Exception) {
    null
}

/** `yyyy-MM-dd` 偏移 N 天（时间快捷档用）。
 *  日期加减走 civil 算法纯算术——0.8.0 的 LocalDate.plusDays 是 internal，别再指过去。 */
internal fun dayShift(day: String, delta: Int): String = try {
    val d = LocalDate.parse(day)
    val (y, m, dd) = civilFromDays(daysFromCivil(d.year, d.monthNumber, d.dayOfMonth) + delta)
    "$y-${pad2(m)}-${pad2(dd)}"
} catch (_: Exception) {
    day
}

/** days-from-civil（Howard Hinnant）：公历日期 → 距 1970-01-01 的天数。 */
private fun daysFromCivil(y0: Int, m: Int, d: Int): Long {
    val y = if (m <= 2) y0 - 1 else y0
    val era = (if (y >= 0) y else y - 399) / 400
    val yoe = (y - era * 400).toLong()
    val doy = ((153 * (if (m > 2) m - 3 else m + 9) + 2) / 5 + d - 1).toLong()
    val doe = yoe * 365 + yoe / 4 - yoe / 100 + doy
    return era * 146097L + doe - 719468L
}

/** civil-from-days：天数 → (年, 月, 日)，[daysFromCivil] 的逆运算。 */
private fun civilFromDays(input: Long): Triple<Int, Int, Int> {
    val z = input + 719468L
    val era = (if (z >= 0) z else z - 146096L) / 146097L
    val doe = z - era * 146097L
    val yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365
    val y = yoe + era * 400
    val doy = doe - (365 * yoe + yoe / 4 - yoe / 100)
    val mp = (5 * doy + 2) / 153
    val d = (doy - (153 * mp + 2) / 5 + 1).toInt()
    val m = if (mp < 10) mp + 3 else mp - 9
    return Triple((if (m <= 2) y + 1 else y).toInt(), m.toInt(), d)
}

/** 保守的 query 编码（UTF-8 字节 → percent；输入是邮箱/uid/事件名，够用）。 */
internal fun urlEnc(raw: String): String {
    val bytes = raw.encodeToByteArray()
    val hex = "0123456789ABCDEF"
    val sb = StringBuilder(bytes.size)
    for (b in bytes) {
        val v = b.toInt() and 0xFF
        val plain = (v in 0x41..0x5A) || (v in 0x61..0x7A) || (v in 0x30..0x39) ||
            v == 0x2D || v == 0x5F || v == 0x2E || v == 0x7E
        if (plain) {
            sb.append(v.toChar())
        } else {
            sb.append('%').append(hex[v shr 4]).append(hex[v and 0xF])
        }
    }
    return sb.toString()
}

private var cachedLabels: Map<String, String>? = null

/** 项目 slug → 展示名（含会话里的 `web` = 网页端），注册表结果进程内缓存。 */
internal suspend fun appLabels(): Map<String, String> {
    cachedLabels?.let { return it }
    val map = mutableMapOf("web" to "网页")
    try {
        Api.get<List<RegistryApp>>("/web/registry").forEach { map[it.key] = it.label }
    } catch (_: Exception) {
        // 拿不到注册表就只留 web：标签缺失不该让页面挂掉
    }
    cachedLabels = map
    return map
}

/** 注册表项目（裸数组回执，见 Dtos.kt 注释）。 */
internal suspend fun registryApps(): List<RegistryApp> = try {
    Api.get<List<RegistryApp>>("/web/registry")
} catch (_: Exception) {
    emptyList()
}

/** 封禁/批量范围选项：super = 全局+全部项目；项目管理员 = 仅其授权项目。 */
internal suspend fun banScopeOptions(): List<Pair<String, String>> {
    if (SessionStore.isSuper) {
        return listOf("*" to "全部项目（全局）") + registryApps().map { it.key to it.label }
    }
    return try {
        Api.get<ProjectsResponse>("/admin/projects").projects.map { it.app to it.name }
    } catch (_: Exception) {
        emptyList()
    }
}

/** 角色三值 → 中文（旧版 ROLE_LABEL 逐字）。 */
internal fun roleLabel(role: String): String = when (role) {
    "super" -> "平台管理员"
    "admin" -> "项目管理员"
    else -> "普通用户"
}

internal fun scopeSummary(u: AdminUser): String {
    if (u.role == "super") return "管理全部项目"
    return if (u.scopeCount > 0) "已授权 ${u.scopeCount} 个项目" else "未授权任何项目"
}

// ===================== 共享组件 =====================

/**
 * 后台统一页面骨架：内容层拿 [PaddingValues] 与本屏 [ScrollBehavior] 自行铺 LazyColumn
 * （与日记 App 的 ScreenScaffold + pageScrollModifiers 配方同款）。
 */
@Composable
internal fun AdminScaffold(
    title: String,
    subtitle: String = "",
    navigationIcon: @Composable () -> Unit = {},
    actions: @Composable RowScope.() -> Unit = {},
    content: @Composable (PaddingValues, ScrollBehavior) -> Unit,
) {
    val scrollBehavior = MiuixScrollBehavior()
    ScreenScaffold(
        title = title,
        subtitle = subtitle,
        scrollBehavior = scrollBehavior,
        navigationIcon = navigationIcon,
        actions = actions,
    ) { innerPadding ->
        val padding = pageContentPadding(innerPadding, PaddingValues(0.dp), extraBottom = 16.dp)
        content(padding, scrollBehavior)
    }
}

/** [AdminScaffold] 的 LazyColumn 快捷铺法：统一 spacing 与滚动链。 */
@Composable
internal fun AdminList(
    padding: PaddingValues,
    scrollBehavior: ScrollBehavior,
    content: LazyListScope.() -> Unit,
) {
    LazyColumn(
        Modifier.fillMaxSize().pageScrollModifiers(scrollBehavior),
        contentPadding = padding,
        verticalArrangement = Arrangement.spacedBy(4.dp),
        content = content,
    )
}

internal enum class BadgeTone { Primary, Success, Warning, Neutral }

/** 小徽标：色底 + 语义字色（卡底用 OnCardColors 变体，保证 4.5:1）。 */
@Composable
internal fun AdminBadge(
    text: String,
    tone: BadgeTone = BadgeTone.Neutral,
    modifier: Modifier = Modifier,
) {
    val bg = when (tone) {
        BadgeTone.Primary -> MiuixTheme.colorScheme.primary.copy(alpha = 0.14f)
        BadgeTone.Success -> StatusColors.success.copy(alpha = 0.14f)
        BadgeTone.Warning -> StatusColors.warning.copy(alpha = 0.14f)
        BadgeTone.Neutral -> MiuixTheme.colorScheme.secondaryContainer
    }
    val fg = when (tone) {
        BadgeTone.Primary -> OnCardColors.primary
        BadgeTone.Success -> OnCardColors.success
        BadgeTone.Warning -> OnCardColors.warning
        BadgeTone.Neutral -> MiuixTheme.colorScheme.onSurfaceVariantSummary
    }
    Box(
        modifier
            .background(bg, RoundedCornerShape(6.dp))
            .padding(horizontal = 6.dp, vertical = 2.dp),
    ) {
        Text(text = text, style = MiuixTheme.textStyles.footnote2, color = fg, maxLines = 1)
    }
}

/** 页面底红字（403/401 等闸口 message 就地展示）。 */
@Composable
internal fun InlineError(message: String?, modifier: Modifier = Modifier) {
    if (message.isNullOrBlank()) return
    Text(
        text = message,
        style = MiuixTheme.textStyles.footnote1,
        color = OnCardColors.danger,
        modifier = modifier.fillMaxWidth(),
    )
}

/** 空态/读取中提示（灰字、居中）。 */
@Composable
internal fun StateHint(text: String, modifier: Modifier = Modifier) {
    Text(
        text = text,
        style = MiuixTheme.textStyles.footnote1,
        color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
        modifier = modifier.fillMaxWidth().padding(vertical = 8.dp),
        textAlign = TextAlign.Center,
    )
}

/** 后台统一卡片：标题行（可带右侧动作）+ 可选说明 + 内容。 */
@Composable
internal fun SectionCard(
    title: String? = null,
    hint: String? = null,
    modifier: Modifier = Modifier,
    actions: @Composable RowScope.() -> Unit = {},
    content: @Composable ColumnScope.() -> Unit,
) {
    Card(modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 6.dp)) {
        Column(
            Modifier.fillMaxWidth().padding(12.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            if (title != null) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    if (title != null) {
                        Text(
                            text = title,
                            style = MiuixTheme.textStyles.title3,
                            color = MiuixTheme.colorScheme.onSurface,
                            modifier = Modifier.weight(1f),
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                    }
                    actions()
                }
            }
            if (hint != null) {
                Text(
                    text = hint,
                    style = MiuixTheme.textStyles.footnote1,
                    color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                )
            }
            content()
        }
    }
}

/** 标签 + 值两列（详情摘要用）。 */
@Composable
internal fun KeyValue(label: String, value: String, modifier: Modifier = Modifier) {
    Column(modifier) {
        Text(
            text = label,
            style = MiuixTheme.textStyles.footnote2,
            color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
        )
        Text(
            text = value,
            style = MiuixTheme.textStyles.body2,
            color = MiuixTheme.colorScheme.onSurface,
            maxLines = 2,
            overflow = TextOverflow.Ellipsis,
        )
    }
}

/** 选项 chips（角色/范围/时长/天数等少量选项的取舍；超宽横向滚动）。 */
@Composable
internal fun ChoiceChips(
    options: List<Pair<String, String>>,
    selectedValue: String,
    modifier: Modifier = Modifier,
    onSelect: (String) -> Unit,
) {
    Row(
        modifier.horizontalScroll(rememberScrollState()),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        options.forEach { (value, label) ->
            val on = value == selectedValue
            TextButton(
                text = label,
                onClick = { onSelect(value) },
                colors = if (on) textButtonColorsPrimaryApp() else ButtonDefaults.textButtonColors(),
            )
        }
    }
}

/** 分页行：左说明右两钮（上一页/下一页按 offset 与本页条数禁用）。 */
@Composable
internal fun PagerRow(
    total: Int,
    shown: Int,
    offset: Int,
    onPrev: () -> Unit,
    onNext: () -> Unit,
    label: String? = null,
    modifier: Modifier = Modifier,
) {
    Row(
        modifier.fillMaxWidth().padding(horizontal = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            text = label ?: if (total > 0) "${offset + 1}–${offset + shown} / $total" else "—",
            style = MiuixTheme.textStyles.footnote1,
            color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
            modifier = Modifier.weight(1f),
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )
        TextButton(text = "上一页", onClick = onPrev, enabled = offset > 0)
        Spacer(Modifier.width(8.dp))
        TextButton(text = "下一页", onClick = onNext, enabled = offset + shown < total)
    }
}

/** 写操作回执：成功带数据，失败带中文 message（统一走重新验证闸）。 */
internal class ApiOutcome<T>(val error: String?, val value: T?) {
    val ok: Boolean get() = error == null
}

/**
 * 写操作统一收口：`ReauthController.ensure()` 先行 → 业务调用 → 成功 snackbar。
 * [call] 回带响应数据（弹层要读回执时用），[exec]/[run] 只要成败。
 */
internal class AdminActions(private val snackbar: top.yukonga.miuix.kmp.basic.SnackbarHostState) {
    suspend fun <T> call(success: String, block: suspend () -> T): ApiOutcome<T> = try {
        ReauthController.ensure()
        val value = block()
        toast(success)
        ApiOutcome(null, value)
    } catch (e: CancellationException) {
        throw e
    } catch (e: Exception) {
        ApiOutcome(e.message?.takeIf { it.isNotBlank() } ?: "操作失败，请稍后重试", null)
    }

    suspend fun exec(success: String, block: suspend () -> Unit): String? =
        call(success) { block() }.error

    suspend fun run(success: String, block: suspend () -> Unit): Boolean = exec(success, block) == null

    // 没有 SnackbarHost 时 showSnackbar 会一直挂起，超时兜底避免写流程被吞
    private suspend fun toast(message: String) {
        runCatching { withTimeoutOrNull(4_000L) { snackbar.showSnackbar(message) } }
    }
}

@Composable
internal fun rememberAdminActions(): AdminActions {
    val snackbar = LocalSnackbarHostState.current
    return remember(snackbar) { AdminActions(snackbar) }
}

/** 待确认动作：标题 + 说明 + 主/危确认钮，成功才关，失败就地红字。 */
internal class ConfirmRequest(
    val title: String,
    val desc: String,
    val success: String,
    val danger: Boolean = true,
    val confirmText: String = "确认",
    val onConfirm: suspend () -> Unit,
)

@Composable
internal fun ConfirmActionDialog(request: ConfirmRequest?, onDismissed: () -> Unit) {
    val req = request ?: return
    val actions = rememberAdminActions()
    val scope = rememberCoroutineScope()
    var busy by remember(request) { mutableStateOf(false) }
    var error by remember(request) { mutableStateOf<String?>(null) }

    OverlayDialog(
        show = true,
        onDismissRequest = { if (!busy) onDismissed() },
        onDismissFinished = {},
        title = req.title,
        summary = req.desc,
    ) {
        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            InlineError(error)
            DialogButtonRow(
                confirmText = req.confirmText,
                onConfirm = {
                    if (!busy) {
                        busy = true
                        scope.launch {
                            val err = actions.exec(req.success) { req.onConfirm() }
                            error = err
                            busy = false
                            if (err == null) onDismissed()
                        }
                    }
                },
                onCancel = { if (!busy) onDismissed() },
                confirmColors = if (req.danger) textButtonColorsDanger() else textButtonColorsPrimaryApp(),
            )
        }
    }
}

// ===================== 用户屏 =====================

/** 一次性临时密码展示层（重置密码回执只出现一次，关层即清零）。 */
@Composable
internal fun TempPasswordDialog(
    password: String?,
    notify: Boolean,
    onDismiss: () -> Unit,
) {
    val scope = rememberCoroutineScope()
    password ?: return
    OverlayDialog(
        show = true,
        onDismissRequest = onDismiss,
        onDismissFinished = {},
        title = "重置完成",
        summary = if (notify) {
            "此密码仅显示一次，关闭后无法再次查看。邮件已发送给用户。"
        } else {
            "此密码仅显示一次，关闭后无法再次查看。请通过其它渠道转告用户。"
        },
    ) {
        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(
                text = password,
                style = MiuixTheme.textStyles.title3,
                color = MiuixTheme.colorScheme.onSurface,
                fontFamily = FontFamily.Monospace,
                modifier = Modifier.fillMaxWidth(),
            )
            DialogButtonRow(
                confirmText = "复制",
                onConfirm = {
                    scope.launch { copyToClipboard(password) }
                    onDismiss()
                },
                onCancel = onDismiss,
                confirmColors = textButtonColorsPrimaryApp(),
            )
        }
    }
}

private const val USER_PAGE = 20

private val BULK_TITLE = mapOf(
    "password_reset" to "批量重置密码",
    "ban" to "批量封禁",
    "unban" to "批量解除封禁",
)

private val BULK_CONSEQUENCES = mapOf(
    "password_reset" to listOf(
        "为每位所选用户生成一个 16 位临时密码，并要求其下次登录时修改",
        "新密码邮件通知到各自的登录邮箱（临时密码不进面板，也不进日志）",
        "这些账号的现有登录会被全部吊销，已登录设备需重新登录",
    ),
    "ban" to listOf(
        "所选用户在所选范围内无法登录，该范围内已登录的设备立即被退出",
        "重复封禁按本次配置覆盖既有记录；限时到期自动解除，永久需手动解封",
        "一次配置（范围/时长/原因）套用到全部所选用户",
    ),
    "unban" to listOf(
        "解除所选用户在所选范围内的封禁，该范围随即恢复登录",
        "解封是幂等的：没有生效中封禁的用户同样回执成功",
        "只解除所选范围，不影响同一账号其它项目的封禁",
    ),
)

private val INVITE_STATE_TONE = mapOf(
    "pending" to (BadgeTone.Primary to "待接受"),
    "accepted" to (BadgeTone.Success to "已接受"),
    "revoked" to (BadgeTone.Neutral to "已撤销"),
    "expired" to (BadgeTone.Neutral to "已过期"),
)

@Composable
fun AdminUsersScreen() {
    val nav = LocalNav.current
    val actions = rememberAdminActions()
    val scope = rememberCoroutineScope()

    var query by remember { mutableStateOf("") }
    var submitted by remember { mutableStateOf("") }
    var offset by remember { mutableStateOf(0) }
    var total by remember { mutableStateOf(0) }
    var users by remember { mutableStateOf<List<AdminUser>>(emptyList()) }
    var loading by remember { mutableStateOf(true) }
    var error by remember { mutableStateOf<String?>(null) }

    var invites by remember { mutableStateOf<List<AdminInvite>>(emptyList()) }
    var invitesOpen by remember { mutableStateOf(false) }
    var invitesError by remember { mutableStateOf<String?>(null) }

    val selected = remember { mutableStateMapOf<Long, String>() }

    // 邀请弹层
    var inviteShow by remember { mutableStateOf(false) }
    var inviteEmail by remember { mutableStateOf("") }
    var inviteApp by remember { mutableStateOf("") }
    var inviteApps by remember { mutableStateOf<List<Pair<String, String>>>(emptyList()) }
    var inviteBusy by remember { mutableStateOf(false) }
    var inviteError by remember { mutableStateOf<String?>(null) }

    // 通用确认弹层
    var confirm by remember { mutableStateOf<ConfirmRequest?>(null) }

    // 批量弹层
    var bulkKind by remember { mutableStateOf<String?>(null) }
    var bulkStage by remember { mutableStateOf("confirm") }
    var bulkScope by remember { mutableStateOf("*") }
    var bulkScopes by remember { mutableStateOf<List<Pair<String, String>>>(emptyList()) }
    var bulkUntil by remember { mutableStateOf("") }
    var bulkReason by remember { mutableStateOf("") }
    var bulkTyped by remember { mutableStateOf("") }
    var bulkBusy by remember { mutableStateOf(false) }
    var bulkError by remember { mutableStateOf<String?>(null) }
    var bulkResult by remember { mutableStateOf<BulkResult?>(null) }
    val bulkEmails = remember { mutableStateMapOf<Long, String>() }

    // 一次性临时密码展示层
    var tempPassword by remember { mutableStateOf<String?>(null) }
    var tempNotify by remember { mutableStateOf(true) }

    suspend fun load() {
        loading = true
        try {
            val res = Api.get<AdminPage<AdminUser>>(
                "/admin/users?query=${urlEnc(submitted)}&limit=$USER_PAGE&offset=$offset",
            )
            users = res.items
            total = res.total
            error = null
        } catch (e: ApiException) {
            error = e.message
        } catch (_: Exception) {
            error = "读取失败，请刷新重试"
        }
        loading = false
    }

    suspend fun loadInvites() {
        try {
            invites = Api.get<InvitesResponse>("/admin/users/invites?query=${urlEnc(submitted)}").invites
            invitesError = null
        } catch (e: ApiException) {
            invitesError = e.message
        } catch (_: Exception) {
            invitesError = "邀请记录读取失败"
        }
    }

    LaunchedEffect(submitted, offset) { load() }
    LaunchedEffect(submitted) { loadInvites() }

    AdminScaffold(
        title = "用户",
        subtitle = if (total > 0) "共 $total 个账号" else "",
    ) { padding, scrollBehavior ->
        Box(Modifier.fillMaxSize()) {
        val listPadding = if (selected.isEmpty()) {
            padding
        } else {
            PaddingValues(
                top = padding.calculateTopPadding(),
                bottom = padding.calculateBottomPadding() + 72.dp,
            )
        }
        AdminList(listPadding, scrollBehavior) {
            item {
                Text(
                    text = "授予任一项目的管理权即成为项目管理员；平台管理员管全部项目、用户目录与全局配置。" +
                        "只有平台管理员能调整角色与授权。",
                    style = MiuixTheme.textStyles.footnote1,
                    color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                    modifier = Modifier.padding(horizontal = 12.dp),
                )
            }

            // 搜索 + 邀请 + 批量工具条
            item {
                SectionCard {
                    Row(
                        Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        TextField(
                            value = query,
                            onValueChange = { query = it },
                            label = "按邮箱片段或 uid 搜索（同时过滤下方邀请）",
                            singleLine = true,
                            modifier = Modifier.weight(1f),
                        )
                        TextButton(
                            text = "搜索",
                            onClick = {
                                submitted = query.trim()
                                offset = 0
                            },
                            colors = textButtonColorsPrimaryApp(),
                        )
                    }
                    Row(
                        Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        TextButton(
                            text = "邀请用户",
                            onClick = {
                                inviteEmail = ""
                                inviteApp = ""
                                inviteError = null
                                inviteBusy = false
                                inviteShow = true
                            },
                        )
                        if (selected.isNotEmpty()) {
                            Text(
                                text = "已选 ${selected.size} 人（勾选行后在底部动作条批量处理）",
                                style = MiuixTheme.textStyles.footnote1,
                                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                            )
                        }
                    }
                    InlineError(error)
                }
            }

            // 用户表
            item {
                SectionCard {
                    when {
                        loading && users.isEmpty() -> StateHint("读取中…")
                        users.isEmpty() -> StateHint(
                            if (submitted.isNotEmpty()) "没有匹配的用户" else "暂无匹配的用户",
                        )
                        else -> {
                            UserTableHeader(
                                allChecked = users.all { selected.containsKey(it.uid) },
                                onToggleAll = { on ->
                                    if (on) users.forEach { selected[it.uid] = it.email }
                                    else users.forEach { selected.remove(it.uid) }
                                },
                            )
                            users.forEach { u ->
                                UserRow(
                                    user = u,
                                    checked = selected.containsKey(u.uid),
                                    onToggle = {
                                        if (selected.containsKey(u.uid)) selected.remove(u.uid)
                                        else selected[u.uid] = u.email
                                    },
                                    onManage = { nav.push(Route.AdminUserDetail(u.uid)) },
                                )
                            }
                        }
                    }
                }
            }

            item {
                PagerRow(
                    total = total,
                    shown = users.size,
                    offset = offset,
                    onPrev = { offset = (offset - USER_PAGE).coerceAtLeast(0) },
                    onNext = { offset += USER_PAGE },
                )
            }

            // 邀请记录（折叠）
            item {
                SectionCard(
                    title = "邀请记录",
                    hint = invitesError,
                    actions = {
                        TextButton(
                            text = if (invitesOpen) "收起" else "展开",
                            onClick = { invitesOpen = !invitesOpen },
                        )
                    },
                ) {
                    if (invitesOpen) {
                        if (invites.isEmpty()) {
                            StateHint(if (submitted.isNotEmpty()) "没有匹配的邀请" else "还没有发出过邀请")
                        } else {
                            invites.forEach { invite ->
                                val (tone, label) = INVITE_STATE_TONE[invite.state]
                                    ?: (BadgeTone.Neutral to invite.state)
                                val live = invite.state == "pending" || invite.state == "expired"
                                Row(
                                    Modifier.fillMaxWidth(),
                                    verticalAlignment = Alignment.CenterVertically,
                                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                                ) {
                                    Column(Modifier.weight(1f)) {
                                        Text(
                                            text = invite.email,
                                            style = MiuixTheme.textStyles.body2,
                                            color = MiuixTheme.colorScheme.onSurface,
                                            maxLines = 1,
                                            overflow = TextOverflow.Ellipsis,
                                        )
                                        Text(
                                            text = buildString {
                                                append(if (invite.app.isEmpty()) "不限项目" else invite.app)
                                                append(" · ")
                                                append(
                                                    if (invite.state == "pending") {
                                                        "剩余 ${remainTime(invite.expiresAt)}"
                                                    } else {
                                                        "至 ${fmtTime(invite.expiresAt)}"
                                                    },
                                                )
                                            },
                                            style = MiuixTheme.textStyles.footnote2,
                                            color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                                            maxLines = 1,
                                            overflow = TextOverflow.Ellipsis,
                                        )
                                    }
                                    AdminBadge(label, tone)
                                    if (live) {
                                        TextButton(
                                            text = "重发",
                                            onClick = {
                                                confirm = ConfirmRequest(
                                                    title = "重发邀请",
                                                    desc = "将重新生成邀请链接并发信到 ${invite.email}，" +
                                                        "旧链接即刻失效，请对方打开新的那封。",
                                                    success = "邀请已重新发送至 ${invite.email}，旧链接已失效",
                                                    danger = false,
                                                ) {
                                                    Api.post<OkResponse>("/admin/users/invite/${invite.id}/resend", "{}")
                                                    loadInvites()
                                                }
                                            },
                                        )
                                        TextButton(
                                            text = "撤销",
                                            colors = textButtonColorsDanger(),
                                            onClick = {
                                                confirm = ConfirmRequest(
                                                    title = "撤销邀请",
                                                    desc = "将撤销发给 ${invite.email} 的邀请链接，对方再打开会看到" +
                                                        "「已被撤销」；需要时可重新发起邀请。",
                                                    success = "已撤销发给 ${invite.email} 的邀请",
                                                ) {
                                                    Api.post<OkResponse>("/admin/users/invite/${invite.id}/revoke", "{}")
                                                    loadInvites()
                                                }
                                            },
                                        )
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // 底部批量动作条：有勾选才出现，随选择集实时刷新
        if (selected.isNotEmpty()) {
            Row(
                Modifier
                    .align(Alignment.BottomCenter)
                    .fillMaxWidth()
                    .padding(horizontal = 12.dp, vertical = 8.dp)
                    .background(MiuixTheme.colorScheme.surface, RoundedCornerShape(16.dp))
                    .horizontalScroll(rememberScrollState())
                    .padding(horizontal = 8.dp, vertical = 4.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    text = "已选 ${selected.size} 人",
                    style = MiuixTheme.textStyles.footnote1,
                    color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                )
                TextButton(
                    text = "批量重置密码",
                    colors = textButtonColorsDanger(),
                    onClick = { bulkKind = "password_reset" },
                )
                TextButton(
                    text = "批量封禁",
                    colors = textButtonColorsDanger(),
                    onClick = { bulkKind = "ban" },
                )
                TextButton(
                    text = "批量解除封禁",
                    onClick = { bulkKind = "unban" },
                )
                TextButton(text = "清空选择", onClick = { selected.clear() })
            }
        }
        }
    }

    // 打开邀请弹层时拉项目清单（super：全部项目 + 不限；项目管理员：仅授权项目）
    LaunchedEffect(inviteShow) {
        if (inviteShow) {
            inviteApps = if (SessionStore.isSuper) {
                listOf("" to "不限项目") + registryApps().map { it.key to it.label }
            } else {
                banScopeOptions()
            }
        }
    }

    if (inviteShow) {
        OverlayDialog(
            show = true,
            onDismissRequest = { if (!inviteBusy) inviteShow = false },
            onDismissFinished = {},
            title = "邀请用户",
            summary = "邀请链接 24 小时内有效且只能使用一次：收件人点开设置密码即完成注册。",
        ) {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                TextField(
                    value = inviteEmail,
                    onValueChange = { inviteEmail = it },
                    label = "邮箱",
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                if (inviteApps.isEmpty()) {
                    StateHint("项目清单加载中…")
                } else {
                    WindowDropdownPreference(
                        title = "项目",
                        summary = inviteApps.firstOrNull { it.first == inviteApp }?.second
                            ?: "请选择要加入的项目",
                        items = inviteApps.map { it.second },
                        selectedIndex = inviteApps.indexOfFirst { it.first == inviteApp }
                            .coerceAtLeast(0),
                        onSelectedIndexChange = { index ->
                            inviteApp = inviteApps.getOrNull(index)?.first ?: ""
                            inviteError = null
                        },
                    )
                }
                InlineError(inviteError)
                DialogButtonRow(
                    confirmText = "发送邀请",
                    onConfirm = {
                        val email = inviteEmail.trim()
                        when {
                            email.isEmpty() -> inviteError = "请先填写被邀请人的邮箱"
                            !SessionStore.isSuper && inviteApp.isEmpty() ->
                                inviteError = "请先选择要加入的项目"
                            inviteBusy -> Unit
                            else -> {
                                inviteBusy = true
                                scope.launch {
                                    val out = actions.call("邀请已发送至 $email") {
                                        val res = Api.post<InviteResult>(
                                            "/admin/users/invite",
                                            Api.encode(InviteRequest(email, inviteApp)),
                                        )
                                        invitesOpen = true
                                        load()
                                        loadInvites()
                                        res
                                    }
                                    inviteError = out.error
                                    inviteBusy = false
                                    if (out.ok) inviteShow = false
                                }
                            }
                        }
                    },
                    onCancel = { if (!inviteBusy) inviteShow = false },
                    confirmColors = textButtonColorsPrimaryApp(),
                )
            }
        }
    }

    // 批量弹层
    bulkKind?.let { kind ->
        OverlayDialog(
            show = true,
            onDismissRequest = { if (!bulkBusy && bulkStage == "confirm") bulkKind = null },
            onDismissFinished = {},
            title = BULK_TITLE.getValue(kind),
            summary = if (bulkStage == "confirm") "将对所选 ${selected.size} 位用户执行：" else null,
        ) {
            if (bulkStage == "confirm") {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    BULK_CONSEQUENCES.getValue(kind).forEach { line ->
                        Text(
                            text = "· $line",
                            style = MiuixTheme.textStyles.footnote1,
                            color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                        )
                    }
                    selected.forEach { (uid, mail) ->
                        Row(
                            Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(8.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Text(
                                text = mail,
                                style = MiuixTheme.textStyles.body2,
                                color = MiuixTheme.colorScheme.onSurface,
                                modifier = Modifier.weight(1f),
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                            Text(
                                text = uid.toString(),
                                style = MiuixTheme.textStyles.footnote2,
                                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                                fontFamily = FontFamily.Monospace,
                            )
                        }
                    }
                    if (kind != "password_reset") {
                        Text(
                            text = "范围",
                            style = MiuixTheme.textStyles.footnote2,
                            color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                        )
                        ChoiceChips(bulkScopes, bulkScope, onSelect = { bulkScope = it })
                    }
                    if (kind == "ban") {
                        TextField(
                            value = bulkUntil,
                            onValueChange = { bulkUntil = it },
                            label = "解除时间（选填，yyyy-MM-ddTHH:mm；留空 = 永久）",
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth(),
                        )
                        TextField(
                            value = bulkReason,
                            onValueChange = { bulkReason = it },
                            label = "原因（选填，记入审计）",
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth(),
                        )
                    }
                    if (selected.size > 5) {
                        TextField(
                            value = bulkTyped,
                            onValueChange = { bulkTyped = it },
                            label = "输入「确认」解锁（${selected.size} 人）",
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth(),
                        )
                    }
                    InlineError(bulkError)
                    DialogButtonRow(
                        confirmText = BULK_TITLE.getValue(kind),
                        onConfirm = {
                            if (bulkBusy) return@DialogButtonRow
                            if ((kind == "ban" || kind == "unban") && bulkScope.isEmpty()) {
                                bulkError = "请先选择操作范围"
                                return@DialogButtonRow
                            }
                            if (selected.size > 5 && bulkTyped.trim() != "确认") {
                                bulkError = "请先输入「确认」解锁"
                                return@DialogButtonRow
                            }
                            var untilMs = 0L
                            if (kind == "ban" && bulkUntil.isNotBlank()) {
                                val parsed = localDateTimeMs(bulkUntil)
                                if (parsed == null || parsed < nowMs() + 5 * 60 * 1000) {
                                    bulkError = "解除时间至少要在 5 分钟之后"
                                    return@DialogButtonRow
                                }
                                untilMs = parsed
                            }
                            bulkBusy = true
                            scope.launch {
                                val body = BulkRequest(
                                    kind = kind,
                                    uids = selected.keys.toList(),
                                    app = bulkScope,
                                    until = if (kind == "ban") untilMs else 0L,
                                    reason = if (kind == "ban") bulkReason.trim() else "",
                                )
                                val out = actions.call("已完成${BULK_TITLE.getValue(kind)}") {
                                    Api.post<BulkResult>("/admin/users/bulk", Api.encode(body))
                                }
                                bulkBusy = false
                                if (out.ok) {
                                    bulkEmails.clear()
                                    selected.forEach { (uid, mail) -> bulkEmails[uid] = mail }
                                    bulkResult = out.value
                                    bulkStage = "result"
                                    selected.clear()
                                    load()
                                    loadInvites()
                                } else {
                                    bulkError = out.error
                                }
                            }
                        },
                        onCancel = { if (!bulkBusy) bulkKind = null },
                        confirmColors = textButtonColorsDanger(),
                    )
                }
            } else {
                val res = bulkResult
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(
                        text = res?.let {
                            "共 ${it.total} 人：成功 ${it.succeeded}，失败 ${it.failed}" +
                                if (it.failed > 0) "。失败项可勾选后重试。" else "。"
                        } ?: "没有结果",
                        style = MiuixTheme.textStyles.body2,
                        color = MiuixTheme.colorScheme.onSurface,
                    )
                    res?.items?.forEach { item ->
                        val mail = bulkEmails[item.uid] ?: "uid ${item.uid}"
                        Row(
                            Modifier.fillMaxWidth(),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(8.dp),
                        ) {
                            Column(Modifier.weight(1f)) {
                                Text(
                                    text = mail,
                                    style = MiuixTheme.textStyles.body2,
                                    color = MiuixTheme.colorScheme.onSurface,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis,
                                )
                                if (!item.ok) {
                                    Text(
                                        text = item.message.ifBlank { "操作失败" },
                                        style = MiuixTheme.textStyles.footnote2,
                                        color = OnCardColors.danger,
                                        maxLines = 2,
                                        overflow = TextOverflow.Ellipsis,
                                    )
                                }
                            }
                            AdminBadge(
                                text = if (item.ok) "成功" else "失败",
                                tone = if (item.ok) BadgeTone.Success else BadgeTone.Warning,
                            )
                        }
                    }
                    DialogButtonRow(
                        confirmText = "关闭",
                        onConfirm = {
                            bulkKind = null
                            bulkStage = "confirm"
                            bulkResult = null
                            bulkTyped = ""
                        },
                        onCancel = {
                            bulkKind = null
                            bulkStage = "confirm"
                            bulkResult = null
                            bulkTyped = ""
                        },
                        confirmColors = textButtonColorsPrimaryApp(),
                    )
                }
            }
        }
    }

    // 一次性临时密码展示层
    TempPasswordDialog(
        password = tempPassword,
        notify = tempNotify,
        onDismiss = { tempPassword = null },
    )

    ConfirmActionDialog(request = confirm, onDismissed = { confirm = null })

    // 打开批量弹层时灌范围选项与默认值
    LaunchedEffect(bulkKind) {
        if (bulkKind == null) return@LaunchedEffect
        bulkStage = "confirm"
        bulkError = null
        bulkTyped = ""
        bulkUntil = ""
        bulkReason = ""
        bulkResult = null
        val opts = banScopeOptions()
        bulkScopes = opts
        bulkScope = opts.firstOrNull()?.first ?: ""
    }
}

/** 一次性密码展示层的复制（剪贴板在非安全上下文不可用时静默失败）。 */
internal suspend fun copyToClipboard(text: String) {
    try {
        kotlinx.browser.window.navigator.clipboard?.writeText(text)?.await()
    } catch (_: Exception) {
        // 剪贴板不可用：用户可手选复制，不打断流程
    }
}

@Composable
private fun UserTableHeader(allChecked: Boolean, onToggleAll: (Boolean) -> Unit) {
    Row(
        Modifier.fillMaxWidth().padding(horizontal = 4.dp, vertical = 2.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Checkbox(
            state = if (allChecked) ToggleableState.On else ToggleableState.Off,
            onClick = { onToggleAll(!allChecked) },
        )
        HeaderCell("用户", 3f)
        HeaderCell("uid", 1f)
        HeaderCell("角色", 1.2f)
        HeaderCell("项目授权", 1.6f)
        HeaderCell("两步验证", 1f)
        HeaderCell("Passkey", 0.9f)
        HeaderCell("注册时间", 1.4f)
        Spacer(Modifier.width(56.dp))
    }
}

@Composable
private fun RowScope.HeaderCell(text: String, weight: Float) {
    Text(
        text = text,
        style = MiuixTheme.textStyles.footnote2,
        color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
        modifier = Modifier.weight(weight),
        maxLines = 1,
    )
}

@Composable
private fun UserRow(
    user: AdminUser,
    checked: Boolean,
    onToggle: () -> Unit,
    onManage: () -> Unit,
) {
    Row(
        Modifier.fillMaxWidth().padding(horizontal = 4.dp, vertical = 2.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Checkbox(
            state = if (checked) ToggleableState.On else ToggleableState.Off,
            onClick = onToggle,
        )
        Column(Modifier.weight(3f)) {
            Text(
                text = user.nickname.ifBlank { user.email },
                style = MiuixTheme.textStyles.body2,
                color = MiuixTheme.colorScheme.onSurface,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            if (user.nickname.isNotBlank()) {
                Text(
                    text = user.email,
                    style = MiuixTheme.textStyles.footnote2,
                    color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
        }
        Text(
            text = user.uid.toString(),
            style = MiuixTheme.textStyles.footnote1,
            color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
            modifier = Modifier.weight(1f),
            fontFamily = FontFamily.Monospace,
        )
        Box(Modifier.weight(1.2f)) {
            AdminBadge(
                text = roleLabel(user.role),
                tone = if (user.role == "user") BadgeTone.Neutral else BadgeTone.Primary,
            )
        }
        Text(
            text = scopeSummary(user),
            style = MiuixTheme.textStyles.footnote1,
            color = MiuixTheme.colorScheme.onSurface,
            modifier = Modifier.weight(1.6f),
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )
        Text(
            text = if (user.totpEnabled) "已开启" else "未开启",
            style = MiuixTheme.textStyles.footnote1,
            color = if (user.totpEnabled) OnCardColors.success else MiuixTheme.colorScheme.onSurfaceVariantSummary,
            modifier = Modifier.weight(1f),
        )
        Text(
            text = user.passkeyCount.toString(),
            style = MiuixTheme.textStyles.footnote1,
            color = MiuixTheme.colorScheme.onSurface,
            modifier = Modifier.weight(0.9f),
        )
        Text(
            text = fmtTime(user.createdAt),
            style = MiuixTheme.textStyles.footnote1,
            color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
            modifier = Modifier.weight(1.4f),
            maxLines = 1,
        )
        TextButton(text = "管理", onClick = onManage, modifier = Modifier.width(56.dp))
    }
}
