// 管理后台「AI 用量」屏（scoped：app-admin 只见授权项目用户集，global 行隐藏）。
//
// 端点（cmd/server/admin.go + internal/auth/admin.go）：
//   GET /admin/ai-usage?days=7|30|90            → AIUsageOverview
//   GET /admin/ai-usage?days=N&uid=X            → AIUsageUserDetail（按用户钻取）
//   限额修改走 PUT /admin/config/{ai_*}（super only，见 AdminConfigScreen 的键域）。
package cn.horatio.authweb.screens.admin

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
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
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import cn.horatio.authweb.component.DialogButtonRow
import cn.horatio.authweb.component.TextButton
import cn.horatio.authweb.component.textButtonColorsPrimaryApp
import cn.horatio.authweb.data.Api
import cn.horatio.authweb.data.ApiException
import cn.horatio.authweb.data.SessionStore
import cn.horatio.authweb.theme.OnCardColors
import kotlinx.coroutines.launch
import kotlin.math.abs
import kotlinx.serialization.Serializable
import top.yukonga.miuix.kmp.basic.LinearProgressIndicator
import top.yukonga.miuix.kmp.basic.ProgressIndicatorDefaults
import top.yukonga.miuix.kmp.basic.TextField
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.overlay.OverlayDialog
import top.yukonga.miuix.kmp.theme.MiuixTheme

// ---- 回执 DTO（internal/auth/admin.go 的 AIUsage* 系列）----

@Serializable data class AiUsageDayTotal(val date: String = "", val count: Int = 0)
@Serializable data class AiUsageGlobal(val used: Int = 0, val limit: Int = 0)
@Serializable data class AiUsageUserRow(
    val uid: Long = 0,
    val email: String = "",
    val today: Int = 0,
    val range: Int = 0,
    val share: Double = 0.0,
    val limitToday: Int = 0,
)

@Serializable data class AiUsageOverview(
    val today: Int = 0,
    val yesterday: Int = 0,
    val activeToday: Int = 0,
    val global: AiUsageGlobal? = null,
    val defaultsUsed: Int = 0,
    val days: List<AiUsageDayTotal> = emptyList(),
    val users: List<AiUsageUserRow> = emptyList(),
)

@Serializable data class AiUsageUserDetail(
    val uid: Long = 0,
    val email: String = "",
    val today: Int = 0,
    val days: List<AiUsageDayTotal> = emptyList(),
    val limitToday: Int = 0,
)

private val DAY_OPTIONS = listOf("7" to "7 天", "30" to "30 天", "90" to "90 天")

/** 四档限额（键名与 internal/auth/admin.go 的 aiQuotaKeys 逐字一致）。 */
private val QUOTA_FIELDS = listOf(
    "ai_rate_per_minute" to "每用户每分钟次数",
    "ai_concurrency" to "全站并发",
    "ai_daily_per_user" to "每用户每日",
    "ai_daily_global" to "全站每日",
)

@Composable
fun AdminAiScreen() {
    val actions = rememberAdminActions()
    val scope = rememberCoroutineScope()

    var days by remember { mutableStateOf("30") }
    var report by remember { mutableStateOf<AiUsageOverview?>(null) }
    var loading by remember { mutableStateOf(true) }
    var error by remember { mutableStateOf<String?>(null) }

    var drill by remember { mutableStateOf<AiUsageUserDetail?>(null) }
    var drillUid by remember { mutableStateOf<Long?>(null) }
    var drillLoading by remember { mutableStateOf(false) }

    var quotaShow by remember { mutableStateOf(false) }
    val quotaDrafts = remember { androidx.compose.runtime.mutableStateMapOf<String, String>() }
    var quotaError by remember { mutableStateOf<String?>(null) }
    var quotaBusy by remember { mutableStateOf(false) }

    suspend fun load() {
        loading = true
        try {
            report = Api.get<AiUsageOverview>("/admin/ai-usage?days=$days")
            error = null
        } catch (e: ApiException) {
            error = e.message
        } catch (_: Exception) {
            error = "读取失败，请刷新重试"
        }
        loading = false
    }

    suspend fun loadDrill(uid: Long) {
        drillLoading = true
        try {
            drill = Api.get<AiUsageUserDetail>("/admin/ai-usage?days=$days&uid=$uid")
        } catch (e: ApiException) {
            drill = null
            error = e.message
        } catch (_: Exception) {
            drill = null
        }
        drillLoading = false
    }

    LaunchedEffect(days) {
        load()
        drillUid?.let { loadDrill(it) }
    }

    // 打开编辑限额弹层：预填现值（未配置的键留空）
    LaunchedEffect(quotaShow) {
        if (!quotaShow) return@LaunchedEffect
        quotaError = null
        quotaDrafts.clear()
        try {
            Api.get<List<ConfigItem>>("/admin/config")
                .filter { it.configured && QUOTA_FIELDS.any { f -> f.first == it.key } }
                .forEach { quotaDrafts[it.key] = it.value }
        } catch (_: Exception) {
            // 预填失败不拦打开：可直接填新值
        }
    }

    AdminScaffold(
        title = "AI 用量",
        actions = {
            if (SessionStore.isSuper) {
                TextButton(text = "编辑限额", onClick = { quotaShow = true })
            }
        },
    ) { padding, scrollBehavior ->
        AdminList(padding, scrollBehavior) {
            item {
                SectionCard(title = "统计窗口") {
                    ChoiceChips(DAY_OPTIONS, days) { days = it }
                    InlineError(error)
                }
            }

            // KPI
            item {
                SectionCard(title = "今日概览") {
                    val rep = report
                    if (rep == null && loading) {
                        StateHint("读取中…")
                    } else if (rep != null) {
                        Row(
                            Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(12.dp),
                        ) {
                            KpiCell(
                                title = "今日总使用",
                                value = "${rep.today} 次",
                                hint = deltaText(rep.today, rep.yesterday),
                                modifier = Modifier.weight(1f),
                            )
                            KpiCell(
                                title = "今日活跃用户",
                                value = "${rep.activeToday} 人",
                                modifier = Modifier.weight(1f),
                            )
                        }
                        // 全站余量（app-admin 视角 global = null，如实说明）
                        val global = rep.global
                        Text(
                            text = "全站今日余量",
                            style = MiuixTheme.textStyles.footnote2,
                            color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                        )
                        if (global == null) {
                            Text(
                                text = "—　全站余量仅平台管理员可见。",
                                style = MiuixTheme.textStyles.body2,
                                color = MiuixTheme.colorScheme.onSurface,
                            )
                        } else {
                            Text(
                                text = if (global.limit > 0) {
                                    "${global.used} / ${global.limit} 次"
                                } else {
                                    "${global.used} 次"
                                },
                                style = MiuixTheme.textStyles.title3,
                                color = MiuixTheme.colorScheme.onSurface,
                            )
                            LinearProgressIndicator(
                                progress = if (global.limit > 0) {
                                    (global.used.toFloat() / global.limit).coerceIn(0f, 1f)
                                } else {
                                    0f
                                },
                                colors = ProgressIndicatorDefaults.progressIndicatorColors(
                                    foregroundColor = MiuixTheme.colorScheme.primary,
                                ),
                                height = 6.dp,
                                modifier = Modifier.fillMaxWidth(),
                            )
                            Text(
                                text = if (rep.defaultsUsed > 0) {
                                    "限额为默认值（ai_* 配置键未配齐）。"
                                } else {
                                    "限额来自配置中心。"
                                },
                                style = MiuixTheme.textStyles.footnote2,
                                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                            )
                        }
                        Spacer(Modifier.height(4.dp))
                        Text(
                            text = "近 7 天走势",
                            style = MiuixTheme.textStyles.footnote2,
                            color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                        )
                        SparkRow(rep.days)
                    }
                }
            }

            // 每日用量
            item {
                SectionCard(
                    title = "每日用量",
                    hint = "今日（${todayStr()}）合计 ${report?.today ?: 0} 次",
                ) {
                    val list = report?.days ?: emptyList()
                    if (list.isEmpty()) {
                        StateHint(if (loading) "读取中…" else "所选区间内暂无用量。")
                    } else {
                        val max = (list.maxOf { it.count }).coerceAtLeast(1)
                        list.forEach { day ->
                            Row(
                                Modifier.fillMaxWidth(),
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(8.dp),
                            ) {
                                Text(
                                    text = day.date,
                                    style = MiuixTheme.textStyles.footnote2,
                                    color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                                    modifier = Modifier.width(84.dp),
                                    fontFamily = FontFamily.Monospace,
                                )
                                LinearProgressIndicator(
                                    progress = (day.count.toFloat() / max).coerceIn(0f, 1f),
                                    colors = ProgressIndicatorDefaults.progressIndicatorColors(
                                        foregroundColor = MiuixTheme.colorScheme.primary,
                                    ),
                                    height = 6.dp,
                                    modifier = Modifier.weight(1f),
                                )
                                Text(
                                    text = day.count.toString(),
                                    style = MiuixTheme.textStyles.footnote1,
                                    color = MiuixTheme.colorScheme.onSurface,
                                    modifier = Modifier.width(44.dp),
                                    textAlign = androidx.compose.ui.text.style.TextAlign.End,
                                )
                            }
                        }
                    }
                }
            }

            // 按用户
            item {
                SectionCard(title = "按用户", hint = "点击一行查看该用户的用量明细。") {
                    val users = report?.users ?: emptyList()
                    if (users.isEmpty()) {
                        StateHint(if (loading) "读取中…" else "所选区间内暂无用户用量。")
                    } else {
                        users.forEach { u ->
                            val left = if (u.limitToday > 0) (u.limitToday - u.today).coerceAtLeast(0) else 0
                            Row(
                                Modifier
                                    .fillMaxWidth()
                                    .clickable {
                                        drillUid = u.uid
                                        scope.launch { loadDrill(u.uid) }
                                    }
                                    .padding(vertical = 4.dp),
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(8.dp),
                            ) {
                                Column(Modifier.weight(1.6f)) {
                                    Text(
                                        text = u.email,
                                        style = MiuixTheme.textStyles.body2,
                                        color = MiuixTheme.colorScheme.onSurface,
                                        maxLines = 1,
                                        overflow = TextOverflow.Ellipsis,
                                    )
                                    Text(
                                        text = "uid ${u.uid}",
                                        style = MiuixTheme.textStyles.footnote2,
                                        color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                                        fontFamily = FontFamily.Monospace,
                                    )
                                }
                                Text(
                                    text = "${u.today}",
                                    style = MiuixTheme.textStyles.footnote1,
                                    color = MiuixTheme.colorScheme.onSurface,
                                    modifier = Modifier.width(40.dp),
                                    textAlign = androidx.compose.ui.text.style.TextAlign.End,
                                )
                                Text(
                                    text = "${u.range}",
                                    style = MiuixTheme.textStyles.footnote1,
                                    color = MiuixTheme.colorScheme.onSurface,
                                    modifier = Modifier.width(48.dp),
                                    textAlign = androidx.compose.ui.text.style.TextAlign.End,
                                )
                                Text(
                                    text = "${(u.share * 100).toInt()}%",
                                    style = MiuixTheme.textStyles.footnote1,
                                    color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                                    modifier = Modifier.width(44.dp),
                                    textAlign = androidx.compose.ui.text.style.TextAlign.End,
                                )
                                Column(Modifier.weight(1.2f)) {
                                    if (u.limitToday > 0) {
                                        LinearProgressIndicator(
                                            progress = (u.today.toFloat() / u.limitToday).coerceIn(0f, 1f),
                                            colors = ProgressIndicatorDefaults.progressIndicatorColors(
                                                foregroundColor = MiuixTheme.colorScheme.primary,
                                            ),
                                            height = 6.dp,
                                            modifier = Modifier.fillMaxWidth(),
                                        )
                                        Text(
                                            text = "剩 $left/${u.limitToday}",
                                            style = MiuixTheme.textStyles.footnote2,
                                            color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                                        )
                                    } else {
                                        Text(
                                            text = "—",
                                            style = MiuixTheme.textStyles.footnote2,
                                            color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                                        )
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // 用户钻取
            drillUid?.let { uid ->
                item(key = "drill-$uid") {
                    SectionCard(
                        title = "用量明细",
                        actions = {
                            TextButton(
                                text = "关闭",
                                onClick = {
                                    drillUid = null
                                    drill = null
                                },
                            )
                        },
                    ) {
                        val d = drill
                        when {
                            drillLoading -> StateHint("读取中…")
                            d == null -> StateHint("该用户在所选区间内暂无用量。")
                            else -> {
                                Text(
                                    text = "${d.email} · 今日 ${d.today} 次",
                                    style = MiuixTheme.textStyles.body2,
                                    color = MiuixTheme.colorScheme.onSurface,
                                )
                                if (d.limitToday > 0) {
                                    LinearProgressIndicator(
                                        progress = (d.today.toFloat() / d.limitToday).coerceIn(0f, 1f),
                                        colors = ProgressIndicatorDefaults.progressIndicatorColors(
                                            foregroundColor = MiuixTheme.colorScheme.primary,
                                        ),
                                        height = 6.dp,
                                        modifier = Modifier.fillMaxWidth(),
                                    )
                                    Text(
                                        text = "今日已用 ${d.today} / ${d.limitToday} 次（每日限额）。",
                                        style = MiuixTheme.textStyles.footnote2,
                                        color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                                    )
                                } else {
                                    Text(
                                        text = "未配置每日限额。",
                                        style = MiuixTheme.textStyles.footnote2,
                                        color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                                    )
                                }
                                val max = (d.days.maxOf { it.count }).coerceAtLeast(1)
                                d.days.forEach { day ->
                                    Row(
                                        Modifier.fillMaxWidth(),
                                        verticalAlignment = Alignment.CenterVertically,
                                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                                    ) {
                                        Text(
                                            text = day.date,
                                            style = MiuixTheme.textStyles.footnote2,
                                            color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                                            modifier = Modifier.width(84.dp),
                                            fontFamily = FontFamily.Monospace,
                                        )
                                        LinearProgressIndicator(
                                            progress = (day.count.toFloat() / max).coerceIn(0f, 1f),
                                            colors = ProgressIndicatorDefaults.progressIndicatorColors(
                                                foregroundColor = MiuixTheme.colorScheme.primary,
                                            ),
                                            height = 6.dp,
                                            modifier = Modifier.weight(1f),
                                        )
                                        Text(
                                            text = day.count.toString(),
                                            style = MiuixTheme.textStyles.footnote1,
                                            color = MiuixTheme.colorScheme.onSurface,
                                            modifier = Modifier.width(44.dp),
                                            textAlign = androidx.compose.ui.text.style.TextAlign.End,
                                        )
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // 编辑限额（super）
    if (quotaShow) {
        OverlayDialog(
            show = true,
            onDismissRequest = { if (!quotaBusy) quotaShow = false },
            onDismissFinished = {},
            title = "编辑限额",
            summary = "留空 = 不修改；必须是正整数，保存后 ≤10 秒生效。",
        ) {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                QUOTA_FIELDS.forEach { (key, label) ->
                    TextField(
                        value = quotaDrafts[key] ?: "",
                        onValueChange = { quotaDrafts[key] = it },
                        label = label,
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                    )
                }
                InlineError(quotaError)
                DialogButtonRow(
                    confirmText = "保存",
                    onConfirm = {
                        if (quotaBusy) return@DialogButtonRow
                        val todo = mutableListOf<Pair<String, String>>()
                        quotaError = null
                        QUOTA_FIELDS.forEach { (key, label) ->
                            val v = (quotaDrafts[key] ?: "").trim()
                            if (v.isNotEmpty()) {
                                if (!v.all { it.isDigit() } || v.toLongOrNull() == null || v.toLong() <= 0) {
                                    quotaError = "${label}必须是正整数"
                                } else {
                                    todo += key to v
                                }
                            }
                        }
                        if (quotaError != null) return@DialogButtonRow
                        if (todo.isEmpty()) {
                            quotaShow = false
                            return@DialogButtonRow
                        }
                        quotaBusy = true
                        scope.launch {
                            var firstError: String? = null
                            todo.forEach { (key, value) ->
                                if (firstError == null) {
                                    val out = actions.exec("限额已保存，≤10 秒生效") {
                                        Api.put<ConfigSetResult>(
                                            "/admin/config/${urlEnc(key)}",
                                            Api.encode(ConfigUpdateRequest(value)),
                                        )
                                    }
                                    firstError = out
                                }
                            }
                            quotaBusy = false
                            if (firstError == null) {
                                quotaShow = false
                                load()
                            } else {
                                quotaError = firstError
                            }
                        }
                    },
                    onCancel = { if (!quotaBusy) quotaShow = false },
                    confirmColors = textButtonColorsPrimaryApp(),
                )
            }
        }
    }
}

/** KPI 小格：标题 + 大数字 + 说明。 */
@Composable
private fun KpiCell(
    title: String,
    value: String,
    hint: String? = null,
    modifier: Modifier = Modifier,
) {
    Column(modifier) {
        Text(
            text = title,
            style = MiuixTheme.textStyles.footnote2,
            color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
        )
        Text(
            text = value,
            style = MiuixTheme.textStyles.title2,
            color = MiuixTheme.colorScheme.onSurface,
        )
        if (hint != null) {
            Text(
                text = hint,
                style = MiuixTheme.textStyles.footnote2,
                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis,
            )
        }
    }
}

private fun deltaText(today: Int, yesterday: Int): String = when {
    yesterday <= 0 -> "昨日无用量"
    today == yesterday -> "与昨日持平"
    else -> {
        val diff = today - yesterday
        val pct = abs(diff) * 100 / yesterday
        "较昨日${if (diff > 0) "↑" else "↓"} $pct%（${if (diff > 0) "+$diff" else "$diff"}）"
    }
}

/** 近 7 天迷你竖条（零值保底 2dp 可见）。 */
@Composable
private fun SparkRow(days: List<AiUsageDayTotal>) {
    val last7 = days.takeLast(7)
    if (last7.isEmpty()) {
        StateHint("暂无数据")
        return
    }
    val max = (last7.maxOf { it.count }).coerceAtLeast(1)
    Row(
        Modifier.fillMaxWidth().height(44.dp),
        verticalAlignment = Alignment.Bottom,
        horizontalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        last7.forEach { day ->
            val frac = day.count.toFloat() / max
            val h = (44.dp * frac).let { if (day.count > 0) it.coerceAtLeast(6.dp) else 2.dp }
            Box(
                Modifier
                    .weight(1f)
                    .height(h)
                    .background(
                        color = if (day.count > 0) MiuixTheme.colorScheme.primary
                        else MiuixTheme.colorScheme.secondaryContainer,
                        shape = RoundedCornerShape(topStart = 3.dp, topEnd = 3.dp),
                    ),
            )
        }
    }
    Text(
        text = "${last7.first().date} → ${last7.last().date}",
        style = MiuixTheme.textStyles.footnote2,
        color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
    )
}
