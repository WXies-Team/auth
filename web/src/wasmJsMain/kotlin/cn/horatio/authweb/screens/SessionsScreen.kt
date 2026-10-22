// 控制台 · 登录会话：行为规格 = 旧前端 internal/ui/templates/sessions.html + app.js
// initSessions（扁平列表：一行=一条会话，行主标题=设备名；本设备不给退出入口）。
// 行副行口径与两个日记 App 的 SessionsScreen 同源：最近活跃 + IP + 首次登录常驻，
// lastSeenAt/createdAt 的 0 哨兵分别回「尚未同步」「—」，绝不渲染 1970。
@file:OptIn(kotlin.time.ExperimentalTime::class)

package cn.horatio.authweb.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.defaultMinSize
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.wrapContentHeight
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyListState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import cn.horatio.authweb.component.DialogButtonRow
import cn.horatio.authweb.component.ItemFadeSpec
import cn.horatio.authweb.component.ItemPlacementSpec
import cn.horatio.authweb.component.SmallTitle
import cn.horatio.authweb.component.TextButton
import cn.horatio.authweb.component.textButtonColorsDanger
import cn.horatio.authweb.data.Api
import cn.horatio.authweb.data.OkResponse
import cn.horatio.authweb.data.ReauthController
import cn.horatio.authweb.data.SessionInfo
import cn.horatio.authweb.data.SessionStore
import cn.horatio.authweb.data.SessionsResponse
import cn.horatio.authweb.screens.common.DeviceIcon
import cn.horatio.authweb.shell.LocalSnackbarHostState
import cn.horatio.authweb.shell.ScreenScaffold
import cn.horatio.authweb.shell.adaptiveContentWidth
import cn.horatio.authweb.shell.pageContentPadding
import cn.horatio.authweb.shell.pageScrollModifiers
import kotlinx.coroutines.launch
import kotlin.time.Clock
import kotlinx.datetime.Instant
import kotlinx.datetime.TimeZone
import kotlinx.datetime.toLocalDateTime
import top.yukonga.miuix.kmp.basic.BasicComponent
import top.yukonga.miuix.kmp.basic.BasicComponentDefaults
import top.yukonga.miuix.kmp.basic.Button
import top.yukonga.miuix.kmp.basic.Card
import top.yukonga.miuix.kmp.basic.CircularProgressIndicator
import top.yukonga.miuix.kmp.basic.MiuixScrollBehavior
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.basic.VerticalScrollBar
import top.yukonga.miuix.kmp.basic.rememberScrollBarAdapter
import top.yukonga.miuix.kmp.overlay.OverlayDialog
import top.yukonga.miuix.kmp.theme.MiuixTheme

// ---- 时间格式（旧 app.js fmtTime/relTime 的 Kotlin 版；全控制台五屏共用，
//      定义放在最先交付的本文件里，其余屏同包直接引用）----

/** app.js `fmtTime`：yyyy-MM-dd HH:mm；0/非法哨兵回「—」。 */
internal fun fmtTime(epochMillis: Long): String {
    if (epochMillis <= 0) return "—"
    val dt = Instant.fromEpochMilliseconds(epochMillis).toLocalDateTime(TimeZone.currentSystemDefault())
    val p = { n: Int -> n.toString().padStart(2, '0') }
    return "${dt.year}-${p(dt.monthNumber)}-${p(dt.dayOfMonth)} ${p(dt.hour)}:${p(dt.minute)}"
}

/** app.js `relTime`：刚刚 / N 分钟前 / N 小时前 / 昨天 / N 天前 / 超 30 天回绝对时间。 */
internal fun relTime(epochMillis: Long): String {
    if (epochMillis <= 0) return "—"
    val diff = Clock.System.now().toEpochMilliseconds() - epochMillis
    val min = diff / 60_000
    if (min < 1) return "刚刚"
    if (min < 60) return "$min 分钟前"
    val hour = min / 60
    if (hour < 24) return "$hour 小时前"
    val day = hour / 24
    if (day == 1L) return "昨天"
    if (day < 30) return "$day 天前"
    return fmtTime(epochMillis)
}

/** app.js `todayStr`：恢复码导出文件的生成日期（yyyy-MM-dd）。 */
internal fun todayStr(): String {
    val dt = Instant.fromEpochMilliseconds(Clock.System.now().toEpochMilliseconds()).toLocalDateTime(TimeZone.currentSystemDefault())
    return "${dt.year}-${dt.monthNumber.toString().padStart(2, '0')}-${dt.dayOfMonth.toString().padStart(2, '0')}"
}

@Composable
fun SessionsScreen() {
    val scope = rememberCoroutineScope()
    val snackbarHostState = LocalSnackbarHostState.current
    val scrollBehavior = MiuixScrollBehavior()
    val lazyListState = remember { LazyListState() }

    var loaded by remember { mutableStateOf(false) }
    var loadError by remember { mutableStateOf<String?>(null) }
    var items by remember { mutableStateOf<List<SessionInfo>>(emptyList()) }
    var busy by remember { mutableStateOf(false) }
    var kickTarget by remember { mutableStateOf<SessionInfo?>(null) }
    var showRevokeOthers by remember { mutableStateOf(false) }

    suspend fun load() {
        try {
            val res = Api.get<SessionsResponse>("/api/sessions")
            // 服务端已按最近活跃倒序（ListSessions ORDER BY last_seen_at DESC）；
            // 本设备置顶只做稳定重排，其余行保持服务端原序
            items = res.sessions.sortedBy { !it.current }
            loadError = null
        } catch (e: Exception) {
            loadError = e.message ?: "会话列表加载失败，请稍后重试"
        }
        loaded = true
    }

    LaunchedEffect(Unit) {
        // 直链进入时 Api 还没有 CSRF 令牌（只由 SessionStore.refresh 装载）
        runCatching { SessionStore.refresh() }
        load()
    }

    fun kick(id: String) {
        if (busy) return
        scope.launch {
            busy = true
            try {
                Api.del<OkResponse>("/api/sessions/$id")
                load()
                snackbarHostState.showSnackbar("已退出该设备")
            } catch (e: Exception) {
                snackbarHostState.showSnackbar(e.message ?: "退出失败，请稍后重试")
            } finally {
                busy = false
            }
        }
    }

    fun revokeOthers() {
        if (busy) return
        val others = items.count { !it.current }
        scope.launch {
            busy = true
            try {
                // 服务端强制 reauth（reauthThen 2 小时强认证窗），先过闸再发请求
                ReauthController.ensure()
                Api.post<OkResponse>("/api/sessions/revoke-others", "{}")
                load()
                snackbarHostState.showSnackbar("已退出其它 $others 条会话")
            } catch (e: Exception) {
                snackbarHostState.showSnackbar(e.message ?: "退出失败，请稍后重试")
            } finally {
                busy = false
            }
        }
    }

    ScreenScaffold(
        title = "登录会话",
        scrollBehavior = scrollBehavior,
        actions = {
            TextButton(
                text = "退出其它所有会话",
                onClick = { showRevokeOthers = true },
                enabled = !busy && items.any { !it.current },
                colors = textButtonColorsDanger(),
            )
        },
    ) { innerPadding ->
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
                    item(key = "list") {
                        Column(Modifier.animateItem(fadeInSpec = ItemFadeSpec, placementSpec = ItemPlacementSpec, fadeOutSpec = ItemFadeSpec)) {
                            SmallTitle(text = "已登录的设备")
                            Card(modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp)) {
                                when {
                                    loadError != null -> InlineError(
                                        text = loadError,
                                        modifier = Modifier.fillMaxWidth().padding(16.dp),
                                    )
                                    items.isEmpty() -> Text(
                                        text = "只有当前设备处于登录状态。",
                                        style = MiuixTheme.textStyles.footnote1,
                                        color = MiuixTheme.colorScheme.onSurfaceSecondary,
                                        modifier = Modifier.fillMaxWidth().padding(16.dp),
                                    )
                                    else -> items.forEach { session ->
                                        SessionRow(
                                            session = session,
                                            busy = busy,
                                            onKick = { kickTarget = session },
                                        )
                                    }
                                }
                            }
                        }
                    }
                    item(key = "hints") {
                        Column(
                            modifier = Modifier
                                .padding(horizontal = 28.dp)
                                .animateItem(fadeInSpec = ItemFadeSpec, placementSpec = ItemPlacementSpec, fadeOutSpec = ItemFadeSpec),
                            verticalArrangement = Arrangement.spacedBy(6.dp),
                        ) {
                            Text(
                                text = "会话为空闲 7 天 / 绝对 90 天过期；最近活跃指该设备最后与服务器通信的时间。",
                                style = MiuixTheme.textStyles.footnote1,
                                color = MiuixTheme.colorScheme.onSurfaceSecondary,
                            )
                            Text(
                                text = "看到不认识的设备？先退出它，再去账号页修改密码。",
                                style = MiuixTheme.textStyles.footnote1,
                                color = MiuixTheme.colorScheme.onSurfaceSecondary,
                            )
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

        // 退出单条会话确认：点名设备，讲清后果（旧 kick-dialog 文案）
        OverlayDialog(
            show = kickTarget != null,
            title = "退出这条会话",
            summary = kickTarget?.let {
                "将退出「${it.device.ifBlank { "未知设备" }}」上的登录会话，它下次请求时会退出登录。"
            } ?: "",
            onDismissRequest = { kickTarget = null },
            onDismissFinished = { kickTarget = null },
        ) {
            DialogButtonRow(
                cancelText = "取消",
                onCancel = { kickTarget = null },
                confirmText = "退出会话",
                onConfirm = {
                    kickTarget?.let { kick(it.id) }
                    kickTarget = null
                },
                confirmColors = textButtonColorsDanger(),
            )
        }
        // 退出其它所有会话确认（旧 revoke-others 文案）；确认里先过 reauth 闸
        OverlayDialog(
            show = showRevokeOthers,
            title = "退出其它所有会话",
            summary = items.count { !it.current }.let { n ->
                if (n > 0) "将退出除「本设备」外的 $n 条会话，本机保持登录。" else "没有其它会话需要退出。"
            },
            onDismissRequest = { showRevokeOthers = false },
            onDismissFinished = { showRevokeOthers = false },
        ) {
            DialogButtonRow(
                cancelText = "取消",
                onCancel = { showRevokeOthers = false },
                confirmText = if (items.count { !it.current } > 0) "全部退出" else "知道了",
                onConfirm = {
                    if (items.any { !it.current }) revokeOthers()
                    showRevokeOthers = false
                },
                confirmColors = textButtonColorsDanger(),
            )
        }
    }
}

@Composable
private fun SessionRow(
    session: SessionInfo,
    busy: Boolean,
    onKick: () -> Unit,
) {
    // 副行 = 最近活跃 + IP + 首次登录常驻（2026-10-22 拍板，与日记 App 同口径）；
    // 0 哨兵回「尚未同步」/「—」，不渲染 1970
    val summary = buildString {
        append(
            session.lastSeenAt.takeIf { it > 0 }
                ?.let { "最近活跃 ${relTime(it)}" }
                ?: "尚未同步",
        )
        session.ip.takeIf { it.isNotBlank() }?.let { append(" · IP $it") }
        append(" · 首次登录 ${fmtTime(session.createdAt)}")
    }
    BasicComponent(
        title = session.device.ifBlank { "未知设备" },
        summary = summary,
        summaryColor = BasicComponentDefaults.summaryColor(
            color = MiuixTheme.colorScheme.onSurfaceSecondary,
        ),
        startAction = { DeviceIcon(device = session.device) },
        endActions = {
            if (session.current) {
                // 本设备只标不动作：BasicComponent 空槽也画箭头（假 affordance），
                // 用右对齐文字徽标；色取 onSurfaceSecondary（卡底 7:1 达 AA）
                Text(
                    text = "本设备",
                    style = MiuixTheme.textStyles.footnote1,
                    color = MiuixTheme.colorScheme.onSurfaceSecondary,
                    modifier = Modifier
                        .defaultMinSize(minHeight = 40.dp)
                        .wrapContentHeight(Alignment.CenterVertically)
                        .padding(end = 4.dp),
                )
            } else {
                TextButton(
                    text = "退出",
                    onClick = onKick,
                    enabled = !busy,
                    colors = textButtonColorsDanger(),
                )
            }
        },
    )
}
