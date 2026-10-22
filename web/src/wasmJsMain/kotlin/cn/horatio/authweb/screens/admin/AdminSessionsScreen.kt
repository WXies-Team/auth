// 管理后台「会话总览」屏（scoped：app-admin 只见授权项目用户的会话）。
//
// 端点（cmd/server/admin.go）：
//   GET /admin/sessions?query=&limit=&offset=&app= → {items,total,totalUsers}
//   行点入 = push AdminUserSessions(uid)（该用户会话走同一条端点的 ?uid= 过滤）。
package cn.horatio.authweb.screens.admin

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import cn.horatio.authweb.component.TextButton
import cn.horatio.authweb.component.textButtonColorsPrimaryApp
import cn.horatio.authweb.data.Api
import cn.horatio.authweb.data.ApiException
import cn.horatio.authweb.nav.LocalNav
import cn.horatio.authweb.nav.Route
import kotlinx.serialization.Serializable
import top.yukonga.miuix.kmp.basic.TextField
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.theme.MiuixTheme

/** GET /admin/sessions 的一条（auth.AdminSession；id 是十进制串）。 */
@Serializable
data class AdminSession(
    val id: String = "",
    val uid: Long = 0,
    val email: String = "",
    val app: String = "",
    val device: String = "",
    val ip: String = "",
    val createdAt: Long = 0,
    val lastSeenAt: Long = 0,
    val nickname: String = "",
    val avatarColor: Int = 0,
)

/** GET /admin/sessions 回执（比 page 多一个去重用户计数）。 */
@Serializable
data class SessionPageResponse(
    val items: List<AdminSession> = emptyList(),
    val total: Int = 0,
    val totalUsers: Int = 0,
)

/** 会话总览页按 uid 聚合出的用户行。 */
internal data class SessionUserRow(
    val uid: Long,
    val email: String,
    val nickname: String,
    val count: Int,
    val lastSeenAt: Long,
)

internal fun aggregateSessionUsers(items: List<AdminSession>): List<SessionUserRow> {
    val map = LinkedHashMap<Long, SessionUserRow>()
    items.forEach { s ->
        val cur = map[s.uid]
        if (cur == null) {
            map[s.uid] = SessionUserRow(s.uid, s.email, s.nickname, 1, s.lastSeenAt)
        } else {
            map[s.uid] = cur.copy(
                count = cur.count + 1,
                lastSeenAt = maxOf(cur.lastSeenAt, s.lastSeenAt),
            )
        }
    }
    return map.values.sortedByDescending { it.lastSeenAt }
}

private const val SESSION_PAGE = 100

@Composable
fun AdminSessionsScreen() {
    val nav = LocalNav.current

    var query by remember { mutableStateOf("") }
    var submitted by remember { mutableStateOf("") }
    var offset by remember { mutableStateOf(0) }
    var items by remember { mutableStateOf<List<AdminSession>>(emptyList()) }
    var total by remember { mutableStateOf(0) }
    var totalUsers by remember { mutableStateOf(0) }
    var loading by remember { mutableStateOf(true) }
    var error by remember { mutableStateOf<String?>(null) }

    suspend fun load() {
        loading = true
        try {
            val res = Api.get<SessionPageResponse>(
                "/admin/sessions?query=${urlEnc(submitted)}&limit=$SESSION_PAGE&offset=$offset",
            )
            items = res.items
            total = res.total
            totalUsers = res.totalUsers
            error = null
        } catch (e: ApiException) {
            error = e.message
        } catch (_: Exception) {
            error = "读取失败，请刷新重试"
        }
        loading = false
    }

    LaunchedEffect(submitted, offset) { load() }

    AdminScaffold(title = "会话总览") { padding, scrollBehavior ->
        AdminList(padding, scrollBehavior) {
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
                            label = "按邮箱片段或 uid 搜索用户",
                            singleLine = true,
                            modifier = Modifier.weight(1f),
                        )
                        TextButton(
                            text = "搜索",
                            colors = textButtonColorsPrimaryApp(),
                            onClick = {
                                submitted = query.trim()
                                offset = 0
                            },
                        )
                    }
                    InlineError(error)
                }
            }

            item {
                SectionCard(title = "用户") {
                    when {
                        loading && items.isEmpty() -> StateHint("读取中…")
                        items.isEmpty() -> StateHint("暂无匹配的活跃会话")
                        else -> aggregateSessionUsers(items).forEach { row ->
                            SessionUserLine(row = row, onOpen = { nav.push(Route.AdminUserSessions(row.uid)) })
                        }
                    }
                }
            }

            item {
                PagerRow(
                    total = total,
                    shown = items.size,
                    offset = offset,
                    label = "第 ${offset / SESSION_PAGE + 1} 页 · 共 $totalUsers 位用户（${total} 条会话）",
                    onPrev = { offset = (offset - SESSION_PAGE).coerceAtLeast(0) },
                    onNext = { offset += SESSION_PAGE },
                )
            }
        }
    }
}

@Composable
private fun SessionUserLine(row: SessionUserRow, onOpen: () -> Unit) {
    Row(
        Modifier.fillMaxWidth().padding(vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Column(Modifier.weight(1f)) {
            Text(
                text = row.nickname.ifBlank { row.email },
                style = MiuixTheme.textStyles.body2,
                color = MiuixTheme.colorScheme.onSurface,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Text(
                text = if (row.nickname.isBlank()) "uid ${row.uid}" else "${row.email} · uid ${row.uid}",
                style = MiuixTheme.textStyles.footnote2,
                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                fontFamily = FontFamily.Monospace,
            )
        }
        Text(
            text = "${row.count} 条会话",
            style = MiuixTheme.textStyles.footnote1,
            color = MiuixTheme.colorScheme.onSurface,
        )
        Text(
            text = relTime(row.lastSeenAt),
            style = MiuixTheme.textStyles.footnote1,
            color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
        )
        TextButton(text = "查看会话", onClick = onOpen)
    }
}
