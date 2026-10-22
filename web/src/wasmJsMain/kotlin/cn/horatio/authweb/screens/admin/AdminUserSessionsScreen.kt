// 管理后台「会话明细」屏：某一个用户的活跃会话，逐条退出。
//
// 端点：GET /admin/sessions?uid={uid}&limit=100（AdminListSessions 的 uid 过滤，
// 以 cmd/server/admin.go 为准——没有独立的 /admin/users/{uid}/sessions 端点）；
// DELETE /admin/sessions/{id}（id 是十进制字符串，路径原样传）。
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
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import cn.horatio.authweb.component.TextButton
import cn.horatio.authweb.component.textButtonColorsDanger
import cn.horatio.authweb.data.Api
import cn.horatio.authweb.data.ApiException
import cn.horatio.authweb.data.OkResponse
import cn.horatio.authweb.nav.LocalNav
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.theme.MiuixTheme

@Composable
fun AdminUserSessionsScreen(uid: Long) {
    val nav = LocalNav.current
    val actions = rememberAdminActions()

    var sessions by remember { mutableStateOf<List<AdminSession>>(emptyList()) }
    var loading by remember { mutableStateOf(true) }
    var error by remember { mutableStateOf<String?>(null) }
    var confirm by remember { mutableStateOf<ConfirmRequest?>(null) }

    suspend fun load() {
        loading = true
        try {
            val res = Api.get<SessionPageResponse>("/admin/sessions?uid=$uid&limit=100")
            sessions = res.items
            error = null
        } catch (e: ApiException) {
            error = e.message
        } catch (_: Exception) {
            error = "读取失败，请刷新重试"
        }
        loading = false
    }

    LaunchedEffect(uid) { load() }

    val email = sessions.firstOrNull()?.email ?: ""

    AdminScaffold(
        title = "会话明细",
        subtitle = if (email.isNotBlank()) "$email · uid $uid" else "uid $uid",
        navigationIcon = { BackIcon(onClick = { nav.back() }) },
    ) { padding, scrollBehavior ->
        AdminList(padding, scrollBehavior) {
            item {
                SectionCard {
                    InlineError(error)
                    if (loading && sessions.isEmpty()) {
                        StateHint("读取中…")
                    } else if (sessions.isEmpty()) {
                        StateHint("该用户已无活跃会话。")
                    }
                }
            }
            items(sessions.size) { index ->
                val s = sessions[index]
                SectionCard {
                    Row(
                        Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        Column(Modifier.weight(1f)) {
                            Text(
                                text = s.device,
                                style = MiuixTheme.textStyles.body2,
                                color = MiuixTheme.colorScheme.onSurface,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                            Text(
                                text = "${s.app} · ${s.ip} · 最近活跃 ${relTime(s.lastSeenAt)}",
                                style = MiuixTheme.textStyles.footnote2,
                                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                            Text(
                                text = "登录于 ${fmtTime(s.createdAt)}",
                                style = MiuixTheme.textStyles.footnote2,
                                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                            )
                        }
                        TextButton(
                            text = "退出",
                            colors = textButtonColorsDanger(),
                            onClick = {
                                confirm = ConfirmRequest(
                                    title = "退出会话",
                                    desc = "将让「${s.device}」（${s.ip}）立即退出登录，该设备需要重新登录。",
                                    success = "已退出该会话",
                                ) {
                                    Api.del<OkResponse>("/admin/sessions/${s.id}")
                                    load()
                                }
                            },
                        )
                    }
                }
            }
        }
    }

    ConfirmActionDialog(request = confirm, onDismissed = { confirm = null })
}
