// 管理后台「项目访问」屏（W5 项目登录白名单）。
//
// 端点（cmd/server/admin.go）：
//   GET    /admin/projects            → {projects:[{app,name,restricted,members,clientId,redirectUris}]}
//   POST   /admin/projects/{app}/restrict  {restricted:bool}
//   POST   /admin/projects/{app}/access    {email}
//   DELETE /admin/projects/{app}/access    {email}
package cn.horatio.authweb.screens.admin

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
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
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import cn.horatio.authweb.component.TextButton
import cn.horatio.authweb.component.textButtonColorsDanger
import cn.horatio.authweb.component.textButtonColorsPrimaryApp
import cn.horatio.authweb.data.Api
import cn.horatio.authweb.data.ApiException
import cn.horatio.authweb.data.OkResponse
import cn.horatio.authweb.theme.OnCardColors
import kotlinx.coroutines.launch
import kotlinx.serialization.Serializable
import top.yukonga.miuix.kmp.basic.Switch
import top.yukonga.miuix.kmp.basic.TextField
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.theme.MiuixTheme

/** POST/DELETE /admin/projects/{app}/access 的请求体。 */
@Serializable data class AccessRequest(val email: String = "")

/** POST /admin/projects/{app}/restrict 的请求体。 */
@Serializable data class RestrictRequest(val restricted: Boolean = false)

@Composable
fun AdminAccessScreen() {
    val actions = rememberAdminActions()
    val scope = rememberCoroutineScope()

    var projects by remember { mutableStateOf<List<AdminProject>>(emptyList()) }
    var loading by remember { mutableStateOf(true) }
    var error by remember { mutableStateOf<String?>(null) }
    var confirm by remember { mutableStateOf<ConfirmRequest?>(null) }

    val draft = remember { mutableStateMapOf<String, String>() }
    val rowError = remember { mutableStateMapOf<String, String>() }

    suspend fun load() {
        loading = true
        try {
            projects = Api.get<ProjectsResponse>("/admin/projects").projects
            error = null
        } catch (e: ApiException) {
            error = e.message
        } catch (_: Exception) {
            error = "读取失败，请刷新重试"
        }
        loading = false
    }

    LaunchedEffect(Unit) { load() }

    AdminScaffold(title = "项目访问") { padding, scrollBehavior ->
        AdminList(padding, scrollBehavior) {
            item {
                Text(
                    text = "开启「仅限受邀」后，除平台管理员、该项目的管理员和名单内用户外，" +
                        "其他账号无法登录该项目。",
                    style = MiuixTheme.textStyles.footnote1,
                    color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                    modifier = Modifier.padding(horizontal = 12.dp),
                )
            }
            item {
                SectionCard {
                    InlineError(error)
                    if (loading && projects.isEmpty()) StateHint("读取中…")
                    if (!loading && projects.isEmpty() && error == null) StateHint("当前没有可管理的项目。")
                }
            }
            items(projects.size) { index ->
                val project = projects[index]
                val restricted = project.restricted
                SectionCard(
                    title = project.name,
                    actions = {
                        AdminBadge(
                            text = if (restricted) "仅限受邀" else "开放登录",
                            tone = if (restricted) BadgeTone.Primary else BadgeTone.Success,
                        )
                        Spacer(Modifier.width(8.dp))
                        Switch(
                            checked = restricted,
                            onCheckedChange = { want ->
                                if (want != restricted) {
                                    confirm = ConfirmRequest(
                                        title = "调整登录范围",
                                        desc = if (want) {
                                            "开启后，除平台管理员、该项目的管理员和名单内用户外，其他账号将无法登录该项目。"
                                        } else {
                                            "开启后所有账号都可登录该项目。"
                                        },
                                        success = if (want) {
                                            "已开启「${project.name}」仅限受邀登录"
                                        } else {
                                            "已关闭「${project.name}」的登录限制"
                                        },
                                        danger = want,
                                    ) {
                                        Api.post<OkResponse>(
                                            "/admin/projects/${project.app}/restrict",
                                            Api.encode(RestrictRequest(want)),
                                        )
                                        load()
                                    }
                                }
                            },
                        )
                    },
                ) {
                    if (project.members.isEmpty()) {
                        StateHint("名单为空：开启限制后将只有管理员可以登录该项目。")
                    }
                    project.members.forEach { member ->
                        Row(
                            Modifier.fillMaxWidth(),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(8.dp),
                        ) {
                            Text(
                                text = member.email,
                                style = MiuixTheme.textStyles.body2,
                                color = MiuixTheme.colorScheme.onSurface,
                                modifier = Modifier.weight(1f),
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                                fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace,
                            )
                            TextButton(
                                text = "移除",
                                colors = textButtonColorsDanger(),
                                onClick = {
                                    confirm = ConfirmRequest(
                                        title = "移出登录名单",
                                        desc = "将把「${member.email}」移出「${project.name}」的登录名单；" +
                                            "开启限制后，该邮箱将无法登录该项目。",
                                        success = "已将 ${member.email} 移出「${project.name}」登录名单",
                                    ) {
                                        Api.del<OkResponse>(
                                            "/admin/projects/${project.app}/access",
                                            Api.encode(AccessRequest(member.email)),
                                        )
                                        load()
                                    }
                                },
                            )
                        }
                    }
                    Row(
                        Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        TextField(
                            value = draft[project.app] ?: "",
                            onValueChange = { draft[project.app] = it },
                            label = "输入邮箱加入登录名单",
                            singleLine = true,
                            modifier = Modifier.weight(1f),
                        )
                        TextButton(
                            text = "添加",
                            colors = textButtonColorsPrimaryApp(),
                            onClick = {
                                val email = (draft[project.app] ?: "").trim()
                                if (email.isEmpty()) {
                                    rowError[project.app] = "请输入邮箱"
                                    return@TextButton
                                }
                                scope.launch {
                                    val out = actions.call("已将 $email 加入「${project.name}」登录名单") {
                                        Api.post<OkResponse>(
                                            "/admin/projects/${project.app}/access",
                                            Api.encode(AccessRequest(email)),
                                        )
                                    }
                                    if (out.ok) {
                                        draft[project.app] = ""
                                        rowError.remove(project.app)
                                        load()
                                    } else {
                                        rowError[project.app] =
                                            if (out.error?.contains("不存在") == true) "该邮箱不存在" else out.error!!
                                    }
                                }
                            },
                        )
                    }
                    InlineError(rowError[project.app])
                }
            }
        }
    }

    ConfirmActionDialog(request = confirm, onDismissed = { confirm = null })
}
