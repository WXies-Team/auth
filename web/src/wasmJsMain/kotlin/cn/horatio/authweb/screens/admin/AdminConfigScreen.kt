// 管理后台「配置中心」屏（super 专属）。
//
// 端点（cmd/server/admin.go）：
//   GET /admin/config            → [ConfigItem]（**裸数组**，非信封）
//   PUT /admin/config/{key}      → {ok, hotWithinSeconds}；value 空串 = 删键
// secret 键只回 configured + 末 4 位 hint（服务端不回原值）；ai_* 组在本页只读，
// 编辑入口收敛到「AI 用量」页的「编辑限额」（旧版 admin-config.html 同一口径）。
package cn.horatio.authweb.screens.admin

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
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
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import cn.horatio.authweb.component.TextButton
import cn.horatio.authweb.component.textButtonColorsDanger
import cn.horatio.authweb.component.textButtonColorsPrimaryApp
import cn.horatio.authweb.data.Api
import cn.horatio.authweb.data.ApiException
import cn.horatio.authweb.theme.OnCardColors
import kotlinx.coroutines.launch
import kotlinx.serialization.Serializable
import top.yukonga.miuix.kmp.basic.TextField
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.theme.MiuixTheme

/** GET /admin/config 的一条（auth.ConfigItem）。 */
@Serializable
data class ConfigItem(
    val key: String = "",
    val secret: Boolean = false,
    val configured: Boolean = false,
    val value: String = "",
    val hint: String = "",
)

@Serializable data class ConfigUpdateRequest(val value: String = "")
@Serializable data class ConfigSetResult(val ok: Boolean = true, val hotWithinSeconds: Int = 0)

private val CONFIG_GROUPS = listOf(
    "mail_" to "邮件",
    "hook_" to "注销钩子",
    "llm_" to "LLM 大模型",
    "ai_" to "AI 限额",
)

private val CONFIG_LABELS = mapOf(
    "llm_api_key" to "API 密钥",
    "llm_base_url" to "接口地址",
    "llm_model" to "模型名",
    "mail_tenant_id" to "邮件租户 ID",
    "mail_client_id" to "邮件客户端 ID",
    "mail_client_secret" to "邮件客户端密钥",
    "hook_token" to "钩子令牌",
    "hook_calorie_diary" to "热量日记注销钩子",
    "hook_expense_diary" to "开支日记注销钩子",
    "ai_rate_per_minute" to "每用户每分钟次数",
    "ai_concurrency" to "全站并发",
    "ai_daily_per_user" to "每用户每日",
    "ai_daily_global" to "全站每日",
    "ai_usage_merged_at" to "用量合并标记",
)

internal fun configLabel(key: String): String =
    CONFIG_LABELS[key] ?: key.removePrefix("llm_").replace('_', ' ')

@Composable
fun AdminConfigScreen() {
    val actions = rememberAdminActions()
    val scope = rememberCoroutineScope()

    var items by remember { mutableStateOf<List<ConfigItem>>(emptyList()) }
    var loading by remember { mutableStateOf(true) }
    var error by remember { mutableStateOf<String?>(null) }
    var confirm by remember { mutableStateOf<ConfirmRequest?>(null) }

    val drafts = remember { mutableStateMapOf<String, String>() }
    val rowErrors = remember { mutableStateMapOf<String, String>() }

    suspend fun load() {
        loading = true
        try {
            items = Api.get<List<ConfigItem>>("/admin/config")
            error = null
        } catch (e: ApiException) {
            error = e.message
        } catch (_: Exception) {
            error = "读取失败，请刷新重试"
        }
        loading = false
    }

    LaunchedEffect(Unit) { load() }

    AdminScaffold(title = "配置中心") { padding, scrollBehavior ->
        AdminList(padding, scrollBehavior) {
            item {
                SectionCard {
                    Text(
                        text = "凭据类只显示末 4 位，原值不会回传到浏览器；留空提交表示不修改，" +
                            "要清掉用「清除」。改动 ≤10 秒热生效。AI 限额不在这里改——" +
                            "去「AI 用量」页右上角的「编辑限额」。",
                        style = MiuixTheme.textStyles.footnote1,
                        color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                    )
                    InlineError(error)
                    if (loading && items.isEmpty()) StateHint("读取中…")
                    if (!loading && items.isEmpty() && error == null) StateHint("暂无配置项。")
                }
            }

            CONFIG_GROUPS.forEach { (prefix, groupTitle) ->
                val mine = items.filter { it.key.startsWith(prefix) }
                if (mine.isEmpty()) return@forEach
                item(key = "group-$prefix") {
                    SectionCard(
                        title = groupTitle,
                        hint = if (prefix == "ai_") "AI 限额在「AI 用量」页的「编辑限额」里改" else null,
                    ) {
                        mine.forEach { item ->
                            ConfigRow(
                                item = item,
                                draft = drafts[item.key] ?: "",
                                onDraft = { drafts[item.key] = it },
                                error = rowErrors[item.key],
                                onSave = {
                                    val value = (drafts[item.key] ?: "").trim()
                                    if (value.isEmpty()) {
                                        rowErrors[item.key] = "留空表示不修改；要清掉用「清除」"
                                    } else {
                                        scope.launch {
                                            val out = actions.call("已保存，≤10 秒生效") {
                                                Api.put<ConfigSetResult>(
                                                    "/admin/config/${urlEnc(item.key)}",
                                                    Api.encode(ConfigUpdateRequest(value)),
                                                )
                                            }
                                            if (out.ok) {
                                                drafts.remove(item.key)
                                                rowErrors.remove(item.key)
                                                load()
                                            } else {
                                                rowErrors[item.key] = out.error ?: "保存失败"
                                            }
                                        }
                                    }
                                },
                                onClear = {
                                    confirm = ConfirmRequest(
                                        title = "清除配置",
                                        desc = "将清除配置键 ${item.key}（值会从库里删除）。",
                                        success = "已清除，≤10 秒生效",
                                    ) {
                                        Api.put<ConfigSetResult>(
                                            "/admin/config/${urlEnc(item.key)}",
                                            Api.encode(ConfigUpdateRequest("")),
                                        )
                                        drafts.remove(item.key)
                                        load()
                                    }
                                },
                            )
                        }
                    }
                }
            }
        }
    }

    ConfirmActionDialog(request = confirm, onDismissed = { confirm = null })
}

@Composable
private fun ConfigRow(
    item: ConfigItem,
    draft: String,
    onDraft: (String) -> Unit,
    error: String?,
    onSave: () -> Unit,
    onClear: () -> Unit,
) {
    Column(Modifier.fillMaxWidth()) {
        Row(
            Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Column(Modifier.weight(1f)) {
                Row(
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(
                        text = configLabel(item.key),
                        style = MiuixTheme.textStyles.body2,
                        color = MiuixTheme.colorScheme.onSurface,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                    AdminBadge(item.key, BadgeTone.Neutral)
                    if (item.secret) AdminBadge("凭据", BadgeTone.Warning)
                }
                val state = when {
                    item.secret && item.configured -> "已配置 · 末 4 位 ${item.hint}"
                    item.configured -> "已配置：${item.value}"
                    else -> "未配置"
                }
                Text(
                    text = state,
                    style = MiuixTheme.textStyles.footnote2,
                    color = if (item.configured) MiuixTheme.colorScheme.onSurfaceVariantSummary else OnCardColors.warning,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                    fontFamily = FontFamily.Monospace,
                )
            }
        }
        Row(
            Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            TextField(
                value = draft,
                onValueChange = onDraft,
                label = if (item.secret) "输入新值替换" else "留空则不修改",
                singleLine = true,
                modifier = Modifier.weight(1f),
            )
            TextButton(text = "保存", colors = textButtonColorsPrimaryApp(), onClick = onSave)
            if (item.configured) {
                TextButton(text = "清除", colors = textButtonColorsDanger(), onClick = onClear)
            }
        }
        InlineError(error)
    }
}
