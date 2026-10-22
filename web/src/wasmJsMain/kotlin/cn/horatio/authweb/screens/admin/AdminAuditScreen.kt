// 管理后台「审计日志」屏（scoped：app-admin 只见自己项目标记的条目）。
//
// 端点：GET /admin/audit?action=&actor=&target=&from=&to=&limit=&offset=
// 回执 {items:[AuditRow], total}（cmd/server/admin.go 的 page）。
// 事件下拉的取值与 internal/auth/audit.go 的 Audit* 常量、旧 admin-audit.html 的
// option 列表逐字一致（login 拆成 login.success / login.fail，与模板同一口径）。
package cn.horatio.authweb.screens.admin

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import cn.horatio.authweb.component.TextButton
import cn.horatio.authweb.component.textButtonColorsPrimaryApp
import cn.horatio.authweb.data.Api
import cn.horatio.authweb.data.ApiException
import kotlinx.serialization.Serializable
import top.yukonga.miuix.kmp.basic.TextField
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.preference.WindowDropdownPreference
import top.yukonga.miuix.kmp.theme.MiuixTheme

/** GET /admin/audit 的一条（auth.AuditRow）。 */
@Serializable
data class AuditRow(
    val id: Long = 0,
    val ts: Long = 0,
    val actorUid: Long = 0,
    val actorEmail: String = "",
    val action: String = "",
    val result: String = "",
    val targetUid: Long = 0,
    val ip: String = "",
    val userAgent: String = "",
    val detail: Map<String, String>? = null,
)

/** 事件下拉：value 逐字对齐 Audit* 常量（login 已按模板拆成两态）。 */
private val AUDIT_ACTIONS: List<Pair<String, String>> = listOf(
    "" to "全部",
    "register" to "register",
    "login.success" to "login.success",
    "login.fail" to "login.fail",
    "logout" to "logout",
    "password.change" to "password.change",
    "password.reset" to "重置密码",
    "email.change" to "email.change",
    "account.delete" to "account.delete",
    "session.kick" to "session.kick",
    "passkey.create" to "passkey.create",
    "passkey.rename" to "passkey.rename",
    "passkey.delete" to "passkey.delete",
    "totp.setup" to "totp.setup",
    "totp.enable" to "totp.enable",
    "totp.disable" to "totp.disable",
    "recovery.generate" to "recovery.generate",
    "recovery.consume" to "recovery.consume",
    "reauth" to "reauth",
    "profile.update" to "profile.update",
    "admin.user.role_change" to "admin.user.role_change",
    "admin.user.session_revoke" to "admin.user.session_revoke",
    "admin.session.revoke" to "admin.session.revoke",
    "admin.config.set" to "admin.config.set",
    "admin.audit.view" to "admin.audit.view",
    "admin.role.grant" to "admin.role.grant",
    "admin.role.revoke" to "admin.role.revoke",
    "admin.role.change" to "admin.role.change",
    "admin.oauth_client.write" to "接入配置",
    "internal.ensure" to "internal.ensure",
    "user.ban" to "封禁账号",
    "user.unban" to "解除封禁",
    "project.access_grant" to "加入项目名单",
    "project.access_revoke" to "移出项目名单",
    "project.restrict_on" to "开启项目限制",
    "project.restrict_off" to "关闭项目限制",
    "account.delete_requested" to "提交注销",
    "account.delete_cancelled" to "撤销注销",
    "user.email_change" to "更换邮箱",
    "user.profile_reset" to "重置资料",
    "user.invite" to "邀请用户",
    "user.invite_resend" to "重发邀请",
    "user.invite_revoke" to "撤销邀请",
    "user.invite_accept" to "接受邀请",
    "admin.bulk_action" to "批量操作",
)

private const val AUDIT_PAGE = 50

/** detail → `k: v k: v` 平铺（旧版 detailText 同款排版）。 */
internal fun detailText(detail: Map<String, String>?): String {
    if (detail == null || detail.isEmpty()) return "—"
    return entriesJoin(detail)
}

private fun entriesJoin(detail: Map<String, String>): String = detail.entries.joinToString(" ") {
    "${it.key}: ${it.value}"
}

@Composable
fun AdminAuditScreen() {
    var actionValue by remember { mutableStateOf("") }
    var actor by remember { mutableStateOf("") }
    var target by remember { mutableStateOf("") }
    var fromDay by remember { mutableStateOf("") }
    var toDay by remember { mutableStateOf("") }
    var rangeKind by remember { mutableStateOf("custom") }
    var offset by remember { mutableStateOf(0) }
    var refreshKey by remember { mutableStateOf(0) }

    var rows by remember { mutableStateOf<List<AuditRow>>(emptyList()) }
    var total by remember { mutableStateOf(0) }
    var loading by remember { mutableStateOf(true) }
    var error by remember { mutableStateOf<String?>(null) }

    fun applyRange(kind: String) {
        rangeKind = kind
        offset = 0
        refreshKey++
        when (kind) {
            "today" -> {
                fromDay = todayStr()
                toDay = todayStr()
            }
            "7" -> {
                fromDay = dayShift(todayStr(), -6)
                toDay = todayStr()
            }
            "30" -> {
                fromDay = dayShift(todayStr(), -29)
                toDay = todayStr()
            }
            else -> {
                fromDay = ""
                toDay = ""
            }
        }
    }

    suspend fun load() {
        loading = true
        try {
            val params = buildString {
                append("/admin/audit?limit=$AUDIT_PAGE&offset=$offset")
                if (actionValue.isNotEmpty()) append("&action=${urlEnc(actionValue)}")
                if (actor.isNotBlank()) append("&actor=${urlEnc(actor.trim())}")
                if (target.isNotBlank()) append("&target=${urlEnc(target.trim())}")
                if (fromDay.isNotBlank()) dayStartMs(fromDay)?.let { append("&from=$it") }
                if (toDay.isNotBlank()) dayEndMs(toDay)?.let { append("&to=$it") }
            }
            val res = Api.get<AdminPage<AuditRow>>(params)
            rows = res.items
            total = res.total
            error = null
        } catch (e: ApiException) {
            error = e.message
        } catch (_: Exception) {
            error = "读取失败，请刷新重试"
        }
        loading = false
    }

    LaunchedEffect(refreshKey) { load() }

    AdminScaffold(title = "审计日志") { padding, scrollBehavior ->
        AdminList(padding, scrollBehavior) {
            // 筛选卡
            item {
                SectionCard(title = "筛选") {
                    WindowDropdownPreference(
                        title = "事件",
                        summary = AUDIT_ACTIONS.firstOrNull { it.first == actionValue }?.second ?: "全部",
                        items = AUDIT_ACTIONS.map { it.second },
                        selectedIndex = AUDIT_ACTIONS.indexOfFirst { it.first == actionValue }
                            .coerceAtLeast(0),
                        onSelectedIndexChange = { index ->
                            actionValue = AUDIT_ACTIONS.getOrNull(index)?.first ?: ""
                            offset = 0
                            refreshKey++
                        },
                    )
                    Row(
                        Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        TextField(
                            value = actor,
                            onValueChange = { actor = it },
                            label = "操作者 uid",
                            singleLine = true,
                            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                            modifier = Modifier.weight(1f),
                        )
                        TextField(
                            value = target,
                            onValueChange = { target = it },
                            label = "对象 uid",
                            singleLine = true,
                            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                            modifier = Modifier.weight(1f),
                        )
                    }
                    ChoiceChips(
                        options = listOf(
                            "today" to "今天",
                            "7" to "近 7 天",
                            "30" to "近 30 天",
                            "custom" to "自定义",
                        ),
                        selectedValue = rangeKind,
                        onSelect = { applyRange(it) },
                    )
                    Row(
                        Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        TextField(
                            value = fromDay,
                            onValueChange = {
                                fromDay = it
                                rangeKind = "custom"
                            },
                            label = "开始 yyyy-MM-dd",
                            singleLine = true,
                            modifier = Modifier.weight(1f),
                        )
                        TextField(
                            value = toDay,
                            onValueChange = {
                                toDay = it
                                rangeKind = "custom"
                            },
                            label = "结束 yyyy-MM-dd",
                            singleLine = true,
                            modifier = Modifier.weight(1f),
                        )
                    }
                    InlineError(error)
                    // 操作按钮独立一行右对齐：查询 primary、重置 ghost（筛选字段同基线不再被挤）
                    Row(
                        Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.End,
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        TextButton(
                            text = "重置",
                            onClick = {
                                actionValue = ""
                                actor = ""
                                target = ""
                                offset = 0
                                applyRange("custom")
                                refreshKey++
                            },
                        )
                        Spacer(Modifier.width(8.dp))
                        TextButton(
                            text = "查询",
                            colors = textButtonColorsPrimaryApp(),
                            onClick = { offset = 0; refreshKey++ },
                        )
                    }
                }
            }

            // 结果表
            item {
                SectionCard(title = "结果") {
                    when {
                        loading && rows.isEmpty() -> StateHint("读取中…")
                        rows.isEmpty() -> StateHint("暂无匹配的审计记录")
                        else -> {
                            rows.forEach { row ->
                                AuditRowLine(row)
                            }
                        }
                    }
                }
            }

            item {
                PagerRow(
                    total = total,
                    shown = rows.size,
                    offset = offset,
                    onPrev = { offset = (offset - AUDIT_PAGE).coerceAtLeast(0); refreshKey++ },
                    onNext = { offset += AUDIT_PAGE; refreshKey++ },
                )
            }
        }
    }
}

@Composable
private fun AuditRowLine(row: AuditRow) {
    val who = if (row.actorUid > 0) {
        "${row.actorUid} ${row.actorEmail}"
    } else {
        row.actorEmail.ifBlank { "匿名" }
    }
    Row(
        Modifier.fillMaxWidth().padding(vertical = 4.dp),
        verticalAlignment = Alignment.Top,
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Column(Modifier.weight(1.2f)) {
            Text(
                text = fmtTime(row.ts),
                style = MiuixTheme.textStyles.footnote1,
                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                maxLines = 1,
            )
            Text(
                text = row.action,
                style = MiuixTheme.textStyles.footnote1,
                color = MiuixTheme.colorScheme.onSurface,
                fontFamily = FontFamily.Monospace,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis,
            )
        }
        Column(Modifier.weight(1.4f)) {
            Text(
                text = who,
                style = MiuixTheme.textStyles.footnote1,
                color = MiuixTheme.colorScheme.onSurface,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Text(
                text = "对象 ${if (row.targetUid > 0) row.targetUid else "—"} · ${row.ip.ifBlank { "—" }}",
                style = MiuixTheme.textStyles.footnote2,
                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                fontFamily = FontFamily.Monospace,
            )
            Text(
                text = detailText(row.detail),
                style = MiuixTheme.textStyles.footnote2,
                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                maxLines = 3,
                overflow = TextOverflow.Ellipsis,
            )
        }
        AdminBadge(
            text = if (row.result == "ok") "成功" else "失败",
            tone = if (row.result == "ok") BadgeTone.Success else BadgeTone.Warning,
        )
    }
}
