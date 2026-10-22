// 管理后台「用户详情」屏（super 专属，由用户列表 push AdminUserDetail(uid) 进入）。
//
// 回执以 internal/auth/admin.go 的 AdminUserDetail 为准：在 AdminUser 之上加
// hasPassword / scopes / sessions / passkeys / bans / avatarImage。
// 写端点：/admin/users/{uid}/{role,password,email,ban,revoke-sessions}、
// /admin/roles/{uid}/scope（见 cmd/server/admin.go，全部经 ReauthController.ensure()）。
package cn.horatio.authweb.screens.admin

import androidx.compose.foundation.clickable
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
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.state.ToggleableState
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import cn.horatio.authweb.icons.AppIcon
import cn.horatio.authweb.component.TextButton
import cn.horatio.authweb.component.textButtonColorsDanger
import cn.horatio.authweb.component.textButtonColorsPrimaryApp
import cn.horatio.authweb.data.Api
import cn.horatio.authweb.data.ApiException
import cn.horatio.authweb.data.OkResponse
import cn.horatio.authweb.data.PasskeyInfo
import cn.horatio.authweb.data.RegistryApp
import cn.horatio.authweb.data.SessionInfo
import cn.horatio.authweb.data.SessionStore
import cn.horatio.authweb.nav.LocalNav
import cn.horatio.authweb.theme.OnCardColors
import com.composables.icons.lucide.ChevronLeft
import com.composables.icons.lucide.Lucide
import kotlinx.coroutines.launch
import kotlinx.serialization.Serializable
import top.yukonga.miuix.kmp.basic.Checkbox
import top.yukonga.miuix.kmp.basic.IconButton
import top.yukonga.miuix.kmp.basic.Switch
import top.yukonga.miuix.kmp.basic.TextField
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.theme.MiuixTheme

// ---- 回执与请求 DTO ----

@Serializable
data class BanInfo(val app: String = "*", val until: Long = 0, val reason: String = "")

/** GET /admin/users/{uid}（auth.AdminUserDetail：AdminUser 字段 + 凭据/授权/会话/封禁）。 */
@Serializable
data class AdminUserDetail(
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
    val hasPassword: Boolean = false,
    val scopes: List<String> = emptyList(),
    val sessions: List<SessionInfo> = emptyList(),
    val passkeys: List<PasskeyInfo> = emptyList(),
    val bans: List<BanInfo> = emptyList(),
    val avatarImage: String = "",
)

@Serializable data class RoleRequest(val role: String = "")
@Serializable data class ScopeRequest(val app: String = "", val op: String = "")
@Serializable data class PasswordResetRequest(
    val mode: String = "generate",
    val password: String = "",
    val forceChange: Boolean = false,
    val notify: Boolean = true,
    val reason: String = "",
)

@Serializable data class PasswordResetResult(val temporaryPassword: String = "")
@Serializable data class EmailChangeRequest(val email: String = "", val reason: String = "")
@Serializable data class BanRequest(val app: String = "", val until: Long = 0, val reason: String = "")
@Serializable data class AppRequest(val app: String = "")

private val ROLE_CHIPS = listOf(
    "user" to "普通用户",
    "admin" to "项目管理员",
    "super" to "平台管理员",
)

@Composable
fun AdminUserDetailScreen(uid: Long) {
    val nav = LocalNav.current
    val actions = rememberAdminActions()
    val scope = rememberCoroutineScope()

    var detail by remember { mutableStateOf<AdminUserDetail?>(null) }
    var loading by remember { mutableStateOf(true) }
    var error by remember { mutableStateOf<String?>(null) }
    var apps by remember { mutableStateOf<List<RegistryApp>>(emptyList()) }
    var scopes by remember { mutableStateOf<List<Pair<String, String>>>(emptyList()) }
    var confirm by remember { mutableStateOf<ConfirmRequest?>(null) }
    var tempPassword by remember { mutableStateOf<String?>(null) }
    var tempNotify by remember { mutableStateOf(true) }

    // 角色调整
    var roleDraft by remember { mutableStateOf("") }

    // 重置密码
    var rpMode by remember { mutableStateOf("generate") }
    var rpPassword by remember { mutableStateOf("") }
    var rpForce by remember { mutableStateOf(true) }
    var rpNotify by remember { mutableStateOf(true) }
    var rpReason by remember { mutableStateOf("") }
    var rpError by remember { mutableStateOf<String?>(null) }

    // 更换邮箱
    var newEmail by remember { mutableStateOf("") }
    var emailReason by remember { mutableStateOf("") }
    var emailError by remember { mutableStateOf<String?>(null) }

    // 封禁
    var banScope by remember { mutableStateOf("*") }
    var banDuration by remember { mutableStateOf("perm") }
    var banUntil by remember { mutableStateOf("") }
    var banReason by remember { mutableStateOf("") }
    var banError by remember { mutableStateOf<String?>(null) }

    suspend fun load() {
        loading = true
        try {
            detail = Api.get<AdminUserDetail>("/admin/users/$uid")
            roleDraft = detail?.role ?: "user"
            error = null
        } catch (e: ApiException) {
            error = e.message
        } catch (_: Exception) {
            error = "读取失败，请下拉重试"
        }
        loading = false
    }

    LaunchedEffect(uid) {
        load()
        apps = registryApps()
        scopes = banScopeOptions()
    }

    AdminScaffold(
        title = "用户详情",
        subtitle = detail?.email ?: "uid $uid",
        navigationIcon = { BackIcon(onClick = { nav.back() }) },
    ) { padding, scrollBehavior ->
        AdminList(padding, scrollBehavior) {
            when {
                loading && detail == null -> item { StateHint("读取中…") }
                detail == null -> item {
                    SectionCard {
                        InlineError(error)
                        TextButton(text = "重新加载", onClick = { scope.launch { load() } })
                    }
                }
                else -> {
                    val d = detail ?: return@AdminList

                    item {
                        SectionCard(title = "账号概要") {
                            Row(
                                Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.spacedBy(16.dp),
                            ) {
                                KeyValue("uid", d.uid.toString(), Modifier.weight(1f))
                                KeyValue("注册时间", fmtTime(d.createdAt), Modifier.weight(1.5f))
                            }
                            Row(
                                Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.spacedBy(16.dp),
                            ) {
                                KeyValue("密码", if (d.hasPassword) "已设置" else "未设置", Modifier.weight(1f))
                                KeyValue("两步验证", if (d.totpEnabled) "已开启" else "未开启", Modifier.weight(1f))
                                KeyValue("Passkey", "${d.passkeyCount} 把", Modifier.weight(1f))
                            }
                            if (d.nickname.isNotBlank() || d.hasAvatar) {
                                KeyValue("档案", d.nickname.ifBlank { "（无昵称）" })
                            }
                            InlineError(error)
                        }
                    }

                    // 角色与项目授权（super 才能动）
                    item {
                        SectionCard(
                            title = "角色与项目授权",
                            hint = "授予项目即成为项目管理员；全部项目都回收后角色自动降回普通用户。" +
                                "平台管理员的授予/撤销仅平台管理员可操作。",
                        ) {
                            ChoiceChips(ROLE_CHIPS, roleDraft) { roleDraft = it }
                            val isSelf = d.uid == SessionStore.session?.uid
                            TextButton(
                                text = if (isSelf) "不能修改自己的角色" else "保存角色",
                                enabled = !isSelf && roleDraft != d.role,
                                colors = if (roleDraft == "user") textButtonColorsDanger() else textButtonColorsPrimaryApp(),
                                onClick = {
                                    confirm = ConfirmRequest(
                                        title = "调整角色",
                                        desc = when (roleDraft) {
                                            "super" -> "将该用户设为平台管理员：可管理全部项目、用户目录与全局配置。"
                                            "admin" -> "将该用户设为项目管理员：需再授予至少一个项目才有实际管理范围。"
                                            else -> "将该用户降为普通用户：项目授权会一并收回。"
                                        },
                                        success = when (roleDraft) {
                                            "super" -> "已设为平台管理员"
                                            "admin" -> "已设为项目管理员"
                                            else -> "已降为普通用户"
                                        },
                                        danger = roleDraft == "user",
                                    ) {
                                        Api.post<OkResponse>(
                                            "/admin/users/${d.uid}/role",
                                            Api.encode(RoleRequest(roleDraft)),
                                        )
                                        load()
                                    }
                                },
                            )
                            if (d.role == "super") {
                                StateHint("平台管理员不受项目授权限制，管理全部项目。")
                            } else {
                                apps.forEach { app ->
                                    val granted = d.scopes.contains(app.key)
                                    Row(
                                        Modifier.fillMaxWidth(),
                                        verticalAlignment = Alignment.CenterVertically,
                                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                                    ) {
                                        Column(Modifier.weight(1f)) {
                                            Text(
                                                text = app.label,
                                                style = MiuixTheme.textStyles.body2,
                                                color = MiuixTheme.colorScheme.onSurface,
                                            )
                                            Text(
                                                text = if (granted) "已授权" else "未授权",
                                                style = MiuixTheme.textStyles.footnote2,
                                                color = if (granted) OnCardColors.success else MiuixTheme.colorScheme.onSurfaceVariantSummary,
                                            )
                                        }
                                        TextButton(
                                            text = if (granted) "回收" else "授予",
                                            colors = if (granted) textButtonColorsDanger() else textButtonColorsPrimaryApp(),
                                            onClick = {
                                                confirm = ConfirmRequest(
                                                    title = if (granted) "回收项目管理员" else "授予项目管理员",
                                                    desc = if (granted) {
                                                        "回收「${app.label}」的管理权；全部项目都回收后，该用户的角色会降回普通用户。"
                                                    } else {
                                                        "将「${app.label}」的管理权授予该用户（角色自动提为项目管理员）。"
                                                    },
                                                    success = if (granted) {
                                                        "已回收「${app.label}」的管理权"
                                                    } else {
                                                        "已授予「${app.label}」管理权"
                                                    },
                                                    danger = granted,
                                                ) {
                                                    Api.post<OkResponse>(
                                                        "/admin/roles/${d.uid}/scope",
                                                        Api.encode(ScopeRequest(app.key, if (granted) "revoke" else "grant")),
                                                    )
                                                    load()
                                                }
                                            },
                                        )
                                    }
                                }
                            }
                        }
                    }

                    // 重置密码
                    item {
                        SectionCard(title = "重置密码") {
                            ChoiceChips(
                                options = listOf("generate" to "自动生成", "manual" to "手动输入"),
                                selectedValue = rpMode,
                                onSelect = { rpMode = it; rpError = null },
                            )
                            if (rpMode == "manual") {
                                TextField(
                                    value = rpPassword,
                                    onValueChange = { rpPassword = it },
                                    label = "指定的新密码（至少 8 位）",
                                    singleLine = true,
                                    visualTransformation = PasswordVisualTransformation(),
                                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                                    modifier = Modifier.fillMaxWidth(),
                                )
                            }
                            CheckRow("下次登录必须修改密码", rpForce) { rpForce = it }
                            CheckRow("邮件通知用户", rpNotify) { rpNotify = it }
                            TextField(
                                value = rpReason,
                                onValueChange = { rpReason = it },
                                label = "原因（选填，记入审计）",
                                singleLine = true,
                                modifier = Modifier.fillMaxWidth(),
                            )
                            InlineError(rpError)
                            TextButton(
                                text = "重置密码",
                                colors = textButtonColorsDanger(),
                                onClick = {
                                    if (rpMode == "manual" && rpPassword.length < 8) {
                                        rpError = "手动输入的密码至少 8 位"
                                        return@TextButton
                                    }
                                    confirm = ConfirmRequest(
                                        title = "重置密码",
                                        desc = "将重置 ${d.email} 的登录密码" +
                                            (if (rpForce) "，并要求其下次登录时修改" else "") +
                                            (if (rpNotify) "，新密码会邮件通知该用户" else "，请通过其它渠道转告该用户") +
                                            "。",
                                        success = "已重置 ${d.email} 的密码",
                                    ) {
                                        val out = Api.post<PasswordResetResult>(
                                            "/admin/users/${d.uid}/password",
                                            Api.encode(
                                                PasswordResetRequest(
                                                    mode = rpMode,
                                                    password = if (rpMode == "manual") rpPassword else "",
                                                    forceChange = rpForce,
                                                    notify = rpNotify,
                                                    reason = rpReason.trim(),
                                                ),
                                            ),
                                        )
                                        tempNotify = rpNotify
                                        tempPassword = out.temporaryPassword.ifBlank { null }
                                        load()
                                    }
                                },
                            )
                        }
                    }

                    // 更换邮箱
                    item {
                        SectionCard(
                            title = "更换邮箱",
                            hint = "当前邮箱 ${d.email}。更换后用户立即用新邮箱登录，现会话不受影响；" +
                                "新旧邮箱都会收到通知。",
                        ) {
                            TextField(
                                value = newEmail,
                                onValueChange = { newEmail = it },
                                label = "新的登录邮箱",
                                singleLine = true,
                                modifier = Modifier.fillMaxWidth(),
                            )
                            TextField(
                                value = emailReason,
                                onValueChange = { emailReason = it },
                                label = "原因（选填，记入审计）",
                                singleLine = true,
                                modifier = Modifier.fillMaxWidth(),
                            )
                            InlineError(emailError)
                            TextButton(
                                text = "更换邮箱",
                                colors = textButtonColorsDanger(),
                                onClick = {
                                    val next = newEmail.trim()
                                    emailError = when {
                                        next.isEmpty() -> "请先填写新邮箱"
                                        next == d.email -> "新邮箱与当前邮箱相同"
                                        else -> null
                                    }
                                    if (emailError != null) return@TextButton
                                    confirm = ConfirmRequest(
                                        title = "更换邮箱",
                                        desc = "将 ${d.email} 的登录邮箱改为 $next，新旧邮箱都会收到通知；" +
                                            "用户立即改用新邮箱登录，现会话不受影响。",
                                        success = "已将 ${d.email} 的邮箱改为 $next",
                                    ) {
                                        Api.post<OkResponse>(
                                            "/admin/users/${d.uid}/email",
                                            Api.encode(EmailChangeRequest(next, emailReason.trim())),
                                        )
                                        newEmail = ""
                                        emailReason = ""
                                        load()
                                    }
                                },
                            )
                        }
                    }

                    // 封禁 / 解封
                    item {
                        SectionCard(title = "封禁", hint = "封禁期间该账号无法登录；限时到期自动解除，永久需手动解封。") {
                            if (d.bans.isEmpty()) {
                                StateHint("当前没有生效中的封禁。")
                            } else {
                                d.bans.forEach { ban ->
                                    Row(
                                        Modifier.fillMaxWidth(),
                                        verticalAlignment = Alignment.CenterVertically,
                                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                                    ) {
                                        Column(Modifier.weight(1f)) {
                                            Text(
                                                text = if (ban.app == "*") "全局" else ban.app,
                                                style = MiuixTheme.textStyles.body2,
                                                color = MiuixTheme.colorScheme.onSurface,
                                            )
                                            Text(
                                                text = (if (ban.until > 0) "将于 ${fmtTime(ban.until)} 解除" else "永久") +
                                                    (if (ban.reason.isNotBlank()) " · ${ban.reason}" else ""),
                                                style = MiuixTheme.textStyles.footnote2,
                                                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                                                maxLines = 2,
                                                overflow = TextOverflow.Ellipsis,
                                            )
                                        }
                                        TextButton(
                                            text = "解除",
                                            colors = textButtonColorsDanger(),
                                            onClick = {
                                                confirm = ConfirmRequest(
                                                    title = "解除封禁",
                                                    desc = "将解除对 ${d.email} 的「${ban.app}」封禁，该范围随即恢复可登录。",
                                                    success = "已解除 ${d.email} 的封禁",
                                                    danger = false,
                                                ) {
                                                    Api.del<OkResponse>(
                                                        "/admin/users/${d.uid}/ban",
                                                        Api.encode(AppRequest(ban.app)),
                                                    )
                                                    load()
                                                }
                                            },
                                        )
                                    }
                                }
                            }
                            Text(
                                text = "封禁范围",
                                style = MiuixTheme.textStyles.footnote2,
                                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                            )
                            ChoiceChips(scopes, banScope) { banScope = it }
                            ChoiceChips(
                                options = listOf("perm" to "永久", "temp" to "限时"),
                                selectedValue = banDuration,
                                onSelect = { banDuration = it },
                            )
                            if (banDuration == "temp") {
                                TextField(
                                    value = banUntil,
                                    onValueChange = { banUntil = it },
                                    label = "解除时间（yyyy-MM-ddTHH:mm，至少 5 分钟后）",
                                    singleLine = true,
                                    modifier = Modifier.fillMaxWidth(),
                                )
                            }
                            TextField(
                                value = banReason,
                                onValueChange = { banReason = it },
                                label = "原因（选填，记入审计）",
                                singleLine = true,
                                modifier = Modifier.fillMaxWidth(),
                            )
                            InlineError(banError)
                            TextButton(
                                text = "封禁",
                                colors = textButtonColorsDanger(),
                                onClick = {
                                    var untilMs = 0L
                                    if (banDuration == "temp") {
                                        val parsed = localDateTimeMs(banUntil)
                                        if (parsed == null || parsed < nowMs() + 5 * 60 * 1000) {
                                            banError = "解除时间至少要在 5 分钟之后"
                                            return@TextButton
                                        }
                                        untilMs = parsed
                                    }
                                    banError = null
                                    val scopeLabel = scopes.firstOrNull { it.first == banScope }?.second ?: banScope
                                    confirm = ConfirmRequest(
                                        title = "封禁账号",
                                        desc = "将封禁 ${d.email}：范围「$scopeLabel」，" +
                                            (if (untilMs > 0) "至 ${fmtTime(untilMs)} 解除" else "永久") +
                                            (if (banReason.isNotBlank()) "；原因：${banReason.trim()}" else "") +
                                            "。封禁期间该账号无法登录。",
                                        success = "已封禁 ${d.email}",
                                    ) {
                                        Api.post<OkResponse>(
                                            "/admin/users/${d.uid}/ban",
                                            Api.encode(BanRequest(banScope, untilMs, banReason.trim())),
                                        )
                                        banReason = ""
                                        banUntil = ""
                                        load()
                                    }
                                },
                            )
                        }
                    }

                    // 活跃会话
                    item {
                        SectionCard(
                            title = "活跃会话",
                            actions = {
                                TextButton(
                                    text = "查看全部",
                                    onClick = { nav.push(cn.horatio.authweb.nav.Route.AdminUserSessions(d.uid)) },
                                )
                                Spacer(Modifier.width(8.dp))
                                TextButton(
                                    text = "退出全部",
                                    colors = textButtonColorsDanger(),
                                    onClick = {
                                        confirm = ConfirmRequest(
                                            title = "退出该用户全部会话",
                                            desc = "该用户的所有设备（含网页端）都会退出登录，需要重新登录。",
                                            success = "已退出该用户全部会话",
                                        ) {
                                            Api.post<OkResponse>("/admin/users/${d.uid}/revoke-sessions", "{}")
                                            load()
                                        }
                                    },
                                )
                            },
                        ) {
                            if (d.sessions.isEmpty()) {
                                StateHint("暂无活跃会话")
                            } else {
                                d.sessions.forEach { s ->
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
                                        }
                                        TextButton(
                                            text = "退出",
                                            colors = textButtonColorsDanger(),
                                            onClick = {
                                                confirm = ConfirmRequest(
                                                    title = "退出会话",
                                                    desc = "将让「${s.device}」（${s.ip}）立即退出登录，需要重新登录。",
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
                }
            }
        }
    }

    ConfirmActionDialog(request = confirm, onDismissed = { confirm = null })
    TempPasswordDialog(password = tempPassword, notify = tempNotify, onDismiss = { tempPassword = null })
}

/** 顶栏返回键（详情/钻取页共用）。 */
@Composable
internal fun BackIcon(onClick: () -> Unit) {
    IconButton(onClick = onClick, backgroundColor = Color.Transparent) {
        AppIcon(
            icon = Lucide.ChevronLeft,
            contentDescription = "返回",
            tint = MiuixTheme.colorScheme.onBackground,
        )
    }
}

/** 复选行（强制改密 / 邮件通知等布尔配置）。 */
@Composable
internal fun CheckRow(label: String, checked: Boolean, onChange: (Boolean) -> Unit) {
    Row(
        Modifier.fillMaxWidth().clickable { onChange(!checked) },
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Checkbox(
            state = if (checked) ToggleableState.On else ToggleableState.Off,
            onClick = { onChange(!checked) },
        )
        Text(
            text = label,
            style = MiuixTheme.textStyles.body2,
            color = MiuixTheme.colorScheme.onSurface,
        )
    }
}
