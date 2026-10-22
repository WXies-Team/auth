// 控制台 · 概览：行为规格 = 旧前端 internal/ui/templates/console.html + app.js initConsole。
// 身份卡（头像色块 + 昵称 + 邮箱 + 角色徽标）、「登录方式与安全」三行（密码 / 两步
// 验证 / Passkey，数据来自 GET /web/session + /api/totp + /api/passkeys）、
// 管理已登录设备入口、退出登录（POST /web/logout → 清 SessionStore → 回登录页）。
package cn.horatio.authweb.screens

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
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import cn.horatio.authweb.component.ItemFadeSpec
import cn.horatio.authweb.component.ItemPlacementSpec
import cn.horatio.authweb.component.PrefIcon
import cn.horatio.authweb.component.SmallTitle
import cn.horatio.authweb.component.TextButton
import cn.horatio.authweb.component.buttonColorsDanger
import cn.horatio.authweb.component.buttonColorsPrimaryApp
import cn.horatio.authweb.data.Api
import cn.horatio.authweb.data.OkResponse
import cn.horatio.authweb.data.PasskeyInfo
import cn.horatio.authweb.data.ProfileResponse
import cn.horatio.authweb.data.SessionStore
import cn.horatio.authweb.data.TotpStatusResponse
import cn.horatio.authweb.data.WebSessionResponse
import cn.horatio.authweb.nav.LocalNav
import cn.horatio.authweb.nav.Route
import cn.horatio.authweb.shell.ScreenScaffold
import cn.horatio.authweb.shell.adaptiveContentWidth
import cn.horatio.authweb.shell.pageContentPadding
import cn.horatio.authweb.shell.pageScrollModifiers
import com.composables.icons.lucide.KeyRound
import com.composables.icons.lucide.Lock
import com.composables.icons.lucide.Lucide
import com.composables.icons.lucide.ShieldCheck
import kotlinx.coroutines.launch
import top.yukonga.miuix.kmp.basic.BasicComponent
import top.yukonga.miuix.kmp.basic.BasicComponentDefaults
import top.yukonga.miuix.kmp.basic.Button
import top.yukonga.miuix.kmp.basic.Card
import top.yukonga.miuix.kmp.basic.CircularProgressIndicator
import top.yukonga.miuix.kmp.basic.MiuixScrollBehavior
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.basic.VerticalScrollBar
import top.yukonga.miuix.kmp.basic.rememberScrollBarAdapter
import top.yukonga.miuix.kmp.theme.MiuixTheme

@Composable
fun ConsoleScreen() {
    val nav = LocalNav.current
    val scope = rememberCoroutineScope()
    val scrollBehavior = MiuixScrollBehavior()
    val lazyListState = remember { LazyListState() }

    var loaded by remember { mutableStateOf(false) }
    var loadError by remember { mutableStateOf<String?>(null) }
    var me by remember { mutableStateOf<WebSessionResponse?>(null) }
    var totpEnabled by remember { mutableStateOf(false) }
    var passkeyCount by remember { mutableStateOf(0) }
    var profile by remember { mutableStateOf<ProfileResponse?>(null) }
    var loggingOut by remember { mutableStateOf(false) }

    LaunchedEffect(Unit) {
        try {
            // 会话入口 + CSRF 令牌装载（401 时 refresh 内部清空并回 null）
            val s = SessionStore.refresh()
            if (s == null) {
                loadError = "登录已过期，请重新登录"
                loaded = true
                return@LaunchedEffect
            }
            me = s
            totpEnabled = Api.get<TotpStatusResponse>("/api/totp").enabled
            passkeyCount = Api.get<List<PasskeyInfo>>("/api/passkeys").size
            // 身份卡的头像色/昵称走档案接口；失败不拦页面（回退邮箱前缀展示）
            profile = runCatching { Api.get<ProfileResponse>("/api/profile") }.getOrNull()
            loaded = true
        } catch (e: Exception) {
            loadError = e.message ?: "账号信息加载失败，请稍后重试"
            loaded = true
        }
    }

    fun logout() {
        if (loggingOut) return
        scope.launch {
            loggingOut = true
            try {
                Api.post<OkResponse>("/web/logout", "{}")
            } catch (_: Exception) {
                // 已登出也要跳
            }
            SessionStore.clear()
            nav.push(Route.Login)
        }
    }

    ScreenScaffold(title = "概览", scrollBehavior = scrollBehavior) { innerPadding ->
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
                    val session = me ?: return@LazyColumn
                    // ① 身份卡
                    item(key = "identity") {
                        Column(Modifier.animateItem(fadeInSpec = ItemFadeSpec, placementSpec = ItemPlacementSpec, fadeOutSpec = ItemFadeSpec)) {
                            SmallTitle(text = "账号")
                            Card(modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp)) {
                                Column(Modifier.padding(16.dp)) {
                                    Row(
                                        verticalAlignment = Alignment.CenterVertically,
                                        horizontalArrangement = Arrangement.spacedBy(12.dp),
                                    ) {
                                        val p = profile
                                        val effective = effectiveAvatarColorIndex(p?.avatarColor ?: 0, session.uid)
                                        AvatarBox(
                                            color = AvatarPalette[effective],
                                            initial = avatarInitial(p?.nickname ?: "", session.email),
                                            image = p?.avatarImage?.takeIf { it.isNotBlank() }?.let { decodeBase64Image(it) },
                                            size = 56.dp,
                                        )
                                        Column(Modifier.weight(1f)) {
                                            Text(
                                                text = (p?.nickname ?: "").ifBlank { session.email.substringBefore('@') },
                                                style = MiuixTheme.textStyles.title3,
                                                fontWeight = FontWeight.SemiBold,
                                            )
                                            Text(
                                                text = session.email,
                                                style = MiuixTheme.textStyles.footnote1,
                                                color = MiuixTheme.colorScheme.onSurfaceSecondary,
                                            )
                                        }
                                        if (session.role == "admin" || session.role == "super") {
                                            Text(
                                                text = if (session.role == "super") "平台管理员" else "项目管理员",
                                                style = MiuixTheme.textStyles.footnote2,
                                                fontWeight = FontWeight.SemiBold,
                                                color = cn.horatio.authweb.theme.OnCardColors.primary,
                                                modifier = Modifier
                                                    .defaultMinSize(minHeight = 40.dp)
                                                    .wrapContentHeight(Alignment.CenterVertically),
                                            )
                                        }
                                    }
                                    Text(
                                        text = "可随时在「登录会话」页退出某台设备。",
                                        style = MiuixTheme.textStyles.footnote1,
                                        color = MiuixTheme.colorScheme.onSurfaceSecondary,
                                        modifier = Modifier.padding(top = 12.dp),
                                    )
                                    Row(
                                        modifier = Modifier.padding(top = 12.dp),
                                        horizontalArrangement = Arrangement.spacedBy(12.dp),
                                    ) {
                                        Button(
                                            onClick = { nav.push(Route.Sessions) },
                                            modifier = Modifier.weight(1f),
                                            colors = buttonColorsPrimaryApp(),
                                        ) {
                                            Text(text = "管理已登录设备")
                                        }
                                        Button(
                                            onClick = { logout() },
                                            enabled = !loggingOut,
                                            modifier = Modifier.weight(1f),
                                            colors = buttonColorsDanger(),
                                        ) {
                                            Text(text = "退出登录")
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // ② 登录方式与安全
                    item(key = "security") {
                        Column(Modifier.animateItem(fadeInSpec = ItemFadeSpec, placementSpec = ItemPlacementSpec, fadeOutSpec = ItemFadeSpec)) {
                            SmallTitle(text = "登录方式与安全")
                            Card(modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp)) {
                                BasicComponent(
                                    title = "密码",
                                    summary = if (session.passwordSet) "已设置" else "未设置（该账号靠验证码或 Passkey 登录）",
                                    summaryColor = BasicComponentDefaults.summaryColor(
                                        color = MiuixTheme.colorScheme.onSurfaceSecondary,
                                    ),
                                    startAction = { PrefIcon(Lucide.Lock) },
                                    endActions = {
                                        TextButton(text = "管理", onClick = { nav.push(Route.Account) })
                                    },
                                )
                                BasicComponent(
                                    title = "两步验证",
                                    summary = if (totpEnabled) "已开启" else "未开启",
                                    summaryColor = BasicComponentDefaults.summaryColor(
                                        color = if (totpEnabled) {
                                            cn.horatio.authweb.theme.OnCardColors.success
                                        } else {
                                            MiuixTheme.colorScheme.onSurfaceSecondary
                                        },
                                    ),
                                    startAction = { PrefIcon(Lucide.ShieldCheck) },
                                    endActions = {
                                        TextButton(text = "管理", onClick = { nav.push(Route.TwoFactor) })
                                    },
                                )
                                BasicComponent(
                                    title = "Passkey",
                                    summary = if (passkeyCount > 0) "$passkeyCount 个" else "未添加",
                                    summaryColor = BasicComponentDefaults.summaryColor(
                                        color = MiuixTheme.colorScheme.onSurfaceSecondary,
                                    ),
                                    startAction = { PrefIcon(Lucide.KeyRound) },
                                    endActions = {
                                        TextButton(text = "管理", onClick = { nav.push(Route.Passkeys) })
                                    },
                                )
                            }
                            Text(
                                text = "至少保留一种登录方式：只有密码、两步验证或 Passkey 至少有其一，账号才进得来。",
                                style = MiuixTheme.textStyles.footnote1,
                                color = MiuixTheme.colorScheme.onSurfaceSecondary,
                                modifier = Modifier.padding(horizontal = 28.dp).padding(top = 2.dp),
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
    }
}
