package cn.horatio.authweb.shell

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clipToBounds
import androidx.compose.ui.unit.dp
import cn.horatio.authweb.component.liquid.IosLiquidGlassNavigationBar
import cn.horatio.authweb.nav.HistoryBridge
import cn.horatio.authweb.nav.LocalNav
import cn.horatio.authweb.nav.NavController
import cn.horatio.authweb.nav.Navigator
import cn.horatio.authweb.nav.Route
import cn.horatio.authweb.screens.AccountScreen
import cn.horatio.authweb.screens.AuthorizeScreen
import cn.horatio.authweb.screens.DeleteCancelScreen
import cn.horatio.authweb.screens.InviteScreen
import cn.horatio.authweb.screens.LoginScreen
import cn.horatio.authweb.screens.ConsoleScreen
import cn.horatio.authweb.screens.PasskeysScreen
import cn.horatio.authweb.screens.SessionsScreen
import cn.horatio.authweb.screens.TwoFactorScreen
import cn.horatio.authweb.screens.admin.AdminAccessScreen
import cn.horatio.authweb.screens.admin.AdminAiScreen
import cn.horatio.authweb.screens.admin.AdminAuditScreen
import cn.horatio.authweb.screens.admin.AdminConfigScreen
import cn.horatio.authweb.screens.admin.AdminSessionsScreen
import cn.horatio.authweb.screens.admin.AdminUserDetailScreen
import cn.horatio.authweb.screens.admin.AdminUserSessionsScreen
import cn.horatio.authweb.screens.admin.AdminUsersScreen
import cn.horatio.authweb.shell.ReauthDialog
import top.yukonga.miuix.kmp.basic.SnackbarHost
import top.yukonga.miuix.kmp.basic.NavigationRail
import top.yukonga.miuix.kmp.basic.NavigationRailItem
import top.yukonga.miuix.kmp.basic.NavigationRailValue
import top.yukonga.miuix.kmp.basic.rememberNavigationRailState
import top.yukonga.miuix.kmp.nav.core.NavCornerClipMode
import top.yukonga.miuix.kmp.nav.core.NavDisplay
import top.yukonga.miuix.kmp.nav.core.NavDisplayEffects
import top.yukonga.miuix.kmp.nav.core.rememberNavBackStack
import top.yukonga.miuix.kmp.nav.core.rememberNavSystemCornerRadius
import top.yukonga.miuix.kmp.theme.MiuixTheme

/**
 * 应用壳：宽屏 NavigationRail / 窄屏液态玻璃胶囊底栏（同一份页签），
 * NavDisplay 承载页面，HistoryBridge 打通浏览器前进后退。
 * 页签集随当前分区切换：控制台五项 / 管理后台六项（super）或四项（项目管理员）。
 */
@Composable
fun AppRoot() {
    // 首帧就以 URL 路由起步（remember 只算一次）：若先落 Login 再由 LaunchedEffect
    // 改栈，已登录深进后台页时 LoginScreen 会抢先把栈改成概览（父/子 effect 竞态）
    val initialRoute = remember { HistoryBridge.currentFromLocation() ?: Route.Login }
    val backStack = rememberNavBackStack(initialRoute)
    val navigator = remember { Navigator(backStack) }
    val nav = remember { NavController(navigator) }
    val current = backStack.lastOrNull() ?: Route.Login
    val backdrop = rememberAppBackdrop()
    val blurActive = backdrop != null && WebUiPrefs.enableBlur

    // 启动接线：先装载会话（角色/能力全局可见，后台页直进也齐）+ 初始 URL → 路由
    //（replaceState 对齐）+ popstate 订阅
    LaunchedEffect(Unit) {
        runCatching { cn.horatio.authweb.data.SessionStore.refresh() }
        HistoryBridge.attach(navigator, initialRoute)
    }

    // 公开页（登录/邀请/授权/注销撤销）不渲染任何分区 chrome：无页签、无底栏、无 rail
    val inPublic = current is Route.Login || current is Route.Invite ||
        current is Route.Authorize || current is Route.DeleteCancel
    val inAdmin = current.toString().contains("Admin")
    val tabs = when {
        inPublic -> emptyList()
        inAdmin -> AppTabs.admin(cn.horatio.authweb.data.SessionStore.isSuper)
        else -> AppTabs.console()
    }
    val selectedIndex = tabs.indexOfFirst { it.route::class == current::class }.coerceAtLeast(0)

    val wide = shouldShowSplitPane()
    val expandRail = shouldExpandNavigationRail()
    val navCornerRadius = rememberNavSystemCornerRadius()

    CompositionLocalProvider(LocalNav provides nav) {
    Column(Modifier.fillMaxSize().background(MiuixTheme.colorScheme.surface)) {
    Row(Modifier.weight(1f).fillMaxWidth()) {
        if (wide && tabs.isNotEmpty()) {
            val railState = rememberNavigationRailState(
                initialValue = if (expandRail) NavigationRailValue.Expanded else NavigationRailValue.Collapsed,
            )
            LaunchedEffect(expandRail) {
                if (expandRail) railState.expand() else railState.collapse()
            }
            NavigationRail(state = railState) {
                tabs.forEachIndexed { index, tab ->
                    NavigationRailItem(
                        selected = index == selectedIndex,
                        onClick = { nav.switchSection(tabs, index) },
                        icon = tab.item.icon,
                        label = tab.item.label,
                    )
                }
            }
        }
        Box(
            Modifier
                .weight(1f)
                .fillMaxHeight()
                // 宽屏转场层不能画到 rail 上面
                .then(if (wide) Modifier.clipToBounds() else Modifier)
        ) {
            NavDisplay(
                backStack = backStack,
                onBack = { nav.back() },
                effects = NavDisplayEffects(
                    enableCornerClip = true,
                    cornerClipRadius = navCornerRadius,
                    cornerClipMode = NavCornerClipMode.Leading,
                    dimAmount = 0.5f,
                    blockInputDuringTransition = false,
                    backdropColor = MiuixTheme.colorScheme.surface,
                ),
            ) {
                entry<Route.Login> { LoginScreen() }
                entry<Route.Authorize> { route -> AuthorizeScreen(route.q) }
                entry<Route.Invite> { route -> InviteScreen(route.token) }
                entry<Route.DeleteCancel> { route -> DeleteCancelScreen(route.token) }
                entry<Route.Console> { ConsoleScreen() }
                entry<Route.Sessions> { SessionsScreen() }
                entry<Route.Passkeys> { PasskeysScreen() }
                entry<Route.TwoFactor> { TwoFactorScreen() }
                entry<Route.Account> { AccountScreen() }
                entry<Route.AdminUsers> { AdminUsersScreen() }
                entry<Route.AdminUserDetail> { route -> AdminUserDetailScreen(route.uid) }
                entry<Route.AdminAccess> { AdminAccessScreen() }
                entry<Route.AdminSessions> { AdminSessionsScreen() }
                entry<Route.AdminUserSessions> { route -> AdminUserSessionsScreen(route.uid) }
                entry<Route.AdminAudit> { AdminAuditScreen() }
                entry<Route.AdminConfig> { AdminConfigScreen() }
                entry<Route.AdminAi> { AdminAiScreen() }
            }
            Box(Modifier.align(Alignment.TopCenter)) {
                SnackbarHost(LocalSnackbarHostState.current)
            }
            ReauthDialog()
        }
        }
        if (!wide && tabs.isNotEmpty()) {
            Box(Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 8.dp)) {
                IosLiquidGlassNavigationBar(
                    items = tabs.map { it.item },
                    selectedIndex = selectedIndex,
                    onItemClick = { nav.switchSection(tabs, it) },
                    backdrop = backdrop,
                    isBlurActive = blurActive,
                    modifier = Modifier.fillMaxWidth(),
                )
            }
        }
    }
}
}
