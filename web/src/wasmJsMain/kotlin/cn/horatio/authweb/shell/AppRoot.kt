package cn.horatio.authweb.shell

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clipToBounds
import androidx.compose.ui.unit.dp
import cn.horatio.authweb.component.liquid.IosLiquidGlassNavigationBar
import cn.horatio.authweb.nav.HistoryBridge
import cn.horatio.authweb.nav.NavController
import cn.horatio.authweb.nav.Navigator
import cn.horatio.authweb.nav.Route
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
fun AppRoot(isSuperAdmin: () -> Boolean = { false }) {
    val backStack = rememberNavBackStack<Route>(Route.Login)
    val navigator = remember { Navigator(backStack) }
    val nav = remember { NavController(navigator) }
    val current = backStack.lastOrNull() ?: Route.Login
    val backdrop = rememberAppBackdrop()
    val blurActive = backdrop != null && WebUiPrefs.enableBlur

    // 启动接线：初始 URL → 路由（replaceState 对齐）+ popstate 订阅
    LaunchedEffect(Unit) {
        val initial = HistoryBridge.currentFromLocation() ?: Route.Login
        backStack.clear()
        backStack.add(initial)
        HistoryBridge.attach(navigator, initial)
    }

    val inAdmin = current.toString().contains("Admin")
    val tabs = if (inAdmin) AppTabs.admin(isSuperAdmin()) else AppTabs.console()
    val selectedIndex = tabs.indexOfFirst { it.route::class == current::class }.coerceAtLeast(0)

    val wide = shouldShowSplitPane()
    val expandRail = shouldExpandNavigationRail()
    val navCornerRadius = rememberNavSystemCornerRadius()

    Row(Modifier.fillMaxSize().background(MiuixTheme.colorScheme.surface)) {
        if (wide) {
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
                // 窄屏给玻璃底栏让位（浮动式，内容不被推挤）
                .then(if (!wide && tabs.isNotEmpty()) Modifier.padding(bottom = 88.dp) else Modifier),
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
                entry<Route.Login> { PlaceholderScreen("登录") }
                entry<Route.Authorize> { PlaceholderScreen("授权登录") }
                entry<Route.Invite> { PlaceholderScreen("接受邀请") }
                entry<Route.DeleteCancel> { PlaceholderScreen("撤销注销") }
                entry<Route.Console> { PlaceholderScreen("概览") }
                entry<Route.Sessions> { PlaceholderScreen("登录会话") }
                entry<Route.Passkeys> { PlaceholderScreen("Passkey") }
                entry<Route.TwoFactor> { PlaceholderScreen("两步验证") }
                entry<Route.Account> { PlaceholderScreen("账号") }
                entry<Route.AdminUsers> { PlaceholderScreen("用户") }
                entry<Route.AdminUserDetail> { PlaceholderScreen("用户详情") }
                entry<Route.AdminAccess> { PlaceholderScreen("项目访问") }
                entry<Route.AdminSessions> { PlaceholderScreen("会话总览") }
                entry<Route.AdminUserSessions> { PlaceholderScreen("会话明细") }
                entry<Route.AdminAudit> { PlaceholderScreen("审计日志") }
                entry<Route.AdminConfig> { PlaceholderScreen("配置中心") }
                entry<Route.AdminAi> { PlaceholderScreen("AI 用量") }
            }
            if (!wide && tabs.isNotEmpty()) {
                Box(Modifier.align(Alignment.BottomCenter)) {
                    IosLiquidGlassNavigationBar(
                        items = tabs.map { it.item },
                        selectedIndex = selectedIndex,
                        onItemClick = { nav.switchSection(tabs, it) },
                        backdrop = backdrop,
                        isBlurActive = blurActive,
                    )
                }
            }
        }
    }
}
