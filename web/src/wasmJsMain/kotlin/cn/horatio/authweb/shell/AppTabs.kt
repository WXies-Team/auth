package cn.horatio.authweb.shell

import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.graphics.vector.ImageVector
import cn.horatio.authweb.component.liquid.NavigationItem
import cn.horatio.authweb.nav.Route
import com.composables.icons.lucide.ChartColumn
import com.composables.icons.lucide.House
import com.composables.icons.lucide.KeyRound
import com.composables.icons.lucide.Lock
import com.composables.icons.lucide.Monitor
import com.composables.icons.lucide.MonitorSmartphone
import com.composables.icons.lucide.ScrollText
import com.composables.icons.lucide.Settings
import com.composables.icons.lucide.ShieldCheck
import com.composables.icons.lucide.SlidersHorizontal
import com.composables.icons.lucide.Users

/** 一个底栏/侧栏页签：路由 + miuix 导航项。 */
data class TabSpec(val route: Route, val item: NavigationItem)

/**
 * 控制台五项 / 管理后台六项（super 全量；项目管理员无「用户」「配置中心」——
 * 后端每请求现查授权，前端只是不展示入口）。文案与旧版控制台一致。
 */
object AppTabs {
    fun console(): List<TabSpec> = listOf(
        TabSpec(Route.Console, NavigationItem(LucideHouse, "概览")),
        TabSpec(Route.Sessions, NavigationItem(LucideMonitorSmartphone, "登录会话")),
        TabSpec(Route.Passkeys, NavigationItem(LucideKeyRound, "Passkey")),
        TabSpec(Route.TwoFactor, NavigationItem(LucideShield, "两步验证")),
        TabSpec(Route.Account, NavigationItem(LucideSettings, "账号")),
    )

    fun admin(superAdmin: Boolean): List<TabSpec> {
        val all = listOf(
            TabSpec(Route.AdminUsers, NavigationItem(LucideUsers, "用户")),
            TabSpec(Route.AdminAccess, NavigationItem(LucideLock, "项目访问")),
            TabSpec(Route.AdminSessions, NavigationItem(LucideMonitor, "会话总览")),
            TabSpec(Route.AdminAudit, NavigationItem(LucideScrollText, "审计日志")),
            TabSpec(Route.AdminConfig, NavigationItem(LucideSliders, "配置中心")),
            TabSpec(Route.AdminAi, NavigationItem(LucideChart, "AI 用量")),
        )
        return if (superAdmin) all else all.filter { it.route !in setOf(Route.AdminUsers, Route.AdminConfig) }
    }
}

// 图标别名：Lucide KMP 的实名以编译为准，这里集中一处，改名只动这里。
private val LucideHouse = com.composables.icons.lucide.Lucide.House
private val LucideKeyRound = com.composables.icons.lucide.Lucide.KeyRound
private val LucideMonitorSmartphone = com.composables.icons.lucide.Lucide.MonitorSmartphone
private val LucideShield = com.composables.icons.lucide.Lucide.ShieldCheck
private val LucideSettings = com.composables.icons.lucide.Lucide.Settings
private val LucideUsers = com.composables.icons.lucide.Lucide.Users
private val LucideLock = com.composables.icons.lucide.Lucide.Lock
private val LucideMonitor = com.composables.icons.lucide.Lucide.Monitor
private val LucideScrollText = com.composables.icons.lucide.Lucide.ScrollText
private val LucideSliders = com.composables.icons.lucide.Lucide.SlidersHorizontal
private val LucideChart = com.composables.icons.lucide.Lucide.ChartColumn
