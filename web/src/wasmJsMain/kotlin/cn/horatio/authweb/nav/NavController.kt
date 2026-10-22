package cn.horatio.authweb.nav

import kotlinx.browser.window

/**
 * 面向页面的导航门面：所有程序化跳转都走这里，保证浏览器历史与导航栈同步。
 * 页面拿 [push]/[back]，不要直接摸 Navigator/HistoryBridge。
 */
class NavController(private val navigator: Navigator) {
    fun push(route: Route) {
        HistoryBridge.push(navigator, route)
    }

    /** 返回：有上一页就还给浏览器（popstate 弹栈），单条目深链栈退无可退。 */
    fun back() {
        if (navigator.backStackSize() > 1) window.history.back() else navigator.pop()
    }

    /** 分区页签切换：不叠历史条目（tab 不是「进入下一页」），直达即换顶。 */
    fun switchSection(tabs: List<cn.horatio.authweb.shell.TabSpec>, index: Int) {
        val target = tabs.getOrNull(index)?.route ?: return
        if (navigator.current() == target) return
        HistoryBridge.replace(navigator, target)
    }
}
