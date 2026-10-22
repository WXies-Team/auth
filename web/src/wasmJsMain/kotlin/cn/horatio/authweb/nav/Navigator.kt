package cn.horatio.authweb.nav

import top.yukonga.miuix.kmp.nav.core.NavBackStack
import top.yukonga.miuix.kmp.nav.core.NavKey

/** 与日记 App 同款的薄 Navigator：push 去重、pop 守 size>1、popUntil 清栈。 */
class Navigator(
    val backStack: NavBackStack,
) {
    fun push(key: NavKey) {
        if (key !in backStack) {
            backStack.add(key)
        }
    }

    fun pop() {
        if (backStack.size > 1) {
            backStack.removeLastOrNull()
        }
    }

    fun popUntil(predicate: (NavKey) -> Boolean) {
        while (backStack.size > 1 && !predicate(backStack.last())) {
            backStack.removeAt(backStack.lastIndex)
        }
    }

    fun replaceAll(vararg keys: NavKey) {
        backStack.clear()
        backStack.addAll(keys)
    }

    fun current() = backStack.lastOrNull()

    fun backStackSize() = backStack.size
}
