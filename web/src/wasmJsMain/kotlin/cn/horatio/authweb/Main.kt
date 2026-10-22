package cn.horatio.authweb

import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.ExperimentalComposeUiApi
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.ComposeViewport
import kotlinx.browser.document
import cn.horatio.authweb.shell.AppRoot
import top.yukonga.miuix.kmp.theme.ColorSchemeMode
import top.yukonga.miuix.kmp.theme.MiuixTheme
import top.yukonga.miuix.kmp.theme.ThemeController
import top.yukonga.miuix.kmp.theme.defaultTextStyles

@OptIn(ExperimentalComposeUiApi::class)
fun main() {
    ComposeViewport(document.body ?: error("missing <body>")) {
        App()
    }
}

/** 根：与两个日记 App 同款主题口径（ThemeController 跟随系统 + 默认字阶）。 */
@Composable
private fun App() {
    val controller = remember { ThemeController(ColorSchemeMode.System) }
    val textStyles = remember { defaultTextStyles() }
    MiuixTheme(controller = controller, textStyles = textStyles) {
        AppRoot()
    }
}
