package cn.horatio.authweb

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.ExperimentalComposeUiApi
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.ComposeViewport
import kotlinx.browser.document
import top.yukonga.miuix.kmp.basic.Button
import top.yukonga.miuix.kmp.basic.Card
import top.yukonga.miuix.kmp.basic.Switch
import top.yukonga.miuix.kmp.basic.Text
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
        Box(
            Modifier
                .fillMaxSize()
                .background(MiuixTheme.colorScheme.surface),
            contentAlignment = Alignment.Center,
        ) {
            Card(Modifier.padding(24.dp)) {
                Column(
                    Modifier.fillMaxWidth().padding(20.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    Text("Auth Web · M0", style = MiuixTheme.textStyles.title4)
                    Text(
                        "miuix 0.9.4 on Kotlin/Wasm",
                        style = MiuixTheme.textStyles.subtitle,
                        color = MiuixTheme.colorScheme.onSurfaceSecondary,
                    )
                    Button(onClick = {}, modifier = Modifier.fillMaxWidth()) {
                        Text("主要按钮")
                    }
                    var on by remember { mutableStateOf(true) }
                    Switch(checked = on, onCheckedChange = { on = it })
                }
            }
        }
    }
}
