package cn.horatio.authweb.shell

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.theme.MiuixTheme

/** 骨架期占位屏：M1-M3 逐页替换成真页面。 */
@Composable
fun PlaceholderScreen(title: String) {
    ScreenScaffold(title = title) {
        Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
            Text(
                text = title,
                color = MiuixTheme.colorScheme.onSurfaceSecondary,
            )
        }
    }
}
