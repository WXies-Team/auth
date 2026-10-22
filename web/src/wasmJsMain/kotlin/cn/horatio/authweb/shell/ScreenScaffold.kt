package cn.horatio.authweb.shell

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.compositionLocalOf
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.RectangleShape
import top.yukonga.miuix.kmp.basic.MiuixScrollBehavior
import top.yukonga.miuix.kmp.basic.Scaffold
import top.yukonga.miuix.kmp.basic.ScrollBehavior
import top.yukonga.miuix.kmp.blur.LayerBackdrop
import top.yukonga.miuix.kmp.blur.isRuntimeShaderSupported
import top.yukonga.miuix.kmp.blur.layerBackdrop
import top.yukonga.miuix.kmp.blur.rememberLayerBackdrop
import top.yukonga.miuix.kmp.theme.MiuixTheme

// 移植自 calorie-diary（miuix 0.9.4 同源工具箱），勿在本仓另起炉灶。

/** 当前页面的液态玻璃 backdrop 源（AppRoot 提供；null=玻璃关）。 */
val LocalPageBackdrop = compositionLocalOf<LayerBackdrop?> { null }

/** 全局 snackbar 状态（AppRoot 提供单例，与日记 App 同款防重复吐司策略）。 */
val LocalSnackbarHostState = compositionLocalOf { top.yukonga.miuix.kmp.basic.SnackbarHostState() }

/**
 * 全站页面统一配方（日记 App 每屏的 Scaffold + BlurredBar + layerBackdrop 收口）：
 * 屏自己只写内容，顶栏模糊/折叠、内容作为玻璃 backdrop 源都在这里接线。
 *
 * 恒传 [scrollBehavior]：传 null 会让 miuix 的 ExitUntilCollapsed 吞掉上滑 delta。
 */
@Composable
fun ScreenScaffold(
    title: String,
    subtitle: String = "",
    scrollBehavior: ScrollBehavior = MiuixScrollBehavior(),
    navigationIcon: @Composable () -> Unit = {},
    actions: @Composable RowScope.() -> Unit = {},
    bottomContent: @Composable () -> Unit = {},
    content: @Composable (PaddingValues) -> Unit,
) {
    val backdrop = LocalPageBackdrop.current
    val blurActive = backdrop != null && WebUiPrefs.enableBlur
    Scaffold(
        topBar = {
            BlurredBar(backdrop = backdrop, blurEnabled = blurActive, scrollBehavior = scrollBehavior) {
                AdaptiveTopAppBar(
                    title = title,
                    subtitle = subtitle,
                    scrollBehavior = scrollBehavior,
                    color = if (blurActive) Color.Transparent else MiuixTheme.colorScheme.surface,
                    navigationIcon = navigationIcon,
                    actions = actions,
                    bottomContent = bottomContent,
                )
            }
        },
    ) { innerPadding ->
        Box(
            Modifier
                .fillMaxSize()
                .then(if (backdrop != null) Modifier.layerBackdrop(backdrop) else Modifier),
        ) {
            content(innerPadding)
        }
    }
}

/** App 级玻璃 backdrop（页面底色先画再 drawContent，供顶栏/底栏取样）。 */
@Composable
fun rememberAppBackdrop(): LayerBackdrop? {
    if (!WebUiPrefs.enableBlur) return null
    if (!isRuntimeShaderSupported()) return null
    val surfaceColor = MiuixTheme.colorScheme.surface
    return rememberLayerBackdrop {
        drawRect(surfaceColor)
        drawContent()
    }
}
