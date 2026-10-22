package cn.horatio.authweb.shell

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.RectangleShape
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import top.yukonga.miuix.kmp.basic.ScrollBehavior
import top.yukonga.miuix.kmp.basic.SmallTopAppBar
import top.yukonga.miuix.kmp.blur.BlendColorEntry
import top.yukonga.miuix.kmp.blur.BlurColors
import top.yukonga.miuix.kmp.blur.BlurDefaults
import top.yukonga.miuix.kmp.blur.LayerBackdrop
import top.yukonga.miuix.kmp.blur.ProgressiveBlur
import top.yukonga.miuix.kmp.blur.isRuntimeShaderSupported
import top.yukonga.miuix.kmp.blur.progressiveTextureBlur
import top.yukonga.miuix.kmp.blur.rememberLayerBackdrop
import top.yukonga.miuix.kmp.blur.textureBlur
import top.yukonga.miuix.kmp.theme.MiuixTheme
import top.yukonga.miuix.kmp.utils.overScrollVertical
import top.yukonga.miuix.kmp.utils.scrollEndHaptic

// 移植自 calorie-diary PageUtils（miuix 0.9.4 同源工具箱），勿在本仓另起炉灶。

/**
 * 页面滚动链：滚动震动 + 过渡滚动 + 接管顶栏折叠 + 行高铺满。
 * 做成 @Composable 是为了把 [ScrollBehavior.nestedScrollConnection] remember 住——
 * 每次重组都新建连接会让 nestedScroll 节点整体重建并重新布局。
 */
@Composable
fun Modifier.pageScrollModifiers(
    topAppBarScrollBehavior: ScrollBehavior,
): Modifier {
    val connection = remember(topAppBarScrollBehavior) { topAppBarScrollBehavior.nestedScrollConnection }
    return this
        .scrollEndHaptic()
        .overScrollVertical()
        .nestedScroll(connection)
        .fillMaxHeight()
}

@Composable
fun pageContentPadding(
    innerPadding: PaddingValues,
    outerPadding: PaddingValues,
    extraTop: Dp = 16.dp,
    extraStart: Dp = 0.dp,
    extraEnd: Dp = 0.dp,
    extraBottom: Dp = 12.dp,
): PaddingValues {
    val topPadding = innerPadding.calculateTopPadding() + extraTop
    // 底部只取 inner/outer 的较大者：内层 Scaffold 的 inner 底已含系统导航栏与
    // captionBar；主 Tab 页再与外层底栏高度取大即可（叠加即双倍）。
    val bottomPadding = maxOf(
        innerPadding.calculateBottomPadding(),
        outerPadding.calculateBottomPadding(),
    ) + extraBottom

    return remember(topPadding, bottomPadding, extraStart, extraEnd) {
        PaddingValues(
            top = topPadding,
            start = extraStart,
            end = extraEnd,
            bottom = bottomPadding,
        )
    }
}

/** 滚动条边缘避让：精准对齐顶栏与底栏边缘，杜绝悬浮在半空 */
@Composable
fun scrollBarTrackPadding(
    innerPadding: PaddingValues,
    outerPadding: PaddingValues,
): PaddingValues {
    val top = innerPadding.calculateTopPadding()
    val bottom = maxOf(innerPadding.calculateBottomPadding(), outerPadding.calculateBottomPadding())
    return remember(top, bottom) {
        PaddingValues(top = top, bottom = bottom)
    }
}

/**
 * 顶栏：全站统一紧凑 SmallTopAppBar。
 * 恒传 scrollBehavior：传 null 会让 miuix 的 ExitUntilCollapsed 把上滑 delta
 * 全部吞掉（heightOffsetLimit 未被 pin），页面看起来完全滑不动。
 */
@Composable
fun AdaptiveTopAppBar(
    title: String,
    scrollBehavior: ScrollBehavior,
    subtitle: String = "",
    color: Color = MiuixTheme.colorScheme.surface,
    navigationIcon: @Composable () -> Unit = {},
    actions: @Composable RowScope.() -> Unit = {},
    bottomContent: @Composable () -> Unit = {},
) {
    SmallTopAppBar(
        title = title,
        subtitle = subtitle,
        color = color,
        scrollBehavior = scrollBehavior,
        defaultWindowInsetsPadding = false,
        navigationIcon = navigationIcon,
        actions = actions,
        bottomContent = bottomContent,
    )
}

/** 液态玻璃 backdrop。来自 miuix example rememberBlurBackdrop。 */
@Composable
fun rememberBlurBackdrop(): LayerBackdrop? {
    if (!WebUiPrefs.enableBlur) return null
    if (!isRuntimeShaderSupported()) return null
    val surfaceColor = MiuixTheme.colorScheme.surface
    return rememberLayerBackdrop {
        drawRect(surfaceColor)
        drawContent()
    }
}

/**
 * 顶栏模糊容器。结构与参数逐行对齐 miuix example BlurredBar（v0.9.4，commit 39c40f99）——
 * 渐进模糊是 miuix-blur 的原生能力，只接线不改配方：
 * - 常开档：整条 textureBlur(25f) + surface 0.8 混色，不随滚动变化。
 * - 渐进档：progressiveTextureBlur 空间渐进（ProgressiveBlur.Top、curve=2.2f、半径 10f、
 *   surface 0.3 混色），外套随滚动渐显的 alpha（滑满 48dp 即全量）。
 */
@Composable
fun BlurredBar(
    backdrop: LayerBackdrop?,
    blurEnabled: Boolean,
    scrollBehavior: ScrollBehavior? = null,
    progressive: Boolean = WebUiPrefs.progressiveBlur,
    content: @Composable () -> Unit,
) {
    val blurActive = blurEnabled && backdrop != null
    Box(
        modifier = if (blurActive && !progressive) {
            Modifier.textureBlur(
                backdrop = backdrop,
                shape = RectangleShape,
                blurRadius = 25f,
                colors = barBlurColors(),
            )
        } else {
            Modifier
        },
    ) {
        if (blurActive && progressive) {
            Box(
                modifier = Modifier
                    .matchParentSize()
                    .graphicsLayer {
                        alpha = scrollBehavior?.state
                            ?.let { (-it.contentOffset / 48.dp.toPx()).coerceIn(0f, 1f) }
                            ?: 1f
                    }
                    .progressiveTextureBlur(
                        backdrop = backdrop,
                        shape = RectangleShape,
                        gradient = ProgressiveBlur.Top.copy(curve = 2.2f),
                        blurRadius = 10f,
                        colors = barBlurColors(progressive = true),
                    ),
            )
        }
        content()
    }
}

@Composable
private fun barBlurColors(progressive: Boolean = false): BlurColors = BlurDefaults.blurColors(
    blendColors = listOf(
        BlendColorEntry(color = MiuixTheme.colorScheme.surface.copy(if (progressive) 0.3f else 0.8f)),
    ),
)
