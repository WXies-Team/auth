// 移植自 calorie-diary（miuix 0.9.4 同源工具箱），勿在本仓另起炉灶
package cn.horatio.authweb.component

import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import cn.horatio.authweb.theme.isInDarkTheme
import top.yukonga.miuix.kmp.theme.MiuixTheme

/**
 * miuix [top.yukonga.miuix.kmp.basic.SmallTitle] 的对比度收口包装（同包 PrefIcon 模式）。
 *
 * 组件缺省 `textColor = onBackgroundVariant`，压页面底不达 14sp subtitle 的 4.5:1 门槛：
 * 浅 #8C93B0 压 surface #F7F7F7 只有 **2.83:1**；深 #787E96 压页面底 #242424 实测
 * **3.86:1** 同样不达标（任务书按「深底达标」给的，实测不成立，故深色也不沿用）。
 * miuix 只给 `textColor` 参数、没有达标的缺省值，缺省因此在这里换成达标值——
 * **硬指标压过组件库缺省**；2026-10-10 起两态都走**主题 token**（动态颜色全 app 适配，
 * 原浅色固定 #5A6070 在壁纸取色下不跟色）：
 *  - 浅色 `onSurface.copy(alpha = 0.7f)`：压 #F7F7F7 ≈ **6.0** / 白卡更高，全 ≥4.5；
 *  - 深色 `onSurfaceSecondary`（80% 白）：压深页底 #242424 **10.37** / 卡底 #434343 **7.01**。
 *
 * 调用点显式传 `textColor` 时按显式值走（显式优先），签名与 miuix 逐参对齐。
 */
@Composable
fun SmallTitle(
    text: String,
    modifier: Modifier = Modifier,
    textColor: Color = if (isInDarkTheme()) {
        MiuixTheme.colorScheme.onSurfaceSecondary
    } else {
        MiuixTheme.colorScheme.onSurface.copy(alpha = 0.7f)
    },
    insideMargin: PaddingValues = top.yukonga.miuix.kmp.basic.SmallTitleDefaults.InsideMargin,
) {
    top.yukonga.miuix.kmp.basic.SmallTitle(
        text = text,
        modifier = modifier,
        textColor = textColor,
        insideMargin = insideMargin,
    )
}
