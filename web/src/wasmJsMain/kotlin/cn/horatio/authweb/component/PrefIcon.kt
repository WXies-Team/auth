// 移植自 calorie-diary（miuix 0.9.4 同源工具箱），勿在本仓另起炉灶
package cn.horatio.authweb.component

import androidx.compose.foundation.layout.size
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.unit.dp
import cn.horatio.authweb.icons.AppIcon
import top.yukonga.miuix.kmp.theme.MiuixTheme

/**
 * 设置行统一图标：20dp 主色。
 * BasicComponent 内置了图标与标题之间 8dp 间距，此处不再额外加 padding，
 * 保证所有设置卡片的图标节奏一致。
 */
@Composable
fun PrefIcon(
    icon: ImageVector,
    tint: Color = MiuixTheme.colorScheme.primary,
    contentDescription: String? = null,
) {
    AppIcon(
        icon = icon,
        contentDescription = contentDescription,
        modifier = Modifier.size(20.dp),
        tint = tint,
    )
}
