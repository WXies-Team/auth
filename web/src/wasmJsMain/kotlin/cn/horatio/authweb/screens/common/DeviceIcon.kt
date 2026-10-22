// 设备类型图标助手：照抄旧前端 internal/ui/app.js 的 DEVICE_ICONS/deviceIcon 映射——
// 移动系统标签出 smartphone、桌面系统标签出 laptop、认不出（脚本/残缺 UA）退回通用
// 设备图标，不猜。正则与 app.js 逐字一致，改判定请同 PR 同步 app.js。
package cn.horatio.authweb.screens.common

import androidx.compose.foundation.layout.size
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.unit.dp
import cn.horatio.authweb.icons.AppIcon
import com.composables.icons.lucide.HardDrive
import com.composables.icons.lucide.Laptop
import com.composables.icons.lucide.Lucide
import com.composables.icons.lucide.Smartphone
import top.yukonga.miuix.kmp.theme.MiuixTheme

/** app.js `DEVICE_ICONS.smartphone`（lucide smartphone）。 */
private val MOBILE_UA = Regex("Android|iPhone|iPad|iOS|Mobile")

/** app.js `DEVICE_ICONS.laptop`（lucide laptop）。 */
private val DESKTOP_UA = Regex("Windows|macOS|Mac OS X|Linux|ChromeOS|Ubuntu")

/**
 * 服务端 UA 解析出的设备标签 → lucide 图标（app.js `deviceIcon` 同式）。
 * 未知态 app.js 用的是已退役的 lucide `device`，本库 2.2.1 无此名，取语义最近的
 * `HardDrive`（通用硬件块），仍是「认不出就给通用件」的不猜策略。
 */
fun deviceIconOf(device: String): ImageVector = when {
    MOBILE_UA.containsMatchIn(device) -> Lucide.Smartphone
    DESKTOP_UA.containsMatchIn(device) -> Lucide.Laptop
    else -> Lucide.HardDrive
}

/** 设置行/会话行统一的设备图标（缺省 20dp 主色，与 [cn.horatio.authweb.component.PrefIcon] 同节奏）。 */
@Composable
fun DeviceIcon(
    device: String,
    modifier: Modifier = Modifier,
    tint: Color = MiuixTheme.colorScheme.primary,
) {
    AppIcon(
        icon = deviceIconOf(device),
        contentDescription = null,
        modifier = modifier.size(20.dp),
        tint = tint,
    )
}
