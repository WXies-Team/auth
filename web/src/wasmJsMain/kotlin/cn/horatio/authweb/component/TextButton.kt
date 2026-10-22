// 移植自 calorie-diary（miuix 0.9.4 同源工具箱），勿在本仓另起炉灶
package cn.horatio.authweb.component

import androidx.compose.foundation.Indication
import androidx.compose.foundation.LocalIndication
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import top.yukonga.miuix.kmp.basic.Button
import top.yukonga.miuix.kmp.basic.ButtonColors
import top.yukonga.miuix.kmp.basic.ButtonDefaults
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.basic.TextButtonColors
import top.yukonga.miuix.kmp.theme.MiuixTheme

/**
 * 全仓统一的单行 TextButton——**与 miuix `TextButton` 同名同签名**，
 * 调用方只需把 import 从 `top.yukonga.miuix.kmp.basic.TextButton` 换成本类，
 * 所有调用点行为不变、外加「文字永不换行」这条全局保证。
 *
 * 为什么需要：miuix TextButton 内部直接 `Text(text, style)`，不暴露
 * `maxLines`/`softWrap`/`overflow`（Text 本身支持但按钮 API 收不到）——
 * 窄槽位里的长文案会折成两行（两行导致按钮高度与同行邻按钮错位）。
 * 用户要求全 App 按钮一律不换行；已知的两处超长（通道切换倒计时、
 * 引导页底栏跳过按钮）已各自专项修复（改文案/倒计时移正文），
 * 本组件兜住其余一切：超长即省略号截断，不再折行。
 *
 * 超长时用 `Ellipsis` 截断而不是裁半个字：截断至少是可读的省略号，
 * 而且这类超长本来就该改文案或改布局（本组件只兜底、不解决文案本身过长）。
 *
 * 与 miuix 的唯一差异就是 Text 的三个参数，其余签名逐参数对齐 0.9.4 源码，
 * 升级 miuix 时对照 Button.kt 同步。
 */
@Composable
fun TextButton(
    text: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
    cornerRadius: Dp = ButtonDefaults.CornerRadius,
    minWidth: Dp = ButtonDefaults.MinWidth,
    minHeight: Dp = ButtonDefaults.MinHeight,
    colors: TextButtonColors = ButtonDefaults.textButtonColors(),
    insideMargin: PaddingValues = ButtonDefaults.InsideMargin,
    textStyle: TextStyle? = null,
    interactionSource: MutableInteractionSource? = null,
    indication: Indication? = LocalIndication.current,
) {
    // 与 miuix TextButton 同款颜色映射：TextButtonColors → ButtonColors
    val mappedColors = remember(colors) {
        ButtonColors(
            color = colors.color,
            disabledColor = colors.disabledColor,
            contentColor = colors.textColor,
            disabledContentColor = colors.disabledTextColor,
        )
    }
    Button(
        onClick = onClick,
        modifier = modifier,
        enabled = enabled,
        cornerRadius = cornerRadius,
        minWidth = minWidth,
        minHeight = minHeight,
        colors = mappedColors,
        insideMargin = insideMargin,
        interactionSource = interactionSource,
        indication = indication,
    ) {
        Text(
            text = text,
            style = textStyle ?: MiuixTheme.textStyles.button,
            // 全仓按钮不换行的落点（同 miuix 源码的其余部分）
            maxLines = 1,
            softWrap = false,
            overflow = TextOverflow.Ellipsis,
        )
    }
}
