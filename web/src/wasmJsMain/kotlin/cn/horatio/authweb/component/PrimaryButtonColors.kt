// 移植自 calorie-diary（miuix 0.9.4 同源工具箱），勿在本仓另起炉灶
package cn.horatio.authweb.component

import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.graphics.Color
import top.yukonga.miuix.kmp.basic.ButtonColors
import top.yukonga.miuix.kmp.basic.ButtonDefaults
import top.yukonga.miuix.kmp.basic.TextButtonColors
import top.yukonga.miuix.kmp.theme.MiuixTheme
import kotlin.math.pow

/**
 * 主按钮（填充）白字对比度配方——与 [textButtonColorsDanger]/[buttonColorsDanger] 同思路。
 *
 * 为什么不直接用官方/miuix 缺省 primary：miuix `primary #3482FF` 压白字只有 **3.63:1**，
 * 17sp 按钮字不达 WCAG AA「≤17pt 文字 4.5:1」（无 3:1 大字豁免）。
 *
 * **2026-10-10 动态色适配拍板**：底色从固定一支蓝（#2870DC，2026-10-09 审计取值）改为
 * 「**主题色相 + 白字对比护栏**」——色相取自 `MiuixTheme.colorScheme.primary`（Monet 下
 * 随壁纸走），亮度按 WCAG 相对亮度迭代乘深直到白字 ≥4.5:1（理论界限 lum ≤0.18333；
 * 缺省 #3482FF 压 3 级后落点 ≈4.7:1，与原审计取值同量级）。原审计的核心约束——
 * **对比度锁死白字配对**——原样保留，只有色相从「固定」改成「跟主题」。
 *
 * 态样式（读 0.9.4 `Button.kt` 源码）：enabled 只有 color/contentColor 一对，**无
 * pressed 颜色态**（按压反馈全走 indication/Sink，不涉及颜色）；disabled 沿用官方
 * `disabledPrimaryButton`/`disabledOnPrimaryButton`（WCAG 1.4.3 明确豁免失效组件，
 * 不另行压深）。
 * 文字色仍写死 `Color.White`：对比度由护栏锁死，读 Monet 的 onPrimary 反而可能配错对。
 */

/**
 * 把颜色压到「白字 ≥4.5:1」为止：WCAG 相对亮度迭代乘深（RGB 同倍率缩放保色相），
 * 达标即原样返回；上限 40 次（0.94^40 ≈ 0.084，纯白也能压到达标）。
 */
internal fun lockWhiteContrast(color: Color): Color {
    fun lin(v: Float): Float =
        if (v <= 0.03928f) v / 12.92f else ((v + 0.055f) / 1.055f).pow(2.4f)
    fun lum(c: Color): Float =
        0.2126f * lin(c.red) + 0.7152f * lin(c.green) + 0.0722f * lin(c.blue)
    var r = color.red
    var g = color.green
    var b = color.blue
    var guard = 0
    while (guard < 40 && 1.05f / (lum(Color(r, g, b)) + 0.05f) < 4.5f) {
        r *= 0.94f; g *= 0.94f; b *= 0.94f; guard++
    }
    return if (guard == 0) color else Color(r, g, b, color.alpha)
}

/** 主按钮填充底：主题色相（动态颜色跟随）+ 白字 4.5:1 护栏（见类注释）。 */
@Composable
fun primaryButtonFill(): Color {
    // CompositionLocal 必须在组合上下文读出再进 remember（lambda 非组合作用域）
    val primary = MiuixTheme.colorScheme.primary
    return remember(primary) { lockWhiteContrast(primary) }
}

/** [buttonColorsPrimaryApp] 的 Button 版。 */
@Composable
fun buttonColorsPrimaryApp(): ButtonColors = ButtonDefaults.buttonColors(
    color = primaryButtonFill(),
    disabledColor = MiuixTheme.colorScheme.disabledPrimaryButton,
    contentColor = Color.White,
    disabledContentColor = MiuixTheme.colorScheme.disabledOnPrimaryButton,
)

/** [buttonColorsPrimaryApp] 的 TextButton 版（替换 `textButtonColorsPrimary()`）。 */
@Composable
fun textButtonColorsPrimaryApp(): TextButtonColors = ButtonDefaults.textButtonColors(
    color = primaryButtonFill(),
    disabledColor = MiuixTheme.colorScheme.disabledPrimaryButton,
    textColor = Color.White,
    disabledTextColor = MiuixTheme.colorScheme.disabledOnPrimaryButton,
)
