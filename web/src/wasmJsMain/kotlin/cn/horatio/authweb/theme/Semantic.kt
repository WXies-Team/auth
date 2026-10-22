// 移植自 calorie-diary（miuix 0.9.4 同源工具箱），勿在本仓另起炉灶
package cn.horatio.authweb.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.Immutable
import androidx.compose.ui.graphics.Color

/**
 * auth web 移植：原 App 的 [isInDarkTheme] 按 LocalColorMode 三态（跟随系统/强制浅/强制深）
 * 判明暗；auth web 无该设置项，直接跟随系统。
 */
@Composable
fun isInDarkTheme(): Boolean = isSystemInDarkTheme()

/** 状态语义色彩模型：达成 / 注意 / 超标 / 信息 */
@Immutable
data class AppStatusColors(
    val success: Color,
    val warning: Color,
    val danger: Color,
    val info: Color,
)

/**
 * 全站状态四色（2026-10-15 作者拍板：**固定一套、不随明暗与自定义色 harmonize**；
 * 2026-10-16 作者拍板把 success/info 同色相压暗一档回白底 AA——单套色白黑双 4.5:1 的
 * 亮度窗仅 L∈[0.175,0.183]，四值全部贴窗取值）。危险按钮的白字对比仍由
 * lockWhiteContrast 动态守；卡底可读变体见 [OnCardColors]。
 */
val FixedStatusColors = AppStatusColors(
    success = Color(0xFF1E8844),
    warning = Color(0xFFAE6400),
    danger = Color(0xFFD63A45),
    info = Color(0xFF3474D8),
)

val LightStatusColors = FixedStatusColors
/** 深浅同套（分家已退役）：旧 Dark 引用点（分享图等）拿到的就是固定值 */
val DarkStatusColors = FixedStatusColors

/**
 * secondaryContainer 卡底（浅 #F0F0F0 / 深 #434343）上的**可读语义色变体**。
 * [LightStatusColors]/[DarkStatusColors] 那组按白/黑页面底校准，压卡底只有
 * 2.09~4.15:1 不达 AA——卡底上的文字与图标走这里；**页面底红字**（`InlineError`、就地
 * 红字，#F7F7F7 上原色仅 4.23）也复用这一对：值按更深的卡底校准，压更亮的页面底只升不降。
 * 值经 WCAG 实测：
 * primary 浅 #1F64C8=4.96 / 深 #7FB3F5=4.56（压卡底）；danger 沿用 AiAdviceCard
 * 既有处方（浅 #C82333=4.92 / 深 #FF9489=4.64）。
 */
object OnCardColors {
    val primary: Color
        @Composable get() = if (isInDarkTheme()) Color(0xFF7FB3F5) else Color(0xFF1F64C8)

    val danger: Color
        @Composable get() = if (isInDarkTheme()) Color(0xFFFF9489) else Color(0xFFC82333)

    // 2026-10-16 审计 P2-2 补齐：StatusChip 卡底用例要求传 OnCardColors，但 success/warning/info
    // 缺组，调用点（断食 PlanBadge、体重 BMI chip）只能拿按页面底校准的原色——压深卡
    // #242424 仅 3.4~3.6:1。值经 WCAG 实测：浅色按浅卡 #F0F0F0 校准（4.55~4.87），
    // 深色按深卡 #242424 校准（7.5~8.0，压更暗的 secondaryContainer 只升不降）
    val success: Color
        @Composable get() = if (isInDarkTheme()) Color(0xFF5FCF8B) else Color(0xFF1A7D3E)

    val warning: Color
        @Composable get() = if (isInDarkTheme()) Color(0xFFE8A94F) else Color(0xFF9E5600)

    val info: Color
        @Composable get() = if (isInDarkTheme()) Color(0xFF92B8F5) else Color(0xFF2E68CC)
}

/** 状态语义色统一访问入口：固定值（2026-10-15 作者拍板不随明暗/自定义色） */
object StatusColors {
    val success: Color get() = FixedStatusColors.success
    val warning: Color get() = FixedStatusColors.warning
    val danger: Color get() = FixedStatusColors.danger
    val info: Color get() = FixedStatusColors.info
}

/**
 * 正文级「链接/强调」蓝：≤17sp 的 primary **文字**专用（去记录、忘记密码、倒计时提示、
 * 许可标签等）。`colorScheme.primary` 浅 #3482FF 压白卡仅 3.63:1、深 #277AF7 压暗卡
 * #242424 仅 3.85:1，不达 WCAG AA「≤17pt 文字 4.5:1」；
 * Monet 动态取色下 primary 由壁纸生成、对比更不可控，故本值**固定双模式**（同色相
 * 压深/提亮），不读 colorScheme。
 *
 * 取值按全仓最差底面算：
 *  - 浅 #1363D6（lum 0.1392）：白卡 5.55 / surface #F7F7F7 5.18 / secondaryContainer
 *    #F0F0F0 4.87 / 许可卡 primaryContainer@20%（lum 0.811）4.55 —— 全部 ≥4.5；
 *  - 深 #66A3FF（lum 0.3624）：暗卡 #242424 6.10 / 纯黑 8.25 / 许可卡
 *    primaryContainer@20%（lum 0.038）4.68 —— 全部 ≥4.5。
 *
 * 只管文字：图标/描边/图表线走 3:1 图形门槛，继续用 colorScheme.primary（3.63≥3 达标）。
 */
val PrimaryText: Color
    @Composable get() = if (isInDarkTheme()) Color(0xFF66A3FF) else Color(0xFF1363D6)
