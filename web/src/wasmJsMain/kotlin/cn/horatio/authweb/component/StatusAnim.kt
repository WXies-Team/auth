// 移植自 calorie-diary（miuix 0.9.4 同源工具箱），勿在本仓另起炉灶
package cn.horatio.authweb.component

import androidx.compose.animation.ContentTransform
import androidx.compose.animation.EnterTransition
import androidx.compose.animation.ExitTransition
import androidx.compose.animation.core.MutableTransitionState
import androidx.compose.animation.expandHorizontally
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.animation.shrinkHorizontally
import androidx.compose.animation.shrinkVertically
import androidx.compose.animation.slideInHorizontally
import androidx.compose.animation.slideOutHorizontally
import androidx.compose.animation.togetherWith

/**
 * 状态块进出场（全仓统一）：规格收口在 [statusSpring]（档位一，见 `AnimSpec.kt`）——
 * folme 弹簧 damping 0.95 / response 0.35，对齐 miuix 内部件弹簧量级，收敛快、无可见回弹。
 * 抽成共享值是为消灭「fadeIn+expand / fadeOut+shrink」四行块的多处复制。
 *
 * 动效规格与豁免清单的唯一来源是 **`AnimSpec.kt`**，本文件只负责把它们组合成进出场。
 */
internal val StatusAnimEnter: EnterTransition =
    fadeIn(statusSpring()) +
        expandVertically(animationSpec = statusSpring())

internal val StatusAnimExit: ExitTransition =
    fadeOut(statusSpring()) +
        shrinkVertically(animationSpec = statusSpring())

/**
 * 勾选框进出场（横向，与 [StatusAnimEnter] 同一弹簧）：
 * 多选态出勾时行内容要**跟着让位**——直接插一个 Checkbox 进来，
 * 右侧文字会瞬移一下（用户反馈「勾出来时文案跳」）。
 */
internal val CheckAnimEnter: EnterTransition =
    // 展开揭示的硬边会把圆圈右半先切掉再补上（2026-10-15/10-17 作者两轮报「右边会被
    // 截断」，延后淡入只是把截断藏进 alpha≈0 时段、弹簧拖尾一长还是会露）：
    // clip=false 让展开期不裁剪内容——圆圈从第一帧就完整，宽度动画只负责行让位，
    // 观感=勾选框淡入的同时文字滑开，没有任何切边
    expandHorizontally(animationSpec = statusSpring(), clip = false) +
        fadeIn(animationSpec = statusSpring())

internal val CheckAnimExit: ExitTransition =
    fadeOut(statusSpring()) +
        shrinkHorizontally(animationSpec = statusSpring())

/**
 * 同位置换词的交叉淡入淡出（与 [StatusAnimEnter] 同一弹簧量级）：
 * 标签/标题这类「今日↔当日」的纯文案切换用它——此前 5 处各自抄
 * `fadeIn(folmeSpring)+fadeOut(folmeSpring)`，违反动效准则的「收口」要求。
 */
internal val FadeAnimEnter: EnterTransition = fadeIn(statusSpring())

internal val FadeAnimExit: ExitTransition = fadeOut(statusSpring())

/**
 * 「首装 Fade 进场」的 visibleState 收口（2026-10-16 审计 P2-16：今日/体重/断食用
 * MutableTransitionState(false) 起手、喝水页用 remember+LaunchedEffect 两套写法并存）。
 * false 起手才能让 AnimatedVisibility 播 enter（写死 true 是死动画），首个组合周期翻真。
 */
@Composable
fun rememberFirstEnterState(): MutableTransitionState<Boolean> =
    remember { MutableTransitionState(false) }.apply { targetState = true }

/**
 * [slideByDirSpec] 的 Int 重载（步数/档位这类数值 target 也走同一套方向判定）。
 */
internal fun slideByDirSpec(initialState: Int, targetState: Int): ContentTransform =
    // 数值比较：toString 后走的是字典序，9→10 会被判成往回翻
    slideByDirSpecByDir(if (targetState < initialState) -1 else 1)

private fun slideByDirSpecByDir(dir: Int): ContentTransform =
    // 位移也必须显式给规格：`slideInHorizontally` 的缺省是 spring(1.0, 1500)（~170ms 收敛），
    // 与淡入的 folme（~270ms）不同根，物体会「先落位、再浮现」两段式——统一到档位一
    (slideInHorizontally(animationSpec = statusSpring(), initialOffsetX = { it / 3 * dir }) +
        fadeIn(statusSpring())) togetherWith
        (slideOutHorizontally(animationSpec = statusSpring(), targetOffsetX = { -it / 3 * dir }) +
            fadeOut(statusSpring()))

/**
 * 切期/切档的**方向感知滑动**规格（全仓统一收口）：往前翻（串变小）内容向左滑出、
 * 往后翻向右，位移 1/3 宽 + 与 [StatusAnimEnter] 同一 folme 弹簧淡入淡出。
 *
 * 此前同一准则三种手感：三历史页用 folme 淡、今日页与日期胶囊用默认 tween 300ms 淡、
 * 周报干脆没有方向（审计 P1）；targetState 传「粒度|锚」复合串——纯锚在跨粒度时
 * 字典序与时间序会错位、方向失真。
 *
 * 进出场方向对称（进来往里推、出去往回退）——反馈动效要与手势和预期一致（本仓动效
 * 准则）；退场走另一个方向会让人以为换了个手势。
 */
internal fun slideByDirSpec(initialState: String, targetState: String): ContentTransform {
    val dir = if (targetState < initialState) -1 else 1
    return (slideInHorizontally(animationSpec = statusSpring(), initialOffsetX = { it / 3 * dir }) +
        fadeIn(statusSpring())) togetherWith
        (slideOutHorizontally(animationSpec = statusSpring(), targetOffsetX = { -it / 3 * dir }) +
            fadeOut(statusSpring()))
}
