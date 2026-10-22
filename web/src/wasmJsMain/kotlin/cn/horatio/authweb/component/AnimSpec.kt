// 移植自 calorie-diary（miuix 0.9.4 同源工具箱），勿在本仓另起炉灶
/**
 * 全仓动效规格的**唯一来源**（2026-10-08「全 App 动画统一」批收口）。
 *
 * 本文件之前，同一个手势在仓库里有四种写法：`StatusAnim.kt` 的 `folmeSpring(0.95, 0.35)`、
 * 11 处行内 `tween(200)`、`animateContentSize()`/`animateItem()` 吃 Compose 默认
 * `spring(1.0, 400)`、两张图表各写各的 500/550ms——数值碰巧接近所以没人看出来，
 * 但只要改一个就得改 N 处，且没人说得清「全仓动效到底是哪一套」。
 * 现在凡本仓库**显式调用**的动画 API，spec 一律取自本文件；组件内部不再写裸
 * `tween(...)` / `spring(...)` / `folmeSpring(...)`。
 *
 * ## 依据（miuix 是唯一设计判据；miuix 未规定处为本项目自选）
 *
 * 本仓动效准则（与 miuix 的交互取向一致，逐条落到本文件）：
 *
 * - 可中断：位移/尺寸走 spring（Compose 的 spring 保速度连续、可被下一次手势打断），
 *   不走固定时长的 tween。
 * - 短而准：按压与状态切换控制在 200~350ms 这一量级，不为好看而拉长。
 * - 克制：不给高频交互加装饰动画，能不加就不加。
 * - 动画不能是唯一的信息通道：重要信息必须有文本/触觉兜底。
 * - 一致：全仓同一套 spec、交互行为可预期——即本文件存在的理由。
 *
 * 分档的实际依据：
 * - **状态弹簧**取 miuix 的 `folmeSpring`（Folme 语义，`stiffness = (2π/response)²`），
 *   0.95/0.35 正是 miuix 自己 `MiuixIndication.PressExitSpring` 的同一组参数——
 *   页面里的状态块与 miuix 内建按压反馈同一根弹簧。damping 0.95 的过冲约 0.007%，
 *   肉眼无回弹（阻尼本身就是为了**不**回弹，与准则的克制取向同向）。
 * - **颜色/透明度/描边**用 200ms tween 而非弹簧：颜色越过目标值就是错的，tween 天生
 *   收敛到目标即停——miuix 同类实现也一律 tween（TabRow 指示器 200ms、PullToRefresh
 *   200ms、TopAppBar 标题色 50ms、弹层内容 alpha 进 200/出 150）。
 * - **页面级横滑**比状态弹簧慢一档（~450ms vs ~270ms）：miuix 没有给页面转场数值，
 *   这是本项目认为整页位移需要重量感而自选的值。
 *
 * **豁免（刻意不并入本文件，改前先读 AGENTS.md §3 的 miuix 单一规范条款）**：
 * - `ui/component/liquid/`、`ui/component/animation/`（DampedDrag / InteractiveHighlight）：
 *   拖拽与按压的**物理**参数，照上游 AndroidLiquidGlass 2.0.1 定参，改了手感就坏；
 * - `ui/component/effect/`：关于页流体背景的循环动效，属背景材质不属于状态切换；
 * - `AnimatedContent` 内部的内容尺寸插值（`SizeTransform`）：**本仓库根本不调用它**，那是这个
 *   composable 自己的内部行为，走 Compose 默认 `spring(1.0, 400)`（与状态弹簧差 11% 时长，
 *   不可感知）。⚠️ 这与上文「`animateItem` 三个 spec 一个都不能省」**不矛盾——分界是
 *   「调没调」**：显式调用的 API，选参数就是调用方的责任，缺省等于把手感交给库；没调的
 *   库内默认归库。真要覆盖它得在 105 个 `AnimatedContent` 调用点逐个补 `sizeTransform`，
 *   拿不可感知的 11% 换 105 处改动，不划算；
 * - miuix 库内建动画（弹窗/底部弹层/TabRow/Switch/NavigationRail/`SinkFeedback`）
 *   与页面转场 `NavTransitions.MiuixDefault`：库的职责，不覆写。
 *
 * **系统减弱动效（Reduce Motion）——由平台兜底，仅自驱动帧循环加闸**。
 * 落到 Android 上：`WindowRecomposer` 把系统 `ANIMATOR_DURATION_SCALE` 注入
 * `MotionDurationScale`（androidx issue 265177763），系统「移除动画」时 Compose **全部
 * 动画收进下一帧**（官方 API 原文：「When the duration scaleFactor is 0, the motion will
 * end in the next frame callback.」）。方向滑既然已被塌成瞬时，就**没有轴向切换需要另行处理**——
 * 「轴向位移改淡入」这类处方在这台设备上没有可观测落点，加 `slideByDirSpec` 分支只会产出
 * 永远测不到的代码。⚠️ 此处早先记的「方向滑改 Fade 未实现、单独一批」是判断错误，已按
 * 平台实际行为改写（2026-10-08）。
 *
 * **唯一例外（2026-10-11 审计 m9）**：`while(true){withFrameNanos}` / `while(isActive)`
 * 这类**自驱动帧循环**不经过 `animate*` API，`MotionDurationScale` 管不到——`WaterScreen`
 * 水面波纹、`BgEffectBackground` 换色与 AI 正文揭示的 `delay` 循环（`rememberAiReveal`）
 * 三处已加显式闸门（scaleFactor≤0 时跳到终态），这是本仓仅有的三处 Reduce Motion 分支；
 * 其余动画仍由平台兜底。
 *
 * auth web 移植：Wasm 目前无 Reduce Motion 兜底（浏览器无 MotionDurationScale 注入），
 * 自驱动帧循环落点（`rememberAiReveal` 等）接入时需自带闸门。
 */
package cn.horatio.authweb.component

import androidx.compose.animation.core.InfiniteRepeatableSpec
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.SpringSpec
import androidx.compose.animation.core.TweenSpec
import androidx.compose.animation.core.VisibilityThreshold
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.spring
import androidx.compose.animation.core.tween
import androidx.compose.ui.unit.IntOffset
import androidx.compose.ui.unit.IntSize
import top.yukonga.miuix.kmp.anim.folmeSpring

// ── 档位一 · 状态弹簧：元素进出场 / 展开收起 / 交叉淡入 / 方向滑 / 列表项 / 尺寸 ────────

/** 弹簧阻尼：0.95 = miuix `MiuixIndication.PressExitSpring` 同值，过冲肉眼不可见。 */
internal const val STATUS_SPRING_DAMPING = 0.95f

/** 弹簧响应（秒）：`folmeSpring` 换算 stiffness = (2π/0.35)² ≈ 322，实测收敛 ~270ms。 */
internal const val STATUS_SPRING_RESPONSE = 0.35f

/**
 * 全仓状态弹簧。T 由期望类型推断（`fadeIn` → Float、`expandVertically` → IntSize、
 * `slideInHorizontally` → IntOffset），阈值默认 `null`——与 StatusAnim 历史行为逐位一致。
 *
 * 需要显式阈值的只有尺寸/位移两处（不给阈值 spring 的收敛判据会退化），照 Compose 自家
 * `animateContentSize`/`animateItem` 的默认阈值传。
 */
internal fun <T> statusSpring(visibilityThreshold: T? = null): SpringSpec<T> =
    folmeSpring(
        damping = STATUS_SPRING_DAMPING,
        response = STATUS_SPRING_RESPONSE,
        visibilityThreshold = visibilityThreshold,
    )

/** `animateContentSize` 的规格：容器高度收口用状态弹簧 + Compose 默认的 1px 尺寸阈值。 */
internal val ContentSizeSpec: SpringSpec<IntSize> = statusSpring(IntSize.VisibilityThreshold)

/** lazy 列表项位移（`animateItem.placementSpec`）：同上，阈值取 Compose 默认的 1px 偏移。 */
internal val ItemPlacementSpec: SpringSpec<IntOffset> = statusSpring(IntOffset.VisibilityThreshold)

/** lazy 列表项淡入淡出（`animateItem.fadeInSpec`/`fadeOutSpec`）：与状态进出场同一根弹簧。 */
internal val ItemFadeSpec: SpringSpec<Float> = statusSpring()

/**
 * 整页横滑（今日↔体重↔喝水↔我的 的 pager 寻址滚动）：比状态弹簧慢一档的 spring。
 * 数值是本项目自选——miuix 没有给页面转场的时长；只有 `MainPagerState.animateToPage` 用。
 */
internal val PageSlideSpring: SpringSpec<Float> =
    spring(
        dampingRatio = Spring.DampingRatioNoBouncy,
        stiffness = Spring.StiffnessLow,
    )

// ── 档位二 · 状态量 tween：颜色 / 透明度 / 描边宽度（不许过冲的量） ─────────────────────

/** 状态量切换时长：200ms（对齐 miuix 同类 tween：TabRow/PullToRefresh 均 200ms）。 */
internal const val STATE_TWEEN_MS = 200

/**
 * 状态量切换的统一规格。T 由期望类型推断，同一份参数服务
 * `animateColorAsState` / `animateDpAsState` / `animateFloatAsState` 三种调用。
 * 为什么不用弹簧：颜色与透明度超过目标值就是错的（miuix 对这类量也一律 tween，见上），
 * 而 tween 天生收敛到目标即停。
 */
internal fun <T> stateTween(): TweenSpec<T> = tween(durationMillis = STATE_TWEEN_MS)

// ── 档位三 · 数值与进度 ───────────────────────────────────────────────────────────────

/** 数字 count-up 时长（`countUpState`）：大数字从旧值滚到新值。 */
internal const val COUNT_UP_MS = 600

/** 进度条插值时长（`progressState`）：匀速，与数字滚动同档。 */
internal const val PROGRESS_MS = 600

/** 高频刷新的进度（下载回调逐帧来）：600ms 会一直追不上目标，收短到 320ms。 */
internal const val FAST_PROGRESS_MS = 320

// ── 档位四 · 图表入场 ─────────────────────────────────────────────────────────────────

/**
 * 图表描线 / 柱体生长的入场时长。原先趋势图 550ms、周报柱状 500ms 各写各的
 * （审计 P2-23 记过「50ms 肉眼无感」），统一取 500ms——两张图里更早存在的那个值。
 */
internal const val CHART_ENTER_MS = 500

/** 图表入场规格（`Animatable.animateTo` 直接吃），缓动用 `tween` 缺省的 FastOutSlowIn。 */
internal val ChartEnterSpec: TweenSpec<Float> = tween(durationMillis = CHART_ENTER_MS)

// ── 档位五 · AI 正文揭示（一次性打字机，2026-10-11「更有 AI 感」批） ──────────────────

/**
 * 揭示速度：**10ms/字 = 100 字/秒**。中文没有空格分词，按字揭示就是逐词揭示的等价体验
 * （ChatGPT/Claude 中文流式的观感）；业内 45~100 字符/秒，作者 2026-10-12 反馈 50 字/秒
 * 太慢、提到 100（中文按字读速高，观感仍从容）。
 * 正文是**已生成的静态文本**而非实时流：只做一次性揭示，播完即停、光标消失；
 * 长文不设总时长上限，按本速度自然结束（「短而准」准则的上限只约束短文本的观感）。
 */
internal const val AI_REVEAL_CHAR_MS = 10

/**
 * 揭示中遇到标点（[AI_PAUSE_CHARS]：`.!?，。！？；、\n`）后的自然停顿。
 * 业内取 200~300ms；作者 2026-10-12 反馈整体偏慢后收到 150ms——保留可感的呼吸点
 * 但不再拖读速：没有停顿的匀速字流读起来像刷屏，有停顿才像在「说话」。
 */
internal const val AI_PUNCT_PAUSE_MS = 150

/**
 * 揭示点光标的闪烁周期（亮→灭→亮为一圈）。灭半圈由 [AiCursorBlinkSpec] 的
 * `RepeatMode.Reverse` 对接：alpha 连续往返，不出现「非 0 即 1」的硬跳。
 */
internal const val AI_CURSOR_BLINK_MS = 900

/** 光标闪烁规格：tween 半周期 + Reverse。组件只吃规格，不写裸 `tween(...)`。 */
internal val AiCursorBlinkSpec: InfiniteRepeatableSpec<Float> =
    infiniteRepeatable(tween(durationMillis = AI_CURSOR_BLINK_MS / 2), RepeatMode.Reverse)

/**
 * 揭示边缘渐隐带的字符数：最新 N 字按到揭示点的距离线性减淡（流式输出的 shimmer 边），
 * 播完后由 `stateTween()` 在 200ms 内把整带抹平成实色——末尾几个字不许瞬跳变实。
 */
internal const val AI_REVEAL_FADE_CHARS = 3

/** 渐隐带最外侧（最新一个字）的 alpha 下限：看得见轮廓、读不实；终态恒为 1f。 */
internal const val AI_REVEAL_EDGE_ALPHA = 0.35f

/** 揭示中需要停顿的字符（标点 + 换行）：出现即多停一次 [AI_PUNCT_PAUSE_MS]。 */
internal val AI_PAUSE_CHARS: Set<Char> = setOf('.', '!', '?', '，', '。', '！', '？', '；', '、', '\n')
