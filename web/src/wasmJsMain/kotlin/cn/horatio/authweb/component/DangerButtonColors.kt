// 移植自 calorie-diary（miuix 0.9.4 同源工具箱），勿在本仓另起炉灶
package cn.horatio.authweb.component

import androidx.compose.runtime.Composable
import cn.horatio.authweb.theme.StatusColors
import top.yukonga.miuix.kmp.basic.ButtonColors
import top.yukonga.miuix.kmp.basic.ButtonDefaults
import top.yukonga.miuix.kmp.basic.TextButtonColors
import top.yukonga.miuix.kmp.theme.MiuixTheme

/**
 * 破坏性操作的 TextButton 配方：红底 + `onError` 白字。
 *
 * 为什么单独收口：`ButtonDefaults.textButtonColors(color = error)` 只改了**底色**，
 * `textColor` 停在默认 `onSecondaryVariant`（深灰）——灰字压在红底上，既难读又与
 * 全 App「彩底白字」的主按钮不一致（曾被当成 bug 反馈：「开始断食按钮的字色和
 * 其它地方不一样」，同款问题在删除云端数据、清除本机数据、注销确认各出现过一次）。
 * 第 4 次出现前收口成配方，disabled 同步给 35% 透明度（与 AccountScreen 既有取值一致）。
 *
 * 普通主按钮（蓝底）用 app 配方 [textButtonColorsPrimaryApp]——官方
 * `ButtonDefaults.textButtonColorsPrimary()` 白字仅 3.63:1 不达 AA（见 [PrimaryButtonColors]），别混用。
 *
 * 底色走语义层 [StatusColors.danger]（固定语义色，2026-10-15 作者拍板不随明暗变——
 * auth web 移植：原 App 的「自定义颜色」种子 harmonize 不在本仓范围），再过
 * [lockWhiteContrast] 护栏——锁死的是**白字 ≥4.5:1 的落点**而不是色值：原色白字
 * 4.53 本来就达标、原样返回；护栏兜住任何未来取值变更（RGB 同倍率缩放色相不变，
 * 暗红仍是「红=危险」）。onError 在 light/dark 色板里均为纯白（M3 规定），护栏按白字算。
 *
 * 必须标 `@Composable`：`MiuixTheme.colorScheme` 只能在组合上下文里读
 * （HANDOFF 坑 6），普通函数里读会编译不过。
 */
@Composable
fun textButtonColorsDanger(): TextButtonColors {
    val danger = lockWhiteContrast(StatusColors.danger)
    return ButtonDefaults.textButtonColors(
        color = danger,
        disabledColor = danger.copy(alpha = 0.35f),
        textColor = MiuixTheme.colorScheme.onError,
        disabledTextColor = MiuixTheme.colorScheme.onError.copy(alpha = 0.35f),
    )
}

/**
 * 破坏性操作的 **Button** 配方：[textButtonColorsDanger] 的 Button 版，同配方同取值。
 *
 * 为什么也要收口：`ButtonDefaults.buttonColors(color = error)` 同样只改底色，内容色停在
 * 默认 `onSecondaryVariant`（深灰）——与 TextButton 侧同一个「灰字压红底」问题，
 * 调用点各自内联还会漏掉 disabled 的 35% 透明度。
 *
 * 与 TextButton 侧的参数名差异来自 miuix：TextButtonColors 用 `textColor`，
 * ButtonColors 用 `contentColor`。底色取值与理由见 [textButtonColorsDanger]
 * （语义层 danger + 白字 4.5:1 护栏）。必须标 `@Composable`，理由同上（HANDOFF 坑 6）。
 */
@Composable
fun buttonColorsDanger(): ButtonColors {
    val danger = lockWhiteContrast(StatusColors.danger)
    return ButtonDefaults.buttonColors(
        color = danger,
        disabledColor = danger.copy(alpha = 0.35f),
        contentColor = MiuixTheme.colorScheme.onError,
        disabledContentColor = MiuixTheme.colorScheme.onError.copy(alpha = 0.35f),
    )
}
