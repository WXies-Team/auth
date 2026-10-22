// 移植自 calorie-diary（miuix 0.9.4 同源工具箱），勿在本仓另起炉灶
package cn.horatio.authweb.component

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.width
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import top.yukonga.miuix.kmp.basic.ButtonDefaults
import top.yukonga.miuix.kmp.basic.TextButtonColors

/**
 * 弹窗底部「取消 / 确认」双钮行（审计 P2-12）：全宽对开、各 `weight(1f)`、中缝 12dp。
 * 此前 ConfirmDeleteDialog、DatePickerDialog/TimePickerDialog（×2）、AvatarCropDialog
 * 四处逐字拷贝同一行布局，收口到这里；间距与权重沿用原四份的等价写法
 * （`SpaceBetween` + `Spacer(12.dp)`，两枚等宽钮时与 `spacedBy(12.dp)` 视觉一致）。
 *
 * @param confirmColors 确认钮配色：危险操作传 [textButtonColorsDanger]、主操作传
 *   [textButtonColorsPrimaryApp]，缺省 = miuix 默认（如裁剪「完成」这类中性确认）
 */
@Composable
fun DialogButtonRow(
    confirmText: String,
    onConfirm: () -> Unit,
    modifier: Modifier = Modifier,
    cancelText: String = "取消",
    onCancel: () -> Unit,
    confirmColors: TextButtonColors = ButtonDefaults.textButtonColors(),
) {
    Row(modifier = modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
        TextButton(
            text = cancelText,
            onClick = onCancel,
            modifier = Modifier.weight(1f),
        )
        Spacer(Modifier.width(12.dp))
        TextButton(
            text = confirmText,
            onClick = onConfirm,
            modifier = Modifier.weight(1f),
            colors = confirmColors,
        )
    }
}
