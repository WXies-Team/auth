// 移植自 calorie-diary（miuix 0.9.4 同源工具箱），勿在本仓另起炉灶
package cn.horatio.authweb.icons

import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.graphics.vector.PathBuilder
import androidx.compose.ui.graphics.vector.PathNode
import androidx.compose.ui.graphics.vector.VectorPath
import androidx.compose.ui.graphics.vector.path
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import top.yukonga.miuix.kmp.basic.Icon
import top.yukonga.miuix.kmp.theme.LocalContentColor

/**
 * 图标粗细九档，对应 SF Symbols ultralight→black（九档各自匹配 San Francisco 字重）。
 * 数值是 24 视口下的描边宽度——描边随图标尺寸等比缩放（SVG 默认行为）。
 */
enum class IconWeight(val strokeWidth: Float) {
    Ultralight(1f),
    Thin(1.25f),
    Light(1.5f),
    Regular(2f),
    Medium(2.25f),
    Semibold(2.5f),
    Bold(3f),
    Heavy(3.5f),
    Black(4f),
}

/**
 * 全局默认档：改这一处全 App 生效——`AppIcon` 以它作 [LocalIconWeight] 缺省值，
 * 非组合上下文读不到 CompositionLocal 的调用处在构造时 `withStrokeWeight(this)` 跟随。
 */
val DefaultIconWeight = IconWeight.Regular

/** 子树级默认档覆盖：CompositionLocalProvider(LocalIconWeight provides …) { … } */
val LocalIconWeight = staticCompositionLocalOf { DefaultIconWeight }

/** lucide-cmp 的静态矢量把描边烘死在 2f（= Regular 档），等于档不重发射、零开销。 */
private const val BASE_STROKE_WIDTH = 2f

/**
 * 按档位重发射描边宽度：lucide-cmp 出的是静态 ImageVector（strokeLineWidth 全量烘死 2f，
 * 不可调），这里从 `root` 逐路径取出节点、以新描边宽重建——路径数据不动，只改粗细。
 *
 * 只处理扁平路径：`root` 下出现嵌套 VectorGroup（本库全量 1665 个图标已核验无 group）就原样返回，
 * 宁可那一档不生效也不画错。# ponytail: 需要按组分色/分层时再补 group 递归
 */
fun ImageVector.withStrokeWeight(weight: IconWeight): ImageVector {
    if (weight.strokeWidth == BASE_STROKE_WIDTH) return this
    val vectorPaths = root.filterIsInstance<VectorPath>()
    if (vectorPaths.size != root.size) return this
    val builder = ImageVector.Builder(
        name = name,
        defaultWidth = defaultWidth,
        defaultHeight = defaultHeight,
        viewportWidth = viewportWidth,
        viewportHeight = viewportHeight,
        tintBlendMode = tintBlendMode,
        tintColor = tintColor,
        autoMirror = autoMirror,
    )
    vectorPaths.forEach { vectorPath ->
        builder.path(
            fill = vectorPath.fill,
            fillAlpha = vectorPath.fillAlpha,
            stroke = vectorPath.stroke,
            strokeAlpha = vectorPath.strokeAlpha,
            strokeLineWidth = weight.strokeWidth,
            strokeLineCap = vectorPath.strokeLineCap,
            strokeLineJoin = vectorPath.strokeLineJoin,
            strokeLineMiter = vectorPath.strokeLineMiter,
            pathFillType = vectorPath.pathFillType,
        ) {
            vectorPath.pathData.forEach(::addNode)
        }
    }
    return builder.build()
}

private fun PathBuilder.addNode(node: PathNode) {
    when (node) {
        is PathNode.MoveTo -> moveTo(node.x, node.y)
        is PathNode.RelativeMoveTo -> moveToRelative(node.dx, node.dy)
        is PathNode.LineTo -> lineTo(node.x, node.y)
        is PathNode.RelativeLineTo -> lineToRelative(node.dx, node.dy)
        is PathNode.HorizontalTo -> horizontalLineTo(node.x)
        is PathNode.RelativeHorizontalTo -> horizontalLineToRelative(node.dx)
        is PathNode.VerticalTo -> verticalLineTo(node.y)
        is PathNode.RelativeVerticalTo -> verticalLineToRelative(node.dy)
        is PathNode.CurveTo -> curveTo(node.x1, node.y1, node.x2, node.y2, node.x3, node.y3)
        is PathNode.RelativeCurveTo ->
            curveToRelative(node.dx1, node.dy1, node.dx2, node.dy2, node.dx3, node.dy3)
        is PathNode.ReflectiveCurveTo -> reflectiveCurveTo(node.x1, node.y1, node.x2, node.y2)
        is PathNode.RelativeReflectiveCurveTo ->
            reflectiveCurveToRelative(node.dx1, node.dy1, node.dx2, node.dy2)
        is PathNode.QuadTo -> quadTo(node.x1, node.y1, node.x2, node.y2)
        is PathNode.RelativeQuadTo -> quadToRelative(node.dx1, node.dy1, node.dx2, node.dy2)
        is PathNode.ReflectiveQuadTo -> reflectiveQuadTo(node.x, node.y)
        is PathNode.RelativeReflectiveQuadTo -> reflectiveQuadToRelative(node.dx, node.dy)
        is PathNode.ArcTo -> arcTo(
            node.horizontalEllipseRadius,
            node.verticalEllipseRadius,
            node.theta,
            node.isMoreThanHalf,
            node.isPositiveArc,
            node.arcStartX,
            node.arcStartY,
        )
        is PathNode.RelativeArcTo -> arcToRelative(
            node.horizontalEllipseRadius,
            node.verticalEllipseRadius,
            node.theta,
            node.isMoreThanHalf,
            node.isPositiveArc,
            node.arcStartDx,
            node.arcStartDy,
        )
        is PathNode.Close -> close()
    }
}

/**
 * 全 App 图标唯一入口。颜色走 tint（缺省 [LocalContentColor]，随主题/暗色模式自动适配），
 * 粗细走 [weight]（缺省读子树的 [LocalIconWeight]，再缺省用全局 [DefaultIconWeight]）。
 */
@Composable
fun AppIcon(
    icon: ImageVector,
    contentDescription: String?,
    modifier: Modifier = Modifier,
    tint: Color = LocalContentColor.current,
    weight: IconWeight = LocalIconWeight.current,
) {
    val imageVector = remember(icon, weight) { icon.withStrokeWeight(weight) }
    Icon(
        imageVector = imageVector,
        contentDescription = contentDescription,
        modifier = modifier,
        tint = tint,
    )
}
