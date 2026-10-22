package cn.horatio.authweb.shell

/**
 * Web 端效果开关。对照日记 App 的 AppUiPrefs：Web 无「动效与手感」设置面，
 * 恒开玻璃；将来要做开关时把这里的 const 换成 localStorage 读值即可。
 */
object WebUiPrefs {
    /** 液态玻璃总开关（顶栏/底栏模糊都看它）。 */
    const val enableBlur = true

    /** 顶栏渐进模糊档（true=ProgressiveBlur 随滚动渐显；false=常开 25f 厚毛玻璃）。 */
    const val progressiveBlur = true
}
