plugins {
    alias(libs.plugins.kotlinMultiplatform)
    alias(libs.plugins.composeMultiplatform)
    alias(libs.plugins.composeCompiler)
    alias(libs.plugins.kotlinSerialization)
}

kotlin {
    // Web 唯一目标：Compose Multiplatform 官方 Web 平台（Wasm/GC）。产物为
    // authweb.js + authweb.wasm，经 distribution 收集后由 Go 侧 embed 内嵌伺服。
    wasmJs {
        browser {
            commonWebpackConfig {
                outputFileName = "authweb.js"
            }
        }
        binaries.executable()
    }

    sourceSets {
        wasmJsMain.dependencies {
            implementation(compose.runtime)
            implementation(compose.foundation)
            implementation(compose.ui)
            implementation(libs.miuix.ui)
            implementation(libs.miuix.nav)
            implementation(libs.miuix.blur)
            implementation(libs.miuix.preference)
            implementation(libs.icons.lucide)
            implementation(libs.androidx.lifecycle.viewmodel)
            implementation(libs.androidx.lifecycle.viewmodel.compose)
            implementation(libs.androidx.lifecycle.runtime.compose)
            implementation(libs.androidx.navigationevent.compose)
            implementation(libs.kotlinx.serialization.json)
            implementation(libs.kotlinx.datetime)
            implementation(libs.kotlinx.coroutines.core)
        }
    }
}
