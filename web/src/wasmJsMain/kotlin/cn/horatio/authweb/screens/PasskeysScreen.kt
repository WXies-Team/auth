// 控制台 · Passkey：行为规格 = 旧前端 internal/ui/templates/passkeys.html + app.js
// initPasskeys（列表 / 行内改名 / 删除确认 / 注册仪式添加）。
// 添加与删除是服务端 reauth 闸操作（reauthed），先 ReauthController.ensure() 再发请求；
// 浏览器取消注册面板 = 静默收场（用户取消不是错误，同登录侧口径）。
package cn.horatio.authweb.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyListState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.unit.dp
import cn.horatio.authweb.component.DialogButtonRow
import cn.horatio.authweb.component.ItemFadeSpec
import cn.horatio.authweb.component.ItemPlacementSpec
import cn.horatio.authweb.component.PrefIcon
import cn.horatio.authweb.component.SmallTitle
import cn.horatio.authweb.component.TextButton
import cn.horatio.authweb.component.buttonColorsPrimaryApp
import cn.horatio.authweb.component.textButtonColorsDanger
import cn.horatio.authweb.component.textButtonColorsPrimaryApp
import cn.horatio.authweb.data.Api
import cn.horatio.authweb.data.CeremonyResponse
import cn.horatio.authweb.data.OkResponse
import cn.horatio.authweb.data.PasskeyFinishRequest
import cn.horatio.authweb.data.PasskeyInfo
import cn.horatio.authweb.data.PasskeyRenameRequest
import cn.horatio.authweb.data.ReauthController
import cn.horatio.authweb.data.SessionStore
import cn.horatio.authweb.data.createCredential
import cn.horatio.authweb.shell.LocalSnackbarHostState
import cn.horatio.authweb.shell.ScreenScaffold
import cn.horatio.authweb.shell.adaptiveContentWidth
import cn.horatio.authweb.shell.pageContentPadding
import cn.horatio.authweb.shell.pageScrollModifiers
import com.composables.icons.lucide.KeyRound
import com.composables.icons.lucide.Lucide
import kotlinx.coroutines.launch
import top.yukonga.miuix.kmp.basic.BasicComponent
import top.yukonga.miuix.kmp.basic.BasicComponentDefaults
import top.yukonga.miuix.kmp.basic.Button
import top.yukonga.miuix.kmp.basic.Card
import top.yukonga.miuix.kmp.basic.CircularProgressIndicator
import top.yukonga.miuix.kmp.basic.MiuixScrollBehavior
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.basic.TextField
import top.yukonga.miuix.kmp.basic.VerticalScrollBar
import top.yukonga.miuix.kmp.basic.rememberScrollBarAdapter
import top.yukonga.miuix.kmp.overlay.OverlayDialog
import top.yukonga.miuix.kmp.theme.MiuixTheme

@Composable
fun PasskeysScreen() {
    val scope = rememberCoroutineScope()
    val snackbarHostState = LocalSnackbarHostState.current
    val scrollBehavior = MiuixScrollBehavior()
    val lazyListState = remember { LazyListState() }

    var loaded by remember { mutableStateOf(false) }
    var loadError by remember { mutableStateOf<String?>(null) }
    var items by remember { mutableStateOf<List<PasskeyInfo>>(emptyList()) }
    var busy by remember { mutableStateOf(false) }
    var actionError by remember { mutableStateOf<String?>(null) }
    var deleteTarget by remember { mutableStateOf<PasskeyInfo?>(null) }

    suspend fun load() {
        try {
            items = Api.get<List<PasskeyInfo>>("/api/passkeys")
            loadError = null
        } catch (e: Exception) {
            loadError = e.message ?: "Passkey 列表加载失败，请稍后重试"
        }
        loaded = true
    }

    LaunchedEffect(Unit) {
        runCatching { SessionStore.refresh() }
        load()
    }

    /** 添加（注册仪式）：reauth 闸 → options → 浏览器创建 → finish → 刷新列表。 */
    fun add() {
        if (busy) return
        scope.launch {
            busy = true
            actionError = null
            try {
                ReauthController.ensure()
                val opts = Api.post<CeremonyResponse>("/webauthn/register/options", "{}")
                val credential = createCredential(opts.publicKey) ?: return@launch // 用户取消：静默收场
                Api.post<PasskeyInfo>(
                    "/webauthn/register/finish",
                    Api.encode(PasskeyFinishRequest(ceremonyId = opts.ceremonyId, response = credential)),
                )
                load()
                snackbarHostState.showSnackbar("Passkey 已添加")
            } catch (e: Exception) {
                actionError = e.message ?: "添加失败，请重试"
            } finally {
                busy = false
            }
        }
    }

    fun rename(id: Long, name: String) {
        if (busy) return
        val trimmed = name.trim()
        if (trimmed.isEmpty()) {
            scope.launch { snackbarHostState.showSnackbar("名称不能为空") }
            return
        }
        scope.launch {
            busy = true
            try {
                Api.patch<OkResponse>("/api/passkeys/$id", Api.encode(PasskeyRenameRequest(name = trimmed.take(64))))
                load()
                snackbarHostState.showSnackbar("已改名")
            } catch (e: Exception) {
                snackbarHostState.showSnackbar(e.message ?: "改名失败，请稍后重试")
            } finally {
                busy = false
            }
        }
    }

    /** 删除（reauth 闸）：唯一登录方式由服务端 400 裁决，文案直显。 */
    fun delete(id: Long) {
        if (busy) return
        scope.launch {
            busy = true
            try {
                ReauthController.ensure()
                Api.del<OkResponse>("/api/passkeys/$id")
                load()
                snackbarHostState.showSnackbar("已删除")
            } catch (e: Exception) {
                snackbarHostState.showSnackbar(e.message ?: "删除失败，请稍后重试")
            } finally {
                busy = false
            }
        }
    }

    ScreenScaffold(title = "Passkey", scrollBehavior = scrollBehavior) { innerPadding ->
        val contentPadding = pageContentPadding(innerPadding, PaddingValues(0.dp), extraBottom = 16.dp)
        Box(Modifier.fillMaxSize()) {
            LazyColumn(
                state = lazyListState,
                modifier = Modifier
                    .adaptiveContentWidth()
                    .align(Alignment.TopCenter)
                    .pageScrollModifiers(scrollBehavior),
                contentPadding = contentPadding,
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                if (!loaded) {
                    item(key = "loading") {
                        Box(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(vertical = 64.dp)
                                .animateItem(fadeInSpec = ItemFadeSpec, placementSpec = ItemPlacementSpec, fadeOutSpec = ItemFadeSpec),
                            contentAlignment = Alignment.Center,
                        ) {
                            CircularProgressIndicator()
                        }
                    }
                } else {
                    item(key = "hint-top") {
                        Text(
                            text = "Passkey 用系统指纹、面容或设备锁解锁登录，可跨设备跨浏览器共用同一批凭证——添加一把，在所有登录入口都能用。",
                            style = MiuixTheme.textStyles.footnote1,
                            color = MiuixTheme.colorScheme.onSurfaceSecondary,
                            modifier = Modifier.padding(horizontal = 28.dp)
                                .animateItem(fadeInSpec = ItemFadeSpec, placementSpec = ItemPlacementSpec, fadeOutSpec = ItemFadeSpec),
                        )
                    }
                    item(key = "list") {
                        Column(Modifier.animateItem(fadeInSpec = ItemFadeSpec, placementSpec = ItemPlacementSpec, fadeOutSpec = ItemFadeSpec)) {
                            SmallTitle(text = "已保存的 Passkey")
                            Card(modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp)) {
                                when {
                                    loadError != null -> InlineError(
                                        text = loadError,
                                        modifier = Modifier.fillMaxWidth().padding(16.dp),
                                    )
                                    items.isEmpty() -> Text(
                                        text = "还没有 Passkey，点击下方「添加 Passkey」创建一个。",
                                        style = MiuixTheme.textStyles.footnote1,
                                        color = MiuixTheme.colorScheme.onSurfaceSecondary,
                                        modifier = Modifier.fillMaxWidth().padding(16.dp),
                                    )
                                    else -> items.forEach { passkey ->
                                        PasskeyRow(
                                            passkey = passkey,
                                            busy = busy,
                                            onRename = { name -> rename(passkey.id, name) },
                                            onDelete = { deleteTarget = passkey },
                                        )
                                    }
                                }
                            }
                        }
                    }
                    item(key = "add") {
                        Column(Modifier.animateItem(fadeInSpec = ItemFadeSpec, placementSpec = ItemPlacementSpec, fadeOutSpec = ItemFadeSpec)) {
                            SmallTitle(text = "添加")
                            Card(modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp)) {
                                Column(Modifier.padding(12.dp)) {
                                    Button(
                                        onClick = { add() },
                                        enabled = !busy,
                                        modifier = Modifier.fillMaxWidth(),
                                        colors = buttonColorsPrimaryApp(),
                                    ) {
                                        Text(text = "添加 Passkey")
                                    }
                                    InlineError(text = actionError, modifier = Modifier.padding(top = 8.dp))
                                    Text(
                                        text = "删除前请确保还剩至少一种登录方式（密码、两步验证或另一把 Passkey）。",
                                        style = MiuixTheme.textStyles.footnote1,
                                        color = MiuixTheme.colorScheme.onSurfaceSecondary,
                                        modifier = Modifier.padding(top = 8.dp),
                                    )
                                }
                            }
                        }
                    }
                }
                item(key = "spacer") {
                    Spacer(Modifier.height(16.dp))
                }
            }
            VerticalScrollBar(
                adapter = rememberScrollBarAdapter(lazyListState),
                modifier = Modifier.align(Alignment.CenterEnd).fillMaxHeight(),
                trackPadding = contentPadding,
            )
        }

        // 删除确认（旧 del-dialog 文案口径）：点名这把 Passkey 与后果
        OverlayDialog(
            show = deleteTarget != null,
            title = "删除 Passkey",
            summary = deleteTarget?.let { "删除「${it.name}」后，这把 Passkey 立即不能再用来登录。" } ?: "",
            onDismissRequest = { deleteTarget = null },
            onDismissFinished = { deleteTarget = null },
        ) {
            DialogButtonRow(
                cancelText = "取消",
                onCancel = { deleteTarget = null },
                confirmText = "删除",
                onConfirm = {
                    deleteTarget?.let { delete(it.id) }
                    deleteTarget = null
                },
                confirmColors = textButtonColorsDanger(),
            )
        }
    }
}

/** 一行一把 Passkey：名称 + 添加于/最近使用 meta + 本机徽标 + 行内改名/删除。 */
@Composable
private fun PasskeyRow(
    passkey: PasskeyInfo,
    busy: Boolean,
    onRename: (String) -> Unit,
    onDelete: () -> Unit,
) {
    var editing by remember { mutableStateOf(false) }
    var draft by remember { mutableStateOf(passkey.name) }

    if (editing) {
        // 行内改名（旧 startRename：就地换成输入框，不弹窗）；Enter/完成提交，取消还原
        Column(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 12.dp)) {
            TextField(
                colors = fieldLabelColors(),
                value = draft,
                onValueChange = { draft = it.take(64) },
                label = "Passkey 名称",
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
                keyboardOptions = KeyboardOptions(imeAction = ImeAction.Done),
            )
            Row(
                modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
                horizontalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                TextButton(
                    text = "取消",
                    onClick = {
                        draft = passkey.name
                        editing = false
                    },
                    modifier = Modifier.weight(1f),
                )
                TextButton(
                    text = "完成",
                    enabled = draft.trim().isNotEmpty() && !busy,
                    onClick = {
                        val name = draft
                        editing = false
                        onRename(name)
                    },
                    modifier = Modifier.weight(1f),
                    colors = textButtonColorsPrimaryApp(),
                )
            }
        }
    } else {
        // lastUsedAt 是可能为 0 的哨兵（从未用过服务端发 0）：>0 才说「最近使用」，
        // 否则只说「从未使用」，绝不渲染 1970（旧 initPasskeys 同式）
        val lastUsed = passkey.lastUsedAt.takeIf { it > 0 }
        val summary = listOfNotNull(
            "添加于 ${fmtTime(passkey.createdAt)}",
            lastUsed?.let { "最近使用 ${relTime(it)}" } ?: "从未使用",
        ).joinToString(" · ")
        BasicComponent(
            title = passkey.name,
            summary = summary,
            summaryColor = BasicComponentDefaults.summaryColor(
                color = MiuixTheme.colorScheme.onSurfaceSecondary,
            ),
            startAction = { PrefIcon(Lucide.KeyRound) },
            endActions = {
                if (passkey.current) {
                    Text(
                        text = "本机登录所用",
                        style = MiuixTheme.textStyles.footnote2,
                        color = MiuixTheme.colorScheme.onSurfaceSecondary,
                        modifier = Modifier.padding(end = 4.dp),
                    )
                }
                TextButton(
                    text = "改名",
                    onClick = {
                        draft = passkey.name
                        editing = true
                    },
                    enabled = !busy,
                )
                TextButton(
                    text = "删除",
                    onClick = onDelete,
                    enabled = !busy,
                    colors = textButtonColorsDanger(),
                )
            },
        )
    }
}
