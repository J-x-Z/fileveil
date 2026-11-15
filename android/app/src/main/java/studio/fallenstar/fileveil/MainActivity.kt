// SPDX-License-Identifier: MPL-2.0
package studio.fallenstar.fileveil

import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.compose.BackHandler
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.focus.FocusDirection
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.platform.LocalSoftwareKeyboardController
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.unit.dp
import androidx.core.content.FileProvider
import androidx.lifecycle.viewmodel.compose.viewModel
import java.util.ArrayList

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent { FileVeilApp() }
    }
    private fun share(result: TaskResult) {
        val uris = ArrayList(result.files.map { FileProvider.getUriForFile(this, "$packageName.files", it) })
        if (uris.isEmpty()) return
        startActivity(Intent.createChooser(Intent(Intent.ACTION_SEND_MULTIPLE).apply {
            type = "application/octet-stream"
            putParcelableArrayListExtra(Intent.EXTRA_STREAM, uris)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }, "FileVeil"))
    }

    @OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)
    @Composable private fun FileVeilApp(model: TaskModel = viewModel()) {
        var settings by rememberSaveable { mutableStateOf(false) }
        var licenses by rememberSaveable { mutableStateOf(false) }
        val homeScroll = rememberLazyListState()
        val settingsScroll = rememberLazyListState()
        val focus = LocalFocusManager.current
        val keyboard = LocalSoftwareKeyboardController.current
        val imeVisible = WindowInsets.ime.getBottom(LocalDensity.current) > 0
        BackHandler(enabled = settings || licenses) {
            when { licenses -> licenses = false; imeVisible -> { keyboard?.hide(); focus.clearFocus() }; else -> settings = false }
        }
        val isDark = when (model.themeChoice) { "dark" -> true; "light" -> false; else -> isSystemInDarkTheme() }
        val colors = if (isDark) darkColorScheme(primary = Color(0xFFD2D2D5), onPrimary = Color(0xFF202022), background = Color(0xFF151516), surface = Color(0xFF202022), secondaryContainer = Color(0xFF37373A))
            else lightColorScheme(primary = Color(0xFF424248), onPrimary = Color.White, background = Color(0xFFF5F5F6), surface = Color(0xFFFFFFFF), secondaryContainer = Color(0xFFE5E5E7))
        val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenMultipleDocuments()) { model.selected = it.take(17) }
        val directory = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocumentTree()) { it?.let(model::setTree) }
        MaterialTheme(colorScheme = colors) {
            if (licenses) AlertDialog(onDismissRequest = { licenses = false }, title = { Text(model.text("Licenses", "许可证")) },
                text = { val text = remember { assets.open("fileveil-license.txt").bufferedReader().use { it.readText() } + "\n\n" + assets.open("ANDROID_NOTICES.txt").bufferedReader().use { it.readText() } + "\n\n" + assets.open("THIRD_PARTY_NOTICES.txt").bufferedReader().use { it.readText() } }; SelectionContainer { Text(text, modifier = Modifier.verticalScroll(rememberScrollState()), style = MaterialTheme.typography.bodySmall) } },
                confirmButton = { TextButton(onClick = { licenses = false }) { Text(model.text("Close", "关闭")) } })
            Scaffold(topBar = { TopAppBar(title = { Text(if (settings) model.text("Settings", "设置") else "FileVeil") }, navigationIcon = {
                if (settings) TextButton(onClick = { keyboard?.hide(); focus.clearFocus(); settings = false }) { Text(model.text("Back", "返回")) }
            }, actions = {
                if (!settings) TextButton(onClick = { settings = true }) { Text(model.text("Settings", "设置")) }
            }) }) { padding ->
                LazyColumn(Modifier.fillMaxSize().padding(padding).imePadding().padding(horizontal = 20.dp), state = if (settings) settingsScroll else homeScroll, verticalArrangement = Arrangement.spacedBy(12.dp), contentPadding = PaddingValues(bottom = 28.dp)) {
                    if (settings) {
                        item { FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) { FilterChip(selected = !model.chinese, onClick = { model.chinese = false; model.saveSettings() }, label = { Text("English") }); FilterChip(selected = model.chinese, onClick = { model.chinese = true; model.saveSettings() }, label = { Text("中文") }) } }
                        item { FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) { FilterChip(selected = model.themeChoice == "dark", onClick = { model.themeChoice = "dark"; model.saveSettings() }, label = { Text(model.text("Dark", "深色")) }); FilterChip(selected = model.themeChoice == "light", onClick = { model.themeChoice = "light"; model.saveSettings() }, label = { Text(model.text("Light", "浅色")) }); FilterChip(selected = model.themeChoice == "system", onClick = { model.themeChoice = "system"; model.saveSettings() }, label = { Text(model.text("System", "跟随系统")) }) } }
                        item { OutlinedTextField(model.workId, { model.workId = it; model.saveSettings() }, label = { Text(model.text("Work ID", "作品 ID")) }, modifier = Modifier.fillMaxWidth(), enabled = !model.running, singleLine = true, keyboardOptions = KeyboardOptions(imeAction = ImeAction.Next), keyboardActions = KeyboardActions(onNext = { focus.moveFocus(FocusDirection.Down) })) }
                        item { OutlinedTextField(model.author, { model.author = it; model.saveSettings() }, label = { Text(model.text("Author statement", "作者声明")) }, modifier = Modifier.fillMaxWidth(), enabled = !model.running, maxLines = 3, keyboardOptions = KeyboardOptions(imeAction = ImeAction.Next), keyboardActions = KeyboardActions(onNext = { focus.moveFocus(FocusDirection.Down) })) }
                        item { OutlinedTextField(model.copyId, { model.copyId = it; model.saveSettings() }, label = { Text(model.text("Copy ID", "发行副本 ID")) }, modifier = Modifier.fillMaxWidth(), enabled = !model.running, singleLine = true, keyboardOptions = KeyboardOptions(imeAction = ImeAction.Done), keyboardActions = KeyboardActions(onDone = { focus.clearFocus(); keyboard?.hide() })) }
                        item {
                            Text(model.text("Ed25519 identity", "Ed25519 签名身份"), style = MaterialTheme.typography.titleMedium)
                            Text(model.text("The seed is AES-GCM wrapped by Android Keystore. Removing app data loses this local identity. Signatures establish integrity; issuer trust is assessed separately.", "签名种子由 Android Keystore 的 AES-GCM 密钥包装。清除应用数据会丢失本机身份。签名验证完整性，发行者信任单独评估。"))
                            Button(onClick = model::createIdentity, enabled = !model.hasIdentity && !model.running) { Text(if (model.hasIdentity) model.text("Identity protected", "身份已保护") else model.text("Create identity", "创建身份")) }
                        }
                        item { HorizontalDivider() }
                        item { Text(model.text("ARM64 · offline · 64 MiB/file · 12 MP decoded image · 16 files/batch", "ARM64 · 离线 · 每文件 64 MiB · 解码图片 1200 万像素 · 每批 16 文件")) }
                        item { TextButton(onClick = model::clearResults, enabled = !model.running) { Text(model.text("Clear local results", "清除本机结果")) } }
                        item { TextButton(onClick = { licenses = true }) { Text(model.text("Open-source licenses", "开源许可证")) } }
                    } else {
                        item { Text(model.text("Clean · Mark · Verify · Trace", "净化 · 标记 · 验证 · 追溯"), style = MaterialTheme.typography.headlineSmall) }
                        item { Text(model.text("Original documents stay unchanged. Choose files with the system picker; results are separate copies.", "通过系统选择器授权文件。原件保持不变，处理结果另存为副本。")) }
                        item { FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                            Button(onClick = { picker.launch(arrayOf("*/*")) }, enabled = !model.running) { Text(model.text("Choose files", "选择文件")) }
                            OutlinedButton(onClick = { directory.launch(null) }, enabled = !model.running) { Text(model.text("Export folder", "导出目录")) }
                        } }
                        item { Text(model.text("${model.selected.size} selected", "已选 ${model.selected.size} 个文件") + if (model.outputTree != null) model.text(" · export enabled", " · 已启用导出") else model.text(" · local results", " · 本机保存")) }
                        if (model.outputTree != null) item { TextButton(onClick = model::disableTree, enabled = !model.running) { Text(model.text("Keep results locally", "仅保存在本机")) } }
                        item { Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) { Text(model.text("Robust image watermark (Experimental)", "抗压缩图片水印（实验性）"), modifier = Modifier.weight(1f)); Switch(model.robust, { model.robust = it }, enabled = !model.running) } }
                        item { Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) { Text(model.text("Clean detected signal watermarks", "清理已检测的信号水印"), modifier = Modifier.weight(1f)); Switch(model.cleanSignal, { model.cleanSignal = it }, enabled = !model.running) } }
                        item { Text(model.text("Signal processing changes image pixels. Unknown watermarks remain unassessed. A keyed watermark requires the matching identity.", "信号处理会改变图片像素。未知水印仍为未评估，密钥水印需要匹配的身份。"), style = MaterialTheme.typography.bodySmall) }
                        item {
                            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                                Button(onClick = { model.start("scan") }, enabled = !model.running && model.selected.isNotEmpty()) { Text(model.text("Scan", "扫描")) }
                                Button(onClick = { model.start("sanitize") }, enabled = !model.running && model.selected.isNotEmpty()) { Text(model.text("Sanitize", "元数据净化")) }
                            }
                            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                                OutlinedButton(onClick = { model.start("mark") }, enabled = !model.running && model.selected.isNotEmpty()) { Text(model.text("Mark", "标记")) }
                                OutlinedButton(onClick = { model.start("verify") }, enabled = !model.running && model.selected.isNotEmpty()) { Text(model.text("Verify", "验证")) }
                                OutlinedButton(onClick = { model.start("clean") }, enabled = !model.running && model.selected.isNotEmpty()) { Text(model.text("Clean", "清理水印")) }
                            }
                            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                                TextButton(onClick = { model.start("trace") }, enabled = !model.running && model.selected.isNotEmpty()) { Text(model.text("Trace", "追溯")) }
                                TextButton(onClick = { model.start("evidence_export") }, enabled = !model.running && model.selected.isNotEmpty()) { Text(model.text("Export evidence", "导出证据")) }
                                TextButton(onClick = { model.start("evidence_verify") }, enabled = !model.running && model.selected.isNotEmpty()) { Text(model.text("Verify evidence", "验证证据")) }
                            }
                        }
                    }
                    if (model.message.isNotBlank()) item { Text(model.message, color = MaterialTheme.colorScheme.error) }
                    if (!settings) {
                        if (model.running) item { LinearProgressIndicator(Modifier.fillMaxWidth()); Text(model.progress); TextButton(onClick = model::stop) { Text(model.text("Stop after current file", "当前文件后停止")) } }
                        else if (model.progress.isNotBlank()) item { Text(model.progress) }
                        items(model.results) { result -> ResultCard(model, result) }
                    }
                }
            }
        }
    }
    @Composable private fun ResultCard(model: TaskModel, result: TaskResult) {
        var details by remember(result) { mutableStateOf(false) }
        Card(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text(result.name, style = MaterialTheme.typography.titleMedium)
                val status = when (result.status) {
                    "verified_within_scope" -> model.text("Verified within scope", "已在声明范围内验证")
                    "partially_verified" -> model.text("Partially verified — review report scope", "部分验证 — 请查看报告范围")
                    "not_assessed" -> model.text("Not assessed", "未评估")
                    "unsupported" -> model.text("Unsupported", "不支持")
                    "blocked" -> model.text("Blocked", "已阻止")
                    "failed" -> model.text("Failed", "失败")
                    "export_failed" -> model.text("Export incomplete — verified local results retained", "导出未完成 — 已保留验证过的本机结果")
                    else -> result.status
                }
                Text(status, color = if (result.success) MaterialTheme.colorScheme.onSurface else MaterialTheme.colorScheme.error)
                Row {
                    TextButton(onClick = { details = !details }) { Text(model.text("Report", "报告")) }
                    if (result.files.isNotEmpty()) TextButton(onClick = { share(result) }) { Text(model.text("Share results", "分享结果")) }
                }
                if (details) SelectionContainer { Text(result.detail.take(16 * 1024) + if (result.detailTruncated || result.detail.length > 16 * 1024) model.text("\n… Full report is included with the shared result files.", "\n… 完整报告包含在分享结果文件中。") else "", style = MaterialTheme.typography.bodySmall) }
            }
        }
    }
}

// FVPROV1 15871 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiI0NGRmOTZiYzUyZDI3MWYzN2U1NzFkMGJiMzQ0NTI3ODI0ODNjY2EzMGM2YjljNTBiODU3MjBhNzY4MjY1ZmUyIiwiY29weV9pZCI6InYwLjcuMC1iZXRhLjEiLCJjcmVhdGVkX2F0IjoiMjAyNi0xMS0xNSIsImVkaXRpb24iOiJiZXRhIiwiaXNzdWVyX3BvbGljeSI6bnVsbCwia2luZCI6ImNyZWF0ZSIsIm1vZGUiOiJzZWxmX3NpZ24iLCJwYXJlbnRfdmVyc2lvbiI6bnVsbCwicHJldmlvdXNfcmVjb3JkX3NoYTI1NiI6bnVsbCwic2NoZW1hIjoiZmlsZXZlaWwucHJvdmVuYW5jZS5zaWduYXR1cmUudjIiLCJzZXF1ZW5jZSI6MCwidHJhbnNmZXJfdG9fa2V5X2lkIjpudWxsLCJ2ZXJzaW9uIjoidjAuNy4wLWJldGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2FuZHJvaWQvYXBwL3NyYy9tYWluL2phdmEvc3R1ZGlvL2ZhbGxlbnN0YXIvZmlsZXZlaWwvTWFpbkFjdGl2aXR5Lmt0In0sInNpZ25hdHVyZXMiOlt7ImtleV9pZCI6Ijk5ZWE2M2VmY2NmZDBmZGJkNjhlMTZlZDhmMDNkMzM3ZjE1ZWMyZTRhNmEzZDY0ZTExZDcxNGVhMWU1NDI1MzMiLCJwdWJsaWNfa2V5X2hleCI6ImFkYjNlMTdjZDEyZjk1NmQwMDcwZTE2NjNmNTMxNTM3ZmNlZGY3MzA4ZDAxNjU4ZmVhNDU2ZmVlYThmN2ZiYzUiLCJzaWduYXR1cmVfaGV4IjoiNTZmMWI5ZDVlOGJiZjZhN2E4ZDA1ZTQ0YzJmZjI1OWI3OGIwN2VhZjJhZWFiZGFkOGQ4NGMxNTVlYTFjODYxN2MwOWM2Njc5MGM0MDcwMDc0MTA2YmNhNzVkOTdhNzgzZmI0MWJlMjQ0ZDJjYjZjMTE5NmZkMWNiYmJiMjBlMDIifV19XQ== FVPROV1-END
