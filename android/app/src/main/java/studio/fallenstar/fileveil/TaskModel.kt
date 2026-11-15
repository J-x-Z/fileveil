// SPDX-License-Identifier: MPL-2.0
package studio.fallenstar.fileveil

import android.app.Application
import android.content.Intent
import android.net.Uri
import android.provider.OpenableColumns
import android.os.ParcelFileDescriptor
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.documentfile.provider.DocumentFile
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.File
import java.security.MessageDigest
import java.time.Instant
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean

data class TaskResult(val name: String, val success: Boolean, val status: String, val detail: String, val files: List<File>, val detailTruncated: Boolean = false)

class TaskModel(app: Application) : AndroidViewModel(app) {
    private val prefs = app.getSharedPreferences("settings", 0)
    private val identity = IdentityStore(app)
    var chinese by mutableStateOf(prefs.getBoolean("chinese", java.util.Locale.getDefault().language == "zh"))
    var themeChoice by mutableStateOf(prefs.getString("theme", "system") ?: "system")
    var author by mutableStateOf(prefs.getString("author", "") ?: "")
    var workId by mutableStateOf(prefs.getString("work", null) ?: "urn:uuid:${UUID.randomUUID()}")
    var copyId by mutableStateOf(prefs.getString("copy", "android") ?: "android")
    var robust by mutableStateOf(false)
    var cleanSignal by mutableStateOf(false)
    var selected by mutableStateOf<List<Uri>>(emptyList())
    var outputTree by mutableStateOf(prefs.getString("tree", null)?.let(Uri::parse))
    var running by mutableStateOf(false)
    var completed by mutableStateOf(0)
    var progress by mutableStateOf("")
    var message by mutableStateOf("")
    var hasIdentity by mutableStateOf(identity.exists)
    var results by mutableStateOf<List<TaskResult>>(emptyList())
    private val cancel = AtomicBoolean(false)
    private fun taskResult(name: String, success: Boolean, status: String, detail: String, files: List<File>) =
        TaskResult(name, success, status, detail.take(16 * 1024), files, detail.length > 16 * 1024)

    init {
        // A killed native task cannot resume. Remove its private input/key staging.
        File(app.cacheDir, "tasks").deleteRecursively()
        saveSettings()
        viewModelScope.launch {
            results = withContext(Dispatchers.IO) {
                File(app.filesDir, "results").listFiles()?.filter { it.isDirectory }?.sortedByDescending { it.lastModified() }?.take(64)?.mapNotNull { directory ->
                    try {
                        val reportFile = directory.listFiles()?.firstOrNull { it.name.endsWith(".fileveil-report.json") && it.length() <= 4L * 1024 * 1024 } ?: return@mapNotNull null
                        val json = JSONObject(reportFile.readText())
                        val status = if (json.optJSONObject("export")?.optString("status") in listOf("partially_exported", "failed", "pending", "verified_assets")) "export_failed" else json.getJSONObject("report").optString("result", "not_assessed")
                        taskResult(reportFile.name.removeSuffix(".fileveil-report.json"), status !in listOf("failed", "blocked", "unsupported", "export_failed"), status, json.toString(2), directory.listFiles()?.filter { it.isFile } ?: emptyList())
                    } catch (_: Exception) { null }
                } ?: emptyList()
            }
        }
    }
    fun text(en: String, zh: String) = if (chinese) zh else en
    fun saveSettings() { prefs.edit().putBoolean("chinese", chinese).putString("theme", themeChoice).putString("author", author).putString("work", workId).putString("copy", copyId).apply() }
    fun setTree(uri: Uri) {
        viewModelScope.launch {
            try {
                withContext(Dispatchers.IO) { ProviderIo.bounded { scope -> scope.check(); getApplication<Application>().contentResolver.takePersistableUriPermission(uri, Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION) } }
                outputTree = uri; prefs.edit().putString("tree", uri.toString()).apply()
            } catch (e: Exception) { message = e.message ?: "Permission error" }
        }
    }
    fun disableTree() {
        outputTree = null
        prefs.edit().remove("tree").apply()
    }
    fun createIdentity() {
        viewModelScope.launch {
            try { withContext(Dispatchers.IO) { identity.create() }; hasIdentity = true; message = text("Local signing identity created. Keep this app's data to retain the identity.", "已创建本机签名身份。保留应用数据以维持同一身份。") }
            catch (e: Exception) { message = e.message ?: "Keystore error" }
        }
    }
    fun stop() { cancel.set(true); progress = text("Stopping after the current file…", "当前文件完成后停止…") }
    fun clearResults() {
        if (running) return
        File(getApplication<Application>().filesDir, "results").deleteRecursively()
        results = emptyList()
    }
    fun start(action: String) {
        if (running || selected.isEmpty()) return
        if (selected.size > 16) { message = text("Select at most 16 files per batch.", "每批最多选择 16 个文件。"); return }
        if (action == "mark" && !hasIdentity) { message = text("Create a local identity in Settings first.", "请先在设置创建本机签名身份。"); return }
        saveSettings(); running = true; completed = 0; cancel.set(false); message = ""
        val inputs = selected.toList()
        val settings = JSONObject().put("action", action).put("work_id", workId).put("author", author).put("copy_id", copyId)
            .put("created_at", Instant.now().toString()).put("robust", robust).put("clean_signal", cleanSignal).put("watermark_version", 2)
        val tree = outputTree
        viewModelScope.launch {
            for (uri in inputs) {
                if (cancel.get()) break
                progress = "${completed + 1}/${inputs.size}"
                val result = withContext(Dispatchers.IO) { process(uri, settings, tree) }
                results = (listOf(result) + results).take(64)
                completed += 1
            }
            running = false
            progress = text("Completed $completed/${inputs.size}", "已完成 $completed/${inputs.size}")
        }
    }
    private fun displayName(uri: Uri): String {
        val resolver = getApplication<Application>().contentResolver
        return ProviderIo.bounded(cancel) { scope ->
            safeDisplayName(resolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null, scope.signal)?.use {
                if (it.moveToFirst()) it.getString(0) else null
            } ?: "input.bin")
        }
    }
    private fun digest(file: File): ByteArray = file.inputStream().use { input ->
        val digest = MessageDigest.getInstance("SHA-256"); val buffer = ByteArray(65536)
        while (true) { val count = input.read(buffer); if (count < 0) break; digest.update(buffer, 0, count) }; digest.digest()
    }
    private fun process(uri: Uri, settings: JSONObject, tree: Uri?): TaskResult {
        val app = getApplication<Application>()
        val task = File(File(app.cacheDir, "tasks"), UUID.randomUUID().toString()).apply { mkdirs() }
        val name = try { displayName(uri) } catch (_: Exception) { "input.bin" }
        var resultDirectory: File? = null
        var retainedFiles: List<File> = emptyList()
        try {
            val input = File(task, name)
            ProviderIo.bounded(cancel) { scope ->
                val descriptor = app.contentResolver.openFileDescriptor(uri, "r", scope.signal) ?: error("The provider did not open the selected document")
                scope.attach(descriptor)
                try { ParcelFileDescriptor.AutoCloseInputStream(descriptor).use { source -> input.outputStream().use { target ->
                    val buffer = ByteArray(65536); var total = 0L
                    while (true) { scope.check(); val n = source.read(buffer); if (n < 0) break; scope.check(); total += n; check(total <= 64L * 1024 * 1024) { "File exceeds the 64 MiB mobile limit" }; target.write(buffer, 0, n) }
                } } } finally { scope.detach(descriptor); descriptor.close() }
            }
            val request = JSONObject(settings.toString()).put("input", name).toString().toByteArray(Charsets.UTF_8)
            val seed = if (hasIdentity) identity.unlock() else null
            val response = try { NativeEngine.request(task.absolutePath.toByteArray(Charsets.UTF_8), request, seed) }
                finally { seed?.fill(0) }
            val json = JSONObject(response.toString(Charsets.UTF_8))
            if (!json.optBoolean("ok")) return taskResult(name, false, "failed", json.optString("error"), emptyList())
            val report = json.getJSONObject("report")
            val result = report.optString("result", "not_assessed")
            val good = result != "failed" && result != "blocked" && result != "unsupported"
            val resultsRoot = File(app.filesDir, "results").apply { mkdirs() }
            val used = resultsRoot.walkTopDown().filter { it.isFile }.sumOf { it.length() }
            val names = json.getJSONArray("outputs")
            check(names.length() <= 8) { "Unexpected result count" }
            val staged = mutableListOf<File>()
            for (i in 0 until names.length()) {
                val outputName = names.getString(i)
                check(outputName == File(outputName).name && outputName != "." && outputName != "..")
                val output = File(task, "output/$outputName")
                check(output.canonicalFile.parentFile == File(task, "output").canonicalFile)
                staged += output
            }
            json.put("export", JSONObject().put("status", if (tree == null) "not_requested" else "pending"))
            val reportBytes = json.toString(2).toByteArray(Charsets.UTF_8)
            val publicationBytes = boundedPublicationBytes(staged, reportBytes)
            // Reserve room for an export failure record without exceeding quota.
            check(used + publicationBytes + 8192 <= 256L * 1024 * 1024) { "Result storage reached 256 MiB; export and clear old results" }
            val published = File(resultsRoot, UUID.randomUUID().toString()).apply { check(mkdir()) }; resultDirectory = published
            val files = mutableListOf<File>()
            for (output in staged) {
                val destination = File(published, output.name)
                check(output.renameTo(destination)) { "Could not preserve the verified result" }; files += destination
            }
            val reportFile = File(published, "$name.fileveil-report.json").apply { writeBytes(reportBytes) }; files += reportFile
            // Once the complete local report exists, export failures must never
            // discard the verified local snapshot.
            retainedFiles = files.toList(); resultDirectory = null
            if (tree != null && good) {
                var exported = 0
                try {
                    // Each remote document is independently readback verified.
                    // Preserve verified local files if a provider fails midway.
                    for (file in files.filter { it != reportFile }) { export(file, tree); exported += 1 }
                    json.put("export", JSONObject().put("status", "verified_assets").put("files", exported).put("report_delivery", "separate_readback"))
                    reportFile.writeText(json.toString(2))
                    export(reportFile, tree); exported += 1
                    json.put("export", JSONObject().put("status", "verified").put("files", exported))
                } catch (e: Exception) {
                    json.put("export", JSONObject().put("status", if (exported == 0) "failed" else "partially_exported").put("verified_files", exported).put("error", (e.message ?: "Provider error").take(1000)).put("local_results_preserved", true))
                    reportFile.writeText(json.toString(2))
                    return taskResult(name, false, "export_failed", json.toString(2), files)
                }
            }
            reportFile.writeText(json.toString(2))
            return taskResult(name, good, result, json.toString(2), files)
        } catch (e: Exception) {
            if (retainedFiles.isEmpty()) resultDirectory?.deleteRecursively()
            return taskResult(name, false, if (retainedFiles.isEmpty()) "failed" else "export_failed", e.message ?: e.javaClass.simpleName, retainedFiles)
        } finally { task.deleteRecursively() }
    }
    private fun export(file: File, tree: Uri) = ProviderIo.bounded(cancel) { scope ->
        val app = getApplication<Application>()
        scope.check()
        val directory = DocumentFile.fromTreeUri(app, tree) ?: error("Output directory permission is unavailable")
        val suffix = UUID.randomUUID().toString().take(8)
        val safeName = safeDisplayName(file.name)
        val base = safeName.substringBeforeLast('.', safeName)
        val extension = safeName.substringAfterLast('.', "")
        val target = directory.createFile("application/octet-stream", "$base-$suffix${if (extension.isEmpty()) "" else ".$extension"}") ?: error("Could not create a new output document")
        // Never write or delete a provider URI that aliases an authorized input.
        check(target.uri !in selected) { "Output provider returned an original input URI" }
        try {
            scope.check()
            val writeFd = app.contentResolver.openFileDescriptor(target.uri, "w", scope.signal) ?: error("Output provider refused the new document")
            scope.attach(writeFd)
            try { ParcelFileDescriptor.AutoCloseOutputStream(writeFd).use { sink -> file.inputStream().use { source ->
                val buffer = ByteArray(65536)
                while (true) { scope.check(); val n = source.read(buffer); if (n < 0) break; sink.write(buffer, 0, n) }
            } } } finally { scope.detach(writeFd); writeFd.close() }
            scope.check()
            val readFd = app.contentResolver.openFileDescriptor(target.uri, "r", scope.signal) ?: error("Output provider refused readback")
            scope.attach(readFd)
            val verified = try { ParcelFileDescriptor.AutoCloseInputStream(readFd).use { input ->
                val hash = MessageDigest.getInstance("SHA-256"); val buffer = ByteArray(65536); var total = 0L
                while (true) { scope.check(); val n = input.read(buffer); if (n < 0) break; scope.check(); total += n; check(total <= file.length()); hash.update(buffer, 0, n) }
                total == file.length() && MessageDigest.isEqual(hash.digest(), digest(file))
            } } finally { scope.detach(readFd); readFd.close() }
            check(verified) { "Export readback did not match the verified output" }
        } catch (e: Exception) {
            if (!target.delete()) throw java.io.IOException("Export failed; an incomplete new provider document may remain. Verified local results are retained.", e)
            throw e
        }
    }
}

// FVPROV1 15365 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiJkOGE2MTdjZGJkN2NhZDQ1MDE2YTYxNzQzMmY0ZmM5Y2Y0YTAxMjU1MmQzZTI3OWQyYTg4MDk1ZTk0YTlmM2Q0IiwiY29weV9pZCI6InYwLjcuMC1iZXRhLjEiLCJjcmVhdGVkX2F0IjoiMjAyNi0xMS0xNSIsImVkaXRpb24iOiJiZXRhIiwiaXNzdWVyX3BvbGljeSI6bnVsbCwia2luZCI6ImNyZWF0ZSIsIm1vZGUiOiJzZWxmX3NpZ24iLCJwYXJlbnRfdmVyc2lvbiI6bnVsbCwicHJldmlvdXNfcmVjb3JkX3NoYTI1NiI6bnVsbCwic2NoZW1hIjoiZmlsZXZlaWwucHJvdmVuYW5jZS5zaWduYXR1cmUudjIiLCJzZXF1ZW5jZSI6MCwidHJhbnNmZXJfdG9fa2V5X2lkIjpudWxsLCJ2ZXJzaW9uIjoidjAuNy4wLWJldGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2FuZHJvaWQvYXBwL3NyYy9tYWluL2phdmEvc3R1ZGlvL2ZhbGxlbnN0YXIvZmlsZXZlaWwvVGFza01vZGVsLmt0In0sInNpZ25hdHVyZXMiOlt7ImtleV9pZCI6Ijk5ZWE2M2VmY2NmZDBmZGJkNjhlMTZlZDhmMDNkMzM3ZjE1ZWMyZTRhNmEzZDY0ZTExZDcxNGVhMWU1NDI1MzMiLCJwdWJsaWNfa2V5X2hleCI6ImFkYjNlMTdjZDEyZjk1NmQwMDcwZTE2NjNmNTMxNTM3ZmNlZGY3MzA4ZDAxNjU4ZmVhNDU2ZmVlYThmN2ZiYzUiLCJzaWduYXR1cmVfaGV4IjoiYWU4ZDFlNTBiMGNiOTA2YWQ5NjM4NjE3MmVmOTI1YzgyZWJhZmEwODIyODJmZjQ5Y2E4ZGE1MzE1ZDU5MjA2Njk3NWU5NjRhZmFlODI2M2I2YjQ3YjQwZTEyZjdmNTBlMDg2N2U3YmNiMTJiMzllMWQ1ZWJkMWJhMTU1ZjY1MDYifV19XQ== FVPROV1-END
