// SPDX-License-Identifier: MPL-2.0
package studio.fallenstar.fileveil

import android.graphics.Bitmap
import androidx.test.platform.app.InstrumentationRegistry
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import java.io.File
import java.util.UUID

class EngineInteropTest {
    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext
    private fun task(): File = File(context.cacheDir, "test-${UUID.randomUUID()}").apply { mkdir() }
    private fun call(directory: File, action: String, seed: ByteArray? = null, robust: Boolean = false, cleanSignal: Boolean = false, inputName: String = "sample.png"): JSONObject {
        val request = JSONObject().put("action", action).put("input", inputName)
            .put("work_id", "urn:fileveil:android-interop-test").put("author", "FileVeil Test")
            .put("copy_id", "android-arm64").put("created_at", "2026-11-15").put("watermark_version", 2).put("robust", robust).put("clean_signal", cleanSignal)
        return JSONObject(NativeEngine.request(directory.absolutePath.toByteArray(), request.toString().toByteArray(), seed).toString(Charsets.UTF_8))
    }
    @Test fun scanMarkVerifyCleanInterop() {
        val roots = mutableListOf<File>()
        try {
            val original = task().also(roots::add)
            Bitmap.createBitmap(256, 256, Bitmap.Config.ARGB_8888).apply { eraseColor(0xff839197.toInt()) }
                .let { bitmap -> File(original, "sample.png").outputStream().use { bitmap.compress(Bitmap.CompressFormat.PNG, 100, it) }; bitmap.recycle() }
            val originalBytes = File(original, "sample.png").readBytes()
            val seed = ByteArray(32) { (it + 1).toByte() }
            val marked = call(original, "mark", seed)
            assertTrue(marked.toString(), marked.getBoolean("ok"))
            assertTrue(marked.getJSONObject("report").getJSONObject("integrity").getBoolean("security_markers_preserved"))
            assertArrayEquals(originalBytes, File(original, "sample.png").readBytes())
            assertFalse(File(original, ".signing-key").exists())
            val verify = task().also(roots::add)
            File(original, "output/sample.png").copyTo(File(verify, "sample.png"))
            val verified = call(verify, "verify", seed)
            assertTrue(verified.toString(), verified.getBoolean("ok"))
            assertEquals("valid", verified.getJSONObject("report").getJSONObject("advanced").getJSONObject("heritage").getJSONObject("verification").getString("signature"))
            val clean = task().also(roots::add)
            File(verify, "sample.png").copyTo(File(clean, "sample.png"))
            val cleaned = call(clean, "clean", seed)
            assertTrue(cleaned.toString(), cleaned.getBoolean("ok"))
            assertArrayEquals(originalBytes, File(clean, "output/sample.png").readBytes())
            val scan = task().also(roots::add)
            File(clean, "output/sample.png").copyTo(File(scan, "sample.png"))
            assertTrue(call(scan, "scan").getBoolean("ok"))
            val artifacts = File(context.cacheDir, "fileveil-v07-acceptance/interop").apply { mkdirs() }
            File(original, "output/sample.png").copyTo(File(artifacts, "android-marked.png"), overwrite = true)
            File(clean, "output/sample.png").copyTo(File(artifacts, "android-cleaned.png"), overwrite = true)
            File(artifacts, "android-verify.json").writeText(verified.toString(2))
            seed.fill(0)
        } finally { roots.forEach { it.deleteRecursively() } }
    }
    @Test fun desktopMarkAndroidVerify() {
        val root = task()
        try {
            val testContext = InstrumentationRegistry.getInstrumentation().context
            testContext.assets.open("desktop-marked.png").use { source -> File(root, "sample.png").outputStream().use { source.copyTo(it) } }
            val verified = call(root, "verify")
            assertTrue(verified.toString(), verified.getBoolean("ok"))
            val state = verified.getJSONObject("report").getJSONObject("advanced").getJSONObject("heritage").getJSONObject("verification")
            assertEquals("valid", state.getString("signature"))
            assertEquals("valid", state.getString("content_binding"))
            assertEquals("not_assessed", state.getString("trust"))
        } finally { root.deleteRecursively() }
    }
    @Test fun c2paOfflineCredentialScan() {
        val root = task()
        try {
            InstrumentationRegistry.getInstrumentation().context.assets.open("c2pa-signed.png").use { source -> File(root, "sample.png").outputStream().use { source.copyTo(it) } }
            val result = call(root, "scan")
            assertTrue(result.toString(), result.getBoolean("ok"))
            val report = result.getJSONObject("report")
            val credential = report.getJSONObject("provenance")
            assertEquals("valid", credential.getString("signature"))
            assertEquals("valid", credential.getString("asset_binding"))
            File(context.cacheDir, "fileveil-v07-acceptance/interop").apply { mkdirs() }.let { File(it, "android-c2pa-offline.json").writeText(result.toString(2)) }
        } finally { root.deleteRecursively() }
    }
    @Test fun evidenceExportAndVerify() {
        val root = task()
        val verify = task()
        val seed = ByteArray(32) { (it + 1).toByte() }
        try {
            InstrumentationRegistry.getInstrumentation().context.assets.open("desktop-marked.png").use { source -> File(root, "sample.png").outputStream().use { source.copyTo(it) } }
            val exported = call(root, "evidence_export", seed)
            assertTrue(exported.toString(), exported.getBoolean("ok"))
            File(root, "output/evidence.json").copyTo(File(verify, "evidence.json"))
            val verified = call(verify, "evidence_verify", inputName = "evidence.json")
            assertTrue(verified.toString(), verified.getBoolean("ok"))
            val artifacts = File(context.cacheDir, "fileveil-v07-acceptance/interop").apply { mkdirs() }
            File(root, "output/evidence.json").copyTo(File(artifacts, "android-evidence.json"), overwrite = true)
            File(artifacts, "android-evidence-verification.json").writeText(verified.toString(2))
        } finally { seed.fill(0); root.deleteRecursively(); verify.deleteRecursively() }
    }
    @Test fun keyedV2SignalMarkCleanRecheck() {
        val roots = mutableListOf<File>()
        val start = android.os.SystemClock.elapsedRealtime()
        try {
            val original = task().also(roots::add)
            val bitmap = Bitmap.createBitmap(512, 512, Bitmap.Config.ARGB_8888)
            val random = java.util.Random(42)
            val pixels = IntArray(512 * 512) { index ->
                val x = index % 512; val y = index / 512
                val value = (64 + (x + y) / 8 + random.nextInt(48)).coerceIn(24, 231)
                android.graphics.Color.rgb(value, (value + 19).coerceAtMost(250), (value + 7).coerceAtMost(250))
            }
            bitmap.setPixels(pixels, 0, 512, 0, 0, 512, 512)
            File(original, "sample.png").outputStream().use { bitmap.compress(Bitmap.CompressFormat.PNG, 100, it) }; bitmap.recycle()
            val seed = ByteArray(32) { (it + 1).toByte() }
            val markStart = android.os.SystemClock.elapsedRealtime()
            val marked = call(original, "mark", seed, robust = true)
            val markMs = android.os.SystemClock.elapsedRealtime() - markStart
            assertTrue(marked.toString(), marked.getBoolean("ok"))
            val verify = task().also(roots::add)
            File(original, "output/sample.png").copyTo(File(verify, "sample.png"))
            val verified = call(verify, "verify", seed)
            assertTrue(verified.toString(), verified.getBoolean("ok"))
            val clean = task().also(roots::add)
            File(verify, "sample.png").copyTo(File(clean, "sample.png"))
            val cleanStart = android.os.SystemClock.elapsedRealtime()
            val cleaned = call(clean, "clean", seed, cleanSignal = true)
            val cleanMs = android.os.SystemClock.elapsedRealtime() - cleanStart
            assertTrue(cleaned.toString(), cleaned.getBoolean("ok"))
            val recheck = task().also(roots::add)
            File(clean, "output/sample.png").copyTo(File(recheck, "sample.png"))
            val rechecked = call(recheck, "verify", seed)
            assertTrue(rechecked.toString(), rechecked.getBoolean("ok"))
            val artifacts = File(context.cacheDir, "fileveil-v07-acceptance/interop").apply { mkdirs() }
            File(original, "sample.png").copyTo(File(artifacts, "android-v2-original.png"), overwrite = true)
            File(original, "output/sample.png").copyTo(File(artifacts, "android-v2-marked.png"), overwrite = true)
            File(clean, "output/sample.png").copyTo(File(artifacts, "android-v2-cleaned.png"), overwrite = true)
            File(artifacts, "android-v2-results.json").writeText(JSONObject().put("mark", marked).put("verify", verified).put("clean", cleaned).put("recheck", rechecked)
                .put("mark_ms", markMs).put("clean_ms", cleanMs).put("elapsed_ms", android.os.SystemClock.elapsedRealtime() - start)
                .put("vm_hwm", File("/proc/self/status").readLines().firstOrNull { it.startsWith("VmHWM:") }).toString(2))
            seed.fill(0)
        } finally { roots.forEach { it.deleteRecursively() } }
    }
    @Test fun wrappedIdentityRoundTrip() {
        // A separate alias and directory never inspect, create or replace the
        // currently installed user's production signing identity.
        val directory = File(context.cacheDir, "test-identity-${UUID.randomUUID()}").apply { mkdir() }
        val isolated = object : android.content.ContextWrapper(context) { override fun getNoBackupFilesDir(): File = directory }
        val alias = "fileveil.test.wrap.${UUID.randomUUID()}"
        try {
            val store = IdentityStore(isolated, alias)
            store.create()
            val first = store.unlock()
            val second = store.unlock()
            assertEquals(32, first.size)
            assertArrayEquals(first, second)
            first.fill(0); second.fill(0)
        } finally {
            directory.deleteRecursively()
            java.security.KeyStore.getInstance("AndroidKeyStore").apply { load(null); deleteEntry(alias) }
        }
    }
    @Test fun concurrentIdentityCreationCannotReplaceSeed() {
        val directory = File(context.cacheDir, "test-identity-${UUID.randomUUID()}").apply { mkdir() }
        val isolated = object : android.content.ContextWrapper(context) { override fun getNoBackupFilesDir(): File = directory }
        val alias = "fileveil.test.concurrent.${UUID.randomUUID()}"
        val start = java.util.concurrent.CyclicBarrier(2)
        val successes = java.util.concurrent.atomic.AtomicInteger()
        val executor = java.util.concurrent.Executors.newFixedThreadPool(2)
        try {
            val calls = (0..1).map { executor.submit { start.await(); try { IdentityStore(isolated, alias).create(); successes.incrementAndGet() } catch (_: IllegalStateException) { } } }
            calls.forEach { it.get(5, java.util.concurrent.TimeUnit.SECONDS) }
            assertEquals(1, successes.get())
            val first = IdentityStore(isolated, alias).unlock()
            try { IdentityStore(isolated, alias).create(); fail("Existing identity replaced") } catch (_: IllegalStateException) { }
            val second = IdentityStore(isolated, alias).unlock()
            assertArrayEquals(first, second)
            first.fill(0); second.fill(0)
        } finally {
            executor.shutdownNow(); directory.deleteRecursively()
            java.security.KeyStore.getInstance("AndroidKeyStore").apply { load(null); deleteEntry(alias) }
        }
    }
    @Test fun pathTraversalRejected() {
        val root = task()
        try {
            val request = "{\"action\":\"scan\",\"input\":\"../secret\"}".toByteArray()
            val result = JSONObject(NativeEngine.request(root.absolutePath.toByteArray(), request, null).toString(Charsets.UTF_8))
            assertFalse(result.getBoolean("ok"))
        } finally { root.deleteRecursively() }
    }
    @Test fun unicodeNamesAndActualOutputBudget() {
        val name = safeDisplayName("标".repeat(200) + ".docx")
        assertTrue(name.toByteArray(Charsets.UTF_8).size <= 180)
        assertTrue(name.endsWith(".docx"))
        assertFalse(safeDisplayName("../output").contains('/'))
        assertNotEquals("output", safeDisplayName("output"))
        val root = task()
        try {
            val expanded = File(root, "expanded.png").apply { writeBytes(ByteArray(8192)) }
            assertEquals(8195L, boundedPublicationBytes(listOf(expanded), ByteArray(3)))
            try { boundedPublicationBytes(List(9) { expanded }, ByteArray(3)); fail("Excess results accepted") } catch (_: IllegalStateException) { }
        } finally { root.deleteRecursively() }
    }
    @Test fun unresponsiveProviderWorkerIsBounded() {
        val entered = java.util.concurrent.CountDownLatch(1)
        val release = java.util.concurrent.CountDownLatch(1)
        val started = android.os.SystemClock.elapsedRealtime()
        try {
            try {
                ProviderIo.bounded(timeoutMs = 200) { scope ->
                    entered.countDown()
                    while (release.count != 0L) { try { release.await() } catch (_: InterruptedException) { /* Deliberately noncooperative provider control. */ } }
                    scope.check()
                }
                fail("Unresponsive provider did not time out")
            } catch (_: java.io.IOException) { }
            assertEquals(0L, entered.count)
            assertTrue(android.os.SystemClock.elapsedRealtime() - started < 2000)
            try { ProviderIo.bounded(timeoutMs = 100) { true }; fail("A second stuck provider worker was admitted") } catch (_: java.io.IOException) { }
        } finally { release.countDown() }
    }
}

// FVPROV1 14112 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiI4MjYyMmJkODUzZDJmZDMwMmZmOTM3Mjc3ZGVkMWZlMGVmNDM0YmExN2MxYzM1YzQwZGI5ZWI5MDVkMjQ1MGY1IiwiY29weV9pZCI6InYwLjcuMC1iZXRhLjEiLCJjcmVhdGVkX2F0IjoiMjAyNi0xMS0xNSIsImVkaXRpb24iOiJiZXRhIiwiaXNzdWVyX3BvbGljeSI6bnVsbCwia2luZCI6ImNyZWF0ZSIsIm1vZGUiOiJzZWxmX3NpZ24iLCJwYXJlbnRfdmVyc2lvbiI6bnVsbCwicHJldmlvdXNfcmVjb3JkX3NoYTI1NiI6bnVsbCwic2NoZW1hIjoiZmlsZXZlaWwucHJvdmVuYW5jZS5zaWduYXR1cmUudjIiLCJzZXF1ZW5jZSI6MCwidHJhbnNmZXJfdG9fa2V5X2lkIjpudWxsLCJ2ZXJzaW9uIjoidjAuNy4wLWJldGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2FuZHJvaWQvYXBwL3NyYy9hbmRyb2lkVGVzdC9qYXZhL3N0dWRpby9mYWxsZW5zdGFyL2ZpbGV2ZWlsL0VuZ2luZUludGVyb3BUZXN0Lmt0In0sInNpZ25hdHVyZXMiOlt7ImtleV9pZCI6Ijk5ZWE2M2VmY2NmZDBmZGJkNjhlMTZlZDhmMDNkMzM3ZjE1ZWMyZTRhNmEzZDY0ZTExZDcxNGVhMWU1NDI1MzMiLCJwdWJsaWNfa2V5X2hleCI6ImFkYjNlMTdjZDEyZjk1NmQwMDcwZTE2NjNmNTMxNTM3ZmNlZGY3MzA4ZDAxNjU4ZmVhNDU2ZmVlYThmN2ZiYzUiLCJzaWduYXR1cmVfaGV4IjoiZDI5YTBjMDQ5ZGNjMDA1MGJjMjU5OGUwZjQxNTYzMmM5YWVhMTE1ZGViYjVkODQ5MDVlYmY5NmNiMjQxOWIzNTA5NGVjYTY0YTdkOTE2ZGY5YThmYzA5MDIzZWZhYTQyY2FkODhkZWJiNWIzZWE3MWUxNDAzZjRjZDY0MmQ4MDcifV19XQ== FVPROV1-END
