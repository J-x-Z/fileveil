// SPDX-License-Identifier: MPL-2.0
package studio.fallenstar.fileveil

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.widget.TextView
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.security.MessageDigest

/** Local test recipient. It has a distinct package UID and can read only the
 * explicit FileProvider grant delivered by the real Android share chooser. */
class ShareProbeActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val result = JSONObject().put("schema", "fileveil.android.share-probe.v1")
        try {
            @Suppress("DEPRECATION")
            val uris = intent.getParcelableArrayListExtra<Uri>(Intent.EXTRA_STREAM) ?: error("No shared files")
            check(uris.isNotEmpty() && uris.size <= 16)
            val rows = JSONArray()
            for (uri in uris) {
                check(uri.scheme == "content" && uri.authority == "studio.fallenstar.fileveil.files")
                val hash = MessageDigest.getInstance("SHA-256")
                var total = 0L
                contentResolver.openInputStream(uri)?.use { input ->
                    val buffer = ByteArray(65536)
                    while (true) { val count = input.read(buffer); if (count < 0) break; total += count; check(total <= 64L * 1024 * 1024); hash.update(buffer, 0, count) }
                } ?: error("Shared URI could not be opened")
                rows.put(JSONObject().put("bytes", total).put("sha256", hash.digest().joinToString("") { "%02x".format(it.toInt() and 255) }))
            }
            result.put("readable", true).put("files", rows)
        } catch (error: Exception) { result.put("readable", false).put("error_type", error.javaClass.simpleName) }
        File(filesDir, "share-probe.json").writeText(result.toString(2))
        setContentView(TextView(this).apply { text = "FileVeil Share Test\n\n" + result.toString(2); textSize = 16f; setPadding(32, 48, 32, 32) })
    }
}
