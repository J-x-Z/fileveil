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

// FVPROV1 2093 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiI5NzU4MmZiN2U2OGZkNzViZjczY2RlM2IzZTM0ZmVmNTAxZGE5MjcxYjg3MzcxZGRjYzlkMTZkY2JiN2QxMjYzIiwiY29weV9pZCI6InYwLjcuMC1iZXRhLjEiLCJjcmVhdGVkX2F0IjoiMjAyNi0xMS0xNSIsImVkaXRpb24iOiJiZXRhIiwiaXNzdWVyX3BvbGljeSI6bnVsbCwia2luZCI6ImNyZWF0ZSIsIm1vZGUiOiJzZWxmX3NpZ24iLCJwYXJlbnRfdmVyc2lvbiI6bnVsbCwicHJldmlvdXNfcmVjb3JkX3NoYTI1NiI6bnVsbCwic2NoZW1hIjoiZmlsZXZlaWwucHJvdmVuYW5jZS5zaWduYXR1cmUudjIiLCJzZXF1ZW5jZSI6MCwidHJhbnNmZXJfdG9fa2V5X2lkIjpudWxsLCJ2ZXJzaW9uIjoidjAuNy4wLWJldGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2FuZHJvaWQvYXBwL3NyYy9hbmRyb2lkVGVzdC9qYXZhL3N0dWRpby9mYWxsZW5zdGFyL2ZpbGV2ZWlsL1NoYXJlUHJvYmVBY3Rpdml0eS5rdCJ9LCJzaWduYXR1cmVzIjpbeyJrZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwicHVibGljX2tleV9oZXgiOiJhZGIzZTE3Y2QxMmY5NTZkMDA3MGUxNjYzZjUzMTUzN2ZjZWRmNzMwOGQwMTY1OGZlYTQ1NmZlZWE4ZjdmYmM1Iiwic2lnbmF0dXJlX2hleCI6IjZlOWRkNTZkYzQ3YzVjOWFiMjIwNzk5MWQ0MWVlYmE1MGVkYmE5MmE4ZGExNzYyNGUyNmExY2NhYTFlMWRhMGIyZTQ1OWEwYjBjOTc0YWM5NTIwNGI4ZWI3MzMxMDViNjE0NmY0Y2JlNWRlZWUxNTYyMWU1NDBhNDljZWRlZjBjIn1dfV0= FVPROV1-END
