// SPDX-License-Identifier: MPL-2.0
package studio.fallenstar.fileveil

import java.io.File

internal fun safeDisplayName(raw: String): String {
    val normalized = raw.replace(Regex("[^\\p{L}\\p{M}\\p{N} ._()-]"), "_")
        .takeIf { it.isNotBlank() && it != "." && it != ".." } ?: "input.bin"
    val suffix = normalized.substringAfterLast('.', "").takeIf { it.matches(Regex("[A-Za-z0-9]{1,16}")) }?.let { ".$it" } ?: ""
    val body = if (suffix.isEmpty()) normalized else normalized.removeSuffix(suffix)
    val bounded = StringBuilder()
    var bytes = suffix.toByteArray(Charsets.UTF_8).size
    var position = 0
    while (position < body.length) {
        val point = body.codePointAt(position)
        val piece = String(Character.toChars(point))
        val size = piece.toByteArray(Charsets.UTF_8).size
        if (bytes + size > 180) break
        bounded.append(piece); bytes += size; position += Character.charCount(point)
    }
    val name = bounded.toString().ifBlank { "input" } + suffix
    return if (name in listOf("output", ".signing-key")) "input-$name" else name
}

internal fun boundedPublicationBytes(outputs: List<File>, report: ByteArray): Long {
    check(outputs.size <= 8) { "Unexpected result count" }
    check(report.size <= 4 * 1024 * 1024) { "Report exceeds the mobile limit" }
    var total = report.size.toLong()
    for (output in outputs) {
        check(output.isFile && output.length() <= 64L * 1024 * 1024) { "Result exceeds the mobile file limit" }
        total = Math.addExact(total, output.length())
    }
    return total
}
