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

// FVPROV1 1576 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiI1NjA3YThmZDBiNThlNDk3NjQwMTU2YTQ3M2E3NDU2YThjOWY2ZGQyMjgxOTU2NTI2MjlmMTliYmVlZjE2MGFlIiwiY29weV9pZCI6InYwLjcuMC1iZXRhLjEiLCJjcmVhdGVkX2F0IjoiMjAyNi0xMS0xNSIsImVkaXRpb24iOiJiZXRhIiwiaXNzdWVyX3BvbGljeSI6bnVsbCwia2luZCI6ImNyZWF0ZSIsIm1vZGUiOiJzZWxmX3NpZ24iLCJwYXJlbnRfdmVyc2lvbiI6bnVsbCwicHJldmlvdXNfcmVjb3JkX3NoYTI1NiI6bnVsbCwic2NoZW1hIjoiZmlsZXZlaWwucHJvdmVuYW5jZS5zaWduYXR1cmUudjIiLCJzZXF1ZW5jZSI6MCwidHJhbnNmZXJfdG9fa2V5X2lkIjpudWxsLCJ2ZXJzaW9uIjoidjAuNy4wLWJldGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2FuZHJvaWQvYXBwL3NyYy9tYWluL2phdmEvc3R1ZGlvL2ZhbGxlbnN0YXIvZmlsZXZlaWwvUmVzdWx0RmlsZXMua3QifSwic2lnbmF0dXJlcyI6W3sia2V5X2lkIjoiOTllYTYzZWZjY2ZkMGZkYmQ2OGUxNmVkOGYwM2QzMzdmMTVlYzJlNGE2YTNkNjRlMTFkNzE0ZWExZTU0MjUzMyIsInB1YmxpY19rZXlfaGV4IjoiYWRiM2UxN2NkMTJmOTU2ZDAwNzBlMTY2M2Y1MzE1MzdmY2VkZjczMDhkMDE2NThmZWE0NTZmZWVhOGY3ZmJjNSIsInNpZ25hdHVyZV9oZXgiOiI1YzVjOGNkNjdlMDQ2NmEzZjZmMWFmMzU2MWNhOWEwYThmODRhYjJlNGZlNDEyN2ZjNDk2MTQ3MjIzOTY0NTYzNjA3MWYxYWZmMmZlY2MyZDIzMDMwNzAxOWY4NWQxMDI5MjY1NzcxOTYwNGNkYmZmOGFlOGFiMjIxNjY1ZjQwOCJ9XX1d FVPROV1-END
