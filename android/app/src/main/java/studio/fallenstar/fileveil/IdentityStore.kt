// SPDX-License-Identifier: MPL-2.0
package studio.fallenstar.fileveil

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.File
import java.io.FileOutputStream
import java.nio.channels.OverlappingFileLockException
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** Ed25519 seed stays in app-private storage wrapped by a nonexportable AES key.
 * Reinstall/device loss does not silently create a substitute identity. */
class IdentityStore internal constructor(private val context: Context, private val alias: String = "fileveil.ed25519.wrap.v1") {
    private val envelope get() = File(context.noBackupFilesDir, "identity-v1.aesgcm")
    val exists get() = envelope.isFile
    private fun wrappingKey(create: Boolean): SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (store.getKey(alias, null) as? SecretKey)?.let { return it }
        check(create) { "The system wrapping key is unavailable; the original identity cannot be recovered." }
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply {
            init(KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256).setRandomizedEncryptionRequired(true).build())
        }.generateKey()
    }
    @Synchronized fun create() {
        // A JVM monitor only protects this instance. Separate Activity models
        // must not race the final rename and replace an already-created seed.
        FileOutputStream(File(context.noBackupFilesDir, "identity-v1.lock"), true).channel.use { channel ->
            val lock = try { channel.tryLock() } catch (_: OverlappingFileLockException) { null }
            check(lock != null) { "Another identity creation is already running" }
            lock.use { createLocked() }
        }
    }
    private fun createLocked() {
        check(!exists) { "An identity already exists" }
        val seed = ByteArray(32).also { SecureRandom().nextBytes(it) }
        try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, wrappingKey(true))
            cipher.updateAAD(alias.toByteArray(Charsets.UTF_8))
            val encoded = byteArrayOf(1) + cipher.iv + cipher.doFinal(seed)
            val temp = File.createTempFile("identity-", ".tmp", context.noBackupFilesDir)
            try {
                temp.outputStream().use { it.write(encoded); it.fd.sync() }
                check(temp.renameTo(envelope)) { "Could not persist the wrapped identity" }
            } finally { temp.delete() }
        } finally { seed.fill(0) }
    }
    @Synchronized fun unlock(): ByteArray {
        check(envelope.length() == 61L) { "Invalid wrapped identity length" }
        val encoded = envelope.readBytes()
        check(encoded.size == 61 && encoded[0].toInt() == 1) { "Invalid wrapped identity" }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, wrappingKey(false), GCMParameterSpec(128, encoded.copyOfRange(1, 13)))
        cipher.updateAAD(alias.toByteArray(Charsets.UTF_8))
        return cipher.doFinal(encoded.copyOfRange(13, encoded.size)).also { check(it.size == 32) }
    }
}


// FVPROV1 3619 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiI2NTk0N2NjOGZhOTZkNWI5MjNlM2RhNWRmY2U0NjNkYWQxMTY4ZWRhOGQ0YWFiNGMwNDljYjA4NWYwYTg4ZWY3IiwiY29weV9pZCI6InYwLjcuMC1iZXRhLjEiLCJjcmVhdGVkX2F0IjoiMjAyNi0xMS0xNSIsImVkaXRpb24iOiJiZXRhIiwiaXNzdWVyX3BvbGljeSI6bnVsbCwia2luZCI6ImNyZWF0ZSIsIm1vZGUiOiJzZWxmX3NpZ24iLCJwYXJlbnRfdmVyc2lvbiI6bnVsbCwicHJldmlvdXNfcmVjb3JkX3NoYTI1NiI6bnVsbCwic2NoZW1hIjoiZmlsZXZlaWwucHJvdmVuYW5jZS5zaWduYXR1cmUudjIiLCJzZXF1ZW5jZSI6MCwidHJhbnNmZXJfdG9fa2V5X2lkIjpudWxsLCJ2ZXJzaW9uIjoidjAuNy4wLWJldGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2FuZHJvaWQvYXBwL3NyYy9tYWluL2phdmEvc3R1ZGlvL2ZhbGxlbnN0YXIvZmlsZXZlaWwvSWRlbnRpdHlTdG9yZS5rdCJ9LCJzaWduYXR1cmVzIjpbeyJrZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwicHVibGljX2tleV9oZXgiOiJhZGIzZTE3Y2QxMmY5NTZkMDA3MGUxNjYzZjUzMTUzN2ZjZWRmNzMwOGQwMTY1OGZlYTQ1NmZlZWE4ZjdmYmM1Iiwic2lnbmF0dXJlX2hleCI6IjQyZTNhNmJiYzIwNzg2YTk3MmVjNjM2MGQ4MmIwOGI2ZDZhYzIxOGFmZDcxODIyNjg3Nzc5Y2M0NmFmYjlmNjFkOTFhYWY1YjAzNjkwMzM5YTRjYjk4MTEyMzNiNmQ0ZGY4MmJjZDZiOWU4ZTJlOGExMjJlMDdlYTVlZDgyNDBjIn1dfV0= FVPROV1-END
