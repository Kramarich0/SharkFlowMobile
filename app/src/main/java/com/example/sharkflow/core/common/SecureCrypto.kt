package com.example.sharkflow.core.common

import android.content.Context
import android.util.Base64
import androidx.core.content.edit
import com.example.sharkflow.core.system.AppLog
import com.google.crypto.tink.Aead
import com.google.crypto.tink.aead.*
import com.google.crypto.tink.integration.android.AndroidKeysetManager
import java.nio.charset.StandardCharsets
import java.security.GeneralSecurityException
import java.security.InvalidKeyException
import kotlin.text.Charsets

object SecureCrypto {
    private lateinit var aead: Aead

    @Volatile
    private var initialized = false

    fun init(context: Context) {
        if (initialized) return
        synchronized(this) {
            if (initialized) return

            var attempts = 0
            while (!initialized && attempts < 2) {
                try {
                    AeadConfig.register()
                    val keysetManager = AndroidKeysetManager.Builder()
                        .withSharedPref(context, "tink_keyset", "tink_key_prefs")
                        .withKeyTemplate(AeadKeyTemplates.AES256_GCM)
                        .withMasterKeyUri("android-keystore://tink_master_key")
                        .build()

                    aead = keysetManager.keysetHandle.getPrimitive(Aead::class.java) as Aead
                    initialized = true
                } catch (e: InvalidKeyException) {
                    AppLog.w("Keystore key missing or invalid, recreating...", e)
                    context.getSharedPreferences("tink_key_prefs", Context.MODE_PRIVATE)
                        .edit { clear() }
                    attempts++
                } catch (e: Exception) {
                    AppLog.e("SecureCrypto init failed", e)
                    break
                }
            }

            if (!initialized) {
                AppLog.e("SecureCrypto could not be initialized after $attempts attempts")
            }
        }
    }

    private fun ensureInit() {
        if (!initialized) throw IllegalStateException("SecureCrypto is not initialized")
    }

    fun encrypt(plainText: String, associatedData: ByteArray? = null): ByteArray {
        ensureInit()
        return aead.encrypt(
            plainText.toByteArray(Charsets.UTF_8),
            associatedData ?: ByteArray(0)
        )
    }

    fun decrypt(cipherText: ByteArray, associatedData: ByteArray? = null): String {
        ensureInit()
        if (cipherText.isEmpty()) throw IllegalArgumentException("Ciphertext cannot be empty")
        
        return try {
            val pt = aead.decrypt(cipherText, associatedData ?: ByteArray(0))
            String(pt, Charsets.UTF_8)
        } catch (e: GeneralSecurityException) {
            AppLog.e("Decryption failed", e)
            throw e
        }
    }

    fun encryptToBase64(plainText: String, associatedData: ByteArray? = null): String {
        val cipher = encrypt(plainText, associatedData)
        return Base64.encodeToString(cipher, Base64.NO_WRAP)
    }

    fun decryptFromBase64(base64: String, associatedData: ByteArray? = null): String {
        val cipher = Base64.decode(base64, Base64.NO_WRAP)
        return decrypt(cipher, associatedData)
    }
}
