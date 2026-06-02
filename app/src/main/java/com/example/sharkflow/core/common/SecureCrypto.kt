package com.example.sharkflow.core.common

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import android.util.Base64

/**
 * Singleton object providing secure AES-GCM encryption and decryption using the Android Keystore system.
 */
object SecureCrypto {
    private const val KEY_ALIAS = "SharkFlowKey"
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val AES_GCM_NO_PADDING = "AES/GCM/NoPadding"
    private const val IV_LENGTH = 12

    /**
     * Retrieves the existing AES secret key from the Android Keystore or generates a new one if it does not exist.
     *
     * @return {SecretKey} The persistent AES key.
     * @throws {Exception} If Keystore operations or key generation fail.
     */
    private fun getSecretKey(): SecretKey {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        return if (keyStore.containsAlias(KEY_ALIAS)) {
            (keyStore.getEntry(KEY_ALIAS, null) as KeyStore.SecretKeyEntry).secretKey
        } else {
            val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
            keyGenerator.init(
                KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .build()
            )
            keyGenerator.generateKey()
        }
    }

    /**
     * Encrypts a plaintext string using AES-GCM, prepending the initialization vector (IV) to the output.
     *
     * @param {String} data The plaintext string to encrypt.
     * @return {String} The Base64-encoded string containing the IV and ciphertext.
     * @throws {Exception} If encryption fails or the cipher cannot be initialized.
     */
    fun encrypt(data: String): String {
        val cipher = Cipher.getInstance(AES_GCM_NO_PADDING)
        cipher.init(Cipher.ENCRYPT_MODE, getSecretKey())
        val iv = cipher.iv
        val encrypted = cipher.doFinal(data.toByteArray())
        val combined = iv + encrypted
        return Base64.encodeToString(combined, Base64.DEFAULT)
    }

    /**
     * Decrypts a Base64-encoded string containing an IV and AES-GCM ciphertext.
     *
     * @param {String} encryptedData The Base64-encoded string to decrypt.
     * @return {String} The original plaintext string.
     * @throws {Exception} If decryption fails, the data is malformed, or the tag validation fails.
     */
    fun decrypt(encryptedData: String): String {
        val combined = Base64.decode(encryptedData, Base64.DEFAULT)
        val iv = combined.sliceArray(0 until IV_LENGTH)
        val encrypted = combined.sliceArray(IV_LENGTH until combined.size)
        val cipher = Cipher.getInstance(AES_GCM_NO_PADDING)
        cipher.init(Cipher.DECRYPT_MODE, getSecretKey(), GCMParameterSpec(128, iv))
        return String(cipher.doFinal(encrypted))
    }
}