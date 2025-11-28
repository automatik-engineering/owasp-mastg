package org.owasp.mastestapp

import android.content.Context
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.Security

// SUMMARY: This sample demonstrates various ways of specifying security providers in getInstance calls, both insecure (hardcoded) and secure (default or AndroidKeyStore).

class MastgTest (private val context: Context){

    fun mastgTest(): String {
        val results = StringBuilder()

        // PASS: [MASTG-TEST-0307] Using default provider (AndroidOpenSSL/Conscrypt) - no provider specified
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        results.append("Default Cipher provider: ${cipher.provider.name}\n")

        // FAIL: [MASTG-TEST-0307] Explicitly specifying BouncyCastle provider - deprecated in Android 9, removed in Android 12
        val cipherBC = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC")
        // FAIL: [MASTG-TEST-0307] Explicitly specifying SunJCE provider - not available on Android
        val cipherSun = Cipher.getInstance("AES/CBC/PKCS5Padding", "SunJCE")
        // FAIL: [MASTG-TEST-0307] Explicitly specifying a custom provider
        val cipherCustom = Cipher.getInstance("AES/CBC/PKCS5Padding", "CustomProvider")

        // PASS: [MASTG-TEST-0307] AndroidKeyStore is allowed as provider for KeyStore
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        results.append("KeyStore provider: ${keyStore.provider.name}\n")

        // PASS: [MASTG-TEST-0307] Using default provider for KeyGenerator
        val keyGen = KeyGenerator.getInstance("AES")
        results.append("KeyGenerator provider: ${keyGen.provider.name}\n")

        // PASS: [MASTG-TEST-0307] Using default provider for MessageDigest
        val digest = MessageDigest.getInstance("SHA-256")
        results.append("MessageDigest provider: ${digest.provider.name}\n")

        return results.toString()
    }

}
