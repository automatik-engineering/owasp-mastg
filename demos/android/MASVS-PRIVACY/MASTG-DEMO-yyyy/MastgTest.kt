package org.owasp.mastestapp

import android.content.Context
import android.os.Bundle
import com.google.firebase.analytics.FirebaseAnalytics

class MastgTest(private val context: Context) {

    fun mastgTest(): String {
        val sensitiveString = "d3a447630194bd4b"
        val email = "user@example.com"
        val firstLast = "John Doe"
        val arbitraryUserId = "user12345"

        val analytics = FirebaseAnalytics.getInstance(context)

        // Test 1: logEvent with bundle
        val eventBundle = Bundle().apply {
            putString("user_email", email)
            putString("full_name", firstLast)
        }
        analytics.logEvent("event_name", eventBundle)

        // Test 2: setUserProperty
        analytics.apply {
            setUserProperty("name", firstLast)
            setUserProperty("email", email)
        }

        // Test 3: setUserId
        analytics.setUserId(arbitraryUserId)

        // Test 4: setDefaultEventParameters
        val defaultBundle = Bundle().apply {
            putString("default_key", sensitiveString)
        }
        analytics.setDefaultEventParameters(defaultBundle)

        return """Sensitive data:
			Email: $email
			Full Name: $firstLast
			User ID: $arbitraryUserId
			Sensitive String: $sensitiveString
			""".trimIndent()
    }
}