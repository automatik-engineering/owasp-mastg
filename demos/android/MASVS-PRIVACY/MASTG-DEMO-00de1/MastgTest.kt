package org.owasp.mastestapp

import android.content.Context
import com.google.firebase.analytics.FirebaseAnalytics
import com.google.firebase.analytics.logEvent

class MastgTest(context: Context) {

    val analytics = FirebaseAnalytics.getInstance(context)

    fun mastgTest(userInput: String): String {
        analytics.logEvent("start_test") {
            param("input", userInput)
        }

        return "'start_test' event was sent to Firebase Analytics with user input: $userInput"
    }
}