package com.lazymail.lazymail

import androidx.compose.ui.test.assertTextEquals
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithTag
import org.junit.Assert.assertFalse
import org.junit.Rule
import org.junit.Test

class CoreVersionTest {
    @get:Rule
    val rule = createAndroidComposeRule<MainActivity>()

    @Test
    fun showsTheCoreVersion() {
        assertFalse(BuildConfig.CORE_VERSION.isEmpty())
        rule.onNodeWithTag("CoreVersion").assertTextEquals(BuildConfig.CORE_VERSION)
    }
}
