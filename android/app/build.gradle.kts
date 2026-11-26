plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
}

// The version the core reports is the workspace version, so the test compares against Cargo.toml.
val coreVersion = Regex("""\[workspace\.package\][^\[]*?^version\s*=\s*"([^"]+)"""", RegexOption.MULTILINE)
    .find(rootProject.file("../Cargo.toml").readText())!!.groupValues[1]

android {
    namespace = "com.lazymail.lazymail"
    compileSdk = 37

    defaultConfig {
        applicationId = "com.lazymail.lazymail"
        minSdk = 26
        targetSdk = 37
        versionCode = 1
        versionName = coreVersion
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        buildConfigField("String", "CORE_VERSION", "\"$coreVersion\"")
        ndk {
            abiFilters += setOf("arm64-v8a", "x86_64")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        buildConfig = true
        compose = true
    }
}

dependencies {
    implementation(platform(libs.compose.bom))
    implementation(libs.compose.ui)
    implementation(libs.compose.material3)
    implementation(libs.activity.compose)
    implementation("${libs.jna.get()}@aar")

    debugImplementation(libs.compose.ui.test.manifest)

    androidTestImplementation(platform(libs.compose.bom))
    androidTestImplementation(libs.compose.ui.test.junit4)
    androidTestImplementation(libs.androidx.test.runner)
    androidTestImplementation(libs.androidx.test.ext.junit)
}
