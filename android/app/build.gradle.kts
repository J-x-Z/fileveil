// SPDX-License-Identifier: MPL-2.0
plugins { id("com.android.application"); id("org.jetbrains.kotlin.android") }
dependencyLocking { lockAllConfigurations() }
android {
    namespace = "studio.fallenstar.fileveil"
    compileSdk = 34
    ndkVersion = "25.1.8937393"
    defaultConfig {
        applicationId = "studio.fallenstar.fileveil"
        minSdk = 26
        targetSdk = 34
        versionCode = 7001
        versionName = "0.7.0-beta.1"
        ndk { abiFilters += "arm64-v8a" }
        externalNativeBuild { cmake { arguments += "-DANDROID_STL=none" } }
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }
    buildFeatures { compose = true; buildConfig = true }
    composeOptions { kotlinCompilerExtensionVersion = "1.5.14" }
    compileOptions { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }
    kotlinOptions { jvmTarget = "17" }
    externalNativeBuild { cmake { path = file("src/main/cpp/CMakeLists.txt"); version = "3.22.1" } }
    packaging { jniLibs { useLegacyPackaging = false } }
    buildTypes { release { isMinifyEnabled = false } }
    sourceSets.getByName("main").assets.srcDir(layout.buildDirectory.dir("generated/licenseAssets"))
}
val packageLicenses by tasks.registering(Sync::class) {
    into(layout.buildDirectory.dir("generated/licenseAssets"))
    from("../../LICENSE") { rename { "fileveil-license.txt" } }
    from("../../THIRD_PARTY_NOTICES.txt")
    from("../ANDROID_NOTICES.txt")
    from("../../assets/licenses") { into("third-party-licenses") }
}
tasks.named("preBuild").configure { dependsOn(packageLicenses) }
dependencies {
    implementation(platform("androidx.compose:compose-bom:2024.06.00"))
    implementation("androidx.activity:activity-compose:1.9.0")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.3")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.3")
    implementation("androidx.documentfile:documentfile:1.0.1")
    implementation("androidx.core:core-ktx:1.13.1")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("androidx.test:runner:1.6.1")
}


// FVPROV1 2334 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiJhMDc5OGQyNTgwOWU0NzFlOGUwOWFhOGVlNTE1ZDY2MDE2ZGZjYTg0MDU2MmQxNzgwZTgyZTA3YzJiNTMwY2M3IiwiY29weV9pZCI6InYwLjcuMC1iZXRhLjEiLCJjcmVhdGVkX2F0IjoiMjAyNi0xMS0xNSIsImVkaXRpb24iOiJiZXRhIiwiaXNzdWVyX3BvbGljeSI6bnVsbCwia2luZCI6ImNyZWF0ZSIsIm1vZGUiOiJzZWxmX3NpZ24iLCJwYXJlbnRfdmVyc2lvbiI6bnVsbCwicHJldmlvdXNfcmVjb3JkX3NoYTI1NiI6bnVsbCwic2NoZW1hIjoiZmlsZXZlaWwucHJvdmVuYW5jZS5zaWduYXR1cmUudjIiLCJzZXF1ZW5jZSI6MCwidHJhbnNmZXJfdG9fa2V5X2lkIjpudWxsLCJ2ZXJzaW9uIjoidjAuNy4wLWJldGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2FuZHJvaWQvYXBwL2J1aWxkLmdyYWRsZS5rdHMifSwic2lnbmF0dXJlcyI6W3sia2V5X2lkIjoiOTllYTYzZWZjY2ZkMGZkYmQ2OGUxNmVkOGYwM2QzMzdmMTVlYzJlNGE2YTNkNjRlMTFkNzE0ZWExZTU0MjUzMyIsInB1YmxpY19rZXlfaGV4IjoiYWRiM2UxN2NkMTJmOTU2ZDAwNzBlMTY2M2Y1MzE1MzdmY2VkZjczMDhkMDE2NThmZWE0NTZmZWVhOGY3ZmJjNSIsInNpZ25hdHVyZV9oZXgiOiIyOWRmOTY1YjBjOTFjNzg2MWQyODAyMGZkMTE4MTE1OTZjOWJlZjdjNWM2YjU5MjBhNzZiMjYzNjI4MzRmZmUwZWJmYmZlZDdjYjU2NjM3MjExYmRlYWI5Y2Q4NzllY2YwYmI2ODZmMDI3Y2NjYmM3ODFmYTFlMmNkYzE2NGYwYyJ9XX1d FVPROV1-END
