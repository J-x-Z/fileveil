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

