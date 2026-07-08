// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.kotlinMultiplatform)
    alias(libs.plugins.android.kotlin.multiplatform.library)
    alias(libs.plugins.vanniktech.mavenPublish)
}

group = "org.nirapod"
version = "0.1.0-SNAPSHOT"

kotlin {
    // Suppress the KT-61573 Beta notice for the intentional expect/actual classes.
    compilerOptions {
        freeCompilerArgs.add("-Xexpect-actual-classes")
    }

    androidLibrary {
        namespace = "org.nirapod.signet"
        compileSdk = libs.versions.android.compileSdk.get().toInt()
        minSdk = libs.versions.android.minSdk.get().toInt()

        withHostTestBuilder {}.configure {}
        withDeviceTestBuilder {
            sourceSetTreeName = "test"
        }

        compilerOptions {
            jvmTarget = JvmTarget.JVM_11
        }
    }

    iosArm64()
    iosSimulatorArm64()
    macosArm64()

    sourceSets {
        val androidMain by getting {
            // Compile the android/ core in-module. commonMain owns the KMP contract
            // types under org.nirapod.signet.kmp; the core keeps its own
            // org.nirapod.signet types in a separate package, and androidMain
            // translates between them.
            kotlin.srcDir("../../android/src/main/kotlin")
            dependencies {
                implementation(libs.androidx.biometric)
                implementation(libs.kotlinx.coroutines.android)
            }
        }
        commonMain.dependencies {
            implementation(libs.kotlinx.coroutines.core)
        }
        commonTest.dependencies {
            implementation(libs.kotlin.test)
        }
    }
}

mavenPublishing {
    publishToMavenCentral()
    signAllPublications()

    coordinates(group.toString(), "signet", version.toString())

    pom {
        name = "Signet"
        description = "Hardware-backed P-256 signing keys via Secure Enclave and StrongBox/TEE."
        inceptionYear = "2026"
        url = "https://github.com/nirapod-labs/signet/"
        licenses {
            license {
                name = "Apache-2.0"
                url = "https://www.apache.org/licenses/LICENSE-2.0"
                distribution = "https://www.apache.org/licenses/LICENSE-2.0"
            }
        }
        developers {
            developer {
                id = "athexweb3"
                name = "athexweb3"
                url = "https://github.com/athexweb3"
            }
        }
        scm {
            url = "https://github.com/nirapod-labs/signet"
            connection = "scm:git:git://github.com/nirapod-labs/signet.git"
            developerConnection = "scm:git:ssh://git@github.com/nirapod-labs/signet.git"
        }
    }
}
