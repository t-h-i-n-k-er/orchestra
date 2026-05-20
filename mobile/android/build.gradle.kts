// Top-level build file for the Orchestra Android agent project.
// Requires Android SDK, NDK, and Rust toolchain with Android targets.

plugins {
    id("com.android.application") version "8.2.0" apply false
}

tasks.register("clean", Delete::class) {
    delete(layout.buildDirectory)
}