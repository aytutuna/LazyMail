#!/bin/bash
# Builds the core for the two Android ABIs into app/src/main/jniLibs and writes the Kotlin
# bindings to app/src/main/java/uniffi. Needs cargo-ndk, the two android rust targets and
# ANDROID_NDK_HOME.
set -euo pipefail

cd "$(dirname "$0")/.."

rm -rf android/app/src/main/jniLibs
cargo ndk -t arm64-v8a -t x86_64 -o android/app/src/main/jniLibs build -p lazymail-core --release

rm -rf android/app/src/main/java/uniffi
cargo run -p uniffi-bindgen -- generate \
  --library target/x86_64-linux-android/release/liblazymail_core.so \
  --language kotlin --out-dir android/app/src/main/java
