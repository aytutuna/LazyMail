#!/bin/bash
# Builds the core for every Apple target and packs LazyMailCore.xcframework plus the
# Swift bindings. Run from anywhere on a Mac; needs the five Apple rust targets.
set -euo pipefail

cd "$(dirname "$0")/.."
out=apple/build
lib=liblazymail_core.a

rm -rf "$out" apple/LazyMailCore.xcframework
mkdir -p "$out/ios-sim" "$out/macos" "$out/headers" apple/LazyMail/Generated

for t in aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios aarch64-apple-darwin x86_64-apple-darwin; do
  cargo build -p lazymail-core --release --target "$t"
done

lipo -create -output "$out/ios-sim/$lib" \
  target/aarch64-apple-ios-sim/release/$lib target/x86_64-apple-ios/release/$lib
lipo -create -output "$out/macos/$lib" \
  target/aarch64-apple-darwin/release/$lib target/x86_64-apple-darwin/release/$lib

cargo run -p uniffi-bindgen -- generate --library "$out/macos/$lib" \
  --language swift --out-dir "$out/bindings"
cp "$out/bindings/lazymail_core.swift" apple/LazyMail/Generated/
cp "$out"/bindings/*.h "$out/headers/"
cp "$out"/bindings/*.modulemap "$out/headers/module.modulemap"

xcodebuild -create-xcframework \
  -library target/aarch64-apple-ios/release/$lib -headers "$out/headers" \
  -library "$out/ios-sim/$lib" -headers "$out/headers" \
  -library "$out/macos/$lib" -headers "$out/headers" \
  -output apple/LazyMailCore.xcframework
