#!/usr/bin/env bash
# Builds the iOS static libraries, the Swift bindings and the XCFramework under bindings/swift/.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/bindings/swift"
NAME="ZeroEnclaveCore"
LIB="libzeroenclave_ffi.a"
MODULE="zeroenclave_ffiFFI"
export IPHONEOS_DEPLOYMENT_TARGET="17.0"

# Cargo profile: `release` (default) or `ios-dev` (no LTO, faster builds).
PROFILE="${ZE_PROFILE:-release}"
case "$PROFILE" in
  release | ios-dev) ;;
  *) echo "Unsupported ZE_PROFILE: $PROFILE" >&2; exit 1 ;;
esac

cd "$ROOT"
rm -rf "$OUT"
mkdir -p "$OUT/Sources/$NAME" "$OUT/build/headers"

for target in aarch64-apple-ios aarch64-apple-ios-sim; do
  cargo build --profile "$PROFILE" --locked -p zeroenclave-ffi --target "$target"
done

TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"

# Library mode reads the interface metadata from the static library.
cargo run --profile "$PROFILE" --locked -p zeroenclave-ffi --bin uniffi-bindgen -- generate \
  --library "$TARGET_DIR/aarch64-apple-ios/$PROFILE/$LIB" \
  --language swift \
  --out-dir "$OUT/build/gen"

cp "$OUT/build/gen/zeroenclave_ffi.swift" "$OUT/Sources/$NAME/"
cp "$OUT/build/gen/$MODULE.h" "$OUT/build/headers/"
cp "$OUT/build/gen/$MODULE.modulemap" "$OUT/build/headers/module.modulemap"

xcodebuild -create-xcframework \
  -library "$TARGET_DIR/aarch64-apple-ios/$PROFILE/$LIB" -headers "$OUT/build/headers" \
  -library "$TARGET_DIR/aarch64-apple-ios-sim/$PROFILE/$LIB" -headers "$OUT/build/headers" \
  -output "$OUT/$NAME.xcframework"

cat > "$OUT/Package.swift" <<PKG
// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "$NAME",
    platforms: [.iOS(.v17)],
    products: [.library(name: "$NAME", targets: ["$NAME"])],
    targets: [
        .binaryTarget(name: "ZeroEnclaveFFI", path: "$NAME.xcframework"),
        .target(name: "$NAME", dependencies: ["ZeroEnclaveFFI"], path: "Sources/$NAME"),
    ]
)
PKG

# Smoke test: the generated Swift must type-check against the C module for both slices.
for triple in arm64-apple-ios17.0 arm64-apple-ios17.0-simulator; do
  sdk=iphoneos
  [[ "$triple" == *-simulator ]] && sdk=iphonesimulator
  xcrun --sdk "$sdk" swiftc -typecheck -target "$triple" \
    -I "$OUT/build/headers" "$OUT/Sources/$NAME"/*.swift
done

rm -rf "$OUT/build"
echo "Built $OUT/$NAME.xcframework"
