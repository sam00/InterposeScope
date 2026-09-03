#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

SDK=$(xcrun --show-sdk-path 2>/dev/null || xcodebuild -sdk macosx -version 2>/dev/null | grep "Path:" | awk '{print $2}')

mkdir -p build
echo "[build] Compiling InterposeScope-C v2.2.0..."

clang -arch arm64 -O2 -isysroot "$SDK" \
      -Wall -Wno-unused-variable -Wno-unused-function \
      -o build/interposescope src/interposescope.c \
      -framework Foundation -lobjc

echo "[build] Done."
ls -lh build/interposescope
file build/interposescope
