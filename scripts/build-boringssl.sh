#!/usr/bin/env bash
# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Builds BoringSSL with Rust bindings for the host, for the `boringssl`
# backend, and writes a Cargo config that patches `bssl-sys` to it.
#
# Usage: scripts/build-boringssl.sh [directory]   (default: ./boringssl)
#
# Requires git, cmake, ninja, a C/C++ compiler, and `bindgen` on PATH
# (`cargo install bindgen-cli`). Afterwards:
#
#   export BORINGSSL_BUILD_DIR=$PWD/boringssl/build
#   cargo test --features boringssl --config boringssl/cargo-config.toml
set -euo pipefail

# The BoringSSL revision this crate is tested against; `bssl-sys` moves in
# lockstep with BoringSSL, so bump both together.
COMMIT=5112448a24999caecfb6f04281379016ac79dc9a
DIR=${1:-boringssl}
HOST=$(rustc -vV | sed -n 's/^host: //p')

if [ ! -d "$DIR/.git" ]; then
  git clone --filter=blob:none https://boringssl.googlesource.com/boringssl "$DIR"
fi
git -C "$DIR" fetch --quiet origin "$COMMIT"
git -C "$DIR" checkout --quiet "$COMMIT"

# Clang is BoringSSL's primary compiler, and bindgen already needs LLVM. GCC 15
# reports a false stringop-overflow in its Keccak code, which -Werror makes fatal.
cmake -S "$DIR" -B "$DIR/build" -GNinja -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_COMPILER="${CC:-clang}" -DCMAKE_CXX_COMPILER="${CXX:-clang++}" \
  -DRUST_BINDINGS="$HOST"
ninja -C "$DIR/build" crypto ssl rust_wrapper bssl_sys

ABS=$(cd "$DIR" && pwd)
cat > "$DIR/cargo-config.toml" <<CONFIG
[patch.crates-io]
bssl-sys = { path = "$ABS/rust/bssl-sys" }
CONFIG

echo "BoringSSL $COMMIT built for $HOST in $ABS/build"
echo "export BORINGSSL_BUILD_DIR=$ABS/build"
echo "cargo test --features boringssl --config $DIR/cargo-config.toml"
