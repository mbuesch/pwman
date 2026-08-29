#!/bin/sh
set -e
cd "$(dirname "$0")"
rm -f argon2purers.so
rustc \
    --edition=2024 \
    --crate-type=cdylib \
    -Cdebuginfo=0 \
    -Copt-level=3 \
    -Cpanic=abort \
    -Cstrip=symbols \
    argon2pure.rs \
    -oargon2purers.so
echo "argon2purers.so built successfully."
