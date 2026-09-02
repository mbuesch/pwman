# Crypto Fallback

This directory contains fallback implementations for cryptographic operations used in pwman.

These modules are **only** used when the primary recommended cryptographic libraries are not available.

## `pyaes/*`

- License: MIT
- Vendored unmodified copy of [pyaes](https://github.com/ricmoo/pyaes) rev `23a1b4c0488bd38e03a48120dfda98913f4c87d2`.

## `aesgcm.py`

- License: MIT
- Pure Python implementation of the GCM part of AES-GCM.
- Implemented independently from scratch with AI assistance and manual methods
- See testvectors in `testvectors` subdirectory

## `argon2pure.rs`

- License: MIT
- Directly derived from the [argon2pure](https://github.com/bwesterb/argon2pure) rev `ae69d86d609299b752bd62e30b6a5c3e96158e83` Python implementation of Argon2
- Derived with AI assistance and manual methods
- Build with `build-argon2purers.sh`
