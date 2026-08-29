#!/usr/bin/env python3
import shutil
import subprocess
import sys
from pathlib import Path
from setuptools import Extension, setup
from setuptools.command.build_ext import build_ext as _build_ext
from setuptools.dist import Distribution

ROOT = Path(__file__).resolve().parent
CRYPTO_FALLBACK_SRC_DIR = ROOT / "libpwman" / "crypto_fallback"

ARGON2PURERS_EXT_NAME = "libpwman.crypto_fallback.argon2purers"
ARGON2PURERS_SCRIPT = CRYPTO_FALLBACK_SRC_DIR / "build-argon2purers.sh"
ARGON2PURERS_BUILT_SO = CRYPTO_FALLBACK_SRC_DIR / "argon2purers.so"

class BinaryDistribution(Distribution):
    """Tells setuptools/wheel this package is platform-specific.

    Without this, since we declare no ext_modules built via the normal
    C-compiler toolchain, setuptools considers the package pure Python
    and bdist_wheel emits a `py3-none-any` tag -- which is wrong, since
    the Rust-built .so is tied to the platform/arch it was compiled on.
    """

    def has_ext_modules(self):
        return True

class build_ext(_build_ext):
    def build_extension(self, ext):
        if ext.name == ARGON2PURERS_EXT_NAME:
            target = Path(self.get_ext_fullpath(ext.name))
            target.parent.mkdir(parents=True, exist_ok=True)

            # Clean up any stale artifact.
            ARGON2PURERS_BUILT_SO.unlink(missing_ok=True)

            if not ARGON2PURERS_SCRIPT.is_file():
                print(
                    f"\n"
                    f"***************************************************************\n"
                    f"* WARNING: argon2purers build script not found:               *\n"
                    f"*          {ARGON2PURERS_SCRIPT}\n"
                    f"* The argon2purers Rust extension will not be available.      *\n"
                    f"***************************************************************\n\n",
                    file=sys.stderr
                )
                return

            try:
                subprocess.run(
                    [ "sh", str(ARGON2PURERS_SCRIPT), ],
                    cwd=CRYPTO_FALLBACK_SRC_DIR,
                    check=True
                )
            except (subprocess.CalledProcessError, OSError) as e:
                print(
                    f"\n"
                    f"***************************************************************\n"
                    f"* WARNING: Failed to build the argon2purers Rust extension.   *\n"
                    f"*          {type(e).__name__}:\n"
                    f"*          {e}\n"
                    f"*                                                             *\n"
                    f"* The argon2purers Rust extension will not be available.      *\n"
                    f"***************************************************************\n\n",
                    file=sys.stderr
                )
                ARGON2PURERS_BUILT_SO.unlink(missing_ok=True)
                return

            shutil.copy(ARGON2PURERS_BUILT_SO, target)
            ARGON2PURERS_BUILT_SO.unlink(missing_ok=True)
        else:
            super().build_extension(ext)

setup(
    distclass=BinaryDistribution,
    cmdclass={
        "build_ext": build_ext,
    },
    ext_modules=[
        Extension(ARGON2PURERS_EXT_NAME, sources=[])
    ],
)
