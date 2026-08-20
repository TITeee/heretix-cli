"""A normal setup.py that shells out during the build.

Calling subprocess to derive a version from git, or to compile a native
extension, is ordinary packaging practice. On its own it is not evidence of an
install-time attack — there is no network fetch here for it to combine with.
"""

import subprocess

from setuptools import setup


def git_version() -> str:
    try:
        out = subprocess.check_output(["git", "describe", "--tags", "--always"])
        return out.decode().strip()
    except Exception:
        return "0.0.0"


setup(
    name="benign-package",
    version=git_version(),
    packages=["benign_package"],
)
