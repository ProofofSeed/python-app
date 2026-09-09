# SPDX-License-Identifier: LGPL-3.0-or-later

"""Exclusive, mode-0600 file creation for proofs and their sidecars."""

from __future__ import annotations

import io
import os
from pathlib import Path


def create_new_0600(path: Path) -> io.BufferedWriter:
    """Opens a path for writing, creating it mode 0600 and refusing to overwrite it or to
    follow a symlink."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    return os.fdopen(fd, "wb")
