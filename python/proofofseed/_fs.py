# SPDX-License-Identifier: LGPL-3.0-or-later

"""Exclusive, mode-0600 file creation for proofs and their sidecars — matching
the CLI's `fsutil::create_new_0600`. ``O_EXCL`` refuses to overwrite an existing
file or follow a pre-planted symlink at the path, and the mode is set at open
time so there is no brief world-readable window before a chmod."""

from __future__ import annotations

import io
import os
from pathlib import Path


def create_new_0600(path: Path) -> io.BufferedWriter:
    """Open ``path`` for writing, creating it 0600 and refusing to overwrite or
    follow a symlink. Raises ``FileExistsError`` if it already exists."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    return os.fdopen(fd, "wb")
