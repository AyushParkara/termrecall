#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Source-tree entry point for the packaged stdlib installer probe."""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

_SOURCE_ROOT = Path(__file__).resolve().parent
_SRC = _SOURCE_ROOT / "src"
_script = Path(__file__)
_metadata = _script.stat(follow_symlinks=False)
if _script.is_symlink() or not stat.S_ISREG(_metadata.st_mode):
    raise SystemExit("refused: unsafe installer probe")
if _metadata.st_uid != os.getuid() or _metadata.st_mode & 0o022:
    raise SystemExit("refused: unsafe installer probe ownership or mode")
_src_metadata = _SRC.stat(follow_symlinks=False)
if _SRC.is_symlink() or not stat.S_ISDIR(_src_metadata.st_mode):
    raise SystemExit("refused: unsafe source package directory")
if _src_metadata.st_uid != os.getuid() or _src_metadata.st_mode & 0o002:
    raise SystemExit("refused: unsafe source package ownership or mode")
sys.path.insert(0, str(_SRC))

from termrecall.installer_probe import (  # noqa: E402
    PLAN_SCHEMA,
    PROBE_SCHEMA,
    REQUEST_SCHEMA,
    build_plan,
    compute_plan_digest,
    main,
    plan_from_bytes,
    plan_to_bytes,
    render_plan,
)

__all__ = [
    "PROBE_SCHEMA",
    "PLAN_SCHEMA",
    "REQUEST_SCHEMA",
    "build_plan",
    "plan_to_bytes",
    "plan_from_bytes",
    "render_plan",
    "compute_plan_digest",
    "main",
]

if __name__ == "__main__":
    raise SystemExit(main())
