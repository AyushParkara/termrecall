# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from termrecall.adapters.base import LaunchItem
from termrecall.adapters.gnome import GnomeTerminalAdapter

pytestmark = pytest.mark.desktop


def _desktop_ready() -> bool:
    return (
        os.environ.get("TERMRECALL_DESKTOP_TEST") == "1"
        and os.environ.get("XDG_CURRENT_DESKTOP", "").casefold() == "x-cinnamon"
        and bool(os.environ.get("DISPLAY"))
        and shutil.which("gnome-terminal") is not None
    )


@pytest.mark.skipif(not _desktop_ready(), reason="requires explicit Linux Mint Cinnamon desktop opt-in")
def test_gnome_terminal_interactive_and_approved_smoke(tmp_path: Path) -> None:
    """Desktop harness must visually confirm cwd and no pre-approval execution.

    The opt-in itself is the approval boundary for the benign printf item. The
    unapproved item is directory-only and therefore has no command argv.
    """
    marker = tmp_path / "termrecall-smoke-approved"
    adapter = GnomeTerminalAdapter(shutil.which)
    actions = adapter.plan((
        LaunchItem("interactive", tmp_path, None),
        LaunchItem("approved", tmp_path, f"printf termrecall-smoke > {marker}"),
    ))
    assert len(actions) == 2
    assert "--" not in actions[0].argv
    assert actions[1].argv[-1] == f"printf termrecall-smoke > {marker}"
    outcomes = adapter.execute(actions, "desktop-smoke")
    assert all(outcome.kind.value == "success" for outcome in outcomes)
    assert marker.read_text() == "termrecall-smoke"
