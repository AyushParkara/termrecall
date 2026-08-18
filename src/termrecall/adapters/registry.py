# SPDX-License-Identifier: GPL-3.0-or-later

"""Multi-terminal adapter registry.

The registry is the single source of truth for which terminal emulators and
which desktop sessions TermRecall supports. Production code (state,
protocol, recovery, bridge, doctor, cli) imports ``SUPPORTED_ADAPTERS`` and
``SUPPORTED_DESKTOPS`` from here instead of hard-coding ``"gnome-terminal"``.
"""

from __future__ import annotations

import shutil
from collections.abc import Callable

from termrecall.adapters.base import TerminalAdapter
from termrecall.adapters.ghostty import GhosttyAdapter
from termrecall.adapters.gnome import GnomeTerminalAdapter
from termrecall.adapters.kitty import KittyAdapter
from termrecall.adapters.konsole import KonsoleAdapter
from termrecall.adapters.xfce4 import Xfce4TerminalAdapter

SUPPORTED_ADAPTERS = frozenset(
    {"gnome-terminal", "kitty", "ghostty", "xfce4-terminal", "konsole"}
)
SUPPORTED_DESKTOPS = frozenset(
    {"X-Cinnamon", "Cinnamon", "GNOME", "ubuntu:GNOME", "XFCE", "KDE"}
)

Resolver = Callable[[str], str | None]

# Order matters for ``detect_adapter``: the first adapter whose ``detect()``
# succeeds wins. GNOME Terminal stays first to preserve V1 behavior on Linux
# Mint Cinnamon where both ``gnome-terminal`` and another emulator may exist.
_ADAPTER_FACTORIES: dict[str, Callable[..., TerminalAdapter]] = {
    "gnome-terminal": GnomeTerminalAdapter,
    "kitty": KittyAdapter,
    "ghostty": GhosttyAdapter,
    "xfce4-terminal": Xfce4TerminalAdapter,
    "konsole": KonsoleAdapter,
}


def create_adapter(name: str, which: Resolver = shutil.which) -> TerminalAdapter:
    """Return the adapter implementation for ``name``.

    Raises ``ValueError`` for any adapter not in ``SUPPORTED_ADAPTERS`` so that
    callers can surface the same ``"unsupported adapter"`` error everywhere.
    """
    if name not in _ADAPTER_FACTORIES:
        raise ValueError("unsupported adapter")
    return _ADAPTER_FACTORIES[name](which)


def detect_adapter(which: Resolver = shutil.which) -> str | None:
    """Return the first supported adapter name that is installed, else ``None``."""
    for name in (
        "gnome-terminal",
        "kitty",
        "ghostty",
        "xfce4-terminal",
        "konsole",
    ):
        if create_adapter(name, which).detect():
            return name
    return None


def get_adapter_for_shell(
    adapter_name: str, which: Resolver = shutil.which
) -> TerminalAdapter:
    """Return the adapter for a shell's recorded adapter name.

    Equivalent to ``create_adapter``; named separately so call sites that build
    a recovery adapter from a persisted shell record read naturally.
    """
    return create_adapter(adapter_name, which)
