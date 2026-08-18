# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import pytest

from termrecall.adapters.base import TerminalAdapter
from termrecall.adapters.registry import (
    SUPPORTED_ADAPTERS,
    SUPPORTED_DESKTOPS,
    create_adapter,
    detect_adapter,
    get_adapter_for_shell,
)

RESOLVERS = {
    "gnome-terminal": "/usr/bin/gnome-terminal",
    "kitty": "/usr/bin/kitty",
    "ghostty": "/usr/bin/ghostty",
    "xfce4-terminal": "/usr/bin/xfce4-terminal",
    "konsole": "/usr/bin/konsole",
}


def which_for(*available: str):
    available_set = set(available)

    def which(name: str) -> str | None:
        return RESOLVERS[name] if name in available_set else None

    return which


def test_supported_adapters_is_a_frozen_canonical_set() -> None:
    assert isinstance(SUPPORTED_ADAPTERS, frozenset)
    assert SUPPORTED_ADAPTERS == frozenset(
        {"gnome-terminal", "kitty", "ghostty", "xfce4-terminal", "konsole"}
    )


def test_supported_desktops_is_a_frozen_canonical_set() -> None:
    assert isinstance(SUPPORTED_DESKTOPS, frozenset)
    assert SUPPORTED_DESKTOPS == frozenset(
        {"X-Cinnamon", "Cinnamon", "GNOME", "ubuntu:GNOME", "XFCE", "KDE"}
    )


@pytest.mark.parametrize("name", ["gnome-terminal", "kitty", "ghostty", "xfce4-terminal", "konsole"])
def test_create_adapter_returns_runtime_adapter_for_each_supported_name(name: str) -> None:
    adapter = create_adapter(name, which_for(name))

    assert isinstance(adapter, TerminalAdapter)
    assert adapter.detect() is True
    assert adapter.capabilities().directories is True


def test_create_adapter_rejects_unknown_adapter_name() -> None:
    with pytest.raises(ValueError, match="unsupported adapter"):
        create_adapter("wezterm", which_for("gnome-terminal"))


@pytest.mark.parametrize(
    "available,expected",
    [
        (("gnome-terminal",), "gnome-terminal"),
        (("kitty",), "kitty"),
        (("ghostty",), "ghostty"),
        (("xfce4-terminal",), "xfce4-terminal"),
        (("konsole",), "konsole"),
        (("gnome-terminal", "kitty"), "gnome-terminal"),
        (("kitty", "gnome-terminal"), "gnome-terminal"),
        ((), None),
    ],
)
def test_detect_adapter_returns_first_match_or_none(
    available: tuple[str, ...], expected: str | None
) -> None:
    assert detect_adapter(which_for(*available)) == expected


def test_detect_adapter_returns_first_match_in_canonical_order() -> None:
    # All available: gnome-terminal wins because it is first in the registry order.
    assert (
        detect_adapter(
            which_for("kitty", "ghostty", "xfce4-terminal", "konsole", "gnome-terminal")
        )
        == "gnome-terminal"
    )


def test_get_adapter_for_shell_returns_detected_adapter_for_name() -> None:
    adapter = get_adapter_for_shell("kitty", which_for("kitty"))
    assert isinstance(adapter, TerminalAdapter)
    assert adapter.detect() is True


def test_get_adapter_for_shell_rejects_unknown_adapter_name() -> None:
    with pytest.raises(ValueError, match="unsupported adapter"):
        get_adapter_for_shell("alacritty", which_for("gnome-terminal"))


def test_create_adapter_passes_executable_resolver_into_detect() -> None:
    requested: list[str] = []

    def which(name: str) -> str | None:
        requested.append(name)
        return "/usr/bin/kitty"

    assert create_adapter("kitty", which).detect()
    assert requested == ["kitty"]
