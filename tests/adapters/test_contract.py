from pathlib import Path
from typing import runtime_checkable

import pytest

from termrecall.adapters.base import (
    AdapterCapabilities,
    LaunchAction,
    LaunchItem,
    TerminalAdapter,
)
from termrecall.model import RestorationLevel


def test_contract_value_types_are_immutable() -> None:
    capabilities = AdapterCapabilities(True, True, False, False, False, True, False)
    item = LaunchItem("item-a", Path("/srv/app"), None)
    action = LaunchAction(
        ("item-a",),
        ("terminal", "--working-directory", "/srv/app"),
        RestorationLevel.PARTIAL,
        ("grouping unsupported",),
    )

    with pytest.raises(AttributeError):
        capabilities.tabs = False  # type: ignore[misc]
    with pytest.raises(AttributeError):
        item.item_id = "item-b"  # type: ignore[misc]
    with pytest.raises(AttributeError):
        action.argv = ()  # type: ignore[misc]


def test_terminal_adapter_is_a_runtime_checkable_protocol() -> None:
    assert getattr(TerminalAdapter, "_is_runtime_protocol", False)
    assert runtime_checkable(TerminalAdapter) is TerminalAdapter


class CompleteAdapter:
    def detect(self) -> bool:
        return True

    def capabilities(self) -> AdapterCapabilities:
        return AdapterCapabilities(True, True, False, False, False, True, False)

    def plan(self, items: tuple[LaunchItem, ...]) -> tuple[LaunchAction, ...]:
        return ()

    def execute(
        self, actions: tuple[LaunchAction, ...], attempt_id: str
    ) -> tuple[object, ...]:
        return ()


def test_terminal_adapter_supports_structural_runtime_checks() -> None:
    assert isinstance(CompleteAdapter(), TerminalAdapter)
