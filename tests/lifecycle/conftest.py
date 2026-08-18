from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from termrecall.installer_contract import DesiredState, SetupMode, SetupRequest


@pytest.fixture
def source_root(tmp_path: Path) -> Path:
    return tmp_path / "source"


@pytest.fixture
def setup_request(source_root: Path) -> SetupRequest:
    return SetupRequest(
        mode=SetupMode.FULL,
        dry_run=True,
        bash=DesiredState.ENABLE,
        autostart=DesiredState.ENABLE,
        chooser=DesiredState.ENABLE,
        source_root=source_root,
        wheel=None,
        probe_request=None,
        probe_plan=None,
        probe_plan_digest=None,
    )


@pytest.fixture
def replace_request():
    return replace
