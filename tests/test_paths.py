from pathlib import Path

import pytest

from termrecall.paths import read_boot_id, resolve_paths


def test_resolve_paths_honors_xdg(tmp_path: Path) -> None:
    paths = resolve_paths(
        {
            "XDG_RUNTIME_DIR": str(tmp_path / "run"),
            "XDG_STATE_HOME": str(tmp_path / "state"),
            "XDG_CONFIG_HOME": str(tmp_path / "config"),
        },
        uid=1000,
        home=tmp_path / "home",
    )
    assert paths.runtime_dir == tmp_path / "run" / "termrecall"
    assert paths.state_dir == tmp_path / "state" / "termrecall"
    assert paths.config_dir == tmp_path / "config" / "termrecall"


def test_runtime_directory_is_required(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="XDG_RUNTIME_DIR"):
        resolve_paths({}, uid=1000, home=tmp_path)


def test_read_boot_id_rejects_non_uuid_text(tmp_path: Path) -> None:
    source = tmp_path / "boot_id"
    source.write_text("not-an-id\n", encoding="ascii")
    with pytest.raises(ValueError, match="boot ID"):
        read_boot_id(source)
