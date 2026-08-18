from dataclasses import dataclass
from pathlib import Path
from typing import Mapping
from uuid import UUID

from termrecall.installer_contract import LifecyclePaths, resolve_lifecycle_paths

__all__ = ["LifecyclePaths", "XDGPaths", "read_boot_id", "resolve_lifecycle_paths_from_env", "resolve_paths"]


@dataclass(frozen=True, slots=True)
class XDGPaths:
    runtime_dir: Path
    state_dir: Path
    config_dir: Path


def resolve_paths(env: Mapping[str, str], uid: int, home: Path) -> XDGPaths:
    runtime_root = env.get("XDG_RUNTIME_DIR")
    if not runtime_root:
        raise ValueError("XDG_RUNTIME_DIR is required for the per-user socket")
    state_root = Path(env.get("XDG_STATE_HOME", home / ".local/state"))
    config_root = Path(env.get("XDG_CONFIG_HOME", home / ".config"))
    return XDGPaths(
        Path(runtime_root) / "termrecall",
        state_root / "termrecall",
        config_root / "termrecall",
    )


def resolve_lifecycle_paths_from_env(env: Mapping[str, str]) -> LifecyclePaths:
    """Resolve installer lifecycle paths without an ``XDG_RUNTIME_DIR``.

    The installed lifecycle commands (``setup``, ``autostart``, ``uninstall``)
    and the hidden bootstrap are independent of the per-user service runtime.
    They resolve only the manifest/config/state/bin roots from ``HOME`` and the
    XDG data/config/state overrides, never the runtime socket directory.
    """
    home = Path(env["HOME"]) if env.get("HOME") else Path.home()
    return resolve_lifecycle_paths(env, home)


def read_boot_id(path: Path = Path("/proc/sys/kernel/random/boot_id")) -> str:
    value = path.read_text(encoding="ascii").strip()
    try:
        return str(UUID(value))
    except ValueError as exc:
        raise ValueError("invalid Linux boot ID") from exc
