# SPDX-License-Identifier: GPL-3.0-or-later
"""Standard-library-only value objects shared by installer lifecycle code."""

from __future__ import annotations

import base64
import hashlib
import json
import os
from dataclasses import asdict, dataclass
from enum import Enum, IntEnum
from pathlib import Path
from typing import Any, Mapping

MANIFEST_SCHEMA = 2
PROBE_SCHEMA = 1
PLAN_SCHEMA = 2
REQUEST_SCHEMA = 1
MAX_PAYLOAD_BYTES = 65_536
_SHA256_LENGTH = 64


class LifecycleExit(IntEnum):
    OK = 0
    INTERNAL = 1
    USAGE = 2
    PREREQUISITE = 3
    REFUSED = 4
    ROLLED_BACK = 5
    ROLLBACK_INCOMPLETE = 6
    WARNING = 7


class SetupMode(str, Enum):
    INTERACTIVE = "interactive"
    FULL = "full"
    NO_AUTOSTART = "no-autostart"
    COMMANDS_ONLY = "commands-only"
    UPGRADE = "upgrade"


class DesiredState(str, Enum):
    ENABLE = "enable"
    DISABLE = "disable"
    PRESERVE = "preserve"


class ObjectKind(str, Enum):
    ABSENT = "absent"
    FILE = "file"
    SYMLINK = "symlink"


@dataclass(frozen=True, slots=True)
class SetupRequest:
    mode: SetupMode
    dry_run: bool
    bash: DesiredState
    autostart: DesiredState
    chooser: DesiredState
    source_root: Path
    wheel: Path | None
    probe_request: bytes | None
    probe_plan: bytes | None
    probe_plan_digest: str | None


@dataclass(frozen=True, slots=True)
class IntegrationSetupRequest:
    dry_run: bool
    bash: DesiredState
    autostart: DesiredState
    chooser: DesiredState


@dataclass(frozen=True, slots=True)
class UninstallRequest:
    remove_application: bool
    remove_bash: bool
    remove_autostart: bool
    restore_chooser: bool
    purge_state: bool
    assume_yes: bool


@dataclass(frozen=True, slots=True)
class LifecyclePaths:
    home: Path
    xdg_data_home: Path
    xdg_config_home: Path
    xdg_state_home: Path
    data_root: Path
    config_root: Path
    state_root: Path
    bin_root: Path
    generations: Path
    current: Path
    manifest: Path
    lifecycle_lock: Path
    bash_integration: Path
    bashrc: Path
    autostart: Path
    chooser: Path
    command_links: tuple[Path, Path, Path]


@dataclass(frozen=True, slots=True)
class BeforeImage:
    path: str
    kind: ObjectKind
    mode: int | None
    literal_target: str | None
    content: bytes | None
    content_sha256: str | None


@dataclass(frozen=True, slots=True)
class OwnedObject:
    path: str
    kind: ObjectKind
    mode: int
    content_sha256: str | None
    literal_target: str | None


@dataclass(frozen=True, slots=True)
class MarkerIdentity:
    path: str
    content_sha256: str
    mode: int


@dataclass(frozen=True, slots=True)
class ChooserOwnership:
    original: BeforeImage
    post: BeforeImage | None
    changed: bool


@dataclass(frozen=True, slots=True)
class InstallManifest:
    schema_version: int
    installer_version: str
    application_version: str
    install_id: str
    generation_id: str
    roots: Mapping[str, object]
    marker: MarkerIdentity
    owned: tuple[OwnedObject, ...]
    created_parents: tuple[str, ...]
    bash_enabled: bool
    autostart_enabled: bool
    chooser: ChooserOwnership
    rollback_images: tuple[BeforeImage, ...]
    bash_backup: OwnedObject | None


@dataclass(frozen=True, slots=True)
class ProbePrior:
    present: bool
    manifest: InstallManifest | None


@dataclass(frozen=True, slots=True)
class ProbeAction:
    sequence: int
    kind: str
    disposition: str
    path_or_token: str
    mode: int | None
    literal_target: str | None
    content_sha256: str | None
    prerequisite: str | None
    rollback: BeforeImage | None


@dataclass(frozen=True, slots=True)
class LockInfrastructurePlan:
    directory_path: str
    lock_path: str
    directory_absent: bool
    lock_absent: bool
    may_create_directory: bool
    may_create_lock: bool
    directory_mode: int
    lock_mode: int


@dataclass(frozen=True, slots=True)
class ProbePlan:
    probe_schema: int
    plan_schema: int
    request: Mapping[str, object]
    prerequisites: Mapping[str, object]
    source: Mapping[str, object]
    prior: ProbePrior
    effective: Mapping[str, object]
    actions: tuple[ProbeAction, ...]
    lock_infrastructure: LockInfrastructurePlan
    state_fingerprint: str
    rendered: str
    plan_digest: str


def _absolute_root(value: str | Path, name: str) -> Path:
    path = Path(value)
    if not path.is_absolute() or os.path.normpath(os.fspath(path)) != os.fspath(path):
        raise ValueError(f"{name} must be a canonical absolute path")
    return path


def resolve_lifecycle_paths(env: Mapping[str, str], home: Path) -> LifecyclePaths:
    home = _absolute_root(home, "home")
    data_home = _absolute_root(env.get("XDG_DATA_HOME", home / ".local/share"), "XDG_DATA_HOME")
    config_home = _absolute_root(env.get("XDG_CONFIG_HOME", home / ".config"), "XDG_CONFIG_HOME")
    state_home = _absolute_root(env.get("XDG_STATE_HOME", home / ".local/state"), "XDG_STATE_HOME")
    data_root = data_home / "termrecall"
    config_root = config_home / "termrecall"
    state_root = state_home / "termrecall"
    bin_root = home / ".local/bin"
    command_names = ("termrecall", "termrecall-bridge", "termrecall-nonblock")
    return LifecyclePaths(
        home=home,
        xdg_data_home=data_home,
        xdg_config_home=config_home,
        xdg_state_home=state_home,
        data_root=data_root,
        config_root=config_root,
        state_root=state_root,
        bin_root=bin_root,
        generations=data_root / "generations",
        current=data_root / "current",
        manifest=config_root / "install-manifest.json",
        lifecycle_lock=config_root / "lifecycle.lock",
        bash_integration=config_root / "bash-integration.bash",
        bashrc=home / ".bashrc",
        autostart=config_home / "autostart/termrecall.desktop",
        chooser=config_root / "config.json",
        command_links=tuple(bin_root / name for name in command_names),  # type: ignore[arg-type]
    )


def _require_type(value: object, expected: type, name: str) -> None:
    if type(value) is not expected:
        raise TypeError(f"{name} must be {expected.__name__}")


def validate_setup_request(request: SetupRequest) -> SetupRequest:
    _require_type(request.mode, SetupMode, "mode")
    _require_type(request.dry_run, bool, "dry_run")
    for name in ("bash", "autostart", "chooser"):
        _require_type(getattr(request, name), DesiredState, name)
    if not isinstance(request.source_root, Path):
        raise TypeError("source_root must be Path")
    if request.wheel is not None and not isinstance(request.wheel, Path):
        raise TypeError("wheel must be Path")
    for name in ("probe_request", "probe_plan"):
        value = getattr(request, name)
        if value is not None:
            _require_type(value, bytes, name)
    if request.probe_plan_digest is not None:
        _require_type(request.probe_plan_digest, str, "probe_plan_digest")
    states = (request.bash, request.autostart, request.chooser)
    valid = (
        request.mode in {SetupMode.INTERACTIVE, SetupMode.FULL}
        or (request.mode is SetupMode.NO_AUTOSTART and request.autostart is not DesiredState.ENABLE)
        or (
            request.mode in {SetupMode.COMMANDS_ONLY, SetupMode.UPGRADE}
            and states == (DesiredState.PRESERVE,) * 3
        )
    )
    if not valid:
        raise ValueError("integration states conflict with setup mode")
    return request


def validate_integration_setup_request(request: IntegrationSetupRequest) -> IntegrationSetupRequest:
    _require_type(request.dry_run, bool, "dry_run")
    for name in ("bash", "autostart", "chooser"):
        _require_type(getattr(request, name), DesiredState, name)
    return request


def _json_default(value: object) -> object:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, bytes):
        return base64.b64encode(value).decode("ascii")
    raise TypeError(f"unsupported manifest value: {type(value).__name__}")


def _canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=_json_default).encode("utf-8") + b"\n"


def manifest_to_bytes(value: InstallManifest) -> bytes:
    if value.schema_version != MANIFEST_SCHEMA:
        raise ValueError("unsupported manifest schema")
    raw = _canonical_json(asdict(value))
    if len(raw) > MAX_PAYLOAD_BYTES:
        raise ValueError("manifest exceeds 65,536 bytes")
    return raw


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _decode_json(raw: bytes) -> object:
    if len(raw) > MAX_PAYLOAD_BYTES:
        raise ValueError("payload exceeds 65,536 bytes")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid JSON") from exc
    if _canonical_json(value) != raw:
        raise ValueError("JSON is not canonical")
    return value


def _exact_keys(value: Mapping[str, object], keys: set[str], name: str) -> None:
    if set(value) != keys:
        raise ValueError(f"invalid {name} keys")


def _string(value: object, name: str) -> str:
    if type(value) is not str or not value or "\x00" in value:
        raise ValueError(f"invalid {name}")
    return value


def _integer(value: object, name: str, *, minimum: int = 0, maximum: int = 0o7777) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"invalid {name}")
    return value


def _boolean(value: object, name: str) -> bool:
    if type(value) is not bool:
        raise ValueError(f"invalid {name}")
    return value


def _hash(value: object, name: str) -> str:
    text = _string(value, name)
    if len(text) != _SHA256_LENGTH or any(char not in "0123456789abcdef" for char in text):
        raise ValueError(f"invalid {name} hash")
    return text


def _path(value: object, name: str) -> str:
    text = _string(value, name)
    path = Path(text)
    if not path.is_absolute() or os.path.normpath(text) != text:
        raise ValueError(f"invalid {name} path")
    return text


def _optional(value: object, decoder: Any, name: str) -> object | None:
    return None if value is None else decoder(value, name)


def _sequence(value: object, name: str, *, maximum: int = 128) -> list[object]:
    if type(value) is not list or len(value) > maximum:
        raise ValueError(f"invalid {name} collection")
    return value


def _decode_before(value: object) -> BeforeImage:
    if type(value) is not dict:
        raise ValueError("invalid before image")
    _exact_keys(value, {"path", "kind", "mode", "literal_target", "content", "content_sha256"}, "before image")
    try:
        kind = ObjectKind(value["kind"])
    except (ValueError, TypeError) as exc:
        raise ValueError("invalid before image kind") from exc
    path = _path(value["path"], "before image")
    mode = _optional(value["mode"], _integer, "before image mode")
    target = _optional(value["literal_target"], _string, "before image target")
    digest = _optional(value["content_sha256"], _hash, "before image content")
    encoded = value["content"]
    if encoded is None:
        content = None
    else:
        try:
            content = base64.b64decode(_string(encoded, "before image content base64"), validate=True)
        except ValueError as exc:
            raise ValueError("invalid before image content base64") from exc
    if kind is ObjectKind.ABSENT and any(item is not None for item in (mode, target, content, digest)):
        raise ValueError("absent before image has metadata")
    if kind is ObjectKind.FILE and (mode is None or target is not None or content is None or digest != hashlib.sha256(content).hexdigest()):
        raise ValueError("invalid file before image content")
    if kind is ObjectKind.SYMLINK and (mode is None or target is None or content is not None or digest is not None):
        raise ValueError("invalid symlink before image")
    return BeforeImage(path, kind, mode, target, content, digest)


def _decode_owned(value: object) -> OwnedObject:
    if type(value) is not dict:
        raise ValueError("invalid owned object")
    _exact_keys(value, {"path", "kind", "mode", "content_sha256", "literal_target"}, "owned object")
    try:
        kind = ObjectKind(value["kind"])
    except (ValueError, TypeError) as exc:
        raise ValueError("invalid owned object kind") from exc
    if kind is ObjectKind.ABSENT:
        raise ValueError("owned object cannot be absent")
    path = _path(value["path"], "owned object")
    mode = _integer(value["mode"], "owned object mode")
    digest = _optional(value["content_sha256"], _hash, "owned content")
    target = _optional(value["literal_target"], _string, "owned target")
    if kind is ObjectKind.FILE and (digest is None or target is not None):
        raise ValueError("invalid owned file")
    if kind is ObjectKind.SYMLINK and (target is None or digest is not None):
        raise ValueError("invalid owned symlink")
    return OwnedObject(path, kind, mode, digest, target)


def manifest_from_bytes(raw: bytes, paths: LifecyclePaths, uid: int) -> InstallManifest:
    value = _decode_json(raw)
    if type(value) is not dict:
        raise ValueError("manifest must be an object")
    keys = {"schema_version", "installer_version", "application_version", "install_id", "generation_id", "roots", "marker", "owned", "created_parents", "bash_enabled", "autostart_enabled", "chooser", "rollback_images", "bash_backup"}
    _exact_keys(value, keys, "manifest")
    if type(value["schema_version"]) is not int or value["schema_version"] != MANIFEST_SCHEMA:
        raise ValueError("unsupported manifest schema")
    roots = value["roots"]
    if type(roots) is not dict:
        raise ValueError("invalid roots")
    _exact_keys(roots, {"uid", "data", "config", "state", "bin"}, "roots")
    expected_roots: dict[str, object] = {"uid": uid, "data": str(paths.data_root), "config": str(paths.config_root), "state": str(paths.state_root), "bin": str(paths.bin_root)}
    if roots != expected_roots or type(roots["uid"]) is not int:
        raise ValueError("manifest roots or uid do not match configured paths")
    for name in ("data", "config", "state", "bin"):
        _path(roots[name], f"root {name}")
    installer_version = _string(value["installer_version"], "installer_version")
    application_version = _string(value["application_version"], "application_version")
    install_id = _string(value["install_id"], "install_id")
    generation_id = _string(value["generation_id"], "generation_id")
    if "/" in generation_id or generation_id in {".", ".."}:
        raise ValueError("invalid generation_id")
    marker_raw = value["marker"]
    chooser_raw = value["chooser"]
    if type(marker_raw) is not dict or type(chooser_raw) is not dict:
        raise ValueError("invalid manifest model")
    _exact_keys(marker_raw, {"path", "content_sha256", "mode"}, "marker")
    marker = MarkerIdentity(_path(marker_raw["path"], "marker"), _hash(marker_raw["content_sha256"], "marker"), _integer(marker_raw["mode"], "marker mode"))
    expected_generation = paths.generations / generation_id
    if marker.path != str(expected_generation / ".termrecall-generation.json") or marker.mode != 0o600:
        raise ValueError("invalid generation marker")
    _exact_keys(chooser_raw, {"original", "post", "changed"}, "chooser")
    chooser = ChooserOwnership(_decode_before(chooser_raw["original"]), None if chooser_raw["post"] is None else _decode_before(chooser_raw["post"]), _boolean(chooser_raw["changed"], "chooser changed"))
    if chooser.original.path != str(paths.chooser) or (chooser.post is not None and chooser.post.path != str(paths.chooser)):
        raise ValueError("invalid chooser path")
    if chooser.changed != (chooser.post is not None):
        raise ValueError("invalid chooser ownership state")
    owned = tuple(_decode_owned(item) for item in _sequence(value["owned"], "owned"))
    rollback = tuple(_decode_before(item) for item in _sequence(value["rollback_images"], "rollback_images"))
    created_parents = tuple(_path(item, "created parent") for item in _sequence(value["created_parents"], "created_parents"))
    bash_backup = None if value["bash_backup"] is None else _decode_owned(value["bash_backup"])
    manifest = InstallManifest(MANIFEST_SCHEMA, installer_version, application_version, install_id, generation_id, roots, marker, owned, created_parents, _boolean(value["bash_enabled"], "bash_enabled"), _boolean(value["autostart_enabled"], "autostart_enabled"), chooser, rollback, bash_backup)
    owned_by_path = {item.path: item for item in owned}
    if len(owned_by_path) != len(owned) or len({item.path for item in rollback}) != len(rollback) or len(set(created_parents)) != len(created_parents):
        raise ValueError("duplicate owned, rollback, or parent path")
    current = owned_by_path.get(str(paths.current))
    if current is None or current.kind is not ObjectKind.SYMLINK or current.literal_target != str(expected_generation):
        raise ValueError("invalid current link ownership")
    for link in paths.command_links:
        item = owned_by_path.get(str(link))
        expected_target = str(paths.current / f"venv/bin/{link.name}")
        if item is None or item.kind is not ObjectKind.SYMLINK or item.literal_target != expected_target:
            raise ValueError("invalid command link ownership")
    return manifest


def probe_plan_from_bytes(raw: bytes, expected_request: Mapping[str, object]) -> ProbePlan:
    from termrecall.installer_probe import plan_from_bytes

    value = plan_from_bytes(raw, expected_request)
    prior_raw = value["prior"]
    request = value["request"]
    paths = resolve_lifecycle_paths(
        {
            "XDG_DATA_HOME": request["xdg_data_home"],
            "XDG_CONFIG_HOME": request["xdg_config_home"],
            "XDG_STATE_HOME": request["xdg_state_home"],
        },
        Path(request["home"]),
    )
    prior_manifest = None
    if prior_raw["present"]:
        manifest_raw = _canonical_json(prior_raw["manifest"])
        prior_manifest = manifest_from_bytes(manifest_raw, paths, uid=value["prerequisites"]["uid"])
    prior = ProbePrior(prior_raw["present"], prior_manifest)
    actions = tuple(
        ProbeAction(
            action["sequence"], action["kind"], action["disposition"],
            action["path_or_token"], action["mode"], action["literal_target"],
            action["content_sha256"], action["prerequisite"],
            None if action["rollback"] is None else _decode_before(action["rollback"]),
        )
        for action in value["actions"]
    )
    lock = LockInfrastructurePlan(**value["lock_infrastructure"])
    return ProbePlan(value["probe_schema"], value["plan_schema"], value["request"], value["prerequisites"], value["source"], prior, value["effective"], actions, lock, value["state_fingerprint"], value["rendered"], value["plan_digest"])
