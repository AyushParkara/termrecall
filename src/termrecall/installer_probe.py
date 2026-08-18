#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Read-only, standard-library installer planner and verified delegate launcher."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import signal
import stat
import subprocess
import sys
import shutil
import threading
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Final

PROBE_SCHEMA: Final[int] = 1
PLAN_SCHEMA: Final[int] = 2
REQUEST_SCHEMA: Final[int] = 1
MAX_PAYLOAD_BYTES: Final[int] = 65_536
REQUEST_KEYS = {
    "request_schema", "source_root", "home", "xdg_data_home", "xdg_config_home",
    "xdg_state_home", "mode", "bash", "autostart", "chooser", "dry_run",
}
PLAN_KEYS = {
    "probe_schema", "plan_schema", "request", "prerequisites", "source", "prior",
    "effective", "actions", "lock_infrastructure", "state_fingerprint", "rendered",
    "plan_digest",
}
LOCK_KEYS = {
    "directory_path", "lock_path", "directory_absent", "lock_absent",
    "may_create_directory", "may_create_lock", "directory_mode", "lock_mode",
}
MODES = {"interactive", "full", "no-autostart", "commands-only", "upgrade"}
STATES = {"enable", "disable", "preserve"}
SHA256_ZERO = "0" * 64


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8") + b"\n"


def _object_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _load(raw: bytes) -> object:
    if len(raw) > MAX_PAYLOAD_BYTES:
        raise ValueError("payload exceeds 65,536 bytes")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_object_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid JSON payload") from exc
    if _canonical(value) != raw:
        raise ValueError("payload is not canonical JSON")
    return value


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def compute_plan_digest(plan: Mapping[str, object]) -> str:
    material = dict(plan)
    material.pop("plan_digest", None)
    return _sha256(material)


def render_plan(plan: Mapping[str, object]) -> str:
    request = plan.get("request")
    actions = plan.get("actions")
    if not isinstance(request, Mapping) or not isinstance(actions, list):
        raise ValueError("invalid plan for rendering")
    lines = [
        "TermRecall installer plan",
        f"Mode: {request.get('mode')}",
        f"Dry run: {'yes' if request.get('dry_run') else 'no'}",
        "Requested integrations: "
        f"bash={request.get('bash')}, autostart={request.get('autostart')}, chooser={request.get('chooser')}",
        "Actions:",
    ]
    for action in actions:
        if not isinstance(action, Mapping):
            raise ValueError("invalid action for rendering")
        lines.append(
            f"  {action.get('sequence')}. {action.get('kind')}: "
            f"{action.get('disposition')} {action.get('path_or_token')}"
        )
    return "\n".join(lines) + "\n"


def plan_to_bytes(plan: Mapping[str, object]) -> bytes:
    raw = _canonical(dict(plan))
    if len(raw) > MAX_PAYLOAD_BYTES:
        raise ValueError("plan exceeds 65,536 bytes")
    return raw


def _canonical_path(value: object, name: str) -> str:
    if type(value) is not str or not value or "\x00" in value:
        raise ValueError(f"invalid {name}")
    path = Path(value)
    if not path.is_absolute() or os.path.normpath(value) != value:
        raise ValueError(f"{name} must be a canonical absolute path")
    return value


def _validate_request(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != REQUEST_KEYS:
        raise ValueError("invalid request keys")
    if value["request_schema"] != REQUEST_SCHEMA:
        raise ValueError("unknown request schema")
    for name in ("source_root", "home", "xdg_data_home", "xdg_config_home", "xdg_state_home"):
        _canonical_path(value[name], name)
    if type(value["dry_run"]) is not bool:
        raise ValueError("invalid dry_run type")
    if value["mode"] not in MODES:
        raise ValueError("invalid mode")
    for name in ("bash", "autostart", "chooser"):
        if value[name] not in STATES:
            raise ValueError(f"invalid {name} state")
    states = (value["bash"], value["autostart"], value["chooser"])
    mode = value["mode"]
    valid = (
        mode in {"interactive", "full"}
        or (mode == "no-autostart" and value["autostart"] != "enable")
        or (mode in {"commands-only", "upgrade"} and states == ("preserve",) * 3)
    )
    if not valid:
        raise ValueError("request states conflict with mode")
    return value


def _validate_hash(value: object, name: str) -> None:
    if type(value) is not str or len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
        raise ValueError(f"invalid {name} hash")


def _exact_object(value: object, keys: set[str], name: str) -> dict[str, object]:
    if type(value) is not dict or set(value) != keys:
        raise ValueError(f"invalid {name} keys")
    return value


def _exact_bool(value: object, name: str) -> bool:
    if type(value) is not bool:
        raise ValueError(f"invalid {name} boolean")
    return value


def _exact_int(value: object, name: str) -> int:
    if type(value) is not int or value < 0:
        raise ValueError(f"invalid {name} integer")
    return value


def _exact_string(value: object, name: str) -> str:
    if type(value) is not str or not value or "\x00" in value:
        raise ValueError(f"invalid {name} string")
    return value


def _validate_prerequisites(value: object) -> None:
    obj = _exact_object(value, {"uid", "python", "python_version", "venv", "cc", "bash"}, "prerequisites")
    _exact_int(obj["uid"], "prerequisite uid")
    _canonical_path(obj["python"], "python prerequisite")
    version = obj["python_version"]
    if type(version) is not list or len(version) != 3 or any(type(item) is not int or item < 0 for item in version):
        raise ValueError("invalid python version")
    if tuple(version) < (3, 12, 0):
        raise ValueError("python 3.12 or newer is required")
    _exact_bool(obj["venv"], "venv prerequisite")
    _canonical_path(obj["cc"], "compiler prerequisite")
    _canonical_path(obj["bash"], "bash prerequisite")


def _validate_source(value: object, request: Mapping[str, object]) -> None:
    obj = _exact_object(value, {"root", "device", "inode", "probe_device", "probe_inode", "manifest"}, "source")
    if _canonical_path(obj["root"], "source root") != request["source_root"]:
        raise ValueError("source root mismatch")
    for name in ("device", "inode", "probe_device", "probe_inode"):
        _exact_int(obj[name], f"source {name}")
    manifest = obj["manifest"]
    if type(manifest) is not dict or any(type(key) is not str or not key or type(digest) is not str for key, digest in manifest.items()):
        raise ValueError("invalid source manifest")
    for digest in manifest.values():
        _validate_hash(digest, "source manifest")


def _validate_prior(value: object) -> None:
    obj = _exact_object(value, {"present", "schema_version", "manifest_sha256", "manifest"}, "prior")
    present = _exact_bool(obj["present"], "prior present")
    if present:
        if type(obj["schema_version"]) is not int or obj["schema_version"] != 2 or type(obj["manifest"]) is not dict:
            raise ValueError("invalid prior manifest")
        _validate_hash(obj["manifest_sha256"], "prior manifest")
    elif any(obj[name] is not None for name in ("schema_version", "manifest_sha256", "manifest")):
        raise ValueError("absent prior has manifest metadata")


def _validate_effective(value: object) -> None:
    obj = _exact_object(value, {"bash", "autostart", "chooser"}, "effective")
    for name in obj:
        _exact_bool(obj[name], f"effective {name}")


def _validate_rollback(value: object) -> None:
    if value is None:
        return
    obj = _exact_object(value, {"path", "kind", "mode", "literal_target", "content", "content_sha256"}, "rollback")
    _canonical_path(obj["path"], "rollback path")
    if obj["kind"] not in {"absent", "file", "symlink"}:
        raise ValueError("invalid rollback kind")
    if obj["mode"] is not None and type(obj["mode"]) is not int:
        raise ValueError("invalid rollback mode")
    if obj["literal_target"] is not None:
        _exact_string(obj["literal_target"], "rollback target")
    if obj["content"] is not None:
        _exact_string(obj["content"], "rollback content")
    if obj["content_sha256"] is not None:
        _validate_hash(obj["content_sha256"], "rollback content")


def _validate_action(value: object, sequence: int, request: Mapping[str, object]) -> None:
    keys = {"sequence", "kind", "disposition", "path_or_token", "mode", "literal_target", "content_sha256", "prerequisite", "rollback"}
    if not isinstance(value, dict) or set(value) != keys or value["sequence"] != sequence:
        raise ValueError("invalid action keys or sequence")
    kinds = {"source-build", "wheel-build", "delegate-staging", "generation-staging", "generation-self-check", "activation-link", "command-link", "bash", "autostart", "chooser", "manifest", "rollback", "cleanup"}
    if value["kind"] not in kinds or value["disposition"] not in {"create", "replace", "remove", "preserve", "skip"}:
        raise ValueError("invalid action type")
    path = value["path_or_token"]
    if path not in {"$BUILD_ROOT", "$GENERATION_STAGE"}:
        _canonical_path(path, "action path")
    if value["mode"] is not None and type(value["mode"]) is not int:
        raise ValueError("invalid action mode")
    if value["literal_target"] is not None:
        _exact_string(value["literal_target"], "action target")
    if value["content_sha256"] is not None:
        _validate_hash(value["content_sha256"], "action content")
    if value["prerequisite"] is not None:
        _exact_string(value["prerequisite"], "action prerequisite")
    _validate_rollback(value["rollback"])
    if value["kind"] == "command-link":
        home = Path(str(request["home"]))
        current = Path(str(request["xdg_data_home"])) / "termrecall/current"
        command = Path(str(path)).name
        expected_paths = {str(home / ".local/bin" / name): str(current / f"venv/bin/{name}") for name in ("termrecall", "termrecall-bridge", "termrecall-nonblock")}
        if path not in expected_paths or value["literal_target"] != expected_paths[path]:
            raise ValueError("invalid command link target")
    if value["kind"] == "activation-link":
        expected_current = str(Path(str(request["xdg_data_home"])) / "termrecall/current")
        if path != expected_current or value["literal_target"] != "$GENERATION_STAGE":
            raise ValueError("invalid current activation target")


def _validate_lock(value: object, request: Mapping[str, object]) -> None:
    if not isinstance(value, dict) or set(value) != LOCK_KEYS:
        raise ValueError("invalid lock plan keys")
    config_root = str(Path(str(request["xdg_config_home"])) / "termrecall")
    if value["directory_path"] != config_root or value["lock_path"] != str(Path(config_root) / "lifecycle.lock"):
        raise ValueError("invalid lock plan paths")
    for name in ("directory_absent", "lock_absent", "may_create_directory", "may_create_lock"):
        if type(value[name]) is not bool:
            raise ValueError("invalid lock plan boolean")
    if value["may_create_directory"] != value["directory_absent"] or value["may_create_lock"] != value["lock_absent"]:
        raise ValueError("lock plan absence and creation permission disagree")
    if type(value["directory_mode"]) is not int or type(value["lock_mode"]) is not int or value["directory_mode"] != 0o700 or value["lock_mode"] != 0o600:
        raise ValueError("invalid lock plan modes")


def plan_from_bytes(raw: bytes, expected_request: Mapping[str, object]) -> dict[str, object]:
    value = _load(raw)
    if not isinstance(value, dict) or set(value) != PLAN_KEYS:
        raise ValueError("invalid plan keys")
    if value["probe_schema"] != PROBE_SCHEMA or value["plan_schema"] != PLAN_SCHEMA:
        raise ValueError("unknown probe or plan schema")
    request = _validate_request(value["request"])
    expected = _validate_request(dict(expected_request))
    if request != expected:
        raise ValueError("plan request does not match expected request")
    _validate_prerequisites(value["prerequisites"])
    _validate_source(value["source"], request)
    _validate_prior(value["prior"])
    _validate_effective(value["effective"])
    actions = value["actions"]
    if type(actions) is not list or len(actions) > 64:
        raise ValueError("invalid actions")
    for sequence, action in enumerate(actions, 1):
        _validate_action(action, sequence, request)
    _validate_lock(value["lock_infrastructure"], request)
    _validate_hash(value["state_fingerprint"], "state fingerprint")
    _validate_hash(value["plan_digest"], "plan digest")
    if value["rendered"] != render_plan(value):
        raise ValueError("rendered plan disagrees with plan")
    if value["plan_digest"] != compute_plan_digest(value):
        raise ValueError("plan digest disagrees with plan")
    return value


def _parser(command: str) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog=f"installer_probe.py {command}", allow_abbrev=False)
    for name in ("source-root", "home", "xdg-data-home", "xdg-config-home", "xdg-state-home"):
        parser.add_argument(f"--{name}", required=True, action="append")
    parser.add_argument("--mode", required=True, choices=sorted(MODES), action="append")
    for name in ("bash", "autostart", "chooser"):
        parser.add_argument(f"--{name}", required=True, choices=sorted(STATES), action="append")
    parser.add_argument("--dry-run", required=True, choices=("yes", "no"), action="append")
    if command == "validate-plan":
        parser.add_argument("--emit", required=True, choices=("json", "rendered"), action="append")
    if command == "launch-delegate":
        parser.add_argument("--expected-digest", required=True, action="append")
        parser.add_argument("--delegate-python", required=True, action="append")
        parser.add_argument("--wheel", required=True, action="append")
    return parser


def _one(namespace: argparse.Namespace, name: str) -> str:
    values = getattr(namespace, name)
    if len(values) != 1:
        raise ValueError(f"{name} must occur exactly once")
    return values[0]


def _parse_request(command: str, argv: Sequence[str]) -> tuple[dict[str, object], argparse.Namespace]:
    namespace = _parser(command).parse_args(list(argv))
    request: dict[str, object] = {
        "request_schema": REQUEST_SCHEMA,
        "source_root": _one(namespace, "source_root"),
        "home": _one(namespace, "home"),
        "xdg_data_home": _one(namespace, "xdg_data_home"),
        "xdg_config_home": _one(namespace, "xdg_config_home"),
        "xdg_state_home": _one(namespace, "xdg_state_home"),
        "mode": _one(namespace, "mode"),
        "bash": _one(namespace, "bash"),
        "autostart": _one(namespace, "autostart"),
        "chooser": _one(namespace, "chooser"),
        "dry_run": _one(namespace, "dry_run") == "yes",
    }
    return _validate_request(request), namespace


def _read_bounded(path: Path, maximum: int = 1_048_576) -> bytes:
    metadata = path.stat(follow_symlinks=False)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > maximum:
        raise ValueError("unsafe or oversized source file")
    raw = path.read_bytes()
    if len(raw) != metadata.st_size:
        raise ValueError("source file changed while reading")
    return raw


def _safe_source(request: Mapping[str, object]) -> dict[str, object]:
    root = Path(str(request["source_root"]))
    script = root / "installer_probe.py"
    root_stat = root.stat(follow_symlinks=False)
    script_stat = script.stat(follow_symlinks=False)
    running_root = Path(__file__).resolve().parents[2]
    if running_root != root.resolve():
        raise ValueError("running probe does not belong to source root")
    if not stat.S_ISDIR(root_stat.st_mode) or not stat.S_ISREG(script_stat.st_mode):
        raise ValueError("unsafe source root or probe")
    if root.is_symlink() or script.is_symlink() or root.resolve() != root or script.resolve() != script:
        raise ValueError("source root and probe must not be symlinks")
    if root_stat.st_uid != os.getuid() or script_stat.st_uid != os.getuid():
        raise ValueError("source objects have a foreign owner")
    if root_stat.st_mode & 0o022 or script_stat.st_mode & 0o022:
        raise ValueError("source objects are group/other writable")
    required_files = ("pyproject.toml", "setup.py", "MANIFEST.in", "installer_probe.py", "native/termrecall-nonblock.c", "src/termrecall/installer_probe.py", "src/termrecall/installer_contract.py")
    manifest: dict[str, str] = {}
    for name in required_files:
        path = root / name
        metadata = path.stat(follow_symlinks=False)
        if path.is_symlink() or metadata.st_uid != os.getuid() or metadata.st_mode & 0o022:
            raise ValueError("unsafe source manifest object")
        manifest[name] = hashlib.sha256(_read_bounded(path)).hexdigest()
    return {"root": str(root), "device": root_stat.st_dev, "inode": root_stat.st_ino, "probe_device": script_stat.st_dev, "probe_inode": script_stat.st_ino, "manifest": manifest}


def _fact(path: Path, *, read_content: bool = True) -> dict[str, object]:
    try:
        metadata = path.stat(follow_symlinks=False)
    except FileNotFoundError:
        return {"path": str(path), "kind": "absent"}
    if stat.S_ISLNK(metadata.st_mode):
        return {"path": str(path), "kind": "symlink", "mode": stat.S_IMODE(metadata.st_mode), "target": os.readlink(path)}
    fact: dict[str, object] = {"path": str(path), "kind": "file" if stat.S_ISREG(metadata.st_mode) else "directory", "mode": stat.S_IMODE(metadata.st_mode), "uid": metadata.st_uid, "size": metadata.st_size}
    if read_content and stat.S_ISREG(metadata.st_mode):
        if metadata.st_size > 1_048_576:
            raise ValueError("destination object exceeds read bound")
        fact["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    return fact


def _safe_ancestors(paths: Sequence[Path], uid: int) -> None:
    checked: set[Path] = set()
    for destination in paths:
        current = destination
        while not current.exists() and current != current.parent:
            current = current.parent
        while current not in checked:
            metadata = current.stat(follow_symlinks=False)
            if current.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
                raise ValueError("unsafe destination ancestor type")
            if metadata.st_uid not in {uid, 0}:
                raise ValueError("destination ancestor has foreign owner")
            if metadata.st_mode & 0o002 and not metadata.st_mode & stat.S_ISVTX:
                raise ValueError("destination ancestor is world writable")
            checked.add(current)
            if current == current.parent:
                break
            current = current.parent


def _prerequisites(env: Mapping[str, str]) -> dict[str, object]:
    python = Path(sys.executable).resolve()
    if sys.version_info < (3, 12):
        raise RuntimeError("Python 3.12 or newer is required")
    try:
        import venv  # noqa: F401
    except ImportError as exc:
        raise RuntimeError("Python venv is required") from exc
    path = env.get("PATH", os.defpath)
    cc = shutil.which(env.get("CC", "cc").split()[0], path=path)
    bash = shutil.which("bash", path=path)
    if cc is None or bash is None:
        raise RuntimeError("C compiler and Bash are required")
    return {"uid": os.getuid(), "python": str(python), "python_version": [sys.version_info.major, sys.version_info.minor, sys.version_info.micro], "venv": True, "cc": str(Path(cc).resolve()), "bash": str(Path(bash).resolve())}


def _before(path: Path) -> dict[str, object]:
    fact = _fact(path)
    kind = fact["kind"]
    if kind == "absent":
        return {"path": str(path), "kind": "absent", "mode": None, "literal_target": None, "content": None, "content_sha256": None}
    if kind == "symlink":
        return {"path": str(path), "kind": "symlink", "mode": fact["mode"], "literal_target": fact["target"], "content": None, "content_sha256": None}
    if kind != "file":
        raise ValueError("destination object is not a file or symlink")
    raw = _read_bounded(path)
    import base64
    return {"path": str(path), "kind": "file", "mode": fact["mode"], "literal_target": None, "content": base64.b64encode(raw).decode("ascii"), "content_sha256": hashlib.sha256(raw).hexdigest()}


def _effective(request: Mapping[str, object], paths: Mapping[str, Path]) -> dict[str, object]:
    result: dict[str, object] = {}
    for name in ("bash", "autostart", "chooser"):
        requested = request[name]
        if requested == "enable":
            result[name] = True
        elif requested == "disable":
            result[name] = False
        else:
            result[name] = paths[name].exists()
    return result


def _action(sequence: int, kind: str, disposition: str, target: Path | str, *, mode: int | None = None, literal_target: str | None = None, content_sha256: str | None = None, prerequisite: str | None = None, rollback: dict[str, object] | None = None) -> dict[str, object]:
    return {"sequence": sequence, "kind": kind, "disposition": disposition, "path_or_token": str(target), "mode": mode, "literal_target": literal_target, "content_sha256": content_sha256, "prerequisite": prerequisite, "rollback": rollback}


def build_plan(argv: Sequence[str], env: Mapping[str, str]) -> dict[str, object]:
    request, _ = _parse_request("plan", argv)
    if os.getuid() == 0 or env.get("SUDO_USER") or env.get("SUDO_UID"):
        raise PermissionError("privileged installation is refused")
    source = _safe_source(request)
    prerequisites = _prerequisites(env)
    home = Path(str(request["home"])); data_home = Path(str(request["xdg_data_home"])); config_home = Path(str(request["xdg_config_home"])); state_home = Path(str(request["xdg_state_home"]))
    data = data_home / "termrecall"; config = config_home / "termrecall"; state = state_home / "termrecall"; current = data / "current"; bin_root = home / ".local/bin"
    semantic_paths = {
        "manifest": config / "install-manifest.json", "current": current,
        "command": bin_root / "termrecall", "bridge": bin_root / "termrecall-bridge",
        "nonblock": bin_root / "termrecall-nonblock", "bashrc": home / ".bashrc",
        "bash": config / "bash-integration.bash", "autostart": config_home / "autostart/termrecall.desktop",
        "chooser": config / "config.json", "state": state,
    }
    _safe_ancestors((home, data_home, config_home, state_home, bin_root), os.getuid())
    fingerprint = _sha256([_fact(path) for path in semantic_paths.values()])
    config_absent = not config.exists()
    lock = config / "lifecycle.lock"
    lock_absent = not lock.exists()
    command_targets = {name: str(current / f"venv/bin/{name}") for name in ("termrecall", "termrecall-bridge", "termrecall-nonblock")}
    actions = [
        _action(1, "source-build", "create", "$BUILD_ROOT", mode=0o700, prerequisite="source"),
        _action(2, "wheel-build", "create", "$BUILD_ROOT", prerequisite="python"),
        _action(3, "delegate-staging", "create", "$BUILD_ROOT", mode=0o700),
        _action(4, "generation-staging", "create", "$GENERATION_STAGE", mode=0o700),
        _action(5, "generation-self-check", "preserve", "$GENERATION_STAGE"),
        _action(6, "activation-link", "create" if not current.exists() else "replace", current, literal_target="$GENERATION_STAGE", prerequisite="generation-self-check", rollback=_before(current)),
    ]
    for index, name in enumerate(command_targets, 7):
        link = bin_root / name
        actions.append(_action(index, "command-link", "create" if not link.exists() else "replace", link, literal_target=command_targets[name], prerequisite="activation-link", rollback=_before(link)))
    actions.extend([
        _action(10, "bash", str(request["bash"]) if request["bash"] == "preserve" else ("create" if request["bash"] == "enable" else "remove"), semantic_paths["bash"], mode=0o600),
        _action(11, "autostart", str(request["autostart"]) if request["autostart"] == "preserve" else ("create" if request["autostart"] == "enable" else "remove"), semantic_paths["autostart"], mode=0o600),
        _action(12, "chooser", str(request["chooser"]) if request["chooser"] == "preserve" else "replace", semantic_paths["chooser"], mode=0o600),
        _action(13, "manifest", "replace", semantic_paths["manifest"], mode=0o600),
        _action(14, "rollback", "preserve", config / "rollback"),
        _action(15, "cleanup", "remove", "$BUILD_ROOT"),
    ])
    prior_present = semantic_paths["manifest"].exists()
    prior: dict[str, object] = {"present": False, "schema_version": None, "manifest_sha256": None, "manifest": None}
    if prior_present:
        manifest_raw = _read_bounded(semantic_paths["manifest"], MAX_PAYLOAD_BYTES)
        manifest_value = _load(manifest_raw)
        if type(manifest_value) is not dict or manifest_value.get("schema_version") != 2:
            raise ValueError("unsupported prior manifest")
        prior = {"present": True, "schema_version": 2, "manifest_sha256": hashlib.sha256(manifest_raw).hexdigest(), "manifest": manifest_value}
    plan: dict[str, object] = {
        "probe_schema": PROBE_SCHEMA, "plan_schema": PLAN_SCHEMA, "request": request,
        "prerequisites": prerequisites, "source": source,
        "prior": prior,
        "effective": _effective(request, {"bash": semantic_paths["bash"], "autostart": semantic_paths["autostart"], "chooser": semantic_paths["chooser"]}),
        "actions": actions,
        "lock_infrastructure": {"directory_path": str(config), "lock_path": str(lock), "directory_absent": config_absent, "lock_absent": lock_absent, "may_create_directory": config_absent, "may_create_lock": lock_absent, "directory_mode": 0o700, "lock_mode": 0o600},
        "state_fingerprint": fingerprint, "rendered": "", "plan_digest": "",
    }
    plan["rendered"] = render_plan(plan)
    plan["plan_digest"] = compute_plan_digest(plan)
    plan_from_bytes(plan_to_bytes(plan), request)
    return plan


def _write_all(fd: int, payload: bytes, errors: list[BaseException]) -> None:
    try:
        view = memoryview(payload)
        while view:
            try:
                count = os.write(fd, view)
            except InterruptedError:
                continue
            if count <= 0:
                raise BrokenPipeError("short payload write")
            view = view[count:]
    except BaseException as exc:
        errors.append(exc)
    finally:
        try: os.close(fd)
        except OSError: pass


def _terminate_group(child: subprocess.Popen[bytes], timeout: float) -> None:
    if child.poll() is not None:
        return
    try:
        os.killpg(child.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        child.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        child.wait()


def _wait_delegate(child: subprocess.Popen[bytes], writer_errors: list[BaseException], *, timeout: float = 2.0) -> int:
    caught: list[int] = []
    old_handlers: dict[int, object] = {}

    def forward(signum: int, _frame: object) -> None:
        if not caught:
            caught.append(signum)
            try:
                os.killpg(child.pid, signum)
            except ProcessLookupError:
                pass

    try:
        for signum in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
            old_handlers[signum] = signal.signal(signum, forward)
        if writer_errors:
            _terminate_group(child, timeout)
            return 4
        while child.poll() is None and not caught:
            try:
                child.wait(timeout=0.05)
            except subprocess.TimeoutExpired:
                continue
        if caught:
            _terminate_group(child, timeout)
            return 128 + caught[0]
        return child.returncode
    finally:
        for signum, handler in old_handlers.items():
            signal.signal(signum, handler)
        if child.poll() is None:
            _terminate_group(child, timeout)


def _launch(argv: Sequence[str], env: Mapping[str, str]) -> int:
    request, namespace = _parse_request("launch-delegate", argv)
    if request["dry_run"] is not False:
        raise ValueError("launch-delegate requires --dry-run no")
    expected = _one(namespace, "expected_digest")
    _validate_hash(expected, "expected digest")
    # Reparse only common explicit arguments through the authoritative planner.
    common: list[str] = []
    skip = {"--expected-digest", "--delegate-python", "--wheel"}
    iterator = iter(argv)
    for item in iterator:
        try:
            value = next(iterator)
        except StopIteration as exc:
            raise ValueError("missing option value") from exc
        if item not in skip:
            common.extend((item, value))
    plan = build_plan(common, env)
    if plan["plan_digest"] != expected:
        return 4
    request_raw = _canonical(request); plan_raw = plan_to_bytes(plan)
    if len(request_raw) > MAX_PAYLOAD_BYTES or len(plan_raw) > MAX_PAYLOAD_BYTES:
        return 4
    request_r = request_w = plan_r = plan_w = -1
    child: subprocess.Popen[bytes] | None = None
    writers: list[threading.Thread] = []
    errors: list[BaseException] = []
    delegate = _canonical_path(_one(namespace, "delegate_python"), "delegate python")
    wheel = _canonical_path(_one(namespace, "wheel"), "wheel")
    try:
        request_r, request_w = os.pipe()
        plan_r, plan_w = os.pipe()
        child = subprocess.Popen([delegate, "-P", "-m", "termrecall.installer", "installer-bootstrap", "--request-fd", str(request_r), "--plan-fd", str(plan_r), "--expected-digest", expected, "--wheel", wheel], pass_fds=(request_r, plan_r), start_new_session=True, close_fds=True)
        os.close(request_r); request_r = -1
        os.close(plan_r); plan_r = -1
        writers = [threading.Thread(target=_write_all, args=(request_w, request_raw, errors)), threading.Thread(target=_write_all, args=(plan_w, plan_raw, errors))]
        request_w = plan_w = -1
        for writer in writers:
            writer.start()
        for writer in writers:
            writer.join()
        return _wait_delegate(child, errors)
    finally:
        for fd in (request_r, request_w, plan_r, plan_w):
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass
        for writer in writers:
            if writer.is_alive():
                writer.join(timeout=2.0)
        if child is not None and child.poll() is None:
            _terminate_group(child, 2.0)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if not arguments or arguments[0] not in {"plan", "validate-plan", "launch-delegate"}:
        print("error: expected plan, validate-plan, or launch-delegate", file=sys.stderr)
        return 2
    command, rest = arguments[0], arguments[1:]
    try:
        if command == "plan":
            sys.stdout.buffer.write(plan_to_bytes(build_plan(rest, os.environ)))
            return 0
        if command == "validate-plan":
            request, namespace = _parse_request(command, rest)
            raw = sys.stdin.buffer.read(MAX_PAYLOAD_BYTES + 1)
            plan = plan_from_bytes(raw, request)
            if _one(namespace, "emit") == "json":
                sys.stdout.buffer.write(plan_to_bytes(plan))
            else:
                sys.stdout.write(str(plan["rendered"]))
            return 0
        return _launch(rest, os.environ)
    except (ValueError, TypeError, argparse.ArgumentError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except (PermissionError, FileNotFoundError, OSError) as exc:
        print(f"refused: {type(exc).__name__}", file=sys.stderr)
        return 4


if __name__ == "__main__":
    raise SystemExit(main())
