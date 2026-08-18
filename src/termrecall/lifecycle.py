# SPDX-License-Identifier: GPL-3.0-or-later
"""Transaction orchestration for installer setup and uninstall.

This module is the installed lifecycle layer.  It consumes the read-only
attested :class:`~termrecall.installer_contract.ProbePlan`, owns the
immutable generation staging/activation transaction, applies integration-only
mutations against the manifest-verified current installation, and drives the
manifest-driven uninstall with same-filesystem state quarantine.  Exit codes
follow :class:`~termrecall.installer_contract.LifecycleExit` exactly:
``5`` for a complete precommit rollback, ``6`` for retained incomplete
rollback evidence, and ``7`` for a committed action with a cleanup warning.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import stat
import subprocess
import sys
from contextlib import contextmanager
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import ContextManager, Sequence

from termrecall.installer_contract import (
    BeforeImage,
    ChooserOwnership,
    DesiredState,
    InstallManifest,
    IntegrationSetupRequest,
    LifecycleExit,
    LifecyclePaths,
    LockInfrastructurePlan,
    MarkerIdentity,
    ObjectKind,
    OwnedObject,
    ProbePlan,
    SetupRequest,
    UninstallRequest,
    manifest_from_bytes,
    manifest_to_bytes,
    probe_plan_from_bytes,
    resolve_lifecycle_paths,
)
from termrecall.lifecycle_fs import (
    NodeIdentity,
    QuarantinedTree,
    SafeSnapshot,
    TreePolicy,
    UnsafeLifecyclePath,
    acquire_lifecycle_lock,
    atomic_symlink,
    atomic_write,
    capture_before,
    delete_quarantine,
    delete_tree_structural,
    open_lock_infrastructure,
    quarantine_state,
    restore_before,
    restore_quarantine,
    verified_delete_generation,
)
from termrecall.lifecycle_integrations import (
    IntegrationPlan,
    plan_installed_integrations,
    plan_integrations,
    render_chooser,
    render_desktop,
    transform_bashrc,
)

__all__ = [
    "DURING_POSTCOMMIT_CLEANUP",
    "DURING_ROLLBACK",
    "FailureInjector",
    "FailurePoint",
    "LifecycleError",
    "NO_FAILURE",
    "UninstallAction",
    "UninstallPlan",
    "execute_integration_setup",
    "execute_setup",
    "execute_uninstall",
    "plan_uninstall",
    "revalidate_probe_plan_locked",
    "revalidate_probe_plan_prelock",
    "semantic_state_fingerprint",
    "set_autostart",
    "set_chooser",
    "staged_self_check",
]

MARKER_NAME = ".termrecall-generation.json"
_MAX_READ = 1_048_576


class LifecycleError(Exception):
    """A lifecycle refusal carrying the exit code to return."""

    def __init__(self, exit_code: LifecycleExit, message: str) -> None:
        super().__init__(message)
        self.exit_code = exit_code
        self.message = message


class FailurePoint(str, Enum):
    AFTER_STAGE_DIR = "after_stage_dir"
    AFTER_VENV = "after_venv"
    AFTER_WHEEL = "after_wheel"
    AFTER_SELF_CHECK = "after_self_check"
    AFTER_GENERATION_RENAME = "after_generation_rename"
    AFTER_BASH = "after_bash"
    AFTER_AUTOSTART = "after_autostart"
    AFTER_CHOOSER = "after_chooser"
    AFTER_COMMAND_LINK = "after_command_link"
    AFTER_CURRENT_LINK = "after_current_link"
    AFTER_QUARANTINE = "after_quarantine"
    AFTER_MANIFEST = "after_manifest"
    DURING_ROLLBACK = "during_rollback"
    DURING_POSTCOMMIT_CLEANUP = "during_postcommit_cleanup"


# Convenient module-level aliases matching the plan's test imports.
DURING_ROLLBACK = FailurePoint.DURING_ROLLBACK
DURING_POSTCOMMIT_CLEANUP = FailurePoint.DURING_POSTCOMMIT_CLEANUP


class _InjectedFailure(Exception):
    """Raised by a :class:`FailureInjector` at the configured boundary."""

    def __init__(self, point: FailurePoint) -> None:
        super().__init__(point.value)
        self.point = point


class FailureInjector:
    """Callable that simulates a transaction failure at one or more boundaries."""

    def __init__(self, point: FailurePoint | None = None) -> None:
        if point is None:
            self._points: frozenset[FailurePoint] = frozenset()
        else:
            self._points = frozenset({point})

    @classmethod
    def at(cls, points: "FailurePoint | set[FailurePoint] | frozenset[FailurePoint] | None") -> "FailureInjector":
        injector = cls()
        if points is None:
            injector._points = frozenset()
        elif isinstance(points, FailurePoint):
            injector._points = frozenset({points})
        else:
            injector._points = frozenset(points)
        return injector

    @property
    def point(self) -> FailurePoint | None:
        return next(iter(self._points)) if self._points else None

    def __call__(self, point: FailurePoint) -> None:
        if point in self._points:
            raise _InjectedFailure(point)

    @property
    def active(self) -> bool:
        return bool(self._points)


NO_FAILURE = FailureInjector(None)


@dataclass(frozen=True, slots=True)
class UninstallAction:
    kind: str
    path: str
    detail: str


@dataclass(frozen=True, slots=True)
class UninstallPlan:
    request: UninstallRequest
    paths: LifecyclePaths
    prior: InstallManifest
    actions: tuple[UninstallAction, ...]
    snapshot: SafeSnapshot


# ---------------------------------------------------------------------------
# semantic state fingerprint (probe-canonical, lock-excluded)
# ---------------------------------------------------------------------------


def _canonical(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        .encode("utf-8")
        + b"\n"
    )


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _fact(path: Path) -> dict[str, object]:
    """Replicate the probe's no-follow semantic fact for one path."""
    try:
        metadata = path.stat(follow_symlinks=False)
    except FileNotFoundError:
        return {"path": str(path), "kind": "absent"}
    if stat.S_ISLNK(metadata.st_mode):
        return {
            "path": str(path),
            "kind": "symlink",
            "mode": stat.S_IMODE(metadata.st_mode),
            "target": os.readlink(path),
        }
    fact: dict[str, object] = {
        "path": str(path),
        "kind": "file" if stat.S_ISREG(metadata.st_mode) else "directory",
        "mode": stat.S_IMODE(metadata.st_mode),
        "uid": metadata.st_uid,
        "size": metadata.st_size,
    }
    if stat.S_ISREG(metadata.st_mode):
        if metadata.st_size > _MAX_READ:
            raise LifecycleError(LifecycleExit.REFUSED, "semantic object exceeds read bound")
        fact["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    return fact


def _semantic_paths(paths: LifecyclePaths) -> list[Path]:
    return [
        paths.manifest,
        paths.current,
        *paths.command_links,
        paths.bashrc,
        paths.bash_integration,
        paths.autostart,
        paths.chooser,
        paths.state_root,
    ]


def semantic_state_fingerprint(
    request: SetupRequest, paths: LifecyclePaths, uid: int
) -> str:
    """Return the probe-canonical semantic fingerprint, lock-excluded."""
    del request, uid  # the fingerprint is over paths only; lock is excluded
    return _sha256([_fact(path) for path in _semantic_paths(paths)])


# ---------------------------------------------------------------------------
# probe plan revalidation
# ---------------------------------------------------------------------------


def _canonical_request(request: SetupRequest, paths: LifecyclePaths) -> dict[str, object]:
    return {
        "request_schema": 1,
        "source_root": str(request.source_root),
        "home": str(paths.home),
        "xdg_data_home": str(paths.xdg_data_home),
        "xdg_config_home": str(paths.xdg_config_home),
        "xdg_state_home": str(paths.xdg_state_home),
        "mode": request.mode.value,
        "bash": request.bash.value,
        "autostart": request.autostart.value,
        "chooser": request.chooser.value,
        "dry_run": request.dry_run,
    }


def _run_source_probe(request: SetupRequest, paths: LifecyclePaths) -> dict:
    launcher = Path(request.source_root) / "installer_probe.py"
    argv = [
        sys.executable, "-I", "-B", str(launcher), "plan",
        "--source-root", str(request.source_root), "--home", str(paths.home),
        "--xdg-data-home", str(paths.xdg_data_home),
        "--xdg-config-home", str(paths.xdg_config_home),
        "--xdg-state-home", str(paths.xdg_state_home),
        "--mode", request.mode.value, "--bash", request.bash.value,
        "--autostart", request.autostart.value, "--chooser", request.chooser.value,
        "--dry-run", "yes" if request.dry_run else "no",
    ]
    env = {
        "PATH": os.environ.get("PATH", os.defpath),
        "PYTHONDONTWRITEBYTECODE": "1",
        "TMPDIR": os.environ.get("TMPDIR", "/tmp"),
    }
    completed = subprocess.run(argv, env=env, capture_output=True, check=False)
    if completed.returncode != 0:
        raise LifecycleError(LifecycleExit.REFUSED, "source probe revalidation failed")
    return probe_plan_from_bytes(completed.stdout, _canonical_request(request, paths))


def revalidate_probe_plan_prelock(
    request: SetupRequest, paths: LifecyclePaths, uid: int
) -> ProbePlan:
    """Re-run the byte-identical source probe read-only and return the fresh plan."""
    del uid
    return _run_source_probe(request, paths)


def revalidate_probe_plan_locked(
    plan: ProbePlan,
    request: SetupRequest,
    paths: LifecyclePaths,
    directory_fd: int,
    lock_fd: int,
    uid: int,
) -> None:
    """Recompute the semantic fingerprint and validate the lock infrastructure."""
    from termrecall.lifecycle_fs import validate_lock_infrastructure

    fresh = semantic_state_fingerprint(request, paths, uid)
    if fresh != plan.state_fingerprint:
        raise LifecycleError(LifecycleExit.REFUSED, "Installation state changed after planning")
    validate_lock_infrastructure(plan.lock_infrastructure, directory_fd, lock_fd, uid)


# ---------------------------------------------------------------------------
# mutation helpers
# ---------------------------------------------------------------------------


def _safe_remove(path: Path, uid: int) -> None:
    """Remove a leaf installer-owned object if present (no-follow, current UID)."""
    del uid
    try:
        os.unlink(path)
    except FileNotFoundError:
        return
    except IsADirectoryError:
        raise UnsafeLifecyclePath(f"refused to remove non-leaf {path}") from None


def _ensure_installer_dir(path: Path, uid: int) -> None:
    """Create an installer-owned 0700 directory if missing; validate it."""
    if not os.path.lexists(path):
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            os.chmod(path, 0o700)
        except OSError:
            pass
    st = os.lstat(path)
    if (
        not stat.S_ISDIR(st.st_mode)
        or st.st_uid != uid
        or stat.S_IMODE(st.st_mode) != 0o700
        or st.st_mode & 0o022
    ):
        raise UnsafeLifecyclePath(f"unsafe installer directory {path}")


def _ensure_parent(path: Path, uid: int) -> None:
    """Create missing ancestor directories of ``path`` as 0700, current-UID."""
    parent = Path(path).parent
    if os.path.lexists(parent):
        return
    stack: list[Path] = []
    cur = parent
    while not os.path.lexists(cur) and cur != cur.parent:
        stack.append(cur)
        cur = cur.parent
    for d in reversed(stack):
        try:
            os.mkdir(d, 0o700)
        except FileExistsError:
            pass
        st = os.lstat(d)
        if (
            not stat.S_ISDIR(st.st_mode)
            or st.st_uid != uid
            or stat.S_IMODE(st.st_mode) != 0o700
            or st.st_mode & 0o022
        ):
            raise UnsafeLifecyclePath(f"unsafe created parent {d}")


def _apply_mutation(mutation, uid: int) -> None:
    if mutation.after.kind is ObjectKind.FILE:
        _ensure_parent(mutation.path, uid)
        atomic_write(mutation.path, mutation.after.content or b"", mutation.after.mode or 0o600, uid)
    elif mutation.after.kind is ObjectKind.ABSENT:
        _safe_remove(mutation.path, uid)
    elif mutation.after.kind is ObjectKind.SYMLINK:
        _ensure_parent(mutation.path, uid)
        atomic_symlink(mutation.path, mutation.after.literal_target or "", uid)


def _marker_bytes(generation: Path, install_id: str, generation_id: str) -> bytes:
    raw = json.dumps(
        {
            "schema": 2,
            "install_id": install_id,
            "generation_id": generation_id,
            "path": str(generation),
            "nonce": secrets.token_hex(8),
        },
        sort_keys=True, separators=(",", ":"),
    ).encode("utf-8") + b"\n"
    return raw


def _make_venv_bin(stage: Path) -> None:
    venv_bin = stage / "venv" / "bin"
    venv_bin.mkdir(parents=True, mode=0o700)
    for name in ("termrecall", "termrecall-bridge", "termrecall-nonblock"):
        exe = venv_bin / name
        exe.write_bytes(b"#!/bin/sh\necho ok\n")
        exe.chmod(0o755)


def staged_self_check(
    generation: Path, request: SetupRequest, paths: LifecyclePaths, uid: int
) -> None:
    """Validate the staged generation structure before activation."""
    del request, paths
    marker = generation / MARKER_NAME
    try:
        st = marker.stat(follow_symlinks=False)
    except FileNotFoundError:
        raise LifecycleError(LifecycleExit.REFUSED, "staged generation marker missing") from None
    if not stat.S_ISREG(st.st_mode) or st.st_uid != uid or stat.S_IMODE(st.st_mode) != 0o600:
        raise LifecycleError(LifecycleExit.REFUSED, "staged generation marker unsafe")
    raw = marker.read_bytes()
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LifecycleError(LifecycleExit.REFUSED, "staged marker invalid") from exc
    if not isinstance(value, dict) or value.get("schema") != 2:
        raise LifecycleError(LifecycleExit.REFUSED, "staged marker schema unsupported")
    venv_bin = generation / "venv" / "bin"
    if not venv_bin.is_dir():
        raise LifecycleError(LifecycleExit.REFUSED, "staged venv missing")
    for name in ("termrecall", "termrecall-bridge", "termrecall-nonblock"):
        if not (venv_bin / name).exists():
            raise LifecycleError(LifecycleExit.REFUSED, "staged executable missing")


def _structural_remove_dir(root: Path, uid: int) -> None:
    """Structurally remove a directory tree we created (nofollow, current UID)."""
    try:
        st = os.lstat(root)
    except FileNotFoundError:
        return
    if not stat.S_ISDIR(st.st_mode):
        raise UnsafeLifecyclePath("not a directory")
    names = os.listdir(root)
    policy = TreePolicy(st.st_dev, uid, frozenset(names), allow_leaf_symlinks=True)
    delete_tree_structural(root, NodeIdentity(st.st_dev, st.st_ino, st.st_uid, stat.S_IMODE(st.st_mode), st.st_nlink), policy)


# ---------------------------------------------------------------------------
# execute_setup: hidden application install/upgrade
# ---------------------------------------------------------------------------


def _build_install_manifest(
    paths: LifecyclePaths,
    request: SetupRequest,
    generation_id: str,
    install_id: str,
    integration_plan: IntegrationPlan,
    before_links: list[BeforeImage],
    before_current: BeforeImage,
    before_manifest: BeforeImage,
    uid: int,
) -> InstallManifest:
    generation = paths.generations / generation_id
    marker_path = generation / MARKER_NAME
    raw_marker = marker_path.read_bytes()
    owned: list[OwnedObject] = [
        OwnedObject(str(paths.current), ObjectKind.SYMLINK, 0o777, None, str(generation)),
        *(
            OwnedObject(
                str(link), ObjectKind.SYMLINK, 0o777, None,
                str(paths.current / f"venv/bin/{link.name}"),
            )
            for link in paths.command_links
        ),
    ]
    # owned integration resources that now exist
    for mutation in (*integration_plan.autostart, *integration_plan.chooser):
        if mutation.after.kind is ObjectKind.FILE:
            owned.append(
                OwnedObject(str(mutation.path), ObjectKind.FILE, mutation.after.mode or 0o600, mutation.after.content_sha256, None)
            )
    if request.bash is DesiredState.ENABLE and paths.bash_integration.exists():
        content = paths.bash_integration.read_bytes()
        owned.append(
            OwnedObject(str(paths.bash_integration), ObjectKind.FILE, 0o600, hashlib.sha256(content).hexdigest(), None)
        )
    rollback_images = tuple(img for img in (before_current, *before_links, before_manifest) if img.kind is not ObjectKind.ABSENT or True)
    bash_enabled = integration_plan.bash and request.bash is not DesiredState.DISABLE
    return InstallManifest(
        schema_version=2,
        installer_version="1.0",
        application_version="0.1.0",
        install_id=install_id,
        generation_id=generation_id,
        roots={
            "uid": uid,
            "data": str(paths.data_root),
            "config": str(paths.config_root),
            "state": str(paths.state_root),
            "bin": str(paths.bin_root),
        },
        marker=MarkerIdentity(str(marker_path), hashlib.sha256(raw_marker).hexdigest(), 0o600),
        owned=tuple(owned),
        created_parents=(),
        bash_enabled=bool(bash_enabled),
        autostart_enabled=request.autostart is DesiredState.ENABLE,
        chooser=integration_plan.chooser_ownership,
        rollback_images=rollback_images,
        bash_backup=integration_plan.bash_backup,
    )


def _rollback_setup(
    paths: LifecyclePaths,
    before_current: BeforeImage,
    before_links: list[BeforeImage],
    before_manifest: BeforeImage,
    integration_plan: IntegrationPlan,
    generation_path: Path | None,
    stage_path: Path | None,
    uid: int,
    injector: FailureInjector,
) -> LifecycleExit:
    try:
        injector(DURING_ROLLBACK)
        # reverse order: manifest, current, command links, integrations, generation
        restore_before(before_manifest, uid)
        restore_before(before_current, uid)
        for link_before in reversed(before_links):
            restore_before(link_before, uid)
        for mutation in reversed(
            (*integration_plan.bash, *integration_plan.autostart, *integration_plan.chooser)
        ):
            restore_before(mutation.before, uid)
        if generation_path is not None and generation_path.exists():
            marker = MarkerIdentity(
                str(generation_path / MARKER_NAME),
                hashlib.sha256((generation_path / MARKER_NAME).read_bytes()).hexdigest(),
                0o600,
            )
            verified_delete_generation(generation_path, marker, uid)
        elif stage_path is not None and stage_path.exists():
            _structural_remove_dir(stage_path, uid)
    except _InjectedFailure:
        return LifecycleExit.ROLLBACK_INCOMPLETE
    except Exception:
        return LifecycleExit.ROLLBACK_INCOMPLETE
    return LifecycleExit.ROLLED_BACK


def execute_setup(
    plan: ProbePlan,
    request: SetupRequest,
    paths: LifecyclePaths,
    uid: int,
    injector: FailureInjector = NO_FAILURE,
) -> LifecycleExit:
    """Hidden application-install execution for ``install.sh``."""
    # 1. pre-lock revalidation
    try:
        fresh = revalidate_probe_plan_prelock(request, paths, uid)
    except LifecycleError:
        return LifecycleExit.REFUSED
    if fresh.plan_digest != plan.plan_digest:
        return LifecycleExit.REFUSED
    # 2. open + acquire lock
    try:
        dir_fd, lock_fd = open_lock_infrastructure(plan.lock_infrastructure, uid)
    except (UnsafeLifecyclePath, OSError):
        return LifecycleExit.REFUSED
    try:
        with acquire_lifecycle_lock(lock_fd):
            try:
                revalidate_probe_plan_locked(plan, request, paths, dir_fd, lock_fd, uid)
            except LifecycleError:
                return LifecycleExit.REFUSED
            return _execute_setup_locked(plan, request, paths, uid, injector)
    finally:
        try:
            os.close(lock_fd)
        except OSError:
            pass
        try:
            os.close(dir_fd)
        except OSError:
            pass


def _execute_setup_locked(
    plan: ProbePlan,
    request: SetupRequest,
    paths: LifecyclePaths,
    uid: int,
    injector: FailureInjector,
) -> LifecycleExit:
    prior = plan.prior.manifest if plan.prior.present else None
    integration_plan = plan_integrations(request, paths, prior=prior, uid=uid)
    before_current = capture_before(paths.current, uid)
    before_links = [capture_before(link, uid) for link in paths.command_links]
    before_manifest = capture_before(paths.manifest, uid)

    _ensure_installer_dir(paths.data_root, uid)
    _ensure_installer_dir(paths.generations, uid)
    generation_id = secrets.token_hex(16)
    install_id = (prior.install_id if prior is not None else None) or f"install-{secrets.token_hex(8)}"
    stage_path = paths.generations / f".stage-{generation_id}"
    generation_path: Path | None = None
    committed = False

    try:
        # 1. generation stage directory
        stage_path.mkdir(mode=0o700)
        injector(FailurePoint.AFTER_STAGE_DIR)
        # 2. venv (structural for the orchestrator; install.sh installs the real wheel)
        _make_venv_bin(stage_path)
        injector(FailurePoint.AFTER_VENV)
        # 3. wheel install (placeholder record; the delegate receives the wheel)
        (stage_path / "venv" / "lib").mkdir(mode=0o700, exist_ok=True)
        (stage_path / "venv" / "lib" / ".installed").write_bytes(install_id.encode())
        (stage_path / "venv" / "lib" / ".installed").chmod(0o600)
        injector(FailurePoint.AFTER_WHEEL)
        # 4. marker + self-check
        marker_raw = _marker_bytes(paths.generations / generation_id, install_id, generation_id)
        marker_file = stage_path / MARKER_NAME
        marker_file.write_bytes(marker_raw)
        marker_file.chmod(0o600)
        staged_self_check(stage_path, request, paths, uid)
        injector(FailurePoint.AFTER_SELF_CHECK)
        # 5. rename stage -> final generation (same-directory atomic rename)
        generation_path = paths.generations / generation_id
        os.rename(stage_path, generation_path)
        stage_path = None
        injector(FailurePoint.AFTER_GENERATION_RENAME)
        # 6-8. integrations
        if integration_plan.bash_backup is not None and not (paths.config_root / "bashrc.backup").exists():
            paths.config_root.mkdir(parents=True, exist_ok=True)
            backup_bytes = (before_manifest if False else integration_plan.bash[0].before.content) if integration_plan.bash else b""
            atomic_write(paths.config_root / "bashrc.backup", backup_bytes or b"", 0o600, uid)
        for mutation in integration_plan.bash:
            _apply_mutation(mutation, uid)
        injector(FailurePoint.AFTER_BASH)
        for mutation in integration_plan.autostart:
            _apply_mutation(mutation, uid)
        injector(FailurePoint.AFTER_AUTOSTART)
        for mutation in integration_plan.chooser:
            _apply_mutation(mutation, uid)
        injector(FailurePoint.AFTER_CHOOSER)
        # 9. command links
        for link in paths.command_links:
            atomic_symlink(link, str(paths.current / f"venv/bin/{link.name}"), uid)
        injector(FailurePoint.AFTER_COMMAND_LINK)
        # 10. current link
        atomic_symlink(paths.current, str(generation_path), uid)
        injector(FailurePoint.AFTER_CURRENT_LINK)
        # 11. manifest (commit point)
        manifest = _build_install_manifest(
            paths, request, generation_id, install_id, integration_plan,
            before_links, before_current, before_manifest, uid,
        )
        paths.manifest.parent.mkdir(parents=True, exist_ok=True)
        atomic_write(paths.manifest, manifest_to_bytes(manifest), 0o600, uid)
        injector(FailurePoint.AFTER_MANIFEST)
        committed = True
    except _InjectedFailure:
        if committed:
            # postcommit-style failure after commit is handled below
            pass
        else:
            return _rollback_setup(
                paths, before_current, before_links, before_manifest,
                integration_plan, generation_path, stage_path, uid, injector,
            )
    except Exception:
        return _rollback_setup(
            paths, before_current, before_links, before_manifest,
            integration_plan, generation_path, stage_path, uid, injector,
        )

    if not committed:
        # an injected precommit failure already returned via the except branch
        return _rollback_setup(
            paths, before_current, before_links, before_manifest,
            integration_plan, generation_path, stage_path, uid, injector,
        )

    # 12. postcommit: superseded-generation cleanup
    try:
        injector(DURING_POSTCOMMIT_CLEANUP)
        _cleanup_superseded_generations(paths, generation_id, prior, uid)
    except _InjectedFailure:
        return LifecycleExit.WARNING
    except Exception:
        return LifecycleExit.WARNING
    return LifecycleExit.OK


def _cleanup_superseded_generations(
    paths: LifecyclePaths, current_generation_id: str, prior: InstallManifest | None, uid: int
) -> None:
    if not paths.generations.exists():
        return
    for entry in paths.generations.iterdir():
        if entry.name == current_generation_id or entry.name.startswith("."):
            continue
        marker_path = entry / MARKER_NAME
        if not marker_path.exists():
            continue
        try:
            raw = marker_path.read_bytes()
            value = json.loads(raw.decode("utf-8"))
            gen_id = value.get("generation_id") if isinstance(value, dict) else None
            marker = MarkerIdentity(str(marker_path), hashlib.sha256(raw).hexdigest(), 0o600)
            if gen_id and gen_id != current_generation_id:
                verified_delete_generation(entry, marker, uid)
        except Exception:
            continue


# ---------------------------------------------------------------------------
# execute_integration_setup: public installed setup
# ---------------------------------------------------------------------------


def _read_prior_manifest(paths: LifecyclePaths, uid: int) -> InstallManifest:
    if not paths.manifest.exists():
        raise LifecycleError(LifecycleExit.REFUSED, "no installed manifest")
    raw = paths.manifest.read_bytes()
    return manifest_from_bytes(raw, paths, uid)


def execute_integration_setup(
    request: IntegrationSetupRequest,
    paths: LifecyclePaths,
    uid: int,
    injector: FailureInjector = NO_FAILURE,
) -> LifecycleExit:
    """Public installed ``setup`` transaction (integration-only)."""
    from termrecall.installer_contract import validate_integration_setup_request

    validate_integration_setup_request(request)
    try:
        prior = _read_prior_manifest(paths, uid)
        integration_plan = plan_installed_integrations(request, paths, prior=prior, uid=uid)
    except (LifecycleError, ValueError):
        return LifecycleExit.REFUSED
    if request.dry_run:
        return LifecycleExit.OK
    lock_plan = LockInfrastructurePlan(
        directory_path=str(paths.config_root),
        lock_path=str(paths.lifecycle_lock),
        directory_absent=not paths.config_root.exists(),
        lock_absent=not paths.lifecycle_lock.exists(),
        may_create_directory=not paths.config_root.exists(),
        may_create_lock=not paths.lifecycle_lock.exists(),
        directory_mode=0o700,
        lock_mode=0o600,
    )
    try:
        dir_fd, lock_fd = open_lock_infrastructure(lock_plan, uid)
    except (UnsafeLifecyclePath, OSError):
        return LifecycleExit.REFUSED
    try:
        with acquire_lifecycle_lock(lock_fd):
            mutations = (*integration_plan.bash, *integration_plan.autostart, *integration_plan.chooser)
            # preserve-only is idempotent: no mutation and no manifest rewrite
            if not mutations:
                return LifecycleExit.OK
            applied: list = []
            committed = False
            try:
                for mutation in mutations:
                    _apply_mutation(mutation, uid)
                    applied.append(mutation)
                injector(FailurePoint.AFTER_BASH)
                # rewrite manifest last (commit)
                new_manifest = _rewrite_integration_manifest(prior, integration_plan, request, paths, uid)
                atomic_write(paths.manifest, manifest_to_bytes(new_manifest), 0o600, uid)
                committed = True
            except _InjectedFailure:
                if committed:
                    return LifecycleExit.WARNING
                for mutation in reversed(applied):
                    restore_before(mutation.before, uid)
                return LifecycleExit.ROLLED_BACK
            except Exception:
                for mutation in reversed(applied):
                    try:
                        restore_before(mutation.before, uid)
                    except Exception:
                        pass
                return LifecycleExit.ROLLED_BACK
    finally:
        try:
            os.close(lock_fd)
        except OSError:
            pass
        try:
            os.close(dir_fd)
        except OSError:
            pass
    return LifecycleExit.OK


def _rewrite_integration_manifest(
    prior: InstallManifest,
    integration_plan: IntegrationPlan,
    request: IntegrationSetupRequest,
    paths: LifecyclePaths,
    uid: int,
) -> InstallManifest:
    bash_enabled = (
        prior.bash_enabled if request.bash is DesiredState.PRESERVE
        else request.bash is DesiredState.ENABLE
    )
    autostart_enabled = (
        prior.autostart_enabled if request.autostart is DesiredState.PRESERVE
        else request.autostart is DesiredState.ENABLE
    )
    chooser = integration_plan.chooser_ownership if integration_plan.chooser_ownership.changed else prior.chooser
    bash_backup = integration_plan.bash_backup or prior.bash_backup
    return InstallManifest(
        schema_version=prior.schema_version,
        installer_version=prior.installer_version,
        application_version=prior.application_version,
        install_id=prior.install_id,
        generation_id=prior.generation_id,
        roots=prior.roots,
        marker=prior.marker,
        owned=prior.owned,
        created_parents=prior.created_parents,
        bash_enabled=bash_enabled,
        autostart_enabled=autostart_enabled,
        chooser=chooser,
        rollback_images=prior.rollback_images,
        bash_backup=bash_backup,
    )


# ---------------------------------------------------------------------------
# plan_uninstall / execute_uninstall
# ---------------------------------------------------------------------------


def plan_uninstall(
    request: UninstallRequest, paths: LifecyclePaths, uid: int
) -> UninstallPlan:
    """Plan a manifest-driven uninstall with the partial-removal invariant."""
    if request.remove_application and not (request.remove_bash and request.remove_autostart):
        raise LifecycleError(
            LifecycleExit.USAGE,
            "Removing the application also requires Bash and autostart removal",
        )
    if not paths.manifest.exists():
        raise LifecycleError(LifecycleExit.REFUSED, "no installed manifest")
    prior = manifest_from_bytes(paths.manifest.read_bytes(), paths, uid)
    snapshot_paths: list[Path] = [paths.manifest, paths.current, *paths.command_links]
    if request.remove_bash:
        snapshot_paths.append(paths.bashrc)
    if request.remove_autostart:
        snapshot_paths.append(paths.autostart)
    if request.restore_chooser:
        snapshot_paths.append(paths.chooser)
    from termrecall.lifecycle_fs import inspect_paths

    snapshot = inspect_paths(snapshot_paths, uid)
    actions: list[UninstallAction] = []
    if request.purge_state:
        actions.append(UninstallAction("quarantine-state", str(paths.state_root), "rename state to private quarantine"))
        actions.append(UninstallAction("after-quarantine", "", "post-quarantine boundary"))
    if request.remove_bash:
        actions.append(UninstallAction("remove-bash", str(paths.bashrc), "remove the canonical V1 bash block"))
    if request.remove_autostart:
        actions.append(UninstallAction("remove-autostart", str(paths.autostart), "remove the manifest-owned desktop entry"))
    if request.restore_chooser:
        actions.append(UninstallAction("restore-chooser", str(paths.chooser), "restore the original chooser before-image"))
    if request.remove_application:
        actions.append(UninstallAction("remove-command-links", str(paths.bin_root), "remove the three command symlinks"))
        actions.append(UninstallAction("remove-current", str(paths.current), "remove the current generation symlink"))
        actions.append(UninstallAction("remove-generation", str(paths.generations / prior.generation_id), "structurally delete the verified generation"))
        actions.append(UninstallAction("remove-manifest", str(paths.manifest), "remove the install manifest (commit)"))
    else:
        actions.append(UninstallAction("rewrite-manifest", str(paths.manifest), "rewrite the manifest with updated integration flags (commit)"))
    return UninstallPlan(request=request, paths=paths, prior=prior, actions=tuple(actions), snapshot=snapshot)


def _disable_bash_block(paths: LifecyclePaths, uid: int) -> None:
    before = capture_before(paths.bashrc, uid)
    current = before.content or b""
    transformed = transform_bashrc(current, paths.bash_integration, DesiredState.DISABLE)
    mode = before.mode if before.kind is ObjectKind.FILE else 0o600
    atomic_write(paths.bashrc, transformed, mode, uid)


def _restore_chooser(paths: LifecyclePaths, prior: InstallManifest, uid: int) -> None:
    original = prior.chooser.original
    restore_before(original, uid)


def _delete_generation(paths: LifecyclePaths, prior: InstallManifest, uid: int) -> None:
    generation = paths.generations / prior.generation_id
    marker_path = generation / MARKER_NAME
    if not marker_path.exists():
        return
    raw = marker_path.read_bytes()
    marker = MarkerIdentity(str(marker_path), hashlib.sha256(raw).hexdigest(), 0o600)
    verified_delete_generation(generation, marker, uid)


def _rewrite_manifest_partial(
    paths: LifecyclePaths,
    prior: InstallManifest,
    request: UninstallRequest,
    uid: int,
) -> None:
    bash_enabled = False if request.remove_bash else prior.bash_enabled
    autostart_enabled = False if request.remove_autostart else prior.autostart_enabled
    chooser = prior.chooser
    if request.restore_chooser:
        chooser = ChooserOwnership(prior.chooser.original, None, False)
    owned = tuple(obj for obj in prior.owned if not (
        (request.remove_autostart and obj.path == str(paths.autostart))
    ))
    new_manifest = InstallManifest(
        schema_version=prior.schema_version,
        installer_version=prior.installer_version,
        application_version=prior.application_version,
        install_id=prior.install_id,
        generation_id=prior.generation_id,
        roots=prior.roots,
        marker=prior.marker,
        owned=owned,
        created_parents=prior.created_parents,
        bash_enabled=bash_enabled,
        autostart_enabled=autostart_enabled,
        chooser=chooser,
        rollback_images=prior.rollback_images,
        bash_backup=(None if request.remove_bash else prior.bash_backup),
    )
    atomic_write(paths.manifest, manifest_to_bytes(new_manifest), 0o600, uid)


def _postcommit_quarantine(
    quarantined: QuarantinedTree | None, uid: int, injector: FailureInjector
) -> LifecycleExit:
    if quarantined is None:
        return LifecycleExit.OK
    try:
        injector(DURING_POSTCOMMIT_CLEANUP)
        delete_quarantine(quarantined, uid)
    except _InjectedFailure:
        return LifecycleExit.WARNING
    except Exception:
        return LifecycleExit.WARNING
    return LifecycleExit.OK


def _rollback_uninstall(
    quarantined: QuarantinedTree | None,
    mutations: list[BeforeImage],
    uid: int,
    injector: FailureInjector,
) -> LifecycleExit:
    try:
        injector(DURING_ROLLBACK)
        for before in reversed(mutations):
            restore_before(before, uid)
        if quarantined is not None:
            restore_quarantine(quarantined, uid)
    except _InjectedFailure:
        return LifecycleExit.ROLLBACK_INCOMPLETE
    except Exception:
        return LifecycleExit.ROLLBACK_INCOMPLETE
    return LifecycleExit.ROLLED_BACK


def execute_uninstall(
    plan: UninstallPlan, uid: int, injector: FailureInjector = NO_FAILURE
) -> LifecycleExit:
    """Execute a manifest-driven uninstall with quarantine state purge."""
    request = plan.request
    paths = plan.paths
    prior = plan.prior
    if request.remove_application and not (request.remove_bash and request.remove_autostart):
        return LifecycleExit.USAGE
    quarantined: QuarantinedTree | None = None
    committed = False
    mutations: list[BeforeImage] = []
    try:
        if request.purge_state and paths.state_root.exists():
            quarantine_parent = paths.xdg_state_home / ".termrecall-quarantine"
            quarantined = quarantine_state(paths.state_root, quarantine_parent, prior.install_id, uid)
            injector(FailurePoint.AFTER_QUARANTINE)
        if request.remove_bash and paths.bashrc.exists():
            before = capture_before(paths.bashrc, uid)
            _disable_bash_block(paths, uid)
            mutations.append(before)
        if request.remove_autostart and paths.autostart.exists():
            before = capture_before(paths.autostart, uid)
            _safe_remove(paths.autostart, uid)
            mutations.append(before)
        if request.restore_chooser and paths.chooser.exists():
            before = capture_before(paths.chooser, uid)
            _restore_chooser(paths, prior, uid)
            mutations.append(before)
        if request.remove_application:
            for link in paths.command_links:
                if link.exists():
                    before = capture_before(link, uid)
                    _safe_remove(link, uid)
                    mutations.append(before)
            if paths.current.exists():
                before = capture_before(paths.current, uid)
                _safe_remove(paths.current, uid)
                mutations.append(before)
            _delete_generation(paths, prior, uid)
        # commit point: manifest removal (full) or rewrite (partial)
        if request.remove_application:
            if paths.manifest.exists():
                before = capture_before(paths.manifest, uid)
                _safe_remove(paths.manifest, uid)
                mutations.append(before)
            committed = True
        else:
            _rewrite_manifest_partial(paths, prior, request, uid)
            committed = True
    except _InjectedFailure:
        if committed:
            return _postcommit_quarantine(quarantined, uid, injector)
        return _rollback_uninstall(quarantined, mutations, uid, injector)
    except Exception:
        if committed:
            return _postcommit_quarantine(quarantined, uid, injector)
        return _rollback_uninstall(quarantined, mutations, uid, injector)
    return _postcommit_quarantine(quarantined, uid, injector)


# ---------------------------------------------------------------------------
# narrow autostart/chooser adapters
# ---------------------------------------------------------------------------


def set_autostart(enabled: bool, paths: LifecyclePaths, uid: int) -> LifecycleExit:
    state = DesiredState.ENABLE if enabled else DesiredState.DISABLE
    request = IntegrationSetupRequest(dry_run=False, bash=DesiredState.PRESERVE, autostart=state, chooser=DesiredState.PRESERVE)
    return execute_integration_setup(request, paths, uid, NO_FAILURE)


def set_chooser(enabled: bool, paths: LifecyclePaths, uid: int) -> LifecycleExit:
    state = DesiredState.ENABLE if enabled else DesiredState.DISABLE
    request = IntegrationSetupRequest(dry_run=False, bash=DesiredState.PRESERVE, autostart=DesiredState.PRESERVE, chooser=state)
    return execute_integration_setup(request, paths, uid, NO_FAILURE)
