# SPDX-License-Identifier: GPL-3.0-or-later
"""Task 4: install orchestration, manifest lifecycle, and quarantine uninstall.

These tests pin the transactional setup/uninstall orchestrator: the failure
boundary matrix with exact 5/6/7 exit-code semantics, semantic fingerprint
membership and lock-infrastructure exclusion, pre-lock and locked
revalidation refusal, the public integration-only setup transaction, the
partial/full uninstall manifest lifecycle, and state-purge quarantine.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import stat
import subprocess
import sys
from dataclasses import fields
from pathlib import Path

import pytest

from termrecall.installer_contract import (
    BeforeImage,
    ChooserOwnership,
    DesiredState,
    InstallManifest,
    IntegrationSetupRequest,
    LifecycleExit,
    LifecyclePaths,
    MarkerIdentity,
    ObjectKind,
    OwnedObject,
    ProbePlan,
    SetupMode,
    SetupRequest,
    UninstallRequest,
    manifest_from_bytes,
    manifest_to_bytes,
    probe_plan_from_bytes,
    resolve_lifecycle_paths,
)
from termrecall.lifecycle import (
    DURING_POSTCOMMIT_CLEANUP,
    DURING_ROLLBACK,
    FailureInjector,
    FailurePoint,
    NO_FAILURE,
    UninstallAction,
    UninstallPlan,
    execute_integration_setup,
    execute_setup,
    execute_uninstall,
    plan_uninstall,
    semantic_state_fingerprint,
    set_autostart,
    set_chooser,
    staged_self_check,
)
from termrecall.lifecycle_fs import capture_before

ROOT = Path(__file__).parents[2]
UID = os.getuid()
MARKER_NAME = ".termrecall-generation.json"


# ---------------------------------------------------------------------------
# fixtures and helpers
# ---------------------------------------------------------------------------


def _make_roots(tmp_path: Path) -> tuple[LifecyclePaths, dict[str, Path]]:
    home = tmp_path / "home"
    home.mkdir(parents=True, mode=0o700)
    paths = resolve_lifecycle_paths({}, home)
    roots = {
        "home": home, "data": paths.xdg_data_home, "config": paths.xdg_config_home,
        "state": paths.xdg_state_home, "bin": paths.bin_root,
        "temp": tmp_path / "tmp", "cache": tmp_path / "cache",
    }
    for root in roots.values():
        root.mkdir(parents=True, exist_ok=True)
        root.chmod(0o755)
    home.chmod(0o700)
    return paths, roots


def _write_chooser(paths: LifecyclePaths, enabled: bool) -> None:
    from termrecall.lifecycle_integrations import render_chooser
    paths.config_root.mkdir(parents=True, exist_ok=True)
    paths.config_root.chmod(0o700)
    paths.chooser.write_bytes(render_chooser(enabled))
    paths.chooser.chmod(0o600)


def _write_bash_block(paths: LifecyclePaths) -> None:
    from termrecall.lifecycle_integrations import _v1_block  # type: ignore[attr-defined]
    paths.bashrc.parent.mkdir(parents=True, exist_ok=True)
    block = _v1_block(paths.bash_integration)
    paths.bashrc.write_bytes(b"alias ll='ls -l'\n" + b"\n" + block)
    paths.bashrc.chmod(0o644)
    paths.bash_integration.parent.mkdir(parents=True, exist_ok=True)
    paths.bash_integration.parent.chmod(0o700)
    paths.bash_integration.write_bytes(b"# integration\n")
    paths.bash_integration.chmod(0o600)


def _write_autostart(paths: LifecyclePaths) -> None:
    from termrecall.lifecycle_integrations import render_desktop
    paths.autostart.parent.mkdir(parents=True, exist_ok=True)
    paths.autostart.parent.chmod(0o700)
    paths.autostart.write_bytes(render_desktop(paths.current / "venv/bin/termrecall"))
    paths.autostart.chmod(0o600)


def _make_generation(paths: LifecyclePaths, gen_id: str, *, with_venv: bool = True) -> Path:
    gen = paths.generations / gen_id
    gen.parent.mkdir(parents=True, exist_ok=True)
    gen.parent.chmod(0o700)
    gen.mkdir(mode=0o700)
    if with_venv:
        venv_bin = gen / "venv/bin"
        venv_bin.mkdir(parents=True, mode=0o700)
        for name in ("termrecall", "termrecall-bridge", "termrecall-nonblock"):
            exe = venv_bin / name
            exe.write_bytes(b"#!/bin/sh\necho ok\n")
            exe.chmod(0o755)
    marker = gen / MARKER_NAME
    import json
    raw = json.dumps(
        {"schema": 2, "install_id": "install-1", "generation_id": gen_id, "path": str(gen), "nonce": "nonce-1"},
        sort_keys=True, separators=(",", ":"),
    ).encode("utf-8") + b"\n"
    marker.write_bytes(raw)
    marker.chmod(0o600)
    return gen


def _owned(paths: LifecyclePaths, gen_id: str) -> tuple[OwnedObject, ...]:
    target = str(paths.generations / gen_id)
    owned = [OwnedObject(str(paths.current), ObjectKind.SYMLINK, 0o777, None, target)]
    for link in paths.command_links:
        owned.append(OwnedObject(str(link), ObjectKind.SYMLINK, 0o777, None, str(paths.current / f"venv/bin/{link.name}")))
    return tuple(owned)


def _manifest(
    paths: LifecyclePaths,
    gen_id: str = "gen-1",
    *,
    bash_enabled: bool = True,
    autostart_enabled: bool = True,
    chooser: ChooserOwnership | None = None,
    owned_extra: tuple[OwnedObject, ...] = (),
) -> InstallManifest:
    marker_path = paths.generations / gen_id / MARKER_NAME
    raw_marker = marker_path.read_bytes()
    owned_list = list(_owned(paths, gen_id))
    # installer-owned integration resources that currently exist
    if paths.autostart.exists():
        content = paths.autostart.read_bytes()
        owned_list.append(OwnedObject(str(paths.autostart), ObjectKind.FILE, 0o600, hashlib.sha256(content).hexdigest(), None))
    if paths.chooser.exists():
        content = paths.chooser.read_bytes()
        owned_list.append(OwnedObject(str(paths.chooser), ObjectKind.FILE, 0o600, hashlib.sha256(content).hexdigest(), None))
    if paths.bash_integration.exists():
        content = paths.bash_integration.read_bytes()
        owned_list.append(OwnedObject(str(paths.bash_integration), ObjectKind.FILE, 0o600, hashlib.sha256(content).hexdigest(), None))
    if (paths.config_root / "bashrc.backup").exists():
        content = (paths.config_root / "bashrc.backup").read_bytes()
        owned_list.append(OwnedObject(str(paths.config_root / "bashrc.backup"), ObjectKind.FILE, 0o600, hashlib.sha256(content).hexdigest(), None))
    owned_list.extend(owned_extra)
    owned = tuple(owned_list)
    absent = BeforeImage(str(paths.chooser), ObjectKind.ABSENT, None, None, None, None)
    if chooser is None:
        if paths.chooser.exists():
            content = paths.chooser.read_bytes()
            img = BeforeImage(str(paths.chooser), ObjectKind.FILE, 0o600, None, content, hashlib.sha256(content).hexdigest())
            chooser = ChooserOwnership(absent, img, True)
        else:
            chooser = ChooserOwnership(absent, None, False)
    bash_backup = None
    if (paths.config_root / "bashrc.backup").exists():
        bash_backup = OwnedObject(
            str(paths.config_root / "bashrc.backup"), ObjectKind.FILE, 0o600,
            hashlib.sha256((paths.config_root / "bashrc.backup").read_bytes()).hexdigest(), None,
        )
    return InstallManifest(
        schema_version=2,
        installer_version="1.0",
        application_version="0.1.0",
        install_id="install-1",
        generation_id=gen_id,
        roots={"uid": UID, "data": str(paths.data_root), "config": str(paths.config_root), "state": str(paths.state_root), "bin": str(paths.bin_root)},
        marker=MarkerIdentity(str(marker_path), hashlib.sha256(raw_marker).hexdigest(), 0o600),
        owned=owned,
        created_parents=(),
        bash_enabled=bash_enabled,
        autostart_enabled=autostart_enabled,
        chooser=chooser,
        rollback_images=(),
        bash_backup=bash_backup,
    )


def _install_prior(paths: LifecyclePaths, gen_id: str = "gen-1", *, bash=True, autostart=True, chooser_enabled=True) -> InstallManifest:
    gen = _make_generation(paths, gen_id)
    paths.current.parent.mkdir(parents=True, exist_ok=True)
    paths.current.parent.chmod(0o700)
    os.symlink(str(gen), str(paths.current))
    paths.bin_root.mkdir(parents=True, exist_ok=True)
    for link in paths.command_links:
        os.symlink(str(paths.current / f"venv/bin/{link.name}"), str(link))
    paths.config_root.mkdir(parents=True, exist_ok=True)
    paths.config_root.chmod(0o700)
    if bash:
        _write_bash_block(paths)
    if autostart:
        _write_autostart(paths)
    _write_chooser(paths, chooser_enabled)
    manifest = _manifest(paths, gen_id, bash_enabled=bash, autostart_enabled=autostart)
    paths.manifest.parent.mkdir(parents=True, exist_ok=True)
    paths.manifest.parent.chmod(0o700)
    paths.manifest.write_bytes(manifest_to_bytes(manifest))
    paths.manifest.chmod(0o600)
    return manifest


def _semantic_snapshot(paths: LifecyclePaths) -> dict:
    snap: dict = {}
    targets = [
        paths.manifest, paths.current, *paths.command_links, paths.bashrc,
        paths.bash_integration, paths.autostart, paths.chooser, paths.state_root,
    ]
    for path in targets:
        try:
            st = path.lstat()
            if stat.S_ISLNK(st.st_mode):
                snap[str(path)] = ("symlink", stat.S_IMODE(st.st_mode), os.readlink(path))
            elif stat.S_ISREG(st.st_mode):
                snap[str(path)] = ("file", stat.S_IMODE(st.st_mode), hashlib.sha256(path.read_bytes()).hexdigest())
            elif stat.S_ISDIR(st.st_mode):
                snap[str(path)] = ("dir", stat.S_IMODE(st.st_mode))
            else:
                snap[str(path)] = ("other", stat.S_IMODE(st.st_mode))
        except FileNotFoundError:
            snap[str(path)] = None
    return snap


# ---------------------------------------------------------------------------
# FailurePoint / FailureInjector
# ---------------------------------------------------------------------------


def test_failure_point_enum_is_exact_and_ordered() -> None:
    expected = [
        "after_stage_dir", "after_venv", "after_wheel", "after_self_check",
        "after_generation_rename", "after_bash", "after_autostart", "after_chooser",
        "after_command_link", "after_current_link", "after_quarantine",
        "after_manifest", "during_rollback", "during_postcommit_cleanup",
    ]
    assert [member.value for member in FailurePoint] == expected
    assert FailurePoint.DURING_ROLLBACK.value == "during_rollback"


def test_no_failure_never_raises() -> None:
    for point in FailurePoint:
        NO_FAILURE(point)  # must not raise


def test_failure_injector_raises_only_at_configured_point() -> None:
    injector = FailureInjector(FailurePoint.AFTER_VENV)
    for point in FailurePoint:
        if point is FailurePoint.AFTER_VENV:
            with pytest.raises(Exception):
                injector(point)
        else:
            injector(point)  # no raise


def test_uninstall_action_and_plan_field_shapes() -> None:
    assert [f.name for f in fields(UninstallAction)] == ["kind", "path", "detail"]
    assert [f.name for f in fields(UninstallPlan)] == ["request", "paths", "prior", "actions", "snapshot"]


# ---------------------------------------------------------------------------
# semantic_state_fingerprint
# ---------------------------------------------------------------------------


def _source_tree(tmp_path: Path) -> Path:
    source = tmp_path / "source"
    ignored = shutil.ignore_patterns("__pycache__", ".pytest_cache", "*.pyc", "dist", "build", "*.egg-info", ".git")
    shutil.copytree(ROOT, source, ignore=ignored)
    for path in (source, *source.rglob("*")):
        path.chmod(path.stat().st_mode & ~0o022)
    return source


def _setup_request(paths: LifecyclePaths, source: Path, *, mode=SetupMode.FULL, dry_run=False) -> SetupRequest:
    return SetupRequest(
        mode=mode, dry_run=dry_run,
        bash=DesiredState.ENABLE, autostart=DesiredState.ENABLE, chooser=DesiredState.ENABLE,
        source_root=source, wheel=None, probe_request=None, probe_plan=None, probe_plan_digest=None,
    )


def test_semantic_fingerprint_excludes_lock_infrastructure(tmp_path: Path) -> None:
    paths, _ = _make_roots(tmp_path)
    source = _source_tree(tmp_path)
    request = _setup_request(paths, source)
    before = semantic_state_fingerprint(request, paths, UID)
    # creating only the planned 0700 directory and 0600 lock leaves the digest unchanged
    paths.config_root.mkdir(parents=True, exist_ok=True)
    paths.config_root.chmod(0o700)
    (paths.config_root / "lifecycle.lock").write_bytes(b"")
    (paths.config_root / "lifecycle.lock").chmod(0o600)
    after = semantic_state_fingerprint(request, paths, UID)
    assert after == before


def test_semantic_fingerprint_mutations_each_change_the_digest(tmp_path: Path) -> None:
    paths, _ = _make_roots(tmp_path)
    source = _source_tree(tmp_path)
    request = _setup_request(paths, source)
    _install_prior(paths)
    base = semantic_state_fingerprint(request, paths, UID)

    # mutate the manifest
    from dataclasses import replace as _replace
    m = manifest_from_bytes(paths.manifest.read_bytes(), paths, UID)
    m2 = _replace(m, install_id="install-2")
    paths.manifest.write_bytes(manifest_to_bytes(m2))
    assert semantic_state_fingerprint(request, paths, UID) != base
    paths.manifest.write_bytes(manifest_to_bytes(m))
    assert semantic_state_fingerprint(request, paths, UID) == base

    # mutate current link target
    gen2 = _make_generation(paths, "gen-2")
    os.unlink(paths.current)
    os.symlink(str(gen2), str(paths.current))
    assert semantic_state_fingerprint(request, paths, UID) != base
    os.unlink(paths.current)
    os.symlink(str(paths.generations / "gen-1"), str(paths.current))
    assert semantic_state_fingerprint(request, paths, UID) == base

    # mutate a command link
    link = paths.command_links[0]
    os.unlink(link)
    os.symlink("/bin/true", str(link))
    assert semantic_state_fingerprint(request, paths, UID) != base

    # mutate .bashrc
    os.unlink(link)
    os.symlink(str(paths.current / f"venv/bin/{link.name}"), str(link))
    assert semantic_state_fingerprint(request, paths, UID) == base
    paths.bashrc.write_bytes(b"alias ll='ls -l'\n\n# tampered\n")
    assert semantic_state_fingerprint(request, paths, UID) != base


# ---------------------------------------------------------------------------
# execute_integration_setup
# ---------------------------------------------------------------------------


def test_execute_integration_setup_dry_run_returns_ok_and_writes_nothing(tmp_path: Path) -> None:
    paths, _ = _make_roots(tmp_path)
    _install_prior(paths)
    before = _semantic_snapshot(paths)
    request = IntegrationSetupRequest(dry_run=True, bash=DesiredState.DISABLE, autostart=DesiredState.DISABLE, chooser=DesiredState.PRESERVE)
    assert execute_integration_setup(request, paths, UID, NO_FAILURE) is LifecycleExit.OK
    assert _semantic_snapshot(paths) == before


def test_execute_integration_setup_preserve_only_is_idempotent(tmp_path: Path) -> None:
    paths, _ = _make_roots(tmp_path)
    _install_prior(paths)
    before = _semantic_snapshot(paths)
    request = IntegrationSetupRequest(dry_run=False, bash=DesiredState.PRESERVE, autostart=DesiredState.PRESERVE, chooser=DesiredState.PRESERVE)
    assert execute_integration_setup(request, paths, UID, NO_FAILURE) is LifecycleExit.OK
    assert _semantic_snapshot(paths) == before


def test_execute_integration_setup_applies_bash_disable_and_rewrites_manifest(tmp_path: Path) -> None:
    paths, _ = _make_roots(tmp_path)
    _install_prior(paths, bash=True)
    request = IntegrationSetupRequest(dry_run=False, bash=DesiredState.DISABLE, autostart=DesiredState.PRESERVE, chooser=DesiredState.PRESERVE)
    assert execute_integration_setup(request, paths, UID, NO_FAILURE) is LifecycleExit.OK
    manifest = manifest_from_bytes(paths.manifest.read_bytes(), paths, UID)
    assert manifest.bash_enabled is False
    assert manifest.autostart_enabled is True
    # the V1 block is gone from .bashrc
    assert b"termrecall v1" not in paths.bashrc.read_bytes()


def test_execute_integration_setup_rollback_on_precommit_failure(tmp_path: Path) -> None:
    paths, _ = _make_roots(tmp_path)
    _install_prior(paths, bash=True)
    before = _semantic_snapshot(paths)
    injector = FailureInjector(FailurePoint.AFTER_BASH)
    request = IntegrationSetupRequest(dry_run=False, bash=DesiredState.DISABLE, autostart=DesiredState.PRESERVE, chooser=DesiredState.PRESERVE)
    result = execute_integration_setup(request, paths, UID, injector)
    assert result is LifecycleExit.ROLLED_BACK
    assert _semantic_snapshot(paths) == before


def test_execute_integration_setup_external_chooser_edit_refused(tmp_path: Path) -> None:
    paths, _ = _make_roots(tmp_path)
    _install_prior(paths, chooser_enabled=True)
    # externally edit the chooser after planning would be caught at planning
    paths.chooser.write_bytes(b'{"schema_version":1,"login_chooser_enabled":false}\n')
    paths.chooser.chmod(0o600)
    request = IntegrationSetupRequest(dry_run=False, bash=DesiredState.PRESERVE, autostart=DesiredState.PRESERVE, chooser=DesiredState.DISABLE)
    assert execute_integration_setup(request, paths, UID, NO_FAILURE) is LifecycleExit.REFUSED


# ---------------------------------------------------------------------------
# plan_uninstall / execute_uninstall
# ---------------------------------------------------------------------------


def test_plan_uninstall_refuses_app_removal_without_bash_and_autostart(tmp_path: Path) -> None:
    paths, _ = _make_roots(tmp_path)
    _install_prior(paths)
    for remove_bash, remove_autostart in [(False, True), (True, False), (False, False)]:
        request = UninstallRequest(remove_application=True, remove_bash=remove_bash, remove_autostart=remove_autostart, restore_chooser=False, purge_state=False, assume_yes=True)
        with pytest.raises(Exception):
            plan_uninstall(request, paths, UID)


def test_plan_uninstall_partial_bash_only_keeps_app_and_lists_actions(tmp_path: Path) -> None:
    paths, _ = _make_roots(tmp_path)
    _install_prior(paths, bash=True, autostart=True)
    request = UninstallRequest(remove_application=False, remove_bash=True, remove_autostart=False, restore_chooser=False, purge_state=False, assume_yes=True)
    plan = plan_uninstall(request, paths, UID)
    kinds = {a.kind for a in plan.actions}
    assert "remove-bash" in kinds
    assert "remove-autostart" not in kinds
    assert not any(a.kind == "remove-application" for a in plan.actions)
    assert not any(a.kind == "remove-manifest" for a in plan.actions)


def test_execute_uninstall_partial_rewrites_manifest_last(tmp_path: Path) -> None:
    paths, _ = _make_roots(tmp_path)
    _install_prior(paths, bash=True, autostart=True)
    request = UninstallRequest(remove_application=False, remove_bash=True, remove_autostart=False, restore_chooser=False, purge_state=False, assume_yes=True)
    plan = plan_uninstall(request, paths, UID)
    assert execute_uninstall(plan, UID, NO_FAILURE) is LifecycleExit.OK
    manifest = manifest_from_bytes(paths.manifest.read_bytes(), paths, UID)
    assert manifest.bash_enabled is False
    assert manifest.autostart_enabled is True
    # the app, current link, command links, and manifest all remain
    assert paths.current.exists()
    assert all(link.exists() for link in paths.command_links)
    assert paths.manifest.exists()
    assert b"termrecall v1" not in paths.bashrc.read_bytes()


def test_execute_uninstall_application_removes_app_and_keeps_chooser(tmp_path: Path) -> None:
    paths, _ = _make_roots(tmp_path)
    _install_prior(paths, bash=True, autostart=True, chooser_enabled=True)
    request = UninstallRequest(remove_application=True, remove_bash=True, remove_autostart=True, restore_chooser=False, purge_state=False, assume_yes=True)
    plan = plan_uninstall(request, paths, UID)
    assert execute_uninstall(plan, UID, NO_FAILURE) is LifecycleExit.OK
    assert not paths.current.exists()
    assert not any(link.exists() for link in paths.command_links)
    assert not paths.manifest.exists()
    assert not (paths.generations / "gen-1").exists()
    # chooser is retained (unowned now) and bash/autostart are gone
    assert paths.chooser.exists()
    assert not paths.autostart.exists()
    assert b"termrecall v1" not in paths.bashrc.read_bytes()


def test_execute_uninstall_all_remove_lifecycle(tmp_path: Path) -> None:
    paths, _ = _make_roots(tmp_path)
    _install_prior(paths, bash=True, autostart=True, chooser_enabled=True)
    request = UninstallRequest(remove_application=True, remove_bash=True, remove_autostart=True, restore_chooser=True, purge_state=False, assume_yes=True)
    plan = plan_uninstall(request, paths, UID)
    assert execute_uninstall(plan, UID, NO_FAILURE) is LifecycleExit.OK
    assert not paths.current.exists()
    assert not paths.manifest.exists()
    assert not paths.chooser.exists()


# ---------------------------------------------------------------------------
# quarantine purge lifecycle
# ---------------------------------------------------------------------------


def _seed_state_secret(paths: LifecyclePaths) -> Path:
    paths.state_root.mkdir(parents=True, exist_ok=True)
    paths.state_root.chmod(0o700)
    secret = paths.state_root / "recovery" / "secret-token"
    secret.parent.mkdir(parents=True, exist_ok=True)
    secret.parent.chmod(0o700)
    secret.write_bytes(b"super-secret-recovery-token")
    secret.chmod(0o600)
    return secret


def test_execute_uninstall_purge_state_succeeds_and_deletes_state(tmp_path: Path) -> None:
    paths, _ = _make_roots(tmp_path)
    _install_prior(paths, bash=True, autostart=True)
    _seed_state_secret(paths)
    request = UninstallRequest(remove_application=True, remove_bash=True, remove_autostart=True, restore_chooser=True, purge_state=True, assume_yes=True)
    plan = plan_uninstall(request, paths, UID)
    assert execute_uninstall(plan, UID, NO_FAILURE) is LifecycleExit.OK
    assert not paths.state_root.exists()


def test_execute_uninstall_purge_precommit_failure_rolls_back_state(tmp_path: Path) -> None:
    paths, _ = _make_roots(tmp_path)
    _install_prior(paths, bash=True, autostart=True)
    secret = _seed_state_secret(paths)
    # fail after quarantine rename but before manifest removal -> rollback state
    request = UninstallRequest(remove_application=True, remove_bash=True, remove_autostart=True, restore_chooser=True, purge_state=True, assume_yes=True)
    plan = plan_uninstall(request, paths, UID)
    injector = FailureInjector(FailurePoint.AFTER_QUARANTINE)
    result = execute_uninstall(plan, UID, injector)
    assert result is LifecycleExit.ROLLED_BACK
    # the live state root is restored (still present with its secret)
    assert paths.state_root.exists()
    assert secret.exists()
    assert secret.read_bytes() == b"super-secret-recovery-token"


def test_execute_uninstall_purge_postcommit_cleanup_failure_warns_with_manifest_committed(tmp_path: Path) -> None:
    paths, _ = _make_roots(tmp_path)
    _install_prior(paths, bash=True, autostart=True)
    _seed_state_secret(paths)
    request = UninstallRequest(remove_application=True, remove_bash=True, remove_autostart=True, restore_chooser=True, purge_state=True, assume_yes=True)
    plan = plan_uninstall(request, paths, UID)
    injector = FailureInjector(DURING_POSTCOMMIT_CLEANUP)
    result = execute_uninstall(plan, UID, injector)
    assert result is LifecycleExit.WARNING
    # the manifest is gone (commit happened) but a private quarantine is retained
    assert not paths.manifest.exists()


def test_execute_uninstall_seed_secret_absent_from_output(tmp_path: Path, capfd) -> None:
    paths, _ = _make_roots(tmp_path)
    _install_prior(paths, bash=True, autostart=True)
    _seed_state_secret(paths)
    request = UninstallRequest(remove_application=True, remove_bash=True, remove_autostart=True, restore_chooser=True, purge_state=True, assume_yes=True)
    plan = plan_uninstall(request, paths, UID)
    injector = FailureInjector(DURING_POSTCOMMIT_CLEANUP)
    execute_uninstall(plan, UID, injector)
    captured = capfd.readouterr()
    assert b"super-secret-recovery-token" not in (captured.out.encode() + captured.err.encode())


# ---------------------------------------------------------------------------
# set_autostart / set_chooser
# ---------------------------------------------------------------------------


def test_set_autostart_disable_then_enable_roundtrip(tmp_path: Path) -> None:
    paths, _ = _make_roots(tmp_path)
    _install_prior(paths, autostart=True)
    assert set_autostart(False, paths, UID) is LifecycleExit.OK
    assert not paths.autostart.exists()
    manifest = manifest_from_bytes(paths.manifest.read_bytes(), paths, UID)
    assert manifest.autostart_enabled is False
    assert set_autostart(True, paths, UID) is LifecycleExit.OK
    assert paths.autostart.exists()
    assert paths.autostart.stat().st_mode & 0o777 == 0o600


def test_set_chooser_disable_then_enable_roundtrip(tmp_path: Path) -> None:
    paths, _ = _make_roots(tmp_path)
    _install_prior(paths, chooser_enabled=True)
    assert set_chooser(False, paths, UID) is LifecycleExit.OK
    import json
    assert json.loads(paths.chooser.read_bytes())["login_chooser_enabled"] is False
    assert set_chooser(True, paths, UID) is LifecycleExit.OK
    assert json.loads(paths.chooser.read_bytes())["login_chooser_enabled"] is True


# ---------------------------------------------------------------------------
# staged_self_check
# ---------------------------------------------------------------------------


def test_staged_self_check_accepts_marked_generation(tmp_path: Path) -> None:
    paths, _ = _make_roots(tmp_path)
    gen = _make_generation(paths, "gen-stage")
    request = _setup_request(paths, _source_tree(tmp_path))
    staged_self_check(gen, request, paths, UID)  # must not raise


def test_staged_self_check_rejects_missing_marker(tmp_path: Path) -> None:
    paths, _ = _make_roots(tmp_path)
    gen = _make_generation(paths, "gen-stage")
    (gen / MARKER_NAME).unlink()
    request = _setup_request(paths, _source_tree(tmp_path))
    with pytest.raises(Exception):
        staged_self_check(gen, request, paths, UID)


# ---------------------------------------------------------------------------
# execute_setup boundary matrix
# ---------------------------------------------------------------------------


def _run_probe_plan(source: Path, paths: LifecyclePaths, *, mode="full") -> ProbePlan:
    argv = [
        sys.executable, "-I", "-B", str(source / "installer_probe.py"), "plan",
        "--source-root", str(source), "--home", str(paths.home),
        "--xdg-data-home", str(paths.xdg_data_home), "--xdg-config-home", str(paths.xdg_config_home),
        "--xdg-state-home", str(paths.xdg_state_home), "--mode", mode, "--bash", "enable",
        "--autostart", "enable", "--chooser", "enable", "--dry-run", "no",
    ]
    completed = subprocess.run(
        argv, env={"PATH": os.environ["PATH"], "PYTHONDONTWRITEBYTECODE": "1"},
        capture_output=True, check=False,
    )
    assert completed.returncode == 0, completed.stderr.decode()
    request = {
        "request_schema": 1, "source_root": str(source), "home": str(paths.home),
        "xdg_data_home": str(paths.xdg_data_home), "xdg_config_home": str(paths.xdg_config_home),
        "xdg_state_home": str(paths.xdg_state_home), "mode": mode, "bash": "enable",
        "autostart": "enable", "chooser": "enable", "dry_run": False,
    }
    return probe_plan_from_bytes(completed.stdout, request)


def _request_from(source: Path, paths: LifecyclePaths) -> SetupRequest:
    return SetupRequest(
        mode=SetupMode.FULL, dry_run=False,
        bash=DesiredState.ENABLE, autostart=DesiredState.ENABLE, chooser=DesiredState.ENABLE,
        source_root=source, wheel=None, probe_request=None, probe_plan=None, probe_plan_digest=None,
    )


@pytest.fixture
def transaction_case(tmp_path: Path):
    paths, _ = _make_roots(tmp_path)
    source = _source_tree(tmp_path)
    # fresh install: no prior install
    plan = _run_probe_plan(source, paths)
    request = _request_from(source, paths)

    class _Case:
        @staticmethod
        def snapshot():
            return _semantic_snapshot(paths)

        @staticmethod
        def fail_upgrade(point: FailurePoint) -> LifecycleExit:
            # AFTER_QUARANTINE is an uninstall-with-purge boundary: it needs a
            # prior install and seeded state to exercise the quarantine rename.
            if point is FailurePoint.AFTER_QUARANTINE:
                p2, _ = _make_roots(tmp_path / "qcase")
                prior = _install_prior(p2, bash=True, autostart=True, chooser_enabled=True)
                _seed_state_secret(p2)
                urequest = UninstallRequest(
                    remove_application=True, remove_bash=True, remove_autostart=True,
                    restore_chooser=True, purge_state=True, assume_yes=True,
                )
                uplan = plan_uninstall(urequest, p2, UID)
                return execute_uninstall(uplan, UID, FailureInjector(point))
            # DURING_ROLLBACK needs a precommit failure to enter rollback, then
            # the rollback itself must fail.
            if point is FailurePoint.DURING_ROLLBACK:
                injector = FailureInjector.at({FailurePoint.AFTER_STAGE_DIR, FailurePoint.DURING_ROLLBACK})
                return execute_setup(plan, request, paths, UID, injector)
            return execute_setup(plan, request, paths, UID, FailureInjector(point))

        @staticmethod
        def new_manifest_committed() -> bool:
            return paths.manifest.exists()

    return _Case


@pytest.mark.parametrize("point", list(FailurePoint))
def test_every_boundary_has_defined_status_and_state(transaction_case, point: FailurePoint) -> None:
    before = transaction_case.snapshot()
    result = transaction_case.fail_upgrade(point)
    if point is DURING_ROLLBACK:
        assert result is LifecycleExit.ROLLBACK_INCOMPLETE
    elif point is DURING_POSTCOMMIT_CLEANUP:
        assert result is LifecycleExit.WARNING
        assert transaction_case.new_manifest_committed()
    else:
        assert result is LifecycleExit.ROLLED_BACK
        assert transaction_case.snapshot() == before


def test_execute_setup_fresh_install_succeeds_without_failure(tmp_path: Path) -> None:
    paths, _ = _make_roots(tmp_path)
    source = _source_tree(tmp_path)
    plan = _run_probe_plan(source, paths)
    request = _request_from(source, paths)
    assert execute_setup(plan, request, paths, UID, NO_FAILURE) is LifecycleExit.OK
    assert paths.current.exists()
    assert all(link.exists() for link in paths.command_links)
    assert paths.manifest.exists()
    manifest = manifest_from_bytes(paths.manifest.read_bytes(), paths, UID)
    assert manifest.bash_enabled is True
    assert manifest.autostart_enabled is True


def test_execute_setup_refuses_when_semantic_state_drifts(tmp_path: Path) -> None:
    paths, _ = _make_roots(tmp_path)
    source = _source_tree(tmp_path)
    plan = _run_probe_plan(source, paths)
    request = _request_from(source, paths)
    # mutate .bashrc between planning and pre-lock revalidation
    paths.bashrc.parent.mkdir(parents=True, exist_ok=True)
    paths.bashrc.write_bytes(b"# drift\n")
    paths.bashrc.chmod(0o644)
    assert execute_setup(plan, request, paths, UID, NO_FAILURE) is LifecycleExit.REFUSED
    # no destination mutation occurred
    assert not paths.current.exists()
    assert not paths.manifest.exists()


def test_execute_setup_refuses_unsafe_preexisting_lock(tmp_path: Path) -> None:
    paths, _ = _make_roots(tmp_path)
    source = _source_tree(tmp_path)
    plan = _run_probe_plan(source, paths)
    request = _request_from(source, paths)
    # plant a symlink where the lock should be created
    paths.config_root.parent.mkdir(parents=True, exist_ok=True)
    paths.config_root.mkdir(mode=0o700)
    os.symlink("/etc/hostname", str(paths.lifecycle_lock))
    assert execute_setup(plan, request, paths, UID, NO_FAILURE) is LifecycleExit.REFUSED
    assert not paths.current.exists()
