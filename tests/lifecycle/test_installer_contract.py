from __future__ import annotations

import itertools
import json
from dataclasses import fields
from pathlib import Path

import pytest

from termrecall.installer_contract import (
    DesiredState,
    IntegrationSetupRequest,
    BeforeImage,
    ChooserOwnership,
    InstallManifest,
    LifecycleExit,
    LockInfrastructurePlan,
    MarkerIdentity,
    ObjectKind,
    OwnedObject,
    ProbeAction,
    ProbePlan,
    manifest_from_bytes,
    manifest_to_bytes,
    SetupMode,
    validate_integration_setup_request,
    validate_setup_request,
)
from termrecall.paths import resolve_lifecycle_paths, resolve_paths


ALL_COMBINATIONS = list(
    itertools.product(SetupMode, DesiredState, DesiredState, DesiredState)
)


def expected_valid(
    mode: SetupMode,
    bash: DesiredState,
    autostart: DesiredState,
    chooser: DesiredState,
) -> bool:
    states = (bash, autostart, chooser)
    return (
        mode in {SetupMode.INTERACTIVE, SetupMode.FULL}
        or (mode is SetupMode.NO_AUTOSTART and autostart is not DesiredState.ENABLE)
        or (
            mode in {SetupMode.COMMANDS_ONLY, SetupMode.UPGRADE}
            and states == (DesiredState.PRESERVE,) * 3
        )
    )


@pytest.mark.parametrize(("mode", "bash", "autostart", "chooser"), ALL_COMBINATIONS)
def test_exact_mode_state_validation(
    setup_request,
    replace_request,
    mode: SetupMode,
    bash: DesiredState,
    autostart: DesiredState,
    chooser: DesiredState,
) -> None:
    request = replace_request(
        setup_request,
        mode=mode,
        bash=bash,
        autostart=autostart,
        chooser=chooser,
    )
    if expected_valid(mode, bash, autostart, chooser):
        assert validate_setup_request(request) is request
    else:
        with pytest.raises(ValueError):
            validate_setup_request(request)


def test_setup_request_requires_exact_enum_and_bool_types(setup_request, replace_request) -> None:
    with pytest.raises(TypeError):
        validate_setup_request(replace_request(setup_request, mode="full"))
    with pytest.raises(TypeError):
        validate_setup_request(replace_request(setup_request, dry_run=1))


def test_integration_request_is_strict() -> None:
    request = IntegrationSetupRequest(
        dry_run=False,
        bash=DesiredState.PRESERVE,
        autostart=DesiredState.DISABLE,
        chooser=DesiredState.ENABLE,
    )
    assert validate_integration_setup_request(request) is request
    with pytest.raises(TypeError):
        validate_integration_setup_request(
            IntegrationSetupRequest(  # type: ignore[arg-type]
                dry_run=False,
                bash="preserve",
                autostart=DesiredState.DISABLE,
                chooser=DesiredState.ENABLE,
            )
        )


def test_exact_exit_codes_and_probe_model_fields() -> None:
    assert [member.value for member in LifecycleExit] == list(range(8))
    assert [field.name for field in fields(ProbeAction)] == [
        "sequence",
        "kind",
        "disposition",
        "path_or_token",
        "mode",
        "literal_target",
        "content_sha256",
        "prerequisite",
        "rollback",
    ]
    assert [field.name for field in fields(LockInfrastructurePlan)] == [
        "directory_path",
        "lock_path",
        "directory_absent",
        "lock_absent",
        "may_create_directory",
        "may_create_lock",
        "directory_mode",
        "lock_mode",
    ]
    assert [field.name for field in fields(ProbePlan)] == [
        "probe_schema",
        "plan_schema",
        "request",
        "prerequisites",
        "source",
        "prior",
        "effective",
        "actions",
        "lock_infrastructure",
        "state_fingerprint",
        "rendered",
        "plan_digest",
    ]


def test_lifecycle_paths_honor_independent_xdg_defaults(tmp_path: Path) -> None:
    home = tmp_path / "home"
    paths = resolve_lifecycle_paths({}, home)
    assert paths.data_root == home / ".local/share/termrecall"
    assert paths.config_root == home / ".config/termrecall"
    assert paths.state_root == home / ".local/state/termrecall"
    assert paths.bin_root == home / ".local/bin"
    assert paths.manifest == paths.config_root / "install-manifest.json"
    assert paths.lifecycle_lock == paths.config_root / "lifecycle.lock"
    assert paths.autostart == home / ".config/autostart/termrecall.desktop"
    assert paths.bashrc == home / ".bashrc"
    assert paths.command_links == (
        home / ".local/bin/termrecall",
        home / ".local/bin/termrecall-bridge",
        home / ".local/bin/termrecall-nonblock",
    )

    overridden = resolve_lifecycle_paths(
        {
            "XDG_DATA_HOME": str(tmp_path / "data root"),
            "XDG_CONFIG_HOME": str(tmp_path / "config root"),
            "XDG_STATE_HOME": str(tmp_path / "state root"),
        },
        home,
    )
    assert overridden.data_root == tmp_path / "data root/termrecall"
    assert overridden.config_root == tmp_path / "config root/termrecall"
    assert overridden.state_root == tmp_path / "state root/termrecall"
    assert overridden.autostart == tmp_path / "config root/autostart/termrecall.desktop"


def make_manifest(tmp_path: Path, uid: int = 1000) -> tuple[InstallManifest, object]:
    paths = resolve_lifecycle_paths({}, tmp_path / "home")
    marker_path = paths.generations / "generation-1/.termrecall-generation.json"
    current_target = str(paths.generations / "generation-1")
    owned = (
        OwnedObject(str(paths.current), ObjectKind.SYMLINK, 0o777, None, current_target),
        *(
            OwnedObject(
                str(link), ObjectKind.SYMLINK, 0o777, None,
                str(paths.current / f"venv/bin/{link.name}"),
            )
            for link in paths.command_links
        ),
    )
    absent = BeforeImage(str(paths.chooser), ObjectKind.ABSENT, None, None, None, None)
    manifest = InstallManifest(
        schema_version=2,
        installer_version="1.0",
        application_version="0.1.0",
        install_id="install-1",
        generation_id="generation-1",
        roots={
            "uid": uid,
            "data": str(paths.data_root),
            "config": str(paths.config_root),
            "state": str(paths.state_root),
            "bin": str(paths.bin_root),
        },
        marker=MarkerIdentity(str(marker_path), "a" * 64, 0o600),
        owned=owned,
        created_parents=(),
        bash_enabled=False,
        autostart_enabled=False,
        chooser=ChooserOwnership(absent, None, False),
        rollback_images=(),
        bash_backup=None,
    )
    return manifest, paths


def test_manifest_round_trip_validates_embedded_uid_and_link_invariants(tmp_path: Path) -> None:
    manifest, paths = make_manifest(tmp_path)
    raw = manifest_to_bytes(manifest)
    assert manifest_from_bytes(raw, paths, uid=1000) == manifest
    with pytest.raises(ValueError, match="uid"):
        manifest_from_bytes(raw, paths, uid=1001)


def test_manifest_rejects_json_type_coercion_bool_modes_and_bad_base64(tmp_path: Path) -> None:
    manifest, paths = make_manifest(tmp_path)
    payload = json.loads(manifest_to_bytes(manifest))
    payload["installer_version"] = 1
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    with pytest.raises(ValueError, match="installer_version"):
        manifest_from_bytes(raw, paths, uid=1000)

    payload = json.loads(manifest_to_bytes(manifest))
    payload["marker"]["mode"] = True
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    with pytest.raises(ValueError, match="mode"):
        manifest_from_bytes(raw, paths, uid=1000)

    payload = json.loads(manifest_to_bytes(manifest))
    payload["chooser"]["original"]["content"] = "not base64!"
    payload["chooser"]["original"]["kind"] = "file"
    payload["chooser"]["original"]["mode"] = 384
    payload["chooser"]["original"]["content_sha256"] = "a" * 64
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    with pytest.raises(ValueError, match="base64|content"):
        manifest_from_bytes(raw, paths, uid=1000)


def test_manifest_rejects_wrong_marker_current_commands_and_oversized_collections(tmp_path: Path) -> None:
    manifest, paths = make_manifest(tmp_path)
    for mutation, message in (
        (("marker", "path", str(paths.config_root / "marker")), "marker"),
        (("owned", 0, "literal_target", str(paths.data_root / "wrong")), "current"),
        (("owned", 1, "literal_target", "/wrong/command"), "command"),
    ):
        payload = json.loads(manifest_to_bytes(manifest))
        if mutation[0] == "marker":
            payload[mutation[0]][mutation[1]] = mutation[2]
        else:
            payload[mutation[0]][mutation[1]][mutation[2]] = mutation[3]
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        with pytest.raises(ValueError, match=message):
            manifest_from_bytes(raw, paths, uid=1000)

    payload = json.loads(manifest_to_bytes(manifest))
    payload["owned"] = payload["owned"] * 33
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    with pytest.raises(ValueError, match="owned"):
        manifest_from_bytes(raw, paths, uid=1000)


def test_service_path_resolution_remains_unchanged(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="XDG_RUNTIME_DIR"):
        resolve_paths({}, uid=1000, home=tmp_path)
