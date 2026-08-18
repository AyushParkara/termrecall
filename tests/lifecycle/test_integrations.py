# SPDX-License-Identifier: GPL-3.0-or-later
"""Task 3: pure Bash/autostart/chooser capture and transform logic.

These tests pin the exact byte-level behaviour of the independent integration
planner before any orchestrator (Task 4) consumes it.  They cover shell quoting,
the canonical V1 ``.bashrc`` block, legacy block migration, malformed marker
refusal, byte/mode preservation, the durable private Bash backup, chooser
ownership rules, independent autostart/chooser plans, and the installed
integration-only planner.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import replace
from pathlib import Path

import pytest

from termrecall.installer_contract import (
    BeforeImage,
    ChooserOwnership,
    DesiredState,
    InstallManifest,
    IntegrationSetupRequest,
    LifecyclePaths,
    MarkerIdentity,
    ObjectKind,
    OwnedObject,
    SetupMode,
    SetupRequest,
    resolve_lifecycle_paths,
)
from termrecall.lifecycle_integrations import (
    IntegrationPlan,
    PlannedMutation,
    plan_installed_integrations,
    plan_integrations,
    render_chooser,
    render_desktop,
    shell_single_quote,
    transform_bashrc,
)

UID = os.getuid()

# Canonical marker lineshares the same byte sequence in every emitted block.
V1_BEGIN = b"# >>> termrecall v1 >>>"
V1_END = b"# <<< termrecall v1 <<<"
LEGACY_BEGIN = b"# BEGIN termrecall"
LEGACY_END = b"# END termrecall"


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _quote(path: Path) -> bytes:
    return shell_single_quote(path)


def _source_line(integration: Path) -> bytes:
    quoted = _quote(integration)
    return b"[ -f " + quoted + b" ] && . " + quoted


def v1_block(integration: Path) -> bytes:
    return V1_BEGIN + b"\n" + _source_line(integration) + b"\n" + V1_END + b"\n"


def legacy_block(integration: Path) -> bytes:
    return LEGACY_BEGIN + b"\n" + b"source " + _quote(integration) + b"\n" + LEGACY_END + b"\n"


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _make_paths(tmp_path: Path) -> tuple[LifecyclePaths, Path]:
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    paths = resolve_lifecycle_paths({}, home)
    return paths, home


def _make_setup_request(
    paths: LifecyclePaths,
    *,
    bash: DesiredState = DesiredState.ENABLE,
    autostart: DesiredState = DesiredState.ENABLE,
    chooser: DesiredState = DesiredState.ENABLE,
    mode: SetupMode = SetupMode.FULL,
    dry_run: bool = False,
    source_root: Path | None = None,
) -> SetupRequest:
    return SetupRequest(
        mode=mode,
        dry_run=dry_run,
        bash=bash,
        autostart=autostart,
        chooser=chooser,
        source_root=source_root or paths.home / "source",
        wheel=None,
        probe_request=None,
        probe_plan=None,
        probe_plan_digest=None,
    )


def _make_integration_request(
    *,
    bash: DesiredState = DesiredState.PRESERVE,
    autostart: DesiredState = DesiredState.PRESERVE,
    chooser: DesiredState = DesiredState.PRESERVE,
    dry_run: bool = False,
) -> IntegrationSetupRequest:
    return IntegrationSetupRequest(
        dry_run=dry_run,
        bash=bash,
        autostart=autostart,
        chooser=chooser,
    )


def _write_chooser(paths: LifecyclePaths, enabled: bool) -> None:
    paths.config_root.mkdir(parents=True, exist_ok=True)
    raw = render_chooser(enabled)
    paths.chooser.write_bytes(raw)
    paths.chooser.chmod(0o600)


def _manifest(
    paths: LifecyclePaths,
    *,
    bash_enabled: bool = False,
    autostart_enabled: bool = False,
    chooser: ChooserOwnership | None = None,
    bash_backup: OwnedObject | None = None,
    generation_id: str = "generation-1",
    owned_extra: tuple[OwnedObject, ...] = (),
) -> InstallManifest:
    marker_path = paths.generations / generation_id / ".termrecall-generation.json"
    current_target = str(paths.generations / generation_id)
    owned: list[OwnedObject] = [
        OwnedObject(str(paths.current), ObjectKind.SYMLINK, 0o777, None, current_target),
        *(
            OwnedObject(
                str(link), ObjectKind.SYMLINK, 0o777, None,
                str(paths.current / f"venv/bin/{link.name}"),
            )
            for link in paths.command_links
        ),
    ]
    owned.extend(owned_extra)
    absent = BeforeImage(str(paths.chooser), ObjectKind.ABSENT, None, None, None, None)
    return InstallManifest(
        schema_version=2,
        installer_version="1.0",
        application_version="0.1.0",
        install_id="install-1",
        generation_id=generation_id,
        roots={
            "uid": UID,
            "data": str(paths.data_root),
            "config": str(paths.config_root),
            "state": str(paths.state_root),
            "bin": str(paths.bin_root),
        },
        marker=MarkerIdentity(str(marker_path), "a" * 64, 0o600),
        owned=tuple(owned),
        created_parents=(),
        bash_enabled=bash_enabled,
        autostart_enabled=autostart_enabled,
        chooser=chooser or ChooserOwnership(absent, None, False),
        rollback_images=(),
        bash_backup=bash_backup,
    )


# ---------------------------------------------------------------------------
# shell_single_quote
# ---------------------------------------------------------------------------


def test_shell_single_quote_plain_absolute_path() -> None:
    path = Path("/srv/termrecall/bash-integration.bash")
    assert shell_single_quote(path) == b"'/srv/termrecall/bash-integration.bash'"


def test_shell_single_quote_spaces() -> None:
    path = Path("/opt/my tools/hook.bash")
    assert shell_single_quote(path) == b"'/opt/my tools/hook.bash'"


def test_shell_single_quote_single_quote_maps_to_prime_quote_escape() -> None:
    # each ' becomes the five bytes '"'"' and the whole token is single-quoted
    path = Path("/tmp/it's/x")
    esc = b"'\"'\"'"  # the five ASCII bytes ' " ' " '
    expected = b"'" + b"/tmp/it" + esc + b"s/x'"
    assert shell_single_quote(path) == expected
    # round-trip through bash to prove the token is equivalent to the raw path
    import subprocess
    result = subprocess.run(
        ["bash", "-c", "set -- " + shell_single_quote(path).decode() + "; printf %s \"$1\""],
        capture_output=True,
    )
    assert result.returncode == 0
    assert result.stdout == os.fsencode(path)


def test_shell_single_quote_multiple_single_quotes() -> None:
    path = Path("/a'b'c")
    esc = b"'\"'\"'"
    expected = b"'" + b"/a" + esc + b"b" + esc + b"c'"
    assert shell_single_quote(path) == expected


# ---------------------------------------------------------------------------
# render_desktop / render_chooser
# ---------------------------------------------------------------------------


def test_render_desktop_has_one_absolute_exec_login_coordinator() -> None:
    executable = Path("/home/user/.local/share/termrecall/current/venv/bin/termrecall")
    raw = render_desktop(executable)
    assert raw.count(b"Exec=") == 1
    assert raw == (
        b"[Desktop Entry]\n"
        b"Type=Application\n"
        b"Name=TermRecall\n"
        b"Exec=" + os.fsencode(executable) + b" login-coordinator\n"
        b"OnlyShowIn=X-Cinnamon;Cinnamon;\n"
        b"X-GNOME-Autostart-enabled=true\n"
        b"Terminal=false\n"
        b"NoDisplay=true\n"
    )
    # forbidden-pattern guard: never a bare command or env launch
    assert b"Exec=termrecall" + b" " not in raw
    assert b"Exec=env" + b" " not in raw


def test_render_chooser_enabled_and_disabled_bytes() -> None:
    assert render_chooser(True) == b'{"schema_version":1,"login_chooser_enabled":true}\n'
    assert render_chooser(False) == b'{"schema_version":1,"login_chooser_enabled":false}\n'


# ---------------------------------------------------------------------------
# transform_bashrc
# ---------------------------------------------------------------------------


def test_transform_bashrc_enable_on_empty_creates_v1_block() -> None:
    integration = Path("/srv/tr/bash-integration.bash")
    assert transform_bashrc(b"", integration, DesiredState.ENABLE) == v1_block(integration)


def test_transform_bashrc_enable_idempotent_when_v1_present() -> None:
    integration = Path("/srv/tr/bash-integration.bash")
    block = v1_block(integration)
    raw = b"alias ll='ls -l'\n" + block
    assert transform_bashrc(raw, integration, DesiredState.ENABLE) == raw


def test_transform_bashrc_enable_preserves_unrelated_bytes() -> None:
    integration = Path("/srv/tr/bash-integration.bash")
    prefix = b"# my header\nalias ll='ls -l'\nexport FOO=bar\n"
    raw = prefix + v1_block(integration)
    assert transform_bashrc(raw, integration, DesiredState.ENABLE) == raw


def test_transform_bashrc_enable_appends_separator_and_block() -> None:
    integration = Path("/srv/tr/bash-integration.bash")
    prefix = b"alias ll='ls -l'"
    assert transform_bashrc(prefix, integration, DesiredState.ENABLE) == prefix + b"\n" + v1_block(integration)


def test_transform_bashrc_enable_adds_owned_separator_even_after_newline_prefix() -> None:
    integration = Path("/srv/tr/bash-integration.bash")
    prefix = b"alias ll='ls -l'\n"
    # exactly one owned separator newline is added before the block regardless
    # of whether the prefix already ends in a newline
    assert transform_bashrc(prefix, integration, DesiredState.ENABLE) == prefix + b"\n" + v1_block(integration)


def test_transform_bashrc_migrates_exact_legacy_block() -> None:
    integration = Path("/srv/tr/bash-integration.bash")
    legacy = legacy_block(integration)
    raw = b"alias ll='ls -l'\n" + legacy
    out = transform_bashrc(raw, integration, DesiredState.ENABLE)
    assert legacy not in out
    assert v1_block(integration) in out
    # unrelated bytes preserved, legacy bytes replaced by v1 bytes
    assert out == b"alias ll='ls -l'\n" + v1_block(integration)


def test_transform_bashrc_disable_removes_block_and_one_separator_newline() -> None:
    integration = Path("/srv/tr/bash-integration.bash")
    prefix = b"alias ll='ls -l'"
    raw = prefix + b"\n" + v1_block(integration)
    assert transform_bashrc(raw, integration, DesiredState.DISABLE) == prefix


def test_transform_bashrc_disable_removes_block_when_prefix_ends_in_newline() -> None:
    integration = Path("/srv/tr/bash-integration.bash")
    prefix = b"alias ll='ls -l'\n"
    raw = prefix + b"\n" + v1_block(integration)
    assert transform_bashrc(raw, integration, DesiredState.DISABLE) == prefix


def test_transform_bashrc_disable_at_start_leaves_empty() -> None:
    integration = Path("/srv/tr/bash-integration.bash")
    raw = v1_block(integration)
    assert transform_bashrc(raw, integration, DesiredState.DISABLE) == b""


def test_transform_bashrc_disable_idempotent_when_absent() -> None:
    integration = Path("/srv/tr/bash-integration.bash")
    raw = b"alias ll='ls -l'\n"
    assert transform_bashrc(raw, integration, DesiredState.DISABLE) == raw


def test_transform_bashrc_preserve_is_byte_identity() -> None:
    integration = Path("/srv/tr/bash-integration.bash")
    raw = b"anything\n" + v1_block(integration) + b"trailing\n"
    assert transform_bashrc(raw, integration, DesiredState.PRESERVE) == raw
    assert transform_bashrc(b"", integration, DesiredState.PRESERVE) == b""


def test_transform_bashrc_refuses_duplicate_v1_block() -> None:
    integration = Path("/srv/tr/bash-integration.bash")
    block = v1_block(integration)
    raw = block + block
    with pytest.raises(ValueError):
        transform_bashrc(raw, integration, DesiredState.ENABLE)
    with pytest.raises(ValueError):
        transform_bashrc(raw, integration, DesiredState.DISABLE)


def test_transform_bashrc_refuses_stray_begin_marker() -> None:
    integration = Path("/srv/tr/bash-integration.bash")
    raw = V1_BEGIN + b"\n" + b"alias ll='ls -l'\n"  # begin without end
    with pytest.raises(ValueError):
        transform_bashrc(raw, integration, DesiredState.ENABLE)


def test_transform_bashrc_refuses_stray_end_marker() -> None:
    integration = Path("/srv/tr/bash-integration.bash")
    raw = b"alias ll='ls -l'\n" + V1_END + b"\n"
    with pytest.raises(ValueError):
        transform_bashrc(raw, integration, DesiredState.ENABLE)


def test_transform_bashrc_refuses_handwritten_v1_middle() -> None:
    integration = Path("/srv/tr/bash-integration.bash")
    # well-formed markers but the middle is not the canonical source line
    raw = V1_BEGIN + b"\necho tampered\n" + V1_END + b"\n"
    with pytest.raises(ValueError):
        transform_bashrc(raw, integration, DesiredState.ENABLE)


def test_transform_bashrc_refuses_nested_v1_markers() -> None:
    integration = Path("/srv/tr/bash-integration.bash")
    block = v1_block(integration)
    # two begin markers before any end -> nested/duplicate
    raw = V1_BEGIN + b"\n" + block
    with pytest.raises(ValueError):
        transform_bashrc(raw, integration, DesiredState.ENABLE)


def test_transform_bashrc_refuses_legacy_without_end() -> None:
    integration = Path("/srv/tr/bash-integration.bash")
    raw = LEGACY_BEGIN + b"\nsource " + _quote(integration) + b"\n"
    with pytest.raises(ValueError):
        transform_bashrc(raw, integration, DesiredState.ENABLE)


def test_transform_bashrc_refuses_v1_and_legacy_coexisting() -> None:
    integration = Path("/srv/tr/bash-integration.bash")
    raw = v1_block(integration) + legacy_block(integration)
    with pytest.raises(ValueError):
        transform_bashrc(raw, integration, DesiredState.ENABLE)


# ---------------------------------------------------------------------------
# plan_integrations
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("mode", "bash", "autostart", "chooser"),
    [
        (SetupMode.FULL, DesiredState.ENABLE, DesiredState.ENABLE, DesiredState.ENABLE),
        (SetupMode.FULL, DesiredState.DISABLE, DesiredState.DISABLE, DesiredState.DISABLE),
        (SetupMode.FULL, DesiredState.PRESERVE, DesiredState.PRESERVE, DesiredState.PRESERVE),
        (SetupMode.NO_AUTOSTART, DesiredState.ENABLE, DesiredState.DISABLE, DesiredState.PRESERVE),
        (SetupMode.COMMANDS_ONLY, DesiredState.PRESERVE, DesiredState.PRESERVE, DesiredState.PRESERVE),
        (SetupMode.UPGRADE, DesiredState.PRESERVE, DesiredState.PRESERVE, DesiredState.PRESERVE),
    ],
)
def test_plan_integrations_accepts_all_valid_mode_state_combinations(
    tmp_path: Path,
    mode: SetupMode,
    bash: DesiredState,
    autostart: DesiredState,
    chooser: DesiredState,
) -> None:
    paths, _ = _make_paths(tmp_path)
    request = _make_setup_request(paths, bash=bash, autostart=autostart, chooser=chooser, mode=mode)
    plan = plan_integrations(request, paths, prior=None, uid=UID)
    assert isinstance(plan, IntegrationPlan)


def test_plan_integrations_bash_enable_writes_bashrc_mutation_and_backup(tmp_path: Path) -> None:
    paths, _ = _make_paths(tmp_path)
    paths.bashrc.parent.mkdir(parents=True, exist_ok=True)
    paths.bashrc.write_bytes(b"alias ll='ls -l'\n")
    paths.bashrc.chmod(0o644)
    request = _make_setup_request(paths, bash=DesiredState.ENABLE, autostart=DesiredState.PRESERVE, chooser=DesiredState.PRESERVE)
    plan = plan_integrations(request, paths, prior=None, uid=UID)
    assert len(plan.bash) == 1
    mutation = plan.bash[0]
    assert mutation.path == paths.bashrc
    assert mutation.before.kind is ObjectKind.FILE
    assert mutation.before.content == b"alias ll='ls -l'\n"
    assert mutation.before.mode == 0o644
    expected_after = v1_block(paths.bash_integration)
    assert mutation.after.kind is ObjectKind.FILE
    assert mutation.after.content == b"alias ll='ls -l'\n" + b"\n" + expected_after
    assert mutation.after.mode == 0o644  # mode preserved
    # durable private backup is planned before first edit
    assert plan.bash_backup is not None
    assert plan.bash_backup.kind is ObjectKind.FILE
    assert plan.bash_backup.mode == 0o600
    assert plan.bash_backup.content_sha256 == _sha(b"alias ll='ls -l'\n")
    assert plan.bash_backup.literal_target is None


def test_plan_integrations_bash_backup_reused_across_later_edits(tmp_path: Path) -> None:
    paths, _ = _make_paths(tmp_path)
    paths.bashrc.parent.mkdir(parents=True, exist_ok=True)
    original = b"alias ll='ls -l'\n"
    # the stored form mirrors what ENABLE produces: prefix + one owned
    # separator newline + the canonical V1 block
    paths.bashrc.write_bytes(original + b"\n" + v1_block(paths.bash_integration))
    paths.bashrc.chmod(0o644)
    backup = OwnedObject(
        str(paths.config_root / "bashrc.backup"),
        ObjectKind.FILE, 0o600, _sha(original), None,
    )
    prior = _manifest(paths, bash_enabled=True, bash_backup=backup)
    request = _make_setup_request(paths, bash=DesiredState.DISABLE, autostart=DesiredState.PRESERVE, chooser=DesiredState.PRESERVE)
    plan = plan_integrations(request, paths, prior=prior, uid=UID)
    # the backup identity is retained unchanged (reused, not recreated)
    assert plan.bash_backup == backup
    assert plan.bash[0].after.kind is ObjectKind.FILE
    assert plan.bash[0].after.content == original


def test_plan_integrations_bash_disable_leaves_empty_bashrc_file(tmp_path: Path) -> None:
    paths, _ = _make_paths(tmp_path)
    # prior manifest says bash enabled and the .bashrc block is the only content
    paths.bashrc.parent.mkdir(parents=True, exist_ok=True)
    paths.bashrc.write_bytes(v1_block(paths.bash_integration))
    paths.bashrc.chmod(0o600)
    prior = _manifest(paths, bash_enabled=True)
    request = _make_setup_request(paths, bash=DesiredState.DISABLE, autostart=DesiredState.PRESERVE, chooser=DesiredState.PRESERVE)
    plan = plan_integrations(request, paths, prior=prior, uid=UID)
    # the user-owned .bashrc is never deleted; its target content is empty bytes
    assert plan.bash[0].after.kind is ObjectKind.FILE
    assert plan.bash[0].after.content == b""


def test_plan_integrations_bash_preserve_has_no_bash_mutation(tmp_path: Path) -> None:
    paths, _ = _make_paths(tmp_path)
    request = _make_setup_request(paths, bash=DesiredState.PRESERVE, autostart=DesiredState.PRESERVE, chooser=DesiredState.PRESERVE)
    plan = plan_integrations(request, paths, prior=None, uid=UID)
    assert plan.bash == ()
    assert plan.bash_backup is None


def test_plan_integrations_autostart_enable_creates_desktop_mutation(tmp_path: Path) -> None:
    paths, _ = _make_paths(tmp_path)
    request = _make_setup_request(paths, bash=DesiredState.PRESERVE, autostart=DesiredState.ENABLE, chooser=DesiredState.PRESERVE)
    plan = plan_integrations(request, paths, prior=None, uid=UID)
    assert len(plan.autostart) == 1
    mutation = plan.autostart[0]
    assert mutation.path == paths.autostart
    assert mutation.before.kind is ObjectKind.ABSENT
    expected = render_desktop(paths.current / "venv/bin/termrecall")
    assert mutation.after.kind is ObjectKind.FILE
    assert mutation.after.content == expected
    assert mutation.after.mode == 0o600


def test_plan_integrations_autostart_enable_refuses_unowned_preexisting_entry(tmp_path: Path) -> None:
    paths, _ = _make_paths(tmp_path)
    paths.autostart.parent.mkdir(parents=True, exist_ok=True)
    paths.autostart.write_bytes(b"[Desktop Entry]\nType=Application\nName=Other\nExec=/bin/true\n")
    paths.autostart.chmod(0o600)
    request = _make_setup_request(paths, bash=DesiredState.PRESERVE, autostart=DesiredState.ENABLE, chooser=DesiredState.PRESERVE)
    with pytest.raises(ValueError):
        plan_integrations(request, paths, prior=None, uid=UID)


def test_plan_integrations_autostart_enable_idempotent_when_manifest_owned_matches(tmp_path: Path) -> None:
    paths, _ = _make_paths(tmp_path)
    paths.autostart.parent.mkdir(parents=True, exist_ok=True)
    expected = render_desktop(paths.current / "venv/bin/termrecall")
    paths.autostart.write_bytes(expected)
    paths.autostart.chmod(0o600)
    owned = OwnedObject(str(paths.autostart), ObjectKind.FILE, 0o600, _sha(expected), None)
    prior = _manifest(paths, autostart_enabled=True, owned_extra=(owned,))
    request = _make_setup_request(paths, bash=DesiredState.PRESERVE, autostart=DesiredState.ENABLE, chooser=DesiredState.PRESERVE)
    plan = plan_integrations(request, paths, prior=prior, uid=UID)
    assert plan.autostart[0].before == plan.autostart[0].after  # idempotent


def test_plan_integrations_autostart_disable_requires_exact_manifest_hash_mode(tmp_path: Path) -> None:
    paths, _ = _make_paths(tmp_path)
    paths.autostart.parent.mkdir(parents=True, exist_ok=True)
    expected = render_desktop(paths.current / "venv/bin/termrecall")
    paths.autostart.write_bytes(expected)
    paths.autostart.chmod(0o600)
    owned = OwnedObject(str(paths.autostart), ObjectKind.FILE, 0o600, _sha(expected), None)
    prior = _manifest(paths, autostart_enabled=True, owned_extra=(owned,))
    request = _make_setup_request(paths, bash=DesiredState.PRESERVE, autostart=DesiredState.DISABLE, chooser=DesiredState.PRESERVE)
    plan = plan_integrations(request, paths, prior=prior, uid=UID)
    assert plan.autostart[0].after.kind is ObjectKind.ABSENT

    # tamper with the content -> disable must refuse
    paths.autostart.write_bytes(expected + b"# tampered\n")
    with pytest.raises(ValueError):
        plan_integrations(request, paths, prior=prior, uid=UID)


def test_plan_integrations_autostart_disable_absent_is_idempotent_no_mutation(tmp_path: Path) -> None:
    paths, _ = _make_paths(tmp_path)
    prior = _manifest(paths, autostart_enabled=False)
    request = _make_setup_request(paths, bash=DesiredState.PRESERVE, autostart=DesiredState.DISABLE, chooser=DesiredState.PRESERVE)
    plan = plan_integrations(request, paths, prior=prior, uid=UID)
    assert plan.autostart == ()


def test_plan_integrations_autostart_and_chooser_never_include_each_others_paths(tmp_path: Path) -> None:
    paths, _ = _make_paths(tmp_path)
    request = _make_setup_request(
        paths, bash=DesiredState.PRESERVE, autostart=DesiredState.ENABLE, chooser=DesiredState.ENABLE
    )
    plan = plan_integrations(request, paths, prior=None, uid=UID)
    autostart_paths = {str(m.path) for m in plan.autostart}
    chooser_paths = {str(m.path) for m in plan.chooser}
    assert str(paths.autostart) in autostart_paths
    assert str(paths.chooser) in chooser_paths
    assert str(paths.autostart) not in chooser_paths
    assert str(paths.chooser) not in autostart_paths


# ---------------------------------------------------------------------------
# chooser ownership
# ---------------------------------------------------------------------------


def test_plan_integrations_chooser_first_mutation_stores_original_and_post(tmp_path: Path) -> None:
    paths, _ = _make_paths(tmp_path)
    _write_chooser(paths, enabled=False)
    request = _make_setup_request(paths, bash=DesiredState.PRESERVE, autostart=DesiredState.PRESERVE, chooser=DesiredState.ENABLE)
    plan = plan_integrations(request, paths, prior=None, uid=UID)
    assert plan.chooser_ownership.changed is True
    assert plan.chooser_ownership.original.path == str(paths.chooser)
    assert plan.chooser_ownership.original.kind is ObjectKind.FILE
    assert plan.chooser_ownership.original.content == render_chooser(False)
    assert plan.chooser_ownership.post is not None
    assert plan.chooser_ownership.post.content == render_chooser(True)
    assert plan.chooser[0].after.content == render_chooser(True)


def test_plan_integrations_chooser_absent_before_image_on_fresh_enable(tmp_path: Path) -> None:
    paths, _ = _make_paths(tmp_path)
    request = _make_setup_request(paths, bash=DesiredState.PRESERVE, autostart=DesiredState.PRESERVE, chooser=DesiredState.ENABLE)
    plan = plan_integrations(request, paths, prior=None, uid=UID)
    assert plan.chooser_ownership.original.kind is ObjectKind.ABSENT
    assert plan.chooser_ownership.post is not None
    assert plan.chooser_ownership.post.kind is ObjectKind.FILE


def test_plan_integrations_chooser_preserve_leaves_ownership_untouched(tmp_path: Path) -> None:
    paths, _ = _make_paths(tmp_path)
    _write_chooser(paths, enabled=False)
    request = _make_setup_request(paths, bash=DesiredState.PRESERVE, autostart=DesiredState.PRESERVE, chooser=DesiredState.PRESERVE)
    plan = plan_integrations(request, paths, prior=None, uid=UID)
    assert plan.chooser_ownership.changed is False
    assert plan.chooser_ownership.post is None
    assert plan.chooser == ()


def test_plan_integrations_chooser_later_mutation_retains_original_and_replaces_post(tmp_path: Path) -> None:
    paths, _ = _make_paths(tmp_path)
    _write_chooser(paths, enabled=True)
    original = BeforeImage(
        str(paths.chooser), ObjectKind.ABSENT, None, None, None, None
    )
    first_post = BeforeImage(
        str(paths.chooser), ObjectKind.FILE, 0o600, None, render_chooser(True), _sha(render_chooser(True))
    )
    prior_ownership = ChooserOwnership(original=original, post=first_post, changed=True)
    prior = _manifest(paths, chooser=prior_ownership, bash_enabled=False)
    request = _make_setup_request(paths, bash=DesiredState.PRESERVE, autostart=DesiredState.PRESERVE, chooser=DesiredState.DISABLE)
    plan = plan_integrations(request, paths, prior=prior, uid=UID)
    # original retained, post replaced with the new image
    assert plan.chooser_ownership.original is original
    assert plan.chooser_ownership.post is not None
    assert plan.chooser_ownership.post.content == render_chooser(False)
    assert plan.chooser_ownership.changed is True


def test_plan_integrations_chooser_external_edit_refused(tmp_path: Path) -> None:
    paths, _ = _make_paths(tmp_path)
    _write_chooser(paths, enabled=True)
    first_post = BeforeImage(
        str(paths.chooser), ObjectKind.FILE, 0o600, None, render_chooser(True), _sha(render_chooser(True))
    )
    prior_ownership = ChooserOwnership(
        original=BeforeImage(str(paths.chooser), ObjectKind.ABSENT, None, None, None, None),
        post=first_post, changed=True,
    )
    prior = _manifest(paths, chooser=prior_ownership)
    # external edit: current bytes no longer equal the recorded post image
    paths.chooser.write_bytes(b'{"schema_version":1,"login_chooser_enabled":false}\n')
    paths.chooser.chmod(0o600)
    request = _make_setup_request(paths, bash=DesiredState.PRESERVE, autostart=DesiredState.PRESERVE, chooser=DesiredState.DISABLE)
    with pytest.raises(ValueError):
        plan_integrations(request, paths, prior=prior, uid=UID)


def test_plan_integrations_chooser_original_survives_upgrade(tmp_path: Path) -> None:
    paths, _ = _make_paths(tmp_path)
    _write_chooser(paths, enabled=True)
    original_absent = BeforeImage(str(paths.chooser), ObjectKind.ABSENT, None, None, None, None)
    first_post = BeforeImage(
        str(paths.chooser), ObjectKind.FILE, 0o600, None, render_chooser(True), _sha(render_chooser(True))
    )
    prior = _manifest(paths, chooser=ChooserOwnership(original_absent, first_post, True))
    request = _make_setup_request(
        paths, bash=DesiredState.PRESERVE, autostart=DesiredState.PRESERVE,
        chooser=DesiredState.PRESERVE, mode=SetupMode.UPGRADE,
    )
    plan = plan_integrations(request, paths, prior=prior, uid=UID)
    assert plan.chooser_ownership.original is original_absent
    assert plan.chooser_ownership.post is first_post
    assert plan.chooser_ownership.changed is True


# ---------------------------------------------------------------------------
# plan_installed_integrations
# ---------------------------------------------------------------------------


def test_plan_installed_integrations_requires_prior_manifest(tmp_path: Path) -> None:
    paths, _ = _make_paths(tmp_path)
    request = _make_integration_request()
    with pytest.raises(ValueError):
        plan_installed_integrations(request, paths, prior=None, uid=UID)  # type: ignore[arg-type]


def test_plan_installed_integrations_preserve_only_is_idempotent(tmp_path: Path) -> None:
    paths, _ = _make_paths(tmp_path)
    prior = _manifest(paths)
    request = _make_integration_request()
    plan = plan_installed_integrations(request, paths, prior=prior, uid=UID)
    assert plan.bash == ()
    assert plan.autostart == ()
    assert plan.chooser == ()
    assert plan.bash_backup is None
    assert plan.chooser_ownership == prior.chooser


def test_plan_installed_integrations_applies_only_integration_mutations(tmp_path: Path) -> None:
    paths, _ = _make_paths(tmp_path)
    _write_chooser(paths, enabled=False)
    prior = _manifest(paths)
    request = _make_integration_request(bash=DesiredState.ENABLE, autostart=DesiredState.ENABLE, chooser=DesiredState.ENABLE)
    plan = plan_installed_integrations(request, paths, prior=prior, uid=UID)
    paths_touched = {str(m.path) for m in (*plan.bash, *plan.autostart, *plan.chooser)}
    # never touches application/generation/command/current paths
    assert paths.current not in paths_touched
    assert paths.manifest not in paths_touched
    assert all(not str(p).startswith(str(paths.generations)) for p in paths_touched)


def test_plan_installed_integrations_dry_run_is_pure_and_unchanged(tmp_path: Path) -> None:
    paths, _ = _make_paths(tmp_path)
    _write_chooser(paths, enabled=False)
    prior = _manifest(paths)
    before_fs = _snapshot_tree(paths.home)
    request = _make_integration_request(
        bash=DesiredState.ENABLE, autostart=DesiredState.ENABLE, chooser=DesiredState.ENABLE, dry_run=True
    )
    # planning is read-only: no writer is invoked and the tree is byte-identical
    plan = plan_installed_integrations(request, paths, prior=prior, uid=UID)
    assert len(plan.bash) == 1
    assert len(plan.autostart) == 1
    assert len(plan.chooser) == 1
    assert _snapshot_tree(paths.home) == before_fs


def test_plan_installed_integrations_rejects_source_application_flags(tmp_path: Path) -> None:
    paths, _ = _make_paths(tmp_path)
    prior = _manifest(paths)
    # IntegrationSetupRequest has no source_root/wheel/mode field; this test
    # documents that the installed planner cannot express application install.
    request = _make_integration_request()
    assert not hasattr(request, "source_root")
    assert not hasattr(request, "wheel")
    assert not hasattr(request, "mode")
    plan_installed_integrations(request, paths, prior=prior, uid=UID)
    # no assertion needed beyond attribute absence; reaching here is the test


def test_plan_installed_integrations_external_chooser_edit_refused(tmp_path: Path) -> None:
    paths, _ = _make_paths(tmp_path)
    _write_chooser(paths, enabled=True)
    first_post = BeforeImage(
        str(paths.chooser), ObjectKind.FILE, 0o600, None, render_chooser(True), _sha(render_chooser(True))
    )
    prior = _manifest(
        paths,
        chooser=ChooserOwnership(
            BeforeImage(str(paths.chooser), ObjectKind.ABSENT, None, None, None, None),
            first_post, True,
        ),
    )
    paths.chooser.write_bytes(b'{"schema_version":1,"login_chooser_enabled":false}\n')
    paths.chooser.chmod(0o600)
    request = _make_integration_request(chooser=DesiredState.DISABLE)
    with pytest.raises(ValueError):
        plan_installed_integrations(request, paths, prior=prior, uid=UID)


# ---------------------------------------------------------------------------
# filesystem snapshot helper for dry-run purity
# ---------------------------------------------------------------------------


def _snapshot_tree(root: Path) -> dict:
    snapshot: dict = {}
    if not root.exists():
        return snapshot
    for path in sorted(root.rglob("*")):
        try:
            st = path.lstat()
        except OSError:
            continue
        snapshot[str(path)] = (st.st_mode, st.st_size, st.st_mtime_ns)
    return snapshot
