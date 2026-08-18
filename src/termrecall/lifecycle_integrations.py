# SPDX-License-Identifier: GPL-3.0-or-later
"""Pure Bash, autostart, and chooser capture and transform logic.

This module is the integration-planning layer consumed by the lifecycle
orchestrator (:mod:`termrecall.lifecycle`).  It never writes to the
filesystem and never imports the native extension; it only captures no-follow
before-images, computes byte-exact transforms, and records independent
integration plans.  The canonical ``.bashrc`` V1 block, the single byte-for-byte
legacy block migration, and the chooser ownership rules live here.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path

from termrecall.installer_contract import (
    BeforeImage,
    ChooserOwnership,
    DesiredState,
    InstallManifest,
    IntegrationSetupRequest,
    LifecyclePaths,
    ObjectKind,
    OwnedObject,
    SetupRequest,
    validate_integration_setup_request,
    validate_setup_request,
)
from termrecall.lifecycle_fs import capture_before

__all__ = [
    "IntegrationPlan",
    "PlannedMutation",
    "plan_installed_integrations",
    "plan_integrations",
    "render_chooser",
    "render_desktop",
    "shell_single_quote",
    "transform_bashrc",
]

# Canonical ``.bashrc`` V1 block markers.  The V1 block is the only block the
# installer owns; a previously shipped legacy block is migrated byte-for-byte.
_V1_BEGIN = b"# >>> termrecall v1 >>>"
_V1_END = b"# <<< termrecall v1 <<<"
_LEGACY_BEGIN = b"# BEGIN termrecall"
_LEGACY_END = b"# END termrecall"

_DESKTOP_TEMPLATE = (
    b"[Desktop Entry]\n"
    b"Type=Application\n"
    b"Name=TermRecall\n"
    b"Exec="  # filled with the absolute active executable
    b"{executable} login-coordinator\n"
    b"OnlyShowIn=X-Cinnamon;Cinnamon;\n"
    b"X-GNOME-Autostart-enabled=true\n"
    b"Terminal=false\n"
    b"NoDisplay=true\n"
)


@dataclass(frozen=True, slots=True)
class PlannedMutation:
    """A single planned integration mutation and its before/after images."""

    path: Path
    before: BeforeImage
    after: BeforeImage


@dataclass(frozen=True, slots=True)
class IntegrationPlan:
    """Independent integration plans plus shared ownership/backup records."""

    bash: tuple[PlannedMutation, ...]
    autostart: tuple[PlannedMutation, ...]
    chooser: tuple[PlannedMutation, ...]
    chooser_ownership: ChooserOwnership
    bash_backup: OwnedObject | None


# ---------------------------------------------------------------------------
# pure renderers
# ---------------------------------------------------------------------------


def shell_single_quote(path: Path) -> bytes:
    """Return the bytes of ``path`` single-quoted for POSIX shells.

    Each embedded single quote is mapped to the five bytes ``'"'"'`` and the
    whole token is wrapped in single quotes.
    """
    raw = os.fsencode(path)
    quoted = raw.replace(b"'", b"'\"'\"'")
    return b"'" + quoted + b"'"


def _source_line(integration: Path) -> bytes:
    quoted = shell_single_quote(integration)
    return b"[ -f " + quoted + b" ] && . " + quoted


def _legacy_source_line(integration: Path) -> bytes:
    return b"source " + shell_single_quote(integration)


def _v1_block(integration: Path) -> bytes:
    return _V1_BEGIN + b"\n" + _source_line(integration) + b"\n" + _V1_END + b"\n"


def _legacy_block(integration: Path) -> bytes:
    return _LEGACY_BEGIN + b"\n" + _legacy_source_line(integration) + b"\n" + _LEGACY_END + b"\n"


def render_desktop(executable: Path) -> bytes:
    """Return the exact autostart desktop bytes with one absolute Exec line."""
    return _DESKTOP_TEMPLATE.replace(b"{executable}", os.fsencode(executable))


def render_chooser(enabled: bool) -> bytes:
    """Return the exact chooser ``config.json`` bytes for the desired state."""
    flag = b"true" if enabled else b"false"
    return b'{"schema_version":1,"login_chooser_enabled":' + flag + b"}\n"


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


# ---------------------------------------------------------------------------
# transform_bashrc
# ---------------------------------------------------------------------------


def _marker_counts(raw: bytes, begin: bytes, end: bytes) -> tuple[int, int]:
    begin_line = begin + b"\n"
    end_line = end + b"\n"
    return raw.count(begin_line), raw.count(end_line)


def transform_bashrc(raw: bytes, integration: Path, state: DesiredState) -> bytes:
    """Transform ``.bashrc`` bytes for the requested Bash integration state.

    ``ENABLE`` inserts the canonical V1 block (or migrates one exact legacy
    block, or is idempotent when the V1 block is already present).  ``DISABLE``
    removes only the V1 block and one owned separator newline.  ``PRESERVE``
    is the byte identity.  Malformed, duplicate, nested, handwritten, or
    coexisting V1/legacy markers refuse.
    """
    if state is DesiredState.PRESERVE:
        return raw
    v1 = _v1_block(integration)
    legacy = _legacy_block(integration)
    v1_begin_n, v1_end_n = _marker_counts(raw, _V1_BEGIN, _V1_END)
    leg_begin_n, leg_end_n = _marker_counts(raw, _LEGACY_BEGIN, _LEGACY_END)
    v1_markers = v1_begin_n + v1_end_n
    leg_markers = leg_begin_n + leg_end_n
    if v1_markers and leg_markers:
        raise ValueError(".bashrc contains both V1 and legacy termrecall markers")
    if state is DesiredState.ENABLE:
        if v1_markers:
            if v1_begin_n != 1 or v1_end_n != 1 or v1 not in raw:
                raise ValueError(".bashrc V1 markers are malformed or handwritten")
            return raw  # idempotent: canonical V1 block already present
        if leg_markers:
            if leg_begin_n != 1 or leg_end_n != 1 or legacy not in raw:
                raise ValueError(".bashrc legacy markers are malformed or handwritten")
            idx = raw.index(legacy)
            return raw[:idx] + v1 + raw[idx + len(legacy):]
        # no markers; append with exactly one owned separator newline
        if not raw:
            return v1
        return raw + b"\n" + v1
    # DesiredState.DISABLE
    if v1_markers:
        if v1_begin_n != 1 or v1_end_n != 1 or v1 not in raw:
            raise ValueError(".bashrc V1 markers are malformed or handwritten")
        idx = raw.index(v1)
        if idx > 0 and raw[idx - 1:idx] == b"\n":
            return raw[:idx - 1] + raw[idx + len(v1):]
        return raw[:idx] + raw[idx + len(v1):]
    if leg_markers:
        raise ValueError(".bashrc legacy markers present without a V1 block to remove")
    return raw  # idempotent disable: no V1 block present


# ---------------------------------------------------------------------------
# before/after image helpers
# ---------------------------------------------------------------------------


def _file_after(path: Path, before: BeforeImage, content: bytes) -> BeforeImage:
    """Build a FILE after-image preserving the user-owned file's mode."""
    mode = before.mode if before.kind is ObjectKind.FILE else 0o600
    return BeforeImage(str(path), ObjectKind.FILE, mode, None, content, _sha256(content))


def _absent_after(path: Path) -> BeforeImage:
    return BeforeImage(str(path), ObjectKind.ABSENT, None, None, None, None)


def _bash_backup(
    paths: LifecyclePaths, prior: InstallManifest | None, before: BeforeImage
) -> OwnedObject | None:
    """Reuse the prior durable backup, or plan one before the first edit."""
    if prior is not None and prior.bash_backup is not None:
        return prior.bash_backup
    if before.kind is ObjectKind.ABSENT:
        # nothing to back up; the executor will still record an empty backup
        original = b""
    else:
        original = before.content or b""
    backup_path = paths.config_root / "bashrc.backup"
    return OwnedObject(
        str(backup_path),
        ObjectKind.FILE,
        0o600,
        _sha256(original),
        None,
    )


# ---------------------------------------------------------------------------
# integration planners
# ---------------------------------------------------------------------------


def _plan_bash(
    state: DesiredState, paths: LifecyclePaths, prior: InstallManifest | None, uid: int
) -> tuple[tuple[PlannedMutation, ...], OwnedObject | None]:
    if state is DesiredState.PRESERVE:
        backup = prior.bash_backup if prior is not None else None
        return (), backup
    before = capture_before(paths.bashrc, uid)
    current = before.content or b""
    transformed = transform_bashrc(current, paths.bash_integration, state)
    after = _file_after(paths.bashrc, before, transformed)
    backup = _bash_backup(paths, prior, before)
    return (PlannedMutation(paths.bashrc, before, after),), backup


def _owned_for(
    prior: InstallManifest | None, target: Path
) -> OwnedObject | None:
    if prior is None:
        return None
    text = str(target)
    for item in prior.owned:
        if item.path == text:
            return item
    return None


def _plan_autostart(
    state: DesiredState, paths: LifecyclePaths, prior: InstallManifest | None, uid: int
) -> tuple[PlannedMutation, ...]:
    executable = paths.current / "venv/bin/termrecall"
    expected = render_desktop(executable)
    before = capture_before(paths.autostart, uid)
    if state is DesiredState.PRESERVE:
        return ()
    if state is DesiredState.ENABLE:
        if before.kind is ObjectKind.ABSENT:
            after = _file_after(paths.autostart, before, expected)
            return (PlannedMutation(paths.autostart, before, after),)
        # pre-existing entry must be owned and exact
        owned = _owned_for(prior, paths.autostart)
        if (
            owned is None
            or owned.kind is not ObjectKind.FILE
            or owned.mode != (before.mode or 0)
            or owned.content_sha256 != before.content_sha256
        ):
            raise ValueError("autostart entry exists but is not owned by the manifest")
        # idempotent when the manifest-owned file matches the canonical bytes
        after = _file_after(paths.autostart, before, expected)
        return (PlannedMutation(paths.autostart, before, after),)
    # DesiredState.DISABLE
    if before.kind is ObjectKind.ABSENT:
        return ()  # idempotent: nothing to remove
    owned = _owned_for(prior, paths.autostart)
    if (
        owned is None
        or owned.kind is not ObjectKind.FILE
        or owned.mode != (before.mode or 0)
        or owned.content_sha256 != before.content_sha256
    ):
        raise ValueError("autostart disable requires exact manifest hash and mode")
    return (PlannedMutation(paths.autostart, before, _absent_after(paths.autostart)),)


def _chooser_after_image(paths: LifecyclePaths, enabled: bool) -> BeforeImage:
    content = render_chooser(enabled)
    return BeforeImage(
        str(paths.chooser), ObjectKind.FILE, 0o600, None, content, _sha256(content)
    )


def _plan_chooser(
    state: DesiredState,
    paths: LifecyclePaths,
    prior: InstallManifest | None,
    uid: int,
) -> tuple[tuple[PlannedMutation, ...], ChooserOwnership]:
    before = capture_before(paths.chooser, uid)
    prior_ownership = prior.chooser if prior is not None else None
    if state is DesiredState.PRESERVE:
        if prior_ownership is not None:
            return (), prior_ownership
        absent = BeforeImage(str(paths.chooser), ObjectKind.ABSENT, None, None, None, None)
        return (), ChooserOwnership(absent, None, False)
    desired_enabled = state is DesiredState.ENABLE
    after = _chooser_after_image(paths, desired_enabled)
    if prior_ownership is not None and prior_ownership.changed:
        # later installer change: current bytes must equal the recorded post image
        expected = prior_ownership.post if prior_ownership.post is not None else prior_ownership.original
        if before.kind != expected.kind or before.content_sha256 != expected.content_sha256:
            raise ValueError("chooser was modified externally since the last installer change")
        original = prior_ownership.original
    else:
        # first installer mutation: store the current before-image as original
        original = before
    ownership = ChooserOwnership(original, after, True)
    return (PlannedMutation(paths.chooser, before, after),), ownership


def _plan_integrations_core(
    bash_state: DesiredState,
    autostart_state: DesiredState,
    chooser_state: DesiredState,
    paths: LifecyclePaths,
    prior: InstallManifest | None,
    uid: int,
) -> IntegrationPlan:
    bash, bash_backup = _plan_bash(bash_state, paths, prior, uid)
    autostart = _plan_autostart(autostart_state, paths, prior, uid)
    chooser, ownership = _plan_chooser(chooser_state, paths, prior, uid)
    return IntegrationPlan(
        bash=bash,
        autostart=autostart,
        chooser=chooser,
        chooser_ownership=ownership,
        bash_backup=bash_backup,
    )


def plan_integrations(
    request: SetupRequest,
    paths: LifecyclePaths,
    prior: InstallManifest | None,
    uid: int,
) -> IntegrationPlan:
    """Plan independent Bash/autostart/chooser mutations for ``install.sh``."""
    validate_setup_request(request)
    return _plan_integrations_core(
        request.bash, request.autostart, request.chooser, paths, prior, uid
    )


def plan_installed_integrations(
    request: IntegrationSetupRequest,
    paths: LifecyclePaths,
    prior: InstallManifest,
    uid: int,
) -> IntegrationPlan:
    """Plan integration-only mutations for the installed ``setup`` command.

    This path has no source root, wheel, probe plan, application mode, or
    generation staging capability; it plans only Bash/autostart/chooser
    mutations against the manifest-verified current installation.
    """
    validate_integration_setup_request(request)
    if prior is None:
        raise ValueError("installed setup requires a manifest-verified current installation")
    return _plan_integrations_core(
        request.bash, request.autostart, request.chooser, paths, prior, uid
    )
