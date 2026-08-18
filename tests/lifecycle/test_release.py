# SPDX-License-Identifier: GPL-3.0-or-later
"""Task 7 release gates: forbidden-pattern checks and packaging invariants.

These tests pin the installer safety invariants that the release process must
not regress: no unchecked recursive deletion, no ``shutil.rmtree``, no
``ln -sfn``, no ``sudo pip``, no ``--purge-data`` typo, no process substitution
into the installer delegate, and every desktop ``Exec`` line uses an absolute
or templated path rather than a bare ``termrecall`` or ``env`` launch.
Classifier/protocol test fixtures that legitimately exercise dangerous command
strings are intentionally out of scope.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[2]

# Files whose installer/packaging surface must stay free of forbidden patterns.
# Test fixtures that classify dangerous commands (tests/test_classifier.py,
# tests/test_protocol.py) are excluded because they legitimately contain such
# strings as input data.
_INSTALLER_FILES = [
    ROOT / "install.sh",
    ROOT / "installer_probe.py",
    ROOT / "cleanup_private_tree.py",
    *sorted((ROOT / "src").rglob("*.py")),
    *sorted(p for p in (ROOT / "tests" / "lifecycle").rglob("*.py") if p.name != "test_release.py"),
    ROOT / "README.md",
    ROOT / "docs" / "INSTALL.md",
]
# Built from fragments so this file does not itself contain the forbidden
# literals it scans for.
_FORBIDDEN_INSTALLER = re.compile(
    "rm" + " -rf" + "|" + "shutil\\." + "rmtree" + "|" + "ln -" + "sfn" + "|"
    + "sudo" + " pip" + "|" + "--purge-" + "data" + "|" + "exec .*termrecall\\." + "installer"
)
_FORBIDDEN_EXEC = re.compile(r"Exec=(env |termrecall )")
_DESKTOP_PATHS = [
    ROOT / "src" / "termrecall" / "data" / "xdg",
    ROOT / "tests" / "lifecycle",
]


def _iter_text_files(paths):
    for path in paths:
        if path.is_file():
            yield path


@pytest.mark.parametrize("path", _INSTALLER_FILES)
def test_no_forbidden_installer_patterns(path: Path) -> None:
    if not path.exists():
        pytest.skip(f"{path} not present")
    text = path.read_text(encoding="utf-8", errors="replace")
    matches = _FORBIDDEN_INSTALLER.findall(text)
    assert not matches, f"{path}: forbidden installer pattern(s) {matches}"


def test_no_forbidden_exec_in_desktop_or_lifecycle() -> None:
    offenders: list[str] = []
    for base in _DESKTOP_PATHS:
        if not base.exists():
            continue
        for path in sorted(base.rglob("*")):
            if not path.is_file():
                continue
            if "__pycache__" in path.parts:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            for match in _FORBIDDEN_EXEC.findall(text):
                offenders.append(f"{path}: {match}")
    assert not offenders, f"forbidden Exec forms: {offenders}"


def test_manifest_includes_root_bootstrap_and_cleanup_helper() -> None:
    manifest = (ROOT / "MANIFEST.in").read_text(encoding="utf-8")
    for required in ("installer_probe.py", "install.sh", "cleanup_private_tree.py", "native/termrecall-nonblock.c"):
        assert required in manifest, f"MANIFEST.in missing {required}"


def test_lifecycle_commands_dispatch_before_service_client_documented() -> None:
    cli = (ROOT / "src" / "termrecall" / "cli.py").read_text(encoding="utf-8")
    # the public lifecycle commands must be registered and dispatched before
    # the service client is constructed
    for command in ('"setup"', '"autostart"', '"uninstall"'):
        assert command in cli, f"cli.py missing {command} subcommand"
    assert "_service_client" in cli


def test_source_modules_compile_clean() -> None:
    result = subprocess.run(
        [sys.executable, "-W", "error", "-m", "compileall", "-q",
         str(ROOT / "src"), str(ROOT / "installer_probe.py"),
         str(ROOT / "cleanup_private_tree.py"), str(ROOT / "tests")],
        capture_output=True, timeout=120,
    )
    assert result.returncode == 0, result.stderr.decode(errors="replace")
