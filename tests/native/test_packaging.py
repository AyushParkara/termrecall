# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import fcntl
import os
import subprocess
import tarfile
from pathlib import Path


def test_sdist_builds_installable_wheel_with_native_helper_and_assets(
    tmp_path: Path,
) -> None:
    root = Path(__file__).parents[2]
    build_env = {key: value for key, value in os.environ.items() if key != "PYTHONWARNINGS"}
    distributions = tmp_path / "distributions"
    distributions.mkdir()
    subprocess.run(
        ["uv", "build", "--sdist", "--out-dir", str(distributions), str(root)],
        check=True,
        timeout=60,
        env=build_env,
    )
    sdist = next(distributions.glob("*.tar.gz"))
    with tarfile.open(sdist, "r:gz") as archive:
        names = set(archive.getnames())
        prefix = names.pop().split("/", 1)[0]
        assert f"{prefix}/native/termrecall-nonblock.c" in names
        # root bootstrap and cleanup helper must be shipped in the sdist
        assert f"{prefix}/install.sh" in names
        assert f"{prefix}/installer_probe.py" in names
        assert f"{prefix}/cleanup_private_tree.py" in names

    extracted = tmp_path / "extracted"
    with tarfile.open(sdist, "r:gz") as archive:
        archive.extractall(extracted, filter="data")
    source_root = extracted / prefix
    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    subprocess.run(
        ["uv", "build", "--wheel", "--out-dir", str(wheelhouse), str(source_root)],
        check=True,
        timeout=60,
        env=build_env,
    )
    venv = tmp_path / "venv"
    subprocess.run(["python3.12", "-m", "venv", str(venv)], check=True, timeout=30)
    wheel = next(wheelhouse.glob("*.whl"))
    subprocess.run(
        [str(venv / "bin/pip"), "install", str(wheel), "--no-deps"],
        check=True,
        timeout=30,
        env=build_env,
    )

    for arguments in (("--help",), ("status", "--help"), ("doctor", "--help")):
        completed = subprocess.run(
            [str(venv / "bin/termrecall"), *arguments],
            check=True,
            timeout=1,
            capture_output=True,
            text=True,
        )
        assert "usage: termrecall" in completed.stdout
    subprocess.run([str(venv / "bin/termrecall-bridge"), "--help"], check=True, timeout=1, capture_output=True)
    result = subprocess.run([str(venv / "bin/termrecall-nonblock"), "bad"], check=False, timeout=1, capture_output=True)
    assert result.returncode == 64
    site_packages = next((venv / "lib").glob("python3.12/site-packages"))
    package = site_packages / "termrecall"
    resource = package / "libexec/termrecall-nonblock"
    assert os.access(resource, os.X_OK)
    assert (package / "data/bash/termrecall.bash").is_file()
    assert (package / "data/xdg/termrecall.desktop").is_file()
    distribution = next(site_packages.glob("termrecall-*.dist-info"))
    assert (distribution / "licenses/LICENSE").is_file()
    assert (distribution / "licenses/THIRD_PARTY.md").is_file()

    read_fd, write_fd = os.pipe()
    try:
        subprocess.run([str(venv / "bin/termrecall-nonblock")], stdin=write_fd, check=True, timeout=1)
        assert fcntl.fcntl(write_fd, fcntl.F_GETFL) & os.O_NONBLOCK
    finally:
        os.close(read_fd)
        os.close(write_fd)
