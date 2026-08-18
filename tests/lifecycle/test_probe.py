from __future__ import annotations

import importlib.util
import json
import os
import shutil
import signal
import subprocess
import sys
import tarfile
import time
import zipfile
from pathlib import Path

import pytest

from termrecall import installer_probe as packaged_probe


ROOT = Path(__file__).parents[2]
SPEC = importlib.util.spec_from_file_location("installer_probe", ROOT / "installer_probe.py")
assert SPEC is not None and SPEC.loader is not None
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)


def test_root_probe_is_thin_and_exports_packaged_implementation() -> None:
    assert probe.build_plan is packaged_probe.build_plan
    assert probe.plan_from_bytes is packaged_probe.plan_from_bytes
    assert probe.main is packaged_probe.main
    assert (ROOT / "installer_probe.py").stat().st_size < 2_048


def canonical_request(tmp_path: Path) -> dict[str, object]:
    return {
        "request_schema": 1,
        "source_root": str(tmp_path / "source"),
        "home": str(tmp_path / "home"),
        "xdg_data_home": str(tmp_path / "data"),
        "xdg_config_home": str(tmp_path / "config"),
        "xdg_state_home": str(tmp_path / "state"),
        "mode": "full",
        "bash": "enable",
        "autostart": "enable",
        "chooser": "enable",
        "dry_run": True,
    }


def minimal_plan(tmp_path: Path) -> dict[str, object]:
    request = canonical_request(tmp_path)
    plan: dict[str, object] = {
        "probe_schema": 1,
        "plan_schema": 2,
        "request": request,
        "prerequisites": {
            "uid": os.getuid(),
            "python": sys.executable,
            "python_version": [3, 12, 0],
            "venv": True,
            "cc": "/usr/bin/cc",
            "bash": "/usr/bin/bash",
        },
        "source": {
            "root": request["source_root"],
            "device": 1,
            "inode": 2,
            "probe_device": 1,
            "probe_inode": 3,
            "manifest": {},
        },
        "prior": {"present": False, "schema_version": None, "manifest_sha256": None, "manifest": None},
        "effective": {"bash": False, "autostart": False, "chooser": False},
        "actions": [],
        "lock_infrastructure": {
            "directory_path": str(tmp_path / "config/termrecall"),
            "lock_path": str(tmp_path / "config/termrecall/lifecycle.lock"),
            "directory_absent": True,
            "lock_absent": True,
            "may_create_directory": True,
            "may_create_lock": True,
            "directory_mode": 0o700,
            "lock_mode": 0o600,
        },
        "state_fingerprint": "0" * 64,
        "rendered": "",
        "plan_digest": "",
    }
    plan["rendered"] = probe.render_plan(plan)
    plan["plan_digest"] = probe.compute_plan_digest(plan)
    return plan


def test_canonical_json_digest_and_rendering(tmp_path: Path) -> None:
    plan = minimal_plan(tmp_path)
    raw = probe.plan_to_bytes(plan)
    assert raw.endswith(b"\n")
    assert raw == json.dumps(
        plan, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8") + b"\n"
    assert probe.plan_from_bytes(raw, canonical_request(tmp_path)) == plan
    assert plan["plan_digest"] == probe.compute_plan_digest(plan)
    assert plan["rendered"] == probe.render_plan(plan)


def test_plan_parser_rejects_duplicates_unknown_keys_and_noncanonical_json(tmp_path: Path) -> None:
    plan = minimal_plan(tmp_path)
    raw = probe.plan_to_bytes(plan)
    duplicate = raw.replace(b'{"actions":', b'{"actions":[],"actions":', 1)
    with pytest.raises(ValueError, match="duplicate"):
        probe.plan_from_bytes(duplicate, canonical_request(tmp_path))

    unknown = dict(plan, unknown=True)
    unknown["plan_digest"] = probe.compute_plan_digest(unknown)
    with pytest.raises(ValueError, match="keys"):
        probe.plan_from_bytes(probe.plan_to_bytes(unknown), canonical_request(tmp_path))

    with pytest.raises(ValueError, match="canonical"):
        probe.plan_from_bytes(raw[:-1], canonical_request(tmp_path))


@pytest.mark.parametrize(
    ("section", "key", "bad"),
    [
        ("request", "dry_run", 1),
        ("prerequisites", "uid", True),
        ("source", "device", True),
        ("prior", "present", 1),
        ("effective", "bash", 1),
        ("lock_infrastructure", "directory_mode", True),
    ],
)
def test_plan_parser_is_recursively_strict(
    tmp_path: Path, section: str, key: str, bad: object
) -> None:
    plan = minimal_plan(tmp_path)
    nested = dict(plan[section])
    nested[key] = bad
    plan[section] = nested
    plan["rendered"] = probe.render_plan(plan)
    plan["plan_digest"] = probe.compute_plan_digest(plan)
    with pytest.raises(ValueError):
        probe.plan_from_bytes(probe.plan_to_bytes(plan), canonical_request(tmp_path))


def test_plan_parser_rejects_unknown_nested_keys_and_invalid_action_variants(tmp_path: Path) -> None:
    plan = minimal_plan(tmp_path)
    source = dict(plan["source"])
    source["unknown"] = True
    plan["source"] = source
    plan["rendered"] = probe.render_plan(plan)
    plan["plan_digest"] = probe.compute_plan_digest(plan)
    with pytest.raises(ValueError, match="source"):
        probe.plan_from_bytes(probe.plan_to_bytes(plan), canonical_request(tmp_path))

    plan = minimal_plan(tmp_path)
    plan["actions"] = [{
        "sequence": 1, "kind": "command-link", "disposition": "replace",
        "path_or_token": str(tmp_path / "home/.local/bin/termrecall"),
        "mode": None, "literal_target": "/wrong", "content_sha256": None,
        "prerequisite": None, "rollback": None,
    }]
    plan["rendered"] = probe.render_plan(plan)
    plan["plan_digest"] = probe.compute_plan_digest(plan)
    with pytest.raises(ValueError, match="command"):
        probe.plan_from_bytes(probe.plan_to_bytes(plan), canonical_request(tmp_path))


def test_plan_parser_rejects_bad_lock_plan_and_request_drift(tmp_path: Path) -> None:
    plan = minimal_plan(tmp_path)
    lock = dict(plan["lock_infrastructure"])
    lock["may_create_lock"] = False
    plan["lock_infrastructure"] = lock
    plan["rendered"] = probe.render_plan(plan)
    plan["plan_digest"] = probe.compute_plan_digest(plan)
    with pytest.raises(ValueError, match="lock"):
        probe.plan_from_bytes(probe.plan_to_bytes(plan), canonical_request(tmp_path))

    plan = minimal_plan(tmp_path)
    expected = canonical_request(tmp_path)
    expected["chooser"] = "preserve"
    with pytest.raises(ValueError, match="request"):
        probe.plan_from_bytes(probe.plan_to_bytes(plan), expected)


def test_plan_payload_limit_is_exact(tmp_path: Path) -> None:
    plan = minimal_plan(tmp_path)
    raw = probe.plan_to_bytes(plan)
    padded = raw + b" " * (65_536 - len(raw))
    with pytest.raises(ValueError, match="canonical"):
        probe.plan_from_bytes(padded, canonical_request(tmp_path))
    with pytest.raises(ValueError, match="65,536"):
        probe.plan_from_bytes(padded + b"x", canonical_request(tmp_path))


def test_sdist_and_wheel_ship_probe_entries_and_packaged_parity(tmp_path: Path) -> None:
    distributions = tmp_path / "dist"
    distributions.mkdir()
    subprocess.run(["uv", "build", "--sdist", "--wheel", "--out-dir", str(distributions), str(ROOT)], check=True, capture_output=True, timeout=120)
    sdist = next(distributions.glob("*.tar.gz"))
    with tarfile.open(sdist, "r:gz") as archive:
        names = archive.getnames()
        prefix = names[0].split("/", 1)[0]
        assert f"{prefix}/installer_probe.py" in names
        assert f"{prefix}/src/termrecall/installer_probe.py" in names
    wheel = next(distributions.glob("*.whl"))
    with zipfile.ZipFile(wheel) as archive:
        packaged = archive.read("termrecall/installer_probe.py")
    assert packaged == (ROOT / "src/termrecall/installer_probe.py").read_bytes()


def test_probe_read_only_from_fresh_unpacked_source(tmp_path: Path) -> None:
    source = tmp_path / "source"
    ignored = shutil.ignore_patterns("__pycache__", ".pytest_cache", "*.pyc", "dist", "build", "*.egg-info")
    shutil.copytree(ROOT, source, ignore=ignored)
    for path in source.rglob("*"):
        path.chmod(path.stat().st_mode & ~0o022)
    source.chmod(source.stat().st_mode & ~0o022)
    roots = {name: tmp_path / name for name in ("home", "data", "config", "state", "temp", "cache")}

    def snapshot() -> list[tuple[str, int, int, int]]:
        result = []
        for root in roots.values():
            if root.exists():
                for path in (root, *root.rglob("*")):
                    metadata = path.stat(follow_symlinks=False)
                    result.append((str(path), metadata.st_mode, metadata.st_size, metadata.st_mtime_ns))
        return result

    before = snapshot()
    completed = subprocess.run(
        [
            sys.executable, "-I", "-B", str(source / "installer_probe.py"), "plan",
            "--source-root", str(source), "--home", str(roots["home"]),
            "--xdg-data-home", str(roots["data"]), "--xdg-config-home", str(roots["config"]),
            "--xdg-state-home", str(roots["state"]), "--mode", "full", "--bash", "enable",
            "--autostart", "enable", "--chooser", "enable", "--dry-run", "yes",
        ],
        env={"PATH": os.environ["PATH"], "TMPDIR": str(roots["temp"]), "XDG_CACHE_HOME": str(roots["cache"]), "PYTHONDONTWRITEBYTECODE": "1"},
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr.decode()
    assert snapshot() == before
    assert not list(source.rglob("__pycache__"))
    assert not (source / "dist").exists()
    plan = probe.plan_from_bytes(completed.stdout, canonical_request_for_source(source, roots))
    assert plan["lock_infrastructure"]["directory_absent"] is True
    assert plan["lock_infrastructure"]["lock_absent"] is True


def canonical_request_for_source(source: Path, roots: dict[str, Path]) -> dict[str, object]:
    request = canonical_request(source.parent)
    request.update(
        source_root=str(source), home=str(roots["home"]), xdg_data_home=str(roots["data"]),
        xdg_config_home=str(roots["config"]), xdg_state_home=str(roots["state"]),
    )
    return request


def test_write_all_handles_broken_pipe_and_closes_descriptor() -> None:
    read_fd, write_fd = os.pipe()
    os.close(read_fd)
    errors: list[BaseException] = []
    packaged_probe._write_all(write_fd, b"payload", errors)
    assert len(errors) == 1
    assert isinstance(errors[0], BrokenPipeError)
    with pytest.raises(OSError):
        os.close(write_fd)


def test_wait_delegate_forwards_real_signals_and_restores_handlers() -> None:
    old_handlers = {sig: signal.getsignal(sig) for sig in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM)}
    for sig, expected in ((signal.SIGHUP, 129), (signal.SIGINT, 130), (signal.SIGTERM, 143)):
        child = subprocess.Popen(
            [sys.executable, "-c", "import signal,time; signal.signal(signal.SIGHUP,lambda *_:None); time.sleep(60)"],
            start_new_session=True,
        )
        def send() -> None:
            time.sleep(0.05)
            os.kill(os.getpid(), sig)
        import threading
        sender = threading.Thread(target=send)
        sender.start()
        assert packaged_probe._wait_delegate(child, [], timeout=0.2) == expected
        sender.join()
        assert child.poll() is not None
        assert {item: signal.getsignal(item) for item in old_handlers} == old_handlers


def test_state_fingerprint_excludes_only_lock_infrastructure(tmp_path: Path) -> None:
    source = tmp_path / "source"
    shutil.copytree(ROOT, source, ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache", "*.pyc"))
    for path in (source, *source.rglob("*")):
        path.chmod(path.stat().st_mode & ~0o022)
    packaged_probe.__file__ = str(source / "src/termrecall/installer_probe.py")
    roots = {name: tmp_path / name for name in ("home", "data", "config", "state")}
    argv = [
        "--source-root", str(source), "--home", str(roots["home"]), "--xdg-data-home", str(roots["data"]),
        "--xdg-config-home", str(roots["config"]), "--xdg-state-home", str(roots["state"]),
        "--mode", "full", "--bash", "enable", "--autostart", "enable", "--chooser", "enable", "--dry-run", "yes",
    ]
    monkey_uid = os.getuid
    if monkey_uid() == 0:
        pytest.skip("planner correctly refuses root")
    first = probe.build_plan(argv, os.environ)
    lock_dir = roots["config"] / "termrecall"
    lock_dir.mkdir(parents=True, mode=0o700)
    lock = lock_dir / "lifecycle.lock"
    lock.write_bytes(b"")
    lock.chmod(0o600)
    second = probe.build_plan(argv, os.environ)
    assert second["state_fingerprint"] == first["state_fingerprint"]

    semantic = roots["home"] / ".bashrc"
    semantic.parent.mkdir(parents=True, exist_ok=True)
    semantic.write_text("changed\n")
    third = probe.build_plan(argv, os.environ)
    assert third["state_fingerprint"] != second["state_fingerprint"]
